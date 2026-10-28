"""Read-only evidence of installed firmware boot arrangements.

This detects disk structures, not the firmware used on the last boot. It does
not execute boot code or certify that the guest will boot. Partition metadata
alone never establishes a supported firmware mode.

PE fields follow Microsoft's PE/COFF specification; GRUB's BIOS core pointer
and blocklist follow include/grub/i386/pc/boot.h and diskboot.S. Unknown boot
code is deliberately left unclassified instead of guessed from a signature.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re
import struct

from .architecture import normalize_arch


EFI_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
BIOS_GUID = "21686148-6449-6e6f-744e-656564454649"
ARCHITECTURES = {0x8664: "x86_64", 0x14C: "i386", 0xAA64: "aarch64", 0x1C2: "arm", 0x5064: "riscv64"}
LOADER_NAME = re.compile(r"(?:boot(?:x64|ia32|aa64|arm|riscv64)|(?:grub|shim)(?:x64|ia32|aa64|arm|riscv64)?|systemd-boot(?:x64|ia32|aa64)|refind_(?:x64|ia32|aa64)|limine(?:_x64|_ia32)?)\.efi$", re.I)


def _bytes(value):
    return value.encode("latin1") if isinstance(value, str) else value


def _pe_application(g, path: str) -> dict:
    """Validate bounded PE headers, sections and an executable entry point."""
    size = g.filesize(path)

    def read(count, offset):
        if offset < 0 or count < 0 or offset + count > size:
            raise ValueError("truncated PE header or section")
        data = _bytes(g.pread(path, count, offset))
        if len(data) != count:
            raise ValueError("short read of PE image")
        return data

    dos = read(64, 0)
    if dos[:2] != b"MZ":
        raise ValueError("missing DOS/PE signature")
    pe_offset = struct.unpack_from("<I", dos, 60)[0]
    if not 64 <= pe_offset <= 1024 * 1024:
        raise ValueError("invalid PE header offset")
    header = read(24, pe_offset)
    if header[:4] != b"PE\x00\x00":
        raise ValueError("missing PE signature")
    machine, sections = struct.unpack_from("<HH", header, 4)
    optional_size, characteristics = struct.unpack_from("<HH", header, 20)
    if not 1 <= sections <= 96 or not characteristics & 0x0002 or not 72 <= optional_size <= 4096:
        raise ValueError("invalid PE executable header")
    optional = read(optional_size, pe_offset + 24)
    magic = struct.unpack_from("<H", optional)[0]
    minimum = 112 if magic == 0x20B else 96 if magic == 0x10B else 0
    if not minimum or optional_size < minimum or (machine in {0x8664, 0xAA64} and magic != 0x20B):
        raise ValueError("invalid PE optional header")
    if struct.unpack_from("<H", optional, 68)[0] != 10:
        raise ValueError("PE image is not an EFI application (drivers are excluded)")
    directories = struct.unpack_from("<I", optional, minimum - 4)[0]
    if directories > (optional_size - minimum) // 8:
        raise ValueError("truncated PE data directory")
    entry = struct.unpack_from("<I", optional, 16)[0]
    image_size, header_size = struct.unpack_from("<II", optional, 56)
    end_headers = pe_offset + 24 + optional_size + sections * 40
    if not entry or not image_size or not end_headers <= header_size <= size:
        raise ValueError("invalid PE entry point or header size")
    names, executable_entry = [], False
    for number in range(sections):
        section = read(40, pe_offset + 24 + optional_size + number * 40)
        names.append(section[:8].rstrip(b"\0").decode("ascii", "replace"))
        virtual_size, address, raw_size, offset = struct.unpack_from("<IIII", section, 8)
        flags = struct.unpack_from("<I", section, 36)[0]
        if raw_size and (offset < header_size or offset + raw_size > size):
            raise ValueError("truncated or overlapping PE section")
        if address + max(virtual_size, raw_size) > image_size:
            raise ValueError("PE section exceeds virtual image")
        if flags & 0x20000000 and address <= entry < address + min(raw_size, virtual_size or raw_size):
            executable_entry = True
    if not executable_entry:
        raise ValueError("PE entry point is outside an executable section")
    return {"architecture": ARCHITECTURES.get(machine, f"machine-0x{machine:04x}"),
            "uki": ".linux" in names and ".osrel" in names}


def _efi_paths(g):
    """Bound traversal and do not follow guest symlinks out of the ESP tree."""
    pending, count = [("/", 0)], 0
    while pending:
        directory, depth = pending.pop()
        for name in sorted(g.ls(directory)):
            if name in {".", ".."} or "/" in name:
                continue
            path = str(PurePosixPath(directory) / name)
            count += 1
            if count > 2048:
                raise ValueError("ESP traversal exceeded 2048 entries")
            if g.is_symlink(path):
                continue
            if g.is_dir(path):
                if depth < 4 and (depth or name.lower() == "efi"):
                    pending.append((path, depth + 1))
            elif depth and path.lower().endswith(".efi") and g.is_file(path):
                yield path


def _probe_esp(g, device, result, declared=True):
    if g.mountpoints():
        result["warnings"].append(f"Cannot probe {device}: an earlier partition could not be unmounted.")
        return
    try:
        g.mount_ro(device, "/")
        for path in _efi_paths(g):
            recognized = bool(LOADER_NAME.fullmatch(PurePosixPath(path).name))
            # Unified Kernel Images have arbitrary names, but live in EFI/Linux
            # and contain both the embedded Linux image and os-release sections.
            possible_uki = str(PurePosixPath(path).parent).lower() == "/efi/linux"
            if not (recognized or possible_uki):
                continue
            try:
                pe = _pe_application(g, path)
                if not recognized and not pe["uki"]:
                    continue
                fallback_path = {"x86_64": "/efi/boot/bootx64.efi", "aarch64": "/efi/boot/bootaa64.efi"}.get(pe["architecture"])
                fallback = path.lower() == fallback_path
                loader = {"device": device, "path": path, "architecture": pe["architecture"], "fallback": fallback}
                result["efi_loaders"].append(loader)
                if declared and pe["architecture"] == result["architecture"]:
                    result["evidence"].append(f"{device}: valid {pe['architecture']} EFI application {path}")
                elif not declared:
                    result["warnings"].append(f"{device}: {path} exists on FAT without an EFI system partition type; firmware discovery is unverified.")
                else:
                    result["warnings"].append(f"{device}: {path} targets {pe['architecture']}, not the {result['architecture']} guest.")
            except (RuntimeError, ValueError) as exc:
                result["warnings"].append(f"{device} {path}: {exc}")
    except (RuntimeError, ValueError) as exc:
        result["warnings"].append(f"Cannot fully inspect EFI partition {device}: {exc}")
    finally:
        # Root here belongs to this independently mounted partition, never to a
        # mounted guest OS. No directories or files are created in the image.
        try:
            g.umount_all()
        except RuntimeError as exc:
            result["warnings"].append(f"Cannot unmount EFI partition {device}: {exc}")


def _grub_bios(g, disk, mbr, regions, warnings):
    if not (mbr[510:] == b"\x55\xaa" and b"GRUB" in mbr[:446]
            and b"Geom" in mbr[:446] and b"Read" in mbr[:446]):
        return []
    sector = struct.unpack_from("<Q", mbr, 0x5C)[0]
    region = next((item for item in regions if item[0] <= sector * 512 and (sector + 1) * 512 <= item[1]), None)
    if not region:
        warnings.append("GRUB MBR code exists, but its core-image pointer is outside a verified BIOS embedding area.")
        return []
    core = _bytes(g.pread_device(disk, 512, sector * 512))
    if len(core) != 512 or not all(marker in core[:500] for marker in (b"loading", b"Geom", b"Read", b" Error")):
        warnings.append("GRUB MBR code exists, but the referenced core-image disk loader is missing or unrecognized.")
        return []
    # GRUB's diskboot.S places its first (12-byte) blocklist entry at 500.
    # Require a real referenced payload inside the embedding area, not merely a
    # reserved BIOS partition or a copied boot-sector signature.
    extents, expected_segment, total, nonempty = [], 0x820, 0, False
    for index in range(32):
        start, count, segment = struct.unpack_from("<QHH", core, 500 - 12 * index)
        if not count:
            if extents and nonempty:
                break
            warnings.append("GRUB core-image payload is empty.")
            return []
        total += count * 512
        if (segment != expected_segment or total > 1024 * 1024
                or not region[0] <= start * 512 < (start + count) * 512 <= region[1]
                or start <= sector < start + count
                or any(start < end and start + count > beginning for beginning, end in extents)):
            warnings.append("GRUB core-image blocklist is invalid or outside its BIOS embedding area.")
            return []
        expected_segment += count * 32
        if expected_segment > 0x10000:
            warnings.append("GRUB core-image blocklist exceeds BIOS addressable loading memory.")
            return []
        extents.append((start, start + count))
        payload = _bytes(g.pread_device(disk, count * 512, start * 512))
        if len(payload) != count * 512:
            warnings.append("GRUB core-image payload is truncated or unreadable.")
            return []
        nonempty = nonempty or bool(payload.strip(b"\x00\xff"))
    else:
        warnings.append("GRUB core-image blocklist has no terminator within the supported inspection bound.")
        return []
    return [f"{disk}: installed GRUB MBR boot code", f"GRUB core-image pointer and payload verified in {region[2]}"]


def _syslinux_bios(g, disk, mbr, partitions, warnings):
    # Standard MBR code must select an active partition; an arbitrary 55aa
    # signature plus a filesystem containing boot packages is insufficient.
    if mbr[510:] != b"\x55\xaa" or not any(marker in mbr[:446] for marker in (b"Missing operating system", b"Invalid partition table", b"Error loading operating system")):
        return []
    for number in range(1, 5):
        if mbr[446 + (number - 1) * 16] != 0x80:
            continue
        partition = next((part for part in partitions if part["part_num"] == number), None)
        if not partition:
            continue
        device = f"{disk}{number}"
        try:
            vbr = _bytes(g.pread_device(disk, 512, partition["part_start"]))
            if len(vbr) != 512 or vbr[510:] != b"\x55\xaa" or not any(marker in vbr[:510] for marker in (b"SYSLINUX", b"EXTLINUX")):
                continue
            if g.mountpoints():
                warnings.append(f"Cannot probe {device}: an earlier partition could not be unmounted.")
                continue
            g.mount_ro(device, "/")
            for directory in ("/", "/syslinux", "/boot/syslinux", "/extlinux", "/boot/extlinux"):
                base = directory.rstrip("/")
                loader = base + "/ldlinux.sys"
                configs = (base + "/syslinux.cfg", base + "/extlinux.conf")
                if g.is_file(loader) and g.filesize(loader) > 512 and any(g.is_file(path) and g.filesize(path) for path in configs):
                    warnings.append(f"{device}: SYSLINUX/EXTLINUX VBR, {loader}, and configuration found; stage-2 sector references and matching loader signatures are unverified.")
                    return []
        except RuntimeError as exc:
            warnings.append(f"Cannot inspect BIOS active partition {device}: {exc}")
        finally:
            try:
                g.umount_all()
            except RuntimeError as exc:
                warnings.append(f"Cannot unmount BIOS candidate {device}: {exc}")
    return []


def detect_boot(g, disk="/dev/sda", architecture="x86_64") -> dict:
    """Inspect an unmounted libguestfs appliance without executing guest code."""
    result = {"mode": "unknown", "label": "Unknown", "supported_firmware": [],
              "recommended_firmware": None, "partition_table": "unknown", "evidence": [],
              "warnings": [], "efi_loaders": [], "bios_evidence": [], "boot_tested": False,
              "architecture": normalize_arch(architecture)}
    warnings = result["warnings"]
    if g.mountpoints():
        warnings.append("Boot detection requires an unmounted appliance; existing guest mounts were left untouched.")
        return result
    try:
        table = g.part_get_parttype(disk)
        result["partition_table"] = "msdos" if table in {"msdos", "mbr"} else "gpt" if table == "gpt" else "unknown"
    except RuntimeError as exc:
        warnings.append(f"Cannot read partition table: {exc}")
    try:
        partitions = g.part_list(disk)
    except RuntimeError as exc:
        warnings.append(f"Cannot list partitions: {exc}")
        partitions = []
    regions, declared_esp = [], set()
    for partition in partitions:
        number = partition["part_num"]
        device = f"{disk}{number}"
        kind = None
        try:
            if result["partition_table"] == "gpt":
                kind = g.part_get_gpt_type(disk, number).lower()
            elif result["partition_table"] == "msdos":
                kind = g.part_get_mbr_id(disk, number)
        except RuntimeError as exc:
            warnings.append(f"Cannot read partition type for {device}: {exc}")
        if kind == BIOS_GUID:
            regions.append((partition["part_start"], partition["part_end"] + 1, f"GPT BIOS Boot Partition {device}"))
        if kind != BIOS_GUID:
            try:
                fat = g.vfs_type(device) in {"vfat", "fat", "msdos"}
                if kind in {EFI_GUID, 0xEF}:
                    if fat:
                        declared_esp.add(device)
                        _probe_esp(g, device, result)
                    else:
                        warnings.append(f"{device} has an EFI partition type but no conforming FAT filesystem; UEFI discovery is unverified.")
                elif fat:
                    _probe_esp(g, device, result, declared=False)
            except RuntimeError as exc:
                warnings.append(f"Cannot identify filesystem on {device}: {exc}")
    if result["partition_table"] == "msdos" and partitions:
        first = min(part["part_start"] for part in partitions)
        if first > 512:
            regions.append((512, first, "the MBR embedding gap"))
    try:
        mbr = _bytes(g.pread_device(disk, 512, 0))
        if len(mbr) != 512:
            raise ValueError("short read of MBR")
        if result["architecture"] != "x86_64":
            if b"GRUB" in mbr[:446]:
                warnings.append("Legacy x86 BIOS boot code does not establish an ARM64 boot chain.")
        elif g.blockdev_getss(disk) == 512:
            result["bios_evidence"] = _grub_bios(g, disk, mbr, regions, warnings)
            if not result["bios_evidence"] and result["partition_table"] == "msdos":
                result["bios_evidence"] = _syslinux_bios(g, disk, mbr, partitions, warnings)
        else:
            warnings.append("BIOS boot-code verification currently supports 512-byte logical sectors only.")
        if not result["bios_evidence"] and b"LILO" in mbr[:446]:
            warnings.append("LILO-like boot code was found; its boot chain could not be verified.")
    except (RuntimeError, ValueError) as exc:
        warnings.append(f"Cannot verify BIOS boot code: {exc}")
    matching = [loader for loader in result["efi_loaders"] if loader["architecture"] == result["architecture"]
                and loader["architecture"] in {"x86_64", "aarch64"} and loader["device"] in declared_esp]
    if matching:
        result["supported_firmware"].append("UEFI_64")
        if not any(loader["fallback"] for loader in matching):
            warnings.append("EFI loaders exist only at vendor paths; the destination firmware needs a matching boot entry. Firmware NVRAM is not included in the disk image.")
    if result["bios_evidence"]:
        result["supported_firmware"].append("BIOS")
        result["evidence"].extend(result["bios_evidence"])
    supported = result["supported_firmware"]
    if len(supported) == 2:
        result.update(mode="dual", label="Dual firmware (UEFI + legacy BIOS)")
    elif supported:
        uefi = supported[0] == "UEFI_64"
        result.update(mode="uefi" if uefi else "bios", label="UEFI (64-bit)" if uefi else "Legacy BIOS", recommended_firmware=supported[0])
    else:
        warnings.append("No supported installed boot chain could be verified; partition style and boot signatures alone do not establish firmware support.")
    warnings.append("Offline inspection detects installed boot arrangements, not the last boot mode. No firmware boot test was performed.")
    return result
