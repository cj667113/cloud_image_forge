"""Explicit BIOS-to-UEFI migration of a disposable Linux working image.

No existing partition is moved, shrunk, or reformatted. EFI installation uses
the guest's bootloader tools/packages; successful offline verification is not
a firmware boot test or a Secure Boot certification.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shlex
import struct
from uuid import uuid4
import zlib

from .boot import EFI_GUID, _bytes, _pe_application

MIB = 1024 * 1024
GIB = 1024 * MIB
RPM_VENDORS = {"oraclelinux": "redhat", "rhel": "redhat", "centos": "centos",
               "rocky": "rocky", "almalinux": "almalinux", "fedora": "fedora"}
TOOLS = ("grub-install", "grub-mkconfig", "grub-script-check", "grub2-mkconfig",
         "grub2-script-check", "rpm", "dnf", "apt-get")


def _read(g, path, limit=2 * MIB):
    try:
        if g.is_file(path) and g.filesize(path) <= limit:
            value = g.read_file(path)
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    except RuntimeError:
        pass
    return ""


def _gpt_header(g, sector, disk_size):
    data = _bytes(g.pread_device("/dev/sda", 512, sector * 512))
    if len(data) != 512 or data[:8] != b"EFI PART":
        raise ValueError("Missing GPT header")
    length, expected = struct.unpack_from("<II", data, 12)
    if not 92 <= length <= 512:
        raise ValueError("Invalid GPT header length")
    header = bytearray(data[:length])
    header[16:20] = bytes(4)
    if zlib.crc32(header) != expected:
        raise ValueError("GPT header checksum failed")
    current, backup, first, last = struct.unpack_from("<QQQQ", data, 24)
    entry_sector, count, entry_size, checksum = struct.unpack_from("<QIII", data, 72)
    if (current != sector or backup >= disk_size // 512 or not 0 < count <= 4096
            or entry_size < 128 or entry_size % 128 or count * entry_size > MIB
            or entry_sector * 512 + count * entry_size > disk_size):
        raise ValueError("Invalid GPT header or partition-array bounds")
    entries = _bytes(g.pread_device("/dev/sda", count * entry_size, entry_sector * 512))
    if len(entries) != count * entry_size or zlib.crc32(entries) != checksum:
        raise ValueError("GPT partition-array checksum failed")
    used = {index + 1 for index in range(count) if entries[index * entry_size:index * entry_size + 16] != bytes(16)}
    return {"current": current, "backup": backup, "first": first, "last": last,
            "entry_sector": entry_sector, "entry_bytes": count * entry_size, "entry_size": entry_size,
            "count": count, "used": used, "entries": entries, "guid": data[56:72].hex()}


def _fat32(g, device):
    data = _bytes(g.pread_device(device, 512, 0))
    return (len(data) == 512 and data[510:] == b"\x55\xaa"
            and struct.unpack_from("<H", data, 11)[0] in {512, 1024, 2048, 4096}
            and data[13] in {1, 2, 4, 8, 16, 32, 64, 128}
            and struct.unpack_from("<H", data, 17)[0] == 0
            and struct.unpack_from("<H", data, 22)[0] == 0
            and struct.unpack_from("<I", data, 36)[0] > 0)


def inspect_layout(g) -> dict:
    """Read table integrity and ESP capacity before any OS mount is made."""
    result = {"partition_table": "unknown", "sector_size": 0, "disk_size": 0,
              "partitions": [], "free_slot": None, "hybrid": False,
              "boot_code_sha256": None, "disk_identity": None, "errors": []}
    errors = result["errors"]
    try:
        if g.mountpoints():
            raise ValueError("Migration layout inspection requires an unmounted appliance")
        result["disk_size"] = size = g.blockdev_getsize64("/dev/sda")
        result["sector_size"] = g.blockdev_getss("/dev/sda")
        if result["sector_size"] != 512:
            raise ValueError("Migration supports 512-byte logical sectors only")
        table = g.part_get_parttype("/dev/sda")
        table = "msdos" if table in {"mbr", "msdos"} else table
        result["partition_table"] = table
        if table not in {"gpt", "msdos"}:
            raise ValueError("Only existing GPT or simple MBR partition tables can be migrated")
        mbr = _bytes(g.pread_device("/dev/sda", 512, 0))
        if len(mbr) != 512 or mbr[510:] != b"\x55\xaa":
            raise ValueError("Invalid disk boot-sector signature")
        result["boot_code_sha256"] = hashlib.sha256(mbr[:440]).hexdigest()
        entries = [mbr[446 + index * 16:462 + index * 16] for index in range(4)]
        used_mbr = {index + 1: entry for index, entry in enumerate(entries) if entry[4]}
        parts = g.part_list("/dev/sda")
        if table == "gpt":
            result["hybrid"] = len(used_mbr) != 1 or next(iter(used_mbr.values()))[4] != 0xEE
            if result["hybrid"]:
                raise ValueError("Hybrid or nonstandard protective MBR is not safe to migrate")
            primary = _gpt_header(g, 1, size)
            backup = _gpt_header(g, size // 512 - 1, size)
            if (primary["backup"] != backup["current"] or backup["backup"] != 1
                    or primary["entries"] != backup["entries"] or primary["guid"] != backup["guid"]
                    or (primary["count"], primary["entry_size"]) != (backup["count"], backup["entry_size"])
                    or (primary["first"], primary["last"]) != (backup["first"], backup["last"])
                    or primary["used"] != {part["part_num"] for part in parts}):
                raise ValueError("GPT copies or partition inventory disagree")
            if (not 2 <= primary["entry_sector"] < primary["first"] <= primary["last"] < backup["entry_sector"] < backup["current"]
                    or primary["entry_sector"] * 512 + primary["entry_bytes"] > primary["first"] * 512
                    or backup["entry_sector"] * 512 + backup["entry_bytes"] > backup["current"] * 512
                    or any(part["part_start"] < primary["first"] * 512 or part["part_end"] >= (primary["last"] + 1) * 512 for part in parts)):
                raise ValueError("GPT partitions or metadata overlap the usable disk boundaries")
            result["disk_identity"] = primary["guid"]
            result["end_guard_bytes"] = ((primary["entry_bytes"] + 512 + MIB - 1) // MIB) * MIB
            result["free_slot"] = next((number for number in range(1, primary["count"] + 1) if number not in primary["used"]), None)
        else:
            if any(entry[4] in {0x05, 0x0F, 0x85, 0xEE} for entry in used_mbr.values()):
                raise ValueError("Extended, logical, or hybrid MBR layouts are not supported")
            if set(used_mbr) != {part["part_num"] for part in parts}:
                raise ValueError("MBR and inspected partition inventory disagree")
            result["disk_identity"] = mbr[440:444].hex()
            result["free_slot"] = next((number for number in range(1, 5) if number not in used_mbr), None)
        end = 0
        for part in sorted(parts, key=lambda value: value["part_start"]):
            number = part["part_num"]
            device = f"/dev/sda{number}"
            start, stop = part["part_start"], part["part_end"]
            if start < max(512, end) or start % 512 or (stop + 1) % 512 or stop >= size or stop < start:
                raise ValueError("Overlapping or invalid partition boundaries")
            end = stop + 1
            if table == "gpt":
                kind = g.part_get_gpt_type("/dev/sda", number).lower()
            else:
                kind = used_mbr[number][4]
                entry_start, entry_size = struct.unpack_from("<II", used_mbr[number], 8)
                if (entry_start * 512, (entry_start + entry_size) * 512) != (start, stop + 1):
                    raise ValueError("MBR partition geometry disagrees with inspection")
            try:
                fs = g.vfs_type(device)
            except RuntimeError:
                fs = "unknown"
            item = {"number": number, "device": device, "start": start, "end": stop,
                    "size": stop - start + 1, "type": kind, "filesystem": fs}
            if table == "gpt":
                offset = (number - 1) * primary["entry_size"]
                item["partition_guid"] = primary["entries"][offset + 16:offset + 32].hex()
                item["attributes"] = struct.unpack_from("<Q", primary["entries"], offset + 48)[0]
                if kind == EFI_GUID and item["attributes"] & 2:
                    errors.append(f"ESP {device} is marked unavailable for firmware discovery")
            if table == "msdos":
                item["active"] = used_mbr[number][0]
                if item["active"] not in {0, 0x80}:
                    errors.append(f"Invalid MBR active flag on {device}")
            try:
                item["uuid"] = g.vfs_uuid(device) if fs != "unknown" else None
            except RuntimeError:
                item["uuid"] = None
            if "crypt" in fs.lower() or "luks" in fs.lower() or "bitlocker" in fs.lower():
                errors.append(f"Encrypted partition {device} is not supported for firmware migration")
            if kind in {EFI_GUID, 0xEF}:
                item["fat32"] = fs in {"vfat", "fat", "msdos"} and _fat32(g, device)
                if item["fat32"]:
                    try:
                        g.mount_ro(device, "/")
                        stats = g.statvfs("/")
                        item["free_bytes"] = stats["bavail"] * stats["frsize"]
                    finally:
                        g.umount_all()
            result["partitions"].append(item)
    except (RuntimeError, ValueError) as exc:
        errors.append(str(exc))
    return result


def inspect_prerequisites(g, root, partitions, layout) -> dict:
    """Collect migration prerequisites without executing guest programs."""
    tools = {name: next((f"{directory}/{name}" for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin") if g.is_file(f"{directory}/{name}")), None) for name in TOOLS}
    errors = []
    boot = next((part for part in partitions if part.get("mountpoint") == "/boot"), None)
    if boot is None:
        boot = next((part for part in partitions if part.get("mountpoint") == "/"), {})
    if boot.get("filesystem") not in {"ext2", "ext3", "ext4", "xfs"}:
        errors.append("Migration requires an ext2/3/4 or XFS filesystem containing /boot")
    boot_uuid = boot.get("uuid")
    if not boot_uuid or not re.fullmatch(r"[A-Za-z0-9-]+", boot_uuid):
        errors.append("The boot filesystem needs a stable, readable UUID")
    elif len({part["device"] for part in partitions if part.get("uuid") == boot_uuid}) != 1:
        errors.append("The boot filesystem UUID is duplicated or ambiguous")
    kernel_paths = g.glob_expand("/boot/vmlinuz-*")
    kernels = []
    for path in kernel_paths:
        version = path.removeprefix("/boot/vmlinuz-")
        if version.startswith("0-rescue-"):
            continue
        config = _read(g, "/boot/config-" + version)
        initrd = next((name for name in (f"/boot/initramfs-{version}.img", f"/boot/initrd.img-{version}", f"/boot/initrd-{version}") if g.is_file(name)), None)
        kernels.append({"path": path, "efi": bool(re.search(r"^CONFIG_EFI=y$", config, re.M)
                        and re.search(r"^CONFIG_EFI_STUB=y$", config, re.M)), "initrd": initrd})
    paths = ("/boot", "/boot/efi", "/etc/fstab", "/boot/grub", "/boot/grub2")
    if any(g.is_symlink(path) for path in paths):
        errors.append("Migration does not follow symlinks at /boot, ESP, GRUB directories, or fstab")
    esp_mount = next((part for part in partitions if part.get("mountpoint") == "/boot/efi"), None)
    esp_candidates = [part for part in layout.get("partitions", []) if part.get("type") in {EFI_GUID, 0xEF}]
    if esp_mount and not any(part["device"] == esp_mount["device"] for part in esp_candidates):
        errors.append("/boot/efi is mounted from a partition that is not an ESP")
    if not esp_mount and g.is_dir("/boot/efi") and g.ls("/boot/efi"):
        errors.append("Unmounted /boot/efi contains files; resolve this ambiguous mountpoint before migration")
    if g.exists("/boot/efi") and not g.is_dir("/boot/efi"):
        errors.append("/boot/efi is not a directory")
    for part in partitions:
        if any(esp["device"] == part["device"] for esp in esp_candidates) and part.get("mountpoint") not in {None, "/boot/efi"}:
            errors.append("An existing ESP uses a mountpoint other than /boot/efi")
    fstab = _read(g, "/etc/fstab")
    if not fstab:
        errors.append("A readable /etc/fstab is required")
    esp_lines = [line.split() for line in fstab.splitlines() if line.strip() and not line.lstrip().startswith("#")
                 and len(line.split()) >= 2 and line.split()[1] == "/boot/efi"]
    if len(esp_lines) > 1:
        errors.append("Multiple /boot/efi entries in fstab are ambiguous")
    if esp_lines:
        allowed_sources = {part["device"] for part in esp_candidates} | {"UUID=" + part["uuid"] for part in esp_candidates if part.get("uuid")}
        if esp_lines[0][0] not in allowed_sources:
            errors.append("The existing /boot/efi fstab entry does not identify the reusable ESP")
    commandline = "\n".join(line for line in _read(g, "/etc/default/grub").splitlines()
                              if re.match(r"^\s*GRUB_CMDLINE_LINUX(?:_DEFAULT)?=", line))
    commandline += "\n" + "\n".join(line for path in g.glob_expand("/boot/loader/entries/*.conf")
                                   for line in _read(g, path).splitlines() if re.match(r"^\s*options\s", line))
    if re.search(r"(?:^|[\s\"'])noefi(?:$|[\s\"'])", commandline):
        errors.append("Remove the noefi kernel argument before requesting UEFI migration")
    return {"tools": tools, "major": g.inspect_get_major_version(root),
            "efi_modules": all(g.is_file("/usr/lib/grub/x86_64-efi/" + name) for name in ("modinfo.sh", "normal.mod", "linux.mod")),
            "kernels": kernels, "boot_uuid": boot_uuid,
            "boot_path": "/grub2/grub.cfg" if boot.get("mountpoint") == "/boot" else "/boot/grub2/grub.cfg",
            "esp_candidates": esp_candidates, "errors": errors}


def plan_migration(inspection: dict, options: dict | None, allow_network=False) -> dict:
    requested = bool(options and options.get("enabled"))
    result = {"requested": requested, "ready_to_migrate": False, "blockers": [], "warnings": [],
              "changes": [], "layout": {}, "growth_bytes": 0, "requires_packages": []}
    if not requested:
        return result
    options = options or {}
    blockers, warnings, changes = result["blockers"], result["warnings"], result["changes"]
    size_mib = options.get("esp_size_mib", 512)
    if isinstance(size_mib, bool) or not isinstance(size_mib, int) or not 512 <= size_mib <= 2048:
        blockers.append("New ESP size must be an integer from 512 through 2048 MiB")
        return result
    from .architecture import normalize_arch, execution_blocker
    arch = normalize_arch(inspection.get("os", {}).get("arch"))
    supported = (inspection.get("boot") or {}).get("supported_firmware", [])
    if arch == "aarch64":
        matching = (normalize_arch(inspection.get("boot", {}).get("architecture")) == arch
                    and any(normalize_arch(loader.get("architecture")) == arch
                            for loader in inspection.get("boot", {}).get("efi_loaders", [])))
        if "UEFI_64" in supported and matching:
            result.update(ready_to_migrate=True, layout={"action": "already_uefi", "preserve_bios": False})
            changes.append("The image already has verified ARM64 UEFI support; no firmware migration is needed")
        else:
            blockers.append("ARM64 requires an existing matching ARM64 UEFI bootloader. Automated BIOS-to-UEFI migration is supported only for x86_64, not ARM64.")
        return result
    if arch != "x86_64":
        blockers.append("UEFI migration supports x86_64 Linux only; it does not convert CPU architectures")
    if "UEFI_64" in supported and not blockers:
        result.update(ready_to_migrate=True, layout={"action": "already_uefi", "preserve_bios": "BIOS" in supported})
        changes.append("The image already has verified UEFI support; no firmware migration is needed")
        return result
    blocker = execution_blocker(arch)
    if blocker:
        blockers.append(blocker)
    if "BIOS" not in supported:
        blockers.append("Migration requires verified installed BIOS boot support; refresh inspection or repair the source boot chain")
    evidence = inspection.get("uefi_migration") or {}
    layout, guest = evidence.get("layout", {}), evidence.get("guest", {})
    if evidence.get("version") != 1:
        blockers.append("Migration prerequisites are missing; refresh inspection")
    blockers.extend(layout.get("errors", []))
    blockers.extend(guest.get("errors", []))
    distro = inspection.get("os", {}).get("distro")
    tools = guest.get("tools", {})
    family = "debian" if distro in {"debian", "ubuntu"} else "rpm" if distro in RPM_VENDORS else None
    if not family:
        blockers.append("Automated migration supports Debian, Ubuntu, EL9/10 derivatives, and Fedora 34 or newer")
    if family == "rpm" and not ((distro == "fedora" and guest.get("major", 0) >= 34) or (distro != "fedora" and guest.get("major") in {9, 10})):
        blockers.append("RPM migration requires EL9/10 or Fedora 34+; older EFI configuration layouts are not supported")
    result["family"] = family
    result["vendor"] = RPM_VENDORS.get(distro)
    kernels = guest.get("kernels", [])
    if not kernels or any(not kernel.get("efi") or not kernel.get("initrd") for kernel in kernels):
        blockers.append("Every installed non-rescue kernel needs CONFIG_EFI=y, CONFIG_EFI_STUB=y, and an initramfs")
    packages = []
    if family == "debian":
        if not guest.get("efi_modules") or not all(tools.get(name) for name in ("grub-install", "grub-mkconfig", "grub-script-check")):
            packages = ["grub-efi-amd64-bin", "grub2-common"]
        if packages and not tools.get("apt-get"):
            blockers.append("Installing Debian EFI bootloader packages requires apt-get inside the guest")
    elif family == "rpm":
        # RPM distributions install their EFI executables via package payloads.
        # Reinstall after mounting the ESP also handles packages already present
        # in the BIOS source, avoiding grub2-install's unsupported EFI workflow.
        packages = ["grub2-efi-x64", "grub2-common", "grub2-tools"]
        if not tools.get("rpm") or not tools.get("dnf"):
            blockers.append("RPM migration requires rpm and dnf inside the guest")
    result["requires_packages"] = packages
    if packages and not (options.get("install_packages") is True and allow_network):
        blockers.append("This migration requires guest package installation; enable migration package installation and guest network access")
    candidates = guest.get("esp_candidates", [])
    disk_size = inspection.get("virtual_size", 0)
    selected = {"action": "blocked", "partition_table": layout.get("partition_table", "unknown"),
                "esp_device": None, "esp_size_mib": size_mib, "disk_size_before": disk_size,
                "disk_size_after": disk_size, "start_sector": None, "end_sector": None, "preserve_bios": True}
    if len(candidates) > 1:
        blockers.append("Multiple existing ESPs make migration ambiguous")
    elif candidates:
        esp = candidates[0]
        if not esp.get("fat32") or esp.get("free_bytes", 0) < 64 * MIB:
            blockers.append("Existing ESP must be FAT32 with at least 64 MiB free; it will not be reformatted")
        else:
            selected.update(action="reuse", esp_device=esp["device"], esp_size_mib=esp["size"] // MIB)
            changes.append(f"Reuse {esp['device']} without formatting it; preserve replaced EFI files in a guest backup directory")
    elif layout.get("free_slot") and layout.get("partition_table") in {"gpt", "msdos"}:
        # Append beyond the original disk end, including its former GPT backup.
        start = ((disk_size + MIB - 1) // MIB) * MIB
        after = start + size_mib * MIB + max(MIB, layout.get("end_guard_bytes", MIB))
        if layout["partition_table"] == "msdos" and after // 512 > 0xFFFFFFFF:
            blockers.append("Appending this ESP would exceed the MBR 2 TiB addressing limit")
        selected.update(action="append", esp_device=f"/dev/sda{layout['free_slot']}", start_sector=start // 512,
                        end_sector=(start + size_mib * MIB) // 512 - 1, disk_size_after=after)
        result["growth_bytes"] = after - disk_size
        changes.append(f"Grow the working disk by {result['growth_bytes'] // MIB} MiB and append a {size_mib} MiB FAT32 ESP; existing partition boundaries remain fixed")
    else:
        blockers.append("No reusable ESP or free primary/GPT partition slot is available")
    if selected["disk_size_after"] > int(os.getenv("FORGE_MAX_VIRTUAL_GIB", "2048")) * GIB:
        blockers.append("Migration would exceed the configured virtual disk size limit")
    result["layout"] = selected
    if family == "debian":
        changes.append("Install x86_64 EFI GRUB at EFI/BOOT/BOOTX64.EFI using grub-install --no-nvram --removable; retain BIOS GRUB")
    elif family == "rpm":
        changes.append("Install RPM-provided EFI GRUB, verify package ownership, and create the fallback loader with UUID-based GRUB forwarding configuration")
    changes.append("Mount the ESP by UUID in fstab and regenerate and validate the guest GRUB configuration")
    warnings.extend(["Secure Boot is not configured; boot the migrated image with Secure Boot disabled",
                     "This preview uses the current image. Storage and package edits run first; migration is replanned and final disk size or ESP location can change",
                     "The existing partition-table type is retained; the destination cloud must support it",
                     "Firmware NVRAM is not modified. Validate a UEFI test launch after export",
                     "Future bootloader package upgrades may require refreshing the EFI fallback loader"])
    result["ready_to_migrate"] = not blockers
    return result


def _preserved(before, after):
    """Partition identity and BIOS stage 1 must survive the append unchanged."""
    if after.get("errors") or before.get("partition_table") != after.get("partition_table"):
        return False
    if any(before.get(key) != after.get(key) for key in ("boot_code_sha256", "disk_identity")):
        return False
    current = {part["number"]: part for part in after["partitions"]}
    return all(part["number"] in current and all(part.get(key) == current[part["number"]].get(key)
               for key in ("device", "start", "end", "type", "uuid", "active", "partition_guid", "attributes")) for part in before["partitions"])


def _safe_directory(g, path):
    from .engine import EngineError
    current = ""
    for part in path.strip("/").split("/"):
        current += "/" + part
        if g.is_symlink(current) or (g.exists(current) and not g.is_dir(current)):
            raise EngineError(f"Unsafe migration directory: {current}")
    g.mkdir_p(path)


def _fstab_with_esp(content, uuid):
    from .engine import EngineError
    if not re.fullmatch(r"[A-Za-z0-9-]+", uuid):
        raise EngineError("The ESP filesystem UUID is invalid")
    lines, replaced = [], False
    for line in content.splitlines():
        fields = line.split()
        if fields and not fields[0].startswith("#") and len(fields) >= 2 and fields[1] == "/boot/efi":
            if replaced:
                raise EngineError("Multiple /boot/efi entries in fstab are ambiguous")
            line = f"UUID={uuid} /boot/efi vfat umask=0077 0 2"
            replaced = True
        lines.append(line)
    if not replaced:
        lines.append(f"UUID={uuid} /boot/efi vfat umask=0077 0 2")
    return "\n".join(lines) + "\n"


def _forward_config(uuid, path):
    if not re.fullmatch(r"[A-Za-z0-9-]+", uuid) or path not in {"/grub2/grub.cfg", "/boot/grub2/grub.cfg"}:
        raise ValueError("Unsafe GRUB boot filesystem identity")
    directory = path.rsplit("/", 1)[0]
    return (f"search --no-floppy --fs-uuid --set=forge_boot {uuid}\n"
            f"set prefix=($forge_boot){directory}\n"
            "export prefix\nconfigfile $prefix/grub.cfg\n")


def _install_script(plan):
    if plan["family"] == "debian":
        return ("set -eu\n"
                "test -f /usr/lib/grub/x86_64-efi/modinfo.sh\n"
                "set --\n"
                "if grub-install --help | grep -q -- --no-uefi-secure-boot; then set -- --no-uefi-secure-boot; fi\n"
                "grub-install --target=x86_64-efi --efi-directory=/boot/efi --boot-directory=/boot --no-nvram --removable \"$@\"\n"
                "grub-mkconfig -o /boot/grub/grub.cfg\n"
                "grub-script-check /boot/grub/grub.cfg\n"
                "test -s /boot/efi/EFI/BOOT/BOOTX64.EFI\n")
    loader = "/boot/efi/EFI/" + plan["vendor"] + "/grubx64.efi"
    return ("set -eu\n"
            "dnf -y install grub2-efi-x64 grub2-common grub2-tools\n"
            "dnf -y reinstall grub2-efi-x64 grub2-common\n"
            f"test \"$(rpm -qf --qf '%{{NAME}}' {shlex.quote(loader)})\" = grub2-efi-x64\n"
            "rpm -V --nomtime --nomode --nouser --nogroup grub2-efi-x64\n"
            "grub2-mkconfig -o /boot/grub2/grub.cfg\n"
            "grub2-script-check /boot/grub2/grub.cfg\n")


def _verify_configuration(g, plan, before, esp_uuid):
    from .engine import EngineError
    config_path = "/boot/grub/grub.cfg" if plan["family"] == "debian" else "/boot/grub2/grub.cfg"
    config = _read(g, config_path)
    if not config or re.search(r"^\s*(?:linux16|initrd16)\s", config, re.M):
        raise EngineError("Generated GRUB configuration is missing or contains BIOS-only linux16/initrd16 commands")
    if not re.search(r"\bmenuentry\b|\bblscfg\b", config):
        raise EngineError("Generated GRUB configuration contains no Linux boot entries")
    if re.search(r"\bblscfg\b", config):
        entries = g.glob_expand("/boot/loader/entries/*.conf")
        if not entries or not any(re.search(r"^linux\s+", _read(g, path), re.M) for path in entries):
            raise EngineError("GRUB requests BLS entries but no Linux BLS entries exist")
    fallback = "/boot/efi/EFI/BOOT/BOOTX64.EFI"
    if _pe_application(g, fallback)["architecture"] != "x86_64":
        raise EngineError("Migration did not produce a valid x86_64 EFI fallback application")
    active = [line.split() for line in _read(g, "/etc/fstab").splitlines()
              if line.strip() and not line.lstrip().startswith("#")]
    if not any(len(fields) >= 3 and fields[:3] == ["UUID=" + esp_uuid, "/boot/efi", "vfat"] for fields in active):
        raise EngineError("The migrated ESP is not mounted by its current filesystem UUID")
    if plan["family"] == "rpm":
        expected = _forward_config(before["uefi_migration"]["guest"]["boot_uuid"], before["uefi_migration"]["guest"]["boot_path"])
        for path in (f"/boot/efi/EFI/{plan['vendor']}/grub.cfg", "/boot/efi/EFI/BOOT/grub.cfg"):
            if _read(g, path) != expected:
                raise EngineError("EFI GRUB forwarding configuration does not match the boot filesystem")


def migrate(work: Path, inspection: dict, options: dict, allow_network: bool, log) -> dict:
    """Apply a validated plan to a standalone working copy and verify its result."""
    from .engine import EngineError, ImageEngine, _guest, _mount, _roots, _run, _write_guest
    plan = plan_migration(inspection, options, allow_network)
    if not plan["requested"]:
        return {"inspection": inspection, "plan": plan, "warnings": []}
    if not plan["ready_to_migrate"]:
        raise EngineError("UEFI migration blocked: " + " ".join(plan["blockers"]))
    if plan["layout"]["action"] == "already_uefi":
        return {"inspection": inspection, "plan": plan, "warnings": []}
    baseline = inspection["uefi_migration"]["layout"]
    selected = plan["layout"]
    with _guest(work, "qcow2") as g:
        fresh = inspect_layout(g)
        if not _preserved(baseline, fresh) or fresh["disk_size"] != selected["disk_size_before"]:
            raise EngineError("Disk layout changed after migration planning")
    if selected["action"] == "append":
        log(f"Growing the working disk and appending {selected['esp_size_mib']} MiB for the EFI System Partition")
        _run(["qemu-img", "resize", "-f", "qcow2", str(work), str(selected["disk_size_after"])], log)
    backup = "/var/lib/cloud-image-forge/uefi-backups/" + uuid4().hex
    with _guest(work, "qcow2", readonly=False) as g:
        if selected["action"] == "append":
            if selected["partition_table"] == "gpt":
                g.part_expand_gpt("/dev/sda")
            before_numbers = {part["part_num"] for part in g.part_list("/dev/sda")}
            g.part_add("/dev/sda", "p", selected["start_sector"], selected["end_sector"])
            added = [part for part in g.part_list("/dev/sda") if part["part_num"] not in before_numbers]
            if (len(added) != 1 or f"/dev/sda{added[0]['part_num']}" != selected["esp_device"]
                    or added[0]["part_start"] != selected["start_sector"] * 512
                    or added[0]["part_end"] != (selected["end_sector"] + 1) * 512 - 1):
                raise EngineError("The newly added ESP does not match the migration plan; nothing was formatted")
            number = added[0]["part_num"]
            if selected["partition_table"] == "gpt":
                g.part_set_gpt_type("/dev/sda", number, EFI_GUID)
                g.part_set_name("/dev/sda", number, "EFI System Partition")
            else:
                g.part_set_mbr_id("/dev/sda", number, 0xEF)
            # dosfstools selects FAT32 for a full >=512 MiB volume; verify the
            # created BPB rather than assuming a particular tool's default.
            g.mkfs("vfat", selected["esp_device"], label="FORGE_EFI")
            if not _fat32(g, selected["esp_device"]):
                raise EngineError("The newly created ESP is not FAT32")
        if not _preserved(baseline, inspect_layout(g)):
            raise EngineError("Appending the ESP changed an existing partition or BIOS boot code")
        root = _roots(g)
        _mount(g, root, False)
        _safe_directory(g, backup)
        g.cp_a("/etc/fstab", backup + "/fstab")
        _safe_directory(g, "/boot/efi")
        mounted = g.mountpoints()
        if selected["esp_device"] not in mounted:
            g.mount(selected["esp_device"], "/boot/efi")
        elif mounted[selected["esp_device"]] != "/boot/efi":
            raise EngineError("The ESP is mounted at an unexpected location")
        if g.is_dir("/boot/efi/EFI"):
            g.cp_a("/boot/efi/EFI", backup + "/EFI")
        for directory in ("/boot/grub", "/boot/grub2"):
            if g.is_file(directory + "/grub.cfg"):
                g.cp_a(directory + "/grub.cfg", backup + "/" + directory.rsplit("/", 1)[1] + ".cfg")
        esp_uuid = g.vfs_uuid(selected["esp_device"])
        _write_guest(g, "/etc/fstab", _fstab_with_esp(_read(g, "/etc/fstab"), esp_uuid))
    log("Installing guest EFI bootloader files without firmware NVRAM changes")
    command = ["virt-customize", "--format", "qcow2", "-a", str(work), "--network" if allow_network else "--no-network"]
    if plan["family"] == "debian" and plan["requires_packages"]:
        command += ["--install", ",".join(plan["requires_packages"])]
    command += ["--run-command", _install_script(plan), "--selinux-relabel"]
    _run(command, log)
    with _guest(work, "qcow2", readonly=False) as g:
        _mount(g, _roots(g), False)
        if plan["family"] == "rpm":
            loader = f"/boot/efi/EFI/{plan['vendor']}/grubx64.efi"
            if _pe_application(g, loader)["architecture"] != "x86_64":
                raise EngineError("The RPM-provided GRUB loader is not an x86_64 EFI application")
            _safe_directory(g, "/boot/efi/EFI/BOOT")
            g.cp_a(loader, "/boot/efi/EFI/BOOT/BOOTX64.EFI")
            guest = inspection["uefi_migration"]["guest"]
            forward = _forward_config(guest["boot_uuid"], guest["boot_path"])
            g.write(f"/boot/efi/EFI/{plan['vendor']}/grub.cfg", forward.encode())
            g.write("/boot/efi/EFI/BOOT/grub.cfg", forward.encode())
        _verify_configuration(g, plan, inspection, esp_uuid)
    after = ImageEngine().inspect(work)
    if not _preserved(baseline, after.get("uefi_migration", {}).get("layout", {})):
        raise EngineError("Migration verification found changed original disk structures")
    supported = after.get("boot", {}).get("supported_firmware", [])
    if "UEFI_64" not in supported or "BIOS" not in supported:
        raise EngineError("Migration must preserve verified BIOS support and add verified UEFI support")
    if not any(loader.get("fallback") and loader.get("device") == selected["esp_device"] for loader in after["boot"].get("efi_loaders", [])):
        raise EngineError("Final migration inspection did not find the installed EFI fallback loader")
    log("UEFI fallback, GRUB configuration, ESP mount, and preserved BIOS structures verified offline")
    return {"inspection": after, "plan": plan, "warnings": plan["warnings"] + ["Migration backups are stored in " + backup]}
