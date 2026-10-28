"""Offline filesystem rebuild into a new disk; never truncate an XFS/PV/LV.

Supported layouts deliberately exclude BIOS boot code, complex LVM, encryption,
and unaccounted partitions. Filesystem UUIDs and GPT identifiers are retained;
new simple LVM containers retain names but receive new internal LVM identifiers.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
from uuid import UUID

from .architecture import SUPPORTED_ARCHES, normalize_arch
from .boot import EFI_GUID

MIB = 1024 ** 2
GIB = 1024 ** 3
LVM_GUID = "e6d6d379-f507-44c2-a23c-238f2a3df928"
LINUX_GUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"
FILESYSTEMS = {"xfs", "ext2", "ext3", "ext4"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,126}\Z")
ARCHIVE_OPTIONS = {"compress": "gzip", "xattrs": True, "selinux": True, "acls": True}
QUOTA_OPTIONS = {"quota", "qnoenforce", "uquota", "usrquota", "uqnoenforce", "gquota", "grpquota",
                 "gqnoenforce", "pquota", "prjquota", "pqnoenforce", "usrjquota", "grpjquota", "jqfmt"}


class StorageError(RuntimeError):
    pass


def _ceil(value, unit=MIB):
    return ((int(value) + unit - 1) // unit) * unit


def _matching_arm_efi(boot, arch):
    return arch != "aarch64" or (
        normalize_arch(boot.get("architecture", arch)) == arch
        and any(normalize_arch(loader.get("architecture")) == arch
                for loader in boot.get("efi_loaders", []))
    )


def _minimum(used, filesystem):
    """An admission estimate; actual expanded archive sizes are checked later."""
    return max(512 if filesystem == "xfs" else 128,
               _ceil(int(used * 1.25) + 256 * MIB) // MIB)


def _read(g, path, limit=2 * MIB):
    if not g.is_file(path):
        return ""
    if g.filesize(path) > limit:
        raise StorageError(f"Configuration {path} is too large to validate")
    value = g.read_file(path)
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _active(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _quota_options(value):
    return {option.partition("=")[0] for option in value.split(",")} & QUOTA_OPTIONS


def _configured_quotas(g):
    """Check actual mount option fields and persistent rootflags arguments."""
    for line in _active(_read(g, "/etc/fstab")).splitlines():
        fields = line.split()
        if len(fields) >= 4 and _quota_options(fields[3]):
            return True
    arguments = []
    for line in _active(_read(g, "/etc/default/grub")).splitlines():
        match = re.match(r"\s*(?:export\s+)?GRUB_CMDLINE_LINUX(?:_DEFAULT)?\s*=(.*)", line)
        if match:
            arguments.append(match[1])
    arguments.append(_active(_read(g, "/etc/kernel/cmdline")))
    for path in g.glob_expand("/boot/loader/entries/*.conf"):
        arguments.extend(match[1] for line in _active(_read(g, path)).splitlines()
                         if (match := re.match(r"\s*options\s+(.*)", line)))
    for path in ("/boot/grub/grubenv", "/boot/grub2/grubenv"):
        arguments.extend(match[1] for line in _active(_read(g, path)).splitlines()
                         if (match := re.match(r"\s*(?:kernelopts|tuned_params)=(.*)", line)))
    for path in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"):
        arguments.extend(match[1] for line in _active(_read(g, path)).splitlines()
                         if (match := re.match(r"\s*(?:linux|linuxefi|linux16)\s+(.*)", line)))
    for text in arguments:
        for match in re.finditer(r"(?:^|[\s\"'])rootflags=(?:\"([^\"]*)\"|'([^']*)'|([^\s\"']+))", text):
            if _quota_options(next(value for value in match.groups() if value is not None)):
                return True
    return False


def _inspect_initrd_lvm(g, identifiers, errors, warnings):
    """Known pins block; unavailable/early-microcode-only parsing is disclosed."""
    results = []
    paths = sorted({path for pattern in ("/boot/initramfs-*.img", "/boot/initrd.img-*", "/boot/initrd-*")
                    for path in g.glob_expand(pattern) if "rescue" not in path})
    if not paths:
        warnings.append("No existing initramfs was found for LVM identity checks; boot readiness is unverified and requires a UEFI test launch.")
    for path in paths:
        record = {"path": path, "status": "unavailable", "checked_files": []}
        results.append(record)
        try:
            names = {str(PurePosixPath(name)): name for name in g.initrd_list(path)}
        except RuntimeError:
            names = {}
        if not set(names) & {"init", "usr/lib/systemd/systemd", "lib/systemd/systemd"}:
            warnings.append(f"Cannot fully inspect embedded LVM metadata in {path}; its bytes will be preserved, and a UEFI boot test is required before use.")
            continue
        record["status"] = "checked"
        wanted = [name for name in names if name in {"etc/lvm/lvm.conf", "etc/lvm/lvmlocal.conf", "etc/fstab", "etc/cmdline"}
                  or name.startswith(("etc/lvm/devices/", "etc/cmdline.d/"))]
        for name in sorted(wanted):
            if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
                errors.append(f"Unsafe initramfs storage configuration path in {path}")
                continue
            try:
                value = g.initrd_cat(path, names[name])
                if len(value) > 2 * MIB:
                    raise RuntimeError("metadata too large")
                text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
            except RuntimeError:
                errors.append(f"Cannot read known embedded storage configuration {name} in {path}")
                continue
            record["checked_files"].append(name)
            active = _active(text)
            if name.startswith("etc/lvm/devices/") and active.strip():
                errors.append(f"Initramfs {path} embeds an LVM devices file tied to the old PV; rebuild its storage metadata before migration")
            elif (any(identifier and identifier in active.replace("-", "") for identifier in identifiers)
                  or re.search(r"\buse_devicesfile\s*=\s*1\b", active)):
                errors.append(f"Initramfs {path} pins internal LVM identities or requires a devices file in {name}")
    return results


def inspect_storage(g, root, partitions: list[dict], layout: dict) -> dict:
    """Optional read-only evidence collector; call with the OS already mounted."""
    result = {"version": 1, "layout": deepcopy(layout), "filesystems": [],
              "lvm": {"pvs": [], "vgs": [], "lvs": []}, "errors": [], "warnings": []}
    errors = result["errors"]
    try:
        if g.list_devices() != ["/dev/sda"]:
            errors.append("Storage rebuild requires exactly one disk")
        for item in result["layout"].get("partitions", []):
            if layout.get("partition_table") == "gpt":
                item["name"] = g.part_get_name("/dev/sda", item["number"])
        lvm = result["lvm"]
        lvm["pvs"], lvm["vgs"], lvm["lvs"] = g.pvs_full(), g.vgs_full(), g.lvs_full()
        vg = lvm["vgs"][0]["vg_name"] if len(lvm["vgs"]) == 1 else None
        for lv in lvm["lvs"]:
            lv["device"] = f"/dev/{vg}/{lv['lv_name']}" if vg else None
        inventory = {item["device"]: item for item in layout.get("partitions", [])}
        for part in partitions:
            fs, device = part.get("filesystem"), part["device"]
            if fs == "LVM2_member" or device in {pv["pv_name"] for pv in lvm["pvs"]}:
                continue
            original = inventory.get(device, {})
            kind = "efi" if original.get("type") == EFI_GUID else "lv" if part.get("logical_volume") else "partition"
            editable = fs in FILESYSTEMS and kind != "efi"
            item = {**deepcopy(part), "kind": kind, "editable": editable,
                    "label": g.vfs_label(device) if fs in FILESYSTEMS | {"vfat", "fat", "msdos"} else "",
                    "minimum_size_mib": _minimum(part["used"], fs) if editable and "used" in part else None}
            if editable:
                if not part.get("mountpoint") or "used" not in part:
                    errors.append(f"Filesystem {device} is not mounted by inspection; all data filesystems must be accounted for")
                if fs == "xfs":
                    info = g.xfs_info(part.get("mountpoint") or device)
                    if info.get("xfs_logname") != "internal" or info.get("xfs_rtblocks", 0) != 0:
                        errors.append(f"{device} uses an external XFS log or realtime device")
                else:
                    info = g.tune2fs_l(device)
                    if info.get("Journal device"):
                        errors.append(f"{device} uses an external ext journal")
                    features = set(info.get("Filesystem features", "").split())
                    if features & {"encrypt", "casefold", "verity", "quota", "project"}:
                        errors.append(f"{device} uses filesystem encryption, quota, verity, project IDs, or casefolding")
            result["filesystems"].append(item)
        if _configured_quotas(g):
            errors.append("Configured filesystem quotas are not supported by file-level rebuild")
        if _active(_read(g, "/etc/projects")).strip() or _active(_read(g, "/etc/projid")).strip():
            errors.append("XFS project IDs require a dedicated migration; tar archives do not preserve them")
        if lvm["pvs"]:
            devices = g.glob_expand("/etc/lvm/devices/*")
            if any(_active(_read(g, path)).strip() for path in devices if g.is_file(path)):
                errors.append("Guest LVM devices files pin old PV identities; rebuild them and the initramfs before this storage workflow")
            config_paths = ["/etc/fstab", "/etc/default/grub", "/etc/kernel/cmdline", "/etc/crypttab", "/etc/lvm/lvm.conf",
                            "/etc/lvm/lvmlocal.conf", "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
            config_paths += g.glob_expand("/boot/loader/entries/*.conf") + g.glob_expand("/etc/dracut.conf.d/*.conf")
            esps = [item for item in result["filesystems"] if item["kind"] == "efi"]
            esp_mount = esps[0].get("mountpoint") if len(esps) == 1 else None
            if not esp_mount:
                errors.append("LVM rebuild requires the EFI partition to be mounted by inspection so its boot configuration can be checked for pinned LVM IDs")
            elif not g.is_dir(esp_mount.rstrip("/") + "/EFI"):
                errors.append("The mounted EFI partition's boot configuration directory is unreadable; LVM identity changes cannot be verified")
            else:
                config_paths += g.glob_expand(esp_mount.rstrip("/") + "/EFI/*/grub.cfg")
            config = "\n".join(_active(_read(g, path)) for path in config_paths)
            identifiers = [str(item[key]).replace("-", "") for group, key in (("pvs", "pv_uuid"), ("vgs", "vg_uuid"), ("lvs", "lv_uuid")) for item in lvm[group]]
            if any(identifier and identifier in config.replace("-", "") for identifier in identifiers):
                errors.append("Boot or mount configuration pins internal LVM UUIDs; this workflow preserves names and filesystem UUIDs only")
            if re.search(r"\buse_devicesfile\s*=\s*1\b", config):
                errors.append("Guest requires an LVM devices file; automatic LVM identity regeneration is not supported")
            result["initramfs"] = _inspect_initrd_lvm(g, identifiers, errors, result["warnings"])
        # mkfs defaults in the supported Debian appliance can enable filesystem
        # features absent from older guest kernels. Reject instead of guessing.
        versions = [re.search(r"vmlinuz-(\d+)\.(\d+)", path) for path in g.glob_expand("/boot/vmlinuz-*") if "rescue" not in path]
        if not versions or any(not match or tuple(map(int, match.groups())) < (5, 15) for match in versions):
            errors.append("Fresh filesystem creation currently requires every non-rescue guest kernel to be Linux 5.15 or newer")
    except (RuntimeError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"Cannot verify storage rebuild prerequisites: {exc}")
    return result


def _lvm_errors(lvm, partitions, filesystems):
    pvs, vgs, lvs = (lvm.get(key, []) for key in ("pvs", "vgs", "lvs"))
    pvparts = [part for part in partitions if part.get("type") == LVM_GUID]
    if not pvs and not vgs and not lvs and not pvparts:
        return []
    errors = []
    if len(pvs) != 1 or len(vgs) != 1 or len(pvparts) != 1 or not lvs:
        return ["LVM rebuild supports exactly one PV, one VG, and ordinary linear LVs"]
    pv, vg = pvs[0], vgs[0]
    if pv.get("pv_name") != pvparts[0]["device"] or pvparts[0] != partitions[-1]:
        errors.append("The single LVM PV must be the last partition on the disk")
    if (not NAME.fullmatch(vg.get("vg_name", "")) or vg.get("pv_count") != 1
            or vg.get("lv_count") != len(lvs) or vg.get("snap_count", 0) != 0
            or vg.get("vg_sysid") or vg.get("vg_tags") or vg.get("vg_fmt") != "lvm2"
            or vg.get("vg_extent_size") != 4 * MIB or not str(vg.get("vg_attr", "")).startswith("wz--n-")):
        errors.append("VG must use ordinary local LVM2, 4 MiB extents, and no tags, snapshots, or system ID")
    if pv.get("pv_fmt") != "lvm2" or pv.get("pv_tags") or "m" in str(pv.get("pv_attr", "")):
        errors.append("The LVM PV uses unsupported metadata or missing-device state")
    fsdevices = {fs["device"] for fs in filesystems if fs.get("kind") == "lv"}
    if fsdevices != {lv.get("device") for lv in lvs}:
        errors.append("Every LV must contain one inspected supported filesystem; swap and hidden volumes are unsupported")
    for lv in lvs:
        if (not NAME.fullmatch(lv.get("lv_name", "")) or not str(lv.get("lv_attr", "")).startswith("-w")
                or lv.get("seg_count", 0) < 1 or any(lv.get(key) for key in ("origin", "move_pv", "mirror_log", "modules", "lv_tags"))):
            errors.append(f"LV {lv.get('lv_name', '?')} is not an ordinary writable linear volume")
    return errors


def plan_rebuild(inspection: dict, options: dict | None, disk_size_gib=None) -> dict:
    requested = bool(options and options.get("enabled"))
    result = {"requested": requested, "ready": False, "blockers": [], "warnings": [],
              "changes": [], "layout": {}, "filesystems": [], "estimated_temporary_bytes": 0,
              "source_architecture": normalize_arch(inspection.get("os", {}).get("arch"))}
    if not requested:
        return result
    errors, warnings = result["blockers"], result["warnings"]
    storage = inspection.get("storage") or {}
    if storage.get("version") != 1:
        errors.append("Storage rebuild evidence is missing; refresh inspection")
        return result
    errors.extend(storage.get("errors", []))
    warnings.extend(storage.get("warnings", []))
    old = storage.get("layout") or {}
    errors.extend(old.get("errors", []))
    parts = deepcopy(old.get("partitions", []))
    filesystems = deepcopy(storage.get("filesystems", []))
    result["filesystems"] = filesystems
    arch = result["source_architecture"]
    if arch not in SUPPORTED_ARCHES:
        errors.append("Storage rebuild supports x86_64 and ARM64 (aarch64) Linux only")
    boot = inspection.get("boot", {})
    firmware = boot.get("supported_firmware", [])
    if "UEFI_64" not in firmware or "BIOS" in firmware:
        errors.append("Storage rebuild requires UEFI-only boot support; BIOS/dual boot code cannot be safely relocated")
    if not _matching_arm_efi(boot, arch):
        errors.append("ARM64 storage rebuild requires a detected matching AArch64 EFI loader; refresh inspection")
    if old.get("partition_table") != "gpt" or old.get("sector_size") != 512 or old.get("hybrid"):
        errors.append("Storage rebuild requires a validated GPT disk with 512-byte sectors and no hybrid MBR")
    if (not parts or [part.get("number") for part in parts] != list(range(1, len(parts) + 1))
            or parts != sorted(parts, key=lambda part: part["start"])):
        errors.append("Partitions must have contiguous numbers in disk order")
    esps = [part for part in parts if part.get("type") == EFI_GUID]
    if len(esps) != 1 or not parts or esps[0] != parts[0] or esps[0].get("filesystem") not in {"vfat", "fat", "msdos"}:
        errors.append("Exactly one FAT EFI partition must be the first partition; it is preserved byte for byte")
    if any(part.get("type") not in {EFI_GUID, LINUX_GUID, LVM_GUID} for part in parts):
        errors.append("Unknown partition types, BIOS boot partitions, and reserved data are not discarded")
    if any(part.get("attributes", 0) != 0 for part in parts):
        errors.append("Non-default GPT attribute flags require a dedicated migration")
    for part in parts:
        try:
            UUID(bytes_le=bytes.fromhex(part["partition_guid"]))
        except (KeyError, ValueError, TypeError):
            errors.append(f"Partition {part.get('device')} lacks a valid GPT identity")
    try:
        UUID(bytes_le=bytes.fromhex(old["disk_identity"]))
    except (KeyError, ValueError, TypeError):
        errors.append("Disk GPT identity is unavailable")
    errors.extend(_lvm_errors(storage.get("lvm", {}), parts, filesystems))
    known = {item["device"]: item for item in filesystems}
    if len(known) != len(filesystems) or any(part["device"] not in known and part.get("type") != LVM_GUID for part in parts):
        errors.append("Every partition and logical volume must be accounted for exactly once")
    uuids = [item.get("uuid") for item in filesystems]
    labels = [item.get("label") for item in filesystems if item.get("label")]
    if any(not uuid for uuid in uuids) or len(set(uuids)) != len(uuids) or len(set(labels)) != len(labels):
        errors.append("Filesystem UUIDs must be present and unique, and nonempty labels must be unique")
    if sum(item.get("mountpoint") == "/" for item in filesystems) != 1:
        errors.append("Exactly one rebuilt filesystem must be mounted as the guest root")
    sizes = {}
    for change in (options or {}).get("sizes", []):
        device, value = change.get("device"), change.get("size_mib")
        if device in sizes or device not in known or not known[device].get("editable"):
            errors.append(f"Size changes must name unique editable filesystems, not EFI/PV containers: {device}")
        elif isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2097152:
            errors.append(f"Invalid filesystem size for {device}")
        else:
            sizes[device] = value
    for item in filesystems:
        if item.get("kind") == "efi":
            item["selected_size_mib"] = item["size"] / MIB
            continue
        if item.get("filesystem") not in FILESYSTEMS or not item.get("editable") or item.get("minimum_size_mib") is None:
            errors.append(f"Unsupported or unmeasured filesystem on {item['device']}")
            continue
        size_mib = sizes.get(item["device"], _ceil(item["size"]) // MIB)
        if item.get("kind") == "lv":
            size_mib = _ceil(size_mib, 4)
        item["selected_size_mib"] = size_mib
        if size_mib < item["minimum_size_mib"]:
            errors.append(f"{item['device']} requires at least an estimated {item['minimum_size_mib']} MiB including restore headroom")
    try:
        raw_size = float(disk_size_gib) * GIB if disk_size_gib is not None else inspection["virtual_size"]
        if isinstance(disk_size_gib, bool) or not math.isfinite(raw_size) or not 0 < raw_size <= int(os.getenv("FORGE_MAX_VIRTUAL_GIB", "2048")) * GIB:
            raise ValueError()
        target = _ceil(int(raw_size), 512)
    except (KeyError, TypeError, ValueError, OverflowError):
        errors.append("Target virtual disk size is invalid or exceeds FORGE_MAX_VIRTUAL_GIB")
        target = 0
    if errors:
        return result
    lvs = [{"device": item["device"], "size": item["selected_size_mib"] * MIB,
            "name": item["device"].rsplit("/", 1)[1]} for item in filesystems if item["kind"] == "lv"]
    cursor = parts[0]["start"]
    planned = []
    for part in parts:
        size = part["size"] if part["type"] == EFI_GUID else sum(lv["size"] for lv in lvs) + 16 * MIB if part["type"] == LVM_GUID else known[part["device"]]["selected_size_mib"] * MIB
        start = cursor if part["type"] == EFI_GUID else _ceil(cursor)
        planned.append({**part, "start": start, "end": start + size - 1, "size": size})
        cursor = start + size
    minimum = _ceil(cursor + 2 * MIB)
    if target < minimum:
        errors.append(f"Selected filesystems require a disk of at least {minimum / GIB:.3f} GiB; target is too small")
    if planned[-1]["type"] == LVM_GUID and target >= minimum:
        planned[-1]["end"] = target - 2 * MIB - 1
        planned[-1]["size"] = planned[-1]["end"] - planned[-1]["start"] + 1
    result["layout"] = {"partition_table": "gpt", "disk_size_before": inspection["virtual_size"],
                        "disk_size_after": target, "minimum_disk_size": minimum,
                        "disk_identity": old["disk_identity"], "partitions": planned, "lvs": lvs}
    used = [item.get("used", 0) for item in filesystems if item.get("editable")]
    result["estimated_temporary_bytes"] = sum(used) * 2 + max(used, default=0) + parts[0]["size"] + 512 * MIB
    warnings.extend(["This preview is source-based; archive contents and capacity are checked again before creating the new disk.",
                     "Size minima and temporary space are estimates. Sparse/reflink files can expand during tar restore; insufficient capacity stops the build.",
                     "Filesystem layout and creation features change; quotas, project IDs, inode flags and BIOS boot-code relocation are unsupported. A UEFI boot test is still required."])
    if lvs:
        warnings.append("PV/VG/LV internal IDs are regenerated. VG/LV names, filesystem UUIDs/labels and GPT identifiers are preserved; UUID-pinned LVM configurations are blocked.")
    result["changes"] = ["Create a new GPT QCOW2 disk and preserve the original working disk until verification succeeds",
                         "Copy the EFI partition byte for byte; recreate XFS/ext filesystems and restore files, ownership, ACLs, xattrs and SELinux contexts",
                         "Verify file contents and archived metadata, filesystem identities, EFI bytes and new partition boundaries"]
    result["ready"] = not errors
    return result


def verify_rebuild(inspection: dict, plan: dict, *, expected_disk_size=None) -> dict:
    """Verify final storage identities after customization/provider alignment.

    File-content equality is checked by rebuild before intentional customization.
    This final check covers the resulting structures without undoing requested
    guest file changes. Only explicit whole-MiB/GiB capacity rounding is allowed;
    partition movement, UUID changes, or altered filesystem/LV sizes are not.
    """
    result = {"requested": bool(plan.get("requested")), "ready": False,
              "verified": False, "blockers": [], "actual_disk_size": inspection.get("virtual_size"),
              "filesystems": deepcopy(inspection.get("storage", {}).get("filesystems", []))}
    if not result["requested"]:
        result.update(ready=True)
        return result
    errors = result["blockers"]
    if not plan.get("ready") or not plan.get("layout"):
        errors.append("There is no successful storage rebuild plan to verify")
        return result
    expected = plan["layout"]
    arch = normalize_arch(inspection.get("os", {}).get("arch"))
    if arch not in SUPPORTED_ARCHES or arch != plan.get("source_architecture"):
        errors.append("Final guest architecture does not match the source storage rebuild plan")
    original_size = expected["disk_size_after"]
    desired_size = original_size if expected_disk_size is None else expected_disk_size
    if (isinstance(desired_size, bool) or not isinstance(desired_size, int)
            or desired_size not in {original_size, _ceil(original_size, MIB), _ceil(original_size, GIB)}):
        errors.append("Final disk capacity may only retain the plan or explicitly round up to a provider MiB/GiB boundary")
        return result
    evidence = inspection.get("storage") or {}
    actual = evidence.get("layout") or {}
    if evidence.get("version") != 1:
        errors.append("Final storage inspection evidence is missing")
    if actual.get("errors"):
        errors.append("Final GPT layout has inspection errors: " + " ".join(actual["errors"]))
    if (actual.get("partition_table") != "gpt" or actual.get("sector_size") != 512
            or actual.get("hybrid") or actual.get("disk_size") != desired_size
            or inspection.get("virtual_size") != desired_size):
        errors.append("Final disk geometry does not match the rebuilt disk and permitted provider alignment")
    if actual.get("disk_identity") != expected.get("disk_identity"):
        errors.append("Final disk GPT identity changed after filesystem rebuild")
    boot = inspection.get("boot", {})
    if "UEFI_64" not in boot.get("supported_firmware", []) or "BIOS" in boot.get("supported_firmware", []):
        errors.append("Final rebuilt disk no longer has UEFI-only boot support")
    if not _matching_arm_efi(boot, arch):
        errors.append("Final ARM64 disk no longer has a matching AArch64 EFI loader")
    partitions = actual.get("partitions", [])
    fields = ("number", "device", "start", "end", "size", "type", "partition_guid", "attributes", "name")
    if len(partitions) != len(expected["partitions"]):
        errors.append("Final partition inventory differs from the rebuild plan")
    else:
        cursor = 512
        for before, after in zip(expected["partitions"], partitions):
            if any(before.get(field) != after.get(field) for field in fields):
                errors.append(f"Final partition geometry or identity changed: {before['device']}")
            start, end, size = (after.get(key) for key in ("start", "end", "size"))
            if (not all(isinstance(value, int) and not isinstance(value, bool) for value in (start, end, size))
                    or start < cursor or start % 512 or (end + 1) % 512
                    or end < start or end >= desired_size - 33 * 512 or size != end - start + 1):
                errors.append(f"Final partition lies outside safe disk boundaries: {before['device']}")
            else:
                cursor = end + 1
    observed = {item["device"]: item for item in result["filesystems"]}
    expected_fs = plan["filesystems"]
    if len(observed) != len(result["filesystems"]) or set(observed) != {item["device"] for item in expected_fs}:
        errors.append("Final filesystem inventory differs from the rebuild plan")
    for before in expected_fs:
        after = observed.get(before["device"], {})
        size = before["size"] if before["kind"] == "efi" else before["selected_size_mib"] * MIB
        if after.get("size") != size or any(after.get(field) != before.get(field) for field in ("filesystem", "uuid", "label", "kind", "mountpoint")):
            errors.append(f"Final filesystem size, identity or mount changed: {before['device']}")
    expected_lvs = {item["device"]: item["size"] for item in expected["lvs"]}
    actual_lvs = evidence.get("lvm", {}).get("lvs", [])
    if (len(actual_lvs) != len(expected_lvs)
            or {item.get("device"): item.get("lv_size") for item in actual_lvs} != expected_lvs):
        errors.append("Final logical volume names or sizes differ from the rebuild plan")
    result["ready"] = result["verified"] = not errors
    return result


def _digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(4 * MIB):
            digest.update(block)
    return digest.hexdigest()


def _member_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\x00" in name:
        raise StorageError("Unsafe member path in filesystem archive")
    return str(path)


def _archive_manifest(path):
    """Read tar contents without extracting anything onto the host.

    Directory iteration can change hardlink traversal order after restore, so
    compare hardlink equivalence classes rather than which name appeared first.
    atime/ctime and inode numbers necessarily change; mtime and archive metadata
    are checked. GNU tar does not include runtime socket entries.
    """
    from decimal import Decimal

    entries, hardlinks, logical_bytes = {}, {}, 0
    with tarfile.open(path, "r|gz", encoding="utf-8", errors="surrogateescape") as archive:
        for member in archive:
            name = _member_path(member.name)
            if name in entries or name in hardlinks or len(entries) + len(hardlinks) >= 500000:
                raise StorageError("Duplicate archive member or more than 500,000 files")
            if member.islnk():
                hardlinks[name] = _member_path(member.linkname)
                continue
            item = {"type": member.type, "mode": member.mode, "uid": member.uid,
                    "gid": member.gid, "mtime": str(Decimal(str(member.mtime)).normalize()),
                    "pax": {key: value for key, value in member.pax_headers.items()
                            if "xattr" in key.lower() or "acl" in key.lower() or "selinux" in key.lower()}}
            if member.isfile():
                digest = hashlib.sha256()
                stream = archive.extractfile(member)
                if stream is None:
                    raise StorageError("Cannot read regular file from filesystem archive")
                total = 0
                while chunk := stream.read(4 * MIB):
                    digest.update(chunk)
                    total += len(chunk)
                if total != member.size:
                    raise StorageError("Truncated file in filesystem archive")
                item.update(type=b"0", size=member.size, sha256=digest.hexdigest())
                logical_bytes += member.size
            elif member.issym():
                item["linkname"] = member.linkname
            elif member.ischr() or member.isblk():
                item.update(devmajor=member.devmajor, devminor=member.devminor)
            elif not member.isdir() and not member.isfifo():
                raise StorageError(f"Unsupported archive file type for {name}")
            entries[name] = item
    groups = {}
    for name, target in hardlinks.items():
        seen = {name}
        while target in hardlinks:
            if target in seen:
                raise StorageError("Hardlink cycle in filesystem archive")
            seen.add(target)
            target = hardlinks[target]
        if target not in entries or entries[target]["type"] != b"0":
            raise StorageError("Hardlink target is missing or is not a regular file")
        groups.setdefault(target, [target]).append(name)
    for target, names in groups.items():
        item = {**entries[target], "hardlink_group": sorted(names)}
        for name in names:
            entries[name] = item
    return {"entries": entries, "logical_bytes": logical_bytes}


def _compare_manifests(expected, actual, device):
    left, right = expected["entries"], actual["entries"]
    if left.keys() != right.keys():
        raise StorageError(f"Restored file inventory differs on {device}")
    for path in left:
        if left[path] != right[path]:
            raise StorageError(f"Restored file content, links, ownership, permissions, mtime, ACLs or xattrs differ on {device}: {path}")


def _identity(g, filesystem):
    device = filesystem["device"]
    if (g.vfs_type(device) != filesystem["filesystem"]
            or g.vfs_uuid(device) != filesystem["uuid"]
            or g.vfs_label(device) != filesystem["label"]):
        raise StorageError(f"Filesystem type, UUID or label changed unexpectedly on {device}")


def _verify_layout(g, plan):
    from .uefi import inspect_layout

    actual = inspect_layout(g)
    expected = plan["layout"]
    if (actual.get("errors") or actual.get("partition_table") != "gpt"
            or actual.get("disk_size") != expected["disk_size_after"]
            or actual.get("disk_identity") != expected["disk_identity"]
            or len(actual.get("partitions", [])) != len(expected["partitions"])):
        raise StorageError("Rebuilt disk geometry or GPT identity failed verification")
    fields = ("number", "device", "start", "end", "size", "type", "partition_guid", "attributes")
    for before, after in zip(expected["partitions"], actual["partitions"]):
        if any(before.get(field) != after.get(field) for field in fields):
            raise StorageError(f"Rebuilt partition layout differs from the plan: {before['device']}")
        if g.part_get_name("/dev/sda", before["number"]) != before.get("name", ""):
            raise StorageError("Rebuilt GPT partition label changed")
    for lv in expected["lvs"]:
        if g.blockdev_getsize64(lv["device"]) != lv["size"]:
            raise StorageError(f"Rebuilt LV has an unexpected size: {lv['device']}")


def rebuild(source_work: Path, destination: Path, inspection: dict, recipe: dict, log) -> Path:
    """Return a verified new image, retaining source_work on success and failure.

    The caller may delete its disposable source after adopting the returned path.
    Only a destination exclusively created by this call is removed on failure.
    Source and destination are never attached to the same appliance (UUID/VG
    collisions would make that unsafe).
    """
    from .engine import ImageEngine, _guest, _run, _mount, _roots

    options = recipe.get("storage_rebuild")
    if not options or not options.get("enabled"):
        return Path(source_work)
    if any(recipe.get(key) for key in ("partition_changes", "expand_partition", "expand_lv")):
        raise StorageError("Filesystem rebuild cannot be combined with in-place partition or LV resize actions")
    source_work, destination = Path(source_work), Path(destination)
    if source_work.is_symlink() or not source_work.is_file():
        raise StorageError("Rebuild source must be a regular image file")
    if destination.exists() or destination.is_symlink():
        raise StorageError("Rebuild destination already exists; it will not be overwritten")
    source_work = source_work.resolve()
    destination = destination.parent.resolve() / destination.name
    if source_work == destination:
        raise StorageError("Rebuild source and destination must be different files")
    log("Refreshing storage evidence in the source working image before filesystem rebuild")
    fresh = ImageEngine().inspect(source_work)
    plan = plan_rebuild(fresh, options, recipe.get("disk_size_gib"))
    if not plan["ready"]:
        raise StorageError("Storage rebuild blocked: " + " ".join(plan["blockers"]))
    if fresh["format"] != "qcow2":
        raise StorageError("Filesystem rebuild requires the standalone QCOW2 working copy")
    source_hash = _digest(source_work)
    file_systems = plan["filesystems"]
    esp = next(item for item in file_systems if item["kind"] == "efi")
    regular = [item for item in file_systems if item["editable"]]
    needed = sum(item.get("used", 0) for item in regular) + esp["size"] + 512 * MIB
    if shutil.disk_usage(destination.parent).free < needed:
        raise StorageError("Not enough host workspace for the source archives and verification headroom")
    created = False
    try:
        with tempfile.TemporaryDirectory(prefix="storage-rebuild-", dir=destination.parent) as folder:
            staging = Path(folder)
            archives, manifests = {}, {}
            efi_raw = staging / "efi.raw"
            with _guest(source_work, "qcow2", readonly=True) as g:
                for index, filesystem in enumerate(regular):
                    device = filesystem["device"]
                    log(f"Archiving {device} separately with numeric ownership, ACLs, xattrs and SELinux contexts")
                    _identity(g, filesystem)
                    g.mount_ro(device, "/")
                    archive = staging / f"filesystem-{index}.tar.gz"
                    g.tar_out("/", str(archive), numericowner=True, **ARCHIVE_OPTIONS)
                    g.umount_all()
                    manifest = _archive_manifest(archive)
                    # guestfs tar-in expands sparse and reflink files; reject a
                    # selection that cannot contain their actual logical data.
                    minimum = _minimum(manifest["logical_bytes"], filesystem["filesystem"])
                    if filesystem["selected_size_mib"] < minimum:
                        raise StorageError(f"Expanded archive for {device} requires at least {minimum} MiB; choose a larger filesystem")
                    archives[device], manifests[device] = archive, manifest
                log(f"Copying EFI partition {esp['device']} byte for byte")
                g.download_offset(esp["device"], str(efi_raw), 0, esp["size"])
            if efi_raw.stat().st_size != esp["size"]:
                raise StorageError("EFI raw copy is truncated")
            efi_hash = _digest(efi_raw)
            needed = sum(manifest["logical_bytes"] for manifest in manifests.values()) + max((path.stat().st_size for path in archives.values()), default=0) + 512 * MIB
            if shutil.disk_usage(destination.parent).free < needed:
                raise StorageError("Not enough host workspace to restore files and verify the rebuilt disk")
            # Reserve ownership atomically so cleanup cannot remove a preexisting
            # artifact if another process creates this name during the preflight.
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            created = True
            layout = plan["layout"]
            log(f"Creating fresh GPT QCOW2 disk with {layout['disk_size_after']} virtual bytes")
            _run(["qemu-img", "create", "-f", "qcow2", "-o", "compat=1.1,cluster_size=65536",
                  str(destination), str(layout["disk_size_after"])], log)
            with _guest(destination, "qcow2", readonly=False) as g:
                g.part_init("/dev/sda", "gpt")
                g.part_set_disk_guid("/dev/sda", str(UUID(bytes_le=bytes.fromhex(layout["disk_identity"]))))
                for part in layout["partitions"]:
                    number = part["number"]
                    g.part_add("/dev/sda", "p", part["start"] // 512, part["end"] // 512)
                    g.part_set_gpt_type("/dev/sda", number, part["type"])
                    g.part_set_gpt_guid("/dev/sda", number, str(UUID(bytes_le=bytes.fromhex(part["partition_guid"]))))
                    g.part_set_gpt_attributes("/dev/sda", number, part.get("attributes", 0))
                    g.part_set_name("/dev/sda", number, part.get("name", ""))
                if layout["lvs"]:
                    pv = next(part["device"] for part in layout["partitions"] if part["type"] == LVM_GUID)
                    vg = fresh["storage"]["lvm"]["vgs"][0]["vg_name"]
                    g.pvcreate(pv)
                    g.vgcreate(vg, [pv])
                    for lv in layout["lvs"]:
                        g.lvcreate(lv["name"], vg, lv["size"] // MIB)
                g.upload_offset(str(efi_raw), esp["device"], 0)
                for filesystem in regular:
                    device, fs = filesystem["device"], filesystem["filesystem"]
                    log(f"Creating and restoring {fs} filesystem on {device}")
                    if fs.startswith("ext"):
                        g.mkfs(fs, device, features="^orphan_file,^metadata_csum_seed")
                    else:
                        g.mkfs(fs, device)
                    g.set_uuid(device, filesystem["uuid"])
                    # Fresh filesystems already have no label. xfs_admin -L ''
                    # is rejected by the supported appliance; do not issue it.
                    # The read-only identity check below still verifies emptiness.
                    if filesystem["label"]:
                        g.set_label(device, filesystem["label"])
                    g.mount(device, "/")
                    if g.is_dir("/lost+found") and not g.ls("/lost+found"):
                        g.rmdir("/lost+found")
                    g.tar_in(str(archives[device]), "/", **ARCHIVE_OPTIONS)
                    stats = g.statvfs("/")
                    if stats["bavail"] * stats["frsize"] < 64 * MIB:
                        raise StorageError(f"Restored filesystem {device} has less than 64 MiB available; choose a larger size")
                    g.umount_all()
            _run(["qemu-img", "check", "-f", "qcow2", str(destination)], log)
            with _guest(destination, "qcow2", readonly=True) as g:
                _verify_layout(g, plan)
                for filesystem in file_systems:
                    _identity(g, filesystem)
                verification = staging / "verify.tar.gz"
                for filesystem in regular:
                    device = filesystem["device"]
                    log(f"Verifying every archived file and preserved metadata on {device}")
                    g.mount_ro(device, "/")
                    g.tar_out("/", str(verification), numericowner=True, **ARCHIVE_OPTIONS)
                    g.umount_all()
                    _compare_manifests(manifests[device], _archive_manifest(verification), device)
                    verification.unlink()
                efi_check = staging / "verify-efi.raw"
                g.download_offset(esp["device"], str(efi_check), 0, esp["size"])
                if efi_check.stat().st_size != esp["size"] or _digest(efi_check) != efi_hash:
                    raise StorageError("EFI partition bytes changed during the rebuild")
                from .boot import detect_boot
                boot = detect_boot(g, architecture=plan["source_architecture"])
                if ("UEFI_64" not in boot.get("supported_firmware", [])
                        or "BIOS" in boot.get("supported_firmware", [])
                        or not _matching_arm_efi(boot, plan["source_architecture"])):
                    raise StorageError("Rebuilt disk lost matching UEFI-only boot support")
                points = _mount(g, _roots(g), True)
                for filesystem in regular:
                    if points.get(filesystem["mountpoint"]) != filesystem["device"]:
                        raise StorageError(f"Restored filesystem mounts do not match the source: {filesystem['device']}")
            if _digest(source_work) != source_hash:
                raise StorageError("Source working image changed during a read-only rebuild")
            log("Filesystem rebuild verified; original working image remains unchanged")
        return destination
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise
