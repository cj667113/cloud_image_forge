"""Offline VM/bare-metal hardware preparation for an imported Linux disk.

OCI BYOI currently supports VMs, not bare-metal imports. The latter is an
experimental hardware preparation profile, never a claim of provider support.
The reference scripts informed generic initramfs, DHCP and serial preparation;
their hard-coded iSCSI endpoints, root LV names and destructive edits are not used.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
from uuid import uuid4

from .oci_guest import MODULE_CONFIG as OCI_MODULE_CONFIG
from .oci_guest import ARCH_CONFIG, _architecture_errors, _glob, _kernel_architecture, _network_files, _read, _serial_device
from .architecture import normalize_arch, execution_blocker


MODULE_CONFIG = {**OCI_MODULE_CONFIG, "nvme": "CONFIG_BLK_DEV_NVME", "nvme_core": "CONFIG_NVME_CORE",
                 "ahci": "CONFIG_SATA_AHCI", "iscsi_ibft": "CONFIG_ISCSI_IBFT",
                 "dm_mod": "CONFIG_BLK_DEV_DM", "xfs": "CONFIG_XFS_FS", "ext4": "CONFIG_EXT4_FS",
                 "ixgbe": "CONFIG_IXGBE", "i40e": "CONFIG_I40E", "mlx4_en": "CONFIG_MLX4_EN",
                 "bnxt_en": "CONFIG_BNXT"}
NIC_DRIVERS = {"ixgbe", "ixgbevf", "i40e", "iavf", "mlx4_en", "mlx5_core", "bnxt_en"}
PV_DRIVERS = {"virtio_pci", "virtio_blk", "virtio_scsi", "sd_mod"}
RPM_DISTROS = {"oraclelinux", "rhel", "centos", "rocky", "almalinux", "fedora"}
DEB_DISTROS = {"debian", "ubuntu"}
VERSION = re.compile(r"[A-Za-z0-9_.+~-]+\Z")
UUID = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{2,127}\Z")
PROFILE = "/var/lib/cloud-image-forge/platform-preparation.json"
BACKUPS = "/var/lib/cloud-image-forge/platform-backups"
SOURCES = ["https://github.com/cj667113/VirtualMachine_to_OCI-BareMetal",
           "https://github.com/cj667113/VirtualMachine_to_OCI-VM",
           "https://docs.oracle.com/en-us/iaas/Content/Compute/References/bringyourownimage.htm",
           "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/importingcustomimagelinux.htm"]


def _dict(value):
    return value.model_dump() if hasattr(value, "model_dump") else value or {}


def _iscsi_backend(content):
    active = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith("#"))
    if re.search(r"\biscsiadm\s+-m\s+fw(?:\s|;|$)", active):
        return "iscsiadm"
    if re.search(r"\biscsistart\s+-b(?:\s|;|$)", active):
        return "iscsistart"
    return None


def _iscsi_archive_ready(g, path, members):
    """Evidence from the archive itself, not just the installed package files."""
    names = {name.lstrip("./") for name in members}
    root = next((name for name in ("usr/sbin/iscsiroot", "sbin/iscsiroot") if name in names), None)
    modules = next((name for name in ("usr/lib/dracut/modules.txt", "lib/dracut/modules.txt") if name in names), None)
    hook = any(re.fullmatch(r"(?:usr/)?lib/dracut/hooks/cmdline/[0-9]+-parse-iscsiroot\.sh", name) for name in names)
    if not root or not modules or not hook:
        return False
    try:
        content = g.initrd_cat(path, root)
        listing = g.initrd_cat(path, modules)
        content = content.decode("utf-8", "replace") if isinstance(content, bytes) else content
        listing = listing.decode("utf-8", "replace") if isinstance(listing, bytes) else listing
    except RuntimeError:
        return False
    selected = set(listing.split())
    if "iscsi" not in selected or not selected.intersection({"network", "network-manager", "network-legacy"}):
        return False
    backend = _iscsi_backend(content)
    required = ("iscsiadm", "iscsid", "iscsi-iname") if backend == "iscsiadm" else ("iscsistart",) if backend == "iscsistart" else ()
    if not required or any(not any(directory + "/" + binary in names for directory in ("usr/sbin", "sbin", "usr/bin", "bin")) for binary in required):
        return False
    if backend == "iscsiadm" and "systemd" in selected:
        if any(not any(directory + "/" + unit in names for directory in ("usr/lib/systemd/system", "lib/systemd/system"))
               for unit in ("iscsid.service", "iscsid.socket")):
            return False
        if "etc/systemd/system/sockets.target.wants/iscsid.socket" not in names:
            return False
    return True


def iscsi_initramfs_checks(path, listing_variable="listing"):
    """Native archive proof shared by platform and OCI dracut preparation.

Modern dracut's firmware handler uses iscsiadm/iscsid, while older handlers
use iscsistart. Inspect the archived handler as data to choose the appropriate
complete toolchain; merely finding an unused helper is insufficient.
"""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", listing_variable):
        raise ValueError("Unsafe initramfs listing variable")
    quoted = shlex.quote(str(path))
    return [
        "forge_iscsi_has() { printf '%s\\n' \"${" + listing_variable + "}\" | grep -Eq \"$1\"; }",
        "forge_iscsi_fail() { echo \"iSCSI initramfs verification failed: $1\" >&2; exit 1; }",
        f"forge_iscsi_modules=$(lsinitrd -m {quoted})",
        "printf '%s\\n' \"$forge_iscsi_modules\" | grep -Eq '^[[:space:]]*iscsi[[:space:]]*$' || forge_iscsi_fail 'iscsi dracut module missing'",
        "printf '%s\\n' \"$forge_iscsi_modules\" | grep -Eq '^[[:space:]]*network(-manager|-legacy)?[[:space:]]*$' || forge_iscsi_fail 'network dracut module missing'",
        "forge_iscsi_has '(^|[[:space:]])(usr/)?lib/dracut/hooks/cmdline/[0-9]+-parse-iscsiroot\\.sh([[:space:]]|$)' || forge_iscsi_fail 'iSCSI cmdline hook missing'",
        "if forge_iscsi_has '(^|[[:space:]])usr/sbin/iscsiroot([[:space:]]|$)'; then forge_iscsi_root_path=usr/sbin/iscsiroot; elif forge_iscsi_has '(^|[[:space:]])sbin/iscsiroot([[:space:]]|$)'; then forge_iscsi_root_path=sbin/iscsiroot; else forge_iscsi_fail 'iSCSI root hook missing'; fi",
        f"forge_iscsi_root=$(lsinitrd -f \"$forge_iscsi_root_path\" {quoted})",
        "forge_iscsi_root=$(printf '%s\\n' \"$forge_iscsi_root\" | sed '/^[[:space:]]*#/d')",
        "if printf '%s\\n' \"$forge_iscsi_root\" | grep -Eq 'iscsiadm[[:space:]]+-m[[:space:]]+fw([[:space:];]|$)'; then",
        "  for forge_iscsi_binary in iscsiadm iscsid iscsi-iname; do forge_iscsi_has \"(^|[[:space:]])(usr/)?s?bin/$forge_iscsi_binary([[:space:]]|$)\" || forge_iscsi_fail \"modern firmware helper $forge_iscsi_binary missing\"; done",
        "  if printf '%s\\n' \"$forge_iscsi_modules\" | grep -Eq '^[[:space:]]*systemd[[:space:]]*$'; then",
        "    for forge_iscsi_unit in iscsid.service iscsid.socket; do forge_iscsi_has \"(^|[[:space:]])(usr/)?lib/systemd/system/$forge_iscsi_unit([[:space:]]|$)\" || forge_iscsi_fail \"$forge_iscsi_unit missing\"; done",
        "    forge_iscsi_has '(^|[[:space:]])etc/systemd/system/sockets.target.wants/iscsid\\.socket([[:space:]]|$)' || forge_iscsi_fail 'iscsid socket enablement missing'",
        "  fi",
        "elif printf '%s\\n' \"$forge_iscsi_root\" | grep -Eq 'iscsistart[[:space:]]+-b([[:space:];]|$)'; then",
        "  forge_iscsi_has '(^|[[:space:]])(usr/)?s?bin/iscsistart([[:space:]]|$)' || forge_iscsi_fail 'legacy firmware helper iscsistart missing'",
        "else forge_iscsi_fail 'unrecognized firmware discovery implementation'; fi",
    ]


def _module_inventory(g, version, text, installed=False):
    names = set()
    for line in text.splitlines():
        path = line.split(":", 1)[0].strip()
        if path.startswith("/") or ".." in PurePosixPath(path).parts:
            continue
        match = re.search(r"/([A-Za-z0-9_-]+)\.ko(?:\.(?:xz|gz|zst))?$", "/" + path)
        if match:
            name = match[1].replace("-", "_")
            if name in MODULE_CONFIG and (not installed or g.is_file(f"/lib/modules/{version}/{path}")):
                names.add(name)
    return names


def _fstab_evidence(g, partitions):
    text = _read(g, "/etc/fstab")
    errors, entries = [], []
    by_mount = {p.get("mountpoint"): p for p in partitions if p.get("mountpoint")}
    by_device = {p["device"]: p for p in partitions}
    uuids = {}
    for p in partitions:
        if p.get("uuid"):
            uuids.setdefault(p["uuid"].lower(), []).append(p)
    if not text:
        errors.append("A readable, nonempty /etc/fstab is required for stable mount preparation.")
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        if not 4 <= len(fields) <= 6:
            errors.append(f"fstab line {number} must contain 4–6 fields.")
            continue
        source, mount, fs, opts = fields[:4]
        options = set(opts.split(","))
        optional = mount != "/" and bool(options & {"nofail", "noauto", "_netdev"})
        entry = {"line": number, "source": source, "mountpoint": mount,
                 "filesystem": fs, "options": opts, "optional": optional}
        local = source.startswith(("/dev/", "UUID=", "LABEL=", "PARTUUID=", "PARTLABEL="))
        if "bind" in options or "rbind" in options or not local:
            entry["preserve"] = True
            if mount == "/":
                errors.append("Root fstab entry must identify a local filesystem on the imported disk.")
            entries.append(entry)
            continue
        partition = None
        if source.startswith("UUID="):
            matches = uuids.get(source[5:].strip("\"'").lower(), [])
            if len(matches) == 1:
                partition = matches[0]
        elif source.startswith("LABEL="):
            try:
                partition = by_device.get(g.findfs_label(source[6:].strip("\"'")))
            except RuntimeError:
                pass
        else:
            # libguestfs has already mounted and inspected this filesystem.
            partition = by_device.get(source) or by_mount.get(mount)
        if partition is None:
            if not optional:
                errors.append(f"fstab line {number}: required {mount} cannot be resolved to the imported disk.")
            entry["preserve"] = True
        else:
            identity = partition.get("uuid") or ""
            if not UUID.fullmatch(identity) or len(uuids.get(identity.lower(), [])) != 1:
                errors.append(f"fstab line {number}: {mount} needs a unique, usable filesystem UUID.")
            elif mount in by_mount and by_mount[mount]["device"] != partition["device"]:
                errors.append(f"fstab line {number}: filesystem identity disagrees with the mounted {mount}.")
            else:
                entry.update({"uuid": identity, "device": partition["device"], "replacement": "UUID=" + identity})
        entries.append(entry)
    roots = [item for item in entries if item["mountpoint"] == "/"]
    if len(roots) != 1 or not roots[0].get("uuid"):
        errors.append("Exactly one root fstab entry with a unique filesystem UUID is required.")
    return {"entries": entries, "errors": errors, "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "root_uuid": roots[0].get("uuid") if len(roots) == 1 else None}


def _inspect_boot_environment(g):
    """Parse GRUB's data file, never source/evaluate guest shell configuration."""
    allowed = {"kernelopts", "tuned_params", "tuned_initrd"}
    environments, errors, paths = [], [], []
    for path in ("/boot/grub2/grubenv", "/boot/grub/grubenv"):
        if not g.is_file(path):
            continue
        content = _read(g, path, 64 * 1024)
        if not content.startswith("# GRUB Environment Block\n") or "\0" in content:
            errors.append(f"Cannot safely parse GRUB environment {path}.")
            continue
        values = {}
        for line in content.splitlines()[1:]:
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                errors.append(f"Malformed entry in GRUB environment {path}.")
                continue
            if name in allowed:
                if name in values and values[name] != value:
                    errors.append(f"Conflicting {name} entries in GRUB environment.")
                values[name] = value
        environments.append(values)
        paths.append(path)
    if not environments:
        return {}, errors, paths
    if any(values != environments[0] for values in environments[1:]):
        return {}, errors + ["Multiple GRUB environments disagree about kernel arguments."], paths
    values = dict(environments[0])
    # Standard tuned_params is optional. A valid block proves it is not saved;
    # inspect literal assignments in the standard menu and local custom snippets
    # before treating an absent value as empty.
    assignments = {name: [] for name in allowed}
    for path in ("/boot/grub2/grub.cfg", "/boot/grub/grub.cfg", "/boot/grub2/custom.cfg", "/boot/grub/custom.cfg"):
        for line in _read(g, path).splitlines():
            match = re.match(r"^\s*set\s+(kernelopts|tuned_params|tuned_initrd)=(.*)$", line)
            if not match:
                continue
            try:
                words = shlex.split(match[2], comments=True)
                if len(words) > 1 or any(character in match[2] for character in ("$", "`", ";")):
                    raise ValueError()
                assignments[match[1]].append(words[0] if words else "")
            except ValueError:
                errors.append(f"Dynamic {match[1]} assignment in {path} cannot be resolved offline.")
    if "tuned_params" not in values:
        candidates = set(assignments["tuned_params"])
        if len(candidates) <= 1:
            values["tuned_params"] = next(iter(candidates), "")
        else:
            errors.append("Multiple tuned_params assignments are ambiguous.")
    candidates = set(assignments["tuned_initrd"])
    if len(candidates) > 1 or candidates and "tuned_initrd" in values and candidates != {values["tuned_initrd"]}:
        errors.append("Multiple tuned_initrd values are ambiguous.")
    elif "tuned_initrd" not in values and len(candidates) == 1:
        values["tuned_initrd"] = next(iter(candidates))
    # An unset kernelopts is only recoverable from a single literal fallback.
    if not values.get("kernelopts"):
        candidates = set(assignments["kernelopts"])
        if len(candidates) == 1:
            values["kernelopts"] = next(iter(candidates))
    return values, errors, paths


def inspect_platform(g, root, partitions, kernels, oci_evidence=None):
    """Optional evidence must not prevent ordinary inspection of older images."""
    try:
        return _inspect_platform(g, root, partitions, kernels, oci_evidence)
    except (RuntimeError, ValueError, KeyError, TypeError, OverflowError, AttributeError) as exc:
        return {"version": 1, "errors": ["Cannot verify optional platform migration prerequisites: " + str(exc)],
                "boot_tested": False}


def _generated_grub_evidence(g, partitions):
    paths = {"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg",
             "/boot/grub/custom.cfg", "/boot/grub2/custom.cfg"}
    mounts = {"/boot/efi", "/efi"}
    mounts.update(part["mountpoint"] for part in partitions
                  if part.get("mountpoint") and part.get("filesystem") in {"vfat", "fat", "fat32", "msdos"})
    for mount in mounts:
        paths.update(_glob(g, mount.rstrip("/") + "/EFI/*/grub.cfg"))
        paths.update(_glob(g, mount.rstrip("/") + "/efi/*/grub.cfg"))
    files, errors = {}, []
    if len(paths) > 64:
        return {}, ["Generated GRUB configuration scan exceeds 64 files."]
    total = 0
    for path in sorted(paths):
        try:
            if not g.is_file(path):
                continue
            size = g.filesize(path)
            total += size
            if size > 4 * 1024 * 1024 or total > 16 * 1024 * 1024:
                errors.append("Generated GRUB configuration exceeds the inspection limit: " + path)
                continue
            content = g.read_file(path)
            files[path] = content.decode("utf-8") if isinstance(content, bytes) else content
            if "\0" in files[path]:
                errors.append("Generated GRUB configuration contains binary data: " + path)
        except (RuntimeError, UnicodeError):
            errors.append("Cannot read generated GRUB configuration: " + path)
    return files, errors


def _inspect_platform(g, root, partitions, kernels, oci_evidence=None):
    """Read evidence only; old imports need refreshing before migration."""
    from .oci_guest import inspect_guest
    from .portability import inspect_archive, inspect_portability
    base = deepcopy(oci_evidence) if oci_evidence is not None else inspect_guest(g, root, partitions, kernels)
    inventory = {}
    for path in kernels:
        version = path.removeprefix("/boot/vmlinuz-")
        if not VERSION.fullmatch(version) or version.startswith("0-rescue-"):
            continue
        old = base.get("kernels", {}).get(version, {})
        config = dict(re.findall(r"^(CONFIG_[A-Z0-9_]+)=([ym])$", _read(g, "/boot/config-" + version), re.M))
        installed = _module_inventory(g, version, _read(g, f"/lib/modules/{version}/modules.dep", 16 * 1024 * 1024), True)
        builtin = _module_inventory(g, version, _read(g, f"/lib/modules/{version}/modules.builtin"))
        builtin.update(name for name, option in MODULE_CONFIG.items() if config.get(option) == "y")
        initrd = old.get("initrd")
        listed, iscsi_userspace, members = None, False, None
        digest = None
        if initrd:
            try:
                members = g.initrd_list(initrd)
                listed = sorted({match.group(1).replace("-", "_") for name in members
                                 if (match := re.search(r"/([A-Za-z0-9_-]+)\.ko(?:\.(?:xz|gz|zst))?$", "/" + name))})
                iscsi_userspace = _iscsi_archive_ready(g, initrd, members)
            except RuntimeError:
                pass
            try:
                digest = g.checksum("sha256", initrd)
            except RuntimeError:
                pass
        archive = inspect_archive(g, initrd, members)
        if initrd and (members is None or not archive.get("readable") or "early_cpio" in members):
            try:
                from .initramfs import read_archive
                parsed = read_archive(g, initrd, digest)
                members = parsed.initrd_list(initrd)
                listed = sorted({match.group(1).replace("-", "_") for name in members
                                 if (match := re.search(r"/([A-Za-z0-9_-]+)\.ko(?:\.(?:xz|gz|zst))?$", "/" + name))})
                iscsi_userspace = _iscsi_archive_ready(parsed, initrd, members)
                archive = inspect_archive(parsed, initrd, members)
                archive["decoder"] = "bounded_newc_gzip"
                digest = parsed.sha256
            except (RuntimeError, ValueError, OSError, AttributeError) as exc:
                archive["readable"] = False
                archive["errors"].append("Bounded initramfs reader: " + str(exc))
                # An early CPIO listing is not the main archive's inventory.
                if members is not None and "early_cpio" in members:
                    listed = None
        inventory[version] = {"modules": sorted(installed), "builtin": sorted(builtin),
                              "config": {key: value for key, value in config.items() if key in ARCH_CONFIG},
                              "architecture": _kernel_architecture(config),
                              "initrd": initrd, "initrd_modules": listed, "initrd_sha256": digest,
                              "initrd_iscsi_userspace": iscsi_userspace,
                              "portability": archive}
    tools = dict(base.get("tools", {}))
    for name in ("iscsistart", "iscsid", "iscsi-iname", "dnf", "yum", "apt-get"):
        tools[name] = any(g.is_file(directory + "/" + name) for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"))
    boot_files = {path: _read(g, path) for path in ["/etc/default/grub", "/etc/kernel/cmdline"]
                  + _glob(g, "/boot/loader/entries/*.conf") if g.is_file(path)}
    persistent = []
    for path in _glob(g, "/etc/udev/rules.d/*.rules") + _glob(g, "/etc/systemd/network/*.link"):
        content = "\n".join(line for line in _read(g, path).splitlines() if not line.lstrip().startswith("#"))
        if ((path.endswith(".rules") and re.search(r'SUBSYSTEM\s*==\s*"net"', content)
             and re.search(r"(?:ATTR\{address\}|NAME\s*=)", content))
                or (path.endswith(".link") and re.search(r"^(?:MACAddress|OriginalName|Name)=", content, re.M))):
            persistent.append(path)
    environment, environment_errors, environment_paths = _inspect_boot_environment(g)
    generated, generated_errors = _generated_grub_evidence(g, partitions)
    result = {"version": 1, "kernels": inventory, "tools": tools, "fstab": _fstab_evidence(g, partitions),
            "boot_files": boot_files, "persistent_network_files": persistent,
            "generated_grub": generated, "generated_grub_errors": generated_errors,
            "boot_environment": environment, "boot_environment_errors": environment_errors,
            "boot_environment_paths": environment_paths,
            "dracut_modules": sorted({re.sub(r"^\d+", "", PurePosixPath(p).name)
                                      for p in _glob(g, "/usr/lib/dracut/modules.d/*")}),
            "iscsi_userspace_backend": _iscsi_backend(_read(g, "/usr/lib/dracut/modules.d/95iscsi/iscsiroot.sh")),
            "network_backend": base.get("network_backend"), "network_ready": base.get("network_ready", False),
            "network_files": base.get("network_files", []), "serial_console_ready": base.get("serial_console_ready", False),
            "serial_device": base.get("serial_device"),
            "os_version": base.get("os_version", {}),
            "blacklisted_modules": base.get("blacklisted_modules", []),
            "boot_tested": False}
    try:
        result["portability"] = inspect_portability(g, partitions, result, base)
    except (RuntimeError, ValueError, AttributeError, TypeError) as exc:
        result["portability"] = {"version": 1, "errors": ["Cannot inspect preservation prerequisites: " + str(exc)]}
    return result


def _boot_args(text, *, assignment=False, environment=None):
    if "`" in text or "\0" in text:
        raise ValueError("Boot arguments contain shell expansion; resolve them before platform migration.")
    try:
        if assignment:
            words = shlex.split(text, comments=False)
            if len(words) > 1:
                raise ValueError("GRUB argument assignment must contain one quoted value.")
            text = words[0] if words else ""
        def expand(value, stack=()):
            def replace(match):
                name = match[1] or match[2]
                if name not in {"kernelopts", "tuned_params", "tuned_initrd"} or name not in (environment or {}) or name in stack:
                    raise ValueError("Boot arguments contain unresolved shell expansion: " + name)
                return expand(environment[name], stack + (name,))
            value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", replace, value)
            if "$" in value or "`" in value:
                raise ValueError("Boot arguments contain unsupported shell expansion.")
            return value
        words = shlex.split(expand(text), comments=False)
    except ValueError as exc:
        raise ValueError("Boot argument syntax cannot be safely updated: " + str(exc)) from exc
    if any(any(ch in value for ch in "\r\n") for value in words):
        raise ValueError("Multiline boot arguments are unsupported.")
    return words


def _boot_records(evidence):
    records = []
    for path, text in evidence.get("boot_files", {}).items():
        if path == "/etc/default/grub":
            for match in re.finditer(r"^GRUB_CMDLINE_LINUX(?:_DEFAULT)?=(.*)$", text, re.M):
                records.append((path, _boot_args(match[1], assignment=True, environment=evidence.get("boot_environment"))))
        elif path == "/etc/kernel/cmdline":
            records.append((path, _boot_args(text.strip(), environment=evidence.get("boot_environment"))))
        else:
            for match in re.finditer(r"^options\s+(.*)$", text, re.M):
                records.append((path, _boot_args(match[1], environment=evidence.get("boot_environment"))))
    return records


def _required_args(plan, options):
    if not UUID.fullmatch(plan.get("root_uuid") or ""):
        raise ValueError("Root filesystem UUID is missing or invalid.")
    args = ["root=UUID=" + plan["root_uuid"]]
    if options.get("boot_attachment") == "iscsi":
        args += ["netroot=iscsi", "rd.iscsi.firmware=1", "rd.iscsi.ibft=1", "rd.neednet=1"]
    if options.get("configure_serial_console", True):
        args += ["console=tty0", f"console={plan.get('serial_device', 'ttyS0')},115200n8"]
    return args


def _adapt_args(words, plan, options):
    result = []
    for word in words:
        key = word.partition("=")[0]
        # This nonidentity session timeout is present on the audited BM E5
        # firmware-iSCSI root. Preserve valid policy values only for an iSCSI
        # destination; never carry source initiator/authentication parameters.
        timeout = re.fullmatch(r"rd\.iscsi\.param=node\.session\.timeo\.replacement_timeout=(-?\d{1,10})", word)
        if options.get("boot_attachment") == "iscsi" and timeout and -2147483648 <= int(timeout[1]) <= 2147483647:
            result.append(word)
            continue
        # Replace only the boot transport being migrated. Retain unrelated policy.
        if key == "root" or key.startswith("rd.iscsi.") or key.startswith("iscsi_"):
            continue
        if key == "netroot" and word.partition("=")[2].startswith("iscsi"):
            continue
        if key == "rd.neednet":
            continue
        if key == "ip" and word.partition("=")[2] == "ibft":
            continue
        if (options.get("configure_serial_console", True) and key == "console"
                and word.partition("=")[2].partition(",")[0] in {"tty0", plan.get("serial_device", "ttyS0")}):
            continue
        result.append(word)
    for arg in _required_args(plan, options):
        if arg not in result:
            result.append(arg)
    return result


def _firmware(inspection, options, boot_migration, allow_network):
    available = list(inspection.get("boot", {}).get("supported_firmware", []))
    if normalize_arch(inspection.get("os", {}).get("arch")) == "aarch64":
        available = [value for value in available if value == "UEFI_64"]
    planned = []
    if _dict(boot_migration).get("enabled"):
        from .uefi import plan_migration
        migration = plan_migration(inspection, _dict(boot_migration), allow_network)
        if migration.get("ready_to_migrate") and "UEFI_64" not in available:
            available.append("UEFI_64")
            planned.append("UEFI_64")
    chosen = "UEFI_64" if options.get("target") == "bare_metal" else inspection.get("boot", {}).get("recommended_firmware")
    if chosen not in available:
        chosen = "UEFI_64" if "UEFI_64" in available else "BIOS" if "BIOS" in available else None
    return available, chosen, planned


def _plan_preserve(inspection, options, plan, oci_config, target_provider, boot_migration=None, allow_network=False):
    from .portability import assess_portability
    blockers, warnings = plan["blockers"], plan["warnings"]
    target, network, boot = options.get("target"), options.get("network_attachment"), options.get("boot_attachment")
    if options.get("source") not in {"vm", "bare_metal"} or target not in {"vm", "bare_metal"}:
        blockers.append("Select valid source and target machine types; the prior machine is not inferred from disk contents.")
    if boot not in {"paravirtualized", "iscsi"} or network not in {"paravirtualized", "accelerated", "vfio"}:
        blockers.append("Select a supported target boot and network attachment profile.")
    if network == "vfio" and options.get("nic_driver") not in NIC_DRIVERS:
        blockers.append("Select the actual target physical/VF NIC driver to validate existing coverage.")
    if target == "bare_metal" and (boot != "iscsi" or network != "vfio"):
        blockers.append("The supported bare-metal assessment profile uses firmware iSCSI boot and a selected hardware NIC.")
    if any(options.get(name) for name in ("install_packages", "configure_network", "configure_serial_console")):
        blockers.append("Preserve mode does not install packages or rewrite networking/serial settings. Disable those changes or choose Reconfigure.")
    if target_provider not in {"oci", "generic"}:
        blockers.append("Hardware preservation validation is available for OCI and generic exports.")
    available, firmware, planned = _firmware(inspection, options, boot_migration, allow_network)
    selected = _dict(oci_config).get("capabilities", {}).get("Compute.Firmware", {}).get("default_value")
    if selected in available:
        firmware = selected
    if not available or target == "bare_metal" and "UEFI_64" not in available:
        blockers.append("A detected compatible boot chain is required; the bare-metal profile requires UEFI.")
    plan.update(effective_firmware=firmware, planned_firmware=planned)
    assessment = assess_portability(inspection, options, target_provider)
    plan["portability"] = assessment
    plan["required_modules"] = assessment.get("required_modules", [])
    blockers.extend(assessment["blockers"])
    warnings.extend(assessment["warnings"])
    plan["actions"] = ["Validate existing target boot prerequisites and retain boot, initramfs, mount and network configuration without rewriting."]
    plan["fstab_changes"] = []
    plan["network_backend"] = inspection.get("platform", {}).get("network_backend")
    if oci_config is not None:
        config = _dict(oci_config)
        if config.get("guest", {}).get("prepare", True):
            blockers.append("Preserve mode requires OCI guest preparation to be disabled; it would rewrite the configuration being retained.")
        expected = {"Storage.BootVolumeType": "ISCSI" if boot == "iscsi" else "PARAVIRTUALIZED",
                    "Network.AttachmentType": {"vfio": "VFIO", "accelerated": "ACCELERATEDPV"}.get(network, "PARAVIRTUALIZED")}
        if firmware:
            expected["Compute.Firmware"] = firmware
        for key, wanted in expected.items():
            choice = config.get("capabilities", {}).get(key, {})
            if choice.get("default_value") != wanted or wanted not in (choice.get("values") or [choice.get("default_value")]):
                blockers.append(f"OCI {key} must allow and prefer {wanted} to match the target being validated.")
        launch = config.get("capabilities", {}).get("Compute.LaunchMode", {}).get("default_value")
        expected_launch = ("NATIVE" if target == "bare_metal" else
                           "ACCELERATEDPV" if network == "accelerated" and boot == "paravirtualized" else
                           "PARAVIRTUALIZED" if boot == network == "paravirtualized" else "CUSTOM")
        if launch not in {expected_launch, "CUSTOM"}:
            blockers.append(f"OCI Compute.LaunchMode must be {expected_launch} or CUSTOM for this platform profile.")
        for item in config.get("import_options", {}).get("shape_compatibility", []):
            name = item.get("shape", "") if isinstance(item, dict) else str(item)
            if target == "vm" and name.startswith("BM.") or target == "bare_metal" and name.startswith("VM."):
                warnings.append(f"{name} is outside the selected {target} target assessment; its prerequisites are not established by this result.")
    if target == "bare_metal":
        warnings.append("Oracle's external BYOI import restriction differs from OCI-native custom images captured from a platform image. This offline assessment cannot establish import eligibility or shape compatibility.")
    warnings.append("Preserve applies to hardware preparation. Explicit edits in other steps run first and are validated again; resulting bootability still needs a target launch.")
    plan["blockers"] = list(dict.fromkeys(blockers))
    plan["warnings"] = list(dict.fromkeys(warnings))
    plan["ready"] = not plan["blockers"]
    return plan


def plan_platform(inspection, options, allow_network=False, oci_config=None, target_provider="oci", boot_migration=None):
    options = _dict(options)
    requested = options.get("enabled", False)
    plan = {"requested": bool(requested), "ready": True, "source": options.get("source"), "target": options.get("target"),
            "strategy": options.get("strategy", "reconfigure"),
            "actions": [], "blockers": [], "warnings": [], "required_modules": [], "packages": [],
            "effective_firmware": None, "provider_supported": options.get("target") != "bare_metal",
            "experimental": options.get("target") == "bare_metal", "boot_tested": False, "sources": SOURCES,
            "fstab_changes": [], "network_backend": None, "initramfs_backend": None}
    if not requested:
        return plan
    arch = normalize_arch(inspection.get("os", {}).get("arch"))
    plan.update(architecture=arch, serial_device=_serial_device(arch))
    if arch == "aarch64" and (options.get("target") != "vm" or options.get("boot_attachment") != "paravirtualized"
                               or options.get("network_attachment") not in {"paravirtualized", "accelerated"}):
        plan["blockers"].append("ARM64 hardware profiles currently support UEFI VMs with paravirtualized boot and PV or Accelerated PV networking; ARM bare-metal, firmware-iSCSI and hardware NIC preparation are not validated.")
    if plan["strategy"] == "preserve":
        return _plan_preserve(inspection, options, plan, oci_config, target_provider, boot_migration, allow_network)
    if plan["strategy"] != "reconfigure":
        plan["blockers"].append("Unsupported hardware preparation strategy.")
    blockers, warnings, actions = plan["blockers"], plan["warnings"], plan["actions"]
    source, target = options.get("source"), options.get("target")
    boot, network, nic = options.get("boot_attachment"), options.get("network_attachment"), options.get("nic_driver")
    if source not in {"vm", "bare_metal"} or target not in {"vm", "bare_metal"} or source == target:
        blockers.append("Select distinct VM and bare-metal source and destination platforms.")
    if boot not in {"paravirtualized", "iscsi"} or network not in {"paravirtualized", "accelerated", "vfio"}:
        blockers.append("Select a supported boot and network attachment profile.")
    if (target == "bare_metal" or network == "vfio") and nic not in NIC_DRIVERS:
        blockers.append("Select the actual target physical/VF NIC driver; hardware cannot be inferred from an imported disk.")
    if target == "bare_metal":
        if boot != "iscsi" or network != "vfio":
            blockers.append("Experimental bare-metal preparation requires iSCSI boot and hardware/VFIO networking.")
        warnings.append("OCI documentation does not support bringing your own image to bare-metal instances. This export is experimental offline hardware preparation, not an OCI-supported bare-metal image.")
        warnings.append("The chosen NIC and NVMe/AHCI controller profile must match the target machine; driver presence does not prove hardware or firmware compatibility.")
    if target_provider not in {"oci", "generic"}:
        blockers.append("This platform migration profile is limited to OCI or generic exports.")
    blocker = execution_blocker(arch)
    if blocker:
        blockers.append(blocker)
    evidence = inspection.get("platform") or {}
    if evidence.get("version") != 1:
        blockers.append("Platform evidence is missing; refresh inspection before preparing this image.")
    blockers.extend(evidence.get("errors", []))
    blockers.extend(evidence.get("boot_environment_errors", []))
    kernels, tools = evidence.get("kernels", {}), evidence.get("tools", {})
    blockers.extend(_architecture_errors(inspection, kernels, serial=options.get("configure_serial_console", True)))
    available, firmware, planned = _firmware(inspection, options, boot_migration, allow_network)
    selected_firmware = _dict(oci_config).get("capabilities", {}).get("Compute.Firmware", {}).get("default_value")
    if target == "vm" and selected_firmware in available:
        firmware = selected_firmware
    plan.update(effective_firmware=firmware, planned_firmware=planned)
    if not available or (target == "bare_metal" and "UEFI_64" not in available):
        blockers.append("A detected boot chain is required; bare-metal preparation needs UEFI. Enable eligible BIOS-to-UEFI migration or import a compatible image.")
    # This profile discovers its boot target from firmware, not an explicit IQN.
    required = set(PV_DRIVERS if boot == "paravirtualized" else {"iscsi_tcp", "iscsi_ibft", "sd_mod"})
    required.update({"virtio_pci", "virtio_net"} if network in {"paravirtualized", "accelerated"} else {nic} if nic in NIC_DRIVERS else set())
    if network == "accelerated":
        actions.append("Prepare AcceleratedPV guest-facing VirtIO network drivers (virtio_net and virtio_pci) in every initramfs.")
        warnings.append("AcceleratedPV is a distinct OCI networking type. Existing native-architecture VirtIO coverage is checked; a compatible shape/image and target launch validation are still required.")
    if target == "bare_metal":
        required.update({"nvme", "nvme_core", "ahci"})
    plan["required_modules"] = sorted(required)
    if not kernels:
        blockers.append("No non-rescue installed kernel inventory is available.")
    for version, kernel in kernels.items():
        if not VERSION.fullmatch(version):
            blockers.append("Unsafe kernel version in inspection.")
            continue
        missing = sorted(required - set(kernel.get("modules", [])) - set(kernel.get("builtin", [])))
        if missing:
            blockers.append(f"Kernel {version} lacks installed/built-in drivers: {', '.join(missing)}. Install a suitable kernel/module package using the package controls, then refresh; a config '=m' flag alone is not a driver.")
    blacklisted = sorted(required & set(evidence.get("blacklisted_modules", [])))
    if blacklisted:
        blockers.append("Required drivers are blacklisted or overridden: " + ", ".join(blacklisted) + ". Resolve those settings explicitly.")
    distro = inspection.get("os", {}).get("distro")
    rpm, deb = distro in RPM_DISTROS, distro in DEB_DISTROS
    if not (rpm or deb):
        blockers.append("Automatic preparation supports systemd Debian/Ubuntu and Enterprise Linux/Fedora guests.")
    backend = "dracut" if tools.get("dracut") and (rpm or boot == "iscsi") else "initramfs-tools" if tools.get("update-initramfs") else "dracut" if tools.get("dracut") else None
    plan["initramfs_backend"] = backend
    if backend == "initramfs-tools":
        for version, kernel in kernels.items():
            if kernel.get("initrd") not in {None, f"/boot/initrd.img-{version}"}:
                blockers.append(f"Kernel {version} uses a nonstandard initrd path for initramfs-tools; resolve the bootloader/initramfs layout before migration.")
    packages = set()
    def need(name, package):
        if tools.get(name):
            return
        if options.get("install_packages") and allow_network and package:
            packages.add(package)
        else:
            blockers.append(f"Missing {name}; install {package or 'a distribution-supported tool'} or enable package installation and guest network access.")
    if not backend:
        blockers.append("Install a supported initramfs generator before migration (dracut or update-initramfs).")
    else:
        need("lsinitrd" if backend == "dracut" else "lsinitramfs", "dracut" if rpm else "dracut-core" if backend == "dracut" else "initramfs-tools-core")
    need("systemctl", None)
    if not (tools.get("update-grub") or tools.get("grub2-mkconfig")):
        blockers.append("Platform preparation needs update-grub or grub2-mkconfig to regenerate the existing bootloader configuration.")
    if rpm and not tools.get("update-grub"):
        major = evidence.get("os_version", {}).get("major", 0)
        if not ((distro == "fedora" and major >= 34) or (distro != "fedora" and major in {9, 10})):
            blockers.append("Automatic RPM GRUB regeneration requires EL9/10 or Fedora 34+ with the common /boot/grub2/grub.cfg layout; older EFI layouts require manual preparation.")
    if boot == "iscsi":
        if backend != "dracut":
            blockers.append("Firmware-discovered iSCSI boot preparation requires an existing dracut setup; replacing an initramfs framework is not automated.")
        need("iscsiadm", "iscsi-initiator-utils" if rpm else "open-iscsi")
        iscsi_backend = evidence.get("iscsi_userspace_backend")
        if iscsi_backend == "iscsiadm":
            need("iscsid", "iscsi-initiator-utils" if rpm else "open-iscsi")
            need("iscsi-iname", "iscsi-initiator-utils" if rpm else "open-iscsi")
        elif iscsi_backend == "iscsistart":
            need("iscsistart", "iscsi-initiator-utils" if rpm else "open-iscsi")
        elif not (rpm and options.get("install_packages") and allow_network and "iscsi" not in evidence.get("dracut_modules", [])):
            blockers.append("Installed dracut firmware iSCSI discovery handler is not recognized; inspect or update the guest dracut package before migration.")
        plan["iscsi_userspace_backend"] = iscsi_backend
        modules = set(evidence.get("dracut_modules", []))
        network_module = next((name for name in ("network-manager", "network-legacy", "network") if name in modules), None)
        plan["dracut_network_module"] = network_module
        if "iscsi" not in modules or not network_module:
            if rpm and options.get("install_packages") and allow_network:
                packages.add("dracut-network")
            else:
                blockers.append("The dracut iSCSI and network modules must be installed (dracut-network on Enterprise Linux).")
        actions.append("Prepare firmware-discovered iSCSI boot with netroot=iscsi, rd.iscsi.firmware=1 and rd.neednet=1; rebuild and verify the iSCSI userspace in every initramfs.")
        warnings.append("The target firmware must supply valid iBFT/iSCSI boot parameters. This image does not invent an OCI address, IQN, credentials or initiator identity, and cannot verify firmware discovery offline.")
    else:
        actions.append("Prepare VirtIO boot and remove prior iSCSI boot transport arguments while retaining unrelated kernel settings.")
    if packages and not (tools.get("dnf") or tools.get("yum") if rpm else tools.get("apt-get")):
        blockers.append("The required guest package manager is unavailable.")
    plan["packages"] = sorted(packages)
    if packages:
        actions.append("Install guest repository packages: " + ", ".join(sorted(packages)))
    fstab = evidence.get("fstab", {})
    blockers.extend(fstab.get("errors", []))
    plan["root_uuid"] = fstab.get("root_uuid")
    if not UUID.fullmatch(plan["root_uuid"] or ""):
        blockers.append("A unique root filesystem UUID is required.")
    plan["fstab_changes"] = [{"line": item["line"], "mountpoint": item["mountpoint"], "from": item["source"], "to": item["replacement"]}
                             for item in fstab.get("entries", []) if item.get("replacement") and item["source"] != item["replacement"]]
    actions += ["Use existing filesystem UUIDs for local fstab mounts and the root boot argument; retain mount options and filesystem identities.",
                "Build generic initramfs for every non-rescue installed kernel and verify each required driver; preserve unrelated installed drivers."]
    for item in fstab.get("entries", []):
        if item.get("optional") and item.get("preserve"):
            warnings.append(f"Optional mount {item['mountpoint']} is not present in this disk and will be retained; validate it on the target.")
    plan["network_backend"] = evidence.get("network_backend")
    if options.get("configure_network", True):
        if plan["network_backend"] not in {"NetworkManager", "netplan", "networkd"}:
            blockers.append("No supported DHCP renderer is installed (NetworkManager, netplan or systemd-networkd).")
        actions.append("Back up existing network profiles and persistent NIC rules, then configure DHCP without a source-machine MAC/interface binding.")
    elif not evidence.get("network_ready") or evidence.get("persistent_network_files"):
        blockers.append("Network changes are disabled and portable DHCP/persistent-name readiness is not verified.")
    if options.get("configure_serial_console", True):
        actions.append(f"Enable {plan['serial_device']} at 115200 baud and serial-getty while preserving unrelated console and boot settings.")
    try:
        records = _boot_records(evidence)
        if not records:
            blockers.append("No safely editable GRUB/kernel boot arguments were found.")
        if any("$" in content for content in evidence.get("boot_files", {}).values()):
            actions.append("Resolve inspected GRUB kernelopts/tuned_params into explicit portable boot arguments; retain their current literal settings.")
            warnings.append("Resolved GRUB tuning variables are captured at build time. Review future tuning or kernel-policy changes after the target boots.")
        if any(key.partition("=")[0] == "root" and key.partition("=")[2].startswith(("/dev/nfs", "live:", "http:")) for _, words in records for key in words):
            blockers.append("Network/live root boot arrangements are not supported by platform migration.")
    except ValueError as exc:
        blockers.append(str(exc))
    if oci_config is not None:
        config = _dict(oci_config)
        expected = {"Storage.BootVolumeType": "ISCSI" if boot == "iscsi" else "PARAVIRTUALIZED",
                    "Network.AttachmentType": {"vfio": "VFIO", "accelerated": "ACCELERATEDPV"}.get(network, "PARAVIRTUALIZED")}
        if firmware:
            expected["Compute.Firmware"] = firmware
        for key, wanted in expected.items():
            descriptor = config.get("capabilities", {}).get(key, {})
            if descriptor.get("default_value") != wanted or wanted not in (descriptor.get("values") or [descriptor.get("default_value")]):
                blockers.append(f"OCI {key} must allow and prefer {wanted} to match the platform migration profile.")
        launch = config.get("capabilities", {}).get("Compute.LaunchMode", {}).get("default_value")
        expected_launch = ("NATIVE" if target == "bare_metal" else
                           "ACCELERATEDPV" if network == "accelerated" and boot == "paravirtualized" else
                           "PARAVIRTUALIZED" if boot == network == "paravirtualized" else "CUSTOM")
        if launch not in {expected_launch, "CUSTOM"}:
            blockers.append(f"OCI Compute.LaunchMode must be {expected_launch} or CUSTOM for this platform profile.")
        shapes = config.get("import_options", {}).get("shape_compatibility") or []
        for shape in shapes:
            name = shape.get("shape", "") if isinstance(shape, dict) else str(shape)
            if (target == "bare_metal" and name.startswith("VM.")) or (target == "vm" and name.startswith("BM.")):
                blockers.append(f"OCI shape {name} conflicts with the destination platform.")
    warnings.append("Source platform is declared by the operator, not detectable with certainty from disk contents. A target VM or hardware boot test is still required.")
    plan["blockers"], plan["warnings"] = list(dict.fromkeys(blockers)), list(dict.fromkeys(warnings))
    plan["ready"] = not plan["blockers"]
    return plan


def _safe_path(g, path):
    pure = PurePosixPath(path)
    if not path.startswith("/") or ".." in pure.parts or "\0" in path:
        raise ValueError("Unsafe guest path during platform preparation.")
    for parent in (pure, *pure.parents):
        if str(parent) != "/" and g.is_symlink(str(parent)):
            raise ValueError(f"Platform preparation refuses guest symlink {parent}.")


def _backup(g, path, backup):
    _safe_path(g, path)
    _safe_path(g, backup)
    if g.is_file(path):
        destination = backup + path
        g.mkdir_p(str(PurePosixPath(destination).parent))
        g.cp_a(path, destination)


def _write(g, path, text, backup, mode=0o644):
    _backup(g, path, backup)
    g.mkdir_p(str(PurePosixPath(path).parent))
    g.write(path, text.encode())
    g.chmod(mode, path)
    g.chown(0, 0, path)


def _fstab_text(text, changes):
    lines = text.splitlines(keepends=True)
    for change in changes:
        index = change["line"] - 1
        match = re.match(r"^(\s*)(\S+)(\s+.*)$", lines[index], re.S)
        if not match or match[2] != change["from"]:
            raise ValueError("fstab changed after platform inspection; repeat planning.")
        lines[index] = match[1] + change["to"] + match[3]
    return "".join(lines)


def _edit_boot(g, evidence, plan, options, backup):
    from .engine import _grub_assignment
    for path, original in evidence["boot_files"].items():
        if _read(g, path) != original:
            raise ValueError("Boot configuration changed after platform inspection; repeat planning.")
        if path == "/etc/default/grub":
            text = original
            for name in ("GRUB_CMDLINE_LINUX", "GRUB_CMDLINE_LINUX_DEFAULT"):
                match = re.search(rf"^{name}=(.*)$", original, re.M)
                words = _boot_args(match[1], assignment=True, environment=evidence.get("boot_environment")) if match else []
                # The main assignment supplies required args; DEFAULT only drops
                # obsolete transport arguments so it cannot override the main one.
                updated = _adapt_args(words, plan, options)
                if name.endswith("_DEFAULT"):
                    if not match:
                        continue
                    required = set(_required_args(plan, options))
                    updated = [word for word in updated if word not in required]
                text = _grub_assignment(text, name, shlex.join(updated))
        elif path == "/etc/kernel/cmdline":
            text = shlex.join(_adapt_args(_boot_args(original.strip(), environment=evidence.get("boot_environment")), plan, options)) + "\n"
        else:
            text = re.sub(r"^options\s+(.*)$", lambda match: "options " + shlex.join(_adapt_args(_boot_args(match[1], environment=evidence.get("boot_environment")), plan, options)), original, flags=re.M)
        if text != original:
            _write(g, path, text, backup)


def _initrd_path(version, kernel, backend):
    if backend == "initramfs-tools":
        return f"/boot/initrd.img-{version}"
    return kernel.get("initrd") or f"/boot/initramfs-{version}.img"


def _initramfs_script(inspection, plan, options):
    commands = ["set -eu"]
    for version, kernel in inspection["platform"]["kernels"].items():
        if not VERSION.fullmatch(version):
            raise ValueError("Unsafe kernel version in platform inspection.")
        modular = sorted(set(plan["required_modules"]) - set(kernel.get("builtin", [])))
        path = _initrd_path(version, kernel, plan["initramfs_backend"])
        if plan["initramfs_backend"] == "dracut":
            command = "dracut --force --no-hostonly --no-hostonly-cmdline --add-drivers " + shlex.quote(" ".join(modular))
            if options["boot_attachment"] == "iscsi":
                command += " --add " + shlex.quote("iscsi " + plan["dracut_network_module"])
            commands += [command + " " + shlex.quote(path) + " " + shlex.quote(version), "listing=$(lsinitrd " + shlex.quote(path) + ")"]
        else:
            commands += ["update-initramfs " + ("-u" if kernel.get("initrd") else "-c") + " -k " + shlex.quote(version),
                         "listing=$(lsinitramfs " + shlex.quote(f"/boot/initrd.img-{version}") + ")"]
        for module in modular:
            expression = "/" + module.replace("_", "[-_]") + r"\.ko([. /]|$)"
            commands.append("printf '%s\\n' \"$listing\" | grep -Eq " + shlex.quote(expression) + " || { echo " + shlex.quote("Required platform driver absent from initramfs " + version + ": " + module) + " >&2; exit 1; }")
        if options["boot_attachment"] == "iscsi":
            commands += iscsi_initramfs_checks(path)
    return "\n".join(commands)


def _grub_commands(content):
    """Read generated commands as data, without evaluating GRUB scripts."""
    for number, line in enumerate(re.sub(r"\\\r?\n", " ", content).splitlines(), 1):
        # Restrict parsing to boot/menu commands. GRUB's other syntax need not
        # be POSIX-shell compatible (functions, variable tests, translations).
        if not re.search(r"(?:^|[;{])\s*(?:(?:then|else)\s+)?(?:linux(?:efi|16)?|blscfg)\b", line):
            continue
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";")
        lexer.whitespace_split = True
        pieces = list(lexer)
        segment = []
        for token in pieces + [";"]:
            if token in {";", "{", "}"}:
                while segment and segment[0] in {"then", "else", "{"}:
                    segment.pop(0)
                if segment and segment[0] in {"linux", "linuxefi", "linux16", "blscfg"}:
                    yield number, segment
                segment = []
            else:
                segment.append(token)


def _verify_generated_grub(evidence, plan, options):
    blockers = list(evidence.get("generated_grub_errors", []))
    files = evidence.get("generated_grub") or {}
    main = "/boot/grub/grub.cfg" if evidence.get("tools", {}).get("update-grub") else "/boot/grub2/grub.cfg"
    if not files.get(main, "").strip():
        return blockers + ["Resulting generated GRUB menu is missing or unreadable: " + main]
    kernels, covered = set(evidence.get("kernels", {})), set()
    bls = False
    for path, content in files.items():
        try:
            for number, command in _grub_commands(content):
                if command[0] == "blscfg":
                    if path == main:
                        if len(command) != 1:
                            blockers.append("Custom blscfg arguments cannot be verified in " + path)
                        else:
                            bls = True
                    continue
                if len(command) < 2:
                    blockers.append(f"Generated GRUB kernel command has no image path: {path}:{number}")
                    continue
                version = PurePosixPath(command[1]).name.removeprefix("vmlinuz-")
                if version not in kernels:
                    continue
                words = []
                for token in command[2:]:
                    words.extend(_boot_args(token, environment=evidence.get("boot_environment"))
                                 if "$" in token or "`" in token else [token])
                if set(words) != set(_adapt_args(words, plan, options)):
                    blockers.append(f"Generated GRUB root/transport/serial arguments conflict with the prepared profile: {path}:{number} ({version}).")
                if path == main:
                    covered.add(version)
        except ValueError as exc:
            blockers.append(f"Cannot verify generated GRUB arguments in {path}: {exc}")
    if bls:
        for path, content in evidence.get("boot_files", {}).items():
            if not path.startswith("/boot/loader/entries/"):
                continue
            images = re.findall(r"^linux\s+(\S+)\s*$", content, re.M)
            if len(images) == 1 and re.search(r"^options\s+\S", content, re.M):
                version = PurePosixPath(images[0]).name.removeprefix("vmlinuz-")
                if version in kernels:
                    covered.add(version)
    missing = kernels - covered
    if missing:
        blockers.append("Resulting GRUB/BLS boot entries are unverified for kernels: " + ", ".join(sorted(missing)) + ".")
    return blockers


def verify_platform(inspection, options, *, oci_config=None, target_provider="oci", receipt=None):
    options = _dict(options)
    plan = plan_platform(inspection, options, False, oci_config, target_provider)
    if not plan["requested"]:
        return plan
    if options.get("strategy") == "preserve":
        expected = (receipt or {}).get("preserved_files")
        if receipt is not None and not expected:
            plan["blockers"].append("The preservation receipt has no baseline file fingerprints.")
        if expected is not None:
            actual = inspection.get("platform", {}).get("portability", {}).get("hashes", {})
            changed = sorted(path for path in set(actual) | set(expected) if actual.get(path) != expected.get(path))
            if changed:
                plan["blockers"].append("Preserved boot/network configuration changed after validation: " + ", ".join(changed[:20]))
        plan["ready"] = not plan["blockers"]
        plan["verified"] = plan["ready"]
        return plan
    blockers = plan["blockers"]
    evidence = inspection.get("platform") or {}
    if plan["fstab_changes"]:
        blockers.append("Local fstab entries are not all using the prepared filesystem UUIDs.")
    required = set(plan["required_modules"])
    proven = (receipt or {}).get("verified_initrds", {})
    for version, kernel in evidence.get("kernels", {}).items():
        missing = required - set(kernel.get("builtin", [])) - set(kernel.get("initrd_modules") or [])
        record = proven.get(version, {})
        matching_receipt = bool(kernel.get("initrd_sha256") and kernel.get("initrd_sha256") == record.get("sha256")
                                and kernel.get("initrd") == record.get("path"))
        if missing and matching_receipt:
            missing -= set(record.get("modules", []))
        if missing:
            blockers.append(f"Kernel {version}: resulting initramfs inclusion is unverified for {', '.join(sorted(missing))}.")
        if options.get("boot_attachment") == "iscsi" and not (kernel.get("initrd_iscsi_userspace")
                                                                or matching_receipt and record.get("iscsi_boot") is True):
            blockers.append(f"Kernel {version}: resulting initramfs iSCSI boot userspace is unverified.")
    if not evidence.get("network_ready") or evidence.get("persistent_network_files"):
        blockers.append("Resulting portable DHCP configuration or persistent NIC naming is not verified.")
    if options.get("configure_serial_console", True) and (not evidence.get("serial_console_ready")
            or plan.get("architecture") == "aarch64" and evidence.get("serial_device") != "ttyAMA0"):
        blockers.append("Resulting serial-console configuration/service is not verified.")
    try:
        records = _boot_records(evidence)
        for path, words in records:
            # DEFAULT is supplementary and may be empty. Required arguments live
            # in the main assignment, BLS options and persistent kernel cmdline.
            if path == "/etc/default/grub":
                continue
            if set(words) != set(_adapt_args(words, plan, options)):
                blockers.append(f"Resulting boot transport/root arguments are inconsistent in {path}.")
        text = evidence.get("boot_files", {}).get("/etc/default/grub", "")
        match = re.search(r"^GRUB_CMDLINE_LINUX=(.*)$", text, re.M)
        if match:
            words = _boot_args(match[1], assignment=True, environment=evidence.get("boot_environment"))
            if set(words) != set(_adapt_args(words, plan, options)):
                blockers.append("Resulting GRUB root/transport arguments are not prepared.")
        elif not records:
            blockers.append("Resulting boot configuration cannot be verified.")
        match = re.search(r"^GRUB_CMDLINE_LINUX_DEFAULT=(.*)$", text, re.M)
        if match:
            words = _boot_args(match[1], assignment=True, environment=evidence.get("boot_environment"))
            expected = [word for word in _adapt_args(words, plan, options) if word not in set(_required_args(plan, options))]
            if words != expected:
                blockers.append("Supplementary GRUB arguments override the prepared boot transport/root.")
    except ValueError as exc:
        blockers.append(str(exc))
    blockers.extend(_verify_generated_grub(evidence, plan, options))
    plan["blockers"] = list(dict.fromkeys(blockers))
    plan["ready"] = not plan["blockers"]
    plan["verified"] = plan["ready"]
    return plan


def prepare_platform(work: Path, inspection, options, allow_network, log, *, oci_config=None, target_provider="oci"):
    from .engine import EngineError, ImageEngine, _guest, _mount, _roots, _run, _validate_fstab
    options = _dict(options)
    plan = plan_platform(inspection, options, allow_network, oci_config, target_provider)
    if not plan["requested"]:
        return plan
    if not plan["ready"]:
        raise EngineError("Platform preparation blocked: " + " ".join(plan["blockers"]))
    if options.get("strategy") == "preserve":
        # Re-read the actual working image after the user's explicit edits.
        # This branch never opens a writable guest or runs a guest command.
        current = ImageEngine().inspect(work)
        final = verify_platform(current, options, oci_config=oci_config, target_provider=target_provider)
        if not final["ready"]:
            raise EngineError("Existing hardware configuration cannot be preserved: " + " ".join(final["blockers"]))
        final["preserved_files"] = deepcopy(current["platform"]["portability"]["hashes"])
        log("Existing hardware boot prerequisites verified; boot files, initramfs and network settings retained without rewriting")
        return final
    for action in plan["actions"]:
        log("Platform: " + action)
    if plan["packages"]:
        _run(["virt-customize", "--format", "qcow2", "-a", str(work), "--network", "--install", ",".join(plan["packages"])], log)
        inspection = ImageEngine().inspect(work)
        plan = plan_platform(inspection, options, False, oci_config, target_provider)
        if not plan["ready"]:
            raise EngineError("Platform prerequisites remain missing after package installation: " + " ".join(plan["blockers"]))
    evidence = inspection["platform"]
    backup = BACKUPS + "/" + uuid4().hex
    commands = ["set -eu"]
    try:
        with _guest(work, "qcow2", readonly=False) as g:
            _mount(g, _roots(g), False)
            fstab = _read(g, "/etc/fstab")
            if hashlib.sha256(fstab.encode()).hexdigest() != evidence["fstab"]["sha256"]:
                raise ValueError("fstab changed after platform inspection.")
            changed = _fstab_text(fstab, plan["fstab_changes"])
            _validate_fstab(changed, g)
            if changed != fstab:
                _write(g, "/etc/fstab", changed, backup)
            _edit_boot(g, evidence, plan, options, backup)
            if plan["initramfs_backend"] == "initramfs-tools":
                path = "/etc/initramfs-tools/modules"
                content = _read(g, path)
                additions = [name for name in plan["required_modules"] if not re.search(r"^\s*" + re.escape(name) + r"(?:\s|$)", content, re.M)]
                _write(g, path, content.rstrip() + "\n# Cloud Image Forge platform drivers\n" + "\n".join(additions) + "\n", backup)
                _write(g, "/etc/initramfs-tools/conf.d/zz-cloud-image-forge-platform", "MODULES=most\n", backup)
            else:
                dracut = 'hostonly="no"\nhostonly_cmdline="no"\nadd_drivers+=" ' + " ".join(plan["required_modules"]) + ' "\n'
                if options["boot_attachment"] == "iscsi":
                    dracut += 'add_dracutmodules+=" iscsi ' + plan["dracut_network_module"] + ' "\n'
                _write(g, "/etc/dracut.conf.d/90-cloud-image-forge-platform.conf",
                       dracut, backup)
            if options.get("configure_network", True):
                generated = _network_files(plan["network_backend"])
                for path in set(evidence.get("network_files", []) + evidence.get("persistent_network_files", [])) - set(generated):
                    _backup(g, path, backup)
                    if g.is_file(path):
                        g.rm(path)
                for path, content in generated.items():
                    _write(g, path, content, backup, 0o600)
                # Keep cloud-init from restoring a stale source-machine NIC profile.
                _write(g, "/etc/cloud/cloud.cfg.d/98-cloud-image-forge-platform-network.cfg", "network:\n  config: disabled\n", backup)
                service = "NetworkManager.service" if plan["network_backend"] == "NetworkManager" else "systemd-networkd.service"
                commands += ["systemctl --root=/ enable " + service]
                competitors = {"NetworkManager.service", "systemd-networkd.service", "networking.service", "network.service"} - {service}
                for competitor in sorted(competitors):
                    if any(g.is_file(directory + "/" + competitor) for directory in ("/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system")):
                        commands.append("systemctl --root=/ disable " + competitor)
                if plan["network_backend"] == "netplan":
                    commands.append("netplan generate")
            if options.get("configure_serial_console", True):
                commands.append(f"systemctl --root=/ enable serial-getty@{plan['serial_device']}.service")
            commands.append(_initramfs_script(inspection, plan, options))
            commands.append("update-grub" if evidence["tools"].get("update-grub") else "grub2-mkconfig -o /boot/grub2/grub.cfg")
            _write(g, PROFILE, json.dumps({"options": options, "required_modules": plan["required_modules"],
                                          "provider_supported": plan["provider_supported"], "boot_tested": False}, indent=2) + "\n", backup)
        _run(["virt-customize", "--format", "qcow2", "-a", str(work), "--no-network", "--run-command", "\n".join(commands), "--selinux-relabel"], log)
        after = ImageEngine().inspect(work)
        after_kernels = after.get("platform", {}).get("kernels", {})
        if set(after_kernels) != set(evidence["kernels"]):
            raise EngineError("Kernel inventory changed during platform preparation.")
        for version, kernel in after_kernels.items():
            expected = _initrd_path(version, evidence["kernels"][version], plan["initramfs_backend"])
            if kernel.get("initrd") != expected:
                raise EngineError(f"Kernel {version}: inspected initramfs is not the file whose driver contents were verified.")
        receipt = {"verified_initrds": {version: {"path": kernel.get("initrd"), "sha256": kernel.get("initrd_sha256"),
                                                "modules": sorted(set(plan["required_modules"]) - set(kernel.get("builtin", []))),
                                                "iscsi_boot": options["boot_attachment"] == "iscsi"}
                                        for version, kernel in after_kernels.items()}}
        final = verify_platform(after, options, oci_config=oci_config, target_provider=target_provider, receipt=receipt)
        if not final["ready"]:
            raise EngineError("Platform verification failed after preparation: " + " ".join(final["blockers"]))
        final.update(receipt)
        final["backup_directory"] = backup
        log("Platform preparation verified against resulting guest configuration and every rebuilt initramfs; target boot test remains required")
        return final
    except ValueError as exc:
        if isinstance(exc, EngineError):
            raise
        raise EngineError(str(exc)) from exc
