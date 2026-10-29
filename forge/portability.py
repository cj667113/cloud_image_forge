"""Read-only evidence for retaining an existing VM/hardware boot configuration.

This checks offline prerequisites, not the machine on which an image last ran.
Guest scripts and GRUB configuration are read as data, never executed.
"""
from __future__ import annotations

import configparser
from pathlib import PurePosixPath
import re


VERSION = 1


def _archive_text(g, path, member, limit=256 * 1024):
    value = g.initrd_cat(path, member)
    if len(value) > limit:
        raise ValueError("Archive text exceeds the inspection limit: " + member)
    value = value.decode("utf-8") if isinstance(value, bytes) else value
    if "\0" in value:
        raise ValueError("Archive text contains binary data: " + member)
    return value


def _local_root_completion(content):
    """Recognize the actual systemd OR branch in dracut's generated wait hook.

Finding the target name in a comment or an unrelated command is insufficient.
Every write to this completion hook must have the recognized OR expression.
"""
    lines = [line.strip() for line in content.splitlines() if not line.lstrip().startswith("#")]
    writes = [line for line in lines if "initqueue/finished/iscsi_started.sh" in line]
    pattern = (r'''echo\s+"\$\{DRACUT_SYSTEMD\+systemctl\s+is-active\s+initrd-root-device\.target\s+\|\|\s*\}'''
               r'''\[\s+-f\s+'?/tmp/iscsistarted-(?:firmware|\$netroot_enc)'?\s*\]"\s*>\s*'''
               r'''"\$hookdir"/initqueue/finished/iscsi_started\.sh''')
    return bool(writes) and all(re.fullmatch(pattern, line) for line in writes)


def inspect_archive(g, path, members=None):
    result = {"version": VERSION, "readable": False, "dracut_modules": [], "hostonly": None,
              "embedded_cmdline": {}, "embedded_mounts": [], "embedded_fstab_present": False,
              "iscsi_local_root_completion": None, "lvm_userspace": False, "errors": []}
    if not path:
        result["errors"].append("No initramfs was found.")
        return result
    try:
        members = g.initrd_list(path) if members is None else members
        if len(members) > 100000 or sum(len(name) for name in members) > 16 * 1024 * 1024:
            raise ValueError("Initramfs member inventory exceeds the inspection limit.")
        names = {name.removeprefix("./").lstrip("/") for name in members}
        if any(".." in PurePosixPath(name).parts for name in names):
            raise ValueError("Initramfs inventory contains parent traversal paths.")
        result["hostonly"] = "etc/hostonly" in names
        result["lvm_userspace"] = any(name in names for name in ("usr/sbin/lvm", "sbin/lvm", "usr/bin/lvm", "bin/lvm"))
        modules = next((name for name in ("usr/lib/dracut/modules.txt", "lib/dracut/modules.txt") if name in names), None)
        if modules:
            result["dracut_modules"] = sorted(set(_archive_text(g, path, modules).split()))
        cmdlines = sorted(name for name in names if re.fullmatch(r"etc/cmdline\.d/[^/]+\.conf", name) or name == "etc/cmdline")
        if len(cmdlines) > 64:
            raise ValueError("Too many embedded initramfs command-line files.")
        result["embedded_cmdline"] = {name: _archive_text(g, path, name, 65536) for name in cmdlines}
        if "etc/fstab" in names:
            result["embedded_fstab_present"] = True
            fstab = _archive_text(g, path, "etc/fstab")
            if len(fstab.splitlines()) > 4096:
                raise ValueError("Embedded fstab exceeds the inspection line limit.")
            for line in fstab.splitlines():
                fields = line.split()
                fields = fields[:next((index for index, value in enumerate(fields) if value.startswith("#")), len(fields))]
                if not fields:
                    continue
                if not 4 <= len(fields) <= 6:
                    raise ValueError("Embedded fstab contains unsupported fields.")
                values = [re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value) for value in fields[:3]]
                if any(character in value for value in values for character in "\0\r\n"):
                    raise ValueError("Embedded fstab contains invalid escapes.")
                # Do not publish mount options, which may contain credentials.
                result["embedded_mounts"].append(dict(zip(("source", "mountpoint", "filesystem"), values)))
        hooks = sorted(name for name in names if re.fullmatch(r"(?:(?:usr|var)/)?lib/dracut/hooks/cmdline/[0-9]+-parse-iscsiroot\.sh", name))
        if len(hooks) > 8:
            raise ValueError("Too many archived iSCSI command-line hooks to verify.")
        systemd = {"systemd", "dracut-systemd"} <= set(result["dracut_modules"])
        target = any(name in names for name in ("usr/lib/systemd/system/initrd-root-device.target", "lib/systemd/system/initrd-root-device.target"))
        result["iscsi_local_root_completion"] = bool(systemd and target and hooks and all(
            _local_root_completion(_archive_text(g, path, name)) for name in hooks))
        result["readable"] = True
    except (RuntimeError, ValueError, UnicodeError, AttributeError, TypeError) as exc:
        result["errors"].append(str(exc))
    return result


def inspect_local_devices(g, partitions):
    """Resolve stable LV aliases from actual LVM inventory, not /dev path shape."""
    try:
        logical = set(g.lvs())
    except (RuntimeError, AttributeError):
        logical = set()
    result = []
    for partition in partitions:
        device = partition.get("device", "")
        aliases = {device}
        is_lv = device in logical
        for lv in logical:
            pieces = lv.split("/")
            if len(pieces) != 4 or pieces[:2] != ["", "dev"]:
                continue
            mapper = "/dev/mapper/" + pieces[2].replace("-", "--") + "-" + pieces[3].replace("-", "--")
            if device in {lv, mapper}:
                is_lv = True
                aliases.update({lv, mapper})
        result.append({"device": device, "aliases": sorted(aliases), "is_lv": is_lv,
                       "uuid": partition.get("uuid"), "filesystem": partition.get("filesystem"),
                       "mountpoint": partition.get("mountpoint")})
    return result


def _resolve_root(value, devices, root_uuid):
    if value.startswith("UUID="):
        matches = [device for device in devices if (device.get("uuid") or "").lower() == value[5:].lower()]
    elif value.startswith("/dev/"):
        matches = [device for device in devices if device.get("is_lv") and value in device.get("aliases", [])]
    else:
        return False
    return len(matches) == 1 and matches[0].get("mountpoint") == "/" and matches[0].get("uuid") == root_uuid


def stable_mount_source(entry, fstab, devices=()):
    """Prove a retained selector independently of a suggested replacement.

    Raw appliance device names never establish transport portability, even
    when they currently resolve. LVM names need actual LV metadata/aliases.
    """
    from .storage import _fstab_unescape, StorageError
    records = fstab.get("filesystems") or devices
    identity = entry.get("uuid") or (fstab.get("root_uuid") if entry.get("mountpoint") == "/" else None)
    candidates = [item for item in records if identity and (item.get("uuid") or "").lower() == identity.lower()]
    if len(candidates) != 1 or (entry.get("device") and entry["device"] != candidates[0].get("device")):
        return False
    try:
        source = _fstab_unescape(entry.get("source", ""))
    except StorageError:
        return False
    for prefix, field in (("UUID=", "uuid"), ("/dev/disk/by-uuid/", "uuid"),
                          ("LABEL=", "label"), ("/dev/disk/by-label/", "label")):
        if source.startswith(prefix):
            value = source[len(prefix):]
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            selected = [item for item in records if value and
                        ((item.get(field) or "").lower() == value.lower() if field == "uuid" else item.get(field) == value)]
            return len(selected) == 1 and selected[0].get("device") == candidates[0].get("device")
    candidate = candidates[0]
    named_lv = bool(re.fullmatch(r"/dev/mapper/[^/]+|/dev/(?!disk/|mapper/)[^/]+/[^/]+", source))
    return (named_lv and bool(candidate.get("is_lv") or candidate.get("lv_uuid"))
            and source in {candidate.get("device"), *candidate.get("aliases", [])})


def _boot_entries(evidence):
    from .platform import _boot_args, _grub_commands
    kernels = evidence.get("kernels", {})
    entries = {version: [] for version in kernels}
    environment = evidence.get("boot_environment", {})
    main = "/boot/grub/grub.cfg" if evidence.get("tools", {}).get("update-grub") else "/boot/grub2/grub.cfg"
    if not (evidence.get("generated_grub", {}).get(main) or "").strip():
        raise ValueError("The generated GRUB menu is missing or unreadable.")
    bls = False
    def valid_initrd(version, paths):
        expected = kernels[version].get("initrd")
        if not expected or not paths:
            return False
        normalized = [value.removeprefix("/boot") if value.startswith("/boot/") else value for value in paths]
        wanted = expected.removeprefix("/boot") if expected.startswith("/boot/") else expected
        return normalized[-1] == wanted and all(PurePosixPath(path).name in {"intel-ucode.img", "amd-ucode.img"} for path in normalized[:-1])
    for path, text in evidence.get("generated_grub", {}).items():
        commands = list(_grub_commands(text))
        lines = re.sub(r"\\\r?\n", " ", text).splitlines()
        for index, (number, command) in enumerate(commands):
            if command[0] == "blscfg":
                if path == main and len(command) == 1:
                    bls = True
                elif len(command) != 1:
                    raise ValueError("Custom BLS menu arguments cannot be verified.")
                continue
            if len(command) < 2:
                raise ValueError("A generated GRUB kernel command has no image path.")
            version = PurePosixPath(command[1]).name.removeprefix("vmlinuz-")
            if version in entries:
                if command[1] not in {"/boot/vmlinuz-" + version, "/vmlinuz-" + version}:
                    raise ValueError("Generated GRUB kernel path cannot be resolved to the inspected kernel.")
                end = commands[index + 1][0] - 1 if index + 1 < len(commands) else len(lines)
                following = "\n".join(lines[number - 1:end])
                initrds = re.findall(r"(?:^|[;{])\s*initrd(?:efi|16)?\s+([^;\n}]+)", following, re.M)
                if len(initrds) != 1 or not valid_initrd(version, _boot_args(initrds[0], environment=environment)):
                    raise ValueError(f"Kernel {version}: the generated GRUB initrd path does not identify the inspected archive.")
                words = []
                for token in command[2:]:
                    words.extend(_boot_args(token, environment=environment) if "$" in token or "`" in token else [token])
                entries[version].append({"path": f"{path}:{number}", "words": words})
    if bls:
        for path, text in evidence.get("boot_files", {}).items():
            if not path.startswith("/boot/loader/entries/"):
                continue
            images = re.findall(r"^linux\s+(\S+)\s*$", text, re.M)
            arguments = re.findall(r"^options\s+(.*)$", text, re.M)
            if len(images) != 1 or len(arguments) != 1:
                raise ValueError("Ambiguous BLS kernel/options entry: " + path)
            version = PurePosixPath(images[0]).name.removeprefix("vmlinuz-")
            if version in entries:
                initrds = re.findall(r"^initrd\s+(.*)$", text, re.M)
                if images[0] not in {"/boot/vmlinuz-" + version, "/vmlinuz-" + version} or len(initrds) != 1 or not valid_initrd(version, _boot_args(initrds[0], environment=environment)):
                    raise ValueError(f"Kernel {version}: the BLS kernel/initrd paths do not identify the inspected boot files.")
                entries[version].append({"path": path, "words": _boot_args(arguments[0], environment=environment)})
    return entries


def _transport(words, devices, root_uuid):
    roots = [word[5:] for word in words if word.startswith("root=")]
    remote = any(root.startswith(("iscsi", "/dev/nfs", "nfs", "dhcp", "live:", "http:", "https:", "nbd:")) for root in roots)
    mandatory = remote or any((word.partition("=")[0] in {"rd.neednet", "rd.iscsi.waitnet"} and word.partition("=")[2] not in {"0", "no", "false"})
                              or word.startswith(("ip=", "rd.iscsi.initiator=", "iscsi_initiator=", "rd.iscsi.target", "rd.iscsi.username", "rd.iscsi.password", "rd.iscsi.in."))
                              or word.startswith("netroot=") and word not in {"netroot=iscsi", "netroot=iscsi:"} for word in words)
    if mandatory:
        return "mandatory_network"
    if not roots or not all(_resolve_root(root, devices, root_uuid) for root in roots):
        return "unknown"
    firmware = any(word in {"rd.iscsi.firmware=1", "rd.iscsi.firmware=yes", "rd.iscsi.firmware=true"} for word in words)
    iscsi = any(word.startswith(("netroot=iscsi", "rd.iscsi.", "iscsi_")) for word in words)
    if iscsi:
        return "optional_firmware_iscsi" if firmware else "unknown"
    return "local"


def inspect_portability(g, partitions, evidence, base):
    from .cloud_bootstrap import inspect_bootstrap
    from .oci_guest import _glob, _network_files, _read
    network_files = base.get("network_files", [])
    direct = bool(base.get("network_ready") and not evidence.get("persistent_network_files"))
    if base.get("network_backend") == "NetworkManager":
        for path in network_files:
            text = _read(g, path)
            if "/ifcfg-" in path:
                direct = direct and not re.search(r"^\s*DEVICE\s*=", text, re.M) and bool(re.search(r'''^\s*ONBOOT=["']?yes["']?\s*$''', text, re.M))
            else:
                parser = configparser.ConfigParser(interpolation=None, strict=True)
                try:
                    parser.read_string(text)
                    direct = direct and parser.getboolean("connection", "autoconnect", fallback=True)
                except (ValueError, configparser.Error):
                    direct = False
    elif base.get("network_backend") in {"netplan", "networkd"}:
        # These renderers can bind to names even when DHCP is enabled. Recognize
        # the known wildcard profile by content, not a Forge marker/path alone.
        known = set(_network_files(base["network_backend"]).values())
        direct = direct and len(network_files) == 1 and _read(g, network_files[0]) in known
    bootstrap = inspect_bootstrap(g, base)
    network_blockers = []
    service = {"NetworkManager": "NetworkManager.service", "netplan": "systemd-networkd.service", "networkd": "systemd-networkd.service"}.get(base.get("network_backend"))
    service_paths = []
    service_dropins = []
    if service:
        service_paths = [directory + "/" + service for directory in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")]
        for path in service_paths:
            if g.is_symlink(path) and g.readlink(path) == "/dev/null":
                network_blockers.append("The network renderer service is masked: " + path)
            elif path.startswith(("/etc/", "/run/")) and (g.is_file(path) or g.is_symlink(path)):
                network_blockers.append("The network renderer service override requires review: " + path)
            service_dropins.extend(_glob(g, path + ".d/*.conf"))
        if service_dropins:
            network_blockers.append("Network renderer service drop-ins require review: " + ", ".join(sorted(service_dropins)))
    manager_files = ["/etc/NetworkManager/NetworkManager.conf"] + _glob(g, "/etc/NetworkManager/conf.d/*.conf") + _glob(g, "/usr/lib/NetworkManager/conf.d/*.conf")
    for path in manager_files:
        active = "\n".join(line for line in _read(g, path).splitlines() if not line.lstrip().startswith(("#", ";")))
        if re.search(r"^\s*(?:unmanaged-devices\s*=\s*\S|managed\s*=\s*(?:false|no|0)\s*$)", active, re.M | re.I):
            network_blockers.append("NetworkManager unmanaged-device policy requires review: " + path)
    paths = {"/etc/fstab", "/etc/default/grub", "/etc/kernel/cmdline", "/etc/cloud/cloud-init.disabled"}
    for key in ("boot_files", "generated_grub"):
        paths.update(evidence.get(key, {}))
    for key in ("boot_environment_paths", "network_files", "persistent_network_files"):
        paths.update(evidence.get(key, []))
    paths.update(bootstrap.get("files", []))
    paths.update(service_paths + service_dropins + manager_files)
    for pattern in ("/etc/modprobe.d/*.conf", "/usr/lib/modprobe.d/*.conf", "/lib/modprobe.d/*.conf",
                    "/etc/dracut.conf.d/*.conf", "/usr/lib/dracut/dracut.conf.d/*.conf",
                    "/etc/NetworkManager/conf.d/*.conf", "/usr/lib/NetworkManager/conf.d/*.conf"):
        paths.update(_glob(g, pattern))
    paths.add("/etc/dracut.conf")
    for version, kernel in evidence.get("kernels", {}).items():
        paths.update({"/boot/vmlinuz-" + version, "/boot/config-" + version})
        if kernel.get("initrd"):
            paths.add(kernel["initrd"])
    hashes, errors = {}, []
    for path in sorted(paths):
        try:
            if g.is_symlink(path):
                target = g.readlink(path)
                hashes[path] = "symlink:" + target
                if target != "/dev/null":
                    # A stable link name does not imply stable target bytes.
                    hashes[path] += ":sha256:" + g.checksum("sha256", path)
            elif g.is_file(path):
                hashes[path] = "sha256:" + g.checksum("sha256", path)
            else:
                hashes[path] = "absent"
        except (RuntimeError, AttributeError):
            errors.append("Cannot fingerprint existing configuration: " + path)
    return {"version": VERSION, "local_devices": inspect_local_devices(g, partitions),
            "network_direct_ready": direct and not network_blockers, "network_bootstrap": bootstrap,
            "network_blockers": network_blockers, "hashes": hashes, "errors": errors}


def assess_portability(inspection, options, target_provider="oci"):
    from .platform import NIC_DRIVERS, PV_DRIVERS, _boot_args, _boot_records
    from .oci_guest import _architecture_errors
    from .architecture import normalize_arch
    evidence = inspection.get("platform") or {}
    facts = evidence.get("portability") or {}
    result = {"version": VERSION, "status": "unknown", "ready": False, "scope": "offline_boot_prerequisites",
              "boot_tested": False, "source_platform": "unknown", "checks": [], "kernels": [],
              "root_transport": "unknown", "dual_environment": {"status": "unknown"}, "blockers": [], "warnings": []}
    def check(name, label, status, details):
        details = list(dict.fromkeys(details))
        result["checks"].append({"id": name, "label": label, "status": status, "evidence": details})
        if status != "ready":
            result["blockers"].extend(details or [label + " is not verified."])
    arch = normalize_arch(inspection.get("os", {}).get("arch"))
    architecture_errors = _architecture_errors(inspection, evidence.get("kernels", {}))
    from .oci_guest import _hardware_architecture_errors
    architecture_errors.extend(_hardware_architecture_errors(inspection, evidence.get("kernels", {}),
                               iscsi=options.get("boot_attachment") == "iscsi",
                               hardware_network=options.get("network_attachment") == "vfio"))
    check("architecture", "Native guest architecture", "blocked" if architecture_errors else "ready",
          architecture_errors or [f"Existing {arch} kernels are retained; no CPU architecture conversion is performed."])
    result["architecture"] = arch
    if facts.get("version") != VERSION:
        check("inspection", "Current preservation evidence", "unknown", ["Preservation evidence is missing. Refresh inspection to read the existing initramfs and boot configuration."])
        return result
    failures = evidence.get("errors", []) + evidence.get("boot_environment_errors", []) + evidence.get("generated_grub_errors", []) + facts.get("errors", [])
    hashes = facts.get("hashes") or {}
    fingerprint_paths = ["/etc/fstab"]
    for version, kernel in evidence.get("kernels", {}).items():
        fingerprint_paths.extend(["/boot/vmlinuz-" + version, kernel.get("initrd")])
    if not hashes or any(not path or not re.fullmatch(r"sha256:[0-9a-f]{64}", hashes.get(path, "")) for path in fingerprint_paths):
        failures.append("Complete fingerprints for the root mount configuration, installed kernels and initrds are unavailable.")
    check("inspection", "Readable existing configuration", "unknown" if failures else "ready", failures or ["Boot and configuration evidence was collected without executing guest code."])
    devices = facts.get("local_devices", [])
    fstab = evidence.get("fstab", {})
    root_uuid = fstab.get("root_uuid")
    mounts = list(fstab.get("errors", []))
    for entry in fstab.get("entries", []):
        if entry.get("optional") or entry.get("preserve") and entry.get("mountpoint") != "/":
            continue
        if not stable_mount_source(entry, fstab, devices):
            mounts.append(f"Mount {entry.get('mountpoint')}: existing source is not a verified unique filesystem label, UUID or LVM name.")
    repeated = set()
    seen = set()
    for entry in fstab.get("entries", []):
        if entry.get("filesystem") != "swap":
            continue
        identity = (entry.get("source"), entry.get("mountpoint"), entry.get("options"))
        if identity in seen:
            repeated.add(entry.get("source"))
        seen.add(identity)
    if repeated:
        result["warnings"].append("Identical duplicate swap entries are retained: " + ", ".join(sorted(repeated)) + ". Their presence alone is not treated as a boot failure.")
    if not root_uuid or not any(item.get("mountpoint") == "/" and item.get("uuid") == root_uuid for item in devices):
        mounts.append("A unique local root filesystem could not be resolved.")
    check("mounts", "Stable local mounts", "blocked" if mounts else "ready", mounts or ["Existing label/UUID/LVM mount identities resolve to this disk; rewriting fstab is unnecessary."])
    boot, network, nic = options.get("boot_attachment"), options.get("network_attachment"), options.get("nic_driver")
    from .oci_guest import verified_nic_bundle
    nic_modules = verified_nic_bundle(evidence.get("kernels", {})) if nic == "auto" else [nic] if nic in NIC_DRIVERS else []
    result["nic_drivers"] = nic_modules if network == "vfio" else []
    if network == "vfio" and nic == "auto":
        if not nic_modules:
            check("nic_bundle", "Automatic NIC bundle", "blocked", ["No supported physical NIC driver is present across every installed kernel."])
        result["warnings"].append("The automatic NIC bundle validates installed driver coverage; the destination NIC remains unverified.")
    required = set(PV_DRIVERS if boot == "paravirtualized" else {"iscsi_tcp", "iscsi_ibft", "sd_mod"})
    required.update({"virtio_pci", "virtio_net"} if network in {"paravirtualized", "accelerated"} else set(nic_modules))
    root = next((device for device in devices if device.get("mountpoint") == "/"), {})
    root_fs = root.get("filesystem")
    if root_fs in {"xfs", "ext4"}:
        required.add(root_fs)
    else:
        check("filesystem", "Root filesystem support", "unknown", ["Preservation checks currently verify XFS and ext4 root filesystem drivers."])
    if root.get("is_lv"):
        required.add("dm_mod")
    result["required_modules"] = sorted(required)
    entries = {}
    boot_errors, boot_unknown = [], []
    try:
        entries = _boot_entries(evidence)
        # Persisted inputs are also checked for conflicting transport flags, but
        # only generated GRUB/BLS entries establish a bootable kernel selection.
        inputs = _boot_records(evidence)
    except ValueError as exc:
        inputs = []
        boot_errors.append(str(exc))
    modes, optional_versions, all_needed, argument_blacklists = set(), set(), set(required), set()
    for version, kernel in evidence.get("kernels", {}).items():
        archive = kernel.get("portability", {})
        if not entries.get(version):
            boot_errors.append(f"Kernel {version}: no verified generated GRUB/BLS boot arguments.")
        embedded = []
        try:
            for text in archive.get("embedded_cmdline", {}).values():
                for line in text.splitlines():
                    if line.strip() and not line.lstrip().startswith("#"):
                        embedded.extend(_boot_args(line))
        except ValueError as exc:
            boot_errors.append(f"Kernel {version}: unreadable embedded boot arguments: {exc}")
        for entry in entries.get(version, []):
            words = entry["words"] + embedded
            for word in words:
                if word.partition("=")[0] in {"modprobe.blacklist", "rd.driver.blacklist", "module_blacklist"}:
                    argument_blacklists.update(name.replace("-", "_") for name in word.partition("=")[2].split(","))
            mode = _transport(words, devices, root_uuid)
            modes.add(mode)
            if not all(_resolve_root(word[5:], devices, root_uuid) for word in words if word.startswith("root=")) or not any(word.startswith("root=") for word in words):
                boot_errors.append(f"Kernel {version}: effective root does not resolve through this disk's stable UUID/LVM identity.")
            if root.get("is_lv"):
                lv_names = {alias.removeprefix("/dev/") for alias in root.get("aliases", []) if alias.startswith("/dev/") and not alias.startswith("/dev/mapper/")}
                selected_lvs = {word.partition("=")[2] for word in words if word.startswith("rd.lvm.lv=")}
                selected_vgs = {word.partition("=")[2] for word in words if word.startswith("rd.lvm.vg=")}
                if selected_lvs and not selected_lvs.intersection(lv_names) or selected_vgs and not selected_vgs.intersection(name.split("/")[0] for name in lv_names):
                    boot_errors.append(f"Kernel {version}: LVM activation arguments exclude the inspected root LV.")
                if any(word in {"rd.lvm=0", "rd.lvm=no", "rd.lvm=false"} for word in words):
                    boot_errors.append(f"Kernel {version}: boot arguments disable LVM activation for an LVM root.")
            if boot == "paravirtualized":
                if mode == "mandatory_network":
                    boot_errors.append(f"Kernel {version}: explicit network/remote-root requirements cannot be treated as optional firmware discovery.")
                elif mode == "unknown":
                    boot_errors.append(f"Kernel {version}: existing root/transport arguments are not recognized as a portable local root.")
                elif mode == "optional_firmware_iscsi":
                    optional_versions.add(version)
                    if archive.get("iscsi_local_root_completion") is not True:
                        boot_unknown.append(f"Kernel {version}: the actual archived systemd iSCSI local-root completion OR branch is unverified.")
            elif not any(word in {"rd.iscsi.firmware=1", "rd.iscsi.firmware=yes", "rd.iscsi.firmware=true", "rd.iscsi.ibft=1", "ip=ibft"} for word in words):
                boot_errors.append(f"Kernel {version}: existing firmware iSCSI discovery is not configured.")
        # Explicit mandatory flags in persistent inputs must not be waved away
        # because the currently generated menu happens to omit them.
        if boot == "paravirtualized":
            for path, words in inputs:
                if _transport(words, devices, root_uuid) == "mandatory_network":
                    boot_errors.append(f"Persistent boot configuration requires networking: {path}.")
        needed = required | ({"iscsi_tcp", "iscsi_ibft"} if version in optional_versions else set())
        all_needed.update(needed)
        installed = set(kernel.get("modules", [])) | set(kernel.get("builtin", []))
        archived = set(kernel.get("initrd_modules") or []) | set(kernel.get("builtin", []))
        absent = sorted(needed - installed)
        absent_initrd = sorted(needed - archived) if kernel.get("initrd_modules") is not None else []
        problems = []
        status = "ready"
        if absent or absent_initrd:
            status = "blocked"
            if absent:
                problems.append(f"Kernel {version}: missing installed/built-in drivers: {', '.join(absent)}.")
            if absent_initrd:
                problems.append(f"Kernel {version}: missing archived/built-in drivers: {', '.join(absent_initrd)}.")
        if archive.get("version") != VERSION or not archive.get("readable") or kernel.get("initrd_modules") is None:
            status = "unknown" if status == "ready" else status
            problems.append(f"Kernel {version}: initramfs contents cannot be read. Preserve mode cannot assume existing driver coverage.")
            problems.extend(f"Kernel {version}: {error}" for error in archive.get("errors", []))
        if not kernel.get("initrd_sha256"):
            status = "unknown" if status == "ready" else status
            problems.append(f"Kernel {version}: initramfs fingerprint cannot be read.")
        if boot == "iscsi" or version in optional_versions:
            if not kernel.get("initrd_iscsi_userspace"):
                status = "unknown" if status == "ready" else status
                problems.append(f"Kernel {version}: archived firmware iSCSI userspace is unverified.")
        if root.get("is_lv") and not archive.get("lvm_userspace"):
            status = "unknown" if status == "ready" else status
            problems.append(f"Kernel {version}: archived LVM activation userspace is unverified.")
        result["kernels"].append({"version": version, "status": status, "required_modules": sorted(needed),
                                  "missing_installed": absent, "missing_initramfs": absent_initrd})
        check("kernel:" + version, "Kernel " + version, status, problems or ["Required target drivers are installed/built-in and present in the existing initramfs."])
        if archive.get("hostonly"):
            result["warnings"].append(f"Kernel {version}: the initramfs is marked host-only; only the inspected target prerequisites are evaluated.")
    if not evidence.get("kernels"):
        boot_errors.append("No installed non-rescue kernels were inspected.")
    blocked = all_needed & (set(evidence.get("blacklisted_modules", [])) | argument_blacklists)
    if blocked:
        boot_errors.append("Required target drivers are blacklisted or overridden: " + ", ".join(sorted(blocked)))
    check("boot", "Existing boot transport", "blocked" if boot_errors else "unknown" if boot_unknown else "ready", boot_errors + boot_unknown or ["Generated boot entries retain stable local-root selection and compatible transport policy."])
    result["root_transport"] = "mandatory_network" if "mandatory_network" in modes else "unknown" if "unknown" in modes or not modes else "optional_firmware_iscsi" if "optional_firmware_iscsi" in modes else "local"
    bootstrap = facts.get("network_bootstrap", {})
    bootstrap_ready = target_provider == "oci" and bootstrap.get("ready") is True
    network_ready = (facts.get("network_direct_ready") or bootstrap_ready) and not facts.get("network_blockers")
    check("network", "Existing network initialization", "ready" if network_ready else "unknown",
          ["Existing unbound DHCP configuration is retained."] if network_ready and facts.get("network_direct_ready") else bootstrap.get("evidence", []) if network_ready else ["Neither portable DHCP nor an enabled, verified destination network initialization path could be established."] + facts.get("network_blockers", []) + bootstrap.get("blockers", []) + (["Oracle datasource bootstrapping requires OCI metadata; it does not establish generic-target networking."] if bootstrap.get("ready") and target_provider != "oci" else []))
    if arch == "x86_64" and nic in NIC_DRIVERS and result["kernels"]:
        dual_required = PV_DRIVERS | {"virtio_net", nic, "iscsi_tcp", "iscsi_ibft"}
        dual = all(dual_required <= (set(kernel.get("modules", [])) | set(kernel.get("builtin", [])))
                   and dual_required <= (set(kernel.get("initrd_modules") or []) | set(kernel.get("builtin", [])))
                   and kernel.get("initrd_iscsi_userspace") and kernel.get("portability", {}).get("iscsi_local_root_completion")
                   for kernel in evidence.get("kernels", {}).values())
        result["dual_environment"] = {"status": "ready" if dual and not result["blockers"] and result["root_transport"] == "optional_firmware_iscsi" else "unknown",
                                       "nic_driver": nic, "scope": "offline_prerequisites", "boot_tested": False}
    statuses = {item["status"] for item in result["checks"]}
    result["status"] = "blocked" if "blocked" in statuses else "unknown" if "unknown" in statuses else "ready"
    result["ready"] = result["status"] == "ready"
    result["blockers"] = list(dict.fromkeys(result["blockers"]))
    result["warnings"].append("This is offline prerequisite evidence, not a boot test or detection of the image's previous machine type. Destination firmware, metadata and network services remain external.")
    return result
