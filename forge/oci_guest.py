"""Evidence-based OCI guest preparation, separate from OCI control-plane JSON.

Inspection uses appliance APIs only. Preparation runs generated commands inside
virt-customize, against a disposable image. Nothing here certifies a cloud boot.
"""
from __future__ import annotations

import configparser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex


MODULE_CONFIG = {
    "virtio_pci": "CONFIG_VIRTIO_PCI", "virtio_blk": "CONFIG_VIRTIO_BLK",
    "virtio_scsi": "CONFIG_SCSI_VIRTIO", "virtio_net": "CONFIG_VIRTIO_NET",
    "virtio_console": "CONFIG_VIRTIO_CONSOLE", "sd_mod": "CONFIG_BLK_DEV_SD",
    "e1000": "CONFIG_E1000", "sym53c8xx": "CONFIG_SCSI_SYM53C8XX_2",
    "ata_piix": "CONFIG_ATA_PIIX", "iscsi_tcp": "CONFIG_ISCSI_TCP",
    "dm_multipath": "CONFIG_DM_MULTIPATH", "ixgbevf": "CONFIG_IXGBEVF",
    "iavf": "CONFIG_IAVF", "mlx5_core": "CONFIG_MLX5_CORE", "ipv6": "CONFIG_IPV6",
}
STORAGE_DRIVERS = {"PARAVIRTUALIZED": {"virtio_pci", "virtio_blk", "virtio_scsi", "sd_mod"},
                   "SCSI": {"sym53c8xx", "sd_mod"}, "IDE": {"ata_piix", "sd_mod"},
                   "ISCSI": {"iscsi_tcp", "sd_mod"}}
STORAGE_KEYS = ("Storage.BootVolumeType", "Storage.LocalDataVolumeType", "Storage.RemoteDataVolumeType")
TOOL_NAMES = ("dracut", "update-initramfs", "lsinitrd", "lsinitramfs", "grubby", "update-grub",
              "grub2-mkconfig", "cloud-init", "NetworkManager", "netplan", "networkctl",
              "iscsiadm", "multipath", "systemctl", "oci-iscsi-config", "ocid")
NETWORK_PATTERNS = {"NetworkManager": ("/etc/NetworkManager/system-connections/*", "/etc/sysconfig/network-scripts/ifcfg-*"),
                    "netplan": ("/etc/netplan/*.yaml", "/etc/netplan/*.yml"),
                    "networkd": ("/etc/systemd/network/*.network",)}
BACKUP_ROOT = "/var/lib/cloud-image-forge/oci-backups"
PROFILE = "/var/lib/cloud-image-forge/oci-preparation.json"
SYSCTL_DISABLE = re.compile(r"^(\s*net\.ipv6\.conf\.[A-Za-z0-9_-]+\.disable_ipv6\s*=\s*)1\b", re.M)


def _read(g, path, limit=4 * 1024 * 1024):
    try:
        if g.is_file(path) and g.filesize(path) <= limit:
            value = g.read_file(path)
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    except RuntimeError:
        pass
    return ""


def _glob(g, pattern):
    try:
        return g.glob_expand(pattern)
    except RuntimeError:
        return []


def _module_names(paths):
    result = set()
    for path in paths:
        name = path.split(":", 1)[0].rsplit("/", 1)[-1].split(".ko", 1)[0].replace("-", "_")
        if name in MODULE_CONFIG:
            result.add(name)
    return sorted(result)


def _enabled(g, name):
    return bool(_glob(g, f"/etc/systemd/system/*.wants/{name}"))


def _network_evidence(g, tools):
    backend = "netplan" if tools.get("netplan") else "NetworkManager" if tools.get("NetworkManager") else "networkd" if tools.get("networkctl") else None
    texts = {path: _read(g, path) for pattern in NETWORK_PATTERNS.get(backend, ()) for path in _glob(g, pattern)
             if not path.endswith("ifcfg-lo")}
    ready = False
    if backend == "NetworkManager":
        profiles = []
        for path, content in texts.items():
            if "/system-connections/" in path:
                parser = configparser.ConfigParser(interpolation=None, strict=False)
                try:
                    parser.read_string(content)
                    if parser.get("connection", "type", fallback="") not in {"ethernet", "802-3-ethernet"}:
                        continue
                    profiles.append(parser.get("ipv4", "method", fallback="") == "auto"
                                    and parser.get("ipv6", "method", fallback="") == "auto"
                                    and not parser.get("connection", "interface-name", fallback="")
                                    and not parser.get("ethernet", "mac-address", fallback="")
                                    and not parser.get("802-3-ethernet", "mac-address", fallback="")
                                    and not parser.get("ethernet", "cloned-mac-address", fallback=""))
                except configparser.Error:
                    profiles.append(False)
            elif content:
                profiles.append(bool(re.search(r'^BOOTPROTO=["\']?dhcp', content, re.M))
                                and bool(re.search(r'^IPV6INIT=["\']?yes', content, re.M))
                                and bool(re.search(r'^IPV6_AUTOCONF=["\']?yes', content, re.M))
                                and not re.search(r"^(HWADDR|MACADDR|IPADDR)=", content, re.M))
        ready = bool(profiles) and all(profiles) and _enabled(g, "NetworkManager.service")
    elif backend == "netplan":
        text = "\n".join(texts.values())
        ready = len(texts) == 1 and bool(re.search(r"dhcp4:\s*true", text) and re.search(r"dhcp6:\s*true", text)) and not re.search(r"(?:macaddress|addresses|set-name):", text)
    elif backend == "networkd":
        text = "\n".join(texts.values())
        ready = len(texts) == 1 and bool(re.search(r"^DHCP=(yes|true)\s*$", text, re.M) and re.search(r"^IPv6AcceptRA=(yes|true)\s*$", text, re.M)) and not re.search(r"^(MACAddress|Address)=", text, re.M) and _enabled(g, "systemd-networkd.service")
    return backend, ready, list(texts)


def inspect_guest(g, root: str, partitions: list, kernels: list, boot: dict | None = None) -> dict:
    """Collect guest evidence, reusing boot detection from the unmounted phase."""
    boot = boot or {}
    firmware = {"UEFI_64": "UEFI_64" in boot.get("supported_firmware", []),
                "BIOS": "BIOS" in boot.get("supported_firmware", []),
                "efi_loaders": boot.get("efi_loaders", []),
                "bios_evidence": boot.get("bios_evidence", []),
                "partition_table": boot.get("partition_table", "unknown"),
                "boot_tested": False}
    tools = {name: any(g.is_file(f"{directory}/{name}") for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin")) for name in TOOL_NAMES}
    support = {}
    for kernel in kernels:
        version = kernel.removeprefix("/boot/vmlinuz-")
        if version.startswith("0-rescue-") or not re.fullmatch(r"[A-Za-z0-9_.+~-]+", version):
            continue
        config = dict(re.findall(r"^(CONFIG_[A-Z0-9_]+)=([ym])$", _read(g, f"/boot/config-{version}"), re.M))
        config = {key: value for key, value in config.items() if key in {*MODULE_CONFIG.values(), "CONFIG_AMD_MEM_ENCRYPT", "CONFIG_IPV6"}}
        modules = _module_names(_read(g, f"/lib/modules/{version}/modules.dep", 16 * 1024 * 1024).splitlines())
        builtin = set(_module_names(_read(g, f"/lib/modules/{version}/modules.builtin").splitlines()))
        builtin.update(name for name, key in MODULE_CONFIG.items() if config.get(key) == "y")
        initrd = next((p for p in (f"/boot/initramfs-{version}.img", f"/boot/initrd.img-{version}", f"/boot/initrd-{version}") if g.is_file(p)), None)
        initrd_modules = None
        if initrd:
            try:
                initrd_modules = _module_names(g.initrd_list(initrd))
            except RuntimeError:
                # Older libguestfs cannot inspect every concatenated/compressed initrd.
                pass
        support[version] = {"modules": modules, "builtin": sorted(builtin), "config": config,
                            "initrd": initrd, "initrd_modules": initrd_modules}
    boot_text = _read(g, "/etc/default/grub") + "\n" + "\n".join(_read(g, path) for path in _glob(g, "/boot/loader/entries/*.conf"))
    boot_text = "\n".join(line for line in boot_text.splitlines() if not line.lstrip().startswith("#"))
    blacklisted = set()
    for pattern in ("/etc/modprobe.d/*.conf", "/usr/lib/modprobe.d/*.conf", "/lib/modprobe.d/*.conf"):
        for path in _glob(g, pattern):
            blacklisted.update(name.replace("-", "_") for name in re.findall(r"^\s*(?:blacklist|install)\s+([A-Za-z0-9_-]+)\b", _read(g, path), re.M))
    for values in re.findall(r"(?:modprobe\.blacklist|rd\.driver\.blacklist|module_blacklist)=([^\s\"']+)", boot_text):
        blacklisted.update(value.replace("-", "_") for value in values.split(","))
    naming = []
    for pattern in ("/etc/udev/rules.d/*.rules", "/usr/lib/udev/rules.d/*.rules", "/lib/udev/rules.d/*.rules"):
        for path in _glob(g, pattern):
            active = "\n".join(line for line in _read(g, path).splitlines() if not line.lstrip().startswith("#"))
            if re.search(r'SYMLINK\s*\+?=\s*"[^"\n]*oracleoci/', active):
                naming.append(path)
    datasource = any(_glob(g, pattern) for pattern in ("/usr/lib/python*/site-packages/cloudinit/sources/DataSourceOracle.py", "/usr/lib/python*/dist-packages/cloudinit/sources/DataSourceOracle.py"))
    cloud_text = _read(g, "/etc/cloud/cloud.cfg") + "\n" + "\n".join(_read(g, path) for path in _glob(g, "/etc/cloud/cloud.cfg.d/*.cfg"))
    cloud_ready = tools.get("cloud-init") and datasource and bool(re.search(r"datasource_list:\s*\[\s*Oracle\b", cloud_text)) and not g.is_file("/etc/cloud/cloud-init.disabled") and "cloud-init=disabled" not in boot_text
    backend, network_ready, network_files = _network_evidence(g, tools)
    ipv6_files = [path for path in ["/etc/sysctl.conf"] + _glob(g, "/etc/sysctl.d/*.conf") if SYSCTL_DISABLE.search(_read(g, path))]
    return {"version": 1, "firmware": firmware, "kernels": support, "tools": tools,
            "network_backend": backend, "network_ready": bool(network_ready), "network_files": network_files,
            "oracle_datasource": bool(datasource), "cloud_init_ready": bool(cloud_ready),
            "consistent_naming_rules": sorted(set(naming)), "blacklisted_modules": sorted(blacklisted),
            "iscsi_boot_configured": any(arg in boot_text for arg in ("rd.iscsi.firmware=1", "rd.iscsi.ibft=1", "ip=ibft")) and g.is_dir("/usr/lib/dracut/modules.d/95iscsi"),
            "os_version": {"major": g.inspect_get_major_version(root), "minor": g.inspect_get_minor_version(root)},
            "ipv6_disable_files": ipv6_files, "boot_arguments": boot_text[:65536],
            "serial_console_ready": "console=ttyS0" in boot_text and _enabled(g, "serial-getty@ttyS0.service"),
            "multipath_configured": bool(_read(g, "/etc/multipath.conf") or _glob(g, "/etc/multipath/conf.d/*.conf")) and _enabled(g, "multipathd.service")}


def _values(config, key):
    setting = config.get("capabilities", {}).get(key, {})
    return setting.get("values") or [setting.get("default_value")]


def _flag(config, key):
    return config.get("capabilities", {}).get(key, {}).get("default_value") is True


def _supported(kernel, module):
    return module in kernel.get("modules", []) or module in kernel.get("builtin", [])


def _uek_supported(version):
    numbers = re.match(r"(\d+)\.(\d+)\.(\d+)-(\d+)", version)
    return "uek" in version.lower() and bool(numbers) and tuple(map(int, numbers.groups())) >= (5, 4, 17, 2036)


def plan_guest(inspection: dict, config: dict, allow_network=False, planned_firmware=()) -> dict:
    evidence = inspection.get("oci_evidence") or {}
    changes, blockers, warnings, packages = [], [], [], set()
    guest = config.get("guest", {})
    prepare = guest.get("prepare", True)
    tools = evidence.get("tools", {})
    kernels = evidence.get("kernels", {})
    distro = inspection.get("os", {}).get("distro", "")
    rpm = distro in {"oraclelinux", "rhel", "centos", "rocky", "almalinux", "fedora"}
    deb = distro in {"ubuntu", "debian"}
    if evidence.get("version") != 1:
        blockers.append("OCI readiness evidence is missing. Refresh inspection to inspect its bootloader, drivers and guest configuration.")
    for firmware in _values(config, "Compute.Firmware"):
        if firmware not in {"BIOS", "UEFI_64"} or (not evidence.get("firmware", {}).get(firmware) and firmware not in planned_firmware):
            hint = ("For BIOS-to-UEFI migration, enable migration in Boot & kernel and review its prerequisites."
                    if firmware == "UEFI_64" else "An existing compatible boot chain is required; conversion to this firmware is not automated.")
            blockers.append(f"{firmware}: compatible bootloader/partition evidence is missing. {hint}")
    if _flag(config, "Compute.SecureBoot"):
        blockers.append("OCI custom images do not support Secure Boot.")
    required = set()
    for key in STORAGE_KEYS:
        for kind in _values(config, key):
            if kind not in STORAGE_DRIVERS:
                blockers.append(f"{key}={kind}: no validated guest driver adapter is available.")
            required.update(STORAGE_DRIVERS.get(kind, set()))
    for kind in _values(config, "Network.AttachmentType"):
        if kind == "PARAVIRTUALIZED":
            required.update({"virtio_pci", "virtio_net"})
        elif kind == "E1000":
            required.add("e1000")
        elif kind == "VFIO":
            common = {"ixgbevf", "iavf", "mlx5_core"}
            for kernel in kernels.values():
                common &= {module for module in common if _supported(kernel, module)}
            if not common:
                blockers.append("VFIO networking needs an installed physical VF driver (ixgbevf, iavf or mlx5_core) across the selected kernels; the target shape's NIC must match it.")
            required.update(common)
            warnings.append("VFIO exposes a hardware VF: verify the selected shape's NIC against the inspected VF drivers. vfio-pci is a host passthrough driver, not a guest Ethernet driver.")
        else:
            blockers.append(f"Network.AttachmentType={kind}: no validated guest driver adapter is available.")
    iscsi = any("ISCSI" in _values(config, key) for key in STORAGE_KEYS)
    iscsi_boot = "ISCSI" in _values(config, "Storage.BootVolumeType")
    multipath = _flag(config, "Storage.Iscsi.MultipathDeviceSupported")
    if iscsi_boot and not evidence.get("iscsi_boot_configured"):
        blockers.append("iSCSI boot needs existing firmware discovery (rd.iscsi.firmware=1, rd.iscsi.ibft=1, or legacy ip=ibft) and dracut iSCSI support. Adding iscsi_tcp alone cannot convert this image to OCI native boot.")
    if iscsi_boot:
        warnings.append("Existing firmware-discovered iSCSI boot configuration will be retained; a successful OCI native-mode boot must still be validated.")
    if multipath:
        required.add("dm_multipath")
        if distro != "oraclelinux" or not kernels or not all(_uek_supported(version) for version in kernels):
            blockers.append("OCI custom-image iSCSI multipath requires Oracle Linux with UEK6U1 (5.4.17-2036) or later for every advertised kernel.")
        if not _flag(config, "Storage.ConsistentVolumeNaming"):
            blockers.append("OCI iSCSI multipath attachments require consistent volume naming and a device path.")
        warnings.append("Create multipath-enabled attachments on a supported shape and configure OCI IAM/agent or initiator connections after launch; offline preparation cannot establish those sessions.")
    if _flag(config, "Network.IPv6Only"):
        required.add("ipv6")
    if _flag(config, "Storage.ConsistentVolumeNaming") and not evidence.get("consistent_naming_rules"):
        blockers.append("Consistent volume naming requires installed OCI udev rules that create oracleoci/ device links. Stable UUID mounts are not equivalent; retain supported OCI platform rules or disable this capability.")
    if not kernels:
        blockers.append("No inspectable non-rescue kernel/module inventory was found.")
    for version, kernel in kernels.items():
        missing = sorted(module for module in required if not _supported(kernel, module))
        if missing:
            blockers.append(f"Kernel {version} lacks installed or built-in drivers: {', '.join(missing)}. Install a suitable kernel/module package before OCI preparation.")
        if not prepare:
            not_in_initrd = sorted(module for module in required if module not in kernel.get("builtin", []) and module not in (kernel.get("initrd_modules") or []))
            if not_in_initrd:
                blockers.append(f"Kernel {version}: initramfs inclusion cannot be verified for {', '.join(not_in_initrd)}. Enable guest preparation to rebuild and verify it.")
    conflicts = sorted(required & set(evidence.get("blacklisted_modules", [])))
    if conflicts:
        blockers.append("Required OCI drivers are blacklisted or overridden: " + ", ".join(conflicts) + ". Remove the conflicting module/boot configuration.")
    if _flag(config, "Compute.AMD_SecureEncryptedVirtualization"):
        if not kernels or not all(kernel.get("config", {}).get("CONFIG_AMD_MEM_ENCRYPT") == "y" for kernel in kernels.values()):
            blockers.append("AMD SEV requires CONFIG_AMD_MEM_ENCRYPT=y in every selected kernel; a capability flag cannot add kernel support.")
        if "mem_encrypt=off" in evidence.get("boot_arguments", ""):
            blockers.append("AMD memory encryption is disabled by mem_encrypt=off in the guest boot configuration.")
        warnings.append("AMD SEV support depends on OCI's current OS/kernel/AMD-shape matrix and attestation requirements; no offline command enables host SEV hardware.")
    if _flag(config, "Network.IPv6Only"):
        if not all(kernel.get("config", {}).get("CONFIG_IPV6") in {"y", "m"} for kernel in kernels.values()):
            blockers.append("IPv6-only support requires IPv6 in every installed kernel configuration.")
        if "ipv6.disable=1" in evidence.get("boot_arguments", ""):
            blockers.append("Remove ipv6.disable=1 from the guest boot parameters before advertising IPv6-only support.")
        if evidence.get("ipv6_disable_files") and not (prepare and guest.get("configure_network", True)):
            blockers.append("Guest sysctl configuration disables IPv6; enable network preparation or correct the listed configuration files.")
    if _flag(config, "Storage.ParaVirtualization.EncryptionInTransit"):
        warnings.append("Paravirtualized encryption-in-transit is an OCI attachment property. Confirm this custom image and target shape are supported by OCI; the exported disk is not encrypted by this setting.")
    warnings.append("Paravirtualized attachment version is applied by OCI. Installed VirtIO drivers are checked; the platform must offer the requested version.")
    initramfs = "dracut" if tools.get("dracut") and rpm else "initramfs-tools" if tools.get("update-initramfs") else "dracut" if tools.get("dracut") else None
    if prepare:
        if not tools.get("systemctl"):
            blockers.append("Automatic OCI guest preparation requires a systemd Linux guest.")
        if not initramfs:
            blockers.append("No supported initramfs generator is installed (dracut or update-initramfs).")
        else:
            changes.append("Include required OCI storage/network drivers and rebuild every non-rescue kernel initramfs; verify module inclusion.")
    def need_tool(name, package):
        if tools.get(name):
            return
        if prepare and guest.get("install_packages") and allow_network and package:
            packages.add(package)
        else:
            blockers.append(f"Missing {name}; install {package or 'the distribution-supported package'} or enable package installation and guest network access.")
    if prepare and initramfs:
        need_tool("lsinitrd" if initramfs == "dracut" else "lsinitramfs",
                  "dracut" if initramfs == "dracut" and rpm else "dracut-core" if initramfs == "dracut" and deb else "initramfs-tools-core" if deb else None)
    if iscsi:
        need_tool("iscsiadm", "iscsi-initiator-utils" if rpm else "open-iscsi" if deb else None)
    if multipath:
        need_tool("multipath", "device-mapper-multipath" if rpm else "multipath-tools" if deb else None)
        if prepare:
            changes.append("Enable multipathd and add a conservative find_multipaths configuration; retain existing vendor settings.")
        elif not evidence.get("multipath_configured"):
            blockers.append("Multipath configuration/service enablement is not present; enable guest preparation.")
    if guest.get("configure_cloud_init", True):
        need_tool("cloud-init", "cloud-init" if rpm or deb else None)
        if tools.get("cloud-init") and not evidence.get("oracle_datasource"):
            blockers.append("Installed cloud-init lacks the Oracle datasource. Upgrade cloud-init before preparing this image.")
        if "cloud-init=disabled" in evidence.get("boot_arguments", ""):
            blockers.append("Remove cloud-init=disabled from guest boot parameters before enabling OCI cloud-init preparation.")
        if prepare:
            changes.append("Select the Oracle cloud-init datasource, enable its units, and clear previous instance state for first-boot metadata/SSH-key provisioning.")
        elif not evidence.get("cloud_init_ready"):
            blockers.append("Oracle cloud-init datasource configuration is not ready; enable guest preparation.")
    backend = evidence.get("network_backend")
    if guest.get("configure_network", True):
        if not backend:
            blockers.append("No supported network renderer detected (NetworkManager, netplan or systemd-networkd); install/configure one before OCI preparation.")
        if prepare:
            changes.append(f"Back up existing {backend or 'network'} profiles and replace them with DHCP + IPv6 autoconfiguration without MAC binding; disable persistent NIC rules.")
        elif not evidence.get("network_ready"):
            blockers.append("DHCP/IPv6 networking without MAC binding cannot be verified; enable guest preparation.")
    elif not evidence.get("network_ready"):
        blockers.append("Network preparation is disabled and DHCP/IPv6 readiness without MAC binding cannot be verified; enable preparation or supply an already-configured guest.")
    if guest.get("configure_serial_console", True):
        if prepare:
            if not (tools.get("update-grub") or tools.get("grub2-mkconfig")):
                blockers.append("Serial-console preparation requires update-grub or grub2-mkconfig.")
            changes.append("Add ttyS0 serial console parameters, regenerate GRUB and enable serial-getty@ttyS0.service.")
        elif not evidence.get("serial_console_ready"):
            blockers.append("Serial-console boot parameters/service are not ready; enable preparation or disable this optional step.")
    if packages:
        changes.insert(0, "Install guest repository packages: " + ", ".join(sorted(packages)))
    if not prepare:
        changes = []
        warnings.append("Guest preparation is disabled. Read-only evidence checks apply; no image files will be adapted for OCI.")
    return {"changes": changes, "blockers": list(dict.fromkeys(blockers)), "warnings": list(dict.fromkeys(warnings)),
            "required_modules": sorted(required), "packages": sorted(packages), "network_backend": backend,
            "initramfs_backend": initramfs, "iscsi_boot": iscsi_boot, "multipath": multipath}


def _backup(g, path):
    if g.is_symlink(path):
        raise ValueError(f"Refusing to replace guest symlink {path} during OCI preparation.")
    if g.is_file(path):
        content = _read(g, path, 16 * 1024 * 1024)
        dest = BACKUP_ROOT + path + "." + hashlib.sha256(content.encode()).hexdigest()[:12]
        if not g.is_file(dest):
            g.mkdir_p(str(PurePosixPath(dest).parent))
            g.cp_a(path, dest)


def _write(g, path, content, mode=0o644):
    _backup(g, path)
    g.mkdir_p(str(PurePosixPath(path).parent))
    g.write(path, content.encode())
    g.chmod(mode, path)
    g.chown(0, 0, path)


def _network_files(backend):
    if backend == "NetworkManager":
        return {"/etc/NetworkManager/system-connections/cloud-image-forge-oci.nmconnection":
                "[connection]\nid=Cloud Image Forge OCI\ntype=ethernet\nautoconnect=true\nautoconnect-priority=999\n[ethernet]\n[ipv4]\nmethod=auto\nmay-fail=true\n[ipv6]\nmethod=auto\nmay-fail=true\n"}
    if backend == "netplan":
        return {"/etc/netplan/90-cloud-image-forge-oci.yaml":
                'network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    oci:\n      match:\n        name: "e*"\n      dhcp4: true\n      dhcp6: true\n      accept-ra: true\n      optional: true\n'}
    return {"/etc/systemd/network/10-cloud-image-forge-oci.network":
            "[Match]\nName=en* eth*\n[Network]\nDHCP=yes\nIPv6AcceptRA=yes\n[Link]\nRequiredForOnline=no\n"}


def _initramfs_script(inspection, plan):
    commands = ["set -eu"]
    for version, kernel in inspection["oci_evidence"]["kernels"].items():
        if not re.fullmatch(r"[A-Za-z0-9_.+~-]+", version):
            raise ValueError("Unsafe kernel version in OCI inspection")
        version_q = shlex.quote(version)
        if plan["initramfs_backend"] == "dracut":
            path = kernel.get("initrd") or f"/boot/initramfs-{version}.img"
            modules = sorted(set(plan["required_modules"]) & set(kernel.get("modules", [])))
            command = f"dracut --force --no-hostonly --add-drivers {shlex.quote(' '.join(modules))} {shlex.quote(path)} {version_q}"
            if plan["iscsi_boot"]:
                command += " --add iscsi"
            commands += [command, f"listing=$(lsinitrd {shlex.quote(path)})"]
        else:
            action = "-u" if kernel.get("initrd") else "-c"
            commands += [f"update-initramfs {action} -k {version_q}", f"listing=$(lsinitramfs {shlex.quote('/boot/initrd.img-' + version)})"]
        for module in plan["required_modules"]:
            if module in kernel.get("builtin", []):
                continue
            expression = r"/" + module.replace("_", "[-_]") + r"\.ko([. /]|$)"
            commands.append("printf '%s\\n' \"$listing\" | grep -Eq " + shlex.quote(expression) + " || { echo " + shlex.quote(f"Required driver {module} absent from initramfs {version}") + " >&2; exit 1; }")
    return "\n".join(commands)


def prepare_guest(work: Path, inspection: dict, config: dict, allow_network: bool, log) -> dict:
    from .engine import EngineError, ImageEngine, _grub_assignment, _guest, _mount, _roots, _run
    from .oci import OciConfig, compatibility_plan

    model = OciConfig.model_validate(config)
    plan = compatibility_plan(inspection, model, allow_network)
    if plan["blockers"]:
        raise EngineError("OCI preparation blocked: " + " ".join(plan["blockers"]))
    if not config.get("guest", {}).get("prepare", True):
        return plan
    for change in plan["changes"]:
        log("OCI: " + change)
    if plan["packages"]:
        _run(["virt-customize", "--format", "qcow2", "-a", str(work), "--network", "--install", ",".join(plan["packages"])], log)
        inspection = ImageEngine().inspect(work)
        plan = compatibility_plan(inspection, model, allow_network=False)
        if plan["blockers"]:
            raise EngineError("OCI prerequisites still missing after package installation: " + " ".join(plan["blockers"]))
    guest = config.get("guest", {})
    evidence = inspection["oci_evidence"]
    commands = []
    with _guest(work, "qcow2", readonly=False) as g:
        _mount(g, _roots(g), False)
        if plan["initramfs_backend"] == "initramfs-tools":
            path = "/etc/initramfs-tools/modules"
            existing = _read(g, path)
            additions = [module for module in plan["required_modules"] if not re.search(rf"^\s*{re.escape(module)}(?:\s|$)", existing, re.M)]
            _write(g, path, existing.rstrip() + "\n# OCI drivers added by Cloud Image Forge\n" + "\n".join(additions) + "\n")
        if guest.get("configure_network", True):
            generated = _network_files(plan["network_backend"])
            for path in evidence.get("network_files", []):
                if path not in generated and g.is_file(path):
                    _backup(g, path)
                    g.rm(path)
            persistent = "/etc/udev/rules.d/70-persistent-net.rules"
            if g.is_file(persistent):
                _backup(g, persistent)
                g.rm(persistent)
            for path, content in generated.items():
                _write(g, path, content, 0o600)
            for path in evidence.get("ipv6_disable_files", []):
                _write(g, path, SYSCTL_DISABLE.sub(r"\g<1>0", _read(g, path)))
            service = "NetworkManager.service" if plan["network_backend"] == "NetworkManager" else "systemd-networkd.service"
            commands += ["systemctl --root=/ enable " + service]
            competitors = ["systemd-networkd.service", "networking.service", "network.service"] if service == "NetworkManager.service" else ["NetworkManager.service", "networking.service", "network.service"]
            for competitor in competitors:
                if any(g.is_file(directory + "/" + competitor) for directory in ("/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system")):
                    commands.append("systemctl --root=/ disable " + competitor)
            if plan["network_backend"] == "netplan":
                commands.append("netplan generate")
        cloud_config = "# Generated OCI configuration; originals are retained under /var/lib/cloud-image-forge/oci-backups.\n"
        if guest.get("configure_cloud_init", True):
            cloud_config += "datasource_list: [Oracle]\ndatasource:\n  Oracle:\n    configure_secondary_nics: false\n"
            if g.is_file("/etc/cloud/cloud-init.disabled"):
                _backup(g, "/etc/cloud/cloud-init.disabled")
                g.rm("/etc/cloud/cloud-init.disabled")
            commands += ["cloud-init clean", "systemctl --root=/ unmask cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service", "systemctl --root=/ enable cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service"]
        if guest.get("configure_network", True):
            cloud_config += "network:\n  config: disabled\n"
        if guest.get("configure_network", True) or guest.get("configure_cloud_init", True):
            _write(g, "/etc/cloud/cloud.cfg.d/99-cloud-image-forge-oci.cfg", cloud_config)
        if plan["multipath"]:
            _write(g, "/etc/multipath/conf.d/90-cloud-image-forge-oci.conf", "defaults {\n    find_multipaths yes\n    user_friendly_names no\n}\n")
            commands += ["multipath -t >/dev/null", "systemctl --root=/ enable multipathd.service"]
        if guest.get("configure_serial_console", True):
            path = "/etc/default/grub"
            text = _read(g, path)
            match = re.search(r"^GRUB_CMDLINE_LINUX=(.*)$", text, re.M)
            parsed = shlex.split(match[1]) if match else []
            args = parsed[0] if parsed else ""
            if "$" in args or "`" in args:
                raise EngineError("GRUB_CMDLINE_LINUX uses shell expansion; configure serial arguments manually before OCI preparation.")
            args = args.strip() + " console=tty0 console=ttyS0,115200n8"
            _write(g, path, _grub_assignment(text, "GRUB_CMDLINE_LINUX", args.strip()))
            if evidence["tools"].get("grubby"):
                commands += ["grubby --update-kernel=ALL --args='console=tty0 console=ttyS0,115200n8'"]
            commands += ["update-grub" if evidence["tools"].get("update-grub") else "grub2-mkconfig -o /boot/grub2/grub.cfg", "systemctl --root=/ enable serial-getty@ttyS0.service"]
        _write(g, PROFILE, json.dumps({"capabilities": config["capabilities"], "required_modules": plan["required_modules"], "kernel_versions": list(evidence["kernels"])}, indent=2) + "\n")
    commands.append(_initramfs_script(inspection, plan))
    command = ["virt-customize", "--format", "qcow2", "-a", str(work), "--no-network"]
    for script in commands:
        command += ["--run-command", script]
    command += ["--selinux-relabel"]
    _run(command, log)
    # Check the actual written files and enabled services, not the provenance marker.
    after = ImageEngine().inspect(work)
    after_kernels = after.get("oci_evidence", {}).get("kernels", {})
    if set(after_kernels) != set(evidence["kernels"]):
        raise EngineError("Kernel inventory changed during OCI preparation; inspect the build before export.")
    for version, kernel in after_kernels.items():
        # The immediately preceding guest-native listing proved these modules are in
        # this freshly rebuilt initrd, even when older libguestfs cannot list it.
        verified = set(plan["required_modules"]) - set(kernel.get("builtin", []))
        kernel["initrd_modules"] = sorted(set(kernel.get("initrd_modules") or []) | verified)
    final_model = model.model_copy(deep=True)
    final_model.guest.prepare = False
    final = compatibility_plan(after, final_model, allow_network=False)
    if final["blockers"]:
        raise EngineError("OCI guest verification failed after preparation: " + " ".join(final["blockers"]))
    log("OCI guest preparation completed; actual configuration and rebuilt initramfs driver inclusion verified")
    return plan
