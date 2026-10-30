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

from .architecture import normalize_arch as _architecture

MODULE_CONFIG = {
    "virtio_pci": "CONFIG_VIRTIO_PCI", "virtio_blk": "CONFIG_VIRTIO_BLK",
    "virtio_scsi": "CONFIG_SCSI_VIRTIO", "virtio_net": "CONFIG_VIRTIO_NET",
    "virtio_console": "CONFIG_VIRTIO_CONSOLE", "sd_mod": "CONFIG_BLK_DEV_SD",
    "e1000": "CONFIG_E1000", "sym53c8xx": "CONFIG_SCSI_SYM53C8XX_2",
    "ata_piix": "CONFIG_ATA_PIIX", "iscsi_tcp": "CONFIG_ISCSI_TCP", "iscsi_ibft": "CONFIG_ISCSI_IBFT",
    "dm_multipath": "CONFIG_DM_MULTIPATH", "ixgbevf": "CONFIG_IXGBEVF",
    "iavf": "CONFIG_IAVF", "mlx5_core": "CONFIG_MLX5_CORE", "ipv6": "CONFIG_IPV6",
    "ixgbe": "CONFIG_IXGBE", "i40e": "CONFIG_I40E", "mlx4_en": "CONFIG_MLX4_EN",
    "bnxt_en": "CONFIG_BNXT",
    "amba_pl011": "CONFIG_SERIAL_AMBA_PL011",
}
HARDWARE_NIC_DRIVERS = frozenset({"ixgbe", "ixgbevf", "i40e", "iavf", "mlx4_en", "mlx5_core", "bnxt_en"})
ARCH_CONFIG = {"CONFIG_ARM64", "CONFIG_X86_64", "CONFIG_EFI", "CONFIG_EFI_STUB",
               "CONFIG_SERIAL_AMBA_PL011", "CONFIG_SERIAL_AMBA_PL011_CONSOLE",
               "CONFIG_ACPI", "CONFIG_PCI"}
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
CLOUD_CONFIG = "/etc/cloud/cloud.cfg.d/zz-cloud-image-forge-oci.cfg"
SYSCTL_DISABLE = re.compile(r"^(\s*net\.ipv6\.conf\.[A-Za-z0-9_-]+\.disable_ipv6\s*=\s*)1\b", re.M)


def _kernel_architecture(config):
    selected = [arch for key, arch in (("CONFIG_ARM64", "aarch64"), ("CONFIG_X86_64", "x86_64"))
                if config.get(key) == "y"]
    return selected[0] if len(selected) == 1 else "conflicting" if selected else None


def _architecture_errors(inspection, kernels, *, serial=False):
    """ARM admission requires fresh architecture/UEFI proof, never filename guesses."""
    arch = _architecture(inspection.get("os", {}).get("arch"))
    errors = []
    if arch not in {"x86_64", "aarch64"}:
        return ["Guest preparation supports x86_64 and ARM64 Linux images; it does not convert CPU architecture."]
    if arch == "aarch64":
        boot = inspection.get("boot") or {}
        if (_architecture(boot.get("architecture")) != arch or "UEFI_64" not in boot.get("supported_firmware", []) or
                not any(_architecture(loader.get("architecture")) == arch for loader in boot.get("efi_loaders", []))):
            errors.append("ARM64 requires existing ARM64 UEFI loader evidence. Refresh inspection; BIOS conversion is not supported for ARM64.")
        if not kernels:
            errors.append("ARM64 kernel architecture and EFI support are unverified; refresh inspection.")
    for version, kernel in kernels.items():
        config = kernel.get("config", {})
        actual = _kernel_architecture(config)
        if actual and actual != arch:
            errors.append(f"Kernel {version} targets {actual}, but the guest architecture is {arch}; architecture conversion is not supported.")
        elif arch == "aarch64" and actual != arch:
            errors.append(f"Kernel {version}: CONFIG_ARM64=y evidence is missing; refresh inspection or supply an ARM64 kernel.")
        if arch == "aarch64":
            if any(config.get(key) != "y" for key in ("CONFIG_EFI", "CONFIG_EFI_STUB")):
                errors.append(f"Kernel {version}: ARM64 UEFI requires CONFIG_EFI=y and CONFIG_EFI_STUB=y.")
            if serial and any(config.get(key) != "y" for key in ("CONFIG_SERIAL_AMBA_PL011", "CONFIG_SERIAL_AMBA_PL011_CONSOLE")):
                errors.append(f"Kernel {version}: ttyAMA0 console preparation requires built-in PL011 serial and console support.")
    return errors


def _serial_device(architecture):
    return "ttyAMA0" if _architecture(architecture) == "aarch64" else "ttyS0"


def verified_nic_bundle(kernels):
    """All supported NIC drivers present in every kernel, never a hardware guess."""
    if not kernels:
        return []
    common = set(HARDWARE_NIC_DRIVERS)
    for kernel in kernels.values():
        common &= set(kernel.get("modules", [])) | set(kernel.get("builtin", []))
    return sorted(common)


def _select_initramfs_backend(tools, kernels, *, rpm=False, iscsi=False):
    # Ubuntu 26.04 ships a dracut-compatible update-initramfs command. The
    # command's name alone therefore cannot establish initramfs-tools usage.
    archived_dracut = bool(kernels) and all(
        kernel.get("initramfs_backend") == "dracut" or
        (kernel.get("portability", {}).get("readable") is True
         and bool(kernel.get("portability", {}).get("dracut_modules")))
        for kernel in kernels.values())
    return ("dracut" if tools.get("dracut") and (rpm or iscsi or archived_dracut) else
            "initramfs-tools" if tools.get("update-initramfs") else
            "dracut" if tools.get("dracut") else None)


def _iscsi_module_directory(g):
    # dracut-ng relocated the unchanged installed module from 95 to 74.
    # Refuse competing copies rather than guess which implementation is active.
    paths = ["/usr/lib/dracut/modules.d/" + name for name in ("74iscsi", "95iscsi")
             if g.is_dir("/usr/lib/dracut/modules.d/" + name)]
    return paths[0] if len(paths) == 1 else None


def _hardware_architecture_errors(inspection, kernels, *, iscsi=False, hardware_network=False):
    """ARM firmware discovery uses ACPI iBFT, not the x86 legacy-memory scan.

    Linux CONFIG_ISCSI_IBFT depends on ACPI/SCSI; only ISCSI_IBFT_FIND is
    x86-specific. Physical PCI NICs still need PCI support and a selected driver.
    This proves kernel prerequisites, never that destination firmware has iBFT.
    """
    if _architecture(inspection.get("os", {}).get("arch")) != "aarch64":
        return []
    required = ({"CONFIG_ACPI"} if iscsi else set()) | ({"CONFIG_PCI"} if hardware_network else set())
    return [f"Kernel {version}: ARM64 hardware preparation requires {key}=y."
            for version, kernel in kernels.items() for key in sorted(required)
            if kernel.get("config", {}).get(key) != "y"]


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


def _tool_file(g, path):
    # Distribution commands such as Ubuntu netplan are regular executables
    # reached through a package-owned symlink. No command is executed here.
    try:
        return bool(g.is_file(path, followsymlinks=True))
    except TypeError:
        return bool(g.is_file(path))


def _cloud_units(g):
    def present(name):
        return any(_tool_file(g, directory + "/" + name) for directory in ("/usr/lib/systemd/system", "/lib/systemd/system"))
    network = "cloud-init-network.service" if present("cloud-init-network.service") else "cloud-init.service"
    units = ["cloud-init-local.service", network, "cloud-config.service", "cloud-final.service"]
    if not all(present(unit) for unit in units):
        return []
    if present("cloud-init-main.service"):
        units.insert(0, "cloud-init-main.service")
    return units


def _oracle_datasource_selected(g):
    """Recognize a literal final Oracle-only datasource policy in file order.

    No YAML tags, scripts or arbitrary configuration are evaluated. Unsupported
    merge directives and nonliteral datasource lists remain unverified.
    """
    selected, merge_override = False, False
    for path in ["/etc/cloud/cloud.cfg"] + sorted(_glob(g, "/etc/cloud/cloud.cfg.d/*.cfg")):
        lines = [line for line in _read(g, path).splitlines() if not line.lstrip().startswith("#")]
        declarations = [line for line in lines if re.match(r"^[\"']?datasource_list(?:[\"']?\s*:|\b)", line)]
        occurrences = [line for line in lines if re.search(r"\bdatasource_list[\"']?\s*:", line.split("#", 1)[0])]
        if len(occurrences) != len(declarations):
            # Indented YAML roots and flow maps are valid YAML, but this
            # deliberately narrow reader cannot establish their precedence.
            selected = False
        if declarations:
            match = re.fullmatch(r"datasource_list:\s*\[\s*(?P<oracle_quote>['\"]?)Oracle(?P=oracle_quote)\s*(?:,\s*(?P<none_quote>['\"]?)None(?P=none_quote)\s*)?\]\s*", declarations[-1].split("#", 1)[0])
            selected = len(occurrences) == len(declarations) == 1 and match is not None
        merge_override |= any(re.search(r"(?:\bmerge_how[\"']?|\bmerge_type[\"']?|<<)\s*:", line.split("#", 1)[0]) for line in lines)
    return selected and not merge_override


def _module_names(paths, guest=None, version=None):
    result = set()
    for entry in paths:
        path = entry.split(":", 1)[0].strip()
        match = re.search(r"/([A-Za-z0-9_-]+)\.ko(?:\.(?:xz|gz|zst))?$", "/" + path)
        if not match:
            continue
        name = match[1].replace("-", "_")
        if name not in MODULE_CONFIG:
            continue
        if guest is not None:
            # modules.dep can outlive a removed module package. A modular config
            # option or index entry alone is not proof of an installed driver.
            if path.startswith("/") or ".." in PurePosixPath(path).parts:
                continue
            try:
                if not guest.is_file(f"/lib/modules/{version}/{path}"):
                    continue
            except RuntimeError:
                continue
        result.add(name)
    return sorted(result)


def _enabled(g, name):
    return bool(_glob(g, f"/etc/systemd/system/*.wants/{name}"))


def _network_evidence(g, tools):
    backend = "netplan" if tools.get("netplan") else "NetworkManager" if tools.get("NetworkManager") else "networkd" if tools.get("networkctl") else None
    all_paths = {path for patterns in NETWORK_PATTERNS.values() for pattern in patterns for path in _glob(g, pattern)
                 if not path.endswith("ifcfg-lo")}
    if backend == "NetworkManager" and tools.get("networkctl") and any(path.endswith('.network') for path in all_paths) and not any('/NetworkManager/' in path or 'ifcfg-' in path for path in all_paths):
        backend = "networkd"
    selected_paths = {path for pattern in NETWORK_PATTERNS.get(backend, ()) for path in _glob(g, pattern)}
    texts = {path: _read(g, path) for path in sorted(selected_paths)
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
    # Explicit preparation backs up/removes all persistent renderer profiles,
    # including stale netplan input that would otherwise regenerate NIC binds.
    ready = ready and not (all_paths - set(texts))
    return backend, ready, sorted(all_paths)


def inspect_guest(g, root: str, partitions: list, kernels: list, boot: dict | None = None,
                  architecture: str | None = None) -> dict:
    """Collect guest evidence, reusing boot detection from the unmounted phase."""
    boot = boot or {}
    if architecture is None:
        try:
            architecture = g.inspect_get_arch(root)
        except (RuntimeError, AttributeError):
            architecture = None
    architecture = _architecture(architecture)
    serial = _serial_device(architecture)
    firmware = {"UEFI_64": "UEFI_64" in boot.get("supported_firmware", []),
                "BIOS": "BIOS" in boot.get("supported_firmware", []),
                "efi_loaders": boot.get("efi_loaders", []),
                "bios_evidence": boot.get("bios_evidence", []),
                "partition_table": boot.get("partition_table", "unknown"),
                "boot_tested": False}
    tools = {name: any(_tool_file(g, f"{directory}/{name}") for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin")) for name in TOOL_NAMES}
    support = {}
    for kernel in kernels:
        version = kernel.removeprefix("/boot/vmlinuz-")
        if version.startswith("0-rescue-") or not re.fullmatch(r"[A-Za-z0-9_.+~-]+", version):
            continue
        config = dict(re.findall(r"^(CONFIG_[A-Z0-9_]+)=([ym])$", _read(g, f"/boot/config-{version}"), re.M))
        config = {key: value for key, value in config.items() if key in {*MODULE_CONFIG.values(), *ARCH_CONFIG, "CONFIG_AMD_MEM_ENCRYPT", "CONFIG_IPV6"}}
        modules = _module_names(_read(g, f"/lib/modules/{version}/modules.dep", 16 * 1024 * 1024).splitlines(), g, version)
        builtin = set(_module_names(_read(g, f"/lib/modules/{version}/modules.builtin").splitlines()))
        builtin.update(name for name, key in MODULE_CONFIG.items() if config.get(key) == "y")
        initrd = next((p for p in (f"/boot/initramfs-{version}.img", f"/boot/initrd.img-{version}", f"/boot/initrd-{version}") if g.is_file(p)), None)
        initrd_modules, initramfs_backend = None, None
        if initrd:
            try:
                members = g.initrd_list(initrd)
                initrd_modules = _module_names(members)
                names = {name.removeprefix("./").lstrip("/") for name in members}
                if names.intersection({"usr/lib/dracut/modules.txt", "lib/dracut/modules.txt"}):
                    initramfs_backend = "dracut"
            except RuntimeError:
                # Older libguestfs cannot inspect every concatenated/compressed initrd.
                pass
        support[version] = {"modules": modules, "builtin": sorted(builtin), "config": config,
                            "architecture": _kernel_architecture(config),
                            "initrd": initrd, "initrd_modules": initrd_modules, "initramfs_backend": initramfs_backend}
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
    cloud_units = _cloud_units(g)
    cloud_units_ready = bool(cloud_units) and all(_enabled(g, unit) and not g.is_symlink("/etc/systemd/system/" + unit) for unit in cloud_units)
    cloud_ready = (tools.get("cloud-init") and datasource and _oracle_datasource_selected(g) and cloud_units_ready
                   and not (g.is_file("/etc/cloud/cloud-init.disabled") or g.is_symlink("/etc/cloud/cloud-init.disabled"))
                   and "cloud-init=disabled" not in boot_text)
    from .iscsi_network import inspect_handover
    backend, network_ready, network_files = _network_evidence(g, tools)
    ipv6_files = [path for path in ["/etc/sysctl.conf"] + _glob(g, "/etc/sysctl.d/*.conf") if SYSCTL_DISABLE.search(_read(g, path))]
    return {"version": 1, "architecture": architecture, "firmware": firmware, "kernels": support, "tools": tools,
            "network_backend": backend, "network_ready": bool(network_ready), "network_files": network_files,
            "oracle_datasource": bool(datasource), "cloud_init_ready": bool(cloud_ready),
            "cloud_init_units": cloud_units, "cloud_init_units_ready": cloud_units_ready,
            "consistent_naming_rules": sorted(set(naming)), "blacklisted_modules": sorted(blacklisted),
            "iscsi_network_handover": inspect_handover(g, backend, network_files),
            "iscsi_boot_configured": any(arg in boot_text for arg in ("rd.iscsi.firmware=1", "rd.iscsi.ibft=1", "ip=ibft")) and bool(_iscsi_module_directory(g)),
            "os_version": {"major": g.inspect_get_major_version(root), "minor": g.inspect_get_minor_version(root)},
            "ipv6_disable_files": ipv6_files, "boot_arguments": boot_text[:65536],
            "serial_device": serial,
            "serial_console_ready": bool(re.search(r"\bconsole=" + re.escape(serial) + r"(?:,|[\s\"']|$)", boot_text)) and _enabled(g, f"serial-getty@{serial}.service"),
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


def plan_guest(inspection: dict, config: dict, allow_network=False, planned_firmware=(), platform_nic_driver=None) -> dict:
    evidence = inspection.get("oci_evidence") or {}
    changes, blockers, warnings, packages = [], [], [], set()
    guest = config.get("guest", {})
    prepare = guest.get("prepare", True)
    portability = inspection.get("platform", {}).get("portability", {})
    bootstrap = portability.get("network_bootstrap", {})
    bootstrap_ready = (portability.get("version") == 1 and bootstrap.get("version") == 1
                       and bootstrap.get("ready") is True and not portability.get("network_blockers"))
    # The Oracle datasource can replace a prior machine's NIC profile at first
    # boot, but only the separately inspected implementation/configuration proof
    # establishes that path. Installed cloud-init alone is insufficient.
    network_ready = (bool(evidence.get("network_ready")) and not portability.get("network_blockers")) or (
        not prepare and bootstrap_ready and not _flag(config, "Network.IPv6Only"))
    tools = evidence.get("tools", {})
    kernels = evidence.get("kernels", {})
    arch = _architecture(inspection.get("os", {}).get("arch"))
    serial = _serial_device(arch)
    blockers.extend(_architecture_errors(inspection, kernels, serial=guest.get("configure_serial_console", True)))
    if prepare:
        from .architecture import execution_blocker
        blocker = execution_blocker(arch)
        if blocker:
            blockers.append(blocker)
    if arch == "aarch64":
        if set(_values(config, "Compute.Firmware")) != {"UEFI_64"}:
            blockers.append("ARM64 OCI guests require UEFI_64; BIOS capability and BIOS migration are not supported.")
        if (not set(_values(config, "Storage.BootVolumeType")) <= {"PARAVIRTUALIZED", "ISCSI"}
                or not set(_values(config, "Network.AttachmentType")) <= {"PARAVIRTUALIZED", "ACCELERATEDPV", "VFIO"}):
            blockers.append("ARM64 OCI profiles require UEFI with paravirtualized or firmware-iSCSI boot and PV, Accelerated PV or explicitly selected hardware networking.")
        hardware_network = "VFIO" in _values(config, "Network.AttachmentType")
        blockers.extend(_hardware_architecture_errors(inspection, kernels,
                        iscsi="ISCSI" in _values(config, "Storage.BootVolumeType"), hardware_network=hardware_network))
        if hardware_network and platform_nic_driver is None:
            blockers.append("ARM64 hardware networking requires an explicitly selected target NIC driver in the hardware profile; installed drivers do not identify destination hardware.")
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
        if kind in {"PARAVIRTUALIZED", "ACCELERATEDPV"}:
            required.update({"virtio_pci", "virtio_net"})
            if kind == "ACCELERATEDPV":
                warnings.append("ARM64 AcceleratedPV checks require existing VirtIO drivers, matching ARM64 firmware and compatible OCI shape/image capabilities; no ARM target launch has been verified by this offline check." if arch == "aarch64" else "The audited VM.Standard.E6.Ax.Flex AcceleratedPV guest uses virtio_net with virtio_pci. These guest drivers do not by themselves prove shape/image compatibility; validate a launch on the selected shape.")
        elif kind == "E1000":
            required.add("e1000")
        elif kind == "VFIO":
            if platform_nic_driver is not None and platform_nic_driver not in HARDWARE_NIC_DRIVERS | {"auto"}:
                raise ValueError("Unsupported selected hardware NIC driver")
            common = (set(verified_nic_bundle(kernels)) if platform_nic_driver == "auto" else
                      {platform_nic_driver} if platform_nic_driver else {"ixgbevf", "iavf", "mlx5_core"})
            for kernel in kernels.values():
                common &= {module for module in common if _supported(kernel, module)}
            if not common:
                blockers.append("Hardware networking needs the selected physical NIC driver across every kernel." if platform_nic_driver else "VFIO networking needs an installed physical VF driver (ixgbevf, iavf or mlx5_core) across the selected kernels; the target shape's NIC must match it.")
            required.update(common)
            warnings.append(("Automatic NIC bundle: " + ", ".join(sorted(common)) + ". The destination NIC remains unverified. " if platform_nic_driver == "auto" else
                             "The explicitly selected hardware NIC driver must match the destination device; no offline check proves the target hardware. " if platform_nic_driver else "VFIO exposes a hardware VF: verify the selected shape's NIC against the inspected VF drivers. ")
                            + "vfio-pci is a host passthrough driver, not a guest Ethernet driver.")
        else:
            blockers.append(f"Network.AttachmentType={kind}: no validated guest driver adapter is available.")
    iscsi = any("ISCSI" in _values(config, key) for key in STORAGE_KEYS)
    iscsi_boot = "ISCSI" in _values(config, "Storage.BootVolumeType")
    multipath = _flag(config, "Storage.Iscsi.MultipathDeviceSupported")
    if iscsi_boot and not evidence.get("iscsi_boot_configured"):
        blockers.append("iSCSI boot needs existing firmware discovery (rd.iscsi.firmware=1, rd.iscsi.ibft=1, or legacy ip=ibft) and dracut iSCSI support. Adding iscsi_tcp alone cannot convert this image to OCI native boot.")
    if iscsi_boot:
        required.add("iscsi_ibft")
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
            archived = kernel.get("initrd_modules")
            fallback = inspection.get("platform", {}).get("kernels", {}).get(version, {})
            if (archived is None and fallback.get("initrd") == kernel.get("initrd")
                    and fallback.get("initrd_sha256") and fallback.get("portability", {}).get("readable") is True):
                archived = fallback.get("initrd_modules")
            not_in_initrd = sorted(module for module in required if module not in kernel.get("builtin", []) and module not in (archived or []))
            if not_in_initrd:
                blockers.append(f"Kernel {version}: initramfs inclusion cannot be verified for {', '.join(not_in_initrd)}. Enable guest preparation to rebuild and verify it.")
    conflicts = sorted(required & set(evidence.get("blacklisted_modules", [])))
    if conflicts:
        blockers.append("Required OCI drivers are blacklisted or overridden: " + ", ".join(conflicts) + ". Remove the conflicting module/boot configuration.")
    if _flag(config, "Compute.AMD_SecureEncryptedVirtualization"):
        if arch != "x86_64":
            blockers.append("AMD SEV is an x86 AMD capability and cannot be enabled for ARM64 guests.")
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
    backend_kernels = {}
    for version, kernel in kernels.items():
        archived = inspection.get("platform", {}).get("kernels", {}).get(version, {})
        backend_kernels[version] = {**kernel, "portability": archived.get("portability", {})
                                   if archived.get("initrd") == kernel.get("initrd") else {}}
    initramfs = _select_initramfs_backend(tools, backend_kernels, rpm=rpm, iscsi=iscsi_boot)
    if iscsi_boot and initramfs != "dracut":
        blockers.append("Firmware-discovered iSCSI boot preparation requires the installed dracut initramfs framework.")
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
    firmware_network = None
    if iscsi_boot:
        from .iscsi_network import plan_network
        if prepare:
            firmware_network = plan_network(inspection.get("platform", {}), install=guest.get("install_packages"), allow_network=allow_network, rpm=rpm)
            packages.update(firmware_network["packages"])
            blockers.extend(firmware_network["blockers"])
        else:
            for version in kernels:
                actual = inspection.get("platform", {}).get("kernels", {}).get(version, {})
                if not actual.get("initrd_iscsi_userspace") or not (actual.get("portability", {}).get("firmware_network") or {}).get("ready"):
                    blockers.append(f"Kernel {version}: archived firmware iSCSI networking and discovery chain are unverified; refresh inspection or choose Reconfigure.")
        if not (prepare and guest.get("configure_network", True)) and not evidence.get("iscsi_network_handover"):
            blockers.append("Existing firmware-root network retention across switch-root is unverified; enable managed network preparation or configure retention explicitly.")
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
        if tools.get("cloud-init") and "cloud_init_units" in evidence and not evidence["cloud_init_units"]:
            blockers.append("The installed cloud-init systemd stages are incomplete; repair the cloud-init package before preparation.")
        if "cloud-init=disabled" in evidence.get("boot_arguments", ""):
            blockers.append("Remove cloud-init=disabled from guest boot parameters before enabling OCI cloud-init preparation.")
        if prepare:
            changes.append("Select the Oracle cloud-init datasource, enable its units, and clear previous instance state for first-boot metadata/SSH-key provisioning.")
        elif not (evidence.get("cloud_init_ready") or bootstrap_ready):
            blockers.append("Existing Oracle cloud-init initialization cannot be verified. Supply supported first-boot configuration or choose Reconfigure.")
    backend = evidence.get("network_backend")
    network_unverified = ("Existing IPv6-capable network initialization cannot be verified; supply portable IPv6 configuration or choose Reconfigure."
                          if _flag(config, "Network.IPv6Only") else
                          "Existing network initialization cannot be verified. Supply portable DHCP or a verified Oracle first-boot network path, or choose Reconfigure.")
    if guest.get("configure_network", True):
        if not backend:
            blockers.append("No supported network renderer detected (NetworkManager, netplan or systemd-networkd); install/configure one before OCI preparation.")
        if prepare:
            changes.append(f"Back up existing {backend or 'network'} profiles and replace them with DHCP + IPv6 autoconfiguration without MAC binding; disable persistent NIC rules.")
        elif not network_ready:
            blockers.append(network_unverified)
    elif not network_ready:
        blockers.append(network_unverified)
    if not prepare and not network_ready:
        blockers.extend(portability.get("network_blockers", []))
    if not prepare and bootstrap_ready and not evidence.get("network_ready") and network_ready:
        warnings.append("Retaining the verified Oracle first-boot DHCP path instead of rewriting prior NIC profiles. OCI metadata and a distinct destination instance identity are required; IPv6-only readiness is not inferred from this path.")
    if guest.get("configure_serial_console", True):
        if prepare:
            if not (tools.get("update-grub") or tools.get("grub2-mkconfig")):
                blockers.append("Serial-console preparation requires update-grub or grub2-mkconfig.")
            changes.append(f"Add {serial} serial console parameters, regenerate GRUB and enable serial-getty@{serial}.service.")
        elif not evidence.get("serial_console_ready") or arch == "aarch64" and evidence.get("serial_device") != serial:
            blockers.append("Serial-console boot parameters/service are not ready; enable preparation or disable this optional step.")
    if packages:
        changes.insert(0, "Install guest repository packages: " + ", ".join(sorted(packages)))
    if not prepare:
        changes = []
        warnings.append("Guest preparation is disabled. Read-only evidence checks apply; no image files will be adapted for OCI.")
    return {"changes": changes, "blockers": list(dict.fromkeys(blockers)), "warnings": list(dict.fromkeys(warnings)),
            "required_modules": sorted(required), "packages": sorted(packages), "network_backend": backend,
            "iscsi_network_handover": bool(evidence.get("iscsi_network_handover")),
            "dracut_network_module": firmware_network["module"] if firmware_network else None,
            "initramfs_backend": initramfs, "iscsi_boot": iscsi_boot, "multipath": multipath,
            "architecture": arch, "serial_device": serial}


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


def _network_files(backend, *, iscsi=False):
    if backend == "NetworkManager":
        from .iscsi_network import NM_KEEP, NM_KEEP_TEXT
        result = {"/etc/NetworkManager/system-connections/cloud-image-forge-oci.nmconnection":
                "[connection]\nid=Cloud Image Forge OCI\ntype=ethernet\nautoconnect=true\nautoconnect-priority=999\n[ethernet]\n[ipv4]\nmethod=auto\nmay-fail=true\n[ipv6]\nmethod=auto\nmay-fail=true\n"}
        if iscsi:
            result[NM_KEEP] = NM_KEEP_TEXT
            key = "/etc/NetworkManager/system-connections/cloud-image-forge-oci.nmconnection"
            result[key] = result[key].replace("autoconnect-priority=999", "autoconnect-priority=-999")
        return result
    if backend == "netplan":
        return {"/etc/netplan/90-cloud-image-forge-oci.yaml":
                'network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    oci:\n      match:\n        name: "e*"\n      dhcp4: true\n      dhcp6: true\n      accept-ra: true\n      optional: true\n' + ('      critical: true\n' if iscsi else '')}
    return {"/etc/systemd/network/10-cloud-image-forge-oci.network":
            "[Match]\nName=en* eth*\n[Network]\nDHCP=yes\nIPv6AcceptRA=yes\n" + ("KeepConfiguration=yes\n" if iscsi else "") + "[Link]\nRequiredForOnline=no\n"}


def _initramfs_script(inspection, plan):
    if plan["iscsi_boot"] and plan["initramfs_backend"] != "dracut":
        raise ValueError("iSCSI initramfs verification requires dracut")
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
                command += " --add 'iscsi network-manager' --omit 'systemd-networkd network-legacy'"
            commands += [command, f"listing=$(lsinitrd {shlex.quote(path)})"]
        else:
            action = "-u" if kernel.get("initrd") else "-c"
            commands += [f"update-initramfs {action} -k {version_q}", f"listing=$(lsinitramfs {shlex.quote('/boot/initrd.img-' + version)})"]
        for module in plan["required_modules"]:
            if module in kernel.get("builtin", []):
                continue
            expression = r"/" + module.replace("_", "[-_]") + r"\.ko([. /]|$)"
            commands.append("printf '%s\\n' \"$listing\" | grep -Eq " + shlex.quote(expression) + " || { echo " + shlex.quote(f"Required driver {module} absent from initramfs {version}") + " >&2; exit 1; }")
        if plan["iscsi_boot"]:
            from .platform import iscsi_initramfs_checks
            commands += iscsi_initramfs_checks(path, firmware_network=True)
    return "\n".join(commands)


def prepare_guest(work: Path, inspection: dict, config: dict, allow_network: bool, log,
                  *, extra_required_modules=(), platform_migration=None, mount_policy="auto") -> dict:
    from .engine import EngineError, ImageEngine, _grub_assignment, _guest, _mount, _roots, _run, _run_guest_script
    from .oci import OciConfig, compatibility_plan

    model = OciConfig.model_validate(config)
    plan = compatibility_plan(inspection, model, allow_network, platform_migration=platform_migration, mount_policy=mount_policy)
    if plan["blockers"]:
        raise EngineError("OCI preparation blocked: " + " ".join(plan["blockers"]))
    if not config.get("guest", {}).get("prepare", True):
        plan["_inspection"] = inspection
        return plan
    for change in plan["changes"]:
        log("OCI: " + change)
    original_network_backend = plan.get("network_backend")
    if plan["packages"]:
        _run(["virt-customize", "--format", "qcow2", "-a", str(work), "--network", "--install", ",".join(plan["packages"])], log)
        inspection = ImageEngine().inspect(work)
        inspection["oci_evidence"]["network_backend"] = original_network_backend
        plan = compatibility_plan(inspection, model, allow_network=False, platform_migration=platform_migration, mount_policy=mount_policy)
        if plan["blockers"]:
            raise EngineError("OCI prerequisites still missing after package installation: " + " ".join(plan["blockers"]))
    if extra_required_modules:
        from copy import deepcopy
        if any(not re.fullmatch(r"[A-Za-z0-9_]{1,100}", module) for module in extra_required_modules):
            raise EngineError("Invalid additional initramfs driver name.")
        inspection = deepcopy(inspection)
        plan["required_modules"] = sorted(set(plan["required_modules"]) | set(extra_required_modules))
        for version, kernel in inspection["oci_evidence"]["kernels"].items():
            hardware = inspection.get("platform", {}).get("kernels", {}).get(version, {})
            for key in ("modules", "builtin"):
                kernel[key] = sorted(set(kernel.get(key, [])) | set(hardware.get(key, [])))
            missing = set(plan["required_modules"]) - set(kernel["modules"]) - set(kernel["builtin"])
            if missing:
                raise EngineError(f"Kernel {version} lacks required migration drivers: {', '.join(sorted(missing))}")
    guest = config.get("guest", {})
    evidence = inspection["oci_evidence"]
    commands = []
    if plan["iscsi_boot"] and plan["network_backend"] != "NetworkManager":
        commands += ["systemctl --root=/ disable NetworkManager.service NetworkManager-wait-online.service"]
    with _guest(work, "qcow2", readonly=False) as g:
        _mount(g, _roots(g), False)
        if plan["initramfs_backend"] == "initramfs-tools":
            path = "/etc/initramfs-tools/modules"
            existing = _read(g, path)
            additions = [module for module in plan["required_modules"] if not re.search(rf"^\s*{re.escape(module)}(?:\s|$)", existing, re.M)]
            _write(g, path, existing.rstrip() + "\n# OCI drivers added by Cloud Image Forge\n" + "\n".join(additions) + "\n")
        if guest.get("configure_network", True):
            generated = _network_files(plan["network_backend"], iscsi=plan["iscsi_boot"])
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
            cloud_units = evidence.get("cloud_init_units") or ["cloud-init-local.service", "cloud-init.service", "cloud-config.service", "cloud-final.service"]
            unit_arguments = " ".join(shlex.quote(unit) for unit in cloud_units)
            commands += ["cloud-init clean", "systemctl --root=/ unmask " + unit_arguments, "systemctl --root=/ enable " + unit_arguments]
        if guest.get("configure_network", True):
            cloud_config += "network:\n  config: disabled\n"
        if guest.get("configure_network", True) or guest.get("configure_cloud_init", True):
            _write(g, CLOUD_CONFIG, cloud_config)
        if plan["multipath"]:
            _write(g, "/etc/multipath/conf.d/90-cloud-image-forge-oci.conf", "defaults {\n    find_multipaths yes\n    user_friendly_names no\n}\n")
            commands += ["multipath -t >/dev/null", "systemctl --root=/ enable multipathd.service"]
        if guest.get("configure_serial_console", True):
            serial = plan["serial_device"]
            path = "/etc/default/grub"
            text = _read(g, path)
            match = re.search(r"^GRUB_CMDLINE_LINUX=(.*)$", text, re.M)
            parsed = shlex.split(match[1]) if match else []
            args = parsed[0] if parsed else ""
            if "$" in args or "`" in args:
                raise EngineError("GRUB_CMDLINE_LINUX uses shell expansion; configure serial arguments manually before OCI preparation.")
            serial_args = f"console=tty0 console={serial},115200n8"
            args = args.strip() + " " + serial_args
            _write(g, path, _grub_assignment(text, "GRUB_CMDLINE_LINUX", args.strip()))
            if evidence["tools"].get("grubby"):
                commands += ["grubby --update-kernel=ALL --args=" + shlex.quote(serial_args)]
            commands += ["update-grub" if evidence["tools"].get("update-grub") else "grub2-mkconfig -o /boot/grub2/grub.cfg", f"systemctl --root=/ enable serial-getty@{serial}.service"]
        _write(g, PROFILE, json.dumps({"capabilities": config["capabilities"], "required_modules": plan["required_modules"], "kernel_versions": list(evidence["kernels"])}, indent=2) + "\n")
    commands.append(_initramfs_script(inspection, plan))
    _run_guest_script(work, "set -eu\n" + "\n".join(commands), log)
    # Check the actual written files and enabled services, not the provenance marker.
    after = ImageEngine().inspect(work)
    after_kernels = after.get("oci_evidence", {}).get("kernels", {})
    if set(after_kernels) != set(evidence["kernels"]):
        raise EngineError("Kernel inventory changed during OCI preparation; inspect the build before export.")
    for version, kernel in after_kernels.items():
        original = evidence["kernels"][version]
        expected = ((original.get("initrd") or f"/boot/initramfs-{version}.img")
                    if plan["initramfs_backend"] == "dracut" else f"/boot/initrd.img-{version}")
        if kernel.get("initrd") != expected:
            raise EngineError("OCI verification found a different initramfs from the one checked by the guest tools.")
        # The immediately preceding guest-native listing proved these modules are in
        # this freshly rebuilt initrd, even when older libguestfs cannot list it.
        verified = set(plan["required_modules"]) - set(kernel.get("builtin", []))
        kernel["initrd_modules"] = sorted(set(kernel.get("initrd_modules") or []) | verified)
    final_model = model.model_copy(deep=True)
    final_model.guest.prepare = False
    final = compatibility_plan(after, final_model, allow_network=False, platform_migration=platform_migration,
                               project_platform=False, mount_policy=mount_policy)
    if final["blockers"]:
        raise EngineError("OCI guest verification failed after preparation: " + " ".join(final["blockers"]))
    if extra_required_modules or plan["iscsi_boot"]:
        hardware = after.get("platform", {}).get("kernels", {})
        if set(hardware) != set(evidence["kernels"]):
            raise EngineError("Hardware kernel inventory changed during OCI preparation.")
        for version, original in evidence["kernels"].items():
            expected = ((original.get("initrd") or f"/boot/initramfs-{version}.img")
                        if plan["initramfs_backend"] == "dracut" else f"/boot/initrd.img-{version}")
            if hardware[version].get("initrd") != expected or not hardware[version].get("initrd_sha256"):
                raise EngineError("OCI migration receipt must identify the exact initramfs that was verified.")
        plan["verified_initrds"] = {
            version: {"path": kernel.get("initrd"), "sha256": kernel.get("initrd_sha256"),
                      "modules": sorted(set(plan["required_modules"]) - set(kernel.get("builtin", []))),
                      "iscsi_boot": bool(plan["iscsi_boot"]),
                      "firmware_network": kernel.get("portability", {}).get("firmware_network"), "projected": False}
            for version, kernel in after.get("platform", {}).get("kernels", {}).items()
        }
    plan["iscsi_network_handover"] = bool(after.get("oci_evidence", {}).get("iscsi_network_handover"))
    log("OCI guest preparation completed; actual configuration and rebuilt initramfs driver inclusion verified")
    plan["_inspection"] = after
    return plan
