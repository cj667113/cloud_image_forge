"""Destination defaults from documented OCI shapes, separate from guest readiness.

No disk content identifies its prior machine or a future physical NIC. The
resolver supplies a reviewable recipe; platform/OCI plans still prove the guest
prerequisites. Catalog membership never certifies a launch or import eligibility.
"""
from copy import deepcopy
import re

from .architecture import normalize_arch
from .oci import ACCELERATED_VM_SHAPES, ARM_SHAPES, X86_SHAPES
from .oci_guest import HARDWARE_NIC_DRIVERS, verified_nic_bundle


NIC_DRIVERS = ("auto", *sorted(HARDWARE_NIC_DRIVERS))
SOURCES = ["https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm",
           "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/edit-launch-options.htm",
           "https://docs.oracle.com/en-us/iaas/Content/Compute/References/bringyourownimage.htm"]


def _operating_system(inspection):
    """Import labels come from inspected release evidence, never a provider default."""
    operating_system = inspection.get("os", {})
    label = {"ubuntu": "Ubuntu", "debian": "Debian", "oraclelinux": "Oracle Linux",
             "rhel": "Red Hat Enterprise Linux", "fedora": "Fedora", "centos": "CentOS",
             "rocky": "Rocky Linux", "almalinux": "AlmaLinux"}.get(operating_system.get("distro"))
    name = operating_system.get("name")
    if not label and isinstance(name, str) and name.strip():
        label = name.strip()[:255]
    result = {"operating_system": label} if label else {}
    # The product name retains the patch version that inspect_get_major/minor drops.
    version = re.search(r"(?<![\w.])(\d+(?:\.\d+)+)(?![\w.])", name or "")
    if label and version:
        result["operating_system_version"] = version.group(1)
    elif label:
        release = inspection.get("oci_evidence", {}).get("os_version", {})
        major, minor = release.get("major"), release.get("minor")
        if type(major) is int and major > 0 and type(minor) is int and minor >= 0:
            result["operating_system_version"] = f"{major}.{minor}"
    return result


def _required_packages(inspection, platform_options, provider, oci_defaults):
    """Preview explicit download consent with pure plans; never enable it."""
    if platform_options.get("strategy") == "preserve":
        return []
    from .platform import plan_platform
    from .oci import OciConfig, compatibility_plan
    options = {**platform_options, "install_packages": True}
    config = OciConfig.model_validate(oci_defaults) if oci_defaults else None
    if config:
        config.guest.install_packages = True
    platform = plan_platform(inspection, options, True, oci_config=config, target_provider=provider)
    packages = set(platform.get("packages", []))
    if config:
        oci = compatibility_plan(inspection, config, True, platform_migration=options)
        packages.update(oci.get("packages", []))
    return sorted(packages)


def _profile(identifier, architecture, target, provider, shape=None):
    bare = target == "bare_metal"
    accelerated = shape in ACCELERATED_VM_SHAPES
    return {"id": identifier, "label": shape or f"{'General OCI' if provider == 'oci' else 'Generic'} {'ARM64' if architecture == 'aarch64' else 'x86_64'} {'bare metal' if bare else 'VM'}",
            "provider": provider, "architecture": architecture, "target": target, "shape": shape,
            "boot_attachment": "iscsi" if bare else "paravirtualized",
            "network_attachment": "vfio" if bare else "accelerated" if accelerated else "paravirtualized",
            "firmware": "UEFI_64" if bare or architecture == "aarch64" else None,
            "nic_driver": "auto" if bare else None, "requires_nic_driver": bare,
            "experimental": bare, "provider_supported": not bare,
            "sources": SOURCES if provider == "oci" else []}


def destination_catalog():
    profiles = [_profile("oci:" + shape, architecture, "bare_metal" if shape.startswith("BM.") else "vm", "oci", shape)
                for architecture, shapes in (("aarch64", ARM_SHAPES), ("x86_64", X86_SHAPES)) for shape in sorted(shapes)]
    profiles.extend(_profile(f"generic:{architecture}:{target}", architecture, target, "generic")
                    for architecture in ("aarch64", "x86_64") for target in ("vm", "bare_metal"))
    profiles.extend(_profile(f"oci:{architecture}:vm", architecture, "vm", "oci")
                    for architecture in ("aarch64", "x86_64"))
    return {"version": 1, "checked_on": "2026-10-28", "profiles": deepcopy(profiles),
            "nic_drivers": list(NIC_DRIVERS), "sources": list(SOURCES)}


def resolve_destination(inspection, selection):
    selection = selection.model_dump(exclude_unset=True) if hasattr(selection, "model_dump") else dict(selection or {})
    result = {"version": 1, "ready": False, "profile": None, "platform_migration": None,
              "oci_defaults": None, "blockers": [], "warnings": [], "boot_tested": False, "required_packages": []}
    profile = next((item for item in destination_catalog()["profiles"] if item["id"] == selection.get("profile_id")), None)
    if profile is None:
        result["blockers"].append("Select a documented destination profile; unknown shapes require explicit manual settings.")
        return result
    result["profile"] = profile
    arch = normalize_arch(inspection.get("os", {}).get("arch"))
    if arch != profile["architecture"]:
        result["blockers"].append(f"This destination requires {profile['architecture']}, but the image is {arch}. CPU architecture conversion is not supported.")
    source, strategy = selection.get("source", "unknown"), selection.get("strategy", "reconfigure")
    if source not in {"unknown", "vm", "bare_metal"}:
        result["blockers"].append("Source must be unknown, VM or bare metal; prior hardware is not inferred from the image.")
    if strategy not in {"preserve", "reconfigure"}:
        result["blockers"].append("Select Preserve & validate or Reconfigure.")
    nic = selection.get("nic_driver", profile["nic_driver"])
    if nic is not None and nic not in NIC_DRIVERS:
        result["blockers"].append("Select a supported physical NIC driver.")
    if profile["requires_nic_driver"] and nic not in NIC_DRIVERS:
        result["blockers"].append("Select the destination's physical NIC driver; the shape catalog does not identify it.")
    result["nic_drivers"] = []
    if profile["requires_nic_driver"] and nic == "auto":
        kernels = inspection.get("platform", {}).get("kernels", {})
        result["nic_drivers"] = verified_nic_bundle(kernels)
        if not result["nic_drivers"]:
            result["blockers"].append("No supported physical NIC driver is verified across every kernel. Refresh inspection or select the target driver explicitly.")
        result["warnings"].append("Automatic NIC bundle: " + (", ".join(result["nic_drivers"]) or "unverified") + ". The destination NIC remains unverified.")
    if not profile["requires_nic_driver"]:
        nic = None
    result["platform_migration"] = {"enabled": True, "strategy": strategy, "source": source, "target": profile["target"],
                                    "boot_attachment": profile["boot_attachment"], "network_attachment": profile["network_attachment"],
                                    "nic_driver": nic, "install_packages": False,
                                    "configure_network": strategy == "reconfigure", "configure_serial_console": strategy == "reconfigure"}
    firmware = profile["firmware"] or inspection.get("boot", {}).get("recommended_firmware")
    if firmware not in {"UEFI_64", "BIOS"}:
        firmware = "UEFI_64" if "UEFI_64" in inspection.get("boot", {}).get("supported_firmware", []) else None
    if firmware is None:
        result["blockers"].append("Boot firmware is unknown. Refresh inspection or review an explicit firmware migration before preparing this destination.")
    if profile["experimental"]:
        result["warnings"].append("Bare-metal preparation is experimental and requires destination firmware iSCSI discovery plus the selected physical NIC. A hardware boot test is required.")
        if profile["provider"] == "oci":
            result["warnings"].append("OCI does not support external BYOI imports to bare metal; offline preparation does not establish provider import eligibility.")
    if source == "unknown":
        result["warnings"].append("The source machine type remains unknown; preparation follows the selected destination without inventing source history.")
    if profile["provider"] == "oci":
        network = {"paravirtualized": "PARAVIRTUALIZED", "accelerated": "ACCELERATEDPV", "vfio": "VFIO"}[profile["network_attachment"]]
        launch = "NATIVE" if profile["target"] == "bare_metal" else network
        storage = "ISCSI" if profile["boot_attachment"] == "iscsi" else "PARAVIRTUALIZED"
        values = {"Compute.LaunchMode": launch, "Network.AttachmentType": network,
                  "Storage.BootVolumeType": storage, "Storage.LocalDataVolumeType": storage,
                  "Storage.RemoteDataVolumeType": storage}
        if firmware:
            values["Compute.Firmware"] = firmware
        capabilities = {key: {"default_value": value, "values": [value]} for key, value in values.items()}
        optional = {"Storage.ConsistentVolumeNaming": bool(inspection.get("oci_evidence", {}).get("consistent_naming_rules")),
                    "Compute.SecureBoot": False, "Compute.AMD_SecureEncryptedVirtualization": False,
                    "Storage.Iscsi.MultipathDeviceSupported": False, "Network.IPv6Only": False}
        capabilities.update({key: {"default_value": value, "values": None} for key, value in optional.items()})
        result["oci_defaults"] = {"capabilities": capabilities,
                                  "import_options": {"launch_mode": launch, "shape_compatibility": [{"shape": profile["shape"]}] if profile["shape"] else [],
                                                     **_operating_system(inspection)}}
    result["ready"] = not result["blockers"]
    if result["ready"]:
        result["required_packages"] = _required_packages(inspection, result["platform_migration"], profile["provider"], result["oci_defaults"])
    return result
