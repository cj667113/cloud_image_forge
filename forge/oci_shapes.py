"""Bounded OCI shape suggestions, separate from guest and cloud boot readiness.

Only the documented AMD Standard PV VM group is expanded automatically.  A
shape's ISA/device class is useful compatibility evidence, not proof that every
application or CPU-specific binary will run on another processor generation.
"""
from __future__ import annotations

from copy import deepcopy

from .architecture import normalize_arch


CHECKED_ON = "2026-11-23"
SOURCES = [
    "https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm",
    "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/edit-launch-options.htm",
]
ARM_STANDARD_PV = ("VM.Standard.A1.Flex", "VM.Standard.A2.Flex", "VM.Standard.A4.Flex")
# Standard limits only. Extended-memory configurations are left to explicit
# entries; they must never be silently inferred for another shape.
AMD_STANDARD_PV = {
    "VM.Standard.E4.Flex": {"max_ocpus": 64, "max_memory_gbs": 1024},
    "VM.Standard.E5.Flex": {"max_ocpus": 126, "max_memory_gbs": 1024},
    "VM.Standard.E6.Flex": {"max_ocpus": 126, "max_memory_gbs": 1454},
}


def platform_launch_mode(target, boot, network):
    """Preferred OCI mode for the selected guest-facing attachments."""
    if target == "bare_metal":
        return "NATIVE" if boot == "iscsi" and network == "vfio" else "CUSTOM"
    if boot == "paravirtualized" and network in {"accelerated", "paravirtualized"}:
        return "ACCELERATEDPV" if network == "accelerated" else "PARAVIRTUALIZED"
    return "CUSTOM"


def shape_compatibility_catalog() -> dict:
    return {"version": 1, "checked_on": CHECKED_ON, "sources": list(SOURCES),
            "groups": [{"id": "amd-standard-pv", "architecture": "x86_64", "target": "vm",
                        "boot_attachment": "PARAVIRTUALIZED", "network_attachment": "PARAVIRTUALIZED",
                        "shapes": [{"shape": name, **limits} for name, limits in AMD_STANDARD_PV.items()]}]}


def _bounded_sibling(shape: str, seeds: list[dict]) -> dict | None:
    limits = AMD_STANDARD_PV[shape]
    result = {"shape": shape}
    for suffix in ("ocpus", "memory_gbs"):
        low, high = "min_" + suffix, "max_" + suffix
        result[low] = max([1] + [row[low] for row in seeds if row.get(low) is not None])
        result[high] = min([limits[high]] + [row[high] for row in seeds if row.get(high) is not None])
        if result[low] > result[high]:
            return None
    # Standard Flex has 1..64 GiB per OCPU, with the shape's total memory cap.
    # These independent image limits need at least one valid launch pair. OCI
    # still applies the per-OCPU ratio to each requested launch configuration.
    least_cpu = max(result["min_ocpus"], (result["min_memory_gbs"] + 63) // 64)
    most_cpu = min(result["max_ocpus"], result["max_memory_gbs"])
    return result if least_cpu <= most_cpu else None


def resolve_shape_compatibility(inspection: dict, config, platform_migration: dict | None = None) -> dict:
    """Return effective rows without altering the source, recipe, or explicit rows.

    This pure policy is used by both previews and final export. Callers still
    run guest readiness checks; this function does not project missing drivers,
    consult OCI, or claim region availability/import eligibility/boot success.
    """
    from .oci import OciConfig

    config = config if isinstance(config, OciConfig) else OciConfig.model_validate(config)
    options = config.import_options
    explicit = [row.model_dump(exclude_none=True) for row in options.shape_compatibility]
    result = {"version": 1, "checked_on": CHECKED_ON, "mode": options.shape_compatibility_mode,
              "effective_shapes": deepcopy(explicit), "explicit_shapes": [row["shape"] for row in explicit],
              "added_shapes": [], "skipped_shapes": [], "warnings": [], "sources": list(SOURCES),
              "boot_tested": False}
    if options.shape_compatibility_mode == "manual":
        return result
    names = set(result["explicit_shapes"])
    seeds = [row for row in explicit if row["shape"] in AMD_STANDARD_PV]
    if not explicit:
        return result
    if not seeds:
        result["warnings"].append("Automatic matching currently covers Standard E4, E5 and E6 Flex VMs. Forge will export the shapes you listed.")
        return result
    allowed = {key: setting.values if setting.values is not None else [setting.default_value]
               for key, setting in config.capabilities.items()}
    reason = None
    arch = normalize_arch(inspection.get("os", {}).get("arch"))
    if arch != "x86_64":
        reason = "Automatic AMD Standard VM siblings require an inspected x86_64 image."
    elif platform_migration and platform_migration.get("enabled") and platform_migration.get("target") != "vm":
        reason = "The selected hardware preparation target is not a VM."
    elif platform_migration and platform_migration.get("enabled") and (
            platform_migration.get("boot_attachment") != "paravirtualized"
            or platform_migration.get("network_attachment") != "paravirtualized"):
        reason = "Automatic VM siblings require a paravirtualized boot and network hardware preparation profile."
    elif any(name.startswith("BM.") for name in names):
        reason = "A list containing bare-metal targets is not expanded into VM siblings automatically."
    elif "PARAVIRTUALIZED" not in allowed.get("Storage.BootVolumeType", []):
        reason = "Automatic VM siblings require allowed paravirtualized boot attachment."
    elif "PARAVIRTUALIZED" not in allowed.get("Network.AttachmentType", []):
        reason = "Automatic VM siblings require allowed paravirtualized networking."
    elif any(config.capabilities[key].default_value != "PARAVIRTUALIZED"
             for key in ("Storage.BootVolumeType", "Network.AttachmentType")):
        reason = "Automatic matching requires paravirtualized boot and network defaults."
    elif not {"PARAVIRTUALIZED", "CUSTOM"}.intersection(allowed.get("Compute.LaunchMode", [])):
        reason = "Automatic VM siblings require a paravirtualized or custom image launch capability."
    elif config.import_options.launch_mode not in {"PARAVIRTUALIZED", "CUSTOM"}:
        reason = "Automatic VM siblings require a paravirtualized or custom import launch mode."
    elif True in allowed.get("Compute.AMD_SecureEncryptedVirtualization", []):
        reason = "Confidential-computing shape and OS support must be selected explicitly."
    if reason:
        result["skipped_shapes"] = [{"shape": name, "reason": reason} for name in AMD_STANDARD_PV if name not in names]
        result["warnings"].append(reason)
        return result
    for name in AMD_STANDARD_PV:
        if name in names:
            continue
        row = _bounded_sibling(name, seeds)
        if row is None:
            result["skipped_shapes"].append({"shape": name, "reason": "Explicit sibling OCPU/memory constraints have no common valid configuration within this shape's standard limits."})
        elif len(result["effective_shapes"]) >= 100:
            result["skipped_shapes"].append({"shape": name, "reason": "The listed entries have reached the 100-shape limit."})
        else:
            result["effective_shapes"].append(row)
            result["added_shapes"].append({"shape": name, "reason": "Shares the selected AMD VM's paravirtualized boot and network drivers. Its limits fit the selected OCPU and memory ranges."})
    if result["added_shapes"]:
        result["warnings"].append("Check CPU-specific software and the requested OCPU-to-memory ratio on each destination shape.")
    return result
