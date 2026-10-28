"""OCI image capabilities, validation, and offline deployment configuration.

The reference schema combines the documented global schema with current launch
API values. It is not a tenancy schema or proof an image boots on a given shape.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any, Literal
from urllib.parse import urlsplit
import zipfile

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator


SOURCES = [
    {"title": "OCI global image capability schema", "url": "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/configuringimagecapabilities.htm"},
    {"title": "OCI image import", "url": "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image/import/from-object.html"},
    {"title": "OCI image capability schema creation", "url": "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image-capability-schema/create.html"},
    {"title": "OCI networking types and supported shapes", "url": "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/edit-launch-options.htm"},
    {"title": "OCI launch option API values", "url": "https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.LaunchOptions.html"},
]
CHECKED_ON = "2026-10-28"
STORAGE_TYPES = ["ISCSI", "SCSI", "IDE", "PARAVIRTUALIZED"]
ACCELERATED_VM_SHAPES = {"VM.Standard.E6.Ax.Flex", "VM.DenseIO.E6.Ax.Flex",
                         "VM.Standard4.Ax.Flex", "VM.Standard.A4.Ax.Flex"}


def descriptor(kind, default, values=None):
    result = {"descriptorType": kind, "defaultValue": default, "source": "IMAGE"}
    if values is not None:
        result["values"] = values
    return result


GLOBAL_SCHEMA = {
    "Compute.AMD_SecureEncryptedVirtualization": descriptor("boolean", False),
    "Compute.Firmware": descriptor("enumstring", "UEFI_64", ["BIOS", "UEFI_64"]),
    "Compute.SecureBoot": descriptor("boolean", False),
    "Compute.LaunchMode": descriptor("enumstring", "PARAVIRTUALIZED", ["NATIVE", "EMULATED", "PARAVIRTUALIZED", "CUSTOM", "ACCELERATEDPV"]),
    "Network.AttachmentType": descriptor("enumstring", "PARAVIRTUALIZED", ["E1000", "VFIO", "PARAVIRTUALIZED", "ACCELERATEDPV"]),
    "Network.IPv6Only": descriptor("boolean", False),
    "Storage.BootVolumeType": descriptor("enumstring", "PARAVIRTUALIZED", STORAGE_TYPES),
    "Storage.LocalDataVolumeType": descriptor("enumstring", "PARAVIRTUALIZED", STORAGE_TYPES),
    "Storage.RemoteDataVolumeType": descriptor("enumstring", "PARAVIRTUALIZED", STORAGE_TYPES),
    "Storage.ConsistentVolumeNaming": descriptor("boolean", True),
    "Storage.ParaVirtualization.EncryptionInTransit": descriptor("boolean", True),
    "Storage.ParaVirtualization.AttachmentVersion": descriptor("enuminteger", 2, [1, 2]),
    "Storage.Iscsi.MultipathDeviceSupported": descriptor("boolean", False),
}

# Labels and effects are separate from the API keys; no display label becomes an API key.
DETAILS = {
    "Compute.AMD_SecureEncryptedVirtualization": ("AMD confidential computing (SEV)", "Validate guest kernel SEV support. Requires a compatible AMD shape and OCI platform configuration."),
    "Compute.Firmware": ("Firmware", "Verify BIOS/UEFI boot support for every advertised firmware. Optional BIOS-to-UEFI migration must pass its prerequisites and final inspection; metadata alone cannot install a bootloader."),
    "Compute.SecureBoot": ("Secure Boot", "OCI does not support Secure Boot for custom images; this must remain disabled."),
    "Compute.LaunchMode": ("Launch mode", "Match the device model to the guest drivers. Use CUSTOM for mixed settings; import mode is a separate OCI operation."),
    "Network.AttachmentType": ("Primary network attachment", "Prepare emulated, hardware-assisted, PV, or Accelerated PV networking. Accelerated PV uses VirtIO guest drivers on the reviewed E6 Ax VM and requires a supported Acceleron shape, compatible image, and regional schema."),
    "Network.IPv6Only": ("IPv6-only networking", "Configure IPv6-capable networking. OCI requires prior IPv6-only validation; VCN/subnet configuration remains external."),
    "Storage.BootVolumeType": ("Boot volume attachment", "Prepare boot storage drivers and initramfs, including early networking for iSCSI boot."),
    "Storage.LocalDataVolumeType": ("Local data volume attachment", "Include drivers for the selected local data volume attachment types."),
    "Storage.RemoteDataVolumeType": ("Remote data volume attachment", "Include drivers and initiator tools for the selected remote volume attachment types."),
    "Storage.ConsistentVolumeNaming": ("Consistent volume naming", "Require OCI device-naming support in the guest; an image capability does not install naming rules."),
    "Storage.ParaVirtualization.EncryptionInTransit": ("Paravirtualized encryption in transit", "OCI enables encryption for paravirtualized boot attachments. This does not encrypt the disk file and needs compatible platform/shape support."),
    "Storage.ParaVirtualization.AttachmentVersion": ("Paravirtualized attachment version", "OCI selects attachment version 1 or 2. Guest VirtIO readiness is checked; the platform must support the selected version."),
    "Storage.Iscsi.MultipathDeviceSupported": ("iSCSI multipath", "Prepare multipath tools/configuration for iSCSI attachments. OCI attachment settings and a cloud test are still needed."),
}


def normalize_schema(value: dict | None) -> dict:
    if value is None:
        return deepcopy(GLOBAL_SCHEMA)
    data = value.get("data", value)
    if not isinstance(data, dict):
        raise ValueError("OCI schema must be a JSON object")
    data = data.get("schemaData", data.get("schema-data", data))
    if not isinstance(data, dict) or not 1 <= len(data) <= 128:
        raise ValueError("OCI schema must contain 1–128 capability descriptors")
    result = {}
    for key, item in data.items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,159}", key) or not isinstance(item, dict):
            raise ValueError("Invalid OCI capability key or descriptor")
        kind = item.get("descriptorType", item.get("descriptor-type"))
        default = item.get("defaultValue", item.get("default-value"))
        choices = item.get("values")
        if kind == "boolean":
            if default in ("true", "false"):
                default = default == "true"
            if type(default) is not bool:
                raise ValueError(f"{key}: a boolean descriptor needs a boolean default")
            choices = None
        elif kind in {"enumstring", "enuminteger"}:
            expected = str if kind == "enumstring" else int
            if (not isinstance(choices, list) or not 1 <= len(choices) <= 64
                    or any(type(v) is not expected for v in choices) or type(default) is not expected
                    or default not in choices or len(set(choices)) != len(choices)):
                raise ValueError(f"{key}: enum values/default are invalid")
            if expected is str and any(len(v) > 256 for v in choices):
                raise ValueError(f"{key}: enum values are too long")
        else:
            raise ValueError(f"{key}: unsupported descriptor type {kind!r}")
        # A new version may add values, but cannot silently change a known key's type.
        if key in GLOBAL_SCHEMA and kind != GLOBAL_SCHEMA[key]["descriptorType"]:
            raise ValueError(f"{key}: unexpected descriptor type for a known capability")
        result[key] = descriptor(kind, default, choices)
    return result


def catalog(schema: dict | None = None) -> dict:
    rows = []
    for key, item in normalize_schema(schema).items():
        label, explanation = DETAILS.get(key, (key, "Additional tenancy capability. No automatic guest adaptation is implemented for this key; verify guest and platform requirements separately."))
        rows.append({"key": key, "label": label, "group": key.split(".")[0],
                     "descriptor_type": item["descriptorType"], "default_value": item["defaultValue"],
                     "values": item.get("values"), "description": explanation, "guest_action": explanation,
                     "custom_image_supported": key != "Compute.SecureBoot", "guest_adapter_known": key in DETAILS})
    return {"capabilities": rows, "sources": SOURCES, "checked_on": CHECKED_ON,
            "schema_origin": "supplied" if schema is not None else "reference_snapshot"}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


Scalar = StrictBool | StrictInt | StrictStr


class CapabilitySetting(StrictModel):
    default_value: Scalar
    values: list[Scalar] | None = Field(default=None, max_length=64)


class GuestPreparation(StrictModel):
    prepare: bool = True
    install_packages: bool = False
    configure_network: bool = True
    configure_cloud_init: bool = True
    configure_serial_console: bool = True
    acknowledge_ipv6_validation: bool = False


class ShapeCompatibility(StrictModel):
    shape: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.-]+$")
    min_ocpus: int | None = Field(default=None, ge=1)
    max_ocpus: int | None = Field(default=None, ge=1)
    min_memory_gbs: int | None = Field(default=None, ge=1)
    max_memory_gbs: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def bounds(self):
        for lower, upper in ((self.min_ocpus, self.max_ocpus), (self.min_memory_gbs, self.max_memory_gbs)):
            if lower is not None and upper is not None and lower > upper:
                raise ValueError("Minimum shape constraints cannot exceed maximum constraints")
        return self


class ImportOptions(StrictModel):
    compartment_id: str | None = Field(default=None, max_length=256)
    namespace: str | None = Field(default=None, max_length=256)
    bucket: str | None = Field(default=None, max_length=256)
    object_name: str | None = Field(default=None, max_length=1024)
    object_uri: str | None = Field(default=None, max_length=8192)
    display_name: str | None = Field(default=None, max_length=255)
    operating_system: str | None = Field(default=None, max_length=255)
    operating_system_version: str | None = Field(default=None, max_length=255)
    launch_mode: Literal["NATIVE", "EMULATED", "PARAVIRTUALIZED", "CUSTOM", "ACCELERATEDPV"] = "PARAVIRTUALIZED"
    freeform_tags: dict[str, str] = Field(default_factory=dict, max_length=100)
    defined_tags: dict[str, dict[str, Any]] = Field(default_factory=dict, max_length=100)
    shape_compatibility: list[ShapeCompatibility] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def valid_location(self):
        try:
            json.dumps(self.defined_tags, allow_nan=False)
        except (ValueError, TypeError) as exc:
            raise ValueError("Defined tags must contain valid JSON values without NaN or infinity") from exc
        if self.object_uri:
            parsed = urlsplit(self.object_uri)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError("OCI import object URI must be HTTPS, without user info or fragment")
            if self.namespace or self.bucket or self.object_name:
                raise ValueError("Select either an object URI or namespace/bucket/object, not both")
        if len({s.shape for s in self.shape_compatibility}) != len(self.shape_compatibility):
            raise ValueError("Each compatible shape can be specified once")
        return self


class OciConfig(StrictModel):
    capabilities: dict[str, CapabilitySetting] = Field(default_factory=dict, max_length=128)
    guest: GuestPreparation = Field(default_factory=GuestPreparation)
    import_options: ImportOptions = Field(default_factory=ImportOptions)
    global_schema_version: str | None = Field(default=None, max_length=256)
    global_schema: dict | None = None

    @model_validator(mode="after")
    def validate_capabilities(self):
        schema = normalize_schema(self.global_schema)
        unknown = self.capabilities.keys() - schema.keys()
        if unknown:
            raise ValueError("Unknown OCI capabilities (keys are case sensitive): " + ", ".join(sorted(unknown)))
        for key, desc in schema.items():
            kind = desc["descriptorType"]
            if key not in self.capabilities:
                default = desc["defaultValue"]
                self.capabilities[key] = CapabilitySetting(default_value=default, values=None if kind == "boolean" else [default])
            item = self.capabilities[key]
            expected = {"boolean": bool, "enumstring": str, "enuminteger": int}[kind]
            if type(item.default_value) is not expected:
                raise ValueError(f"{key}: wrong value type")
            if kind == "boolean":
                if item.values is not None:
                    raise ValueError(f"{key}: boolean capabilities do not have an allowed-values list")
            else:
                if item.values is None:
                    item.values = [item.default_value]
                if (not item.values or any(type(v) is not expected or v not in desc["values"] for v in item.values)
                        or item.default_value not in item.values or len(set(item.values)) != len(item.values)):
                    raise ValueError(f"{key}: preferred value must belong to the allowed subset of the global schema")
        if self.capabilities.get("Compute.SecureBoot", CapabilitySetting(default_value=False)).default_value:
            raise ValueError("OCI custom images do not support Secure Boot")
        return self


def capability_schema(config: OciConfig) -> dict:
    schema = normalize_schema(config.global_schema)
    return {key: descriptor(schema[key]["descriptorType"], setting.default_value, setting.values)
            for key, setting in config.capabilities.items()}


def compatibility_plan(inspection: dict, config: OciConfig, allow_network=False, boot_migration: dict | None = None,
                       platform_migration: dict | None = None, *, project_platform=True) -> dict:
    from .oci_guest import plan_guest

    migration_plan = None
    platform_plan = None
    platform_nic_driver = None
    evidence = inspection
    preserve_platform = bool(platform_migration and platform_migration.get("enabled")
                             and platform_migration.get("strategy", "reconfigure") == "preserve")
    bm_e5_selected = any(shape.shape == "BM.Standard.E5.192" for shape in config.import_options.shape_compatibility)
    if platform_migration and platform_migration.get("enabled"):
        from copy import deepcopy
        from .platform import plan_platform
        platform_plan = plan_platform(inspection, platform_migration, allow_network, config.model_dump(),
                                      target_provider="oci", boot_migration=boot_migration)
        if platform_migration.get("network_attachment") == "vfio":
            platform_nic_driver = platform_migration.get("nic_driver")
        if platform_plan["ready"] and not preserve_platform:
            # This is explicitly planned evidence. The engine applies migration
            # first, then repeats OCI preparation against the actual working disk.
            evidence = deepcopy(inspection)
            planned_guest = evidence.setdefault("oci_evidence", {})
            if project_platform and platform_migration.get("boot_attachment") == "iscsi":
                planned_guest["iscsi_boot_configured"] = True
            if project_platform and platform_migration.get("configure_network", True):
                planned_guest["network_ready"] = True
            if project_platform and platform_migration.get("configure_serial_console", True):
                planned_guest["serial_console_ready"] = True
            if platform_migration.get("network_attachment") == "vfio":
                platform_nic_driver = platform_migration.get("nic_driver")
            for version, kernel in (planned_guest.get("kernels", {}).items() if project_platform else ()):
                physical = inspection.get("platform", {}).get("kernels", {}).get(version, {})
                for key in ("modules", "builtin"):
                    kernel[key] = sorted(set(kernel.get(key, [])) | set(physical.get(key, [])))
                kernel["initrd_modules"] = sorted(set(kernel.get("initrd_modules") or []) | set(platform_plan.get("required_modules", [])))
    # A known hardware target must not pass based on an unrelated installed VF
    # driver. The reviewed E5 host exposes ConnectX-6 Dx physical functions.
    if bm_e5_selected:
        platform_nic_driver = "mlx5_core"
    pending = ()
    if boot_migration and boot_migration.get("enabled"):
        from .uefi import plan_migration
        migration_plan = plan_migration(inspection, boot_migration, allow_network)
        if migration_plan["ready_to_migrate"] and migration_plan.get("layout", {}).get("action") != "already_uefi":
            pending = ("UEFI_64",)
    plan = plan_guest(evidence, config.model_dump(), allow_network=allow_network, planned_firmware=pending,
                      platform_nic_driver=platform_nic_driver)
    for field in ("changes", "blockers", "warnings"):
        plan.setdefault(field, [])
        if migration_plan:
            plan[field] = list(migration_plan.get(field, [])) + plan[field]
        if platform_plan:
            plan[field] = list(platform_plan.get("actions" if field == "changes" else field, [])) + plan[field]
    if platform_plan:
        plan["platform_migration"] = platform_plan
        if preserve_platform:
            plan["warnings"].append("Hardware preservation uses existing inspected evidence; no missing drivers, networking or firmware are projected as prepared. Explicit edits elsewhere are checked again before export.")
            if config.guest.prepare:
                plan["blockers"].append("Preserve and validate requires OCI guest preparation disabled; use Validate only or select Reconfigure.")
        else:
            plan["warnings"].append("Machine migration changes are planned. OCI preparation is checked again after those changes are applied to the working disk.")
    if migration_plan:
        plan["boot_migration"] = migration_plan
        if pending:
            plan["warnings"].append("UEFI support is planned, not yet present. The build must install and verify it before OCI preparation and export.")
    values = {k: v.default_value for k, v in config.capabilities.items()}
    allowed = {k: v.values or [v.default_value] for k, v in config.capabilities.items()}
    boot = values.get("Storage.BootVolumeType")
    network = values.get("Network.AttachmentType")
    mode = values.get("Compute.LaunchMode")
    if mode == "NATIVE" and (boot != "ISCSI" or network != "VFIO"):
        plan["blockers"].append("NATIVE launch mode requires iSCSI boot and VFIO networking; select CUSTOM for a mixed configuration.")
    if mode == "PARAVIRTUALIZED" and (boot != "PARAVIRTUALIZED" or network != "PARAVIRTUALIZED"):
        plan["blockers"].append("PARAVIRTUALIZED launch mode requires paravirtualized boot and networking; use CUSTOM for mixed attachments.")
    if mode == "EMULATED" and (boot not in {"SCSI", "IDE"} or network != "E1000"):
        plan["blockers"].append("EMULATED launch mode requires emulated storage (SCSI/IDE) and E1000 networking; use CUSTOM for mixed attachments.")
    if mode == "ACCELERATEDPV" and network != "ACCELERATEDPV":
        plan["blockers"].append("ACCELERATEDPV launch mode requires ACCELERATEDPV networking.")
    for advertised in allowed.get("Compute.LaunchMode", []):
        required = {"NATIVE": ({"ISCSI"}, "VFIO"), "PARAVIRTUALIZED": ({"PARAVIRTUALIZED"}, "PARAVIRTUALIZED"),
                    "EMULATED": ({"SCSI", "IDE"}, "E1000")}.get(advertised)
        if required and (not required[0].intersection(allowed.get("Storage.BootVolumeType", []))
                         or required[1] not in allowed.get("Network.AttachmentType", [])):
            plan["blockers"].append(f"Allowed launch mode {advertised} needs matching allowed boot and network attachment types, not just a preferred value.")
        if advertised == "ACCELERATEDPV" and "ACCELERATEDPV" not in allowed.get("Network.AttachmentType", []):
            plan["blockers"].append("Allowed launch mode ACCELERATEDPV needs ACCELERATEDPV in the allowed network attachment types.")
    accelerated = "ACCELERATEDPV" in allowed.get("Network.AttachmentType", []) or "ACCELERATEDPV" in allowed.get("Compute.LaunchMode", [])
    if accelerated:
        if config.global_schema is None:
            plan["warnings"].append("ACCELERATEDPV is a current OCI launch API value. Load the destination region's global schema to verify it is accepted before applying image capabilities; a schema version name alone does not verify its values.")
        plan["warnings"].append("AcceleratedPV requires a compatible image and Acceleron shape. The reviewed E6 Ax guest uses virtio_net and virtio_pci; offline driver checks do not prove SmartNIC offload or a successful OCI launch.")
    if values.get("Network.IPv6Only"):
        if any("ISCSI" in allowed.get(k, []) for k in ("Storage.BootVolumeType", "Storage.RemoteDataVolumeType")):
            plan["blockers"].append("OCI IPv6-only launches do not support iSCSI boot or remote data-volume attachments.")
        if not config.guest.acknowledge_ipv6_validation:
            plan["blockers"].append("IPv6-only capability requires confirmation that this guest has been validated for an OCI IPv6-only launch.")
    if values.get("Storage.Iscsi.MultipathDeviceSupported") and not any("ISCSI" in allowed.get(k, []) for k in ("Storage.BootVolumeType", "Storage.LocalDataVolumeType", "Storage.RemoteDataVolumeType")):
        plan["blockers"].append("iSCSI multipath support requires at least one allowed iSCSI volume attachment.")
    if values.get("Storage.ParaVirtualization.EncryptionInTransit") and boot != "PARAVIRTUALIZED":
        plan["warnings"].append("Encryption-in-transit capability applies only when the boot volume uses paravirtualized attachment.")
    if not config.global_schema_version:
        plan["warnings"].append("Select the target tenancy's global capability schema version before applying the exported OCI configuration.")
    if config.import_options.launch_mode != mode:
        plan["warnings"].append("Import launch mode differs from the preferred image capability. Apply the capability schema after import and verify OCI's resulting launch settings.")
    for shape in config.import_options.shape_compatibility:
        if (inspection.get("os", {}).get("arch") == "x86_64"
                and re.match(r"^(?:VM|BM)\.Standard\.A(?:1|2|4)\.", shape.shape)):
            plan["blockers"].append(f"{shape.shape} is an Arm shape. An x86_64 image cannot be converted to Arm by changing image capabilities.")
        if shape.shape in ACCELERATED_VM_SHAPES and "ACCELERATEDPV" not in allowed.get("Network.AttachmentType", []):
            plan["blockers"].append(f"{shape.shape} supports only ACCELERATEDPV networking. Include it in the allowed network attachment types.")
        if shape.shape in {"VM.Standard.E6.Ax.Flex", "BM.Standard.E5.192"}:
            arch = inspection.get("os", {}).get("arch")
            if arch and arch != "x86_64":
                plan["blockers"].append(f"{shape.shape} requires x86_64; changing image capabilities cannot convert the guest architecture.")
            if "UEFI_64" not in allowed.get("Compute.Firmware", []):
                plan["warnings"].append(f"The reviewed {shape.shape} host uses UEFI. BIOS compatibility has not been established by that host audit.")
        if shape.shape == "BM.Standard.E5.192":
            if "ISCSI" not in allowed.get("Storage.BootVolumeType", []) or "VFIO" not in allowed.get("Network.AttachmentType", []):
                plan["blockers"].append("BM.Standard.E5.192 requires iSCSI boot and hardware/VFIO networking in the allowed attachment types; its reviewed NIC driver is mlx5_core.")
            if platform_migration and platform_migration.get("enabled") and platform_migration.get("nic_driver") not in {None, "mlx5_core"}:
                plan["blockers"].append("BM.Standard.E5.192 uses mlx5_core on the reviewed hardware; the machine migration NIC driver conflicts with that target.")
    if config.import_options.shape_compatibility:
        plan["warnings"].append("Shape compatibility entries only advertise support. Verify the selected shapes' architecture, boot modes, memory/OCPU limits and confidential-computing support in the destination region.")
    for key in config.capabilities.keys() - GLOBAL_SCHEMA.keys():
        plan["warnings"].append(f"{key}: supplied tenancy capability will be exported, but no guest adaptation or readiness check exists for this additional key.")
    plan["warnings"].append("Hardware, shape support, subnet setup and successful cloud boot are verified in OCI, not by offline image inspection.")
    plan["coverage"] = [{"key": key, "selected": setting.model_dump(),
                         "effect": DETAILS.get(key, (key, "Metadata only; requires manual guest validation"))[1]}
                        for key, setting in config.capabilities.items()]
    plan["schema_data"] = capability_schema(config)
    plan["sources"] = SOURCES
    plan["ready_to_build"] = not plan["blockers"]
    return plan


def bundle_files(config: OciConfig, artifact: dict) -> dict[str, str]:
    """Generate CLI inputs without executing an OCI command or modifying the disk."""
    options = config.import_options
    comp = options.compartment_id or "REPLACE_COMPARTMENT_OCID"
    version = config.global_schema_version or "REPLACE_GLOBAL_SCHEMA_VERSION"
    image_id = "REPLACE_IMPORTED_IMAGE_OCID"
    imports = {"compartmentId": comp, "sourceImageType": "QCOW2", "launchMode": options.launch_mode,
               "displayName": options.display_name or "Cloud Image Forge image",
               "freeformTags": options.freeform_tags, "definedTags": options.defined_tags}
    if options.operating_system:
        imports["operatingSystem"] = options.operating_system
    if options.operating_system_version:
        imports["operatingSystemVersion"] = options.operating_system_version
    method = "from-object-uri" if options.object_uri else "from-object"
    if options.object_uri:
        imports["uri"] = options.object_uri
    else:
        imports.update(namespace=options.namespace or "REPLACE_NAMESPACE", bucketName=options.bucket or "REPLACE_BUCKET",
                       name=options.object_name or artifact.get("name", "image.qcow2"))
    schema = {"compartmentId": comp, "imageId": image_id, "globalImageCapabilitySchemaVersionName": version,
              "schemaData": capability_schema(config), "displayName": ((options.display_name or "Cloud Image Forge") + " capabilities")[:255],
              "definedTags": options.defined_tags, "freeformTags": options.freeform_tags}
    values = {key: value.default_value for key, value in config.capabilities.items()}
    launch_map = {"Compute.Firmware": "firmware", "Storage.BootVolumeType": "bootVolumeType",
                  "Network.AttachmentType": "networkType", "Storage.RemoteDataVolumeType": "remoteDataVolumeType",
                  "Storage.ConsistentVolumeNaming": "isConsistentVolumeNamingEnabled",
                  "Storage.ParaVirtualization.EncryptionInTransit": "isEncryptionInTransitEnabled"}
    launch = {api: values[key] for key, api in launch_map.items() if key in values}
    instance_fragment = {"launchOptions": launch}
    if "Storage.ParaVirtualization.EncryptionInTransit" in values:
        instance_fragment["isPvEncryptionInTransitEnabled"] = values["Storage.ParaVirtualization.EncryptionInTransit"]
    files = {"image-import.json": imports, "image-capability-schema.json": schema,
             "schema-data.json": capability_schema(config), "instance-launch-options.json": launch,
             "instance-launch-fragment.json": instance_fragment,
             "forge-oci-profile.json": config.model_dump(),
             "artifact.json": {k: artifact[k] for k in ("name", "sha256", "virtual_size", "format") if k in artifact}}
    shape_commands = []
    for i, shape in enumerate(options.shape_compatibility, 1):
        entry = {"imageId": image_id, "shapeName": shape.shape}
        if shape.min_ocpus is not None or shape.max_ocpus is not None:
            entry["ocpuConstraints"] = {k: v for k, v in (("min", shape.min_ocpus), ("max", shape.max_ocpus)) if v is not None}
        if shape.min_memory_gbs is not None or shape.max_memory_gbs is not None:
            entry["memoryConstraints"] = {k: v for k, v in (("minInGBs", shape.min_memory_gbs), ("maxInGBs", shape.max_memory_gbs)) if v is not None}
        name = f"shape-{i:03}.json"
        files[name] = entry
        shape_commands.append(f"oci compute image-shape-compatibility-entry add --from-json file://{name}")
    rendered = {name: json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n" for name, value in files.items()}
    rendered["README.txt"] = (
        "OCI configuration for a Cloud Image Forge artifact\n\n"
        "This ZIP contains configuration only. It is NOT an OCI .oci image archive.\n"
        "The QCOW2 must be uploaded separately to OCI Object Storage. Generic S3 upload does not register an OCI image.\n"
        "No cloud command has been run. Review every file and replace all REPLACE_* values before using it.\n"
        "Presigned object URIs, if supplied, are included in image-import.json and the profile; keep this ZIP private.\n\n"
        "1. Obtain the target region/tenancy schema (do not guess its version):\n"
        "   oci compute global-image-capability-schema list --all\n"
        "   oci compute global-image-capability-schema-version get --global-image-capability-schema-id SCHEMA_OCID --global-image-capability-schema-version-name VERSION\n"
        "   Compare schema-data.json with the returned schema. The reference catalog combines documentation and API values, not a region's live schema.\n"
        "   ACCELERATEDPV must be accepted by that schema and supported by both the image and the destination Acceleron shape.\n"
        "2. Check the artifact SHA-256, upload it, then import:\n"
        f"   oci compute image import {method} --from-json file://image-import.json\n"
        "   Wait for image lifecycle state AVAILABLE; substitute its OCID in schema/shape JSON files.\n"
        "3. Create the image capability schema (do not create a second one if one already exists):\n"
        "   oci compute image-capability-schema create --from-json file://image-capability-schema.json\n"
        "   For an existing schema, use its ID and update --schema-data file://schema-data.json.\n"
        "4. Add any selected shape compatibility entries:\n   " + "\n   ".join(shape_commands or ["No shape entries selected."]) + "\n"
        "5. Inspect the imported image and capability schema before launching:\n"
        "   oci compute image get --image-id IMAGE_OCID\n"
        "   instance-launch-options.json is an optional --launch-options fragment for instance launch, not an image-update payload.\n"
        "   instance-launch-fragment.json also includes top-level isPvEncryptionInTransitEnabled; merge it\n"
        "   into a complete instance launch request to configure boot/block encryption. It is not a complete launch request.\n"
        "   Launch mode comes from the image import/capability configuration; it is not a LaunchInstanceDetails field.\n"
        "   Local-volume type, attachment version, IPv6-only, multipath and SEV are carried in schema-data.json.\n"
        "   Configure the VCN/subnet, compatible shape, and confidential-computing platform options separately.\n"
        "   AMD SEV requires a supported platformConfig type with isMemoryEncryptionEnabled=true at instance launch.\n"
        "   Custom images do not support Secure Boot. Test a launch and all advertised attachment/firmware combinations.\n\n"
        "The CLI capability-schema key is globalImageCapabilitySchemaVersionName. For the REST API the key is\n"
        "computeGlobalImageCapabilitySchemaVersionName. Do not use this CLI input unchanged as a REST request.\n\n"
        "References:\n" + "\n".join(source["url"] for source in SOURCES) + "\n"
    )
    return rendered


def write_bundle(path: Path, config: OciConfig, artifact: dict):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in bundle_files(config, artifact).items():
            archive.writestr(name, content)
