import io
from copy import deepcopy
import json
import zipfile

import pytest
from pydantic import ValidationError

from forge.models import Recipe
from forge.oci import (GLOBAL_SCHEMA, OciConfig, ShapeCompatibility, bundle_files,
                       capability_schema, catalog, compatibility_plan, normalize_schema)


EXPECTED_KEYS = {
    "Compute.AMD_SecureEncryptedVirtualization", "Compute.Firmware", "Compute.SecureBoot", "Compute.LaunchMode",
    "Network.AttachmentType", "Network.IPv6Only", "Storage.BootVolumeType", "Storage.LocalDataVolumeType",
    "Storage.RemoteDataVolumeType", "Storage.ConsistentVolumeNaming", "Storage.ParaVirtualization.EncryptionInTransit",
    "Storage.ParaVirtualization.AttachmentVersion", "Storage.Iscsi.MultipathDeviceSupported",
}


def test_only_a_feasible_explicit_migration_can_defer_oci_uefi_evidence(monkeypatch):
    inspection = {"os": {"distro": "oraclelinux", "arch": "x86_64"}, "oci_evidence": {
        "version": 1, "firmware": {"BIOS": True, "UEFI_64": False}, "kernels": {}, "tools": {}}}
    original = deepcopy(inspection)
    config = OciConfig()
    before = compatibility_plan(inspection, config)
    assert any(item.startswith("UEFI_64:") for item in before["blockers"])
    calls = []

    def feasible(*args):
        calls.append(args)
        return {"requested": True, "ready_to_migrate": True, "blockers": [], "warnings": [],
                "changes": ["Install EFI loader"], "growth_bytes": 512 * 1024**2}

    monkeypatch.setattr("forge.uefi.plan_migration", feasible)
    disabled = compatibility_plan(inspection, config, boot_migration={"enabled": False})
    assert disabled["blockers"] == before["blockers"] and not calls
    plan = compatibility_plan(inspection, config, boot_migration={"enabled": True})
    assert not any(item.startswith("UEFI_64:") for item in plan["blockers"])
    assert plan["blockers"]  # Unrelated missing drivers/tools are still enforced.
    assert plan["changes"][0] == "Install EFI loader"
    assert any("planned, not yet present" in item for item in plan["warnings"])
    assert plan["boot_migration"]["ready_to_migrate"]
    assert inspection == original
    monkeypatch.setattr("forge.uefi.plan_migration", lambda *a: {
        "ready_to_migrate": False, "blockers": ["No safe ESP location"], "warnings": [], "changes": []})
    blocked = compatibility_plan(inspection, config, boot_migration={"enabled": True})
    assert "No safe ESP location" in blocked["blockers"]
    assert any(item.startswith("UEFI_64:") for item in blocked["blockers"])


def setting(default, values=None):
    return {"default_value": default, "values": values}


def test_catalog_covers_complete_documented_schema_and_all_choices():
    rows = {item["key"]: item for item in catalog()["capabilities"]}
    assert rows.keys() == EXPECTED_KEYS
    assert rows["Compute.Firmware"]["values"] == ["BIOS", "UEFI_64"]
    assert rows["Network.AttachmentType"]["values"] == ["E1000", "VFIO", "PARAVIRTUALIZED"]
    assert rows["Storage.ParaVirtualization.AttachmentVersion"]["values"] == [1, 2]
    assert not rows["Compute.SecureBoot"]["custom_image_supported"]
    for key in EXPECTED_KEYS:
        assert rows[key]["description"]


def test_capability_descriptors_use_real_boolean_and_integer_values():
    config = OciConfig(capabilities={"Compute.Firmware": setting("BIOS", ["BIOS", "UEFI_64"]),
                                   "Storage.ParaVirtualization.AttachmentVersion": setting(1, [1, 2])})
    data = capability_schema(config)
    assert data["Compute.Firmware"] == {"descriptorType": "enumstring", "defaultValue": "BIOS", "values": ["BIOS", "UEFI_64"], "source": "IMAGE"}
    assert type(data["Storage.ConsistentVolumeNaming"]["defaultValue"]) is bool
    assert type(data["Storage.ParaVirtualization.AttachmentVersion"]["defaultValue"]) is int
    assert len(data) == 13


@pytest.mark.parametrize("capabilities", [
    {"Compute.SecureBoot": setting(True)},
    {"Compute.firmware": setting("BIOS")},
    {"Compute.Firmware": setting("UEFI_64", ["BIOS"])},
    {"Compute.Firmware": setting("ARM")},
    {"Storage.ParaVirtualization.AttachmentVersion": setting(True, [True])},
    {"Storage.ParaVirtualization.AttachmentVersion": setting("2", ["2"])},
    {"Network.IPv6Only": setting("false")},
    {"Network.IPv6Only": setting(False, [False, True])},
    {"Network.AttachmentType": setting("VFIO", ["VFIO", "VFIO"])},
])
def test_invalid_values_fail_before_any_image_operation(capabilities):
    with pytest.raises(ValidationError):
        OciConfig(capabilities=capabilities)


def test_tenancy_schema_supports_cli_and_api_wrappers_without_invented_membership():
    schema = {key: dict(value) for key, value in GLOBAL_SCHEMA.items()}
    schema["Compute.LaunchMode"] = {"descriptorType": "enumstring", "defaultValue": "ACCELERATEDPV", "values": ["CUSTOM", "ACCELERATEDPV"]}
    schema["Compute.FutureFeature"] = {"descriptor-type": "boolean", "default-value": False}
    parsed = normalize_schema({"data": {"schema-data": schema}})
    assert parsed["Compute.FutureFeature"]["defaultValue"] is False
    config = OciConfig(global_schema={"data": {"schemaData": schema}})
    assert config.capabilities["Compute.LaunchMode"].default_value == "ACCELERATEDPV"
    assert len(config.capabilities) == 14
    with pytest.raises(ValidationError):
        OciConfig(capabilities={"Compute.LaunchMode": setting("ACCELERATEDPV")})


def test_non_oci_recipes_cannot_silently_drop_oci_configuration():
    with pytest.raises(ValidationError, match="only to an OCI"):
        Recipe(target="aws", output_format="raw", oci={})


def test_import_and_schema_handoff_contains_every_setting_in_right_api_location():
    config = OciConfig(import_options={"compartment_id": "ocid1.compartment.test", "namespace": "ns", "bucket": "images",
                                     "object_name": "oracle.qcow2", "display_name": "Test image", "operating_system": "Oracle Linux",
                                     "operating_system_version": "9.8", "freeform_tags": {"owner": "team"},
                                     "defined_tags": {"Operations": {"CostCenter": "42"}},
                                     "shape_compatibility": [{"shape": "VM.Standard.E5.Flex", "min_ocpus": 1, "max_ocpus": 4,
                                                               "min_memory_gbs": 8, "max_memory_gbs": 64}]},
                       global_schema_version="version-from-tenancy")
    files = bundle_files(config, {"name": "image.qcow2", "sha256": "abc", "format": "qcow2"})
    imports = json.loads(files["image-import.json"])
    assert imports["name"] == "oracle.qcow2" and imports["displayName"] == "Test image"
    assert imports["sourceImageType"] == "QCOW2"
    assert "launchOptions" not in imports
    schema = json.loads(files["image-capability-schema.json"])
    assert schema["globalImageCapabilitySchemaVersionName"] == "version-from-tenancy"
    assert "computeGlobalImageCapabilitySchemaVersionName" not in schema
    assert schema["schemaData"].keys() == EXPECTED_KEYS
    launch = json.loads(files["instance-launch-options.json"])
    assert "localDataVolumeType" not in launch
    assert launch["isEncryptionInTransitEnabled"] is True
    assert json.loads(files["instance-launch-fragment.json"])["isPvEncryptionInTransitEnabled"] is True
    shape = json.loads(files["shape-001.json"])
    assert shape["ocpuConstraints"] == {"min": 1, "max": 4}
    assert shape["memoryConstraints"] == {"minInGBs": 8, "maxInGBs": 64}
    assert "NOT an OCI .oci" in files["README.txt"]


def test_uri_import_is_distinct_from_bucket_import():
    files = bundle_files(OciConfig(import_options={"object_uri": "https://object.example/disk.qcow2"}), {})
    data = json.loads(files["image-import.json"])
    assert data["uri"] == "https://object.example/disk.qcow2"
    assert "namespace" not in data and "name" not in data
    assert "from-object-uri" in files["README.txt"]
    with pytest.raises(ValidationError):
        OciConfig(import_options={"object_uri": "https://object.example/disk", "bucket": "ambiguous"})


def test_shape_ranges_validate():
    with pytest.raises(ValidationError):
        ShapeCompatibility(shape="VM.Standard.E5.Flex", min_ocpus=8, max_ocpus=1)


def test_defined_tags_cannot_emit_nonstandard_json():
    with pytest.raises(ValidationError, match="without NaN"):
        OciConfig(import_options={"defined_tags": {"namespace": {"value": float("nan")}}})


@pytest.fixture
def ready_guest_plan(monkeypatch):
    monkeypatch.setattr("forge.oci_guest.plan_guest", lambda *args, **kwargs: {"changes": ["Prepare guest"], "warnings": [], "blockers": []})


def test_cross_capability_ipv6_and_launch_mode_conflicts(ready_guest_plan):
    config = OciConfig(capabilities={"Network.IPv6Only": setting(True), "Storage.BootVolumeType": setting("ISCSI")})
    plan = compatibility_plan({}, config)
    assert not plan["ready_to_build"]
    assert any("IPv6-only" in message and "iSCSI" in message for message in plan["blockers"])
    assert any("PARAVIRTUALIZED launch mode" in message for message in plan["blockers"])
    assert len(plan["coverage"]) == 13


def test_allowed_modes_require_all_device_models(ready_guest_plan):
    config = OciConfig(capabilities={"Compute.LaunchMode": setting("CUSTOM", ["CUSTOM", "NATIVE"])})
    plan = compatibility_plan({}, config)
    assert any("Allowed launch mode NATIVE" in message for message in plan["blockers"])


def test_arm_shapes_rejected_for_x86_images(ready_guest_plan):
    config = OciConfig(import_options={"shape_compatibility": [{"shape": "VM.Standard.A4.Flex"}]})
    plan = compatibility_plan({"os": {"arch": "x86_64"}}, config)
    assert any("cannot be converted to Arm" in message for message in plan["blockers"])


def test_new_tenancy_key_does_not_claim_guest_adaptation(ready_guest_plan):
    schema = {**GLOBAL_SCHEMA, "Compute.FutureFeature": {"descriptorType": "boolean", "defaultValue": False}}
    plan = compatibility_plan({}, OciConfig(global_schema=schema))
    assert any("no guest adaptation" in message for message in plan["warnings"])
