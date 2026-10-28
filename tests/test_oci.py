import io
from copy import deepcopy
import json
import zipfile

import pytest
from pydantic import ValidationError

from forge.models import PlatformMigration, Recipe
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
    assert rows["Network.AttachmentType"]["values"] == ["E1000", "VFIO", "PARAVIRTUALIZED", "ACCELERATEDPV"]
    assert "ACCELERATEDPV" in rows["Compute.LaunchMode"]["values"]
    assert catalog()["schema_origin"] == "reference_snapshot"
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
        OciConfig(capabilities={"Compute.LaunchMode": setting("FUTURE_MODE")})


def test_region_schema_is_authoritative_for_accelerated_values():
    schema = deepcopy(GLOBAL_SCHEMA)
    for key in ("Compute.LaunchMode", "Network.AttachmentType"):
        schema[key]["values"].remove("ACCELERATEDPV")
        with pytest.raises(ValidationError, match="allowed subset"):
            OciConfig(global_schema=schema, capabilities={key: setting("ACCELERATEDPV")})
    rows = {row["key"]: row for row in catalog(schema)["capabilities"]}
    assert "ACCELERATEDPV" not in rows["Network.AttachmentType"]["values"]
    assert catalog(schema)["schema_origin"] == "supplied"


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
    assert any("requires aarch64" in message for message in plan["blockers"])


@pytest.mark.parametrize("arch", ["aarch64", "arm64"])
@pytest.mark.parametrize("shape", ["VM.Standard.A1.Flex", "VM.Standard.A2.Flex", "VM.Standard.A4.Flex", "VM.Standard.A4.Ax.Flex"])
def test_arm_images_match_arm_shapes_and_retain_architecture_in_bundle(ready_guest_plan, arch, shape):
    network = "ACCELERATEDPV" if ".Ax." in shape else "PARAVIRTUALIZED"
    config = OciConfig(capabilities={"Network.AttachmentType": setting(network), "Compute.LaunchMode": setting(network)},
                       import_options={"shape_compatibility": [{"shape": shape}]})
    assert compatibility_plan({"os": {"arch": arch}}, config)["ready_to_build"]
    bundle = bundle_files(config, {"architecture": "aarch64"})
    assert json.loads(bundle["artifact.json"])["architecture"] == "aarch64"


@pytest.mark.parametrize("shape", ["VM.Standard3.Flex", "VM.Standard.E4.Flex", "VM.DenseIO.E6.Ax.Flex"])
def test_arm_images_cannot_advertise_known_x86_shapes(ready_guest_plan, shape):
    plan = compatibility_plan({"os": {"arch": "arm64"}}, OciConfig(import_options={"shape_compatibility": [{"shape": shape}]}))
    assert any("requires x86_64" in item for item in plan["blockers"])


def test_new_tenancy_key_does_not_claim_guest_adaptation(ready_guest_plan):
    schema = {**GLOBAL_SCHEMA, "Compute.FutureFeature": {"descriptorType": "boolean", "defaultValue": False}}
    plan = compatibility_plan({}, OciConfig(global_schema=schema))
    assert any("no guest adaptation" in message for message in plan["warnings"])


def accelerated_config(**options):
    return OciConfig(capabilities={"Compute.LaunchMode": setting("ACCELERATEDPV"),
                                   "Network.AttachmentType": setting("ACCELERATEDPV")},
                     import_options={"launch_mode": "ACCELERATEDPV", **options})


def test_accelerated_handoff_preserves_network_and_launch_mode(ready_guest_plan):
    config = accelerated_config(shape_compatibility=[{"shape": "VM.Standard.E6.Ax.Flex"}])
    plan = compatibility_plan({"os": {"arch": "x86_64"}}, config)
    assert plan["ready_to_build"]
    assert any("region's global schema" in warning for warning in plan["warnings"])
    files = bundle_files(config, {})
    assert json.loads(files["image-import.json"])["launchMode"] == "ACCELERATEDPV"
    assert json.loads(files["instance-launch-options.json"])["networkType"] == "ACCELERATEDPV"
    assert json.loads(files["instance-launch-options.json"])["bootVolumeType"] == "PARAVIRTUALIZED"
    schema = json.loads(files["schema-data.json"])
    assert schema["Network.AttachmentType"]["values"] == ["ACCELERATEDPV"]
    assert json.loads(files["shape-001.json"])["shapeName"] == "VM.Standard.E6.Ax.Flex"


@pytest.mark.parametrize("mode,network", [("ACCELERATEDPV", "PARAVIRTUALIZED"),
                                          ("PARAVIRTUALIZED", "ACCELERATEDPV")])
def test_accelerated_and_pv_modes_cannot_silently_interchange(ready_guest_plan, mode, network):
    config = OciConfig(capabilities={"Compute.LaunchMode": setting(mode), "Network.AttachmentType": setting(network)})
    plan = compatibility_plan({}, config)
    assert not plan["ready_to_build"]
    assert any("launch mode requires" in message for message in plan["blockers"])


def test_advertised_accelerated_mode_also_requires_network_support(ready_guest_plan):
    config = OciConfig(capabilities={"Compute.LaunchMode": setting("CUSTOM", ["CUSTOM", "ACCELERATEDPV"])})
    assert any("Allowed launch mode ACCELERATEDPV" in message for message in compatibility_plan({}, config)["blockers"])


@pytest.mark.parametrize("shape", ["VM.Standard.E6.Ax.Flex", "VM.DenseIO.E6.Ax.Flex", "VM.Standard4.Ax.Flex", "VM.Standard.A4.Ax.Flex"])
def test_acceleron_shape_rejects_a_pv_only_image(ready_guest_plan, shape):
    config = OciConfig(import_options={"shape_compatibility": [{"shape": shape}]})
    assert any("supports only ACCELERATEDPV" in message for message in compatibility_plan({}, config)["blockers"])


@pytest.mark.parametrize("shape", ["VM.Standard.E5.Flex", "VM.Standard.E6.Flex"])
def test_pv_shapes_reject_accelerated_only_image(ready_guest_plan, shape):
    config = accelerated_config(shape_compatibility=[{"shape": shape}])
    plan = compatibility_plan({}, config)
    assert not plan["ready_to_build"]
    assert any(shape in message and "PARAVIRTUALIZED or VFIO" in message for message in plan["blockers"])


@pytest.mark.parametrize("shape", ["VM.Standard.E5.Flex", "VM.Standard.E6.Flex"])
@pytest.mark.parametrize("network", ["PARAVIRTUALIZED", "VFIO"])
def test_pv_shapes_accept_each_documented_network_type(ready_guest_plan, shape, network):
    config = OciConfig(capabilities={"Compute.LaunchMode": setting("CUSTOM"),
                                    "Network.AttachmentType": setting(network)},
                       import_options={"shape_compatibility": [{"shape": shape}]})
    assert compatibility_plan({}, config)["ready_to_build"]


@pytest.mark.parametrize("mode,network,destination", [
    ("PARAVIRTUALIZED", "PARAVIRTUALIZED", "VM.Standard.E6.Ax.Flex"),
    ("ACCELERATEDPV", "ACCELERATEDPV", "VM.Standard.E5.Flex"),
    ("CUSTOM", "PARAVIRTUALIZED", "VM.Standard.E6.Ax.Flex"),
])
def test_multi_shape_network_support_warns_about_default_without_inventing_launch_override(
        ready_guest_plan, mode, network, destination):
    config = OciConfig(capabilities={"Compute.LaunchMode": setting(mode),
                                    "Network.AttachmentType": setting(network, ["PARAVIRTUALIZED", "ACCELERATEDPV"])},
                       import_options={"launch_mode": mode, "shape_compatibility": [
                           {"shape": "VM.Standard.E5.Flex"}, {"shape": "VM.Standard.E6.Ax.Flex"}]})
    original = config.model_dump()
    plan = compatibility_plan({}, config)
    assert plan["ready_to_build"], plan["blockers"]
    assert any(destination in warning and "launchOptions.networkType" in warning for warning in plan["warnings"])
    files = bundle_files(config, {})
    launch = json.loads(files["instance-launch-options.json"])
    assert launch["networkType"] == network
    assert "launchMode" not in launch
    assert "launchMode" not in json.loads(files["instance-launch-fragment.json"])
    assert "preferred defaults" in files["README.txt"] and "override networkType" in files["README.txt"]
    assert json.loads(files["schema-data.json"])["Network.AttachmentType"]["values"] == ["PARAVIRTUALIZED", "ACCELERATEDPV"]
    assert config.model_dump() == original


def test_network_shape_rules_do_not_guess_future_shape_support(ready_guest_plan):
    config = accelerated_config(shape_compatibility=[{"shape": "VM.Standard.E7.Flex"}])
    plan = compatibility_plan({}, config)
    assert plan["ready_to_build"]
    assert any("Verify the selected shapes" in warning for warning in plan["warnings"])


def test_custom_mode_can_describe_accelerated_networking(ready_guest_plan):
    config = OciConfig(capabilities={"Compute.LaunchMode": setting("CUSTOM"), "Network.AttachmentType": setting("ACCELERATEDPV")})
    assert compatibility_plan({}, config)["ready_to_build"]


def test_import_mode_does_not_invent_image_capability_membership(ready_guest_plan):
    schema = deepcopy(GLOBAL_SCHEMA)
    schema["Compute.LaunchMode"]["values"].remove("ACCELERATEDPV")
    config = OciConfig(global_schema=schema, capabilities={"Compute.LaunchMode": setting("CUSTOM"),
                       "Network.AttachmentType": setting("ACCELERATEDPV")},
                       import_options={"launch_mode": "ACCELERATEDPV"})
    plan = compatibility_plan({}, config)
    assert plan["ready_to_build"]
    assert any("Import launch mode differs" in warning for warning in plan["warnings"])
    files = bundle_files(config, {})
    assert json.loads(files["image-import.json"])["launchMode"] == "ACCELERATEDPV"
    assert json.loads(files["schema-data.json"])["Compute.LaunchMode"]["values"] == ["CUSTOM"]


@pytest.mark.parametrize("shape", ["VM.Standard.E5.Flex", "VM.Standard.E6.Flex", "VM.Standard.E6.Ax.Flex", "BM.Standard.E5.192"])
def test_known_x86_shapes_reject_arm_guest(ready_guest_plan, shape):
    config = accelerated_config(shape_compatibility=[{"shape": shape}])
    assert any("requires x86_64" in message for message in compatibility_plan({"os": {"arch": "aarch64"}}, config)["blockers"])


def test_bm_e5_requires_iscsi_and_actual_mlx5_driver(monkeypatch):
    calls = []
    def guest(*args, **kwargs):
        calls.append(kwargs)
        return {"changes": [], "warnings": [], "blockers": []}
    monkeypatch.setattr("forge.oci_guest.plan_guest", guest)
    config = OciConfig(import_options={"shape_compatibility": [{"shape": "BM.Standard.E5.192"}]})
    plan = compatibility_plan({}, config)
    assert any("BM.Standard.E5.192 requires iSCSI boot" in message for message in plan["blockers"])
    assert calls[0]["platform_nic_driver"] == "mlx5_core"


def test_accelerated_migration_network_roundtrips_recipe():
    recipe = Recipe(platform_migration={"enabled": True, "source": "bare_metal", "target": "vm",
                                        "boot_attachment": "paravirtualized", "network_attachment": "accelerated"})
    assert Recipe.model_validate(recipe.model_dump()).platform_migration.network_attachment == "accelerated"


def test_preservation_is_explicit_and_legacy_recipes_keep_reconfiguration():
    assert PlatformMigration(enabled=True).strategy == "reconfigure"
    preserve = PlatformMigration(enabled=True, strategy="preserve", source="vm", target="vm")
    assert not preserve.install_packages and not preserve.configure_network and not preserve.configure_serial_console
    assert PlatformMigration.model_validate(preserve.model_dump()) == preserve
    with pytest.raises(ValidationError, match="different source"):
        PlatformMigration(enabled=True, source="vm", target="vm")
    for field in ("install_packages", "configure_network", "configure_serial_console"):
        with pytest.raises(ValidationError, match="Preserve and validate"):
            PlatformMigration(enabled=True, strategy="preserve", **{field: True})


def test_preservation_rejects_oci_rewrites_but_allows_explicit_other_edits():
    with pytest.raises(ValidationError, match="OCI guest preparation disabled"):
        Recipe(platform_migration={"enabled": True, "strategy": "preserve"}, oci={})
    recipe = Recipe(platform_migration={"enabled": True, "strategy": "preserve"},
                    oci={"guest": {"prepare": False}}, kernel_args="loglevel=4")
    assert recipe.kernel_args == "loglevel=4"


def test_preservation_never_projects_missing_oci_evidence(monkeypatch):
    source = {"oci_evidence": {"kernels": {"test": {"modules": [], "initrd_modules": []}},
                               "iscsi_boot_configured": False, "network_ready": False, "serial_console_ready": False},
              "platform": {"kernels": {"test": {"modules": ["mlx5_core"], "builtin": ["iscsi_ibft"]}}}}
    original = deepcopy(source)
    monkeypatch.setattr("forge.platform.plan_platform", lambda *a, **kw: {
        "ready": True, "actions": [], "blockers": [], "warnings": [], "required_modules": ["mlx5_core", "iscsi_ibft"]})
    seen = []
    def guest(evidence, *args, **kwargs):
        seen.append(deepcopy(evidence))
        return {"changes": [], "blockers": [], "warnings": []}
    monkeypatch.setattr("forge.oci_guest.plan_guest", guest)
    config = OciConfig(guest={"prepare": False})
    compatibility_plan(source, config, platform_migration={"enabled": True, "strategy": "preserve",
                        "boot_attachment": "iscsi", "configure_network": True, "configure_serial_console": True})
    assert source == original and seen == [original]
