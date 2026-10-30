from copy import deepcopy

import pytest

from forge.destinations import destination_catalog, resolve_destination


def image(arch="aarch64"):
    return {"os": {"arch": arch}, "boot": {"recommended_firmware": "UEFI_64", "supported_firmware": ["UEFI_64"]}}


def test_catalog_has_exact_architecture_shapes_without_invented_nics():
    profiles = {item["id"]: item for item in destination_catalog()["profiles"]}
    assert profiles["oci:BM.Standard.A1.160"]["architecture"] == "aarch64"
    assert profiles["oci:BM.Standard.A4.Ax.48"]["requires_nic_driver"]
    assert profiles["oci:VM.Standard.E6.Ax.Flex"]["architecture"] == "x86_64"
    assert all(item["nic_driver"] in {None, "auto"} for item in profiles.values())
    profiles["oci:VM.Standard.A1.Flex"]["sources"].clear()
    assert destination_catalog()["sources"]


@pytest.mark.parametrize("shape,network,launch", [
    ("VM.Standard.A1.Flex", "paravirtualized", "PARAVIRTUALIZED"),
    ("VM.Standard.A4.Ax.Flex", "accelerated", "ACCELERATEDPV"),
])
def test_vm_defaults_are_derived_without_source_inference_or_input_mutation(shape, network, launch):
    source = image()
    original = deepcopy(source)
    result = resolve_destination(source, {"profile_id": "oci:" + shape})
    assert result["ready"] and result["platform_migration"]["source"] == "unknown"
    assert result["platform_migration"]["network_attachment"] == network
    assert result["oci_defaults"]["capabilities"]["Compute.LaunchMode"]["default_value"] == launch
    assert result["oci_defaults"]["import_options"]["shape_compatibility"] == [{"shape": shape}]
    assert not result["boot_tested"] and source == original


def test_bare_metal_missing_nic_keeps_intended_controls_with_blocker():
    result = resolve_destination(image(), {"profile_id": "oci:BM.Standard.A1.160", "nic_driver": None})
    assert not result["ready"]
    assert result["platform_migration"]["target"] == "bare_metal"
    assert result["platform_migration"]["nic_driver"] is None
    assert any("NIC" in error for error in result["blockers"])
    assert any("BYOI" in warning for warning in result["warnings"])
    result = resolve_destination(image(), {"profile_id": "oci:BM.Standard.A1.160", "nic_driver": "mlx5_core"})
    assert result["ready"] and result["profile"]["provider_supported"] is False
    assert result["oci_defaults"]["capabilities"]["Storage.BootVolumeType"]["values"] == ["ISCSI"]


def test_bare_metal_defaults_to_all_common_verified_nic_drivers():
    source = image()
    source["platform"] = {"kernels": {"first": {"modules": ["ixgbe", "mlx5_core", "bnxt_en"]},
                                      "second": {"modules": ["ixgbe"], "builtin": ["mlx5_core"]}}}
    result = resolve_destination(source, {"profile_id": "oci:BM.Standard.A1.160"})
    assert result["ready"]
    assert result["platform_migration"]["nic_driver"] == "auto"
    assert result["nic_drivers"] == ["ixgbe", "mlx5_core"]
    assert any("destination NIC remains unverified" in item for item in result["warnings"])
    from forge.models import DestinationSelection
    request = DestinationSelection(profile_id="oci:BM.Standard.A1.160")
    assert resolve_destination(source, request)["platform_migration"]["nic_driver"] == "auto"
    assert not resolve_destination(source, request.model_copy(update={"nic_driver": None}))["ready"]
    source["platform"]["kernels"]["second"] = {"modules": []}
    assert not resolve_destination(source, {"profile_id": "oci:BM.Standard.A1.160"})["ready"]


def test_architecture_mismatch_and_unknown_shape_fail_without_guesses():
    result = resolve_destination(image(), {"profile_id": "oci:VM.Standard.E6.Ax.Flex"})
    assert not result["ready"] and any("architecture conversion" in item for item in result["blockers"])
    result = resolve_destination(image(), {"profile_id": "oci:BM.Standard.A99.48"})
    assert not result["ready"] and result["platform_migration"] is None


def test_preserve_mode_never_schedules_writes_or_packages():
    result = resolve_destination(image(), {"profile_id": "oci:VM.Standard.A1.Flex", "strategy": "preserve", "source": "vm"})
    assert result["ready"]
    options = result["platform_migration"]
    assert options["source"] == options["target"] == "vm"
    assert not any(options[key] for key in ("install_packages", "configure_network", "configure_serial_console"))


def test_generic_resolution_does_not_generate_oci_metadata_and_x86_keeps_bios():
    source = image("amd64")
    source["boot"] = {"recommended_firmware": "BIOS", "supported_firmware": ["BIOS"]}
    generic = resolve_destination(source, {"profile_id": "generic:x86_64:vm"})
    assert generic["ready"] and generic["oci_defaults"] is None
    oci = resolve_destination(source, {"profile_id": "oci:VM.Standard.E5.Flex"})
    assert oci["ready"] and oci["oci_defaults"]["capabilities"]["Compute.Firmware"]["default_value"] == "BIOS"


@pytest.mark.parametrize("selection", [{"source": "invented"}, {"strategy": "unsafe"}, {"nic_driver": "vfio-pci"}])
def test_invalid_explicit_overrides_fail(selection):
    assert not resolve_destination(image(), {"profile_id": "oci:BM.Standard.A1.160", **selection})["ready"]


def test_oci_profile_uses_actual_ubuntu_release_and_conservative_optional_features():
    from forge.oci import OciConfig
    source = image()
    source["os"].update(distro="ubuntu", name="Ubuntu 26.04.1 LTS")
    source["oci_evidence"] = {"os_version": {"major": 26, "minor": 4}, "consistent_naming_rules": []}
    defaults = resolve_destination(source, {"profile_id": "oci:VM.Standard.A1.Flex"})["oci_defaults"]
    assert defaults["import_options"]["operating_system"] == "Ubuntu"
    assert defaults["import_options"]["operating_system_version"] == "26.04.1"
    for key in ("Storage.ConsistentVolumeNaming", "Compute.SecureBoot", "Compute.AMD_SecureEncryptedVirtualization",
                "Storage.Iscsi.MultipathDeviceSupported", "Network.IPv6Only"):
        assert defaults["capabilities"][key] == {"default_value": False, "values": None}
    assert OciConfig.model_validate(defaults).import_options.operating_system_version == "26.04.1"
    source["oci_evidence"]["consistent_naming_rules"] = ["/etc/udev/rules.d/99-oracle.rules"]
    assert resolve_destination(source, {"profile_id": "oci:VM.Standard.A1.Flex"})["oci_defaults"]["capabilities"]["Storage.ConsistentVolumeNaming"]["default_value"] is True


def test_oci_profile_does_not_invent_release_metadata_without_inspection():
    defaults = resolve_destination(image(), {"profile_id": "oci:VM.Standard.A1.Flex"})["oci_defaults"]
    assert "operating_system" not in defaults["import_options"]
    assert "operating_system_version" not in defaults["import_options"]


@pytest.mark.parametrize("architecture", ["aarch64", "x86_64"])
def test_general_oci_vm_profile_prepares_provider_without_inventing_shape(architecture):
    from forge.oci import OciConfig
    source = image(architecture)
    source["os"].update(distro="ubuntu", name="Ubuntu 26.04.1 LTS")
    result = resolve_destination(source, {"profile_id": f"oci:{architecture}:vm"})
    assert result["ready"] and result["profile"]["provider"] == "oci"
    assert result["profile"]["shape"] is None
    assert result["platform_migration"]["boot_attachment"] == "paravirtualized"
    assert result["platform_migration"]["network_attachment"] == "paravirtualized"
    assert result["oci_defaults"]["import_options"]["shape_compatibility"] == []
    config = OciConfig.model_validate(result["oci_defaults"])
    assert config.import_options.operating_system == "Ubuntu"
    assert config.import_options.operating_system_version == "26.04.1"
    assert config.import_options.launch_mode == "PARAVIRTUALIZED"
    assert config.guest.prepare and config.guest.configure_cloud_init
    assert config.capabilities["Storage.ConsistentVolumeNaming"].default_value is False


def test_required_download_preview_does_not_grant_network_or_package_consent():
    source = image()
    source["os"]["distro"] = "ubuntu"
    tools = {name: True for name in ("dracut", "lsinitrd", "update-grub", "systemctl", "apt-get", "cloud-init",
                                    "iscsiadm", "iscsistart", "iscsid", "iscsi-iname")}
    kernel = {"modules": ["mlx5_core"], "builtin": [], "config": {}}
    source["platform"] = {"kernels": {"test": kernel}, "tools": tools, "dracut_modules": [],
                          "network_backend": "netplan", "fstab": {"root_uuid": "root-uuid", "entries": []}}
    source["oci_evidence"] = {"version": 1, "kernels": {"test": kernel}, "tools": tools,
                              "firmware": {"UEFI_64": True}, "network_backend": "netplan"}
    before = deepcopy(source)
    bare = resolve_destination(source, {"profile_id": "oci:BM.Standard.A1.160"})
    assert bare["required_packages"] == ["dracut-network", "network-manager"]
    assert bare["platform_migration"]["install_packages"] is False
    assert "allow_network" not in bare and source == before
    vm = resolve_destination(source, {"profile_id": "oci:aarch64:vm"})
    assert vm["required_packages"] == []
    preserved = resolve_destination(source, {"profile_id": "oci:BM.Standard.A1.160", "strategy": "preserve"})
    assert preserved["required_packages"] == []
