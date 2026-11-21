from copy import deepcopy
import json

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


@pytest.mark.parametrize("group_id,arch,shapes", [
    ("oci:arm-standard-pv", "aarch64", ["VM.Standard.A1.Flex", "VM.Standard.A2.Flex", "VM.Standard.A4.Flex"]),
    ("oci:amd-standard-pv", "x86_64", ["VM.Standard.E4.Flex", "VM.Standard.E5.Flex", "VM.Standard.E6.Flex"]),
])
def test_group_shares_preparation_and_exports_each_named_shape(group_id, arch, shapes):
    from forge.oci import OciConfig, bundle_files

    profiles = {item["id"]: item for item in destination_catalog()["profiles"]}
    group = profiles[group_id]
    assert group["shapes"] == shapes
    assert group["label"] == f"{shapes[0]}, {shapes[1]} and {shapes[2]}"
    listed = [p for p in profiles.values() if p["architecture"] == arch and "group_id" not in p]
    assert [p["id"] for p in listed if set(shapes).intersection(p["shapes"])] == [group_id]
    assert all(p in listed for p in profiles.values() if p["architecture"] == arch and
               (p["network_attachment"] == "accelerated" or (not p["shapes"] and not p.get("group_id"))))

    source = image(arch)
    grouped = resolve_destination(source, {"profile_id": group_id})
    assert grouped["ready"]
    for name in shapes:
        exact = resolve_destination(source, {"profile_id": "oci:" + name})
        assert exact["profile"]["group_id"] == group_id
        assert exact["oci_defaults"]["import_options"]["shape_compatibility"] == [{"shape": name}]
        assert grouped["platform_migration"] == exact["platform_migration"]
        assert grouped["oci_defaults"]["capabilities"] == exact["oci_defaults"]["capabilities"]
        assert grouped["oci_defaults"]["guest"] == exact["oci_defaults"]["guest"]
        assert grouped["required_packages"] == exact["required_packages"]
    config = OciConfig.model_validate(grouped["oci_defaults"])
    assert config.import_options.shape_compatibility_mode == "manual"
    resolution = grouped["shape_compatibility_resolution"]
    assert resolution["effective_shapes"] == [{"shape": name} for name in shapes]
    files = bundle_files(config, {"format": "oci", "shape_compatibility_resolution": resolution})
    assert [r["shapeName"] for r in json.loads(files["shape-compatibility.json"])["entries"]] == shapes

    wrong_arch = "aarch64" if arch == "x86_64" else "x86_64"
    assert not resolve_destination(image(wrong_arch), {"profile_id": group_id})["ready"]


@pytest.mark.parametrize("arch", ["aarch64", "x86_64"])
def test_bare_metal_picker_groups_equal_overrides_and_keeps_saved_single_shape(arch):
    profiles = destination_catalog()["profiles"]
    members = [p for p in profiles if p["architecture"] == arch and p["target"] == "bare_metal" and p["shape"]]
    group, = [p for p in profiles if p["id"] == members[0]["group_id"]]
    source = image(arch)
    grouped = resolve_destination(source, {"profile_id": group["id"], "nic_driver": "mlx5_core"})
    assert grouped["ready"] and group["shapes"] == [p["shape"] for p in members]
    assert grouped["oci_defaults"]["import_options"]["shape_compatibility_mode"] == "manual"
    assert grouped["shape_compatibility_resolution"]["effective_shapes"] == [{"shape": name} for name in group["shapes"]]
    for p in members:
        assert p["group_id"] == group["id"]
        saved = resolve_destination(source, {"profile_id": p["id"], "nic_driver": "mlx5_core"})
        assert saved["oci_defaults"]["capabilities"] == grouped["oci_defaults"]["capabilities"]
        assert saved["platform_migration"] == grouped["platform_migration"]
        assert saved["shape_compatibility_resolution"]["effective_shapes"] == [{"shape": p["shape"]}]


@pytest.mark.parametrize("arch", ["aarch64", "x86_64"])
@pytest.mark.parametrize("target", ["vm", "bare_metal"])
def test_generic_alias_shares_hardware_but_preserves_its_export_semantics(arch, target):
    profiles = {p["id"]: p for p in destination_catalog()["profiles"]}
    generic = profiles[f"generic:{arch}:{target}"]
    row = profiles[generic["group_id"]]
    assert row["shapes"] and row["architecture"] == arch and row["target"] == target
    variants = [row["id"], generic["id"]]
    if target == "vm":
        general = profiles[f"oci:{arch}:vm"]
        assert general["group_id"] == row["id"]
        variants.append(general["id"])
    assert row["variants"] == variants
    options = {"nic_driver": "mlx5_core"} if target == "bare_metal" else {}
    plans = [resolve_destination(image(arch), {"profile_id": key, "strategy": "reconfigure", **options}) for key in variants]
    assert all(p["platform_migration"] == plans[0]["platform_migration"] for p in plans)
    assert plans[1]["oci_defaults"] is None
    assert plans[0]["oci_defaults"]["import_options"]["shape_compatibility"] == [{"shape": name} for name in row["shapes"]]
    if target == "vm":
        assert plans[2]["oci_defaults"]["import_options"]["shape_compatibility"] == []


def test_group_splits_when_a_member_requires_different_network_preparation(monkeypatch):
    from forge import destinations

    monkeypatch.setattr(destinations, "ACCELERATED_VM_SHAPES", destinations.ACCELERATED_VM_SHAPES | {"VM.Standard.A2.Flex"})
    profiles = {p["id"]: p for p in destination_catalog()["profiles"]}
    assert "oci:arm-standard-pv" not in profiles
    for generation in ("A1", "A2", "A4"):
        assert "group_id" not in profiles[f"oci:VM.Standard.{generation}.Flex"]
    assert profiles["oci:VM.Standard.A2.Flex"]["network_attachment"] == "accelerated"


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


@pytest.mark.parametrize("cloud_ready,oci_prepare", [(True, False), (False, True)])
def test_automatic_does_only_the_preparation_needed_for_the_destination(cloud_ready, oci_prepare):
    from test_platform import image as hardware_image, KERNEL
    from test_oci_guest import inspected
    source = hardware_image()
    guest = inspected()["oci_evidence"]
    kernel = next(iter(guest["kernels"].values()))
    kernel.update(initrd=source["platform"]["kernels"][KERNEL]["initrd"], initrd_modules=[])
    guest.update(kernels={KERNEL: kernel}, cloud_init_ready=cloud_ready)
    source["oci_evidence"] = guest
    before = deepcopy(source)
    result = resolve_destination(source, {"profile_id": "oci:VM.Standard.E5.Flex"})
    assert result["platform_migration"]["strategy"] == "reconfigure"
    assert result["oci_defaults"]["guest"]["prepare"] is oci_prepare
    explicit = resolve_destination(source, {"profile_id": "oci:VM.Standard.E5.Flex", "strategy": "reconfigure"})
    assert explicit["oci_defaults"]["guest"]["prepare"]
    assert source == before


def test_automatic_preserves_a_guest_with_existing_platform_and_provider_evidence():
    from test_portability import image as portable_image, KERNEL
    from test_oci_guest import inspected
    source = portable_image()
    guest = inspected()["oci_evidence"]
    kernel = next(iter(guest["kernels"].values()))
    kernel["initrd"] = source["platform"]["kernels"][KERNEL]["initrd"]
    guest["kernels"] = {KERNEL: kernel}
    source["oci_evidence"] = guest
    for profile in ("oci:VM.Standard.E5.Flex", "generic:x86_64:vm"):
        result = resolve_destination(source, {"profile_id": profile, "strategy": "auto"})
        assert result["platform_migration"]["strategy"] == "preserve"
        assert result["required_packages"] == []
        if result["oci_defaults"]:
            assert not result["oci_defaults"]["guest"]["prepare"]


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
