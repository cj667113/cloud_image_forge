from copy import deepcopy

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from forge.config import Settings
from forge.destinations import resolve_destination
from forge.main import create_app
from forge.oci import OciConfig, compatibility_plan
from forge.oci_shapes import AMD_STANDARD_PV, resolve_shape_compatibility, shape_compatibility_catalog


def image(arch="x86_64"):
    return {"os": {"arch": arch}, "boot": {"recommended_firmware": "UEFI_64", "supported_firmware": ["UEFI_64"]}}


def config(rows=None, mode="auto", **kwargs):
    return OciConfig(import_options={"shape_compatibility": rows or [], "shape_compatibility_mode": mode}, **kwargs)


def test_e5_adds_e4_e6_with_same_limits_without_mutating_explicit_choice():
    rows = [{"shape": "VM.Standard.E5.Flex", "min_ocpus": 2, "max_ocpus": 8,
             "min_memory_gbs": 16, "max_memory_gbs": 128}]
    settings, source = config(rows), image()
    before = deepcopy((settings.model_dump(), source))
    result = resolve_shape_compatibility(source, settings)
    assert result["explicit_shapes"] == ["VM.Standard.E5.Flex"]
    assert result["effective_shapes"][0] == rows[0]
    assert {row["shape"] for row in result["added_shapes"]} == {"VM.Standard.E4.Flex", "VM.Standard.E6.Flex"}
    for row in result["effective_shapes"][1:]:
        assert {key: value for key, value in row.items() if key != "shape"} == {key: value for key, value in rows[0].items() if key != "shape"}
    assert not result["boot_tested"] and result["warnings"]
    assert before == (settings.model_dump(), source)


def test_explicit_extended_limits_are_unchanged_but_added_shapes_use_standard_caps():
    rows = [{"shape": "VM.Standard.E5.Flex", "max_ocpus": 200, "max_memory_gbs": 4000}]
    result = resolve_shape_compatibility(image(), config(rows))
    assert result["effective_shapes"][0] == rows[0]
    added = {row["shape"]: row for row in result["effective_shapes"][1:]}
    assert added["VM.Standard.E4.Flex"]["max_ocpus"] == 64
    assert added["VM.Standard.E6.Flex"]["max_memory_gbs"] == 1454


def test_multiple_explicit_limits_intersect_only_for_new_entries():
    rows = [{"shape": "VM.Standard.E4.Flex", "min_ocpus": 2, "max_ocpus": 12},
            {"shape": "VM.Standard.E5.Flex", "min_ocpus": 4, "max_ocpus": 8, "min_memory_gbs": 16}]
    result = resolve_shape_compatibility(image(), config(rows))
    assert result["effective_shapes"][:2] == rows
    assert result["effective_shapes"][2] == {"shape": "VM.Standard.E6.Flex", "min_ocpus": 4,
                                            "max_ocpus": 8, "min_memory_gbs": 16, "max_memory_gbs": 1454}


@pytest.mark.parametrize("rows", [
    [{"shape": "VM.Standard.E5.Flex", "min_ocpus": 127}],
    [{"shape": "VM.Standard.E5.Flex", "max_ocpus": 1, "min_memory_gbs": 65}],
    [{"shape": "VM.Standard.E4.Flex", "max_ocpus": 2}, {"shape": "VM.Standard.E5.Flex", "min_ocpus": 4}],
])
def test_empty_resource_intersection_never_invents_or_widens_a_sibling(rows):
    result = resolve_shape_compatibility(image(), config(rows))
    assert result["effective_shapes"] == rows
    assert result["skipped_shapes"] and not result["added_shapes"]
    assert all("constraints" in row["reason"] for row in result["skipped_shapes"])


@pytest.mark.parametrize("shape", ["BM.Standard.E5.192", "VM.DenseIO.E5.Flex", "VM.Standard.E6.Ax.Flex",
                                   "VM.Standard.A1.Flex", "VM.Standard.E7.Flex"])
def test_other_hardware_classes_and_unknown_names_are_never_guessed(shape):
    result = resolve_shape_compatibility(image(), config([{"shape": shape}]))
    assert result["effective_shapes"] == [{"shape": shape}]
    assert not result["added_shapes"] and result["warnings"]


@pytest.mark.parametrize("arch", ["aarch64", "unknown", "s390x"])
def test_no_automatic_cross_isa_or_unknown_architecture(arch):
    result = resolve_shape_compatibility(image(arch), config())
    assert result["effective_shapes"] == [] and not result["added_shapes"]


def test_manual_and_old_config_default_preserve_explicit_intent():
    rows = [{"shape": "VM.Standard.E5.Flex", "max_ocpus": 4}]
    result = resolve_shape_compatibility(image(), config(rows, "manual"))
    assert result["effective_shapes"] == rows and not result["added_shapes"]
    assert resolve_shape_compatibility(image(), config([], "manual"))["effective_shapes"] == []
    assert OciConfig(import_options={"shape_compatibility": rows}).import_options.shape_compatibility_mode == "auto"
    with pytest.raises(ValidationError):
        config(mode="all")


@pytest.mark.parametrize("capabilities", [
    {"Network.AttachmentType": {"default_value": "VFIO"}},
    {"Storage.BootVolumeType": {"default_value": "ISCSI"}},
    {"Compute.LaunchMode": {"default_value": "ACCELERATEDPV"}},
    {"Compute.AMD_SecureEncryptedVirtualization": {"default_value": True}},
])
def test_non_pv_or_special_hardware_features_require_explicit_selection(capabilities):
    row = {"shape": "VM.Standard.E5.Flex"}
    result = resolve_shape_compatibility(image(), config([row], capabilities=capabilities))
    assert result["effective_shapes"] == [row] and result["skipped_shapes"]


def test_bare_metal_recipe_does_not_gain_vm_shapes_even_with_pv_capabilities():
    assert not resolve_shape_compatibility(image(), config(), {"enabled": True, "target": "bare_metal"})["effective_shapes"]
    result = resolve_shape_compatibility(image(), config([{"shape": "VM.Standard.E5.Flex"}, {"shape": "BM.Standard.E5.192"}]))
    assert not result["added_shapes"]


def test_limit_preserves_all_explicit_rows_and_unknown_entries():
    rows = [{"shape": "VM.Standard.E5.Flex"}] + [{"shape": f"VM.Future{number}.Flex"} for number in range(99)]
    result = resolve_shape_compatibility(image(), config(rows))
    assert result["effective_shapes"] == rows
    assert len(result["skipped_shapes"]) == 2 and all("100-shape" in row["reason"] for row in result["skipped_shapes"])


def test_general_profile_does_not_invent_shapes_and_catalog_is_independent():
    result = resolve_destination(image(), {"profile_id": "oci:x86_64:vm", "strategy": "reconfigure"})
    assert result["oci_defaults"]["import_options"]["shape_compatibility"] == []
    assert result["shape_compatibility_resolution"]["effective_shapes"] == []
    assert resolve_shape_compatibility(image(), config())["effective_shapes"] == []
    assert result["shape_compatibility_resolution"] == resolve_shape_compatibility(
        image(), result["oci_defaults"], result["platform_migration"])
    catalog = shape_compatibility_catalog()
    catalog["groups"][0]["shapes"].clear()
    assert len(shape_compatibility_catalog()["groups"][0]["shapes"]) == 3


@pytest.mark.parametrize("key,preferred", [("Network.AttachmentType", "VFIO"),
                                          ("Network.AttachmentType", "ACCELERATEDPV"),
                                          ("Storage.BootVolumeType", "ISCSI")])
def test_optional_pv_capabilities_do_not_expand_non_pv_preferred_defaults(key, preferred):
    row = {"shape": "VM.Standard.E5.Flex"}
    settings = config([row], capabilities={key: {"default_value": preferred, "values": [preferred, "PARAVIRTUALIZED"]}})
    result = resolve_shape_compatibility(image(), settings)
    assert result["effective_shapes"] == [row]
    assert all("defaults" in item["reason"] for item in result["skipped_shapes"])


@pytest.mark.parametrize("boot,network", [("iscsi", "paravirtualized"), ("paravirtualized", "vfio"),
                                         ("paravirtualized", "accelerated"), (None, None)])
def test_automatic_siblings_require_shared_pv_hardware_profile_when_enabled(boot, network):
    row = {"shape": "VM.Standard.E5.Flex"}
    result = resolve_shape_compatibility(image(), config([row]),
                                         {"enabled": True, "target": "vm", "boot_attachment": boot, "network_attachment": network})
    assert result["effective_shapes"] == [row]
    assert all("hardware preparation profile" in item["reason"] for item in result["skipped_shapes"])


def test_suggestions_do_not_waive_guest_readiness_and_final_architecture_is_rechecked(monkeypatch):
    monkeypatch.setattr("forge.oci_guest.plan_guest", lambda *a, **k: {"changes": [], "warnings": [], "blockers": ["Missing actual guest driver"]})
    settings = config([{"shape": "VM.Standard.E5.Flex"}])
    plan = compatibility_plan(image(), settings)
    assert len(plan["shape_compatibility_resolution"]["effective_shapes"]) == 3
    assert not plan["ready_to_build"] and "Missing actual guest driver" in plan["blockers"]
    final = compatibility_plan(image("aarch64"), settings, project_platform=False)
    assert not final["shape_compatibility_resolution"]["added_shapes"]
    assert any("requires x86_64" in message for message in final["blockers"])


def test_existing_oci_preview_route_resolves_edits_without_queueing_or_source_changes(tmp_path, monkeypatch):
    monkeypatch.setattr("forge.oci_guest.plan_guest", lambda *a, **k: {"changes": [], "warnings": [], "blockers": []})
    app = create_app(Settings(data_dir=tmp_path))
    with TestClient(app) as client:
        source = app.state.store.create("image", status="ready", inspection=image(), name="fixture")
        before = deepcopy(source)
        url = f"/api/images/{source['id']}/oci/plan"
        body = {"oci": config([{"shape": "VM.Standard.E5.Flex", "max_ocpus": 4}]).model_dump()}
        response = client.post(url, json=body)
        assert response.status_code == 200
        resolved = response.json()["shape_compatibility_resolution"]
        assert len(resolved["effective_shapes"]) == 3
        assert all(row["max_ocpus"] == 4 for row in resolved["effective_shapes"])
        body["oci"]["import_options"]["shape_compatibility_mode"] = "manual"
        assert len(client.post(url, json=body).json()["shape_compatibility_resolution"]["effective_shapes"]) == 1
        assert app.state.store.get("image", source["id"]) == before and app.state.store.list("job") == []
        app.state.store.update("image", source["id"], inspection_status="running")
        assert client.post(url, json=body).status_code == 409
