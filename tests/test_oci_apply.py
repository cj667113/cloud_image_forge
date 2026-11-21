from copy import deepcopy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import io
import zipfile

import pytest

from forge.oci import OciConfig, bundle_files, download_bundle, shape_architecture
from forge.oci_apply import ApplyError, apply


IMAGE = "ocid1.image.oc1.test.imported"
SHAPES = [
    {"shapeName": "VM.Standard.E4.Flex", "ocpuConstraints": {"min": 2, "max": 4}, "memoryConstraints": {"minInGBs": 8, "maxInGBs": 64}},
    {"shapeName": "VM.Standard.E5.Flex", "ocpuConstraints": None, "memoryConstraints": None},
]


def bundle(tmp_path, entries=None, uri=False, arch="x86_64"):
    imports = {"compartmentId": "ocid1.compartment.oc1.test.owner", "launchMode": "PARAVIRTUALIZED"}
    imports.update({"uri": "https://object.example/private-value"} if uri else {"namespace": "ns", "bucketName": "images", "name": "disk.oci"})
    (tmp_path / "image-import.json").write_text(json.dumps(imports))
    entries = entries if entries is not None else SHAPES
    (tmp_path / "shape-compatibility.json").write_text(json.dumps({"version": 1, "entries": entries, "architecture": arch,
        "shapeArchitectures": {row["shapeName"]: shape_architecture(row["shapeName"]) for row in entries}}))
    return tmp_path


class FakeCli:
    def __init__(self, rows=None):
        self.rows = deepcopy(rows or [])
        self.calls = []
        self.fail_shape = None
        self.drop_shape = None
        self.fail_remove = None
        self.ignore_remove = False
        self.import_timeout = False
        self.drop_inherited_limit = False
        self.lifecycle = ["AVAILABLE"]

    def __call__(self, command, **kwargs):
        assert kwargs == {"capture_output": True, "text": True, "timeout": 120, "check": False}
        args = command[command.index("compute"):]
        assert "--no-retry" in args and args[args.index("--output") + 1] == "json"
        payload = None
        if "--from-json" in args:
            path = Path(args[args.index("--from-json") + 1].removeprefix("file://"))
            assert path.stat().st_mode & 0o777 == 0o600
            payload = json.loads(path.read_text())
        self.calls.append((list(command), deepcopy(payload)))
        if args[:3] == ["compute", "image", "import"]:
            assert payload.get("sourceImageType") in (None, "QCOW2", "VMDK")
            if self.import_timeout:
                raise subprocess.TimeoutExpired(command, 120)
            data = {"id": IMAGE, "lifecycle-state": "IMPORTING"}
        elif args[:3] == ["compute", "image", "get"]:
            assert args[args.index("--image-id") + 1] == IMAGE
            status = self.lifecycle.pop(0) if len(self.lifecycle) > 1 else self.lifecycle[0]
            data = {"id": IMAGE, "lifecycle-state": status}
        elif args[:3] == ["compute", "image-shape-compatibility-entry", "list"]:
            assert "--all" in args
            data = deepcopy(self.rows)
            if not data:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
        elif args[:3] == ["compute", "image-shape-compatibility-entry", "add"]:
            assert "--force" in args and payload["imageId"] == IMAGE
            if self.fail_shape == payload["shapeName"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="private object URL must not be echoed")
            row = {"image-id": IMAGE, "shape": payload["shapeName"],
                   "ocpu-constraints": payload.get("ocpuConstraints"),
                   "memory-constraints": {k.replace("minInGBs", "min-in-gbs").replace("maxInGBs", "max-in-gbs"): v for k, v in payload.get("memoryConstraints", {}).items()} or None}
            if self.drop_inherited_limit:
                row["ocpu-constraints"].pop("max", None)
            if self.drop_shape != payload["shapeName"]:
                self.rows = [old for old in self.rows if old["shape"] != row["shape"]] + [row]
            data = row
        elif args[:3] == ["compute", "image-shape-compatibility-entry", "remove"]:
            assert "--force" in args and args[args.index("--image-id") + 1] == IMAGE
            name = args[args.index("--shape-name") + 1]
            if self.fail_remove == name:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if not self.ignore_remove:
                self.rows = [row for row in self.rows if row["shape"] != name]
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        else:
            pytest.fail("Unexpected cloud operation: " + repr(args[:4]))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"data": data}), stderr="")

    def count(self, operation):
        return sum(operation in command for command, _ in self.calls)


@pytest.mark.parametrize("uri,method", [(False, "from-object"), (True, "from-object-uri")])
def test_one_command_import_wait_apply_every_shape_and_verify(tmp_path, uri, method):
    cli = FakeCli([{ "shape": "VM.Unrelated.Existing", "ocpu-constraints": {"min": 0.125}, "memory-constraints": None}])
    cli.lifecycle = ["IMPORTING", "AVAILABLE"]
    pauses = []
    result = apply(bundle(tmp_path, uri=uri), import_image=True, profile="TEAM", region="us-test-1", run=cli, sleep=pauses.append)
    assert result["image_id"] == IMAGE and result["verified_shapes"] == [row["shapeName"] for row in SHAPES]
    assert cli.count("import") == 1 and cli.count("add") == 2 and cli.count("list") == 2
    assert cli.calls[0][0][cli.calls[0][0].index("import") + 1] == method
    assert all(command[:5] == ["oci", "--profile", "TEAM", "--region", "us-test-1"] for command, _ in cli.calls)
    assert pauses == [10]
    assert any(row["shape"] == "VM.Unrelated.Existing" for row in cli.rows)
    state = json.loads((tmp_path / ".forge-oci-apply-state.json").read_text())
    assert state["completed"] and state["image_id"] == IMAGE
    assert (tmp_path / ".forge-oci-apply-state.json").stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".oci-request-*"))


def test_partial_shape_failure_resumes_without_duplicate_import_or_first_add(tmp_path):
    cli = FakeCli(); cli.fail_shape = SHAPES[1]["shapeName"]
    with pytest.raises(ApplyError, match="state is saved") as error:
        apply(bundle(tmp_path), import_image=True, run=cli)
    assert "private object URL" not in str(error.value)
    assert json.loads((tmp_path / ".forge-oci-apply-state.json").read_text())["image_id"] == IMAGE
    cli.fail_shape = None
    apply(tmp_path, import_image=True, run=cli)
    assert cli.count("import") == 1 and cli.count("add") == 3
    apply(tmp_path, import_image=True, run=cli)
    assert cli.count("import") == 1 and cli.count("add") == 3


def test_unknown_import_result_blocks_duplicate_until_operator_supplies_ocid(tmp_path):
    cli = FakeCli(); cli.import_timeout = True
    with pytest.raises(ApplyError, match="did not finish"):
        apply(bundle(tmp_path), import_image=True, run=cli)
    with pytest.raises(ApplyError, match="outcome is unknown"):
        apply(tmp_path, import_image=True, run=cli)
    assert cli.count("import") == 1
    apply(tmp_path, image_id=IMAGE, run=cli)
    assert cli.count("import") == 1


def test_existing_import_skips_matching_and_preserves_unspecified_bounds(tmp_path):
    rows = [{"shape": SHAPES[0]["shapeName"], "ocpu-constraints": {"min": 1, "max": 8}, "memory-constraints": {"min-in-gbs": 4, "max-in-gbs": 128}}]
    cli = FakeCli(rows)
    apply(bundle(tmp_path, [{"shapeName": SHAPES[0]["shapeName"], "ocpuConstraints": {"min": 2}}]), image_id=IMAGE, run=cli)
    assert cli.count("import") == 0
    payload = next(payload for command, payload in cli.calls if "add" in command)
    assert payload["ocpuConstraints"] == {"min": 2, "max": 8}
    assert payload["memoryConstraints"] == {"minInGBs": 4, "maxInGBs": 128}


def test_service_dropping_requested_shape_fails_verification(tmp_path):
    cli = FakeCli(); cli.drop_shape = SHAPES[1]["shapeName"]
    with pytest.raises(ApplyError, match="did not retain every"):
        apply(bundle(tmp_path), image_id=IMAGE, run=cli)


def test_exact_shapes_reconciles_existing_arm_import_and_resumes(tmp_path):
    selected = "BM.Standard.A4.48"
    extras = ["VM.Standard.E4.Flex", "VM.Standard.E5.Flex"]
    cli = FakeCli([{"shape": name, "ocpu-constraints": {"min": 0.125}} for name in extras])
    apply(bundle(tmp_path, [{"shapeName": selected}], arch="aarch64"), image_id=IMAGE, run=cli)
    assert cli.count("remove") == 0
    cli.fail_remove = extras[1]
    with pytest.raises(ApplyError, match="remove.*failed"):
        apply(tmp_path, image_id=IMAGE, exact_shapes=True, run=cli)
    assert {row["shape"] for row in cli.rows} == {selected, extras[1]}
    cli.fail_remove = None
    result = apply(tmp_path, image_id=IMAGE, exact_shapes=True, run=cli)
    assert result["verified_shapes"] == [selected] and result["additional_shapes"] == []
    assert result["removed_shapes"] == [extras[1]]
    assert [row["shape"] for row in cli.rows] == [selected]
    assert cli.count("import") == 0 and cli.count("add") == 1


def test_exact_shapes_requires_verified_selection_before_removal(tmp_path):
    cli = FakeCli([{"shape": "VM.Other"}])
    with pytest.raises(ApplyError, match="at least one"):
        apply(bundle(tmp_path, []), import_image=True, exact_shapes=True, run=cli)
    assert not cli.calls
    with pytest.raises(ApplyError, match="guest architecture"):
        apply(bundle(tmp_path, arch="aarch64"), image_id=IMAGE, exact_shapes=True, run=cli)
    assert not cli.calls
    cli.drop_shape = SHAPES[0]["shapeName"]
    with pytest.raises(ApplyError, match="did not retain"):
        apply(bundle(tmp_path), image_id=IMAGE, exact_shapes=True, run=cli)
    assert cli.count("remove") == 0
    cli.drop_shape = None
    cli.ignore_remove = True
    with pytest.raises(ApplyError, match="still lists additional"):
        apply(tmp_path, image_id=IMAGE, exact_shapes=True, run=cli)


def test_download_updates_older_bundles_without_changing_shape_selection(tmp_path):
    path = tmp_path / "bundle.zip"
    selected = b'{"version":1,"entries":[{"shapeName":"BM.Standard.A1.160"}]}'
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("shape-compatibility.json", selected)
        archive.writestr("apply-oci.py", "old helper")
        archive.writestr("README.txt", "Existing custom instructions.\n")
    with zipfile.ZipFile(io.BytesIO(download_bundle(path, architecture="arm64"))) as archive:
        manifest = json.loads(archive.read("shape-compatibility.json"))
        assert manifest["entries"] == json.loads(selected)["entries"]
        assert manifest["architecture"] == "aarch64" and manifest["shapeArchitectures"] == {"BM.Standard.A1.160": "aarch64"}
        assert b"--exact-shapes" in archive.read("apply-oci.py")
        assert b"--exact-shapes" in archive.read("README.txt")
        assert b"Existing custom instructions." in archive.read("README.txt")


def test_service_dropping_preserved_limit_also_fails_readback(tmp_path):
    cli = FakeCli([{"shape": "VM.Standard.E4.Flex", "ocpu-constraints": {"min": 1, "max": 8}, "memory-constraints": None}])
    cli.drop_inherited_limit = True
    with pytest.raises(ApplyError, match="did not retain every"):
        apply(bundle(tmp_path, [{"shapeName": "VM.Standard.E4.Flex", "ocpuConstraints": {"min": 2}}]), image_id=IMAGE, run=cli)


@pytest.mark.parametrize("entries", [SHAPES * 2, [{"shapeName": "bad;command"}], [{"shapeName": "VM.Test", "extra": True}], [{"shapeName": "VM.Test", "memoryConstraints": {"minInGBs": 8, "maxInGBs": 4}}]])
def test_invalid_shapes_rejected_before_cloud_calls(tmp_path, entries):
    cli = FakeCli()
    with pytest.raises(ApplyError):
        apply(bundle(tmp_path, entries), image_id=IMAGE, run=cli)
    assert not cli.calls


def test_unfilled_import_and_changed_saved_context_do_not_import(tmp_path):
    bundle(tmp_path); (tmp_path / "image-import.json").write_text('{"compartmentId":"REPLACE_COMPARTMENT_OCID"}')
    cli = FakeCli()
    with pytest.raises(ApplyError, match="REPLACE"):
        apply(tmp_path, import_image=True, run=cli)
    assert not cli.calls
    bundle(tmp_path)
    apply(tmp_path, image_id=IMAGE, profile="ONE", run=cli)
    count = len(cli.calls)
    with pytest.raises(ApplyError, match="profile/region changed"):
        apply(tmp_path, image_id=IMAGE, profile="TWO", run=cli)
    assert len(cli.calls) == count


def test_invalid_oci_standalone_type_is_rejected_before_import_intent(tmp_path):
    bundle(tmp_path)
    path = tmp_path / "image-import.json"
    data = json.loads(path.read_text()); data["sourceImageType"] = "OCI"
    path.write_text(json.dumps(data))
    cli = FakeCli()
    with pytest.raises(ApplyError, match="omit that field"):
        apply(tmp_path, import_image=True, run=cli)
    assert not cli.calls and not (tmp_path / ".forge-oci-apply-state.json").exists()


def test_existing_image_terminal_state_does_not_write_shapes(tmp_path):
    cli = FakeCli(); cli.lifecycle = ["DELETED"]
    with pytest.raises(ApplyError, match="not available"):
        apply(bundle(tmp_path), image_id=IMAGE, run=cli)
    assert cli.count("add") == 0


def test_exported_script_is_standalone_and_manifest_uses_effective_rows():
    config = OciConfig(import_options={"shape_compatibility": [{"shape": "VM.Standard.E5.Flex"}]})
    resolution = {"effective_shapes": [{"shape": row["shapeName"]} for row in SHAPES]}
    files = bundle_files(config, {"format": "oci", "shape_compatibility_resolution": resolution})
    assert "from forge" not in files["apply-oci.py"]
    compile(files["apply-oci.py"], "apply-oci.py", "exec")
    assert [row["shapeName"] for row in json.loads(files["shape-compatibility.json"])["entries"]] == [row["shapeName"] for row in SHAPES]
    assert json.loads(files["shape-resolution.json"]) == resolution
    assert "python3 apply-oci.py --import-image" in files["README.txt"]
    assert "python3 apply-oci.py --image-id IMAGE_OCID" in files["README.txt"]
