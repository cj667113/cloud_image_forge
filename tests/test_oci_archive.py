from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tarfile
from types import SimpleNamespace

import pytest

from forge import oci_archive as subject
from forge.oci import ARM_SHAPES, GLOBAL_SCHEMA, X86_SHAPES, OciConfig


FORMAT_UUID = "34dd2cea-aff2-4f45-b8f6-1cb5290bfab2"
INSPECTION = {"os": {"distro": "ubuntu", "name": "Ubuntu 26.04.1 LTS", "arch": "aarch64"},
              "boot": {"mode": "bios", "supported_firmware": ["BIOS"]}}


def qcow(path, *, version=3, payload=b"image bytes\0" * 100):
    # The engine owns QEMU validity checks. This fixture tests the archive's
    # bounded header gate and byte preservation, without invoking QEMU.
    header = bytearray(104 if version == 3 else 72)
    header[:4] = b"QFI\xfb"
    struct.pack_into(">I", header, 4, version)
    struct.pack_into(">I", header, 20, 16)
    struct.pack_into(">Q", header, 24, 1024**3)
    if version == 3:
        struct.pack_into(">I", header, 100, 104)
    path.write_bytes(header + payload)
    return path


def package(tmp_path, config=None, **kwargs):
    source = qcow(tmp_path / "source.qcow2", **kwargs)
    destination = tmp_path / "image.oci"
    result = subject.write_archive(destination, source, config or OciConfig(), deepcopy(INSPECTION), lambda _: None)
    return source, destination, result


def native_reference(shape, internal):
    return {"image_metadata": {"version": 2,
                               "operatingSystem": "Different source",
                               "additionalMetadata": {"shapeCompatibilities": [
                                   {"internalShapeName": internal, "memoryConstraints": {"maxInGBs": 999}}]}},
            "oci_shape_list": {"data": [{"image-id": "ocid1.image.oc1.iad.reference", "shape": shape}]}}


def test_operator_reference_embeds_only_single_named_shape_and_uses_export_limits(monkeypatch, tmp_path):
    name = "BM.Standard.A4.48"
    monkeypatch.setattr(subject, "SHAPE_REFERENCE_DIR", tmp_path)
    (tmp_path / f"{name}.json").write_text(json.dumps(native_reference(name, "test-native-arm")))
    config = OciConfig(import_options={"shape_compatibility": [{"shape": name, "max_memory_gbs": 16}]})
    _, archive_path, receipt = package(tmp_path, config)
    with tarfile.open(archive_path) as archive:
        metadata = json.load(archive.extractfile("image_metadata.json"))
    assert metadata["additionalMetadata"] == {"shapeCompatibilities": [
        {"internalShapeName": "test-native-arm", "memoryConstraints": {"maxInGBs": 16}, "ocpuConstraints": None}]}
    assert metadata["operatingSystem"] == "Ubuntu" and "ocid1.image" not in json.dumps(metadata)
    assert receipt["shape_compatibility"]["embedded_shapes"] == [name]


@pytest.mark.parametrize("change", ["shape", "image-id", "two-public", "two-internal", "version", "next-page",
                                    "other-public-alias", "other-variant", "incompatible-alias", "path-alias",
                                    "oversize", "symlink"])
def test_shape_reference_requires_unambiguous_native_pair(monkeypatch, tmp_path, change):
    name = "BM.Standard.A4.48"
    monkeypatch.setattr(subject, "SHAPE_REFERENCE_DIR", tmp_path)
    path = tmp_path / f"{name}.json"
    ref = native_reference(name, "test-native-arm")
    public = ref["oci_shape_list"]["data"]
    internal = ref["image_metadata"]["additionalMetadata"]["shapeCompatibilities"]
    if change == "shape":
        public[0]["shape"] = "BM.Standard.A1.160"
    elif change == "image-id":
        public[0]["image-id"] = "wrong"
    elif change == "two-public":
        public.append(dict(public[0]))
    elif change == "two-internal":
        internal.append(dict(internal[0]))
    elif change == "version":
        ref["image_metadata"]["version"] = 1
    elif change == "next-page":
        ref["oci_shape_list"]["opc-next-page"] = "more"
    elif change == "other-public-alias":
        internal[0]["internalShapeName"] = "VM.Standard.A2.Flex"
    elif change == "other-variant":
        internal[0]["internalShapeName"] = "a4-2c.96.768.ax"
    elif change == "incompatible-alias":
        internal[0]["internalShapeName"] = "e99-2c.test-x86"
    elif change == "path-alias":
        internal[0]["internalShapeName"] = "../escape"
    elif change == "oversize":
        ref["padding"] = "x" * subject.MAX_REFERENCE_BYTES
    if change == "symlink":
        other = tmp_path / "uploaded.json"
        other.write_text(json.dumps(ref))
        path.symlink_to(other)
    else:
        path.write_text(json.dumps(ref))
    with pytest.raises(subject.OciArchiveError, match="shape reference"):
        package(tmp_path, OciConfig(import_options={"shape_compatibility": [{"shape": name}]}))
    assert not (tmp_path / "image.oci").exists()


def test_duplicate_aliases_from_installed_references_are_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(subject, "SHAPE_REFERENCE_DIR", tmp_path)
    names = ["BM.Standard.A1.160", "BM.Standard.A4.48"]
    for name in names:
        (tmp_path / f"{name}.json").write_text(json.dumps(native_reference(name, "one-test-alias")))
    config = OciConfig(import_options={"shape_compatibility": [{"shape": name} for name in names]})
    with pytest.raises(subject.OciArchiveError, match="same archive name"):
        package(tmp_path, config)


def test_actual_os_and_selected_launch_values_without_source_firmware_gate():
    config = OciConfig(capabilities={
        "Compute.Firmware": {"default_value": "UEFI_64", "values": ["UEFI_64"]},
        "Compute.LaunchMode": {"default_value": "CUSTOM", "values": ["CUSTOM"]},
        "Network.AttachmentType": {"default_value": "ACCELERATEDPV", "values": ["ACCELERATEDPV"]},
        "Storage.ConsistentVolumeNaming": {"default_value": False}},
        import_options={"launch_mode": "ACCELERATEDPV", "operating_system": "Oracle Linux", "operating_system_version": "9"})
    before, inspection = config.model_dump(), deepcopy(INSPECTION)
    result = subject.image_metadata(config, inspection)
    assert result["operatingSystem"] == "Ubuntu" and result["operatingSystemVersion"] == "26.04.1"
    launch = result["externalLaunchOptions"]
    assert len(launch) == 9
    assert launch["firmware"] == "UEFI_64"
    assert launch["launchOptionsSource"] == launch["networkType"] == "ACCELERATEDPV"
    assert launch["consistentVolumeNamingEnabled"] is False
    assert type(launch["pvAttachmentVersion"]) is int
    assert result["imageCapabilityData"] is result["imageCapsFormatVersion"] is None
    assert "additionalMetadata" not in result and "sourcePublicImageId" not in json.dumps(result)
    assert inspection == INSPECTION and config.model_dump() == before


def test_explicit_format_embeds_every_descriptor_without_api_source():
    schema = deepcopy(GLOBAL_SCHEMA)
    schema["Compute.FutureFlag"] = {"descriptorType": "boolean", "defaultValue": False}
    config = OciConfig(global_schema=schema, global_schema_version="api-global-version-not-a-uuid",
                       image_caps_format_version=FORMAT_UUID,
                       capabilities={"Compute.FutureFlag": {"default_value": True},
                                     "Storage.ParaVirtualization.AttachmentVersion": {"default_value": 1, "values": [1, 2]}})
    result = subject.image_metadata(config, INSPECTION)
    assert result["imageCapsFormatVersion"] == FORMAT_UUID
    assert isinstance(result["imageCapabilityData"], str)
    caps = json.loads(result["imageCapabilityData"])["capabilities"]
    assert caps.keys() == config.capabilities.keys()
    assert caps["Compute.FutureFlag"] == {"descriptorType": "boolean", "defaultValue": True}
    assert caps["Storage.ParaVirtualization.AttachmentVersion"]["values"] == [1, 2]
    assert all("source" not in value for value in caps.values())


def test_global_api_version_is_never_archive_format_version():
    result = subject.image_metadata(OciConfig(global_schema_version=FORMAT_UUID), INSPECTION)
    assert result["imageCapabilityData"] is result["imageCapsFormatVersion"] is None


def test_multiple_observed_vm_shapes_are_embedded_with_exact_limits():
    config = OciConfig(import_options={"shape_compatibility": [
        {"shape": "VM.Standard.E5.Flex", "min_ocpus": 2, "max_ocpus": 4,
         "min_memory_gbs": 8, "max_memory_gbs": 64}]})
    inspection = {**deepcopy(INSPECTION), "os": {"distro": "ubuntu", "name": "Ubuntu 26.04.1 LTS", "arch": "x86_64"}}
    before = config.model_dump()
    metadata = subject.image_metadata(config, inspection)
    shapes = metadata["additionalMetadata"]["shapeCompatibilities"]
    assert {row["internalShapeName"] for row in shapes} == {"VM.Standard.E4.Flex", "VM.Standard.E5.Flex", "VM.Standard.E6.Flex"}
    assert all(row["ocpuConstraints"] == {"min": 2, "max": 4} for row in shapes)
    assert all(row["memoryConstraints"] == {"minInGBs": 8, "maxInGBs": 64} for row in shapes)
    assert config.model_dump() == before


def test_arm_vm_group_has_the_same_three_shapes_and_per_shape_limits_in_archive_and_companion(tmp_path):
    from forge.destinations import resolve_destination
    from forge.oci import bundle_files

    selected = resolve_destination(INSPECTION, {"profile_id": "oci:arm-standard-pv"})
    config = OciConfig.model_validate(selected["oci_defaults"])
    config.import_options.shape_compatibility[1].max_ocpus = 4
    path = tmp_path / "arm.oci"
    subject.write_archive(path, qcow(tmp_path / "source.qcow2"), config, INSPECTION, lambda _: None)
    with tarfile.open(path) as archive:
        embedded = json.load(archive.extractfile("image_metadata.json"))["additionalMetadata"]["shapeCompatibilities"]
    files = bundle_files(config, {"format": "oci"})
    entries = json.loads(files["shape-compatibility.json"])["entries"]
    assert [entry["shapeName"] for entry in entries] == ["VM.Standard.A1.Flex", "VM.Standard.A2.Flex", "VM.Standard.A4.Flex"]
    assert [entry["ocpuConstraints"] for entry in entries] == [None, {"max": 4}, None]
    assert embedded == [{"internalShapeName": row["shapeName"], "ocpuConstraints": row["ocpuConstraints"],
                         "memoryConstraints": None} for row in entries]


def test_selected_x86_shapes_use_native_names_and_ignore_source_shape_list():
    config = OciConfig(import_options={"shape_compatibility_mode": "manual", "shape_compatibility": [
        {"shape": "VM.Standard.E4.Flex", "max_ocpus": 8}, {"shape": "BM.Standard.E5.192"}]})
    inspection = deepcopy(INSPECTION)
    inspection["os"]["arch"] = "x86_64"
    inspection["additionalMetadata"] = {"shapeCompatibilities": [{"internalShapeName": "unsafe-source-default"}]}
    metadata = subject.image_metadata(config, inspection)
    assert [row["internalShapeName"] for row in metadata["additionalMetadata"]["shapeCompatibilities"]] == [
        "VM.Standard.E4.Flex", "e5-2c.192.2304"]


def test_every_catalog_shape_has_a_distinct_native_identifier():
    assert subject.OBSERVED_SHAPE_NAMES.keys() == ARM_SHAPES | X86_SHAPES
    assert len(set(subject.OBSERVED_SHAPE_NAMES.values())) == len(subject.OBSERVED_SHAPE_NAMES)


def test_missing_bare_metal_mapping_cannot_publish_a_literal_public_name(tmp_path, monkeypatch):
    name = "BM.Standard.A4.48"
    monkeypatch.delitem(subject.OBSERVED_SHAPE_NAMES, name)
    monkeypatch.setattr(subject, "SHAPE_REFERENCE_DIR", tmp_path)
    config = OciConfig(import_options={"shape_compatibility": [{"shape": name}]})
    with pytest.raises(subject.OciArchiveError, match="No verified OCI archive mapping"):
        package(tmp_path, config)
    assert not (tmp_path / "image.oci").exists()


@pytest.mark.parametrize("shapes,aliases,network,launch", [
    (["BM.Standard.A1.160", "BM.Standard.A4.48"], ["a1-2c.160.1024", "a4-2c.96.768"], "VFIO", "NATIVE"),
    (["BM.Standard.A4.Ax.48"], ["a4-2c.96.768.ax"], "PARAVIRTUALIZED", "CUSTOM"),
])
def test_bare_metal_download_contains_only_selected_shapes_and_effective_overrides(tmp_path, shapes, aliases, network, launch):
    config = OciConfig(import_options={"shape_compatibility": [{"shape": shape, "max_ocpus": 8} for shape in shapes],
                                       "launch_mode": launch},
                       capabilities={"Network.AttachmentType": {"default_value": network},
                                     "Compute.LaunchMode": {"default_value": launch},
                                     "Storage.BootVolumeType": {"default_value": "ISCSI"}})
    _, path, receipt = package(tmp_path, config)
    with tarfile.open(path) as archive:
        metadata = json.load(archive.extractfile("image_metadata.json"))
    assert metadata["additionalMetadata"]["shapeCompatibilities"] == [
        {"internalShapeName": alias, "ocpuConstraints": {"max": 8}, "memoryConstraints": None}
        for alias in aliases]
    assert metadata["externalLaunchOptions"]["networkType"] == network
    assert metadata["externalLaunchOptions"]["launchOptionsSource"] == launch
    assert metadata["externalLaunchOptions"]["bootVolumeType"] == "ISCSI"
    assert metadata["imageCapsFormatVersion"] == FORMAT_UUID
    assert json.loads(metadata["imageCapabilityData"])["capabilities"]["Network.AttachmentType"]["defaultValue"] == network
    assert receipt["capability_mode"] == "embedded"
    assert receipt["shape_compatibility"]["embedded_shapes"] == shapes
    assert receipt["shape_compatibility"]["public_name_shapes"] == []


@pytest.mark.parametrize("arch,shape,reason", [
    ("arm64", "VM.Standard.E4.Flex", "requires x86_64"),
    ("amd64", "VM.Standard.A2.Flex", "requires aarch64"),
    ("aarch64", "VM.Future.Flex", "architecture of VM.Future.Flex is unknown"),
    ("unknown", "VM.Standard.A1.Flex", "verified ARM64 or x86_64")])
def test_effective_archive_shapes_must_match_inspected_architecture(arch, shape, reason):
    config = OciConfig(import_options={"shape_compatibility_mode": "manual", "shape_compatibility": [{"shape": shape}]})
    inspection = deepcopy(INSPECTION)
    inspection["os"]["arch"] = arch
    with pytest.raises(subject.OciArchiveError, match=reason):
        subject.image_metadata(config, inspection, shape_resolution={"effective_shapes": [{"shape": shape}]})


def test_empty_shape_selection_cannot_advertise_a_stale_effective_row():
    with pytest.raises(subject.OciArchiveError, match="unselected shape"):
        subject.image_metadata(OciConfig(), INSPECTION,
                               shape_resolution={"effective_shapes": [{"shape": "VM.Standard.A1.Flex"}]})


@pytest.mark.parametrize("effective", [[], [{"shape": "VM.Standard.A1.Flex"}, {"shape": "VM.Standard.A2.Flex"}]])
def test_manual_shape_selection_cannot_be_dropped_or_expanded(effective):
    config = OciConfig(import_options={"shape_compatibility_mode": "manual",
                                       "shape_compatibility": [{"shape": "VM.Standard.A1.Flex"}]})
    with pytest.raises(subject.OciArchiveError, match="saved OCI shape list"):
        subject.image_metadata(config, INSPECTION, shape_resolution={"effective_shapes": effective})


def test_final_resolution_is_identical_in_archive_and_companion(tmp_path):
    from forge.oci import bundle_files
    from forge.oci_shapes import resolve_shape_compatibility
    config = OciConfig(import_options={"shape_compatibility": [
        {"shape": "VM.Standard.E5.Flex", "min_ocpus": 2, "max_ocpus": 6, "max_memory_gbs": 128}]})
    source = qcow(tmp_path / "source.qcow2")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "image.oci"
    inspection = deepcopy(INSPECTION)
    inspection["os"]["arch"] = "x86_64"
    resolution = resolve_shape_compatibility(inspection, config)
    receipt = subject.write_archive(output, source, config, inspection, lambda _: None, shape_resolution=resolution)
    files = bundle_files(config, {"format": "oci", "shape_compatibility_resolution": resolution})
    public = json.loads(files["shape-compatibility.json"])["entries"]
    with tarfile.open(output) as archive:
        assert archive.getnames() == ["image_metadata.json", "output.QCOW2"]
        embedded = json.load(archive.extractfile("image_metadata.json"))["additionalMetadata"]["shapeCompatibilities"]
    assert embedded == [{"internalShapeName": row["shapeName"], "ocpuConstraints": row["ocpuConstraints"], "memoryConstraints": row["memoryConstraints"]} for row in public]
    assert receipt["shape_compatibility"]["embedded_shapes"] == [row["shapeName"] for row in public]
    assert receipt["shape_compatibility"]["companion_only_shapes"] == []
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest


def test_unknown_os_needs_explicit_labels():
    with pytest.raises(subject.OciArchiveError, match="operating system"):
        subject.image_metadata(OciConfig(), {})
    config = OciConfig(import_options={"operating_system": "Example Linux", "operating_system_version": "1"})
    assert subject.image_metadata(config, {})["operatingSystem"] == "Example Linux"


def test_metadata_bound_matches_existing_oci_importer():
    assert subject.MAX_METADATA_BYTES == 1024 * 1024
    with pytest.raises(subject.OciArchiveError, match="metadata size"):
        subject._json_bytes({"oversized": "x" * subject.MAX_METADATA_BYTES})


def test_validated_config_missing_launch_capability_fails_clearly():
    config = OciConfig(global_schema={"Compute.FutureFlag": {"descriptorType": "boolean", "defaultValue": False}})
    with pytest.raises(subject.OciArchiveError, match="missing capabilities"):
        subject.image_metadata(config, INSPECTION)


@pytest.mark.parametrize("embedded", [False, True])
def test_shape_enforcement_is_independent_of_embedded_capabilities(tmp_path, embedded):
    config = OciConfig(image_caps_format_version=FORMAT_UUID if embedded else None,
                       import_options={"shape_compatibility": [{"shape": "VM.Standard.A2.Flex"}]})
    _, _, result = package(tmp_path, config)
    assert any("shape" in text for text in result["warnings"])
    assert any("null" in text for text in result["warnings"]) is not embedded
    assert result["capability_mode"] == ("embedded" if embedded else "deferred")
    assert result["metadata"]["additionalMetadata"]["shapeCompatibilities"] == [
        {"internalShapeName": "VM.Standard.A2.Flex", "ocpuConstraints": None, "memoryConstraints": None}]


@pytest.mark.parametrize("version", [2, 3])
def test_plain_two_member_archive_exact_readback_hashes_and_private_mode(tmp_path, version):
    source, destination, result = package(tmp_path, version=version)
    source_bytes = source.read_bytes()
    assert result["verified"] and result["format"] == "oci"
    assert destination.stat().st_mode & 0o777 == 0o600
    assert result["disk_size"] == len(source_bytes)
    assert result["disk_sha256"] == hashlib.sha256(source_bytes).hexdigest()
    assert result["archive_size"] == destination.stat().st_size
    assert result["archive_sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert destination.read_bytes()[257:263] == b"ustar\0"
    with tarfile.open(destination, "r:") as archive:
        assert archive.getnames() == ["image_metadata.json", "output.QCOW2"]
        for member in archive:
            assert member.type == tarfile.REGTYPE and not member.pax_headers
        assert archive.extractfile("output.QCOW2").read() == source_bytes
        metadata_bytes = archive.extractfile("image_metadata.json").read()
        assert json.loads(metadata_bytes) == result["metadata"]
        assert hashlib.sha256(metadata_bytes).hexdigest() == result["metadata_sha256"]
    assert not list(tmp_path.glob(".*.tmp"))


def test_large_member_uses_gnu_size_without_pax_or_longname_member():
    size = 8 * 1024**3
    assert subject._tar_format(size - 1) == tarfile.USTAR_FORMAT
    assert subject._tar_format(size) == tarfile.GNU_FORMAT
    header = subject._member(subject.DISK_NAME, size).tobuf(format=subject._tar_format(size))
    assert len(header) == 512 and header[156:157] == tarfile.REGTYPE
    assert header[124] & 0x80
    decoded = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
    assert decoded.name == subject.DISK_NAME and decoded.size == size


@pytest.mark.parametrize("kind", ["file", "symlink", "dangling", "source"])
def test_existing_destination_is_never_overwritten(tmp_path, kind):
    source = qcow(tmp_path / "source")
    before = source.read_bytes()
    destination = tmp_path / "archive.oci"
    if kind == "source":
        destination = source
    elif kind == "file":
        destination.write_bytes(b"keep")
    else:
        destination.symlink_to(source if kind == "symlink" else tmp_path / "absent")
    with pytest.raises(FileExistsError):
        subject.write_archive(destination, source, OciConfig(), INSPECTION, lambda _: None)
    assert source.read_bytes() == before
    if kind == "file":
        assert destination.read_bytes() == b"keep"
    assert not list(tmp_path.glob(".*.tmp"))


def test_source_symlink_and_nonregular_source_rejected(tmp_path):
    source = qcow(tmp_path / "source")
    alias = tmp_path / "alias"
    alias.symlink_to(source)
    with pytest.raises(OSError):
        subject.write_archive(tmp_path / "image.oci", alias, OciConfig(), INSPECTION, lambda _: None)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(subject.OciArchiveError, match="regular"):
        subject.write_archive(tmp_path / "image.oci", fifo, OciConfig(), INSPECTION, lambda _: None)
    assert not (tmp_path / "image.oci").exists()


@pytest.mark.parametrize("offset,fmt,value,match", [(0, ">I", 0, "standalone"), (4, ">I", 1, "Unsupported"),
    (8, ">Q", 200, "backing"), (16, ">I", 10, "backing"), (32, ">I", 2, "encryption"),
    (72, ">Q", 1, "dirty"), (72, ">Q", 4, "external"), (72, ">Q", 8, "non-zlib")])
def test_nonstandalone_or_unsupported_qcow_header_rejected(tmp_path, offset, fmt, value, match):
    source = qcow(tmp_path / "source")
    content = bytearray(source.read_bytes())
    struct.pack_into(fmt, content, offset, value)
    source.write_bytes(content)
    with pytest.raises(subject.OciArchiveError, match=match):
        subject.write_archive(tmp_path / "image.oci", source, OciConfig(), INSPECTION, lambda _: None)
    assert source.read_bytes() == content and not (tmp_path / "image.oci").exists()


def test_insufficient_workspace_fails_before_any_output(tmp_path, monkeypatch):
    source = qcow(tmp_path / "source")
    monkeypatch.setattr(subject.shutil, "disk_usage", lambda _: SimpleNamespace(free=subject.WORKSPACE_RESERVE))
    with pytest.raises(subject.OciArchiveError, match="workspace"):
        subject.write_archive(tmp_path / "image.oci", source, OciConfig(), INSPECTION, lambda _: None)
    assert list(tmp_path.iterdir()) == [source]


def test_input_mutation_is_detected_and_no_output_published(tmp_path):
    source = qcow(tmp_path / "source")
    destination = tmp_path / "image.oci"

    def mutate(message):
        if message.startswith("Verifying"):
            with source.open("r+b") as handle:
                handle.seek(-1, 2)
                handle.write(b"x")

    with pytest.raises(subject.OciArchiveError, match="source changed"):
        subject.write_archive(destination, source, OciConfig(), INSPECTION, mutate)
    assert not destination.exists() and not list(tmp_path.glob(".*.tmp"))


def test_destination_race_keeps_other_writer_output(tmp_path):
    source = qcow(tmp_path / "source")
    destination = tmp_path / "image.oci"

    def race(message):
        if message.startswith("Verifying"):
            destination.write_bytes(b"another writer")

    with pytest.raises(FileExistsError):
        subject.write_archive(destination, source, OciConfig(), INSPECTION, race)
    assert destination.read_bytes() == b"another writer" and not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("failure", [OSError("write failed"), KeyboardInterrupt()])
def test_write_or_cancellation_failure_removes_owned_temporary_only(tmp_path, monkeypatch, failure):
    source = qcow(tmp_path / "source")
    before = source.read_bytes()

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(tarfile.TarFile, "addfile", fail)
    with pytest.raises(type(failure)):
        subject.write_archive(tmp_path / "image.oci", source, OciConfig(), INSPECTION, lambda _: None)
    assert list(tmp_path.iterdir()) == [source] and source.read_bytes() == before


@pytest.mark.parametrize("target", ["metadata", "disk", "tail", "extra", "truncated"])
def test_readback_tamper_rejects_and_cleans_up(tmp_path, monkeypatch, target):
    source = qcow(tmp_path / "source")
    original = subject._verify_archive

    def corrupt(output, metadata, size, digest):
        if target == "metadata":
            output.seek(512)
        elif target == "disk":
            output.seek(1024 + subject._padded(len(metadata)) + 110)
        elif target == "tail":
            output.seek(-1, 2)
        elif target == "truncated":
            output.truncate(512)
            output.seek(0)
        else:
            output.seek(0, 2)
        output.write(b"x")
        output.flush()
        return original(output, metadata, size, digest)

    monkeypatch.setattr(subject, "_verify_archive", corrupt)
    with pytest.raises(subject.OciArchiveError):
        subject.write_archive(tmp_path / "image.oci", source, OciConfig(), INSPECTION, lambda _: None)
    assert list(tmp_path.iterdir()) == [source]


def test_readback_rejects_extra_member_and_pax_headers():
    metadata, disk = b"{}", b"data"
    for extra, pax in [(True, False), (False, True)]:
        file = io.BytesIO()
        with tarfile.open(fileobj=file, mode="w", format=tarfile.PAX_FORMAT if pax else tarfile.USTAR_FORMAT) as archive:
            item = subject._member(subject.METADATA_NAME, len(metadata))
            if pax:
                item.pax_headers = {"comment": "extra metadata"}
            archive.addfile(item, io.BytesIO(metadata))
            archive.addfile(subject._member(subject.DISK_NAME, len(disk)), io.BytesIO(disk))
            if extra:
                archive.addfile(subject._member("extra", 0), io.BytesIO())
        with pytest.raises(subject.OciArchiveError):
            subject._verify_archive(file, metadata, len(disk), hashlib.sha256(disk).hexdigest())
