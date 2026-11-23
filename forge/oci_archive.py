"""Create an Oracle version-2 image archive from an already verified QCOW2.

Oracle documents image_metadata.json and output.QCOW2 as the archive members:
https://docs.oracle.com/en/solutions/opc-import-workloads/export1.html
The archive capability-format UUID is independent of the tenancy API schema
version. It must come from an explicit metadata reference, never a guess.

This module packages bytes only. ImageEngine owns disk consistency, guest
readiness and export byte comparison; neither metadata nor packaging proves a
cloud boot. No archive member is extracted or executed.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tarfile
import tempfile

from .architecture import SUPPORTED_ARCHES, normalize_arch
from .oci import (ARM_BARE_METAL_SHAPES, ARM_SHAPES, CNIC_BARE_METAL_SHAPES, PV_ATTACHMENT_VERSION, X86_SHAPES,
                  OciConfig, ShapeCompatibility, capability_schema, cnic_network_error, saved_attachment_error,
                  shape_architecture, shape_config_error)
from .oci_shapes import resolve_shape_compatibility


METADATA_NAME = "image_metadata.json"
DISK_NAME = "output.QCOW2"
CHUNK_SIZE = 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
WORKSPACE_RESERVE = 64 * 1024 * 1024
LAUNCH_CAPABILITIES = {
    "firmware": "Compute.Firmware",
    "networkType": "Network.AttachmentType",
    "bootVolumeType": "Storage.BootVolumeType",
    "remoteDataVolumeType": "Storage.RemoteDataVolumeType",
    "localDataVolumeType": "Storage.LocalDataVolumeType",
    "pvAttachmentVersion": PV_ATTACHMENT_VERSION,
    "pvEncryptionInTransitEnabled": "Storage.ParaVirtualization.EncryptionInTransit",
    "consistentVolumeNamingEnabled": "Storage.ConsistentVolumeNaming",
}
# Identifiers observed in native OCI v2 exports (2026-09-29 and 2026-11-21).
# Bare-metal entries were matched to Oracle's shape specifications by family,
# CPU count, memory and variant. See docs/oci-compatibility.md.
OBSERVED_SHAPE_NAMES = {
    **{name: name for name in (
        "VM.Standard.A1.Flex", "VM.Standard.A2.Flex", "VM.Standard.A4.Flex", "VM.Standard.A4.Ax.Flex",
        "VM.Standard.E4.Flex", "VM.Standard.E5.Flex", "VM.Standard.E6.Flex",
        "VM.Standard3.Flex", "VM.Standard4.Ax.Flex", "VM.Standard.E6.Ax.Flex",
        "VM.DenseIO.E4.Flex", "VM.DenseIO.E5.Flex", "VM.DenseIO.E6.Ax.Flex", "VM.Optimized3.Flex")},
    "BM.Standard.A1.160": "a1-2c.160.1024",
    "BM.Standard.A4.48": "a4-2c.96.768",
    "BM.Standard.A4.Ax.48": "a4-2c.96.768.ax",
    "BM.Standard.E4.128": "e4-2c.128.2048",
    "BM.Standard.E5.192": "e5-2c.192.2304",
    "BM.Standard.E6.256": "e6-2c.256.3072",
    "BM.Standard.E6.Ax.192": "e6-2c.192.1536.ax",
    "BM.Standard3.64": "x9-2c.64.1024",
    "BM.Standard4.Ax.120": "x12-2c.120.1152.ax",
}
# Reject recognizable x86 hardware-family aliases on ARM. This check never
# supplies a mapping or establishes that an alias is valid for a given shape.
X86_INTERNAL_FAMILY = re.compile(r"(?:[ex][0-9]+-2[cl]?|b200)\.", re.IGNORECASE)
# Version-2 capability descriptor format from the supplied Oracle native export.
NATIVE_CAPABILITY_FORMAT = "34dd2cea-aff2-4f45-b8f6-1cb5290bfab2"
ARCHIVE_POLICY_VERSION = 4
SHAPE_REFERENCE_DIR = Path("/etc/cloud-image-forge/oci-shapes")
MAX_REFERENCE_BYTES = 2 * MAX_METADATA_BYTES


class OciArchiveError(ValueError):
    """An archive cannot be produced or its exact contents cannot be verified."""


class ArchiveSpaceError(OciArchiveError):
    """The archive and its free-space reserve exceed the workspace capacity."""


def _config(config):
    # Revalidate a private copy, including models modified since construction.
    return OciConfig.model_validate(config.model_dump() if isinstance(config, OciConfig) else config)


def _json_bytes(value):
    result = (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("utf-8")
    if len(result) > MAX_METADATA_BYTES:
        raise OciArchiveError("OCI archive metadata exceeds the bounded metadata size")
    return result


def shape_entries(config, shape_resolution=None):
    if shape_resolution is not None and (not isinstance(shape_resolution, dict)
                                         or not isinstance(shape_resolution.get("effective_shapes"), list)):
        raise OciArchiveError("The saved OCI shape list is invalid. Create a new export.")
    rows = (shape_resolution["effective_shapes"] if shape_resolution is not None
            else [row.model_dump() for row in config.import_options.shape_compatibility])
    shapes = [ShapeCompatibility.model_validate(row) for row in rows]
    if len(shapes) > 100 or len({row.shape for row in shapes}) != len(shapes):
        raise OciArchiveError("Invalid effective shape compatibility list")
    entries = []
    for row in shapes:
        entries.append({"shapeName": row.shape,
                        "ocpuConstraints": {k: v for k, v in (("min", row.min_ocpus), ("max", row.max_ocpus)) if v is not None} or None,
                        "memoryConstraints": {k: v for k, v in (("minInGBs", row.min_memory_gbs), ("maxInGBs", row.max_memory_gbs)) if v is not None} or None})
    return entries


def _reference_alias(name):
    # The reference directory belongs to the operator. Image uploads, recipes
    # and metadata references in the browser cannot install mappings here.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name):
        raise OciArchiveError("Invalid public OCI shape name.")
    try:
        fd = os.open(SHAPE_REFERENCE_DIR / (name + ".json"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OciArchiveError(f"Cannot read the installed shape reference for {name}.") from exc
    try:
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_REFERENCE_BYTES:
                raise ValueError("Invalid reference file")
            content = stream.read(MAX_REFERENCE_BYTES + 1)
            if len(content) != info.st_size:
                raise ValueError("Shape reference changed")
        reference = json.loads(content)
        metadata = reference["image_metadata"]
        rows = metadata["additionalMetadata"]["shapeCompatibilities"]
        listing = reference["oci_shape_list"]
        public = listing["data"]
        if (type(metadata["version"]) is not int or metadata["version"] != 2
                or not isinstance(rows, list) or len(rows) != 1
                or not isinstance(public, list) or len(public) != 1 or public[0]["shape"] != name
                or listing.get("opc-next-page") or listing.get("opcNextPage")
                or not re.fullmatch(r"ocid1\.image\.[A-Za-z0-9-]{1,32}\.[A-Za-z0-9-]{1,64}\.[A-Za-z0-9_-]{1,160}",
                                    public[0]["image-id"])):
            raise ValueError("Shape reference must identify a single matching shape")
        alias = rows[0]["internalShapeName"]
        if (not isinstance(alias, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", alias)
                or (alias != name and alias.upper().startswith(("VM.", "BM.")))
                or (X86_INTERNAL_FAMILY.match(alias) and shape_architecture(name) != "x86_64")
                or any(other != name and alias.lower() == internal.lower() for other, internal in OBSERVED_SHAPE_NAMES.items())):
            raise ValueError("Invalid or mismatched internal shape name")
    except (KeyError, IndexError, TypeError, ValueError, OSError, RecursionError) as exc:
        raise OciArchiveError(f"The installed shape reference for {name} must pair one OCI v2 archive shape "
                              "with the matching public shape from the same native image.") from exc
    return alias


def shape_metadata(config, shape_resolution, arch, *, allow_missing_arch=False, platform_migration=None):
    entries = shape_entries(config, shape_resolution)
    names = {entry["shapeName"] for entry in entries}
    selected = {entry["shapeName"]: entry for entry in shape_entries(config)}
    arch = normalize_arch(arch)
    if not selected.keys() <= names:
        raise OciArchiveError("The saved OCI shape list is missing a selected shape. Create a new export.")
    if any(entry["shapeName"] in selected and entry != selected[entry["shapeName"]] for entry in entries):
        raise OciArchiveError("The saved OCI shape limits differ from the selected limits. Create a new export.")
    if names != selected.keys():
        if not selected or config.import_options.shape_compatibility_mode == "manual":
            raise OciArchiveError("The saved OCI shape list includes an unselected shape. Create a new export.")
        # With no saved ISA, read_export_os supplies it before publication.
        if arch != "unknown" or not allow_missing_arch:
            allowed = resolve_shape_compatibility({"os": {"arch": arch}}, config, platform_migration)
            permitted = {entry["shapeName"]: entry for entry in shape_entries(config, allowed)}
            if any(permitted.get(entry["shapeName"]) != entry for entry in entries):
                raise OciArchiveError("The saved OCI shape list includes an unselected shape or different limits. Create a new export.")
    if entries and arch not in SUPPORTED_ARCHES and not (allow_missing_arch and arch == "unknown"):
        raise OciArchiveError("The selected OCI shapes require a verified ARM64 or x86_64 guest architecture.")
    shape_arches = set()
    for name in sorted(names):
        required = shape_architecture(name)
        if required is None:
            raise OciArchiveError(f"The CPU architecture of {name} is unknown. Use QCOW2 or select a verified shape.")
        if arch in SUPPORTED_ARCHES and arch != required:
            raise OciArchiveError(f"{name} requires {required}. The exported image is {arch}.")
        shape_arches.add(required)
    if len(shape_arches) > 1:
        raise OciArchiveError("The selected OCI shapes span both ARM64 and x86_64. Choose one guest architecture.")
    shape_error = shape_config_error(names, config)
    if shape_error:
        raise OciArchiveError(shape_error)
    aliases = {name: _reference_alias(name) or OBSERVED_SHAPE_NAMES.get(name) for name in sorted(names)}
    unmapped = [name for name, alias in aliases.items() if not alias]
    if unmapped:
        raise OciArchiveError("No verified OCI archive mapping for " + ", ".join(unmapped) +
                              ". Use QCOW2 with the OCI configuration, or install a native shape reference.")
    if len({alias.lower() for alias in aliases.values()}) != len(aliases):
        raise OciArchiveError("Two selected OCI shapes resolve to the same archive name. Check the installed shape references.")
    embedded = [{"internalShapeName": aliases[row["shapeName"]],
                 "ocpuConstraints": row["ocpuConstraints"], "memoryConstraints": row["memoryConstraints"]}
                for row in entries]
    return {"entries": embedded, "embedded_shapes": [row["shapeName"] for row in entries],
            "companion_only_shapes": [], "public_name_shapes": [],
            "mapping_basis": "OCI native export identifiers or installed per-shape references"}


def image_metadata(config, inspection, *, shape_resolution=None):
    """Derive export metadata without claiming the selected firmware boots.

This also runs before a planned migration. Final inspection and OCI validation
must establish guest compatibility separately, after the migration completes.
"""
    config = _config(config)
    if shape_resolution is None:
        shape_resolution = resolve_shape_compatibility(inspection, config)
    shapes = shape_metadata(config, shape_resolution, (inspection.get("os") or {}).get("arch"))
    return _image_metadata(config, inspection, shapes)


def _image_metadata(config, inspection, shapes):
    from .destinations import _operating_system

    labels = _operating_system(inspection)
    operating_system = labels.get("operating_system") or config.import_options.operating_system
    version = labels.get("operating_system_version") or config.import_options.operating_system_version
    if not operating_system or not operating_system.strip() or not version or not version.strip():
        raise OciArchiveError("OCI archive needs an inspected operating system and version, or explicit import labels when inspection is unavailable")
    missing = set(LAUNCH_CAPABILITIES.values()) - config.capabilities.keys()
    if missing:
        raise OciArchiveError("OCI archive launch metadata is missing capabilities: " + ", ".join(sorted(missing)))
    launch = {name: config.capabilities[key].default_value for name, key in LAUNCH_CAPABILITIES.items()}
    if not ARM_BARE_METAL_SHAPES.isdisjoint(shapes["embedded_shapes"]):
        # The resolved launch option and the image capability preference are
        # independent fields in native archives. Keep the user's allowed set.
        launch["pvAttachmentVersion"] = 1
    launch["launchOptionsSource"] = config.import_options.launch_mode
    capabilities = None
    format_version = config.image_caps_format_version
    if not format_version and any(name.startswith("BM.") for name in shapes["embedded_shapes"]):
        format_version = NATIVE_CAPABILITY_FORMAT
    if format_version:
        descriptors = capability_schema(config)
        for descriptor in descriptors.values():
            descriptor.pop("source", None)  # API-only; absent in version-2 export descriptors.
        capabilities = json.dumps({"capabilities": descriptors}, sort_keys=True, separators=(",", ":"), allow_nan=False)
    result = {"version": 2, "externalLaunchOptions": launch,
              "imageCapabilityData": capabilities,
              "imageCapsFormatVersion": format_version,
              "operatingSystem": operating_system, "operatingSystemVersion": version}
    if shapes["entries"]:
        result["additionalMetadata"] = {"shapeCompatibilities": shapes["entries"]}
    _json_bytes(result)
    return result


def _warnings(metadata, shapes):
    result = []
    if not metadata["imageCapsFormatVersion"]:
        result.append("No OCI archive capability-format UUID was supplied: imageCapabilityData and imageCapsFormatVersion are null. The archive retains its launch options; apply additional selected capabilities from the companion OCI configuration after import.")
    if shapes["embedded_shapes"]:
        result.append("Run the companion apply-oci.py command after import to verify the selected shapes and limits in OCI.")
    return result


def _identity(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def shape_reference_revision():
    """Include installed reference changes in the conditional artifact inventory."""
    if not SHAPE_REFERENCE_DIR.is_dir():
        return "default"
    digest = hashlib.sha256()
    for name in sorted(ARM_SHAPES | X86_SHAPES):
        try:
            identity = _identity((SHAPE_REFERENCE_DIR / (name + ".json")).lstat())
        except FileNotFoundError:
            continue
        except OSError as exc:
            identity = ("unavailable", exc.errno)
        digest.update(json.dumps([name, identity]).encode())
    return digest.hexdigest()[:16]


def _unchanged(source, path, initial):
    try:
        current = path.lstat()
    except OSError as exc:
        raise OciArchiveError("QCOW2 source changed while packaging") from exc
    if not stat.S_ISREG(current.st_mode) or _identity(current) != _identity(initial) or _identity(os.fstat(source.fileno())) != _identity(initial):
        raise OciArchiveError("QCOW2 source changed while packaging")


def _check_qcow2(source):
    """A bounded standalone/header guard, in addition to engine qemu checks."""
    header = source.read(104)
    if len(header) < 72 or header[:4] != b"QFI\xfb":
        raise OciArchiveError("OCI archive disk must be a standalone QCOW2")
    version = struct.unpack_from(">I", header, 4)[0]
    if version not in (2, 3) or (version == 3 and len(header) < 104):
        raise OciArchiveError("Unsupported or truncated QCOW2 header")
    if struct.unpack_from(">Q", header, 8)[0] or struct.unpack_from(">I", header, 16)[0]:
        raise OciArchiveError("OCI archive disk cannot depend on a backing file")
    if struct.unpack_from(">I", header, 32)[0]:
        raise OciArchiveError("OCI archive disk cannot use QCOW2 encryption")
    if version == 3:
        features = struct.unpack_from(">Q", header, 72)[0]
        if features & ~0x10:  # Extended L2 is self-contained; dirty, external, zstd, unknown are not accepted.
            raise OciArchiveError("OCI archive disk has dirty, corrupt, external-data, non-zlib or unsupported QCOW2 features")
    source.seek(0)


def _padded(size, unit=512):
    return ((size + unit - 1) // unit) * unit


def _archive_size(metadata_size, disk_size):
    return _padded(512 + _padded(metadata_size) + 512 + _padded(disk_size) + 1024, tarfile.RECORDSIZE)


def _tar_format(disk_size):
    # USTAR's 11 octal size digits cannot hold >=8 GiB. GNU's base-256 size
    # encoding needs no PAX/long-name members and preserves the two-file layout.
    return tarfile.USTAR_FORMAT if disk_size < 8 * 1024**3 else tarfile.GNU_FORMAT


class _HashReader:
    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, amount=-1):
        data = self.source.read(amount)
        self.digest.update(data)
        self.size += len(data)
        return data


def _member(name, size):
    item = tarfile.TarInfo(name)
    item.type = tarfile.REGTYPE
    item.size = size
    item.mode = 0o600
    item.uid = item.gid = item.mtime = 0
    item.uname = item.gname = ""
    return item


def _verify_archive(output, metadata, disk_size, disk_sha256):
    """Read back both regular members and all bytes, without extracting files."""
    expected_size = _archive_size(len(metadata), disk_size)
    output.seek(0, os.SEEK_END)
    if output.tell() != expected_size:
        raise OciArchiveError("OCI archive size or trailing data failed verification")
    output.seek(0)
    archive = _HashReader(output)
    expected = [(METADATA_NAME, len(metadata), 0), (DISK_NAME, disk_size, 512 + _padded(len(metadata)))]
    with tarfile.open(fileobj=archive, mode="r|", bufsize=CHUNK_SIZE) as contents:
        for name, size, offset in expected:
            item = contents.next()
            if (item is None or item.name != name or item.size != size or item.type != tarfile.REGTYPE
                    or item.offset != offset or item.offset_data != offset + 512 or item.pax_headers or item.linkname):
                raise OciArchiveError("OCI archive member names, types, offsets or sizes failed verification")
            member = contents.extractfile(item)
            if member is None:
                raise OciArchiveError("OCI archive member could not be read")
            with member:
                if name == METADATA_NAME:
                    if member.read(len(metadata) + 1) != metadata:
                        raise OciArchiveError("OCI archive metadata failed readback verification")
                else:
                    digest, count = hashlib.sha256(), 0
                    while data := member.read(CHUNK_SIZE):
                        digest.update(data)
                        count += len(data)
                    if count != disk_size or digest.hexdigest() != disk_sha256:
                        raise OciArchiveError("OCI archive QCOW2 failed readback hash verification")
        if contents.next() is not None:
            raise OciArchiveError("OCI archive contains an unexpected extra member")
    # tarfile may read ahead but every read passed through the digest wrapper.
    while archive.size < expected_size:
        if not archive.read(min(CHUNK_SIZE, expected_size - archive.size)):
            raise OciArchiveError("OCI archive was truncated during verification")
    output.seek(0, os.SEEK_END)
    if archive.size != expected_size or output.tell() != expected_size:
        raise OciArchiveError("OCI archive size or trailing data failed verification")
    padding_start = expected[1][2] + 512 + disk_size
    output.seek(padding_start)
    # Only disk padding, the two end blocks, and record padding may follow.
    padding_size = expected_size - padding_start
    padding = output.read(padding_size)
    if len(padding) != padding_size or any(padding):
        raise OciArchiveError("OCI archive has nonzero data after its disk member")
    return archive.digest.hexdigest(), archive.size


def _unlink_owned(path, identity):
    if path is None or identity is None:
        return
    try:
        current = path.lstat()
        if (current.st_dev, current.st_ino) == identity:
            path.unlink()
    except FileNotFoundError:
        pass


def write_archive(destination, qcow2, config, inspection, log, *, shape_resolution=None, expected_disk_sha256=None):
    """Publish one private .oci file exclusively after streamed verification.

An existing destination is never replaced. Failures remove only this call's
owned temporary/output inode; the input file is opened read-only throughout.
"""
    config = _config(config)
    if shape_resolution is None:
        shape_resolution = resolve_shape_compatibility(inspection, config)
    shapes = shape_metadata(config, shape_resolution, (inspection.get("os") or {}).get("arch"))
    metadata = _image_metadata(config, inspection, shapes)
    metadata_bytes = _json_bytes(metadata)
    destination, qcow2 = Path(destination), Path(qcow2)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"OCI archive destination already exists: {destination.name}")
    temporary, owned = None, None
    published = False
    try:
        descriptor = os.open(qcow2, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            initial = os.fstat(source.fileno())
            if not stat.S_ISREG(initial.st_mode):
                raise OciArchiveError("OCI archive source must be a regular QCOW2 file")
            _check_qcow2(source)
            size = _archive_size(len(metadata_bytes), initial.st_size)
            if shutil.disk_usage(destination.parent).free < size + WORKSPACE_RESERVE:
                raise ArchiveSpaceError("Insufficient workspace for the OCI archive and reserved free space")
            descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
            temporary = Path(name)
            with os.fdopen(descriptor, "w+b") as output:
                output_stat = os.fstat(output.fileno())
                owned = output_stat.st_dev, output_stat.st_ino
                log("Packaging OCI archive: image_metadata.json and output.QCOW2")
                disk = _HashReader(source)
                with tarfile.open(fileobj=output, mode="w|", format=_tar_format(initial.st_size),
                                  bufsize=CHUNK_SIZE, copybufsize=CHUNK_SIZE) as archive:
                    archive.addfile(_member(METADATA_NAME, len(metadata_bytes)), io.BytesIO(metadata_bytes))
                    archive.addfile(_member(DISK_NAME, initial.st_size), disk)
                if disk.size != initial.st_size:
                    raise OciArchiveError("QCOW2 source length changed while packaging")
                if expected_disk_sha256 is not None and disk.digest.hexdigest() != expected_disk_sha256:
                    raise OciArchiveError("The QCOW2 checksum differs from the published export")
                _unchanged(source, qcow2, initial)
                output.flush()
                os.fsync(output.fileno())
                log("Verifying OCI archive member contents and hashes")
                archive_sha256, archive_size = _verify_archive(output, metadata_bytes, initial.st_size, disk.digest.hexdigest())
                _unchanged(source, qcow2, initial)
                current = temporary.lstat()
                if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != owned:
                    raise OciArchiveError("OCI archive temporary file changed before publication")
                # Hard-link publication is atomic and fails if any destination
                # entry appeared during writing; unlike replace(), it clobbers nothing.
                os.link(temporary, destination, follow_symlinks=False)
                published = True
                _unlink_owned(temporary, owned)
                temporary = None
                receipt = {"verified": True, "format": "oci", "archive_size": archive_size,
                           "archive_sha256": archive_sha256, "disk_size": initial.st_size,
                           "disk_sha256": disk.digest.hexdigest(),
                           "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(), "metadata": metadata,
                           "capability_mode": "embedded" if metadata["imageCapsFormatVersion"] else "deferred",
                           "shape_compatibility": {key: value for key, value in shapes.items() if key != "entries"},
                           "warnings": _warnings(metadata, shapes)}
        return receipt
    except BaseException:
        if published:
            _unlink_owned(destination, owned)
        raise
    finally:
        _unlink_owned(temporary, owned)


def can_download_archive(artifact):
    recipe = artifact.get("recipe") or {}
    return (artifact.get("format") == "qcow2" and artifact.get("target", recipe.get("target")) == "oci"
            and isinstance(recipe.get("oci"), dict)
            and bool(re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256") or "")))


def _stored_shapes(artifact, *, allow_missing_arch=False):
    config = _config(artifact["recipe"]["oci"])
    return shape_metadata(config, artifact.get("shape_compatibility_resolution"), artifact.get("architecture"),
                          allow_missing_arch=allow_missing_arch, platform_migration=artifact["recipe"].get("platform_migration"))


def _check_declared_shapes(metadata, expected):
    additional = metadata.get("additionalMetadata", {}) if isinstance(metadata, dict) else None
    if not isinstance(additional, dict) or additional.get("shapeCompatibilities", []) != expected["entries"]:
        raise OciArchiveError("This older .oci file has a different shape list than the export. Create a new export.")
    names = expected["embedded_shapes"]
    arm_bare_metal = not ARM_BARE_METAL_SHAPES.isdisjoint(names)
    cnic = not CNIC_BARE_METAL_SHAPES.isdisjoint(names)
    if not (arm_bare_metal or cnic):
        return
    try:
        launch = metadata["externalLaunchOptions"]
        caps = json.loads(metadata["imageCapabilityData"])["capabilities"]
        if arm_bare_metal:
            if error := saved_attachment_error(names, caps):
                raise OciArchiveError(error)
            version = launch.get("pvAttachmentVersion") if isinstance(launch, dict) else None
            if type(version) is not int or version != 1:
                raise OciArchiveError("The saved ARM bare-metal launch options must select PV attachment version 1. Create a new export.")
        if not cnic:
            return
        nic = caps["Network.AttachmentType"]
        if not isinstance(nic["values"], list) or "PARAVIRTUALIZED" not in nic["values"]:
            raise OciArchiveError("This .oci file must allow PARAVIRTUALIZED networking for its bare-metal CNIC shapes. Create a new export.")
        for network, boot, mode in (
                (launch["networkType"], launch["bootVolumeType"], launch["launchOptionsSource"]),
                (nic["defaultValue"], caps["Storage.BootVolumeType"]["defaultValue"],
                 caps["Compute.LaunchMode"]["defaultValue"])):
            error = cnic_network_error(names, network, boot, mode)
            if error:
                raise OciArchiveError(error)
    except (KeyError, TypeError, json.JSONDecodeError, RecursionError) as exc:
        raise OciArchiveError("This .oci file is missing bare-metal launch settings. Create a new export.") from exc


def archive_blocker(artifact):
    """Inventory check against the saved recipe, inspection and package receipt (no disk I/O)."""
    native = artifact.get("format") == "oci"
    if not native and not can_download_archive(artifact):
        return None
    if not isinstance((artifact.get("recipe") or {}).get("oci"), dict):
        return "This export has no saved OCI settings to verify its shape list. Create a new export."
    try:
        expected = _stored_shapes(artifact, allow_missing_arch=not native)
        if native:
            metadata = (artifact.get("oci_archive") or {}).get("metadata")
            if expected["entries"] or metadata is not None:
                _check_declared_shapes(metadata, expected)
    except OciArchiveError as exc:
        return str(exc)
    except ValueError:
        return "This export has invalid OCI settings. Create a new export."
    return None


def verify_published_archive(artifact):
    """Check the actual bounded metadata header before serving or uploading a native archive."""
    blocker = archive_blocker(artifact)
    if blocker:
        raise OciArchiveError(blocker)
    with Path(artifact["path"]).open("rb") as stream:
        try:
            first = tarfile.TarInfo.frombuf(stream.read(512), "utf-8", "strict")
            if first.name != METADATA_NAME or first.type != tarfile.REGTYPE or not 0 < first.size <= MAX_METADATA_BYTES:
                raise OciArchiveError("Invalid OCI archive metadata member.")
            metadata = json.loads(stream.read(first.size))
        except (tarfile.TarError, UnicodeError, ValueError) as exc:
            raise OciArchiveError("The published OCI archive metadata cannot be verified. Create a new export.") from exc
    _check_declared_shapes(metadata, _stored_shapes(artifact))


def archive_download(cache_dir, artifact, inspect_os):
    """Materialize a verified, resumable alternate download for one published QCOW2.

    The caller serializes first downloads of this export and holds a download
    claim through the HTTP response. Renaming the export changes its suggested
    filename only, so the packaged disk can continue to serve range requests.
    """
    source = Path(artifact["path"])
    original = source.lstat()
    if not stat.S_ISREG(original.st_mode) or original.st_size != artifact["size"]:
        raise OciArchiveError("The published QCOW2 file type or size has changed")
    config = _config(artifact["recipe"]["oci"])
    labels = artifact.get("oci_archive_os") or {}
    resolution = artifact.get("shape_compatibility_resolution")
    if resolution is None:
        # Earlier companions emitted only the public shapes saved in the recipe.
        resolution = {"effective_shapes": [row.model_dump() for row in config.import_options.shape_compatibility]}
    arch = normalize_arch(artifact.get("architecture"))
    expected = shape_metadata(config, resolution, arch, allow_missing_arch=True,
                              platform_migration=artifact["recipe"].get("platform_migration"))["entries"]
    inputs = json.dumps([ARCHIVE_POLICY_VERSION, artifact["sha256"], _identity(original), labels,
                         arch, expected, resolution, config.model_dump()],
                        sort_keys=True, separators=(",", ":")).encode()
    signature = hashlib.sha256(inputs).hexdigest()
    output = cache_dir / "image.oci"
    marker = cache_dir / "verified.json"
    if cache_dir.is_symlink() or cache_dir.parent.is_symlink():
        raise OciArchiveError("The OCI download directory is unavailable")
    try:
        if marker.is_file() and not marker.is_symlink() and marker.stat().st_size < 4096:
            cached = json.loads(marker.read_bytes())
            cached_stat = output.lstat()
            if (stat.S_ISREG(cached_stat.st_mode) and cached == {
                    "inputs": signature, "archive": list(_identity(cached_stat))}):
                return output
    except (FileNotFoundError, ValueError):
        pass
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir(parents=True, mode=0o700)
    try:
        os_keys = ("operating_system", "operating_system_version")
        if (expected and arch == "unknown") or not all(labels.get(k) or getattr(config.import_options, k) for k in os_keys):
            inspected = inspect_os(source)
            if arch == "unknown":
                arch = normalize_arch(inspected.get("architecture"))
                shape_metadata(config, resolution, arch, platform_migration=artifact["recipe"].get("platform_migration"))
            labels = {**{key: inspected[key] for key in os_keys if inspected.get(key)}, **labels}
        config = config.model_copy(update={"import_options": config.import_options.model_copy(update=labels)})
        receipt = write_archive(output, source, config, {"os": {"arch": arch}}, lambda _: None, shape_resolution=resolution,
                                expected_disk_sha256=artifact["sha256"])
        if receipt["metadata"].get("additionalMetadata", {}).get("shapeCompatibilities", []) != expected:
            raise OciArchiveError("The installed shape references changed during packaging. Retry the download.")
        if _identity(original) != _identity(source.lstat()):
            raise OciArchiveError("The QCOW2 changed while preparing the download")
        marker.write_text(json.dumps({"inputs": signature, "archive": _identity(output.lstat())}))
    except BaseException:
        shutil.rmtree(cache_dir)
        raise
    return output
