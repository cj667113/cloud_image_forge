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
import shutil
import stat
import struct
import tarfile
import tempfile

from .oci import OciConfig, capability_schema


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
    "pvAttachmentVersion": "Storage.ParaVirtualization.AttachmentVersion",
    "pvEncryptionInTransitEnabled": "Storage.ParaVirtualization.EncryptionInTransit",
    "consistentVolumeNamingEnabled": "Storage.ConsistentVolumeNaming",
}


class OciArchiveError(ValueError):
    """An archive cannot be produced or its exact contents cannot be verified."""


def _config(config):
    # Revalidate a private copy, including models modified since construction.
    return OciConfig.model_validate(config.model_dump() if isinstance(config, OciConfig) else config)


def _json_bytes(value):
    result = (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("utf-8")
    if len(result) > MAX_METADATA_BYTES:
        raise OciArchiveError("OCI archive metadata exceeds the bounded metadata size")
    return result


def image_metadata(config, inspection):
    """Derive export metadata without claiming the selected firmware boots.

This also runs before a planned migration. Final inspection and OCI validation
must establish guest compatibility separately, after the migration completes.
"""
    from .destinations import _operating_system

    config = _config(config)
    labels = _operating_system(inspection)
    operating_system = labels.get("operating_system") or config.import_options.operating_system
    version = labels.get("operating_system_version") or config.import_options.operating_system_version
    if not operating_system or not operating_system.strip() or not version or not version.strip():
        raise OciArchiveError("OCI archive needs an inspected operating system and version, or explicit import labels when inspection is unavailable")
    missing = set(LAUNCH_CAPABILITIES.values()) - config.capabilities.keys()
    if missing:
        raise OciArchiveError("OCI archive launch metadata is missing capabilities: " + ", ".join(sorted(missing)))
    launch = {name: config.capabilities[key].default_value for name, key in LAUNCH_CAPABILITIES.items()}
    launch["launchOptionsSource"] = config.import_options.launch_mode
    capabilities = None
    if config.image_caps_format_version:
        descriptors = capability_schema(config)
        for descriptor in descriptors.values():
            descriptor.pop("source", None)  # API-only; absent in version-2 export descriptors.
        capabilities = json.dumps({"capabilities": descriptors}, sort_keys=True, separators=(",", ":"), allow_nan=False)
    result = {"version": 2, "externalLaunchOptions": launch,
              "imageCapabilityData": capabilities,
              "imageCapsFormatVersion": config.image_caps_format_version,
              "operatingSystem": operating_system, "operatingSystemVersion": version}
    _json_bytes(result)
    return result


def _warnings(config):
    result = []
    if not config.image_caps_format_version:
        result.append("No OCI archive capability-format UUID was supplied: imageCapabilityData and imageCapsFormatVersion are null. The archive retains its launch options; apply additional selected capabilities from the companion OCI configuration after import.")
    if config.import_options.shape_compatibility:
        result.append("Selected shape compatibility and shape limits are retained in the companion OCI configuration, not embedded as Oracle internal shape metadata in this archive; apply them after import.")
    return result


def _identity(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


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
    with tarfile.open(fileobj=archive, mode="r|") as contents:
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


def write_archive(destination, qcow2, config, inspection, log):
    """Publish one private .oci file exclusively after streamed verification.

An existing destination is never replaced. Failures remove only this call's
owned temporary/output inode; the input file is opened read-only throughout.
"""
    config = _config(config)
    metadata = image_metadata(config, inspection)
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
                raise OciArchiveError("Insufficient workspace for the OCI archive and reserved free space")
            descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
            temporary = Path(name)
            with os.fdopen(descriptor, "w+b") as output:
                output_stat = os.fstat(output.fileno())
                owned = output_stat.st_dev, output_stat.st_ino
                log("Packaging OCI archive: image_metadata.json and output.QCOW2")
                disk = _HashReader(source)
                with tarfile.open(fileobj=output, mode="w|", format=_tar_format(initial.st_size)) as archive:
                    archive.addfile(_member(METADATA_NAME, len(metadata_bytes)), io.BytesIO(metadata_bytes))
                    archive.addfile(_member(DISK_NAME, initial.st_size), disk)
                if disk.size != initial.st_size:
                    raise OciArchiveError("QCOW2 source length changed while packaging")
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
                           "capability_mode": "embedded" if config.image_caps_format_version else "deferred",
                           "warnings": _warnings(config)}
        return receipt
    except BaseException:
        if published:
            _unlink_owned(destination, owned)
        raise
    finally:
        _unlink_owned(temporary, owned)
