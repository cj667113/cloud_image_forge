"""Bounded, data-only reader for newc initramfs plus gzip/zstd members.

Used when older libguestfs cannot decode an early microcode CPIO followed by a
compressed main CPIO. Nothing is extracted or executed. Unsupported structures
remain unknown to the caller rather than being treated as missing drivers.
"""
from __future__ import annotations

from contextlib import closing
from collections import OrderedDict
import ctypes
import ctypes.util
from functools import lru_cache
import hashlib
import posixpath
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
import zlib


MAX_INPUT = 256 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_NAMES = 16 * 1024 * 1024
MAX_TEXT = 256 * 1024
MAX_RETAINED = 16 * 1024 * 1024
MAX_ARCHIVES = 8
MAX_SECONDS = 60
CHUNK = 64 * 1024
MAX_ZSTD_WINDOW_LOG = 27  # 128 MiB; the stable libzstd streaming allocation cap.
MAX_CACHE_ARCHIVES = 2


class ArchiveError(ValueError):
    pass


class _ZstdBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("size", ctypes.c_size_t), ("pos", ctypes.c_size_t)]


@lru_cache(maxsize=1)
def _zstd_library():
    """Only stable public libzstd APIs; no subprocess or guest executable."""
    try:
        name = ctypes.util.find_library("zstd")
        if not name:
            raise OSError("not installed")
        library = ctypes.CDLL(name)
        signatures = {
            "ZSTD_createDStream": ([], ctypes.c_void_p),
            "ZSTD_freeDStream": ([ctypes.c_void_p], ctypes.c_size_t),
            "ZSTD_initDStream": ([ctypes.c_void_p], ctypes.c_size_t),
            "ZSTD_DCtx_setParameter": ([ctypes.c_void_p, ctypes.c_int, ctypes.c_int], ctypes.c_size_t),
            "ZSTD_decompressStream": ([ctypes.c_void_p, ctypes.POINTER(_ZstdBuffer), ctypes.POINTER(_ZstdBuffer)], ctypes.c_size_t),
            "ZSTD_isError": ([ctypes.c_size_t], ctypes.c_uint),
        }
        for name, (arguments, returns) in signatures.items():
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, returns
        return library
    except (OSError, AttributeError) as exc:
        raise ArchiveError("Zstd initramfs inspection needs a worker with libzstd 1.4 or newer") from exc


class _ZstdDecoder:
    """zlib-like bounded adapter with exact consumed-input/frame accounting."""
    def __init__(self):
        self.library = _zstd_library()
        self.context = self.library.ZSTD_createDStream()
        self.eof = False
        self.unconsumed_tail = self.unused_data = b""
        if not self.context:
            raise ArchiveError("Cannot allocate the bounded zstd decoder")
        if self.library.ZSTD_isError(self.library.ZSTD_initDStream(self.context)):
            self.close()
            raise ArchiveError("Cannot initialize the bounded zstd decoder")
        # ZSTD_d_windowLogMax=100 is a stable public enum, not experimental API.
        if self.library.ZSTD_isError(self.library.ZSTD_DCtx_setParameter(self.context, 100, MAX_ZSTD_WINDOW_LOG)):
            self.close()
            raise ArchiveError("Cannot enforce the zstd streaming window limit")

    def close(self):
        if self.context:
            self.library.ZSTD_freeDStream(self.context)
            self.context = None

    def decompress(self, data, limit):
        if not self.context or not 0 < limit <= CHUNK or len(data) > CHUNK:
            raise ArchiveError("Invalid bounded zstd decoder request")
        source = ctypes.create_string_buffer(data)
        destination = ctypes.create_string_buffer(limit)
        incoming = _ZstdBuffer(ctypes.addressof(source), len(data), 0)
        outgoing = _ZstdBuffer(ctypes.addressof(destination), limit, 0)
        remaining = self.library.ZSTD_decompressStream(self.context, ctypes.byref(outgoing), ctypes.byref(incoming))
        if self.library.ZSTD_isError(remaining):
            raise ArchiveError("Invalid zstd initramfs stream or window exceeds the 128 MiB limit")
        if incoming.pos > len(data) or outgoing.pos > limit:
            raise ArchiveError("Zstd decoder exceeded its buffer bounds")
        self.eof = remaining == 0
        self.unconsumed_tail = data[incoming.pos:] if not self.eof else b""
        self.unused_data = data[incoming.pos:] if self.eof else b""
        return destination.raw[:outgoing.pos]


def _wanted(name):
    from .iscsi_network import retained
    return (retained(name) or name in {"usr/lib/dracut/modules.txt", "lib/dracut/modules.txt", "usr/sbin/iscsiroot", "sbin/iscsiroot", "etc/cmdline", "etc/fstab", "etc/lvm/lvm.conf", "etc/lvm/lvmlocal.conf"}
            or bool(re.fullmatch(r"etc/cmdline\.d/[^/]+\.conf", name))
            or bool(re.fullmatch(r"etc/lvm/devices/[^/]+", name))
            or bool(re.fullmatch(r"(?:(?:usr|var)/)?lib/dracut/hooks/cmdline/[0-9]+-parse-iscsiroot\.sh", name)))


class Archive:
    def __init__(self, path):
        self.path = path
        self.members = []
        self.texts = {}
        self.sha256 = None
        self.formats = []
        self.kinds = {}
        self.links = {}

    def _regular_target(self, name):
        seen = set()
        def safe_ancestors(value):
            return all(self.kinds.get(str(parent), stat.S_IFDIR) == stat.S_IFDIR for parent in PurePosixPath(value).parents)
        if not safe_ancestors(name):
            return None
        while self.kinds.get(name) == stat.S_IFLNK:
            if name in seen or len(seen) >= 16 or name not in self.links:
                return None
            seen.add(name)
            target = self.links[name]
            name = posixpath.normpath(target.lstrip("/") if target.startswith("/") else posixpath.join(posixpath.dirname(name), target))
            if name.startswith("../") or name == "..":
                return None
            if not safe_ancestors(name):
                return None
        return name if self.kinds.get(name) == stat.S_IFREG else None

    def initrd_list(self, path):
        if path != self.path:
            raise RuntimeError("Archive path does not match the inspected initramfs.")
        # Presence proof applies only to real files or links resolved within
        # this archive, never a directory/device merely named like a driver.
        return [name for name in self.members if self._regular_target(name) is not None]

    def initrd_cat(self, path, name):
        if path != self.path:
            raise RuntimeError("Archive path does not match the inspected initramfs.")
        target = self._regular_target(name)
        if target not in self.texts:
            raise RuntimeError("Required archive text is missing, too large, or not a regular file: " + name)
        return self.texts[target]


class _Reader:
    def __init__(self, file, compressed, budget):
        self.file, self.compressed, self.budget = file, compressed, budget
        self.decoder = (_ZstdDecoder() if compressed == "zstd" else
                        zlib.decompressobj(16 + zlib.MAX_WBITS) if compressed else None)
        self.pending = b""
        self.eof = False
        self.offset = 0

    def close(self):
        if isinstance(self.decoder, _ZstdDecoder):
            self.decoder.close()

    def read(self, count):
        if count < 0 or count > CHUNK:
            raise ArchiveError("Unbounded archive read requested.")
        self._check()
        if not self.compressed:
            value = self.file.read(count)
        else:
            pieces, length = [], 0
            while length < count and not self.eof:
                data = self.pending or self.file.read(CHUNK)
                try:
                    chunk = self.decoder.decompress(data, count - length)
                except zlib.error as exc:
                    raise ArchiveError("Invalid gzip initramfs stream.") from exc
                if not data and not chunk and not self.decoder.eof:
                    raise ArchiveError("Truncated compressed initramfs stream.")
                self.pending = self.decoder.unconsumed_tail
                pieces.append(chunk)
                length += len(chunk)
                self._check()
                if self.decoder.eof:
                    # Restore unused compressed input so the outer parser can
                    # validate padding/another archive instead of ignoring it.
                    unused = self.decoder.unused_data
                    if unused:
                        self.file.seek(-len(unused), 1)
                    self.pending = b""
                    self.eof = True
            value = b"".join(pieces)
        self.offset += len(value)
        self.budget[0] += len(value)
        self._check()
        return value

    def _check(self):
        if self.budget[0] > MAX_EXPANDED:
            raise ArchiveError("Expanded initramfs exceeds the 1 GiB inspection limit.")
        if time.monotonic() > self.budget[1]:
            raise ArchiveError("Initramfs decoding exceeded the inspection time limit.")

    def exact(self, count):
        parts = []
        while count:
            value = self.read(min(count, CHUNK))
            if not value:
                raise ArchiveError("Truncated CPIO header, name or body.")
            parts.append(value)
            count -= len(value)
        return b"".join(parts)

    def discard(self, count, *, zeros=False):
        while count:
            value = self.read(min(count, CHUNK))
            if not value:
                raise ArchiveError("Truncated CPIO body or padding.")
            if zeros and any(value):
                raise ArchiveError("Nonzero CPIO padding is unsupported.")
            count -= len(value)


def parse_file(file, path="initramfs"):
    """Decode every archive in order, retaining only small evidence files."""
    archive = Archive(path)
    file.seek(0, 2)
    if file.tell() > MAX_INPUT:
        raise ArchiveError("Compressed initramfs exceeds the 256 MiB inspection limit.")
    file.seek(0)
    budget = [0, time.monotonic() + MAX_SECONDS]
    seen, hardlinks, pending_text, link_groups, link_digests = {}, {}, {}, {}, {}
    def remember_link(key, digest):
        if key in link_digests and link_digests[key] != digest:
            raise ArchiveError("Conflicting CPIO hardlink contents.")
        link_digests[key] = digest
    entries, names_size, retained, archives = 0, 0, 0, 0
    while True:
        # Linux permits NUL padding between concatenated CPIO/compressed archives.
        while True:
            prefix = file.read(1)
            if prefix != b"\0":
                break
            if time.monotonic() > budget[1]:
                raise ArchiveError("Initramfs decoding exceeded the inspection time limit.")
        if not prefix:
            break
        file.seek(-1, 1)
        magic = file.read(6)
        file.seek(-len(magic), 1)
        compressed = ("gzip" if magic.startswith(b"\x1f\x8b") else
                      "zstd" if magic.startswith(b"\x28\xb5\x2f\xfd") else None)
        if not compressed and magic != b"070701":
            raise ArchiveError("Unsupported initramfs format; this reader accepts newc CPIO, gzip and zstd only.")
        if (compressed or "newc") not in archive.formats:
            archive.formats.append(compressed or "newc")
        archives += 1
        if archives > MAX_ARCHIVES:
            raise ArchiveError("Too many concatenated initramfs archives.")
        with closing(_Reader(file, compressed, budget)) as reader:
            trailer = False
            while not trailer:
                header = reader.exact(110)
                if header[:6] != b"070701" or not re.fullmatch(rb"[0-9a-fA-F]{104}", header[6:]):
                    raise ArchiveError("Malformed or unsupported CPIO header.")
                fields = [int(header[pos:pos + 8], 16) for pos in range(6, 110, 8)]
                ino, mode, _, _, links, _, size, devmajor, devminor, _, _, name_size, checksum = fields
                if not 1 <= name_size <= 4096 or checksum != 0:
                    raise ArchiveError("Invalid CPIO name/checksum fields.")
                name_raw = reader.exact(name_size)
                if name_raw[-1:] != b"\0" or b"\0" in name_raw[:-1]:
                    raise ArchiveError("Malformed CPIO member name.")
                try:
                    name = name_raw[:-1].decode("utf-8")
                except UnicodeError as exc:
                    raise ArchiveError("Unsupported CPIO filename encoding.") from exc
                while name.startswith("./"):
                    name = name[2:]
                if not name or name.startswith("/") or ".." in PurePosixPath(name).parts or any(c in name for c in "\r\n"):
                    raise ArchiveError("Unsafe or ambiguous CPIO member name.")
                if str(PurePosixPath(name)) != name:
                    raise ArchiveError("Noncanonical CPIO path is ambiguous.")
                reader.discard((-reader.offset) % 4, zeros=True)
                if name == "TRAILER!!!":
                    if size:
                        raise ArchiveError("CPIO trailer contains data.")
                    trailer = True
                    continue
                entries += 1
                names_size += len(name_raw)
                if entries > MAX_ENTRIES or names_size > MAX_NAMES:
                    raise ArchiveError("CPIO member/name inventory exceeds the inspection limit.")
                kind = stat.S_IFMT(mode)
                if name in seen and not (kind == seen[name] == stat.S_IFDIR):
                    raise ArchiveError("Duplicate CPIO file makes the resulting contents ambiguous: " + name)
                if name not in seen:
                    archive.members.append(name)
                    seen[name] = kind
                    archive.kinds[name] = kind
                key = (archives, devmajor, devminor, ino)
                if links > 1 and kind == stat.S_IFREG:
                    group = (mode, links)
                    if key in link_groups and link_groups[key] != group:
                        raise ArchiveError("Inconsistent CPIO hardlink group.")
                    link_groups[key] = group
                save = kind == stat.S_IFREG and size <= MAX_TEXT and (_wanted(name) or links > 1)
                if save:
                    if retained + size > MAX_RETAINED:
                        raise ArchiveError("Retained archive evidence exceeds the 16 MiB inspection limit.")
                    data = reader.exact(size)
                    retained += size
                    if links > 1 and size:
                        remember_link(key, hashlib.sha256(data).digest())
                        hardlinks[key] = data
                    if _wanted(name):
                        if links > 1 and not size:
                            pending_text[name] = key
                        else:
                            archive.texts[name] = data
                elif kind == stat.S_IFREG and links > 1 and size:
                    digest, remaining = hashlib.sha256(), size
                    while remaining:
                        value = reader.exact(min(remaining, CHUNK))
                        digest.update(value)
                        remaining -= len(value)
                    remember_link(key, digest.digest())
                elif kind == stat.S_IFLNK and size <= 4096:
                    try:
                        target = reader.exact(size).decode("utf-8")
                    except UnicodeError as exc:
                        raise ArchiveError("Unsupported CPIO symlink encoding.") from exc
                    if "\0" in target or "\n" in target or "\r" in target:
                        raise ArchiveError("Invalid CPIO symlink target.")
                    names_size += size
                    if names_size > MAX_NAMES:
                        raise ArchiveError("CPIO path/link inventory exceeds the inspection limit.")
                    archive.links[name] = target
                else:
                    reader.discard(size)
                reader.discard((-reader.offset) % 4, zeros=True)
            if compressed:
                while True:
                    padding = reader.read(CHUNK)
                    if not padding:
                        break
                    if any(padding):
                        raise ArchiveError("Unexpected nonzero data after compressed CPIO trailer.")
    if not archives:
        raise ArchiveError("Empty initramfs image.")
    for name, key in pending_text.items():
        if key in hardlinks:
            archive.texts[name] = hardlinks[key]
    return archive


def _archive_cache(g):
    cache = getattr(g, "_forge_initramfs_cache", None)
    if not isinstance(cache, OrderedDict):
        cache = OrderedDict()
        try:
            setattr(g, "_forge_initramfs_cache", cache)
        except (AttributeError, TypeError):
            pass
    return cache


def _cache_archive(cache, key, archive):
    # Cache only parsed evidence, never the compressed or expanded full image.
    # Aggregate member, name/link, and retained-text limits match one parse.
    cache[key] = archive
    def oversized():
        return (len(cache) > MAX_CACHE_ARCHIVES
                or sum(len(item.members) for item in cache.values()) > MAX_ENTRIES
                or sum(sum(len(name.encode()) for name in item.members)
                       + sum(len(value.encode()) for value in item.links.values()) for item in cache.values()) > MAX_NAMES
                or sum(sum(len(value) for value in item.texts.values()) for item in cache.values()) > MAX_RETAINED)
    while cache and oversized():
        cache.popitem(last=False)


def read_archive(g, path, expected_sha256=None):
    size = g.filesize(path)
    if not 0 < size <= MAX_INPUT:
        raise ArchiveError("Initramfs file is empty or exceeds the 256 MiB inspection limit.")
    # An actual checksum is re-read even when the caller supplied its earlier
    # observation. This prevents same-size mutation or a stale expected hash
    # from turning the per-handle cache into a proof bypass.
    try:
        observed = g.checksum("sha256", path)
    except (RuntimeError, AttributeError):
        observed = None
    if not isinstance(observed, str) or not re.fullmatch(r"[0-9a-f]{64}", observed):
        observed = None
    if observed and expected_sha256 and observed != expected_sha256:
        raise ArchiveError("Initramfs fingerprint changed during inspection.")
    cache = _archive_cache(g)
    key = (path, size, observed)
    if observed and key in cache:
        cache.move_to_end(key)
        return cache[key]
    with tempfile.TemporaryDirectory(prefix="forge-initramfs-") as directory:
        target = Path(directory) / "initramfs"
        # Download through the already read-only libguestfs appliance. No guest
        # executable, symlink, device or archive member is extracted on the host.
        g.download(path, str(target))
        if target.stat().st_size != size:
            raise ArchiveError("Downloaded initramfs size changed during inspection.")
        with target.open("rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
            if expected_sha256 and digest != expected_sha256 or observed and digest != observed:
                raise ArchiveError("Initramfs fingerprint changed during inspection.")
            file.seek(0)
            archive = parse_file(file, path)
        archive.sha256 = digest
        _cache_archive(cache, (path, size, digest), archive)
        return archive
