"""Bounded, data-only reader for newc initramfs plus gzip members.

Used when older libguestfs cannot decode an early microcode CPIO followed by a
compressed main CPIO. Nothing is extracted or executed. Unsupported structures
remain unknown to the caller rather than being treated as missing drivers.
"""
from __future__ import annotations

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


class ArchiveError(ValueError):
    pass


def _wanted(name):
    return (name in {"usr/lib/dracut/modules.txt", "lib/dracut/modules.txt", "usr/sbin/iscsiroot", "sbin/iscsiroot", "etc/cmdline"}
            or bool(re.fullmatch(r"etc/cmdline\.d/[^/]+\.conf", name))
            or bool(re.fullmatch(r"(?:usr/)?lib/dracut/hooks/cmdline/[0-9]+-parse-iscsiroot\.sh", name)))


class Archive:
    def __init__(self, path):
        self.path = path
        self.members = []
        self.texts = {}
        self.sha256 = None
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
        self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if compressed else None
        self.pending = b""
        self.eof = False
        self.offset = 0

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
                if not data:
                    raise ArchiveError("Truncated gzip initramfs stream.")
                try:
                    chunk = self.decoder.decompress(data, count - length)
                except zlib.error as exc:
                    raise ArchiveError("Invalid gzip initramfs stream.") from exc
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
        # Linux permits NUL padding between concatenated CPIO/gzip archives.
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
        compressed = magic.startswith(b"\x1f\x8b")
        if not compressed and magic != b"070701":
            raise ArchiveError("Unsupported initramfs format; this reader accepts newc CPIO and gzip only.")
        archives += 1
        if archives > MAX_ARCHIVES:
            raise ArchiveError("Too many concatenated initramfs archives.")
        reader = _Reader(file, compressed, budget)
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


def read_archive(g, path, expected_sha256=None):
    size = g.filesize(path)
    if not 0 < size <= MAX_INPUT:
        raise ArchiveError("Initramfs file is empty or exceeds the 256 MiB inspection limit.")
    with tempfile.TemporaryDirectory(prefix="forge-initramfs-") as directory:
        target = Path(directory) / "initramfs"
        # Download through the already read-only libguestfs appliance. No guest
        # executable, symlink, device or archive member is extracted on the host.
        g.download(path, str(target))
        if target.stat().st_size != size:
            raise ArchiveError("Downloaded initramfs size changed during inspection.")
        with target.open("rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
            if expected_sha256 and digest != expected_sha256:
                raise ArchiveError("Initramfs fingerprint changed during inspection.")
            file.seek(0)
            archive = parse_file(file, path)
        archive.sha256 = digest
        return archive
