"""Untrusted initramfs data must be decoded with bounds and without extraction."""
import fnmatch
import ctypes
import gzip
import hashlib
import io
from pathlib import Path
import stat
from unittest.mock import patch

import pytest

from forge.initramfs import ArchiveError, _zstd_library, parse_file, read_archive
from forge.platform import _iscsi_archive_ready, inspect_platform
from forge.portability import inspect_archive


def cpio(entries):
    result = bytearray()
    for index, entry in enumerate([*entries, ("TRAILER!!!", b"")], 1):
        name, body, *extra = entry
        mode, ino, links = (extra + [stat.S_IFREG | 0o644, index, 1][len(extra):])
        encoded = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, links, 0, len(body), 0, 0, 0, 0, len(encoded), 0]
        result.extend(b"070701" + b"".join(f"{value:08x}".encode() for value in fields))
        result.extend(encoded)
        result.extend(b"\0" * ((-len(result)) % 4))
        result.extend(body)
        result.extend(b"\0" * ((-len(result)) % 4))
    return bytes(result)


def main_entries():
    hook = b'''echo "${DRACUT_SYSTEMD+systemctl is-active initrd-root-device.target || }[ -f '/tmp/iscsistarted-firmware' ]" > "$hookdir"/initqueue/finished/iscsi_started.sh\n'''
    return [("usr/lib/dracut/modules.txt", b"systemd\ndracut-systemd\niscsi\nnetwork-manager\nlvm\n"),
            ("usr/lib/dracut/hooks/cmdline/90-parse-iscsiroot.sh", hook),
            ("usr/sbin/iscsiroot", b"iscsiadm -m fw\n"),
            ("usr/sbin/iscsiadm", b"binary"), ("usr/sbin/iscsid", b"binary"),
            ("usr/sbin/iscsi-iname", b"binary"), ("usr/sbin/lvm", b"binary"),
            ("usr/lib/systemd/system/initrd-root-device.target", b"[Unit]\n"),
            ("usr/lib/systemd/system/iscsid.service", b"[Unit]\n"),
            ("usr/lib/systemd/system/iscsid.socket", b"[Unit]\n"),
            ("etc/systemd/system/sockets.target.wants/iscsid.socket", b"/usr/lib/systemd/system/iscsid.socket", stat.S_IFLNK | 0o777),
            ("usr/lib/modules/test/kernel/drivers/virtio/virtio_pci.ko.xz", b"module"),
            ("usr/lib/modules/test/kernel/drivers/md/dm-mod.ko.xz", b"module")]


def composed(entries=None):
    early = cpio([("early_cpio", b"1\n"), ("kernel/x86/microcode/AuthenticAMD.bin", b"microcode" * 37)])
    return early + b"\0" * ((-len(early)) % 512) + gzip.compress(cpio(entries or main_entries()))


def zstd_bytes(data):
    try:
        library = _zstd_library()
    except ArchiveError:
        pytest.skip("This host lacks libzstd; the deployment installs libzstd1")
    library.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    library.ZSTD_compressBound.restype = ctypes.c_size_t
    library.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    library.ZSTD_compress.restype = ctypes.c_size_t
    source = ctypes.create_string_buffer(data)
    target = ctypes.create_string_buffer(library.ZSTD_compressBound(len(data)))
    size = library.ZSTD_compress(target, len(target), source, len(data), 3)
    assert not library.ZSTD_isError(size)
    return target.raw[:size]


def test_zstd_main_archive_after_early_cpio_preserves_evidence_and_formats():
    early = cpio([("early_cpio", b"1\n")])
    value = early + b"\0" * ((-len(early)) % 512) + zstd_bytes(cpio(main_entries() + [("etc/fstab", b"UUID=root / ext4 defaults 0 1\n")]))
    parsed = parse_file(io.BytesIO(value))
    assert parsed.formats == ["newc", "zstd"]
    assert parsed.initrd_cat(parsed.path, "etc/fstab").startswith(b"UUID=root")
    assert inspect_archive(parsed, parsed.path)["readable"]


def test_zstd_reader_retains_exact_dracut_var_hook_without_admitting_other_directories():
    hook = "var/lib/dracut/hooks/cmdline/90-parse-iscsiroot.sh"
    body = next(content for name, content, *extra in main_entries() if name.endswith("/90-parse-iscsiroot.sh"))
    other = "opt/lib/dracut/hooks/cmdline/90-parse-iscsiroot.sh"
    entries = [(hook if name.endswith("/90-parse-iscsiroot.sh") else name, content, *extra)
               for name, content, *extra in main_entries()]
    parsed = parse_file(io.BytesIO(zstd_bytes(cpio(entries + [(other, body)]))))
    assert parsed.initrd_cat(parsed.path, hook) == body
    assert other in parsed.initrd_list(parsed.path)
    assert inspect_archive(parsed, parsed.path)["iscsi_local_root_completion"]
    assert _iscsi_archive_ready(parsed, parsed.path, parsed.initrd_list(parsed.path))
    with pytest.raises(RuntimeError, match="Required archive text is missing"):
        parsed.initrd_cat(parsed.path, other)


@pytest.mark.parametrize("suffix", ["newc", "gzip", "zstd"])
def test_zstd_consumed_input_preserves_following_archive_boundaries(suffix):
    following = cpio([("second", b"data")])
    if suffix == "gzip":
        following = gzip.compress(following)
    if suffix == "zstd":
        following = zstd_bytes(following)
    value = zstd_bytes(cpio([("etc/cmdline", b"root=UUID=root")])) + b"\0" * 17 + following
    assert "second" in parse_file(io.BytesIO(value)).initrd_list("initramfs")


def test_zstd_stream_flushes_large_compressible_body_without_unbounded_output():
    value = cpio([("discard", b"A" * (512 * 1024)), ("etc/cmdline", b"root=UUID=root")])
    parsed = parse_file(io.BytesIO(zstd_bytes(value)))
    assert parsed.initrd_cat(parsed.path, "etc/cmdline") == b"root=UUID=root"
    with patch("forge.initramfs.MAX_EXPANDED", 1000), pytest.raises(ArchiveError, match="Expanded"):
        parse_file(io.BytesIO(zstd_bytes(value)))


def test_zstd_window_limit_rejects_frame_before_unbounded_allocation():
    value = zstd_bytes(cpio([("file", b"a" * (256 * 1024))]))
    with patch("forge.initramfs.MAX_ZSTD_WINDOW_LOG", 10), pytest.raises(ArchiveError, match="window"):
        parse_file(io.BytesIO(value))


@pytest.mark.parametrize("kind", ["truncated", "corrupt", "trailing", "duplicate", "hidden"])
def test_zstd_invalid_or_ambiguous_contents_are_not_accepted(kind):
    raw = cpio([("etc/cmdline", b"root=UUID=root")])
    value = zstd_bytes(raw)
    value = {"truncated": value[:-2], "corrupt": b"\x28\xb5\x2f\xfdinvalid",
             "trailing": value + b"junk", "duplicate": value + value,
             "hidden": zstd_bytes(raw + b"hidden")}[kind]
    with pytest.raises(ArchiveError):
        parse_file(io.BytesIO(value))


def test_zstd_context_is_freed_when_cpio_rejected(monkeypatch):
    from forge.initramfs import _ZstdDecoder
    calls, original = [], _ZstdDecoder.close
    def closed(self):
        calls.append(bool(self.context))
        original(self)
        assert self.context is None
    monkeypatch.setattr(_ZstdDecoder, "close", closed)
    with pytest.raises(ArchiveError, match="header"):
        parse_file(io.BytesIO(zstd_bytes(b"not a cpio" * 32)))
    assert calls == [True]


def test_zstd_missing_library_remains_explicitly_unknown(monkeypatch):
    value = zstd_bytes(cpio([]))
    def absent():
        raise ArchiveError("Zstd initramfs inspection needs a worker with libzstd 1.4 or newer")
    monkeypatch.setattr("forge.initramfs._zstd_library", absent)
    with pytest.raises(ArchiveError, match="libzstd"):
        parse_file(io.BytesIO(value))


def test_early_microcode_and_gzip_main_are_merged_and_support_existing_proof():
    archive = parse_file(io.BytesIO(composed()), "/boot/initramfs.img")
    names = archive.initrd_list(archive.path)
    assert "early_cpio" in names
    assert "usr/lib/modules/test/kernel/drivers/md/dm-mod.ko.xz" in names
    evidence = inspect_archive(archive, archive.path, names)
    assert evidence["readable"] and evidence["iscsi_local_root_completion"]
    assert evidence["lvm_userspace"]
    assert _iscsi_archive_ready(archive, archive.path, names)


@pytest.mark.parametrize("compressed", [False, True])
def test_stream_reads_handle_chunk_boundaries(compressed):
    raw = cpio([("large-discarded", bytes(range(256)) * 2000), ("etc/cmdline", b"root=UUID=local")])
    value = gzip.compress(raw) if compressed else raw
    archive = parse_file(io.BytesIO(value))
    assert archive.initrd_cat("initramfs", "etc/cmdline") == b"root=UUID=local"


def test_bounded_reader_retains_fstab_for_mount_identity_verification():
    text = b"UUID=root / ext4 defaults 0 1\n"
    archive = parse_file(io.BytesIO(composed(main_entries() + [("etc/fstab", text)])))
    assert archive.initrd_cat("initramfs", "etc/fstab") == text


@pytest.mark.parametrize("payload", [b"070701", cpio([("file", b"body")])[:-6],
                                      gzip.compress(cpio([("file", b"body")]))[:-5],
                                      b"\xfd7zXZ\x00unsupported", b"070702" + b"0" * 104])
def test_truncated_or_unsupported_inputs_are_unknown(payload):
    with pytest.raises(ArchiveError):
        parse_file(io.BytesIO(payload))


def test_concatenated_compressed_members_are_checked_instead_of_ignored():
    payload = gzip.compress(cpio([("etc/cmdline", b"first")])) + gzip.compress(cpio([("another", b"second")]))
    assert "another" in parse_file(io.BytesIO(payload)).initrd_list("initramfs")
    with pytest.raises(ArchiveError, match="Duplicate"):
        parse_file(io.BytesIO(payload + gzip.compress(cpio([("etc/cmdline", b"changed")]))))
    with pytest.raises(ArchiveError, match="Unsupported"):
        parse_file(io.BytesIO(payload + b"unexpected trailing bytes"))
    with pytest.raises(ArchiveError, match="nonzero"):
        parse_file(io.BytesIO(gzip.compress(cpio([]) + b"hidden payload")))


@pytest.mark.parametrize("name", ["../escape", "/absolute", "usr/../escape", "usr/./file", "usr//file", "bad\nname"])
def test_ambiguous_paths_are_rejected(name):
    with pytest.raises(ArchiveError):
        parse_file(io.BytesIO(cpio([(name, b"data")])))


def test_nonregular_driver_names_do_not_establish_presence_and_links_stay_inside_archive():
    entries = [("real", b"value"), ("safe", b"real", stat.S_IFLNK | 0o777),
               ("outside", b"../../escape", stat.S_IFLNK | 0o777),
               ("fake.ko", b"", stat.S_IFDIR | 0o755),
               ("loop1", b"loop2", stat.S_IFLNK | 0o777), ("loop2", b"loop1", stat.S_IFLNK | 0o777)]
    archive = parse_file(io.BytesIO(cpio(entries)))
    assert archive.initrd_list("initramfs") == ["real", "safe"]
    with pytest.raises(RuntimeError):
        archive.initrd_cat("initramfs", "outside")
    alias = parse_file(io.BytesIO(cpio([("usr/lib/dracut", b"alternate", stat.S_IFLNK | 0o777),
                                       ("usr/lib/dracut/modules.txt", b"systemd\niscsi")])))
    assert "usr/lib/dracut/modules.txt" not in alias.initrd_list("initramfs")
    with pytest.raises(RuntimeError):
        alias.initrd_cat("initramfs", "usr/lib/dracut/modules.txt")


def test_hardlink_text_resolution_and_conflicts():
    entries = [("etc/cmdline", b"", stat.S_IFREG | 0o644, 7, 2),
               ("other", b"root=UUID=local", stat.S_IFREG | 0o644, 7, 2)]
    assert parse_file(io.BytesIO(cpio(entries))).initrd_cat("initramfs", "etc/cmdline") == b"root=UUID=local"
    with pytest.raises(ArchiveError, match="Conflicting"):
        parse_file(io.BytesIO(cpio([("etc/cmdline", b"one", stat.S_IFREG | 0o644, 7, 2),
                                    ("other", b"two", stat.S_IFREG | 0o644, 7, 2)])))
    with pytest.raises(ArchiveError, match="Inconsistent"):
        parse_file(io.BytesIO(cpio([entries[0], ("other", b"text", stat.S_IFREG | 0o755, 7, 2)])))


@pytest.mark.parametrize("constant,limit", [("MAX_INPUT", 12), ("MAX_EXPANDED", 128), ("MAX_ENTRIES", 1),
                                              ("MAX_NAMES", 20), ("MAX_RETAINED", 4), ("MAX_ARCHIVES", 1)])
def test_limits_fail_before_unbounded_retention(constant, limit):
    with patch("forge.initramfs." + constant, limit), pytest.raises(ArchiveError):
        parse_file(io.BytesIO(composed()))


def test_oversized_evidence_file_is_not_returned_as_text():
    with patch("forge.initramfs.MAX_TEXT", 4):
        archive = parse_file(io.BytesIO(cpio([("etc/cmdline", b"longer than text bound")])))
    with pytest.raises(RuntimeError):
        archive.initrd_cat("initramfs", "etc/cmdline")


class Guest:
    def __init__(self, data):
        self.downloads = []
        self.files = {"/boot/initramfs-test.img": data, "/boot/vmlinuz-test": b"kernel",
                      "/etc/fstab": b"UUID=11111111-2222-3333-4444-555555555555 / xfs defaults 0 0\n"}
    def filesize(self, path): return len(self.files[path])
    def is_file(self, path): return path in self.files
    def is_dir(self, path): return any(name.startswith(path.rstrip('/') + '/') for name in self.files)
    def is_symlink(self, path): return False
    def glob_expand(self, pattern): return [path for path in self.files if fnmatch.fnmatch(path, pattern)]
    def read_file(self, path): return self.files[path]
    def lvs(self): return []
    def checksum(self, kind, path): return hashlib.sha256(self.files[path]).hexdigest()
    def initrd_list(self, path): raise RuntimeError("native decoder cannot read early CPIO")
    def download(self, path, target):
        self.downloads.append(Path(target))
        Path(target).write_bytes(self.files[path])


def test_download_happens_once_cleans_temp_file_and_enforces_source_fingerprint():
    guest = Guest(composed())
    path = "/boot/initramfs-test.img"
    archive = read_archive(guest, path, guest.checksum("sha256", path))
    for _ in range(3):
        archive.initrd_list(path)
        archive.initrd_cat(path, "usr/lib/dracut/modules.txt")
    assert len(guest.downloads) == 1
    assert not guest.downloads[0].exists()
    with pytest.raises(ArchiveError, match="fingerprint"):
        read_archive(guest, path, "0" * 64)
    assert not guest.downloads[-1].exists()


def test_checksum_keyed_cache_reuses_only_unchanged_archive_evidence():
    path = "/boot/initramfs-test.img"
    guest = Guest(cpio([("etc/cmdline", b"root=UUID=old")]))
    first = read_archive(guest, path)
    assert read_archive(guest, path) is first and len(guest.downloads) == 1
    guest.files[path] = cpio([("etc/cmdline", b"root=UUID=new")])
    with pytest.raises(ArchiveError, match="fingerprint"):
        read_archive(guest, path, first.sha256)
    second = read_archive(guest, path)
    assert second is not first and len(guest.downloads) == 2
    assert second.initrd_cat(path, "etc/cmdline") == b"root=UUID=new"


def test_cache_has_aggregate_member_and_retained_text_limits():
    guest = Guest(cpio([("etc/cmdline", b"aa")]))
    first, second = "/boot/initramfs-test.img", "/boot/other.img"
    guest.files[second] = cpio([("etc/cmdline", b"bb")])
    for constant, limit in (("MAX_CACHE_ARCHIVES", 1), ("MAX_ENTRIES", 1), ("MAX_RETAINED", 3)):
        guest.downloads.clear()
        guest._forge_initramfs_cache = None
        with patch("forge.initramfs." + constant, limit):
            read_archive(guest, first)
            read_archive(guest, second)
            assert len(guest._forge_initramfs_cache) == 1
            read_archive(guest, first)
            assert len(guest.downloads) == 3


def test_zstd_lvm_configuration_retained_and_storage_fallback_blocks_identity_pins():
    from forge.storage import _inspect_initrd_lvm
    entries = [("init", b"program"), ("etc/lvm/lvm.conf", b"devices { use_devicesfile=1 }"),
               ("etc/lvm/devices/system.devices", b"PVID=pinned"),
               ("etc/lvm/lvmlocal.conf", b"activation { }")]
    guest = Guest(zstd_bytes(cpio(entries)))
    path = "/boot/initramfs-test.img"
    parsed = read_archive(guest, path)
    assert parsed.initrd_cat(path, "etc/lvm/lvm.conf").startswith(b"devices")
    errors, warnings = [], []
    result = _inspect_initrd_lvm(guest, [], errors, warnings)
    assert result[0]["status"] == "checked" and result[0]["formats"] == ["zstd"]
    assert len(errors) == 2 and not warnings
    assert len(guest.downloads) == 1  # Shared evidence, no second full download.


def test_platform_fallback_reuses_the_parsed_archive_for_all_evidence():
    guest = Guest(composed())
    base = {"kernels": {"test": {"initrd": "/boot/initramfs-test.img"}}, "tools": {}}
    result = inspect_platform(guest, "/dev/sda1", [{"device": "/dev/sda1", "mountpoint": "/", "filesystem": "xfs",
                                                   "uuid": "11111111-2222-3333-4444-555555555555"}], ["/boot/vmlinuz-test"], base)
    kernel = result["kernels"]["test"]
    assert kernel["portability"]["decoder"] == "bounded_newc"
    assert kernel["portability"]["formats"] == ["newc", "gzip"]
    assert kernel["portability"]["readable"] and kernel["initrd_iscsi_userspace"]
    assert "dm_mod" in kernel["initrd_modules"]
    assert len(guest.downloads) == 1
