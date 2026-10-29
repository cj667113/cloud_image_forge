"""VMDK admission must reject external references before invoking image tools."""
import shutil
import struct
import subprocess
from unittest.mock import patch

import pytest

from forge.engine import EngineError, ImageEngine, _input_format


def sparse_image(descriptor=None, *, stream=False):
    descriptor = descriptor or ('# Disk DescriptorFile\nversion=1\nCID=12345678\n'
        'parentCID=ffffffff\ncreateType="monolithicSparse"\n'
        'RW 4096 SPARSE "original-export-name.vmdk"\n')
    data = bytearray(16384)
    struct.pack_into('<4sIIQQQQ', data, 0, b'KDMV', 3 if stream else 1,
                     0x30001 if stream else 3, 4096, 128, 1, 1)
    data[512:512 + len(descriptor)] = descriptor.encode()
    if stream:
        struct.pack_into('<Q', data, 56, 0xffffffffffffffff)
        data[-1024:-512] = data[:512]
        struct.pack_into('<II', data, len(data) - 1536 + 8, 0, 3)
    return data


@pytest.mark.parametrize('stream', [False, True])
def test_embedded_vmdk_survives_upload_rename(tmp_path, stream):
    path = tmp_path / 'source'
    path.write_bytes(sparse_image(stream=stream))
    assert _input_format(path) == 'vmdk'


@pytest.mark.parametrize('change', [
    lambda s: s.replace('parentCID=ffffffff', 'parentCID=12345678'),
    lambda s: s + 'parentFileNameHint="/etc/shadow"\n',
    lambda s: s + '# parentFileNameHint="https://example.invalid/disk"\n',
    lambda s: s.replace('monolithicSparse', 'twoGbMaxExtentSparse'),
    lambda s: s.replace('monolithicSparse', 'monolithicFlat'),
    lambda s: s + 'RW 4096 SPARSE "extra.vmdk"\n',
    lambda s: s.replace('RW 4096 SPARSE', 'RW 2048 SPARSE'),
    lambda s: s + 'createType="monolithicSparse"\n',
])
def test_unsafe_descriptors_rejected_before_qemu(tmp_path, change):
    path = tmp_path / 'source'
    descriptor = bytes(sparse_image()[512:1024]).split(b'\0')[0].decode()
    path.write_bytes(sparse_image(change(descriptor)))
    with patch('forge.engine._run') as run:
        with pytest.raises(EngineError):
            ImageEngine().inspect(path)
        run.assert_not_called()


def test_qemu_parent_scan_extends_beyond_declared_descriptor_size(tmp_path):
    data = sparse_image()
    data[512:1024] = b'#' * 512
    data[1024:1062] = b'\nparentFileNameHint="/etc/shadow"\n'.ljust(38)
    path = tmp_path / 'source'
    path.write_bytes(data)
    with pytest.raises(EngineError, match='parent/backing'):
        _input_format(path)


@pytest.mark.parametrize('field,value', [(12, 0), (28, 0), (28, 2**63), (36, 2**63)])
def test_invalid_sparse_header_never_reaches_qemu(tmp_path, field, value):
    data = sparse_image()
    struct.pack_into('<Q', data, field, value)
    path = tmp_path / 'source'
    path.write_bytes(data)
    with patch('forge.engine._run') as run:
        with pytest.raises(EngineError):
            ImageEngine().inspect(path)
        run.assert_not_called()


@pytest.mark.parametrize('offset', [-1024, -1536 + 12, -512 + 12])
def test_missing_or_invalid_stream_footer_is_actionable(tmp_path, offset):
    data = sparse_image(stream=True)
    data[offset] ^= 1
    path = tmp_path / 'source'
    path.write_bytes(data)
    with pytest.raises(EngineError, match='incomplete or damaged'):
        _input_format(path)


def test_footer_cannot_redirect_descriptor(tmp_path):
    data = sparse_image(stream=True)
    struct.pack_into('<Q', data, len(data) - 1024 + 28, 8)
    path = tmp_path / 'source'
    path.write_bytes(data)
    with pytest.raises(EngineError, match='disagrees'):
        _input_format(path)


@pytest.mark.skipif(not shutil.which('qemu-img'), reason='QEMU is optional on development hosts')
@pytest.mark.parametrize('subformat', ['monolithicSparse', 'streamOptimized'])
def test_real_qemu_import_and_conversion_preserve_disk_bytes(tmp_path, subformat):
    raw = tmp_path / 'disk.raw'
    raw.write_bytes(bytes(range(256)) * 8192)
    source = tmp_path / 'original.vmdk'
    work = tmp_path / 'working.qcow2'
    def qemu(*args):
        subprocess.run(['qemu-img', *map(str, args)], check=True, capture_output=True)
    qemu('convert', '-f', 'raw', '-O', 'vmdk', '-o', f'subformat={subformat}', raw, source)
    uploaded = tmp_path / 'source'
    source.rename(uploaded)
    original = uploaded.read_bytes()
    assert _input_format(uploaded) == 'vmdk'
    qemu('info', '-f', 'vmdk', uploaded)
    qemu('convert', '-f', 'vmdk', '-O', 'qcow2', uploaded, work)
    qemu('compare', '-f', 'raw', '-F', 'qcow2', raw, work)
    assert uploaded.read_bytes() == original
