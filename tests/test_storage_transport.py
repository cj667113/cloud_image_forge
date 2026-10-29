"""Version-specific GPT name handling and native gzip transport invariants."""
from copy import deepcopy
import gzip
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from forge.storage import (MIB, StorageError, _archive_manifest, _compare_manifests,
                           _export_archive, _import_archive, _raw_gpt_names, _set_gpt_name)
from test_storage import make_archive


@pytest.mark.parametrize('name',['','Data volume','数据 Δ'])
def test_exact_gpt_names_use_empty_token_only_when_legacy_setter_is_noop(name):
    guest=Mock();state={1:'primary'}
    def setting(disk,number,value):
        if value:state[number]='' if value=="''" else value
    guest.part_set_name.side_effect=setting;guest.part_get_name.side_effect=lambda disk,number:state[number]
    with patch('forge.storage._raw_gpt_names',side_effect=lambda g:dict(state)):
        _set_gpt_name(guest,1,name)
    assert state[1]==name
    assert [call.args[-1] for call in guest.part_set_name.call_args_list]==(['',"''"] if name=='' else [name])


def test_modern_empty_name_setter_needs_no_legacy_token_and_raw_disagreement_blocks():
    guest=Mock();guest.part_get_name.return_value=''
    with patch('forge.storage._raw_gpt_names',return_value={1:''}):_set_gpt_name(guest,1,'')
    guest.part_set_name.assert_called_once_with('/dev/sda',1,'')
    with patch('forge.storage._raw_gpt_names',return_value={1:'primary'}),pytest.raises(StorageError):_set_gpt_name(guest,1,'')


@pytest.mark.parametrize('name',['','Data volume','数据 Δ'])
def test_raw_gpt_names_stop_at_first_utf16_nul_and_ignore_padding(name):
    field=(name+'\0old padding').encode('utf-16-le').ljust(72,b'\0')
    entries=bytes(56)+field
    header={'entries':entries,'entry_size':128,'used':{1}}
    guest=Mock();guest.blockdev_getsize64.return_value=16*MIB
    with patch('forge.uefi._gpt_header',side_effect=[header,deepcopy(header)]):assert _raw_gpt_names(guest)=={1:name}


def test_raw_gpt_names_reject_disagreeing_copies_or_invalid_utf16():
    header={'entries':bytes(56)+b'\0\xd8'+bytes(70),'entry_size':128,'used':{1}}
    guest=Mock();guest.blockdev_getsize64.return_value=16*MIB
    with patch('forge.uefi._gpt_header',side_effect=[header,deepcopy(header)]),pytest.raises(StorageError,match='UTF-16'):_raw_gpt_names(guest)
    other={**header,'entries':bytes(128)}
    with patch('forge.uefi._gpt_header',side_effect=[header,other]),pytest.raises(StorageError,match='copies'):_raw_gpt_names(guest)


def tar_guest(tmp_path):
    fixture=tmp_path/'fixture.gz';make_archive(fixture)
    raw=gzip.decompress(fixture.read_bytes());guest=Mock();calls=[]
    def out(directory,path,**options):
        assert directory=='/' and 'compress' not in options
        assert all(options[key] for key in ('numericowner','xattrs','selinux','acls'))
        assert Path(path).stat().st_mode&0o777==0o600
        Path(path).write_bytes(raw);calls.append(('out',path))
    def into(path,directory,**options):
        assert directory=='/' and 'compress' not in options
        assert all(options[key] for key in ('xattrs','selinux','acls'))
        assert Path(path).read_bytes()==raw;calls.append(('in',path))
    guest.tar_out.side_effect=out;guest.tar_in.side_effect=into
    return guest,fixture,raw,calls


def test_host_gzip_roundtrip_preserves_exact_tar_and_manifest_metadata(tmp_path):
    guest,fixture,raw,calls=tar_guest(tmp_path);archive=tmp_path/'archive.gz'
    size=_export_archive(guest,archive,len(raw))
    assert size==len(raw) and gzip.decompress(archive.read_bytes())==raw
    _compare_manifests(_archive_manifest(fixture),_archive_manifest(archive),'/dev/fixture')
    _import_archive(guest,archive,size)
    assert [call[0] for call in calls]==['out','in']
    assert not list(tmp_path.glob('raw-*.tar'))


def test_export_does_not_overwrite_preexisting_archive(tmp_path):
    guest,fixture,raw,calls=tar_guest(tmp_path);archive=tmp_path/'archive.gz';archive.write_bytes(b'untouched')
    with pytest.raises(FileExistsError):_export_archive(guest,archive,len(raw))
    assert archive.read_bytes()==b'untouched' and not list(tmp_path.glob('raw-*.tar'))


@pytest.mark.parametrize('stage',['export','compress','restore','truncated','expanded','corrupt','space'])
def test_failed_transport_cleans_only_owned_raw_and_partial_gzip(tmp_path,stage):
    guest,fixture,raw,calls=tar_guest(tmp_path);archive=tmp_path/'archive.gz'
    if stage=='export':
        def fail(*args,**kwargs):Path(args[1]).write_bytes(b'partial');raise RuntimeError('transfer failed')
        guest.tar_out.side_effect=fail
        with pytest.raises(RuntimeError):_export_archive(guest,archive,len(raw))
        assert not archive.exists()
    elif stage=='compress':
        with patch('forge.storage.shutil.copyfileobj',side_effect=OSError('disk full')),pytest.raises(OSError):_export_archive(guest,archive,len(raw))
        assert not archive.exists()
    elif stage=='space':
        with patch('forge.storage.shutil.disk_usage',return_value=Mock(free=0)),pytest.raises(StorageError,match='workspace'):_export_archive(guest,archive,len(raw))
        guest.tar_out.assert_not_called()
    else:
        size=_export_archive(guest,archive,len(raw))
        if stage=='restore':guest.tar_in.side_effect=RuntimeError('restore failed')
        if stage=='truncated':size+=1
        if stage=='expanded':size-=1
        if stage=='corrupt':archive.write_bytes(archive.read_bytes()[:-6])
        with pytest.raises((RuntimeError,EOFError,OSError)):_import_archive(guest,archive,size)
        if stage!='restore':guest.tar_in.assert_not_called()
        assert archive.exists()
    assert fixture.exists() and not list(tmp_path.glob('raw-*.tar'))
