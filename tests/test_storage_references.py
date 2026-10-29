"""Narrow rebuild normalization of proved GRUB LVM search fallbacks."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import UUID

import pytest

from forge.storage import (_normalize_grub_lvm, normalize_rebuild_boot_references,
                           plan_rebuild, verify_rebuild, StorageError, LINUX_GUID)
from test_storage import fstab_pinned, OPTIONS, MIB, GIB


def grub_pinned():
    image=fstab_pinned();storage=image['storage'];vg='A'*32;lv='B'*32;root_uuid=str(UUID(int=99))
    storage['lvm']['vgs'][0]['vg_uuid']=vg;storage['lvm']['lvs'][0]['lv_uuid']=lv
    storage['filesystems'][-1]['uuid']=root_uuid
    old=f'/dev/disk/by-id/dm-uuid-LVM-{vg}{lv} / xfs defaults 0 1\n'
    source_hash=hashlib.sha256(old.encode()).hexdigest()
    storage['lvm_identity_pins'].update(paths=['/etc/fstab','/boot/grub/grub.cfg'],fstab_sha256=source_hash)
    image['mount_reconciliation'].update(sha256=source_hash,content=f'UUID={root_uuid} / xfs defaults 0 1\n')
    token=f'lvmid/{vg}/{lv}'
    content=("insmod lvm\ninsmod ext2\n"+f"set root='{token}'\n"
        "if [ x$feature_platform_search_hint = xy ]; then\n"
        f"  search --no-floppy --fs-uuid --set=root --hint='{token}'  {root_uuid}\n"
        "else\n"+f"  search --no-floppy --fs-uuid --set=root {root_uuid}\nfi\n"
        "font='/usr/share/grub/unicode.pf2'\nlinux /vmlinuz root=/dev/mapper/ocivolume-root ro\n")
    image['platform']={'generated_grub':{'/boot/grub/grub.cfg':content}}
    return image


def test_verified_pair_projection_binds_original_content_and_preserves_other_boot_lines():
    original=grub_pinned();before=deepcopy(original)
    plan=plan_rebuild(original,OPTIONS,10)
    assert plan['ready'],plan['blockers']
    update=plan['projected_boot_updates'][0]
    assert update['source_sha256']==hashlib.sha256(original['platform']['generated_grub'][update['path']].encode()).hexdigest()
    assert update['sha256']==hashlib.sha256(update['content'].encode()).hexdigest()
    assert 'lvmid/' not in update['content'] and '--hint=' not in update['content']
    assert update['content'].startswith('insmod lvm\ninsmod ext2\nsearch ')
    assert "font='/usr/share/grub/unicode.pf2'\nlinux /vmlinuz root=/dev/mapper/ocivolume-root ro\n" in update['content']
    assert original==before and plan['projected_mount_changes']
    assert not plan_rebuild(original,OPTIONS,10,mount_policy='preserve')['ready']
    assert not plan_rebuild(original,OPTIONS,10,project_references=False)['ready']


@pytest.mark.parametrize('change',['standalone','dynamic','wrong-uuid','wrong-hint','residual','missing-branch','different-set','duplicate-uuid','unknown-path','unknown-initrd'])
def test_unknown_conflicting_and_partial_reference_proofs_remain_blocked(change):
    image=grub_pinned();path='/boot/grub/grub.cfg';text=image['platform']['generated_grub'][path]
    if change=='standalone':text=text[:text.index('if [')]
    if change=='dynamic':text=text.replace("set root='lvmid/", "set root='$prefix/lvmid/")
    if change=='wrong-uuid':text=text.replace(str(UUID(int=99)),str(UUID(int=98)),1)
    if change=='wrong-hint':text=text.replace('--hint=\'lvmid/A','--hint=\'lvmid/C')
    if change=='residual':text+='set unrelated='+('A'*32)+'\n'
    if change=='missing-branch':text=text.replace('else\n','')
    if change=='different-set':text=text.replace('--set=root','--set=boot',1)
    if change=='duplicate-uuid':image['storage']['filesystems'][1]['uuid']=str(UUID(int=99))
    if change=='unknown-path':image['storage']['lvm_identity_pins']['paths'].append('/etc/kernel/cmdline')
    if change=='unknown-initrd':image['storage']['initramfs'][0]['status']='unavailable'
    image['platform']['generated_grub'][path]=text
    plan=plan_rebuild(image,OPTIONS,10)
    assert not plan['ready'] and 'pins internal' in ' '.join(plan['blockers'])


def test_proved_linux_data_pv_role_drives_layout_without_changing_its_type():
    image=grub_pinned();image['storage']['layout']['partitions'][-1]['type']=LINUX_GUID
    plan=plan_rebuild(image,OPTIONS,10)
    assert plan['ready'],plan['blockers']
    assert plan['layout']['pv_device']=='/dev/sda3'
    assert plan['layout']['partitions'][-1]['type']==LINUX_GUID
    assert plan['layout']['partitions'][-1]['end']==10*GIB-2*MIB-1
    image['storage']['layout']['partitions'][-1]['filesystem']='ext4'
    assert not plan_rebuild(image,OPTIONS,10)['ready']


def prepared_guest(image):
    guest=Mock();storage=image['storage'];files=dict(image['platform']['generated_grub'])
    guest.pvs_full.return_value=deepcopy(storage['lvm']['pvs']);guest.vgs_full.return_value=deepcopy(storage['lvm']['vgs']);guest.lvs_full.return_value=deepcopy(storage['lvm']['lvs'])
    guest.list_filesystems.return_value={fs['device']:fs['filesystem'] for fs in storage['filesystems']}
    guest.vfs_uuid.side_effect=lambda device:next(fs['uuid'] for fs in storage['filesystems'] if fs['device']==device)
    guest.is_symlink.return_value=False;guest.is_file.side_effect=lambda path:path in files
    guest.statns.return_value={'st_uid':0,'st_gid':0,'st_mode':0o100640,'st_nlink':1}
    guest.filesize.side_effect=lambda path:len(files[path].encode())
    guest.read_file.side_effect=lambda path:files[path].encode()
    guest.write.side_effect=lambda path,value:files.__setitem__(path,value.decode())
    guest.checksum.side_effect=lambda algorithm,path:hashlib.sha256(files[path].encode()).hexdigest()
    return guest,files


def test_working_copy_normalization_preserves_metadata_and_checks_readback():
    image=grub_pinned();updates=plan_rebuild(image,OPTIONS,10)['projected_boot_updates'];guest,files=prepared_guest(image)
    @contextmanager
    def opened(path,fmt,readonly):
        assert path==Path('/working-copy') and readonly is False
        yield guest
    with patch('forge.engine._guest',opened),patch('forge.engine._roots',return_value='/dev/ocivolume/root'),patch('forge.engine._mount'):
        receipt=normalize_rebuild_boot_references(Path('/working-copy'),image,updates,lambda _:None)
    assert receipt['changed'] and receipt['files'][0]['sha256']==updates[0]['sha256']
    assert files[updates[0]['path']]==updates[0]['content']
    guest.chmod.assert_called_once_with(0o640,updates[0]['path']);guest.chown.assert_called_once_with(0,0,updates[0]['path'])
    guest.command.assert_not_called();guest.sh.assert_not_called()


@pytest.mark.parametrize('change',['content','uuid','vg-id','symlink','hardlink','readback'])
def test_working_copy_identity_or_content_change_cannot_silently_apply_projection(change):
    image=grub_pinned();updates=plan_rebuild(image,OPTIONS,10)['projected_boot_updates'];guest,files=prepared_guest(image)
    if change=='content':files[updates[0]['path']]+='# changed after preview\n'
    if change=='uuid':guest.vfs_uuid.side_effect=lambda device:'changed'
    if change=='vg-id':guest.vgs_full.return_value[0]['vg_uuid']='C'*32
    if change=='symlink':guest.is_symlink.return_value=True
    if change=='hardlink':guest.statns.return_value['st_nlink']=2
    if change=='readback':guest.checksum.return_value='different';guest.checksum.side_effect=None
    @contextmanager
    def opened(*args,**kwargs):yield guest
    with patch('forge.engine._guest',opened),patch('forge.engine._roots'),patch('forge.engine._mount'),pytest.raises((StorageError,ValueError)):
        normalize_rebuild_boot_references(Path('/working-copy'),image,updates,lambda _:None)
    if change!='readback':guest.write.assert_not_called()


def test_final_rebuild_rejects_stale_grub_reintroduced_after_normalization():
    image=grub_pinned();plan=plan_rebuild(image,OPTIONS,10);final=deepcopy(image)
    final['virtual_size']=10*GIB;final['storage']['layout'].update(plan['layout'],disk_size=10*GIB)
    for fs in final['storage']['filesystems']:
        planned=next(x for x in plan['filesystems'] if x['device']==fs['device'])
        fs['size']=planned['size'] if fs['kind']=='efi' else planned['selected_size_mib']*MIB
    final['storage']['lvm']['lvs'][0]['lv_size']=7680*MIB
    final['platform']['generated_grub']['/boot/grub/grub.cfg']=plan['projected_boot_updates'][0]['content']
    assert verify_rebuild(final,plan)['ready']
    final['platform']['generated_grub']['/boot/grub/grub.cfg']=image['platform']['generated_grub']['/boot/grub/grub.cfg']
    assert not verify_rebuild(final,plan)['ready']
