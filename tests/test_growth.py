"""Automatic sizing follows actual containers and preserves unrelated identities."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import pytest

from forge.growth import plan_growth, verify_growth, grow
from forge.storage import MIB, GIB, StorageError, plan_storage
from test_storage import inspected


def image(lvm=True):
    result=inspected(lvm)
    result['os']['root']='/dev/ocivolume/root' if lvm else '/dev/sda3'
    storage=result['storage'];storage['growth_errors']=[]
    layout=storage['layout'];layout['boot_code_sha256']='boot-hash';layout['end_guard_bytes']=MIB
    if lvm:
        extent=4*MIB;part=layout['partitions'][-1];count=(part['size']-MIB)//extent;allocated=8192*MIB//extent
        storage['lvm']['pvs'][0].update(pe_start=MIB,pv_size=count*extent,pv_free=(count-allocated)*extent,pv_pe_count=count,pv_pe_alloc_count=allocated,pv_mda_count=1)
        storage['lvm']['vgs'][0].update(vg_size=count*extent,vg_free=(count-allocated)*extent,vg_extent_count=count,vg_free_count=count-allocated)
        storage['lvm']['lvs'][0]['lv_size']=8192*MIB
    else:
        storage['filesystems'][-1]['size']=layout['partitions'][-1]['size']
    return result


def options(device='/dev/ocivolume/root',size=10240):
    return {'enabled':True,'sizes':[{'device':device,'size_mib':size}]}


def final_image(original,plan):
    result=deepcopy(original);result['virtual_size']=plan['layout']['disk_size_after']
    result['storage']['layout']=deepcopy(plan['layout']);result['storage']['layout']['disk_size']=result['virtual_size']
    result['storage']['filesystems']=deepcopy(plan['filesystems'])
    for fs in result['storage']['filesystems']:fs['size']=fs['selected_size'];fs['filesystem_capacity']=fs['selected_size']
    for lv in result['storage']['lvm']['lvs']:lv['lv_size']=next(x['size'] for x in plan['layout']['lvs'] if x['device']==lv['device'])
    return result


def test_lv_growth_uses_existing_vg_space_without_growing_disk_or_partition():
    original=image();before=deepcopy(original);plan=plan_storage(original,options())
    assert plan['ready'],plan['blockers']
    assert plan['mode']=='growth' and plan['layout']['disk_size_after']==original['virtual_size']
    assert plan['layout']['partitions']==original['storage']['layout']['partitions']
    assert plan['actions']==[{'device':'/dev/ocivolume/root','filesystem':'xfs','kind':'lv','before':8192*MIB,'after':10240*MIB}]
    assert original==before


def test_cached_rebuild_only_lvm_pin_error_does_not_block_identity_preserving_growth():
    from forge.storage import LVM_PIN_ERROR
    original=image();original['storage'].pop('growth_errors')
    original['storage']['errors']=[LVM_PIN_ERROR]
    plan=plan_storage(original,options())
    assert plan['ready'],plan['blockers']
    assert plan['source']['lvm']==original['storage']['lvm']
    original['storage']['errors'].append('Unverified data filesystem')
    assert not plan_storage(original,options())['ready']


def test_new_inspection_growth_errors_are_never_waived():
    from forge.storage import LVM_PIN_ERROR
    original=image();original['storage']['growth_errors']=[LVM_PIN_ERROR]
    assert not plan_storage(original,options())['ready']


def test_actual_lvm_metadata_supports_linux_data_partition_type_without_changing_it():
    original=image();part=original['storage']['layout']['partitions'][-1]
    part.update(type='0fc63daf-8483-4772-8e79-3d69d8477de4',filesystem='LVM2_member')
    plan=plan_storage(original,options(size=16384))
    assert plan['ready'],plan['blockers']
    assert plan['layout']['partitions'][-1]['type']==part['type']
    part['filesystem']='unknown'
    assert not plan_storage(original,options(size=16384))['ready']


def test_explicit_lv_growth_automatically_grows_its_pv_partition_and_disk():
    original=image();plan=plan_storage(original,options(size=16385))
    assert plan['ready'],plan['blockers']
    assert plan['filesystems'][-1]['selected_size']==16388*MIB
    assert plan['layout']['partitions'][-1]['start']==original['storage']['layout']['partitions'][-1]['start']
    assert plan['layout']['partitions'][-1]['size']==16389*MIB
    assert plan['layout']['disk_size_after']>original['virtual_size']
    assert plan['layout']['partitions'][:2]==original['storage']['layout']['partitions'][:2]


def test_explicit_targets_do_not_consume_extra_disk_or_vg_space():
    plan=plan_storage(image(),options(size=10240),24)
    assert plan['ready'] and plan['filesystems'][-1]['selected_size']==10240*MIB
    assert not plan['root_fill'] and plan['layout']['disk_size_after']==24*GIB


def test_multiple_lvs_receive_exact_requested_capacities_not_all_free_space():
    original=image();storage=original['storage'];other=deepcopy(storage['lvm']['lvs'][0]);other.update(device='/dev/ocivolume/data',lv_name='data',lv_uuid='data-id',lv_size=512*MIB);storage['lvm']['lvs'].append(other)
    fs=deepcopy(storage['filesystems'][-1]);fs.update(device=other['device'],uuid='data-uuid',label='DATA',mountpoint='/data',size=512*MIB);storage['filesystems'].append(fs)
    vg,pv=storage['lvm']['vgs'][0],storage['lvm']['pvs'][0];vg['lv_count']=2;vg['vg_free']-=512*MIB;vg['vg_free_count']-=128;pv['pv_free']-=512*MIB;pv['pv_pe_alloc_count']+=128
    plan=plan_storage(original,{'enabled':True,'sizes':[{'device':'/dev/ocivolume/root','size_mib':12288},{'device':other['device'],'size_mib':1024}]})
    assert plan['ready'],plan['blockers']
    assert {lv['device']:lv['size'] for lv in plan['layout']['lvs']}=={'/dev/ocivolume/root':12288*MIB,other['device']:1024*MIB}


@pytest.mark.parametrize('lvm',[False,True])
def test_disk_only_growth_fills_only_independently_verified_root(lvm):
    original=image(lvm);plan=plan_storage(original,{'enabled':True,'sizes':[]},16)
    assert plan['ready'] and plan['root_fill'],plan['blockers']
    assert len(plan['actions'])==1 and plan['actions'][0]['device']==original['os']['root']
    assert plan['layout']['disk_size_after']==16*GIB
    assert plan['warnings'] and plan['filesystems'][:2]==[{**fs,'selected_size':fs['size'],'selected_size_mib':fs['size']//MIB} for fs in original['storage']['filesystems'][:2]]


def test_raw_ext_growth_requires_no_lvm_choice_and_preserves_start():
    original=image(False);plan=plan_storage(original,options('/dev/sda3',16384))
    assert plan['ready'] and not plan['layout']['lvs']
    assert plan['layout']['partitions'][-1]['size']==16384*MIB
    assert plan['layout']['partitions'][-1]['start']==original['storage']['layout']['partitions'][-1]['start']


def test_shrinking_selects_existing_verified_rebuild_restrictions():
    original=image();plan=plan_storage(original,options(size=7680),10)
    assert plan['ready'] and plan['mode']=='rebuild'
    original['boot']['supported_firmware'].append('BIOS')
    assert not plan_storage(original,options(size=7680),10)['ready']


@pytest.mark.parametrize('change,needle',[
 ('root','independently inspected'),('collision','overlap'),('multiple-pv','one PV'),
 ('extent','inconsistent'),('identity','preservation evidence'),('partial','incomplete'),
 ('wrong-capacity','disagrees'),('size-too-small','increase disk'),('unknown','unique inspected')])
def test_ambiguous_unsupported_or_conflicting_growth_is_blocked(change,needle):
    original=image();opts=options();disk=None
    if change=='root':original['os']['root']='/dev/unknown';opts={'enabled':True,'sizes':[]};disk=16
    if change=='collision':opts=options('/dev/sda2',1024)
    if change=='multiple-pv':original['storage']['lvm']['pvs'].append(deepcopy(original['storage']['lvm']['pvs'][0]))
    if change=='extent':original['storage']['lvm']['pvs'][0].pop('pe_start')
    if change=='identity':original['storage']['layout'].pop('boot_code_sha256')
    if change=='partial':original['storage']['growth_errors']=None
    if change=='wrong-capacity':original['storage']['layout']['disk_size']-=MIB
    if change=='size-too-small':opts=options(size=20000);disk=13
    if change=='unknown':opts=options('/dev/ocivolume/not-root',20000)
    plan=plan_storage(original,opts,disk)
    assert not plan['ready'] and needle in ' '.join(plan['blockers']),plan


def test_legacy_bios_growth_preserves_boundaries_without_rebuild_gate():
    original=image(False);original['boot']['supported_firmware']=['BIOS'];layout=original['storage']['layout'];layout['partition_table']='msdos';layout['disk_identity']='1234abcd'
    for part in layout['partitions']:part['type']=0x83;part['active']=0x80 if part['number']==3 else 0;part.pop('partition_guid');part.pop('attributes')
    plan=plan_storage(original,options('/dev/sda3',16384))
    assert plan['ready'] and plan['mode']=='growth'
    assert verify_growth(final_image(original,plan),plan)['ready']


@pytest.mark.parametrize('tamper',['uuid','label','partition-start','disk-id','lv-id','lv-size','boot','architecture','capacity'])
def test_final_growth_verification_rejects_identity_geometry_and_size_drift(tamper):
    original=image();plan=plan_storage(original,options(size=16384));final=final_image(original,plan)
    assert verify_growth(final,plan)['ready']
    if tamper in ('uuid','label'):final['storage']['filesystems'][-1][tamper]='changed'
    elif tamper=='partition-start':final['storage']['layout']['partitions'][-1]['start']+=512
    elif tamper=='disk-id':final['storage']['layout']['disk_identity']='changed'
    elif tamper=='lv-id':final['storage']['lvm']['lvs'][0]['lv_uuid']='changed'
    elif tamper=='lv-size':final['storage']['lvm']['lvs'][0]['lv_size']+=4*MIB
    elif tamper=='boot':final['boot']['supported_firmware']=[]
    elif tamper=='architecture':final['os']['arch']='aarch64'
    else:final['virtual_size']+=MIB
    assert not verify_growth(final,plan)['ready']


def test_alignment_can_only_increase_capacity_explicitly():
    original=image();plan=plan_storage(original,options());final=final_image(original,plan);final['virtual_size']+=MIB;final['storage']['layout']['disk_size']+=MIB
    assert not verify_growth(final,plan)['ready']
    assert verify_growth(final,plan,expected_disk_size=final['virtual_size'])['ready']


def test_growth_failure_deletes_only_owned_new_copy_and_keeps_source(tmp_path):
    source=tmp_path/'source';source.write_bytes(b'original');destination=tmp_path/'grown';original=image();calls=[]
    def run(command,log):
        calls.append(command)
        if command[:2]==['qemu-img','convert']:destination.write_bytes(b'copy')
    @contextmanager
    def guest(*args,**kwargs):raise RuntimeError('appliance failed');yield
    with patch('forge.engine.ImageEngine.inspect',return_value=original),patch('forge.engine._run',run),patch('forge.engine._guest',guest):
        with pytest.raises(RuntimeError,match='appliance failed'):grow(source,destination,original,options(),None,lambda _:None)
    assert source.read_bytes()==b'original' and not destination.exists()
    assert calls[0][:2]==['qemu-img','convert']


def test_rejected_plan_performs_no_writes(tmp_path):
    source=tmp_path/'source';source.write_bytes(b'original');original=image();original['storage']['growth_errors']=['invalid']
    with patch('forge.engine.ImageEngine.inspect',return_value=original),patch('forge.engine._run') as run:
        with pytest.raises(StorageError,match='blocked'):grow(source,tmp_path/'new',original,options(),None,lambda _:None)
    run.assert_not_called();assert source.read_bytes()==b'original'


def test_unchanged_tight_gpt_layout_does_not_add_padding_or_grow_disk():
    original=image(False);last=original['storage']['layout']['partitions'][-1]
    original['virtual_size']=last['end']+1+34*512;original['storage']['layout']['disk_size']=original['virtual_size']
    plan=plan_storage(original,options('/dev/sda3',last['size']//MIB))
    assert plan['ready'] and plan['mode']=='unchanged'
    assert plan['layout']['disk_size_after']==original['virtual_size']


def test_small_disk_growth_never_rounds_an_unaligned_root_down():
    original=image(False);last=original['storage']['layout']['partitions'][-1]
    last['size']+=512;last['end']+=512;original['storage']['filesystems'][-1]['size']=last['size']
    plan=plan_storage(original,{'enabled':True,'sizes':[]},(original['virtual_size']+512)/GIB)
    assert plan['ready'],plan['blockers']
    assert plan['filesystems'][-1]['selected_size']>=last['size']


def test_complex_lvm_segments_require_dedicated_workflow():
    original=image();original['storage']['lvm']['lvs'][0]['seg_count']=2
    plan=plan_storage(original,options())
    assert not plan['ready'] and 'single-segment' in ' '.join(plan['blockers'])


def test_final_verifier_measures_filesystem_capacity_not_just_device_size():
    original=image();plan=plan_storage(original,options());final=final_image(original,plan)
    final['storage']['filesystems'][-1]['filesystem_capacity']=8192*MIB
    assert not verify_growth(final,plan)['ready']


def test_execution_grows_partition_then_pv_then_exact_lv_and_filesystem(tmp_path):
    from unittest.mock import Mock
    source=tmp_path/'source';source.write_bytes(b'original');destination=tmp_path/'grown';original=image();opts=options(size=16384);plan=plan_storage(original,opts);final=final_image(original,plan);events=[]
    guest=Mock()
    for name in ('part_expand_gpt','part_resize','pvresize','lvresize','mount','xfs_growfs','umount_all','sync'):
        getattr(guest,name).side_effect=lambda *args,_name=name,**kwargs:events.append((_name,args))
    @contextmanager
    def opened(*args,**kwargs):assert kwargs['readonly'] is False;yield guest
    def run(command,log):
        if command[:2]==['qemu-img','convert']:destination.write_bytes(b'grown')
    with patch('forge.engine.ImageEngine.inspect',side_effect=[original,final]),patch('forge.engine._run',run),patch('forge.engine._guest',opened):
        assert grow(source,destination,original,opts,None,lambda _:None)==destination
    names=[event[0] for event in events]
    assert names==['part_expand_gpt','part_resize','pvresize','lvresize','mount','xfs_growfs','umount_all','sync']
    assert ('lvresize',('/dev/ocivolume/root',16384)) in events
    assert events[1][1][-1]==plan['layout']['partitions'][-1]['end']//512
    assert source.read_bytes()==b'original'
