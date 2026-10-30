"""Firmware login readiness must include the network path before discovery."""
from copy import deepcopy
import io
from unittest.mock import patch

import pytest

from forge.iscsi_network import inspect_archive_network, inspect_handover, plan_network
from forge.platform import _iscsi_archive_ready, plan_platform, verify_platform, _initramfs_script
from forge.oci_guest import _network_files, _network_evidence
from test_platform import Guest, image, options, KERNEL
from test_initramfs import cpio
from forge.initramfs import parse_file


def network_files():
    return {
        'usr/lib/dracut/modules.txt': b'iscsi network-manager network systemd dracut-systemd',
        'usr/sbin/NetworkManager': b'ELF', 'usr/lib/nm-initrd-generator': b'ELF',
        'usr/bin/nm-online': b'ELF', 'usr/bin/bash': b'ELF',
        'usr/share/dbus-1/system.d/org.freedesktop.NetworkManager.conf': b'<busconfig/>',
        'usr/lib/systemd/system/dbus.service': b'[Service]\nExecStart=/usr/bin/dbus-daemon',
        'usr/lib/systemd/system/nm-initrd.service': b'[Service]\nExecStart=/usr/sbin/NetworkManager --debug\nEnvironment=NM_CONFIG_ENABLE_TAG=initrd\n',
        'usr/lib/systemd/system/nm-wait-online-initrd.service': b'[Service]\nExecStart=/usr/bin/nm-online -s -q -t 3600\n',
        'etc/systemd/system/initrd.target.wants/nm-initrd.service': b'enabled',
        'etc/systemd/system/initrd.target.wants/nm-wait-online-initrd.service': b'enabled',
        'usr/lib/nm-lib.sh': b'/usr/lib/nm-initrd-generator -- $(getcmdline)\nmkdir -p /run/NetworkManager/initrd/neednet\n',
        'var/lib/dracut/hooks/cmdline/99-nm-config.sh': b'nm_generate_connections\n',
        'var/lib/dracut/hooks/initqueue/settled/99-nm-run.sh': b'#!/bin/bash\nfor i in /sys/class/net/*; do\n state=/run/NetworkManager/devices/name\n grep connection-uuid= "$state"\n source_hook initqueue/online "$i"\n /sbin/netroot "$i"\ndone\n',
    }


def archive(files):
    return parse_file(io.BytesIO(cpio(list(files.items()))))


def assess(files):
    parsed = archive(files)
    return inspect_archive_network(parsed, parsed.path, parsed.initrd_list(parsed.path))


def test_archive_proves_firmware_network_chain_and_retains_exact_hook_text():
    result = assess(network_files())
    assert result['ready'], result['errors']
    assert result['backend'] == 'network-manager'
    parsed = archive(network_files())
    assert parsed.initrd_cat(parsed.path, 'var/lib/dracut/hooks/cmdline/99-nm-config.sh') == b'nm_generate_connections\n'


@pytest.mark.parametrize('missing', [name for name in network_files() if name != 'usr/lib/dracut/modules.txt'])
def test_each_runtime_link_is_required(missing):
    files = network_files(); files.pop(missing)
    assert not assess(files)['ready']


@pytest.mark.parametrize('path', ['etc/systemd/system/nm-initrd.service',
    'etc/systemd/system/nm-initrd.service.d/override.conf',
    'usr/lib/systemd/system/nm-initrd.service.d/unreviewed.conf',
    'etc/systemd/system/service.d/override.conf'])
def test_masks_and_unmodelled_overrides_never_inherit_vendor_proof(path):
    files = network_files(); files[path] = b'[Service]\nExecStart=/bin/false\n'
    assert not assess(files)['ready']


def test_symlink_mask_is_not_hidden_by_regular_file_inventory():
    files = network_files()
    parsed = parse_file(io.BytesIO(cpio(list(files.items()) + [('etc/systemd/system/nm-initrd.service', b'/dev/null', 0o120777)])))
    assert not inspect_archive_network(parsed, parsed.path, parsed.initrd_list(parsed.path))['ready']


def test_current_networkd_archive_is_not_firmware_ready_even_with_iscsi_helpers():
    files = network_files(); files['usr/lib/dracut/modules.txt'] = b'iscsi network systemd systemd-networkd'
    result = assess(files)
    assert not result['ready'] and result['backend'] == 'systemd-networkd'
    assert 'DHCP-only' in ' '.join(result['errors'])
    files['usr/lib/dracut/modules.txt'] += b' network-manager'
    assert 'Competing' in ' '.join(assess(files)['errors'])


@pytest.mark.parametrize('file,content', [
    ('var/lib/dracut/hooks/cmdline/99-nm-config.sh', b'# nm_generate_connections\necho unrelated'),
    ('usr/lib/nm-lib.sh', b'# /usr/lib/nm-initrd-generator -- $(getcmdline)\n# /run/NetworkManager/initrd/neednet'),
    ('usr/lib/systemd/system/nm-initrd.service', b'[Service]\nExecStart=/bin/false\nEnvironment=NM_CONFIG_ENABLE_TAG=initrd'),
    ('var/lib/dracut/hooks/initqueue/settled/99-nm-run.sh', b'# source_hook initqueue/online foo\n# /sbin/netroot foo\n'),
])
def test_comment_or_unrelated_commands_cannot_prove_chain(file, content):
    files = network_files(); files[file] = content
    assert not assess(files)['ready']


def test_package_permission_requires_both_flags_and_vm_path_is_unchanged():
    source = image(); source['os']['distro'] = 'ubuntu'
    source['platform']['tools'].update(NetworkManager=False, **{'apt-get': True})
    source['platform']['nm_initrd_generator'] = None
    profile = options(boot_attachment='iscsi', configure_network=True)
    for install, network in [(False, False), (False, True), (True, False)]:
        assert not plan_platform(source, {**profile, 'install_packages': install}, network)['ready']
    ready = plan_platform(source, {**profile, 'install_packages': True}, True)
    assert ready['ready'], ready['blockers']
    assert ready['packages'] == ['network-manager']
    assert ready['dracut_network_module'] == 'network-manager'
    script = _initramfs_script(source, ready, profile)
    assert "--omit 'systemd-networkd network-legacy'" in script
    assert '--add \'iscsi network-manager\'' in script
    assert 'iBFT network generator missing' in script
    assert plan_platform(source, options())['ready']
    assert plan_platform(source, options())['packages'] == []


def test_final_receipt_cannot_waive_unverified_firmware_network():
    source = image(); kernel = source['platform']['kernels'][KERNEL]
    kernel['portability']['firmware_network'] = {'ready': False, 'backend': 'systemd-networkd'}
    receipt = {'verified_initrds': {KERNEL: {'path': kernel['initrd'], 'sha256': kernel['initrd_sha256'], 'iscsi_boot': True}}}
    plan = verify_platform(source, options(boot_attachment='iscsi'), receipt=receipt)
    assert not plan['ready']
    assert any('iSCSI boot userspace' in message for message in plan['blockers'])


@pytest.mark.parametrize('backend', ['netplan', 'networkd'])
def test_managed_network_root_handover_and_manual_opt_out(backend):
    files = _network_files(backend, iscsi=True)
    g = Guest(files)
    assert inspect_handover(g, backend, list(files))
    ordinary = _network_files(backend)
    assert not inspect_handover(Guest(ordinary), backend, list(ordinary))
    source = image(); source['platform']['iscsi_network_handover'] = False
    assert not plan_platform(source, options(boot_attachment='iscsi', configure_network=False))['ready']
    assert plan_platform(source, options(boot_attachment='iscsi', configure_network=True))['ready']


def test_nm_root_keeps_inherited_connection_without_high_priority_replacement():
    files = _network_files('NetworkManager', iscsi=True)
    assert 'autoconnect-priority=-999' in files['/etc/NetworkManager/system-connections/cloud-image-forge-oci.nmconnection']
    assert inspect_handover(Guest(files), 'NetworkManager', list(files))
    files['/etc/NetworkManager/conf.d/override.conf'] = '[device]\nkeep-configuration=no\n'
    assert not inspect_handover(Guest(files), 'NetworkManager', list(files))


def test_installing_initrd_nm_does_not_switch_networkd_root_renderer():
    files = _network_files('networkd', iscsi=True)
    files['/etc/systemd/system/multi-user.target.wants/systemd-networkd.service'] = ''
    backend, ready, _ = _network_evidence(Guest(files), {'NetworkManager': True, 'networkctl': True})
    assert backend == 'networkd' and ready


def test_known_dropin_name_does_not_allow_arbitrary_exec_replacement():
    files = network_files()
    files['usr/lib/systemd/system/nm-initrd.service.d/NetworkManager-config-initrd-dracut.conf'] = b'[Service]\nExecStart=/bin/false\n'
    assert not assess(files)['ready']
    files = network_files(); files['usr/lib/systemd/system/nm-initrd.service'] += b'ExecStart=/bin/false\n'
    assert not assess(files)['ready']


def test_network_hook_requires_its_actual_shell_not_incidental_reload_tool():
    files = network_files()
    assert assess(files)['ready']
    files.pop('usr/bin/bash')
    assert not assess(files)['ready']
    files['usr/bin/sh'] = b'ELF'
    files['var/lib/dracut/hooks/initqueue/settled/99-nm-run.sh'] = files['var/lib/dracut/hooks/initqueue/settled/99-nm-run.sh'].replace(b'#!/bin/bash', b'#!/bin/sh')
    assert assess(files)['ready']


def test_modern_nm_initrd_units_need_the_configuration_stage_enabled():
    files = network_files()
    for old, new in [('nm-initrd.service', 'NetworkManager-initrd.service'),
                     ('nm-wait-online-initrd.service', 'NetworkManager-wait-online-initrd.service')]:
        for name in list(files):
            if name.endswith('/' + old):
                files[name[:-len(old)] + new] = files.pop(name)
    files['usr/lib/systemd/system/NetworkManager-config-initrd.service'] = (
        b'[Service]\nExecStart=/bin/sh -c "/usr/lib/nm-initrd-generator -- $(cat /proc/cmdline)"\n'
        b'ExecStartPost=/bin/sh -c "mkdir -p /run/NetworkManager/initrd/neednet"\n')
    assert not assess(files)['ready']
    files['etc/systemd/system/initrd.target.wants/NetworkManager-config-initrd.service'] = b'enabled'
    assert assess(files)['ready'], assess(files)['errors']
    files['etc/systemd/system/NetworkManager-config-initrd.service'] = b'masked'
    assert not assess(files)['ready']


def test_archived_unmanaged_nic_policy_blocks_otherwise_complete_chain():
    files = network_files()
    files['usr/lib/NetworkManager/conf.d/unmanaged.conf'] = b'[keyfile]\nunmanaged-devices=*\n'
    assert not assess(files)['ready']


def test_combined_preview_projects_only_feasible_nm_preparation_and_final_uses_actual():
    import json
    from forge.oci import OciConfig, compatibility_plan
    from test_oci_guest import inspected, VERSION
    source = image()
    source['oci_evidence'] = json.loads(json.dumps(inspected()['oci_evidence']).replace(VERSION, KERNEL))
    source['platform']['tools']['NetworkManager'] = False
    source['platform']['nm_initrd_generator'] = None
    source['platform']['kernels'][KERNEL]['initrd_iscsi_userspace'] = False
    source['platform']['kernels'][KERNEL]['portability']['firmware_network'] = {'ready': False, 'backend': 'systemd-networkd'}
    source['platform']['iscsi_network_handover'] = False
    before = deepcopy(source)
    settings = OciConfig(capabilities={
        'Compute.LaunchMode': {'default_value': 'NATIVE'},
        'Storage.BootVolumeType': {'default_value': 'ISCSI'},
        'Network.AttachmentType': {'default_value': 'VFIO'},
        'Storage.ConsistentVolumeNaming': {'default_value': False}}, guest={'prepare': False, 'install_packages': False})
    profile = options(source='vm', target='bare_metal', boot_attachment='iscsi', network_attachment='vfio',
                      nic_driver='mlx5_core', install_packages=True, configure_network=True)
    preview = compatibility_plan(source, settings, True, platform_migration=profile)
    assert preview['ready_to_build'], preview['blockers']
    assert source == before
    final = compatibility_plan(source, settings, False, platform_migration=profile, project_platform=False)
    assert not final['ready_to_build']
    assert any('firmware iSCSI networking' in error for error in final['blockers'])


@pytest.mark.parametrize('alter', [
    lambda text: text.replace('      critical: true\n', '') + '    other:\n      match:\n        name: "eth9"\n      addresses: [192.0.2.2/24]\n      critical: true\n',
    lambda text: text.replace('      critical: true\n', '') + '      match:\n        critical: true\n',
    lambda text: text + '      critical: false\n',
    lambda text: text + '    other:\n      critical: true\n',
    lambda text: text.replace('      critical: true', '      addresses: [192.0.2.2/24]\n      critical: true'),
    lambda text: text.replace('      critical: true', '      critical: &retention true'),
])
def test_netplan_handover_cannot_borrow_critical_from_other_stanza(alter):
    files = _network_files('netplan', iscsi=True)
    path = next(iter(files)); files[path] = alter(files[path])
    assert not inspect_handover(Guest(files), 'netplan', list(files))


def test_single_custom_named_netplan_profile_can_prove_handover():
    files = _network_files('netplan', iscsi=True)
    path = next(iter(files))
    files[path] = '# Retain the firmware boot connection\n' + files[path].replace('    oci:', '    portable_ethernet:')
    assert inspect_handover(Guest(files), 'netplan', list(files))


@pytest.mark.parametrize('alter', [
    lambda text: text.replace('KeepConfiguration=yes\n', '') + 'KeepConfiguration=yes\n',
    lambda text: text.replace('[Network]\n', 'KeepConfiguration=yes\n[Network]\n').replace('IPv6AcceptRA=yes\nKeepConfiguration=yes', 'IPv6AcceptRA=yes'),
    lambda text: text.replace('KeepConfiguration=yes', 'KeepConfiguration=yes\nKeepConfiguration=no'),
    lambda text: '[DEFAULT]\nKeepConfiguration=yes\n' + text.replace('KeepConfiguration=yes\n', ''),
])
def test_networkd_handover_requires_unique_network_section_policy(alter):
    files = _network_files('networkd', iscsi=True)
    path = next(iter(files)); files[path] = alter(files[path])
    assert not inspect_handover(Guest(files), 'networkd', list(files))
