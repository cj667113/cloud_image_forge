"""Bounded evidence for the firmware-network stage of dracut iSCSI boot.

A storage discovery helper does not configure the boot NIC. NetworkManager's
initrd generator reads iBFT; systemd-network-generator's DHCP fallback does not.
No firmware table, IP address or credentials are invented by this module.
"""
from __future__ import annotations

import re
import hashlib
import configparser

NM_GENERATORS = ('/usr/libexec/nm-initrd-generator', '/usr/lib/nm-initrd-generator')
NM_KEEP = '/etc/NetworkManager/conf.d/zz-cloud-image-forge-iscsi.conf'
NM_KEEP_TEXT = '[device-forge-iscsi]\nmatch-device=type:ethernet\nkeep-configuration=yes\n'
KNOWN_DRACUT_DROPS = {'NetworkManager-config-initrd-dracut.conf': '7fdb319063625dfcaa67792019e78d5660c1619df3a916a26e7947e4f3474e72', 'NetworkManager-wait-online-initrd-dracut.conf': 'a850b73dd2169f23f8f70e220edf49cacb5a3500e232016ae0460988caba95b9'}
UNIT_NAMES = ('nm-initrd.service', 'nm-wait-online-initrd.service',
              'NetworkManager-config-initrd.service', 'NetworkManager-initrd.service',
              'NetworkManager-wait-online-initrd.service')


def retained(name):
    return (name in {'lib/nm-lib.sh', 'usr/lib/nm-lib.sh',
                    'usr/lib/systemd/system-generators/nm-initrd-generator.sh',
                    'lib/systemd/system-generators/nm-initrd-generator.sh',
                    'lib/net-lib.sh', 'usr/lib/net-lib.sh', 'sbin/ifup', 'usr/sbin/ifup',
                    'etc/NetworkManager/NetworkManager.conf'}
            or bool(re.fullmatch(r'(?:etc|usr/lib)/NetworkManager/conf\.d/[^/]+\.conf', name))
            or bool(re.fullmatch(r'(?:(?:usr|var)/)?lib/dracut/hooks/(?:cmdline/[0-9]+-(?:nm-config|parse-ip-opts)\.sh|initqueue/settled/[0-9]+-nm-run\.sh)', name))
            or bool(re.fullmatch(r'(?:usr/)?lib/systemd/system/(?:nm-(?:wait-online-)?initrd|NetworkManager-(?:config-|wait-online-)?initrd)\.service(?:\.d/[^/]+\.conf)?', name)))


def _text(g, path, name):
    value = g.initrd_cat(path, name)
    if len(value) > 256 * 1024:
        raise ValueError('Firmware networking evidence exceeds the text limit')
    value = value.decode('utf-8') if isinstance(value, bytes) else value
    if '\0' in value:
        raise ValueError('Binary firmware networking configuration')
    return '\n'.join(line for line in value.splitlines() if not line.lstrip().startswith(('#', ';')))


def inspect_archive_network(g, path, members):
    result = {'version': 1, 'ready': False, 'backend': None, 'errors': []}
    names = {name.removeprefix('./').lstrip('/') for name in members}
    all_names = names | set(getattr(g, 'links', {})) | set(getattr(g, 'members', {}))
    def present(*paths):
        return next((name for name in paths if name in names), None)
    def text(*paths):
        name = present(*paths)
        return _text(g, path, name) if name else ''
    def hook(kind, leaf):
        found = sorted(name for name in names if re.fullmatch(r'(?:(?:usr|var)/)?lib/dracut/hooks/' + kind + r'/[0-9]+-' + leaf + r'\.sh', name))
        return _text(g, path, found[0]) if len(found) == 1 else ''
    def unit(name):
        # An unmodelled override or mask can bypass a valid vendor unit.
        if any(re.fullmatch(r'(?:etc|run)/systemd/system/' + re.escape(name) + r'(?:\.d/.*)?', item) for item in all_names):
            raise ValueError('Initrd network unit has a persistent override or mask: ' + name)
        return text('usr/lib/systemd/system/' + name, 'lib/systemd/system/' + name)
    def enabled(name):
        return any('etc/systemd/system/' + target + '.wants/' + name in names
                   for target in ('initrd.target', 'network-online.target', 'sysinit.target'))
    try:
        modules = set(text('usr/lib/dracut/modules.txt', 'lib/dracut/modules.txt').split())
        if 'network-manager' not in modules:
            result['backend'] = 'systemd-networkd' if 'systemd-networkd' in modules else 'network-legacy' if 'network-legacy' in modules else None
            # Retain a legacy chain only when the archived parser actually calls
            # its iBFT translator and the networking helper includes the reader.
            legacy = hook('cmdline', 'parse-ip-opts')
            library = text('lib/net-lib.sh', 'usr/lib/net-lib.sh')
            if ('network-legacy' in modules and re.search(r'(?m)^\s*(?:.*&&\s*)?ibft_to_cmdline(?:\s|$)', legacy)
                    and 'rd.iscsi.ibft' in legacy and '/sys/firmware/ibft' in library
                    and re.search(r'ibft_to_cmdline\s*\(\)', library)
                    and present('sbin/ifup', 'usr/sbin/ifup')):
                result['ready'] = True
                return result
            raise ValueError('Firmware NIC configuration is unverified: require an archived NetworkManager iBFT generator and its active initrd chain; DHCP-only systemd-networkd is insufficient')
        result['backend'] = 'network-manager'
        for name in sorted(name for name in names if name == 'etc/NetworkManager/NetworkManager.conf'
                           or re.fullmatch(r'(?:etc|usr/lib)/NetworkManager/conf\.d/[^/]+\.conf', name)):
            conf = _text(g, path, name)
            if re.search(r'^\s*(?:unmanaged-devices\s*=\s*\S|managed\s*=\s*(?:no|false|0)\b)', conf, re.M):
                raise ValueError('Archived NetworkManager configuration can leave the boot NIC unmanaged')
        if 'systemd-networkd' in modules or 'network-legacy' in modules:
            raise ValueError('Competing initrd network backends are present')
        required = [('usr/sbin/NetworkManager', 'sbin/NetworkManager'),
                    ('usr/libexec/nm-initrd-generator', 'usr/lib/nm-initrd-generator'),
                    ('usr/bin/nm-online', 'bin/nm-online')]
        if any(not present(*alternatives) for alternatives in required):
            raise ValueError('NetworkManager initrd daemon, iBFT generator, online helper or shell is missing')
        if any(re.fullmatch(r'(?:etc|run|usr/lib|lib)/systemd/system/service\.d/.+', name) for name in all_names):
            raise ValueError('Global initrd service overrides are unverified')
        # The exact hook interpreter is a dependency; nmcli is incidental to
        # optional reload operations and does not gate the boot chain.
        run_paths = [name for name in names if re.fullmatch(r'(?:(?:usr|var)/)?lib/dracut/hooks/initqueue/settled/[0-9]+-nm-run\.sh', name)]
        if len(run_paths) == 1:
            raw = g.initrd_cat(path, run_paths[0])
            first = (raw.decode('utf-8') if isinstance(raw, bytes) else raw).splitlines()[0]
            if first.startswith('#!'):
                interpreter = first[2:].strip()
                if interpreter not in {'/bin/bash', '/bin/sh', '/usr/bin/bash', '/usr/bin/sh'} or not present(interpreter.lstrip('/'), 'usr/' + interpreter.lstrip('/')):
                    raise ValueError('Archived network online hook interpreter is missing or unsupported')
        run = hook('initqueue/settled', 'nm-run')
        config = hook('cmdline', 'nm-config')
        library = text('lib/nm-lib.sh', 'usr/lib/nm-lib.sh')
        if not (re.search(r'source_hook\s+initqueue/online\s+', run)
                and re.search(r'/sbin/netroot\s+', run) and '/run/NetworkManager/devices/' in run
                and 'connection-uuid=' in run and 'nm_generate_connections' in config):
            raise ValueError('Archived NetworkManager config/online-to-iSCSI hooks are incomplete')
        if not ('nm-initrd-generator -- $(getcmdline)' in library
                and '/run/NetworkManager/initrd/neednet' in library):
            raise ValueError('Archived NetworkManager command-line generator invocation is unverified')
        if 'systemd' not in modules:
            if '--configure-and-quit=initrd' not in run or '--no-daemon' not in run:
                raise ValueError('Non-systemd NetworkManager startup is unverified')
        else:
            if not present('usr/share/dbus-1/system.d/org.freedesktop.NetworkManager.conf',
                           'etc/dbus-1/system.d/org.freedesktop.NetworkManager.conf'):
                raise ValueError('Initrd NetworkManager D-Bus policy is missing')
            if not present('usr/lib/systemd/system/dbus.service', 'lib/systemd/system/dbus.service',
                           'etc/systemd/system/dbus.service'):
                raise ValueError('Initrd D-Bus service is missing')
            modern = present('usr/lib/systemd/system/NetworkManager-initrd.service', 'lib/systemd/system/NetworkManager-initrd.service')
            daemon = 'NetworkManager-initrd.service' if modern else 'nm-initrd.service'
            waiter = 'NetworkManager-wait-online-initrd.service' if modern else 'nm-wait-online-initrd.service'
            daemon_text, wait_text = unit(daemon), unit(waiter)
            for content in (daemon_text, wait_text):
                if len(re.findall(r'^\s*ExecStart=', content, re.M)) != 1 or re.search(r'^\s*(?:ExecStartPre|ExecStartPost|RootDirectory|RootImage|BindPaths|BindReadOnlyPaths)=', content, re.M):
                    raise ValueError('Unrecognized initrd network service launch override')
            if not (re.search(r'^ExecStart=(?:/usr)?/sbin/NetworkManager\b', daemon_text, re.M)
                    and ('NM_CONFIG_ENABLE_TAG=initrd' in daemon_text or '--configure-and-quit=initrd' in daemon_text)
                    and re.search(r'^ExecStart=(?:/usr)?/bin/nm-online\b.*(?: -s| --wait-for-startup)', wait_text, re.M)):
                raise ValueError('Initrd NetworkManager daemon/wait service commands are unverified')
            generated_activation = False
            if modern:
                cfg = unit('NetworkManager-config-initrd.service')
                drops = sorted(name for name in names if '/NetworkManager-config-initrd.service.d/' in name)
                if len(drops) > 8:
                    raise ValueError('Too many initrd network unit overrides')
                cfg += '\n' + '\n'.join(_text(g, path, name) for name in drops)
                if not ('nm-initrd-generator' in cfg and '/run/NetworkManager/initrd/neednet' in cfg):
                    raise ValueError('NetworkManager initrd configuration service is unverified')
                generator = text('usr/lib/systemd/system-generators/nm-initrd-generator.sh', 'lib/systemd/system-generators/nm-initrd-generator.sh')
                generated_activation = bool('SYSTEMD_IN_INITRD' in generator and 'initrd.target.wants' in generator
                                            and 'NetworkManager-initrd.service' in generator
                                            and 'NetworkManager-wait-online-initrd.service' in generator)
            if not generated_activation and not (enabled(daemon) and enabled(waiter) and (not modern or enabled('NetworkManager-config-initrd.service'))):
                raise ValueError('NetworkManager initrd services are not enabled')
            allowed_drops = KNOWN_DRACUT_DROPS
            for name in names:
                if any('/' + unit_name + '.d/' in name for unit_name in UNIT_NAMES):
                    digest = hashlib.sha256(_text(g, path, name).encode()).hexdigest()
                    if digest != allowed_drops.get(name.rsplit('/', 1)[-1]):
                        raise ValueError('Unrecognized initrd NetworkManager service drop-in')
        result['ready'] = True
    except (RuntimeError, ValueError, UnicodeError, AttributeError, TypeError) as exc:
        result['errors'].append(str(exc))
    return result


def installed_generator(g):
    for path in NM_GENERATORS:
        try:
            if g.is_file(path):
                return path
        except (RuntimeError, AttributeError):
            pass
    return None


def plan_network(evidence, *, install, allow_network, rpm):
    tools = evidence.get('tools', {})
    modules = set(evidence.get('dracut_modules', []))
    packages, blockers = set(), []
    if 'iscsi' not in modules or 'network-manager' not in modules:
        if install and allow_network:
            packages.add('dracut-network')
        else:
            blockers.append('Firmware iSCSI needs dracut-network with its NetworkManager module; allow required package installation or install it first.')
    if not tools.get('NetworkManager') or not evidence.get('nm_initrd_generator'):
        if install and allow_network:
            packages.add('NetworkManager' if rpm else 'network-manager')
        else:
            blockers.append('Firmware iSCSI needs NetworkManager and nm-initrd-generator; enable required package installation or install them and refresh inspection.')
    return {'module': 'network-manager', 'packages': sorted(packages), 'blockers': blockers}



def _profile_handover(content, backend):
    """Admit the small, unambiguous managed profile shape, not arbitrary YAML.

A custom profile name, comments and mapping order may differ. Multiple NICs,
static stanzas, duplicate keys, YAML aliases/flow syntax and unknown nesting
remain unverified rather than borrowing another interface's critical flag.
"""
    if backend == 'netplan':
        tree, stack = {}, [(-1, {})]
        stack[0] = (-1, tree)
        for line in content.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            match = re.fullmatch(r'( *)([A-Za-z0-9_.-]+):(?: +([^\r\n]+))?', line.rstrip())
            if not match:
                return False
            indent, key, value = len(match[1]), match[2], match[3]
            while len(stack) > 1 and indent <= stack[-1][0]:
                stack.pop()
            parent = stack[-1][1]
            if indent != stack[-1][0] + (1 if len(stack) == 1 else 2) or key in parent:
                return False
            parent[key] = value if value is not None else {}
            if value is None:
                stack.append((indent, parent[key]))
            if len(stack) > 6:
                return False
        network = tree.get('network')
        if set(tree) != {'network'} or not isinstance(network, dict):
            return False
        if set(network) - {'version', 'renderer', 'ethernets'} or network.get('version') != '2' or network.get('renderer', 'networkd') != 'networkd':
            return False
        profiles = network.get('ethernets')
        if not isinstance(profiles, dict) or len(profiles) != 1:
            return False
        profile = next(iter(profiles.values()))
        if not isinstance(profile, dict) or set(profile) - {'match', 'dhcp4', 'dhcp6', 'accept-ra', 'optional', 'critical'}:
            return False
        match = profile.get('match')
        if not isinstance(match, dict) or set(match) != {'name'}:
            return False
        name = match['name']
        if name not in {'e*', 'en*', 'eth*', '"e*"', '"en*"', '"eth*"', "'e*'", "'en*'", "'eth*'"}:
            return False
        return (all(profile.get(key) == 'true' for key in ('critical', 'dhcp4', 'dhcp6'))
                and profile.get('accept-ra', 'true') == 'true'
                and profile.get('optional', 'false') in {'true', 'false'})
    if backend != 'networkd':
        return False
    parser = configparser.ConfigParser(interpolation=None, strict=True, delimiters=('=',))
    parser.optionxform = str
    try:
        parser.read_string(content)
    except configparser.Error:
        return False
    if parser.defaults() or set(parser.sections()) - {'Match', 'Network', 'Link', 'DHCP', 'DHCPv4', 'DHCPv6'}:
        return False
    if any('KeepConfiguration' in parser[section] for section in parser.sections() if section != 'Network'):
        return False
    return (set(parser['Match']) == {'Name'} if parser.has_section('Match') else False) and (
        parser.get('Match', 'Name') in {'e*', 'en*', 'eth*', 'en* eth*'}
        and parser.get('Network', 'KeepConfiguration', fallback='') in {'yes', 'true'}
        and parser.get('Network', 'DHCP', fallback='') in {'yes', 'true'}
        and parser.get('Network', 'IPv6AcceptRA', fallback='') in {'yes', 'true'})


def inspect_handover(g, backend, paths):
    """Require an explicit keep policy for networkd; NM retains initrd state.

The surrounding network inspector proves the profile set/renderer. This is
additional connection-retention evidence, not proof of firmware or connectivity.
"""
    def read(path):
        if g.filesize(path) > 256 * 1024:
            raise ValueError('Oversized network configuration')
        value = g.read_file(path)
        return value.decode('utf-8') if isinstance(value, bytes) else value
    try:
        if backend == 'NetworkManager':
            configs = sorted(set(g.glob_expand('/etc/NetworkManager/conf.d/*.conf')
                                 + g.glob_expand('/usr/lib/NetworkManager/conf.d/*.conf')
                                 + (['/etc/NetworkManager/NetworkManager.conf'] if g.is_file('/etc/NetworkManager/NetworkManager.conf') else [])))
            if len(configs) > 64:
                return False
            # Defaults keep configured interfaces, but an explicit conflicting
            # device policy must not be waived by our own later snippet.
            return not any(re.search(r'^\s*keep-configuration\s*=\s*(?:no|false|0)\s*$', read(path), re.M) for path in configs)
        selected = [path for path in paths if path.endswith(('.yaml', '.yml') if backend == 'netplan' else '.network')]
        if len(selected) != 1:
            return False
        content = read(selected[0])
        return _profile_handover(content, backend)
    except (RuntimeError, ValueError, UnicodeError, AttributeError):
        return False
