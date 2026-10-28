"""Conservative bootstrap evidence must not turn disabled/unknown guests green."""
import fnmatch
import hashlib

import pytest

from forge import cloud_bootstrap as bootstrap


class Guest:
    def __init__(self):
        self.files = {}
        self.links = {}
        self.reads = []

    def resolve(self, path):
        return self.links.get(path, path)

    def is_file(self, path):
        return self.resolve(path) in self.files

    def is_dir(self, path):
        return False

    def is_symlink(self, path):
        return path in self.links

    def readlink(self, path):
        return self.links[path]

    def read_file(self, path):
        self.reads.append(path)
        return self.files[self.resolve(path)].encode()

    def filesize(self, path):
        return len(self.files[self.resolve(path)].encode())

    def statns(self, path):
        return {"st_mode": 0o100755}

    def glob_expand(self, pattern):
        return sorted(p for p in self.files.keys() | self.links.keys() if fnmatch.fnmatchcase(p, pattern))


@pytest.fixture
def reviewed(monkeypatch):
    g = Guest()
    root = "/usr/lib/python3.9/site-packages/cloudinit"
    sources = {}
    for relative in bootstrap.SOURCE_HASHES:
        text = "# reviewed packaged source " + relative
        g.files[root + "/" + relative] = text
        sources[relative] = hashlib.sha256(text.encode()).hexdigest()
    units = {}
    for name in bootstrap.UNIT_HASHES:
        text = "[Unit]\nDescription=Reviewed " + name + "\n"
        path = "/usr/lib/systemd/system/" + name
        g.files[path] = text
        units[name] = hashlib.sha256(text.encode()).hexdigest()
        g.links["/etc/systemd/system/cloud-init.target.wants/" + name] = path
    g.files.setdefault("/usr/lib/systemd/system/NetworkManager.service", "[Service]\n")
    g.links["/etc/systemd/system/multi-user.target.wants/NetworkManager.service"] = "/usr/lib/systemd/system/NetworkManager.service"
    for name in ("dhclient", "ip", "NetworkManager"):
        g.files["/usr/sbin/" + name] = "executable fixture"
    g.files["/etc/cloud/cloud.cfg"] = "# no bootstrap override\n"
    g.files["/etc/cloud/cloud.cfg.d/99_oci.cfg"] = "datasource_list: [Oracle, OpenStack]\n"
    profile = "/etc/sysconfig/network-scripts/ifcfg-oldnic"
    g.files[profile] = '# Created by cloud-init automatically, do not edit.\nBOOTPROTO=dhcp\nONBOOT=yes\nDEVICE=oldnic\nHWADDR=00:00:00:00:00:01\n'
    base = {"tools": {"cloud-init": True}, "oracle_datasource": True, "network_backend": "NetworkManager",
            "boot_arguments": "root=/dev/mapper/vg-root netroot=iscsi rd.iscsi.firmware=1", "network_files": [profile]}
    monkeypatch.setattr(bootstrap, "SOURCE_HASHES", sources)
    monkeypatch.setattr(bootstrap, "UNIT_HASHES", units)
    return g, base


def test_reviewed_path_retains_mac_bound_generated_profile_without_reading_cache(reviewed):
    g, base = reviewed
    g.files["/var/lib/cloud/instance/obj.pkl"] = "not safe to deserialize"
    g.files["/var/lib/cloud/instance/user-data.txt"] = "private"
    result = bootstrap.inspect_bootstrap(g, base)
    assert result["ready"] and result["mechanism"] == "oracle_cloud_init"
    assert not any("/var/lib/cloud/" in p for p in g.reads)
    assert "/etc/sysconfig/network-scripts/ifcfg-oldnic" in result["files"]
    assert any("UUID" in line for line in result["evidence"])


@pytest.mark.parametrize("override", [
    "manual_cache_clean: true\n", "disable_network_activation: true\n", "disable_fallback_netcfg: true\n",
    "network: {config: disabled}\n", "network:\n  config: disabled\n", "datasource_list: [None]\n",
])
def test_effective_disable_overrides_block(reviewed, override):
    g, base = reviewed
    g.files["/etc/cloud/cloud.cfg.d/zz-policy.cfg"] = override
    result = bootstrap.inspect_bootstrap(g, base)
    assert result["status"] == "blocked" and not result["ready"]


def test_later_simple_override_can_restore_default_cache_check(reviewed):
    g, base = reviewed
    g.files["/etc/cloud/cloud.cfg.d/01-cache.cfg"] = "manual_cache_clean: true\n"
    g.files["/etc/cloud/cloud.cfg.d/99-cache.cfg"] = "manual_cache_clean: false # reviewed override\n"
    assert bootstrap.inspect_bootstrap(g, base)["ready"]


@pytest.mark.parametrize("value", ["false", "true"])
def test_literal_ssh_password_policy_does_not_change_network_bootstrap(reviewed, value):
    g, base = reviewed
    path = "/etc/cloud/cloud.cfg.d/zz-cloud-image-forge-ssh.cfg"
    g.files[path] = "# Cloud Image Forge: retain SSH key authentication.\nssh_pwauth: " + value + "\n"
    result = bootstrap.inspect_bootstrap(g, base)
    assert result["ready"] and result["mechanism"] == "oracle_cloud_init"
    assert path in result["files"]


@pytest.mark.parametrize("text", [
    "ssh_pwauth: false\nssh_pwauth: true\n",
    "ssh_pwauth: false\nssh_pwauth: false\n",
    'ssh_pwauth: "false"\n', "ssh_pwauth: False\n", "ssh_pwauth: no\n",
    "ssh_pwauth: !!bool false\n", "ssh_pwauth: *policy\n",
    "ssh_pwauth: false\nwrite_files: []\n",
])
def test_ssh_policy_does_not_admit_unsupported_or_duplicate_yaml(reviewed, text):
    g, base = reviewed
    g.files["/etc/cloud/cloud.cfg.d/zz-cloud-image-forge-ssh.cfg"] = text
    result = bootstrap.inspect_bootstrap(g, base)
    assert result["status"] == "unknown" and not result["ready"]


def test_ssh_policy_does_not_override_network_bootstrap_blocker(reviewed):
    g, base = reviewed
    g.files["/etc/cloud/cloud.cfg.d/zz-cloud-image-forge-ssh.cfg"] = (
        "#cloud-config\nssh_pwauth: false\ndisable_network_activation: true\n"
    )
    result = bootstrap.inspect_bootstrap(g, base)
    assert result["status"] == "blocked" and not result["ready"]


@pytest.mark.parametrize("text", [
    "network:\n  version: 2\n  ethernets: {}\n", "network: *alias\n", "<<: *defaults\n",
    "manual_cache_clean: !!bool false\n", "manual_cache_clean: false\nmanual_cache_clean: true\n",
    "datasource_list:\n - Oracle\n", "write_files:\n - path: /etc/example\n",
])
def test_unknown_yaml_and_static_overrides_never_pass(reviewed, text):
    g, base = reviewed
    g.files["/etc/cloud/cloud.cfg.d/zz-custom.cfg"] = text
    result = bootstrap.inspect_bootstrap(g, base)
    assert result["status"] == "unknown" and not result["ready"]


@pytest.mark.parametrize("path", ["/etc/cloud/cloud-init.disabled", "/var/lib/cloud/instance/manual-clean"])
def test_disable_and_cache_trust_markers_block_without_reading_contents(reviewed, path):
    g, base = reviewed
    g.files[path] = "not inspected"
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "blocked"
    assert path not in g.reads


def test_same_module_name_with_unreviewed_behavior_is_unknown(reviewed):
    g, base = reviewed
    path = "/usr/lib/python3.9/site-packages/cloudinit/sources/DataSourceOracle.py"
    g.files[path] += "\nperform_dhcp_setup = False\n"
    result = bootstrap.inspect_bootstrap(g, base)
    assert result["status"] == "unknown"
    assert any("implementation" in message for message in result["blockers"])


def test_masked_or_not_enabled_service_fails(reviewed):
    g, base = reviewed
    g.links["/etc/systemd/system/cloud-init-local.service"] = "/dev/null"
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "blocked"
    del g.links["/etc/systemd/system/cloud-init-local.service"]
    del g.links["/etc/systemd/system/cloud-init.target.wants/cloud-init-local.service"]
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "blocked"


def test_unit_dropin_and_global_commandline_override_are_unknown(reviewed):
    g, base = reviewed
    g.files["/etc/systemd/system/cloud-init-local.service.d/override.conf"] = "[Service]\nEnvironment=KERNEL_CMDLINE=cloud-init=disabled\n"
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"
    del g.files["/etc/systemd/system/cloud-init-local.service.d/override.conf"]
    g.files["/etc/systemd/system.conf"] = "[Manager]\nDefaultEnvironment=KERNEL_CMDLINE=cloud-init=disabled\n"
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"


def test_missing_dhcp_tool_blocks_before_future_boot(reviewed):
    g, base = reviewed
    del g.files["/usr/sbin/dhclient"]
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "blocked"


def test_network_manager_command_override_does_not_pass(reviewed):
    g, base = reviewed
    g.files["/etc/systemd/system/NetworkManager.service.d/override.conf"] = "[Service]\nExecStart=\nExecStart=/bin/false\n"
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"


def test_changed_vendor_renderer_unit_is_unknown(reviewed):
    g, base = reviewed
    g.files["/usr/lib/systemd/system/NetworkManager.service"] += "ExecStart=/bin/false\n"
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"


def test_nonautomatic_generic_profile_is_not_a_bootstrap_path(reviewed):
    g, base = reviewed
    path = "/etc/NetworkManager/system-connections/manual.nmconnection"
    g.files[path] = "[connection]\ntype=ethernet\nautoconnect=false\n[ipv4]\nmethod=auto\n"
    base["network_files"] = [path]
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"


def test_service_environment_file_cannot_override_reviewed_unit(reviewed, monkeypatch):
    g, base = reviewed
    unit = "NetworkManager.service"
    path = "/usr/lib/systemd/system/" + unit
    g.files[path] += "EnvironmentFile=-/etc/sysconfig/NetworkManager\n"
    monkeypatch.setitem(bootstrap.UNIT_HASHES, unit, hashlib.sha256(g.files[path].encode()).hexdigest())
    g.files["/etc/sysconfig/NetworkManager"] = "KERNEL_CMDLINE=cloud-init=disabled\n"
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"


def test_manual_static_profile_does_not_inherit_cloud_init_proof(reviewed):
    g, base = reviewed
    g.files[base["network_files"][0]] += "IPADDR=192.0.2.2\n"
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"


@pytest.mark.parametrize("args,status", [("cloud-init=disabled", "blocked"), ("network-config=disabled", "blocked"), ("ip=dhcp", "unknown")])
def test_kernel_overrides_require_explicit_evidence(reviewed, args, status):
    g, base = reviewed
    base["boot_arguments"] = args
    assert bootstrap.inspect_bootstrap(g, base)["status"] == status


def test_inspection_failure_is_unknown_and_never_breaks_image_import(reviewed):
    g, base = reviewed
    g.glob_expand = lambda pattern: (_ for _ in ()).throw(RuntimeError("unavailable"))
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"


def test_bounded_read_rejects_oversized_config(reviewed):
    g, base = reviewed
    g.files["/etc/cloud/cloud.cfg"] = "#" * (bootstrap.LIMIT + 1)
    assert bootstrap.inspect_bootstrap(g, base)["status"] == "unknown"
