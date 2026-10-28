"""SSH key framing, configuration precedence and immutable verification tests."""
import base64
from contextlib import contextmanager
import fnmatch
import hashlib
import os
from pathlib import PurePosixPath, Path
import struct
import subprocess
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from forge.models import Recipe, SSHAccess
from forge.ssh_access import (CLOUD_POLICY, CLOUD_TEXT, CONFIG, POLICY, _native_script, _run_native, _sudo_denial_check, _native_relabel_flags,
                              _policy_check, _state, apply_access, config_graph,
                              disable_passwords, inspect_access, merge_keys,
                              plan_access, validate_public_key, verify_access)


def wire(*fields):
    return b"".join(struct.pack(">I", len(field)) + field for field in fields)


def key(seed=1):
    return "ssh-ed25519 " + base64.b64encode(wire(b"ssh-ed25519", bytes([seed]) * 32)).decode() + " fixture"


class Guest:
    def __init__(self):
        self.files = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nopc:x:1000:1000::/home/opc:/bin/bash\ndaemon:x:2:2::/:/usr/sbin/nologin\n",
            "/etc/group": "root:x:0:\nopc:x:1000:\n",
            "/etc/shadow": "root:*:20000:0:99999:7:::\nopc:*:20000:0:99999:7:::\n",
            CONFIG: "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nUsePAM yes\n",
            "/etc/ssh/sshd_config.d/50-default.conf": "Match User opc\n  PasswordAuthentication yes\n  KbdInteractiveAuthentication yes\nMatch all\n",
            "/usr/lib/systemd/system/sshd.service": "[Service]\nExecStart=/usr/sbin/sshd -D $OPTIONS\nEnvironmentFile=-/etc/sysconfig/sshd\n",
            "/etc/sysconfig/sshd": '# Sample\nOPTIONS=""\n',
            "/usr/sbin/sshd": "binary", "/bin/bash": "binary",
            "/etc/cloud/cloud.cfg": "users:\n - default\nssh_pwauth: true\n",
        }
        self.dirs = {"/", "/root", "/home", "/home/opc", "/etc", "/etc/ssh", "/etc/ssh/sshd_config.d", "/etc/cloud", "/etc/cloud/cloud.cfg.d", "/run"}
        for name in self.files:
            self.dirs.update(str(parent) for parent in PurePosixPath(name).parents)
        self.links = {}
        self.meta = {"/home/opc": {"st_mode": 0o40755, "st_uid": 1000, "st_gid": 1000, "st_nlink": 1}}
        self.reads, self.writes = [], []
        self.xattrs, self.relabels, self.native_commands = {}, [], []

    def exists(self, path): return path in self.files or path in self.dirs or path in self.links
    def is_file(self, path): return path in self.files
    def is_dir(self, path): return path in self.dirs
    def is_symlink(self, path): return path in self.links
    def readlink(self, path): return self.links[path]
    def realpath(self, path): return self.links.get(path, path)
    def filesize(self, path): return len(self.files[path].encode())
    def checksum(self, algorithm, path): return hashlib.new(algorithm, self.files[path].encode()).hexdigest()
    def glob_expand(self, pattern): return sorted(path for path in self.files if fnmatch.fnmatchcase(path, pattern))
    def read_file(self, path):
        self.reads.append(path)
        return self.files[path].encode()
    def statns(self, path):
        assert self.exists(path), path
        return self.meta.get(path, {"st_mode": 0o40755 if self.is_dir(path) else 0o100644, "st_uid": 0, "st_gid": 0, "st_nlink": 1}).copy()
    def mkdir_p(self, path):
        self.dirs.add(path)
        self.dirs.update(str(parent) for parent in PurePosixPath(path).parents)
    def write(self, path, value):
        self.writes.append(path)
        self.files[path] = value.decode()
    def chmod(self, mode, path):
        self.meta[path] = {**self.statns(path), "st_mode": mode}
    def chown(self, uid, gid, path):
        self.meta[path] = {**self.statns(path), "st_uid": uid, "st_gid": gid}
    def expected_context(self, path):
        kind = "ssh_home_t" if "/.ssh" in path else "user_home_dir_t" if path.startswith("/home/") else "shadow_t" if "shadow" in path else "etc_t"
        return "system_u:object_r:" + kind + ":s0"
    def selinux_relabel(self, policy, path, force=False):
        assert policy == "/etc/selinux/targeted/contexts/files/file_contexts" and force
        self.relabels.append(path)
        for name in {*self.dirs, *self.files}:
            if name == path or name.startswith(path + "/"):
                self.xattrs[name] = self.expected_context(name).encode() + b"\0"
    def command(self, args):
        self.native_commands.append(args)
        assert args[:2] == ["/usr/sbin/matchpathcon", "-n"]
        return self.expected_context(args[2]) + "\n"
    def lgetxattr(self, path, name):
        assert name == "security.selinux"
        if path not in self.xattrs:
            raise RuntimeError("No data available")
        return self.xattrs[path]
    def lsetxattr(self, name, value, length, path):
        assert name == "security.selinux" and length == len(value.encode())
        self.xattrs[path] = value.encode()


def options(**changes):
    return {"disable_password_auth": True, "users": [{"username": "opc", "create": False, "authorized_keys": [key(2)]}], **changes}


def inspection(g, arch="x86_64"):
    return {"os": {"arch": arch}, "ssh_access": inspect_access(g)}


@pytest.mark.parametrize("bad", ["-----BEGIN OPENSSH PRIVATE KEY-----", "from=\"example\" " + key(), key() + "\ncommand=x",
                                 key() + "\r", key() + "\0", key().replace("ssh-ed25519 ", "ssh-rsa "),
                                 "ssh-ed25519 !!!", "ssh-ed25519 " + base64.b64encode(wire(b"ssh-ed25519", b"short")).decode(),
                                 key() + "x" * 16384])
def test_invalid_public_keys_rejected_without_echo(bad):
    with pytest.raises(ValueError) as exc:
        validate_public_key(bad)
    assert bad not in str(exc.value)


def test_key_wire_trailing_and_truncation_rejected():
    for raw in (wire(b"ssh-ed25519", b"x" * 32) + b"extra", wire(b"ssh-ed25519") + b"\xff\xff\xff\xff"):
        with pytest.raises(ValueError):
            validate_public_key("ssh-ed25519 " + base64.b64encode(raw).decode())


def test_supported_rsa_and_ecdsa_wire_shapes():
    rsa = "ssh-rsa " + base64.b64encode(wire(b"ssh-rsa", b"\x01\0\x01", b"\0\x80" + b"\x01" * 255)).decode()
    assert validate_public_key(rsa) == rsa
    short = "ssh-rsa " + base64.b64encode(wire(b"ssh-rsa", b"\x01\0\x01", b"\0\x80" + b"\x01" * 127)).decode()
    with pytest.raises(ValueError, match="2048"):
        validate_public_key(short)
    for curve, length in (("nistp256", 65), ("nistp384", 97), ("nistp521", 133)):
        name = "ecdsa-sha2-" + curve
        value = name + " " + base64.b64encode(wire(name.encode(), curve.encode(), b"\x04" + b"\1" * (length - 1))).decode()
        assert validate_public_key(value) == value


def test_recipe_bounds_and_empty_policy_default():
    assert Recipe().ssh_access is None
    assert Recipe(ssh_access={"disable_password_auth": True}).ssh_access.users == []
    for value in ({"users": [{"username": "bad/name", "authorized_keys": [key()]}]},
                  {"users": [{"username": "opc", "authorized_keys": []}]},
                  {"disable_password_auth": "true"},
                  {"users": [{"username": "root", "create": True, "authorized_keys": [key()]}]},
                  {"users": options()["users"] * 2},
                  {"users": [{"username": "opc", "authorized_keys": [key()] * 33}]},
                  {"password": "forbidden"}):
        with pytest.raises(ValidationError):
            SSHAccess.model_validate(value)


def test_existing_options_and_duplicate_key_restrictions_retained_byte_for_byte():
    existing = '# retained comment\ncommand="echo restricted",no-pty ' + key() + "\n"
    value, count = merge_keys(existing, [key().replace(" fixture", " renamed"), key(2), key(2)])
    assert count == 1 and value.startswith(existing)
    assert value.count(key().split()[1]) == 1
    assert value.endswith(key(2) + "\n")


def test_existing_last_line_without_newline_preserved():
    value, count = merge_keys(key(), [key(2)])
    assert value == key() + "\n" + key(2) + "\n" and count == 1


def test_inspection_is_readonly_and_never_reads_any_authorized_or_private_keys():
    g = Guest()
    g.files["/root/.ssh/authorized_keys"] = "do not read"
    g.files["/etc/ssh/ssh_host_rsa_key"] = "do not read"
    result = inspect_access(g)
    assert [user["username"] for user in result["users"]] == ["root", "opc"]
    assert result["sshd_present"] and result["config_present"] and not result["errors"]
    assert not g.writes
    assert not any("authorized_keys" in path or "ssh_host" in path for path in g.reads)


def test_missing_ssh_and_partial_inventory_do_not_break_import():
    g = Guest()
    del g.files["/usr/sbin/sshd"]
    assert inspect_access(g)["warnings"]
    g.files["/etc/passwd"] = "malformed"
    assert inspect_access(g)["errors"]


def test_global_and_all_nested_match_password_settings_are_rewritten():
    g = Guest()
    g.files["/etc/ssh/sshd_config.d/50-default.conf"] += "Match Address 10.0.0.0/8\n Include nested.conf\n"
    g.files["/etc/ssh/nested.conf"] = "ChallengeResponseAuthentication yes\n"
    files, directives = config_graph(g)
    for path, text in files.items():
        g.files[path] = disable_passwords(text, main=path == CONFIG)
    _, changed = config_graph(g)
    assert g.files[CONFIG].startswith(POLICY)
    assert all(values == ["no"] for _, _, name, values in changed if name.endswith("authentication") and name != "usepam")
    assert len(files) == 3


@pytest.mark.parametrize("line", ["Include /tmp/other.conf", "Include ../other.conf", "Include $HOME/ssh.conf", "PasswordAuthentication=yes", "PasswordAuthentication yes\\"])
def test_ambiguous_or_unsafe_config_is_rejected(line):
    g = Guest()
    g.files[CONFIG] = line + "\n"
    with pytest.raises(ValueError):
        config_graph(g)


def test_cycles_and_symlinked_includes_rejected():
    g = Guest()
    g.files["/etc/ssh/sshd_config.d/50-default.conf"] = "Include sshd_config\n"
    with pytest.raises(ValueError, match="cycle"):
        config_graph(g)
    g.files["/etc/ssh/sshd_config.d/50-default.conf"] = "# okay\n"
    g.links["/etc/ssh/sshd_config.d/50-default.conf"] = "/elsewhere"
    with pytest.raises(ValueError, match="symlink"):
        config_graph(g)


@pytest.mark.parametrize("setting", ["AuthorizedKeysFile /etc/keys/%u", "AuthenticationMethods publickey,password", "AuthorizedKeysCommand /usr/bin/custom", "PubkeyAuthentication no", "AllowUsers other", "ForceCommand /bin/false"])
def test_unsupported_key_authentication_paths_fail_closed(setting):
    with pytest.raises(ValueError):
        _policy_check([(CONFIG, 1, setting.split()[0].lower(), setting.split()[1:])], options())


def test_standard_two_authorized_key_files_are_supported():
    _policy_check([(CONFIG, 1, "authorizedkeysfile", [".ssh/authorized_keys", ".ssh/authorized_keys2"])], options())


def test_plan_requires_native_worker_and_refreshed_account_inventory(monkeypatch):
    g = Guest()
    assert plan_access(inspection(g), options())["ready"]
    assert not plan_access({"os": {"arch": "x86_64"}}, options())["ready"]
    monkeypatch.setattr("forge.architecture.worker_arch", lambda: "aarch64")
    assert not plan_access(inspection(g), options())["ready"]
    assert plan_access(inspection(g, "aarch64"), options())["ready"]


def run_apply(g, selected=None):
    selected = selected or options()
    modes, commands = [], []
    @contextmanager
    def guest(path, fmt, readonly=True):
        modes.append(readonly)
        yield g
    def run(command, log=None):
        if command == ["virt-customize", "--help"]:
            return "  --no-selinux-relabel   Disable automatic relabeling\n"
        path = Path(command[command.index("--run") + 1])
        assert path.stat().st_mode & 0o777 == 0o600
        script = path.read_text()
        commands.append([*command, "test-script", script])
        if "useradd" in script:
            g.files["/etc/passwd"] += "newuser:x:1001:1001::/home/newuser:/bin/bash\n"
            g.files["/etc/group"] += "newuser:x:1001:\n"
            g.mkdir_p("/home/newuser")
            g.meta["/home/newuser"] = {"st_mode": 0o40755, "st_uid": 1001, "st_gid": 1001, "st_nlink": 1}
        return ""
    with patch("forge.engine._guest", guest), patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._mount"), patch("forge.engine._run", side_effect=run):
        receipt = apply_access(Path("working.qcow2"), inspection(g), selected, lambda _: None)
        result = verify_access(Path("working.qcow2"), receipt)
    return receipt, result, modes, commands


def test_apply_preserves_keys_and_verifies_native_config_then_readonly_receipt():
    g = Guest()
    g.mkdir_p("/home/opc/.ssh")
    existing = 'command="echo only" ' + key() + "\n"
    g.files["/home/opc/.ssh/authorized_keys"] = existing
    receipt, result, modes, commands = run_apply(g)
    assert result["ready"] and result["password_auth_disabled"] and not result["login_tested"]
    assert g.files["/home/opc/.ssh/authorized_keys"] == existing + key(2) + "\n"
    assert g.files[CLOUD_POLICY] == CLOUD_TEXT and modes == [True, False, False, True]
    assert receipt["files"] and len(commands) == 1
    script = commands[0][commands[0].index("test-script") + 1]
    assert "sshd -t" in script and "sshd -T" in script and "-h \"$forge_tmp/key\"" in script
    assert "trap cleanup" in script and "ssh-keygen -q -t rsa" in script
    assert "--no-network" in commands[0] and "--no-selinux-relabel" in commands[0]
    assert "--selinux-relabel" not in commands[0]


def test_create_user_has_unusable_password_private_group_and_no_sudo_changes():
    g = Guest()
    selected = options(users=[{"username": "newuser", "create": True, "authorized_keys": [key()]}])
    receipt, result, _, commands = run_apply(g, selected)
    assert result["ready"] and receipt["users"][0]["uid"] == 1001
    script = commands[0][commands[0].index("test-script") + 1]
    assert "useradd -m -U" in script and "-p '*'" in script and "-K UID_MIN=1000" in script
    assert "CREATE_MAIL_SPOOL" not in script
    assert "sudo" not in script and "usermod" not in script
    assert all("--no-selinux-relabel" in command for command in commands)


@pytest.mark.parametrize("fault", ["home_link", "keys_link", "writable_home", "service_override", "later_cloud_policy"])
def test_unsafe_home_or_daemon_policy_stops_build(fault):
    g = Guest()
    if fault == "home_link": g.links["/home/opc"] = "/root"
    elif fault == "keys_link": g.links["/home/opc/.ssh/authorized_keys"] = "/etc/passwd"
    elif fault == "writable_home": g.meta["/home/opc"]["st_mode"] = 0o40777
    elif fault == "service_override": g.files["/usr/lib/systemd/system/sshd.service"] = "[Service]\nExecStart=/usr/sbin/sshd -D -o PasswordAuthentication=yes\n"
    else: g.files["/etc/cloud/cloud.cfg.d/zzz-override.cfg"] = "ssh_pwauth: true\n"
    with pytest.raises(ValueError):
        run_apply(g)


def test_final_config_and_keys_tampering_cannot_publish():
    g = Guest()
    receipt, _, _, _ = run_apply(g)
    @contextmanager
    def guest(*args, **kwargs): yield g
    with patch("forge.engine._guest", guest), patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._mount"):
        for path, text in ((CONFIG, "PasswordAuthentication yes\n"), ("/home/opc/.ssh/authorized_keys", key(7) + "\n"), ("/etc/shadow", "opc:!:0:0:1:7:::\n")):
            original = g.files[path]
            g.files[path] = text
            assert not verify_access(Path("working.qcow2"), receipt)["ready"]
            g.files[path] = original
        g.files["/etc/ssh/sshd_config.d/new.conf"] = "# New include discovered after verification\n"
        assert not verify_access(Path("working.qcow2"), receipt)["ready"]


def test_native_failure_propagates_and_no_success_receipt_is_minted():
    g = Guest()
    @contextmanager
    def guest(*args, **kwargs): yield g
    with patch("forge.engine._guest", guest), patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._mount"), patch("forge.engine._run", side_effect=ValueError("native sshd failed")):
        with pytest.raises(ValueError, match="native sshd failed"):
            apply_access(Path("working.qcow2"), inspection(g), options(), lambda _: None)


def test_noop_never_opens_guest():
    with patch("forge.engine._guest") as guest:
        assert apply_access(Path("unused.qcow2"), {}, {"users": [], "disable_password_auth": False}, lambda _: None) is None
        assert verify_access(Path("unused.qcow2"), None) is None
        guest.assert_not_called()


@pytest.mark.parametrize("fault", ["global_dropin", "indented_environment", "second_indented_start", "crypto_environment", "hardlinked_keys"])
def test_effective_launch_override_and_hardlink_bypasses_are_rejected(fault):
    g = Guest()
    unit = "/usr/lib/systemd/system/sshd.service"
    if fault == "global_dropin":
        g.files["/etc/systemd/system/service.d/auth.conf"] = "[Service]\nEnvironment=OPTIONS=-oPasswordAuthentication=yes\n"
    elif fault == "indented_environment":
        g.files[unit] += '  Environment="OPTIONS=-oPasswordAuthentication=yes"\n'
    elif fault == "second_indented_start":
        g.files[unit] += "  ExecStart=\n  ExecStart=/usr/sbin/sshd -D -f /elsewhere\n"
    elif fault == "crypto_environment":
        g.files[unit] += "  EnvironmentFile=/etc/crypto-policies/back-ends/opensshserver.config\n"
        g.files["/etc/crypto-policies/back-ends/opensshserver.config"] = "CRYPTO_POLICY='-oPasswordAuthentication=yes'\n"
    else:
        g.mkdir_p("/home/opc/.ssh")
        path = "/home/opc/.ssh/authorized_keys"
        g.files[path] = key() + "\n"
        g.meta[path] = {"st_mode": 0o100600, "st_uid": 1000, "st_gid": 1000, "st_nlink": 2}
    with pytest.raises(ValueError):
        run_apply(g)


def test_password_only_request_preserves_keys_without_reading_them():
    g = Guest()
    g.files["/root/.ssh/authorized_keys"] = key()
    _, result, _, _ = run_apply(g, options(users=[]))
    assert result["ready"] and result["users"] == []
    assert "/root/.ssh/authorized_keys" not in g.reads


@pytest.mark.parametrize("accepted,success", [("ssh-ed25519,rsa-sha2-256", True), ("rsa-sha2-256", False)])
def test_native_algorithm_check_rejects_server_exclusion(tmp_path, accepted, success):
    script = _native_script(options(), "/run/test")
    algorithm = next(line for line in script.splitlines() if "Requested public-key algorithm is excluded" in line)
    (tmp_path / "effective").write_text("pubkeyacceptedalgorithms " + accepted + "\n")
    result = subprocess.run(["/bin/sh", "-c", algorithm], env={**os.environ, "forge_tmp": str(tmp_path)}, capture_output=True)
    assert (result.returncode == 0) == success


@pytest.mark.parametrize("shadow,pam,success", [("opc:*:20000:0:99999:7:::" , "no", True),
                                             ("opc:!:20000:0:99999:7:::" , "no", False),
                                             ("opc:!:20000:0:99999:7:::" , "yes", True),
                                             ("opc:*:0:0:99999:7:::" , "yes", False),
                                             ("opc:*:20000:0:99999:7::1:" , "yes", False)])
def test_native_account_check_rejects_expired_or_unusable_account(shadow, pam, success):
    script = _native_script(options(), "/run/test")
    account = next(line for line in script.splitlines() if "SSH account is locked or expired" in line)
    result = subprocess.run(["/bin/sh", "-c", account], env={**os.environ, "forge_account": shadow, "forge_pam": pam, "forge_today": "21000"}, capture_output=True)
    assert (result.returncode == 0) == success


def test_shared_home_cannot_add_keys_to_another_account():
    g = Guest()
    g.files["/etc/passwd"] += "another:x:1005:1005::/home/opc:/bin/bash\n"
    with pytest.raises(ValueError, match="shared"):
        run_apply(g)


@pytest.mark.parametrize("directory", ["/usr/local/lib/systemd/system", "/run/systemd/system", "/etc/systemd/system.control", "/run/systemd/generator.early", "/etc/systemd/system.attached"])
def test_higher_priority_ssh_launch_units_cannot_override_verified_config(directory):
    g = Guest()
    g.files[directory + "/sshd.service"] = "[Service]\nExecStart=/usr/sbin/sshd -D -oPasswordAuthentication=yes\n"
    with pytest.raises(ValueError):
        run_apply(g)


@pytest.mark.parametrize("setting", ["BindReadOnlyPaths=/tmp/other:/etc/ssh/sshd_config", "RootDirectory=/srv/ssh", "RootImage=/other.img", "ExecStartPre=/bin/cp /tmp/other /etc/ssh/sshd_config", "ExecStartPost=/bin/sh -c something", "ExecReload=/bin/sh -c something", "Environment=LD_PRELOAD=/tmp/lib.so", "StandardOutput=file:/etc/ssh/sshd_config", "StandardError=append:/etc/ssh/sshd_config"])
def test_custom_service_namespace_environment_or_hooks_cannot_bypass_verification(setting):
    g = Guest()
    g.files["/usr/lib/systemd/system/sshd.service"] += "  " + setting + "\n"
    with pytest.raises(ValueError):
        run_apply(g)


def test_standard_debian_preflight_reload_and_runtime_directory_supported():
    g = Guest()
    g.files["/usr/lib/systemd/system/sshd.service"] += "ExecStartPre=/usr/sbin/sshd -t\nExecReload=/usr/sbin/sshd -t\nExecReload=/bin/kill -HUP $MAINPID\nRuntimeDirectory=sshd\nRuntimeDirectoryMode=0755\n"
    assert run_apply(g)[1]["ready"]


@pytest.mark.parametrize("shell", ["/usr/bin/false", "/bin/nologin", "/usr/local/bin/nologin", "/bin/true"])
def test_nonlogin_shells_are_not_offered_as_login_accounts(shell):
    g = Guest()
    g.files["/etc/passwd"] = g.files["/etc/passwd"].replace("/home/opc:/bin/bash", "/home/opc:" + shell)
    g.files[shell] = "binary"
    assert "opc" not in {user["username"] for user in inspect_access(g)["users"]}
    assert not plan_access(inspection(g), options())["ready"]


def test_shell_alias_to_nonlogin_binary_is_rejected():
    g = Guest()
    g.links["/bin/bash"] = "/usr/bin/false"
    with pytest.raises(ValueError, match="login shell"):
        run_apply(g)


def test_standard_hardlinked_crypto_policy_is_readonly_evidence():
    g = Guest()
    include = "/etc/crypto-policies/back-ends/opensshserver.config"
    target = "/usr/share/crypto-policies/DEFAULT/opensshserver.txt"
    g.files[CONFIG] += "Include " + include + "\n"
    g.files[include] = g.files[target] = "Ciphers aes256-gcm@openssh.com\n"
    g.links[include] = target
    g.meta[target] = {"st_mode": 0o100644, "st_uid": 0, "st_gid": 0, "st_nlink": 3}
    result = inspect_access(g)
    assert not result["errors"]
    assert run_apply(g)[1]["ready"]
    assert include not in g.writes and target not in g.writes


def test_native_script_file_is_private_and_removed_on_command_failure():
    captured = []
    def fail(command, log=None):
        if command == ["virt-customize", "--help"]:
            return "  --no-selinux-relabel   Disable automatic relabeling\n"
        assert "--run-command" not in command
        path = Path(command[command.index("--run") + 1])
        captured.append(path)
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
        assert path.read_text() == "#!/bin/sh\necho controlled\n"
        raise ValueError("Specific native error")
    with patch("forge.engine._run", side_effect=fail), pytest.raises(ValueError, match="Specific native error"):
        _run_native(Path("working.qcow2"), "echo controlled", lambda _: None)
    assert len(captured) == 1 and not captured[0].exists() and not captured[0].parent.exists()


@pytest.mark.parametrize("listing,status,allowed", [
    ("User forgenew is not allowed to run sudo on (none).", "0", True),
    ("sudo: unable to resolve host (none): Name or service not known\nUser forgenew is not allowed to run sudo on (none).", "0", True),
    ("User forgenew is not allowed to run sudo on server.", "1", True),
    ("User forgenew may run the following commands on server:\n    (ALL) ALL", "0", False),
    ("User forgenew is not allowed to run sudo on server.\nUser forgenew may run the following commands on server:\n    (root) /usr/bin/id", "0", False),
    ("sudo: unable to open sudoers", "1", False),
    ("User another is not allowed to run sudo on server.", "0", False),
    ("User forgenew is not allowed to run sudo on server.", "2", False),
])
def test_sudo_listing_success_does_not_mean_privilege_grant(listing, status, allowed):
    result = subprocess.run(["/bin/sh", "-c", _sudo_denial_check("forgenew")],
                            env={**os.environ, "forge_sudo": listing, "forge_sudo_status": status}, capture_output=True)
    assert (result.returncode == 0) == allowed


def selinux_guest():
    g = Guest()
    g.files["/etc/selinux/config"] = "SELINUX=enforcing\nSELINUXTYPE=targeted\n"
    g.files["/etc/selinux/targeted/contexts/files/file_contexts"] = "fixture policy"
    g.files["/usr/sbin/matchpathcon"] = "binary"
    return g


def test_selinux_labels_keys_and_only_existing_home_inode():
    g = selinux_guest()
    g.files["/home/opc/keep-custom-context"] = "unrelated"
    g.xattrs["/home/opc/keep-custom-context"] = b"system_u:object_r:custom_data_t:s0"
    receipt, result, _, _ = run_apply(g)
    assert result["ready"] and result["selinux_labels_verified"]
    assert "/home/opc" not in g.relabels and "/home/opc/.ssh" in g.relabels
    assert g.xattrs["/home/opc/keep-custom-context"] == b"system_u:object_r:custom_data_t:s0"
    assert receipt["selinux"]["labels"]["/home/opc/.ssh"].split(":")[2] == "ssh_home_t"
    assert receipt["selinux"]["labels"]["/home/opc"].split(":")[2] == "user_home_dir_t"
    assert CLOUD_POLICY in g.relabels


def test_selinux_new_home_account_databases_and_mail_spool_are_relabelled():
    g = selinux_guest()
    g.files["/etc/gshadow"] = "fixture"
    g.files["/var/spool/mail/newuser"] = ""
    g.mkdir_p("/var/spool/mail")
    selected = options(users=[{"username": "newuser", "create": True, "authorized_keys": [key()]}])
    receipt, result, _, _ = run_apply(g, selected)
    assert result["ready"]
    for path in ("/home/newuser", "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/var/spool/mail/newuser"):
        assert path in g.relabels and path in receipt["selinux"]["labels"]


def test_successful_but_ineffective_relabel_cannot_mint_receipt():
    g = selinux_guest()
    g.selinux_relabel = lambda *args, **kwargs: None
    with pytest.raises(ValueError, match="did not label"):
        run_apply(g)


@pytest.mark.parametrize("value", ["", "<<none>>\n", "system_u:object_r:unlabeled_t:s0\n", "bad\ncontext"])
def test_invalid_matchpathcon_result_is_rejected(value):
    g = selinux_guest()
    g.command = lambda args: value
    with pytest.raises(ValueError, match="context"):
        run_apply(g)


def test_final_selinux_label_tamper_is_rejected_readonly():
    g = selinux_guest()
    receipt, _, _, _ = run_apply(g)
    g.xattrs["/home/opc/.ssh/authorized_keys"] = b"system_u:object_r:user_home_t:s0\0"
    @contextmanager
    def guest(*args, **kwargs):
        assert kwargs.get("readonly") is True
        yield g
    with patch("forge.engine._guest", guest), patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._mount"):
        assert not verify_access(Path("working.qcow2"), receipt)["ready"]


def test_selinux_disabled_does_not_run_label_tools():
    g = selinux_guest()
    g.files["/etc/selinux/config"] = "SELINUX=disabled\nSELINUXTYPE=targeted\n"
    _, result, _, _ = run_apply(g)
    assert result["ready"] and not result["selinux_labels_verified"]
    assert g.relabels == g.native_commands == []


def test_modern_native_helper_disables_automatic_relabel_from_advertised_capability():
    with patch("forge.engine._run", return_value=" --no-selinux-relabel Disable automatic relabeling") as run:
        assert _native_relabel_flags() == ["--no-selinux-relabel"]
        run.assert_called_once_with(["virt-customize", "--help"])


def test_bookworm_native_helper_omits_both_opt_in_relabel_flags():
    commands = []
    def run(command, log=None):
        commands.append(command)
        if command[-1] == "--help":
            return "  --selinux-relabel Relabel files in the guest\n"
        if command[-1] == "--version":
            return "virt-customize 1.48.2\n"
        assert "--selinux-relabel" not in command and "--no-selinux-relabel" not in command
        assert "--run" in command
        return ""
    with patch("forge.engine._run", side_effect=run):
        _run_native(Path("working.qcow2"), "true", lambda _: None)
    assert len(commands) == 3


@pytest.mark.parametrize("help_text,version", [(" --selinux-relabel", "virt-customize 1.50.0"),
                                              (" --something-else", "virt-customize 1.48.2"),
                                              (" --no-selinux-relabel-custom", "virt-customize 3.0.0")])
def test_unknown_relabel_interface_is_rejected_before_guest_command(help_text, version):
    with patch("forge.engine._run", side_effect=[help_text, version]) as run:
        with pytest.raises(ValueError, match="relabel behavior"):
            _run_native(Path("working.qcow2"), "true", lambda _: None)
        assert run.call_count == 2 and all("-a" not in call.args[0] for call in run.call_args_list)
