"""Bounded SSH access customization of disposable, native-architecture guests.

Inspection never runs guest code or reads private/authorized key files. Changes
are verified with the guest's OpenSSH tools; this is not a network login test.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import shlex
import struct
import tempfile
from uuid import uuid4

USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
KEY_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
CONFIG = "/etc/ssh/sshd_config"
CLOUD_POLICY = "/etc/cloud/cloud.cfg.d/zz-cloud-image-forge-ssh.cfg"
CLOUD_TEXT = "# Cloud Image Forge: retain SSH key authentication.\nssh_pwauth: false\n"
PASSWORD_KEYS = {"passwordauthentication", "kbdinteractiveauthentication", "challengeresponseauthentication"}
POLICY = "# Cloud Image Forge: password and PAM keyboard-interactive login disabled.\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\n"
LIMIT = 512 * 1024
MAX_FILES = 128
CRYPTO_INCLUDE = "/etc/crypto-policies/back-ends/opensshserver.config"
UNIT_PATHS = ("/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
              "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
              "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
              "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
              "/run/systemd/generator.late")
SERVICE_SETTINGS = {"Type", "NotifyAccess", "Restart", "RestartSec", "RestartPreventExitStatus", "SuccessExitStatus",
                    "TimeoutStartSec", "TimeoutStopSec", "KillMode", "KillSignal", "SendSIGHUP", "IgnoreSIGPIPE",
                    "RuntimeDirectory", "RuntimeDirectoryMode", "PIDFile", "SyslogIdentifier", "SyslogFacility",
                    "LogLevelMax", "UMask", "StandardOutput", "StandardError", "LimitNOFILE", "LimitNPROC",
                    "OOMScoreAdjust", "Slice", "TasksMax", "ExecStart", "ExecStartPre", "ExecReload", "EnvironmentFile"}


def validate_public_key(value: str) -> str:
    """Validate SSH wire framing, declared key type and supported key sizes."""
    if not isinstance(value, str) or not 1 <= len(value) <= 16384 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Public keys must be single printable lines, at most 16384 characters")
    fields = value.strip().split(None, 2)
    if len(fields) < 2 or fields[0] not in KEY_TYPES:
        raise ValueError("Use an Ed25519, RSA, or NIST ECDSA public key without authorized_keys options or private-key data")
    try:
        raw = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Public key has invalid base64 data") from exc
    if base64.b64encode(raw).decode() != fields[1] or len(raw) > 8192:
        raise ValueError("Public key has noncanonical or oversized base64 data")
    offset = 0

    def word():
        nonlocal offset
        if offset + 4 > len(raw):
            raise ValueError("Truncated SSH public-key data")
        length = struct.unpack_from(">I", raw, offset)[0]
        offset += 4
        if length > len(raw) - offset:
            raise ValueError("Truncated SSH public-key field")
        result = raw[offset:offset + length]
        offset += length
        return result

    if word() != fields[0].encode():
        raise ValueError("Public key type does not match its SSH wire data")
    if fields[0] == "ssh-ed25519":
        if len(word()) != 32:
            raise ValueError("Ed25519 public keys must contain 32 key bytes")
    elif fields[0] == "ssh-rsa":
        numbers = []
        for _ in range(2):
            encoded = word()
            if not encoded or encoded[0] & 128 or (len(encoded) > 1 and encoded[0] == 0 and not encoded[1] & 128):
                raise ValueError("RSA public key contains a noncanonical positive integer")
            numbers.append(int.from_bytes(encoded, "big"))
        exponent, modulus = numbers
        if not 3 <= exponent <= 0xFFFFFFFF or exponent % 2 != 1 or modulus % 2 != 1 or not 2048 <= modulus.bit_length() <= 8192:
            raise ValueError("RSA public keys require a valid exponent and a 2048–8192 bit modulus")
    else:
        curve = fields[0].removeprefix("ecdsa-sha2-")
        point = None
        if word() != curve.encode():
            raise ValueError("ECDSA curve does not match the public-key type")
        point = word()
        if len(point) != {"nistp256": 65, "nistp384": 97, "nistp521": 133}[curve] or point[0] != 4:
            raise ValueError("ECDSA key must contain a correctly sized uncompressed curve point")
    if offset != len(raw):
        raise ValueError("Public key has trailing SSH wire data")
    return " ".join(fields)


def key_identity(line):
    """Find key bytes without changing existing options, comments or formatting."""
    try:
        fields = shlex.split(line, comments=True)
        for index, field in enumerate(fields[:-1]):
            if field in KEY_TYPES:
                return field, base64.b64decode(fields[index + 1], validate=True)
    except (ValueError, binascii.Error):
        pass
    return None


def merge_keys(existing: str, requested: list[str]) -> tuple[str, int]:
    identities = {identity for line in existing.splitlines() if (identity := key_identity(line))}
    added = []
    for line in requested:
        line = validate_public_key(line)
        identity = key_identity(line)
        if identity not in identities:
            identities.add(identity)
            added.append(line)
    if not added:
        return existing, 0
    return existing + ("\n" if existing and not existing.endswith("\n") else "") + "\n".join(added) + "\n", len(added)


def meaningful(options):
    return bool(options and (options.get("disable_password_auth") or options.get("users")))


def _safe(g, path, *, regular=False, allow_hardlinks=False):
    if not isinstance(path, str) or not path.startswith("/") or str(PurePosixPath(path)) != path or any(c in path for c in "\r\n\0") or ".." in PurePosixPath(path).parts:
        raise ValueError("Unsafe guest path in SSH access configuration")
    for parent in reversed(PurePosixPath(path).parents):
        if str(parent) != "/" and g.is_symlink(str(parent)):
            raise ValueError("SSH access refuses symlinked directories: " + str(parent))
    if g.is_symlink(path):
        raise ValueError("SSH access refuses symlinks: " + path)
    if regular and g.exists(path) and not g.is_file(path):
        raise ValueError("SSH access requires a regular file: " + path)
    if regular and not allow_hardlinks and g.is_file(path) and g.statns(path).get("st_nlink", 1) != 1:
        raise ValueError("SSH access refuses hard-linked files: " + path)


def _read(g, path, *, optional=False, allow_hardlinks=False):
    _safe(g, path, regular=True, allow_hardlinks=allow_hardlinks)
    if not g.exists(path) and optional:
        return ""
    if not g.is_file(path) or g.filesize(path) > LIMIT:
        raise ValueError("SSH access requires a readable file of at most 512 KiB: " + path)
    text = g.read_file(path)
    text = text.decode("utf-8") if isinstance(text, bytes) else text
    if "\0" in text:
        raise ValueError("NUL bytes in SSH configuration: " + path)
    return text


def _words(line):
    # OpenSSH does not use shell execution. Reject continuations/ambiguous input
    # instead of treating shell syntax as its configuration grammar.
    if line.rstrip().endswith("\\"):
        raise ValueError("SSH configuration line continuations are unsupported")
    words = shlex.split(line, comments=True)
    if words and "=" in words[0]:
        raise ValueError("SSH keyword=value syntax is unsupported; use keyword value configuration")
    return words


def config_graph(g):
    files, directives, stack = {}, [], []
    total = 0

    def visit(path):
        nonlocal total
        if path in stack or len(stack) >= 16:
            raise ValueError("SSH Include cycle or excessive nesting")
        if len(files) >= MAX_FILES and path not in files:
            raise ValueError("SSH Include inventory exceeds 128 files")
        if path == CRYPTO_INCLUDE and g.is_symlink(path):
            resolved = g.realpath(path)
            if not resolved.startswith("/usr/share/crypto-policies/"):
                raise ValueError("Unsupported crypto-policy include symlink")
            # Distribution crypto policies commonly share immutable hardlinked
            # files. This target is evidence only and is never rewritten.
            text = _read(g, resolved, allow_hardlinks=True)
        else:
            text = _read(g, path)
        if path not in files:
            total += len(text.encode())
        if total > 4 * 1024**2:
            raise ValueError("SSH Include content exceeds 4 MiB")
        files[path] = text
        stack.append(path)
        for number, line in enumerate(text.splitlines(), 1):
            words = _words(line)
            if not words:
                continue
            key, values = words[0].lower(), words[1:]
            directives.append((path, number, key, values))
            if len(directives) > 8192:
                raise ValueError("SSH expanded configuration exceeds 8192 directives")
            if key != "include":
                continue
            if not values:
                raise ValueError("Empty SSH Include directive")
            for value in values:
                pattern = value if value.startswith("/") else "/etc/ssh/" + value
                if (not pattern.startswith("/etc/ssh/") and pattern != CRYPTO_INCLUDE) or ".." in PurePosixPath(pattern).parts or any(c in pattern for c in "%$`\\\0\r\n"):
                    raise ValueError("Only literal /etc/ssh includes and the standard crypto-policy include are supported")
                paths = sorted(g.glob_expand(pattern))
                if len(paths) > MAX_FILES:
                    raise ValueError("SSH Include expansion exceeds 128 files")
                for child in paths:
                    visit(child)
        stack.pop()

    visit(CONFIG)
    return files, directives


def _accounts(g):
    users, names, uids = [], set(), set()
    text = _read(g, "/etc/passwd")
    if len(text.splitlines()) > 2048:
        raise ValueError("Local account inventory exceeds 2048 entries")
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) != 7 or not fields[2].isdigit() or not fields[3].isdigit():
            raise ValueError("Local passwd database is malformed")
        name, _, uid, gid, _, home, shell = fields
        if name in names:
            raise ValueError("Local passwd database contains duplicate usernames")
        names.add(name)
        uid, gid = int(uid), int(gid)
        if uid == 0 and name != "root":
            raise ValueError("Non-root UID 0 aliases are unsupported")
        users.append({"username": name, "uid": uid, "gid": gid, "home": home, "shell": shell})
        uids.add(uid)
    return users


def _login_user(user):
    return bool((user["uid"] == 0 or user["uid"] >= 1000) and USERNAME.fullmatch(user["username"])
                and user["home"].startswith("/") and user["shell"].startswith("/")
                and PurePosixPath(user["shell"]).name not in {"false", "nologin", "true"})


def inspect_access(g):
    result = {"version": 1, "users": [], "sshd_present": False, "config_present": False,
              "warnings": [], "errors": [], "config_hashes": {}}
    try:
        result["users"] = [user for user in _accounts(g) if _login_user(user)]
        result["sshd_present"] = g.is_file("/usr/sbin/sshd")
        result["config_present"] = g.is_file(CONFIG)
        if result["config_present"]:
            files, directives = config_graph(g)
            result["config_hashes"] = {path: hashlib.sha256(text.encode()).hexdigest() for path, text in files.items()}
            result["password_directives"] = [{"path": path, "line": number, "setting": key, "value": " ".join(values)}
                                               for path, number, key, values in directives if key in PASSWORD_KEYS]
        if not result["sshd_present"]:
            result["warnings"].append("OpenSSH server is not installed; install it before configuring SSH access.")
    except (RuntimeError, ValueError, UnicodeError, AttributeError, TypeError) as exc:
        result["errors"].append("SSH access inspection is incomplete: " + str(exc)[:300])
    return result


def plan_access(inspection, options):
    from .architecture import execution_blocker
    requested = meaningful(options)
    plan = {"requested": requested, "ready": True, "blockers": [], "warnings": [], "changes": []}
    if not requested:
        return plan
    evidence = inspection.get("ssh_access") or {}
    if evidence.get("version") != 1:
        plan["blockers"].append("Refresh inspection to discover SSH server and local login accounts.")
    elif not evidence.get("sshd_present") or not evidence.get("config_present"):
        plan["blockers"].append("SSH customization requires an installed OpenSSH server and /etc/ssh/sshd_config.")
    plan["blockers"].extend(evidence.get("errors", []))
    reason = execution_blocker(inspection.get("os", {}).get("arch"))
    if reason:
        plan["blockers"].append(reason)
    users = {user["username"]: user for user in evidence.get("users", [])}
    for selected in options.get("users", []):
        name = selected["username"]
        if name not in users and not selected.get("create"):
            plan["blockers"].append(f"Login user {name} is not present; select Create user or choose an existing login account.")
        if name in users and selected.get("create"):
            plan["blockers"].append(f"User {name} already exists; clear Create user to add keys to that account.")
        plan["changes"].append(("Create non-administrator login user " if selected.get("create") else "Add public keys for ") + name)
    if options.get("disable_password_auth"):
        plan["changes"].append("Disable password and keyboard-interactive SSH authentication, including loaded Match blocks; retain cloud-init ssh_pwauth:false.")
        plan["warnings"].append("Retain a usable SSH key or console recovery path. Later explicit cloud user-data or startup scripts can change image policy.")
    plan["ready"] = not plan["blockers"]
    return plan


def _policy_check(directives, options):
    """Reject authentication paths we cannot prove, without rewriting them."""
    users = options.get("users", [])
    for path, number, key, values in directives:
        where = f"{path}:{number}"
        if key == "authenticationmethods" and values not in [["any"], ["publickey"]]:
            raise ValueError("Custom AuthenticationMethods requires manual review before SSH changes: " + where)
        if not users:
            continue
        if key == "authorizedkeysfile" and (not values or any(value not in {".ssh/authorized_keys", "%h/.ssh/authorized_keys", ".ssh/authorized_keys2", "%h/.ssh/authorized_keys2"} for value in values)
                                            or not any(value.endswith("/.ssh/authorized_keys") or value == ".ssh/authorized_keys" for value in values)):
            raise ValueError("Custom AuthorizedKeysFile is unsupported; use .ssh/authorized_keys: " + where)
        if key in {"authorizedkeyscommand", "forcecommand", "chrootdirectory", "revokedkeys"} and values != ["none"]:
            raise ValueError("SSH " + key + " requires manual review before adding login keys: " + where)
        if key in {"allowusers", "denyusers", "allowgroups", "denygroups"}:
            raise ValueError("SSH allow/deny account restrictions require manual review: " + where)
        if key == "pubkeyauthentication" and values != ["yes"]:
            raise ValueError("Public-key authentication must be enabled in every applicable SSH configuration: " + where)
        if key == "permitrootlogin" and any(user["username"] == "root" for user in users) and values not in [["yes"], ["prohibit-password"], ["without-password"]]:
            raise ValueError("Existing PermitRootLogin policy does not allow unrestricted root key login; it will not be changed: " + where)


def disable_passwords(text, *, main=False):
    lines = []
    for line in text.splitlines(keepends=True):
        words = _words(line)
        if words and words[0].lower() in PASSWORD_KEYS:
            lines.append(words[0] + " no\n")
        else:
            lines.append(line)
    content = "".join(lines)
    return (POLICY if main else "") + content


def _read_following(g, path):
    """Read service evidence only; never write through aliases or execute it."""
    if not g.is_file(path) or g.filesize(path) > LIMIT:
        raise ValueError("Unreadable SSH launch configuration: " + path)
    content = g.read_file(path)
    return content.decode("utf-8") if isinstance(content, bytes) else content


def _launch_evidence(g):
    files = {}
    units = []
    for name in ("ssh.service", "sshd.service"):
        for directory in UNIT_PATHS:
            path = directory + "/" + name
            if g.is_symlink(path) and g.readlink(path) == "/dev/null":
                raise ValueError("SSH service is masked: " + name)
            if g.is_symlink(path) and PurePosixPath(g.realpath(path)).name not in {"ssh.service", "sshd.service"}:
                raise ValueError("Custom SSH service alias requires manual review: " + path)
            if g.is_file(path):
                files[path] = _read_following(g, path)
                units.append(path)
                break
        for directory in UNIT_PATHS:
            paths = g.glob_expand(directory + "/" + name + ".d/*.conf")
            if paths:
                raise ValueError("Custom SSH service drop-ins require manual review before SSH configuration changes")
    if not units:
        raise ValueError("A standard OpenSSH systemd service is required for SSH access customization")
    for path in units:
        lines = [line.strip() for line in files[path].splitlines() if line.strip() and not line.lstrip().startswith(("#", ";"))]
        if any(line.endswith("\\") for line in lines):
            raise ValueError("SSH unit continuations require manual review: " + path)
        section = ""
        for line in lines:
            if line.startswith("["):
                section = line
                continue
            if "=" not in line:
                raise ValueError("Malformed SSH systemd unit: " + path)
            key, value = (part.strip() for part in line.split("=", 1))
            if section == "[Service]" and key not in SERVICE_SETTINGS:
                raise ValueError("Unsupported SSH service setting requires manual review: " + key)
            if key in {"RootDirectory", "RootImage", "BindPaths", "BindReadOnlyPaths", "JoinsNamespaceOf"}:
                raise ValueError("SSH filesystem namespace overrides require manual review: " + key)
            if key == "ExecStartPre" and value != "/usr/sbin/sshd -t":
                raise ValueError("Custom SSH pre-start command requires manual review")
            if key == "ExecReload" and value not in {"/usr/sbin/sshd -t", "/bin/kill -HUP $MAINPID", "/usr/bin/kill -HUP $MAINPID"}:
                raise ValueError("Custom SSH reload command requires manual review")
            if key == "RuntimeDirectory" and value != "sshd":
                raise ValueError("Custom SSH runtime directory requires manual review")
            if key in {"StandardOutput", "StandardError"} and value not in {"journal", "journal+console", "syslog", "syslog+console", "kmsg", "kmsg+console", "null", "inherit", "tty"}:
                raise ValueError("SSH service output redirection requires manual review")
        starts = [line.split("=", 1)[1].strip() for line in lines if re.match(r"ExecStart\s*=", line)]
        if len(starts) != 1 or not re.fullmatch(r"/?usr/sbin/sshd\s+-D(?:\s+\$(?:OPTIONS|SSHD_OPTS|CRYPTO_POLICY))*\s*", starts[0]):
            raise ValueError("Custom SSH daemon launch arguments require manual review: " + path)
        for line in lines:
            if re.match(r"(?:Environment|PassEnvironment)\s*=", line) and re.search(r"\b(?:OPTIONS|SSHD_OPTS|CRYPTO_POLICY)\b", line):
                raise ValueError("SSH service Environment overrides are unsupported: " + path)
            if re.match(r"EnvironmentFile\s*=", line):
                environment = line.split("=", 1)[1].strip().lstrip("-")
                if environment not in {"/etc/default/ssh", "/etc/sysconfig/sshd", CRYPTO_INCLUDE}:
                    raise ValueError("Custom SSH environment file requires manual review: " + path)
                if environment == CRYPTO_INCLUDE and g.is_file(environment):
                    text = _read_following(g, environment)
                    files[environment] = text
                    if any(shlex.split(value, comments=True) not in ([], ["CRYPTO_POLICY="]) for value in text.splitlines()):
                        raise ValueError("Nonempty crypto-policy launch arguments require manual review; configuration-file crypto policies remain supported")
    for directory in UNIT_PATHS:
        if g.glob_expand(directory + "/service.d/*.conf"):
            raise ValueError("Global systemd service drop-ins require manual review before SSH changes")
    for path in ("/etc/default/ssh", "/etc/sysconfig/sshd"):
        if not g.exists(path):
            continue
        text = _read(g, path)
        files[path] = text
        for line in text.splitlines():
            words = shlex.split(line, comments=True)
            if not words:
                continue
            if len(words) != 1 or not re.fullmatch(r"(?:SSHD_OPTS|OPTIONS|CRYPTO_POLICY)=", words[0]):
                # Environment files can affect the daemon's config/arguments.
                raise ValueError("Nonempty or custom SSH service environment settings require manual review: " + path)
    return files


def _home(g, user):
    path = user["home"]
    if path in {"/", "/etc", "/var", "/usr", "/tmp", "/run"}:
        raise ValueError("Unsupported login home for " + user["username"])
    _safe(g, path)
    if not g.is_dir(path):
        raise ValueError("Existing login home is missing: " + path)
    if any(account["username"] != user["username"] and account["home"] == path for account in _accounts(g)):
        raise ValueError("SSH access refuses a home shared by multiple accounts: " + path)
    for directory in [path, *[str(parent) for parent in PurePosixPath(path).parents]]:
        metadata = g.statns(directory)
        if metadata["st_uid"] not in {0, user["uid"]} or metadata["st_mode"] & 0o022:
            raise ValueError("SSH StrictModes requires an appropriately owned home and non-writable parent directories: " + directory)
    if (not _login_user(user) or not g.is_file(user["shell"])
            or PurePosixPath(g.realpath(user["shell"])).name in {"false", "nologin", "true"}):
        raise ValueError("A usable existing login shell is required for " + user["username"])


def _write(g, path, content, mode=0o644, uid=0, gid=0):
    _safe(g, path, regular=True)
    parent = str(PurePosixPath(path).parent)
    _safe(g, parent)
    g.mkdir_p(parent)
    g.write(path, content.encode())
    g.chmod(mode, path)
    g.chown(uid, gid, path)


def _cloud_policy(g):
    _safe(g, CLOUD_POLICY, regular=True)
    paths = g.glob_expand("/etc/cloud/cloud.cfg.d/*.cfg")
    if len(paths) > MAX_FILES:
        raise ValueError("Cloud-init configuration inventory exceeds 128 files")
    for path in paths:
        if path <= CLOUD_POLICY:
            continue
        text = _read(g, path)
        if re.search(r"(?m)^[^#\n]*\bssh_pwauth\b", text):
            raise ValueError("A later cloud-init ssh_pwauth setting would override the managed policy: " + path)
    _write(g, CLOUD_POLICY, CLOUD_TEXT)


def _sudo_denial_check(username):
    # Root's sudo -l -U may successfully list *zero* grants with exit status 0.
    # Require the explicit denial, allowing only the known appliance hostname
    # warning; an allowed-command listing or any other error remains unknown.
    return ("{ test \"$forge_sudo_status\" = 0 || test \"$forge_sudo_status\" = 1; } && printf '%s\\n' \"$forge_sudo\" | awk -v u=" + shlex.quote(username)
            + " '($0 ~ (\"^User \" u \" is not allowed to run sudo on .+[.]$\")) {denied++; next} /^sudo: unable to resolve host / {next} NF {bad=1} END {exit !(denied==1 && !bad)}'"
            + " || { echo 'Existing sudo privileges or unreadable sudo policy prevent non-administrator account verification' >&2; exit 1; }")


def _native_script(options, temp, *, create=False):
    """Native commands execute inside virt-customize's isolated guest appliance."""
    q = shlex.quote
    commands = ["set -eu", "umask 077", "export LC_ALL=C"]
    if create:
        for user in options.get("users", []):
            if not user.get("create"):
                continue
            name = q(user["username"])
            commands += [f"if getent passwd {name} >/dev/null; then echo 'Requested new SSH user already exists in NSS' >&2; exit 1; fi",
                         "forge_shell=/bin/bash; test -x \"$forge_shell\" || forge_shell=/bin/sh; test -x \"$forge_shell\"",
                         f"useradd -m -U -d {q('/home/' + user['username'])} -s \"$forge_shell\" -p '*' -e '' -f -1 -K UID_MIN=1000 -K UID_MAX=60000 {name}",
                         f"test \"$(id -Gn {name})\" = {name}",
                         f"test \"$(id -u {name})\" -ge 1000"]
        return "\n".join(commands)
    commands += [f"forge_tmp={q(temp)}", 'test ! -e "$forge_tmp"', 'mkdir -m 700 "$forge_tmp"',
                 'forge_created_run=0',
                 'cleanup() { rm -f "$forge_tmp/key" "$forge_tmp/key.pub" "$forge_tmp/public" "$forge_tmp/effective"; rmdir "$forge_tmp"; if test "$forge_created_run" = 1; then rmdir /run/sshd; fi; }',
                 "trap cleanup EXIT HUP INT TERM",
                 'if test ! -d /run/sshd; then mkdir -m 755 /run/sshd; forge_created_run=1; fi',
                 'ssh-keygen -q -t rsa -b 3072 -N "" -f "$forge_tmp/key"',
                 '/usr/sbin/sshd -t -f /etc/ssh/sshd_config -h "$forge_tmp/key"',
                 "forge_check() { awk -v k=\"$1\" -v v=\"$2\" '$1==k {$1=\"\"; sub(/^ /,\"\"); if ($0==v) ok=1} END {exit !ok}' \"$forge_tmp/effective\" || { echo \"Effective SSH setting not supported: $1\" >&2; exit 1; }; }"]
    contexts = [None, *options.get("users", [])]
    for user in contexts:
        context = "" if user is None else " -C " + q("user=" + user["username"] + ",host=forge-validation.invalid,addr=192.0.2.1,laddr=192.0.2.2,lport=22")
        commands += ['/usr/sbin/sshd -T -f /etc/ssh/sshd_config -h "$forge_tmp/key"' + context + ' >"$forge_tmp/effective"']
        if options.get("disable_password_auth"):
            commands += ["forge_check passwordauthentication no", "forge_check kbdinteractiveauthentication no"]
        if user is None:
            continue
        name = q(user["username"])
        commands += ["forge_check pubkeyauthentication yes",
                     "awk '$1==\"authorizedkeysfile\" {for(i=2;i<=NF;i++) if($i==\".ssh/authorized_keys\" || $i==\"%h/.ssh/authorized_keys\") ok=1} END {exit !ok}' \"$forge_tmp/effective\"",
                     f"forge_account=$(getent shadow {name})",
                     'test -n "$forge_account"',
                     "forge_pam=$(awk '$1==\"usepam\" {print $2}' \"$forge_tmp/effective\")",
                     'forge_today=$(($(date +%s) / 86400))',
                     "printf '%s\\n' \"$forge_account\" | awk -F: -v pam=\"$forge_pam\" -v today=\"$forge_today\" '{if (pam!=\"yes\" && $2 ~ /^!/) exit 1; if ($8!=\"\" && $8!=\"-1\" && $8<=today) exit 1; if ($3==\"0\") exit 1; if ($5!=\"\" && $5!=\"-1\" && $3+$5<=today) exit 1}' || { echo 'SSH account is locked or expired; update account policy explicitly' >&2; exit 1; }"]
        if user["username"] == "root":
            commands.append("awk '$1==\"permitrootlogin\" && ($2==\"yes\" || $2==\"prohibit-password\" || $2==\"without-password\") {ok=1} END {exit !ok}' \"$forge_tmp/effective\" || { echo 'Effective SSH policy does not permit root key login' >&2; exit 1; }")
        for key in user["authorized_keys"]:
            commands += ["printf '%s\\n' " + q(key) + ' >"$forge_tmp/public"',
                         'ssh-keygen -l -f "$forge_tmp/public" >/dev/null']
            kind = key.split()[0]
            accepted = {"rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"} if kind == "ssh-rsa" else {kind}
            expression = " || ".join('a[i]=="' + algorithm + '"' for algorithm in sorted(accepted))
            commands.append("awk '$1==\"pubkeyacceptedalgorithms\" || $1==\"pubkeyacceptedkeytypes\" {n=split($2,a,\",\");for(i=1;i<=n;i++) if(" + expression + ") ok=1} END {exit !ok}' \"$forge_tmp/effective\" || { echo 'Requested public-key algorithm is excluded by SSH policy' >&2; exit 1; }")
            if kind == "ssh-rsa":
                commands += ["forge_rsa_bits=$(ssh-keygen -l -f \"$forge_tmp/public\" | awk '{print $1}')",
                             "awk -v bits=\"$forge_rsa_bits\" '$1==\"requiredrsasize\" && $2>bits {exit 1}' \"$forge_tmp/effective\" || { echo 'RSA key is smaller than the configured server minimum' >&2; exit 1; }"]
        if user.get("create"):
            commands += ["printf '%s\\n' \"$forge_account\" | awk -F: '$2!=\"*\" {exit 1}'",
                         "if command -v doas >/dev/null; then echo 'Existing doas policy requires manual review for a new non-administrator account' >&2; exit 1; fi",
                         "if command -v sudo >/dev/null; then",
                         f"  forge_sudo_status=0; forge_sudo=$(sudo -n -l -U {name} 2>&1) || forge_sudo_status=$?",
                         "  " + _sudo_denial_check(user["username"]),
                         "fi"]
    return "\n".join(commands)


def _selinux_policy(g):
    path = "/etc/selinux/config"
    if not g.is_file(path):
        return None
    text = _read(g, path)
    values = {}
    for key in ("SELINUX", "SELINUXTYPE"):
        matches = re.findall(r"^\s*" + key + r"\s*=\s*['\"]?([A-Za-z0-9_-]+)['\"]?\s*(?:#.*)?$", text, re.M)
        if len(set(matches)) > 1:
            raise ValueError("Ambiguous SELinux configuration prevents SSH labeling")
        values[key] = matches[-1] if matches else None
    if values["SELINUX"] == "disabled":
        return None
    if values["SELINUX"] not in {"enforcing", "permissive"} or not values["SELINUXTYPE"]:
        raise ValueError("Cannot determine active SELinux policy for SSH labeling")
    return values["SELINUXTYPE"]


def _context(value):
    text = (value.decode("utf-8") if isinstance(value, bytes) else value).rstrip("\0").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_:.,-]+", text) or len(text) > 512:
        raise ValueError("Missing or invalid SELinux context on an SSH access path")
    if text.split(":")[2] in {"unlabeled_t", "default_t"}:
        raise ValueError("SSH access path has an unusable SELinux context")
    return text


def _label_targets(g, options):
    """Exact metadata targets; recursively relabel only .ssh and new homes."""
    users = {user["username"]: user for user in _accounts(g)}
    directories, recursive, files, ssh_paths = set(), set(), set(), set()
    for entry in options.get("users", []):
        user = users[entry["username"]]
        home = user["home"]
        _home(g, user)
        directories.add(home)
        ssh_paths.update({home + "/.ssh", home + "/.ssh/authorized_keys"})
        recursive.add(home if entry["create"] else home + "/.ssh")
        if entry["create"]:
            for name in ("passwd", "group", "shadow", "gshadow", "subuid", "subgid"):
                for suffix in ("", "-"):
                    path = "/etc/" + name + suffix
                    if g.is_file(path):
                        _safe(g, path, regular=True)
                        files.add(path)
            for parent in ("/var/spool/mail", "/var/mail"):
                path = parent + "/" + user["username"]
                if g.is_file(path):
                    resolved = g.realpath(path)
                    if resolved not in {"/var/spool/mail/" + user["username"], "/var/mail/" + user["username"]}:
                        raise ValueError("Unexpected new-account mail-spool path")
                    _safe(g, resolved, regular=True)
                    files.add(resolved)
    if options.get("disable_password_auth"):
        loaded, _ = config_graph(g)
        files.update(path for path in loaded if path != CRYPTO_INCLUDE)
        files.add(CLOUD_POLICY)
        directories.update({"/etc/cloud", "/etc/cloud/cloud.cfg.d"})
    return directories, recursive, files, ssh_paths


def _label_state(g, options):
    policy = _selinux_policy(g)
    if policy is None:
        return {"enabled": False}
    directories, _, files, ssh_paths = _label_targets(g, options)
    labels = {}
    for path in sorted(directories | files | ssh_paths):
        _safe(g, path)
        try:
            labels[path] = _context(g.lgetxattr(path, "security.selinux"))
        except RuntimeError as exc:
            raise ValueError("SELinux label is missing on SSH access path: " + path) from exc
        if path in ssh_paths and labels[path].split(":")[2] != "ssh_home_t":
            raise ValueError("SSH keys require a supported ssh_home_t SELinux context: " + path)
    return {"enabled": True, "policy": policy, "labels": labels}


def _relabel_access(g, options):
    from .engine import _relabel_edited_files
    if _selinux_policy(g) is None:
        return
    directories, recursive, files, ssh_paths = _label_targets(g, options)
    _relabel_edited_files(g, sorted(recursive | files))
    # The libguestfs relabel API walks directories recursively. For an existing
    # home and managed-config parent, set only its own expected policy label.
    tool = next((path for path in ("/usr/sbin/matchpathcon", "/sbin/matchpathcon") if g.is_file(path)), None)
    if not tool:
        raise ValueError("SELinux SSH access requires matchpathcon to label directory metadata without recursively changing existing homes")
    for path in sorted(directories | files | ssh_paths):
        _safe(g, path)
        expected = _context(g.command([tool, "-n", path]))
        if path in directories - recursive:
            g.lsetxattr("security.selinux", expected, len(expected.encode()), path)
        try:
            actual = _context(g.lgetxattr(path, "security.selinux"))
        except RuntimeError as exc:
            raise ValueError("Offline SELinux relabel did not label " + path) from exc
        if actual != expected:
            raise ValueError("Offline SELinux context differs from the guest policy on " + path)
    _label_state(g, options)


def _state(g, options):
    files, directives = config_graph(g)
    _policy_check(directives, options)
    launch = _launch_evidence(g)
    if options.get("disable_password_auth"):
        if not files[CONFIG].startswith(POLICY) or any(values != ["no"] for _, _, key, values in directives if key in PASSWORD_KEYS):
            raise ValueError("Password authentication policy changed after native verification")
        if _read(g, CLOUD_POLICY) != CLOUD_TEXT:
            raise ValueError("Managed cloud-init password policy changed")
        for path in g.glob_expand("/etc/cloud/cloud.cfg.d/*.cfg"):
            files[path] = _read(g, path)
        if g.is_file("/etc/cloud/cloud.cfg"):
            files["/etc/cloud/cloud.cfg"] = _read(g, "/etc/cloud/cloud.cfg")
    users = {user["username"]: user for user in _accounts(g)}
    selected = []
    for entry in options.get("users", []):
        user = users.get(entry["username"])
        if not user:
            raise ValueError("SSH login user disappeared during preparation")
        _home(g, user)
        directory, path = user["home"] + "/.ssh", user["home"] + "/.ssh/authorized_keys"
        text = _read(g, path)
        for target, mode in ((directory, 0o700), (path, 0o600)):
            _safe(g, target)
            stat = g.statns(target)
            if stat["st_uid"] != user["uid"] or stat["st_gid"] != user["gid"] or stat["st_mode"] & 0o7777 != mode:
                raise ValueError("SSH key ownership or permissions were not retained: " + target)
        identities = {key_identity(line) for line in text.splitlines()}
        if any(key_identity(key) not in identities for key in entry["authorized_keys"]):
            raise ValueError("Requested authorized key was not retained")
        files[path] = text
        selected.append(user)
    files.update(launch)
    for path in ("/etc/passwd", "/etc/group"):
        files[path] = _read(g, path)
    hashes = {path: hashlib.sha256(text.encode()).hexdigest() for path, text in files.items()}
    # Native account validation depends on shadow; retain a digest only, never
    # expose password hashes or read them into the inspection/API inventory.
    if options.get("users"):
        _safe(g, "/etc/shadow", regular=True)
        if g.filesize("/etc/shadow") > LIMIT:
            raise ValueError("Local shadow database exceeds the verification limit")
        hashes["/etc/shadow"] = g.checksum("sha256", "/etc/shadow")
    if g.is_file("/etc/selinux/config"):
        hashes["/etc/selinux/config"] = hashlib.sha256(_read(g, "/etc/selinux/config").encode()).hexdigest()
    return {"files": hashes, "users": selected, "selinux": _label_state(g, options)}


def _native_relabel_flags():
    from .engine import _run
    help_text = _run(["virt-customize", "--help"])
    if re.search(r"(?<![\w-])--no-selinux-relabel(?![\w-])", help_text):
        return ["--no-selinux-relabel"]
    # Bookworm guestfs-tools 1.48.x relabels only with --selinux-relabel.
    # New tools changed that default; never infer an unknown interface's
    # behavior merely from absence of the newer disable switch.
    version = _run(["virt-customize", "--version"]).strip()
    if (re.search(r"\bvirt-customize\s+1\.48\.[0-9]+\b", version)
            and re.search(r"(?<![\w-])--selinux-relabel(?![\w-])", help_text)):
        return []
    raise ValueError("Cannot determine virt-customize relabel behavior; use the supplied Bookworm worker or a version advertising --no-selinux-relabel")


def _run_native(work, script, log):
    from .engine import _run
    relabel_flags = _native_relabel_flags()
    # --run executes the same guest-chroot script as --run-command, without
    # echoing its public-key material into a truncated error message.
    with tempfile.TemporaryDirectory(prefix="forge-ssh-access-") as directory:
        path = Path(directory) / "ssh-access.sh"
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            stream.write("#!/bin/sh\n" + script + "\n")
        command = ["virt-customize", "--format", "qcow2", "-a", str(work), "--no-network",
                   *relabel_flags, "--run", str(path)]
        _run(command, log)


def apply_access(work: Path, inspection, options, log):
    from .engine import EngineError, _guest, _mount, _roots
    from .models import SSHAccess
    options = SSHAccess.model_validate(options).model_dump()
    plan = plan_access(inspection, options)
    if not plan["requested"]:
        return None
    if not plan["ready"]:
        raise EngineError("SSH access blocked: " + " ".join(plan["blockers"]))
    log("Preparing requested SSH users, public keys and authentication policy")
    try:
        with _guest(work, "qcow2", readonly=True) as g:
            _mount(g, _roots(g), True)
            files, directives = config_graph(g)
            _policy_check(directives, options)
            _launch_evidence(g)
            accounts = {user["username"]: user for user in _accounts(g)}
            for user in options["users"]:
                name = user["username"]
                if user["create"]:
                    if name in accounts or g.exists("/home/" + name) or g.is_symlink("/home/" + name):
                        raise ValueError("New SSH account or home already exists: " + name)
                    _safe(g, "/home/" + name)
                elif name not in accounts:
                    raise ValueError("Requested SSH user no longer exists: " + name)
                else:
                    _home(g, accounts[name])
                    _safe(g, accounts[name]["home"] + "/.ssh/authorized_keys", regular=True)
        if any(user["create"] for user in options["users"]):
            _run_native(work, _native_script(options, "", create=True), log)
        with _guest(work, "qcow2", readonly=False) as g:
            _mount(g, _roots(g), False)
            accounts = {user["username"]: user for user in _accounts(g)}
            for entry in options["users"]:
                user = accounts[entry["username"]]
                _home(g, user)
                directory, path = user["home"] + "/.ssh", user["home"] + "/.ssh/authorized_keys"
                existing = _read(g, path, optional=True)
                updated, added = merge_keys(existing, entry["authorized_keys"])
                _write(g, path, updated, 0o600, user["uid"], user["gid"])
                g.chmod(0o700, directory)
                g.chown(user["uid"], user["gid"], directory)
                log(f"SSH: retained existing keys and added {added} key(s) for {user['username']}")
            if options["disable_password_auth"]:
                for path, text in files.items():
                    updated = disable_passwords(text, main=path == CONFIG)
                    if updated != text:
                        if path == CRYPTO_INCLUDE:
                            raise ValueError("Authentication directives in a crypto-policy include are unsupported")
                        stat = g.statns(path)
                        _write(g, path, updated, stat["st_mode"] & 0o7777, stat["st_uid"], stat["st_gid"])
                _cloud_policy(g)
        temp = "/run/forge-ssh-validation-" + uuid4().hex
        _run_native(work, _native_script(options, temp), log)
        with _guest(work, "qcow2", readonly=False) as g:
            _mount(g, _roots(g), False)
            if g.exists(temp):
                raise ValueError("Temporary SSH validation key was not removed")
            _relabel_access(g, options)
            receipt = _state(g, options)
        receipt.update({"options": options, "temp": temp, "warnings": plan["warnings"], "verified": True})
        log("Guest OpenSSH syntax and effective authentication verified; temporary validation host key removed")
        return receipt
    except (ValueError, RuntimeError, UnicodeError) as exc:
        raise EngineError("SSH access preparation failed: " + str(exc)) from exc


def verify_access(work: Path, receipt):
    from .engine import _guest, _mount, _roots
    if not receipt:
        return None
    try:
        if not receipt.get("verified") or not receipt.get("files"):
            raise ValueError("SSH validation receipt is missing")
        with _guest(work, "qcow2", readonly=True) as g:
            _mount(g, _roots(g), True)
            actual = _state(g, receipt["options"])
            if g.exists(receipt["temp"]):
                raise ValueError("Temporary SSH validation files remain")
        if (actual["files"] != receipt["files"] or actual["users"] != receipt["users"]
                or actual["selinux"] != receipt.get("selinux")):
            raise ValueError("SSH configuration, user identity, authorized keys or SELinux labels changed after native verification")
        return {"ready": True, "verified": True, "password_auth_disabled": receipt["options"]["disable_password_auth"],
                "users": [{"username": entry["username"], "created": entry["create"], "requested_keys": len(entry["authorized_keys"])} for entry in receipt["options"]["users"]],
                "selinux_labels_verified": bool(actual["selinux"]["enabled"]),
                "login_tested": False, "warnings": receipt["warnings"], "blockers": []}
    except (ValueError, RuntimeError, UnicodeError) as exc:
        return {"ready": False, "verified": False, "blockers": [str(exc)]}
