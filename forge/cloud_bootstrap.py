"""Narrow, read-only evidence for the audited Oracle cloud-init DHCP path.

This is deliberately not a YAML interpreter or a cloud-init simulator. The
profile was read-only audited on Oracle Linux 9.8, cloud-init
24.4-8.0.1.el9_8.1, on 2026-10-28. Its source/configuration fingerprints establish
the observed bootstrap behavior. Other implementations or syntax stay unknown.
No guest code, cached pickle, instance metadata or user-data is executed/read.
"""
from __future__ import annotations

import configparser
import hashlib
import posixpath
import re


SOURCE_HASHES = {
    "sources/DataSourceOracle.py": "7e7396059386e6c99f5591a61a21a01d1906627f9e76ff22c393813677738a71",
    "cmd/main.py": "97785c8fa8960d46f1f213a4cde284559518a841825f20224c1670418b3270ec",
    "helpers.py": "43deb130ff798e58aac6ce64e999e1734f4ce4d45fec234514abf921221adef1",
    "net/dhcp.py": "b1d29fbeb37a81bf64a33050dd17f0b25c0ee61fca43d98bbfc41399dd637d11",
    "net/ephemeral.py": "e3894c7e8371a57e4fbdbf8a7e6f214b7059683bae992c59e050303f410a9cdf",
}
UNIT_HASHES = {
    "NetworkManager.service": "5275dce5bd66cf3cef52173dbdf835bbbda76f386a30041c995ccc1f215fe48e",
    "cloud-init-local.service": "2ed9867099c943d625afee31ddc9df57227d58b9db0d0510fa7c99371f02df7a",
    "cloud-init.service": "21f8ede2a1c273a166646053a901822239ea55d25e68d2f8e99d3a6930fe4847",
    "cloud-config.service": "70c670f46eea29fb91a44dddf0af86db149bd7da065b8c98410102c07c086649",
    "cloud-final.service": "21cc194c58f4f342a8f8ecf32d8ebeb8a1eab65b4e4110e086a9e8c1b0f43ac1",
}
# Effective bootstrap-related settings in audited distribution files. In
# particular, the base cloud.cfg does not override networking or cache policy.
CONFIG_HASHES = {
    "cb8c119d0a002b3765873d549bffcc796c8f71da1ccf45cc017aa47ced33ea03": {},
    "b4b8674e13cf47acc4c21b77839cd6b980288376b4a7a550232ccf2a17f61469": {},
    "89469ec74955a4ff42889f65a744b5559718125bf5045029e93ff80694755e49": {"datasource_list": ["Oracle", "OpenStack"]},
}
LIMIT = 512 * 1024


def _settings(text):
    """Accept only simple, fully consumed overrides; never infer YAML meaning."""
    fingerprint = hashlib.sha256(text.encode()).hexdigest()
    if fingerprint in CONFIG_HASHES:
        return dict(CONFIG_HASHES[fingerprint])
    lines = [line.rstrip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    result = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.fullmatch(r"([a-z_]+):\s*(.*?)\s*(?:#.*)?", line)
        if not match or match[1] in result:
            raise ValueError("unsupported or duplicate YAML setting")
        key, value = match.groups()
        if key == "datasource_list":
            if not re.fullmatch(r"\[\s*[A-Za-z]+(?:\s*,\s*[A-Za-z]+)*\s*\]", value):
                raise ValueError("unsupported datasource list syntax")
            result[key] = re.findall(r"[A-Za-z]+", value)
        elif key in {"manual_cache_clean", "disable_network_activation", "disable_fallback_netcfg", "ssh_pwauth"}:
            if value not in {"true", "false"}:
                raise ValueError("unsupported boolean setting")
            # SSH password policy does not alter the audited DHCP/bootstrap path.
            # Retain it so duplicate declarations still fail closed.
            result[key] = value == "true"
        elif key == "network":
            if value == "{config: disabled}":
                result[key] = "disabled"
            elif not value and index + 1 < len(lines) and re.fullmatch(r" +config: +disabled\s*(?:#.*)?", lines[index + 1]):
                result[key] = "disabled"
                index += 1
            else:
                raise ValueError("network override requires manual review")
        else:
            raise ValueError("configuration is outside the audited bootstrap profile")
        index += 1
    return result


def inspect_bootstrap(g, base_oci_evidence):
    """Inspect a mounted guest; every operation is read-only and bounded."""
    files, evidence, blocked, unknown = set(), [], [], []
    total = 0

    def glob(pattern):
        matches = g.glob_expand(pattern)
        if len(matches) > 128:
            raise ValueError("bootstrap file inventory exceeds 128 entries")
        return matches

    def read(path, required=False):
        nonlocal total
        if not g.is_file(path):
            if required:
                unknown.append("Required bootstrap file is unavailable: " + path)
            return None
        size = g.filesize(path)
        total += size
        if size > LIMIT or total > 8 * LIMIT:
            raise ValueError("bootstrap content exceeds the inspection limit")
        files.add(path)
        value = g.read_file(path)
        return value.decode("utf-8") if isinstance(value, bytes) else value

    def present(path):
        return g.is_file(path) or g.is_dir(path) or g.is_symlink(path)

    def enabled(unit):
        links = glob("/etc/systemd/system/*.wants/" + unit)
        accepted = False
        for path in links:
            files.add(path)
            if not g.is_symlink(path):
                continue
            target = g.readlink(path)
            resolved = posixpath.normpath(target if target.startswith("/") else posixpath.join(posixpath.dirname(path), target))
            accepted |= resolved in {"/usr/lib/systemd/system/" + unit, "/lib/systemd/system/" + unit}
        return accepted

    try:
        tools = base_oci_evidence.get("tools", {})
        if not tools.get("cloud-init") or not base_oci_evidence.get("oracle_datasource"):
            blocked.append("Oracle cloud-init datasource/tool evidence is missing.")
        if base_oci_evidence.get("network_backend") != "NetworkManager":
            unknown.append("Only the audited Oracle NetworkManager bootstrap profile is verified.")
        roots = sorted(set(posixpath.dirname(posixpath.dirname(p)) for pattern in (
            "/usr/lib/python*/site-packages/cloudinit/sources/DataSourceOracle.py",
            "/usr/lib/python*/dist-packages/cloudinit/sources/DataSourceOracle.py") for p in glob(pattern)))
        if len(roots) != 1:
            unknown.append("A single installed Oracle cloud-init source tree is required.")
        else:
            for suffix, expected in SOURCE_HASHES.items():
                path = roots[0] + "/" + suffix
                text = read(path, True)
                if text is not None and hashlib.sha256(text.encode()).hexdigest() != expected:
                    unknown.append("Unreviewed Oracle bootstrap implementation: " + path)
        for name in ("dhclient", "ip", "NetworkManager"):
            paths = [directory + "/" + name for directory in ("/usr/sbin", "/sbin", "/usr/bin", "/bin")]
            executable = next((p for p in paths if g.is_file(p) and g.statns(p)["st_mode"] & 0o111), None)
            if executable:
                files.add(executable)
            else:
                blocked.append("Oracle ephemeral DHCP requires the installed executable " + name + ".")
        for path in ("/etc/cloud/cloud-init.disabled", "/var/lib/cloud/instance/manual-clean"):
            if present(path):
                files.add(path)
                blocked.append("Cloud-init disable/cache-trust marker prevents verified first-boot bootstrap: " + path)
        args = base_oci_evidence.get("boot_arguments", "")
        if re.search(r"\b(?:cloud-init|network-config)=disabled\b", args):
            blocked.append("Boot arguments disable cloud-init or its network configuration.")
        if re.search(r"\b(?:network-config|ip)=", args) and not re.search(r"\bnetwork-config=disabled\b", args):
            unknown.append("Kernel network configuration overrides require manual review.")
        settings = {}
        config_paths = ["/etc/cloud/cloud.cfg"] + sorted(glob("/etc/cloud/cloud.cfg.d/*.cfg"))
        for path in config_paths:
            text = read(path, True)
            if text is None:
                continue
            try:
                settings.update(_settings(text))
            except ValueError as exc:
                unknown.append(path + ": " + str(exc))
        if settings.get("datasource_list", [])[:1] != ["Oracle"]:
            blocked.append("Effective datasource order does not select Oracle first.")
        for key in ("manual_cache_clean", "disable_network_activation", "disable_fallback_netcfg"):
            if settings.get(key):
                blocked.append("Effective cloud-init " + key + " prevents verified bootstrap.")
        if settings.get("network") == "disabled":
            blocked.append("Effective cloud-init network configuration is disabled.")
        identify = read("/etc/cloud/ds-identify.cfg")
        if identify and any(line.strip() and not line.lstrip().startswith("#") for line in identify.splitlines()):
            unknown.append("Custom ds-identify policy requires manual review.")
        for unit, expected in UNIT_HASHES.items():
            path = "/usr/lib/systemd/system/" + unit
            text = read(path, True)
            if text is not None and hashlib.sha256(text.encode()).hexdigest() != expected:
                unknown.append("Unreviewed cloud-init service implementation: " + path)
            for value in re.findall(r"^EnvironmentFile=(.*)$", text or "", re.M):
                if not re.fullmatch(r"-?/[A-Za-z0-9_./-]+", value):
                    unknown.append("Bootstrap service environment path requires manual review: " + unit)
                    continue
                environment_path = value.removeprefix("-")
                files.add(environment_path)
                environment = read(environment_path)
                if environment and any(line.strip() and not line.lstrip().startswith("#") for line in environment.splitlines()):
                    unknown.append("Bootstrap service environment overrides require manual review: " + environment_path)
            override = "/etc/systemd/system/" + unit
            if present(override):
                files.add(override)
                if g.is_symlink(override) and g.readlink(override) == "/dev/null":
                    blocked.append("Cloud-init service is masked: " + unit)
                else:
                    unknown.append("Cloud-init unit override requires manual review: " + override)
            if not enabled(unit):
                blocked.append("Cloud-init service is not verifiably enabled: " + unit)
            for directory in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
                dropins = glob(directory + "/" + unit + ".d/*.conf")
                files.update(dropins)
                if dropins:
                    unknown.append("Cloud-init service drop-ins require manual review: " + unit)
        if not enabled("NetworkManager.service"):
            blocked.append("NetworkManager is not verifiably enabled.")
        manager_override = "/etc/systemd/system/NetworkManager.service"
        if present(manager_override):
            files.add(manager_override)
            unknown.append("NetworkManager unit override requires manual review.")
        for pattern in ("/etc/systemd/system.conf", "/etc/systemd/system.conf.d/*.conf",
                        "/etc/systemd/system/NetworkManager.service.d/*.conf",
                        "/etc/NetworkManager/NetworkManager.conf", "/etc/NetworkManager/conf.d/*.conf",
                        "/usr/lib/NetworkManager/conf.d/*.conf"):
            for path in glob(pattern):
                text = read(path) or ""
                active = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("#", ";")))
                if "/NetworkManager.service.d/" in path:
                    unknown.append("NetworkManager service drop-ins require manual review: " + path)
                if re.search(r"KERNEL_CMDLINE|(?:^|\n)\s*(?:unmanaged-devices\s*=\s*\S|managed\s*=\s*(?:0|false|no))", active):
                    unknown.append("Network or service environment override requires manual review: " + path)
        for path in base_oci_evidence.get("network_files", []):
            text = read(path, True)
            if text is None:
                continue
            if "/ifcfg-" in path:
                values = dict(re.findall(r"^([A-Z0-9_]+)=[\"']?([^\"'\n]*)[\"']?\s*$", text, re.M))
                generated = bool(re.search(r"^# Created by cloud-init\b", text, re.M))
                if not generated or values.get("BOOTPROTO") != "dhcp" or values.get("ONBOOT") != "yes" or values.get("NM_CONTROLLED", "yes") == "no" or any(key in values for key in ("IPADDR", "IPV6ADDR", "MACADDR")):
                    unknown.append("Preserved network profile is not the audited cloud-init DHCP output: " + path)
            else:
                parser = configparser.ConfigParser(interpolation=None, strict=True)
                try:
                    parser.read_string(text)
                    if (parser.get("ipv4", "method", fallback="") != "auto"
                            or parser.get("connection", "type", fallback="") not in {"ethernet", "802-3-ethernet"}
                            or parser.get("connection", "autoconnect", fallback="true").lower() in {"false", "no", "0"}
                            or parser.get("connection", "interface-name", fallback="")
                            or any(parser.get(s, "mac-address", fallback="") for s in ("ethernet", "802-3-ethernet"))):
                        raise ValueError("profile is not generic DHCP")
                except (ValueError, configparser.Error):
                    unknown.append("Preserved NetworkManager profile requires manual review: " + path)
        if not blocked and not unknown:
            evidence = ["Audited Oracle cloud-init 24.4 source provides ephemeral DHCP before metadata, primary NIC rendering, and new-instance UUID checking.",
                        "Oracle is first in the effective datasource order; automatic cache checks and networking are enabled.",
                        "Audited cloud-init units and NetworkManager are enabled, with no unreviewed bootstrap override.",
                        "Existing cloud-init DHCP profiles may remain bound to the prior NIC; the Oracle datasource can render the destination NIC on first boot."]
    except (RuntimeError, OSError, UnicodeError, ValueError, TypeError, KeyError, AttributeError) as exc:
        unknown.append("Bootstrap inspection is incomplete: " + type(exc).__name__)
    status = "blocked" if blocked else "unknown" if unknown else "ready"
    return {"version": 1, "status": status, "ready": status == "ready",
            "mechanism": "oracle_cloud_init" if status == "ready" else None,
            "evidence": evidence, "blockers": list(dict.fromkeys(blocked + unknown)), "files": sorted(files)}
