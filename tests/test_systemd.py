"""Offline unit graphs use guest filesystem evidence, never service execution."""
import posixpath
import unittest
from unittest.mock import patch

from forge.systemd import LIMITS, _cycles, inspect_systemd


VENDOR = "/usr/lib/systemd/system/"
LOCAL = "/etc/systemd/system/"


class FakeGuest:
    """Small guestfs read API suitable for UI graph fixtures as well."""
    def __init__(self, files=None, links=None, unreadable=()):
        self.files = dict(files or {})
        self.links = dict(links or {})
        self.unreadable = set(unreadable)
        self.reads = []

    def _check(self, path):
        if path in self.unreadable:
            raise RuntimeError("unreadable fixture")

    def _resolve(self, path):
        seen = set()
        while path in self.links:
            if path in seen:
                raise RuntimeError("symlink loop")
            seen.add(path)
            target = self.links[path]
            path = posixpath.normpath(target if target.startswith("/") else posixpath.join(posixpath.dirname(path), target))
        return path

    def is_dir(self, path):
        self._check(path)
        return any(name.startswith(path.rstrip("/") + "/") for name in (*self.files, *self.links))

    def ls(self, path):
        self._check(path)
        prefix = path.rstrip("/") + "/"
        return sorted({name[len(prefix):].split("/", 1)[0]
                       for name in (*self.files, *self.links) if name.startswith(prefix)})

    def is_symlink(self, path):
        self._check(path)
        return path in self.links

    def readlink(self, path):
        self._check(path)
        return self.links[path]

    def is_file(self, path):
        self._check(path)
        return self._resolve(path) in self.files

    def filesize(self, path):
        self._check(path)
        data = self.files[self._resolve(path)]
        return len(data.encode() if isinstance(data, str) else data)

    def read_file(self, path):
        self._check(path)
        self.reads.append(path)
        return self.files[self._resolve(path)]


def units(graph):
    return {unit["name"]: unit for unit in graph["units"]}


def edges(graph):
    return {(edge["source"], edge["relation"], edge["target"]) for edge in graph["edges"]}


class SystemdTests(unittest.TestCase):
    def test_activation_order_and_install_instructions_are_distinct(self):
        guest = FakeGuest({VENDOR + "sshd.service": """[Unit]
Description=SSH server
Wants=network-online.target
After=network.target auditd.service
[Service]
Type=notify
[Install]
WantedBy=multi-user.target
"""})
        graph = inspect_systemd(guest)
        self.assertTrue(graph["available"])
        self.assertFalse(graph["timing_available"])
        self.assertEqual(graph["mode"], "offline")
        self.assertEqual(edges(graph), {("sshd.service", "Wants", "network-online.target"),
                                       ("sshd.service", "After", "network.target"),
                                       ("sshd.service", "After", "auditd.service")})
        unit = units(graph)["sshd.service"]
        self.assertEqual(unit["unit_file_state"], "disabled")
        self.assertEqual(unit["service_type"], "notify")
        self.assertEqual(unit["description"], "SSH server")
        self.assertNotIn("multi-user.target", units(graph))
        self.assertEqual(units(graph)["auditd.service"]["load_state"], "missing")
        self.assertNotIn("duration", unit)

    def test_local_fragment_replaces_vendor_and_dropin_dependencies_cannot_reset(self):
        guest = FakeGuest({
            VENDOR + "demo.service": "[Unit]\nAfter=old.target\n",
            LOCAL + "demo.service": "[Unit]\nAfter=base.target\n",
            VENDOR + "demo.service.d/20-custom.conf": "[Unit]\nAfter=overridden.target\nDescription=vendor\n",
            LOCAL + "demo.service.d/20-custom.conf": "[Unit]\nAfter=local.target\nDescription=local\n",
            VENDOR + "demo.service.d/30-last.conf": "[Unit]\nAfter=\nAfter=last.target\nDescription=last\n",
        })
        graph = inspect_systemd(guest)
        self.assertEqual(edges(graph), {("demo.service", "After", target)
                                       for target in ("base.target", "local.target", "last.target")})
        self.assertEqual(units(graph)["demo.service"]["description"], "last")
        self.assertEqual(units(graph)["demo.service"]["fragment_path"], LOCAL + "demo.service")
        self.assertEqual(len(units(graph)["demo.service"]["dropins"]), 2)

    def test_aliases_enablement_and_alias_dropins_use_canonical_names(self):
        guest = FakeGuest({
            VENDOR + "ssh.service": "[Unit]\nDescription=SSH\n",
            VENDOR + "multi-user.target": "[Unit]\nDescription=Normal boot\n",
            LOCAL + "sshd.service.d/10-network.conf": "[Unit]\nAfter=network.target\n",
        }, {
            LOCAL + "sshd.service": VENDOR + "ssh.service",
            LOCAL + "default.target": VENDOR + "multi-user.target",
            LOCAL + "multi-user.target.wants/ssh-alias.service": VENDOR + "ssh.service",
        })
        graph = inspect_systemd(guest)
        self.assertEqual(graph["default_target"], "multi-user.target")
        self.assertEqual(graph["aliases"]["sshd.service"], "ssh.service")
        self.assertEqual(graph["aliases"]["ssh-alias.service"], "ssh.service")
        self.assertNotIn("sshd.service", units(graph))
        self.assertIn(("multi-user.target", "Wants", "ssh.service"), edges(graph))
        self.assertIn(("ssh.service", "After", "network.target"), edges(graph))
        self.assertEqual(units(graph)["ssh.service"]["enabled_by"], ["multi-user.target"])
        self.assertEqual(units(graph)["ssh.service"]["unit_file_state"], "enabled")

    def test_type_prefix_template_and_specific_dropins_with_same_name(self):
        guest = FakeGuest({
            VENDOR + "worker-mail@.service": "[Unit]\nAfter=base.target\n",
            LOCAL + "service.d/10-common.conf": "[Unit]\nAfter=type.target\n",
            LOCAL + "worker-.service.d/20-prefix.conf": "[Unit]\nAfter=prefix.target\n",
            LOCAL + "worker-mail@.service.d/10-common.conf": "[Unit]\nAfter=template.target\n",
            LOCAL + "worker-mail@blue.service.d/10-common.conf": "[Unit]\nAfter=instance.target\n",
        }, {LOCAL + "multi-user.target.wants/worker-mail@blue.service": VENDOR + "worker-mail@.service"})
        graph = inspect_systemd(guest)
        observed = {target for source, relation, target in edges(graph)
                    if source == "worker-mail@blue.service" and relation == "After"}
        self.assertEqual(observed, {"base.target", "prefix.target", "instance.target"})
        self.assertFalse(units(graph)["worker-mail@blue.service"]["is_template"])

    def test_template_specifiers_are_expanded_only_when_known(self):
        guest = FakeGuest({
            VENDOR + "worker@.service": "[Unit]\nDescription=Worker %i\nRequires=data@%i.service\nAfter=host-%H.target\n",
            VENDOR + "data@.service": "[Unit]\nDescription=Data %i\n",
        }, {LOCAL + "multi-user.target.wants/worker@blue.service": VENDOR + "worker@.service"})
        graph = inspect_systemd(guest)
        self.assertIn(("worker@blue.service", "Requires", "data@blue.service"), edges(graph))
        self.assertEqual(units(graph)["data@blue.service"]["load_state"], "loaded")
        self.assertEqual(units(graph)["worker@blue.service"]["description"], "Worker blue")
        self.assertTrue(any("%H" in warning for warning in units(graph)["worker@blue.service"]["warnings"]))
        self.assertFalse(any("%" in unit for unit in units(graph)))

    def test_comments_continuations_conditions_and_default_dependencies(self):
        guest = FakeGuest({VENDOR + "demo.service": """# explanatory comment
[Unit]
After=one.target \\
# comment inside a continuation
    "two.target"
Requires=three.target
Requires=four.target
DefaultDependencies=no
ConditionPathExists=/old
ConditionVirtualization=kvm
ConditionPathExists=
ConditionPathExists=/new
AssertPathExists=/required
RequiresMountsFor=/srv/data
"""})
        graph = inspect_systemd(guest)
        unit = units(graph)["demo.service"]
        self.assertFalse(unit["default_dependencies"])
        self.assertEqual(unit["conditions"], ["ConditionPathExists=/new", "AssertPathExists=/required"])
        self.assertEqual(len(edges(graph)), 4)
        self.assertIn(("demo.service", "After", "two.target"), edges(graph))
        self.assertNotIn("basic.target", units(graph))
        self.assertTrue(any("mount-derived" in value for value in unit["warnings"]))

    def test_masks_and_symlink_cycles_do_not_hide_other_units(self):
        guest = FakeGuest({VENDOR + "good.service": "[Unit]\nAfter=masked.service\n",
                           VENDOR + "empty.service": ""}, {
            LOCAL + "masked.service": "/dev/null",
            LOCAL + "loop-a.service": "loop-b.service",
            LOCAL + "loop-b.service": "loop-a.service",
        })
        graph = inspect_systemd(guest)
        for name in ("masked.service", "empty.service"):
            self.assertEqual(units(graph)[name]["load_state"], "masked")
        self.assertEqual(units(graph)["loop-a.service"]["load_state"], "unreadable")
        self.assertIn(("good.service", "After", "masked.service"), edges(graph))

    def test_masked_dropin_suppresses_vendor_file_with_same_basename(self):
        guest = FakeGuest({VENDOR + "demo.service": "[Unit]\nDescription=Demo\n",
                           VENDOR + "demo.service.d/10-extra.conf": "[Unit]\nAfter=hidden.target\n"},
                          {LOCAL + "demo.service.d/10-extra.conf": "/dev/null"})
        graph = inspect_systemd(guest)
        self.assertFalse(graph["edges"])
        self.assertEqual(units(graph)["demo.service"]["dropins"], [LOCAL + "demo.service.d/10-extra.conf"])

    def test_unreadable_directories_and_fragments_are_partial_evidence(self):
        guest = FakeGuest({VENDOR + "good.service": "[Unit]\nDescription=Good\n",
                           VENDOR + "bad.service": "[Unit]\nDescription=Bad\n"},
                          unreadable={LOCAL.rstrip("/"), VENDOR + "bad.service"})
        graph = inspect_systemd(guest)
        self.assertTrue(graph["available"])
        self.assertEqual(units(graph)["good.service"]["load_state"], "loaded")
        self.assertEqual(units(graph)["bad.service"]["load_state"], "unreadable")
        self.assertTrue(any("Could not list" in warning for warning in graph["warnings"]))

    def test_ordering_and_dependency_cycles_are_separate(self):
        guest = FakeGuest({
            VENDOR + "a.service": "[Unit]\nAfter=b.service\nWants=c.service\n",
            VENDOR + "b.service": "[Unit]\nAfter=a.service\n",
            VENDOR + "c.service": "[Unit]\nWants=a.service\n",
        })
        graph = inspect_systemd(guest)
        self.assertEqual(graph["cycles"], [{"kind": "ordering", "units": ["a.service", "b.service"]},
                                          {"kind": "dependencies", "units": ["a.service", "c.service"]}])

    def test_large_cycle_traversal_does_not_use_python_recursion(self):
        names = [f"unit-{index}.service" for index in range(1500)]
        relations = [{"source": name, "target": names[(index + 1) % len(names)], "relation": "After"}
                     for index, name in enumerate(names)]
        result = _cycles(names, relations)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]["units"]), 1500)

    def test_limits_bound_reads_nodes_edges_and_mark_incompleteness(self):
        guest = FakeGuest({VENDOR + "a.service": "[Unit]\nAfter=b.service c.service d.service\n",
                           VENDOR + "huge.service": "x" * 200})
        with patch.dict(LIMITS, {"units": 3, "edges": 2, "file_bytes": 100}):
            graph = inspect_systemd(guest)
        self.assertTrue(graph["truncated"])
        self.assertLessEqual(len(graph["units"]), 3)
        self.assertLessEqual(len(graph["edges"]), 2)
        self.assertNotIn(VENDOR + "huge.service", guest.reads)
        self.assertTrue(all(edge["source"] in units(graph) and edge["target"] in units(graph)
                            for edge in graph["edges"]))

    def test_inspection_preserves_guest_files_and_handles_non_systemd_images(self):
        files = {"/etc/issue": "Non-systemd OS"}
        guest = FakeGuest(files)
        graph = inspect_systemd(guest)
        self.assertFalse(graph["available"])
        self.assertEqual(graph["units"], [])
        self.assertEqual(guest.files, files)
        self.assertEqual(guest.reads, [])

    def test_external_linked_unit_remains_guest_local_and_type_mismatch_is_unreadable(self):
        guest = FakeGuest({"/opt/services/custom.unit": "[Unit]\nDescription=External fragment\n",
                           VENDOR + "normal.target": "[Unit]\nDescription=Target\n"}, {
            LOCAL + "linked.service": "/opt/services/custom.unit",
            LOCAL + "wrong.service": VENDOR + "normal.target",
        })
        graph = inspect_systemd(guest)
        self.assertEqual(units(graph)["linked.service"]["description"], "External fragment")
        self.assertEqual(units(graph)["wrong.service"]["load_state"], "unreadable")
        self.assertNotIn("linked.service", graph["aliases"])

    def test_invalid_template_aliases_do_not_claim_a_loaded_service(self):
        guest = FakeGuest({VENDOR + "worker@.service": "[Unit]\nDescription=Worker\n",
                           VENDOR + "worker@green.service": "[Unit]\nDescription=Green\n"}, {
            LOCAL + "plain.service": VENDOR + "worker@.service",
            LOCAL + "worker@blue.service": VENDOR + "worker@green.service",
        })
        graph = inspect_systemd(guest)
        self.assertEqual(units(graph)["plain.service"]["load_state"], "unreadable")
        self.assertEqual(units(graph)["worker@blue.service"]["load_state"], "unreadable")

    def test_install_list_reset_and_empty_default_target_are_not_false_enablement(self):
        guest = FakeGuest({
            VENDOR + "demo.service": "[Unit]\nDescription=Demo\n[Install]\nWantedBy=multi-user.target\n",
            LOCAL + "demo.service.d/10-reset.conf": "[Install]\nWantedBy=\n",
            LOCAL + "default.target": "",
        })
        graph = inspect_systemd(guest)
        self.assertEqual(units(graph)["demo.service"]["unit_file_state"], "static")
        self.assertIsNone(graph["default_target"])


if __name__ == "__main__":
    unittest.main()
