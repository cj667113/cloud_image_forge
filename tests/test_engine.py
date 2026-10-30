"""Safety invariants and conversion orchestration; no libguestfs installation needed."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from forge.engine import (EngineError, GIB, MIB, ImageEngine, _grub_assignment,
                          _input_format, _roots, _run, _validate_fstab, _validate_recipe, _mount, _run_guest_script)


def qcow_header(*, backing=False, external=False, encrypted=False):
    header = bytearray(512)
    struct.pack_into(">4sI", header, 0, b"QFI\xfb", 3)
    struct.pack_into(">QI", header, 8, 128 if backing else 0, 8 if backing else 0)
    struct.pack_into(">I", header, 32, 2 if encrypted else 0)
    struct.pack_into(">Q", header, 72, 4 if external else 0)
    return header


def inspection():
    return {"format": "qcow2", "virtual_size": 10 * GIB, "os": {"arch": "x86_64"},
            "partitions": [{"device": "/dev/sda1", "filesystem": "ext4", "size": 9 * GIB},
                           {"device": "/dev/sda2", "filesystem": "xfs", "size": GIB},
                           {"device": "/dev/vg/root", "filesystem": "xfs", "size": GIB, "logical_volume": True}],
            "kernels": ["/boot/vmlinuz-6.8.0"],
            "boot": {"mode": "uefi", "supported_firmware": ["UEFI_64"], "boot_tested": False}}


class HeaderTests(unittest.TestCase):
    def test_qcow_security_checks_happen_before_any_external_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.qcow2"
            for flag, message in (("backing", "Backing-file"), ("external", "external data"),
                                  ("encrypted", "Encrypted")):
                with self.subTest(flag=flag):
                    path.write_bytes(qcow_header(**{flag: True}))
                    with patch("forge.engine._run") as run:
                        with self.assertRaisesRegex(EngineError, message):
                            ImageEngine().inspect(path)
                        run.assert_not_called()

    def test_vhd_differencing_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.vhd"
            footer = bytearray(512)
            footer[:8] = b"conectix"
            struct.pack_into(">I", footer, 60, 4)
            path.write_bytes(footer)
            with self.assertRaisesRegex(EngineError, "differencing"):
                _input_format(path)
            struct.pack_into(">I", footer, 60, 2)
            path.write_bytes(footer)
            self.assertEqual(_input_format(path), "vpc")

    def test_embedded_vmdk_descriptor_rejected_even_with_raw_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.raw"
            path.write_bytes(b"# Disk DescriptorFile" + b"\x00" * 512)
            with self.assertRaisesRegex(EngineError, "VMDK"):
                _input_format(path)

    def test_inspection_rejects_symlink_before_resolving_it(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "disk.qcow2"
            source.write_bytes(qcow_header())
            link = Path(directory) / "alias.qcow2"
            link.symlink_to(source)
            with patch("forge.engine._run") as run:
                with self.assertRaisesRegex(EngineError, "non-symlink"):
                    ImageEngine().inspect(link)
                run.assert_not_called()

    def test_virtual_size_limit_precedes_appliance_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.qcow2"
            path.write_bytes(qcow_header())
            with patch("forge.engine._run", return_value=json.dumps({"virtual-size": 2049 * GIB})), \
                    patch("forge.engine._guest") as guest, \
                    patch.dict(os.environ, {"FORGE_MAX_VIRTUAL_GIB": "2048"}):
                with self.assertRaisesRegex(EngineError, "at most 2048"):
                    ImageEngine().inspect(path)
                guest.assert_not_called()

    def test_both_64_bit_architectures_are_accepted_and_32_bit_is_rejected(self):
        from unittest.mock import Mock
        guest = Mock()
        guest.inspect_os.return_value = ["/dev/sda1"]
        guest.inspect_get_type.return_value = "linux"
        for arch in ("aarch64", "arm64", "x86_64", "amd64"):
            guest.inspect_get_arch.return_value = arch
            self.assertEqual(_roots(guest), "/dev/sda1")
        guest.inspect_get_arch.return_value = "arm"
        with self.assertRaisesRegex(EngineError, "32-bit"):
            _roots(guest)


class InspectionTests(unittest.TestCase):
    def test_actual_mounts_resolve_persistent_aliases_and_independent_root(self):
        guest = Mock()
        guest.inspect_get_mountpoints.return_value = {
            "/": "/dev/disk/by-id/old-root", "/boot": "/dev/disk/by-uuid/boot-id"}
        guest.mountpoints.return_value = {"/dev/vg/root": "/", "/dev/sda2": "/boot"}
        points = _mount(guest, "/dev/vg/root", True)
        self.assertEqual(points, {"/": "/dev/vg/root", "/boot": "/dev/sda2"})
        self.assertEqual(guest.mount_ro.call_args_list[0].args, ("/dev/vg/root", "/"))
        guest.mount_ro.assert_any_call("/dev/disk/by-uuid/boot-id", "/boot")

    def test_boot_scan_precedes_os_mounts_and_is_shared_with_oci(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "disk.qcow2"
            source.write_bytes(qcow_header())
            g = Mock()
            g.list_filesystems.return_value = {}
            g.list_partitions.return_value = []
            g.lvs.return_value = []
            g.is_file.return_value = False
            g.is_dir.return_value = False
            g.glob_expand.return_value = []
            g.inspect_get_product_name.return_value = "Linux"
            g.inspect_get_distro.return_value = "oraclelinux"
            g.inspect_get_arch.return_value = "x86_64"
            events = []
            boot = inspection()["boot"]
            systemd = {"version": 1, "available": True, "units": [], "edges": [], "timing_available": False}

            @contextmanager
            def guest(*args, **kwargs):
                self.assertNotEqual(kwargs.get("readonly"), False)
                yield g

            def detect(handle, architecture):
                self.assertIs(handle, g)
                self.assertEqual(architecture, "x86_64")
                events.append("boot")
                return boot

            def mount(handle, root, readonly):
                self.assertEqual(events, ["boot"])
                self.assertTrue(readonly)
                events.append("root")
                return {}

            with patch("forge.engine._guest", guest), patch("forge.engine._run"), \
                    patch("forge.engine._image_info", return_value={"virtual-size": GIB}), \
                    patch("forge.engine._roots", return_value="/dev/sda2"), \
                    patch("forge.engine._mount", side_effect=mount), \
                    patch("forge.boot.detect_boot", side_effect=detect), \
                    patch("forge.uefi.inspect_layout", return_value={}), \
                    patch("forge.uefi.inspect_prerequisites", return_value={}), \
                    patch("forge.systemd.inspect_systemd", return_value=systemd) as systemd_scan, \
                    patch("forge.oci_guest.inspect_guest", return_value={}) as oci:
                result = ImageEngine().inspect(source)
            self.assertEqual(events, ["boot", "root"])
            self.assertEqual(result["boot"], boot)
            self.assertEqual(result["systemd"], systemd)
            self.assertEqual(result["services"], [])
            systemd_scan.assert_called_once_with(g)
            oci.assert_called_once_with(g, "/dev/sda2", [], [], boot=boot)


class FstabTests(unittest.TestCase):
    def test_comments_optional_fields_and_escaped_spaces_are_accepted(self):
        _validate_fstab("# comment\nUUID=root / ext4 defaults 0 1\nLABEL=My\\040Disk /mnt/my\\040disk ext4 nofail\n/swapfile none swap sw 0 0\n")

    def test_broken_field_count_and_numeric_columns_are_rejected(self):
        for line in ("UUID=root / ext4", "UUID=root / ext4 defaults zero 1", "UUID=root relative ext4 defaults 0 1"):
            with self.subTest(line=line), self.assertRaisesRegex(EngineError, "fstab line 1"):
                _validate_fstab(line)

    def test_required_unknown_uuid_fails_but_optional_future_volume_passes(self):
        from unittest.mock import Mock
        guest = Mock()
        guest.findfs_uuid.side_effect = RuntimeError("not found")
        with self.assertRaisesRegex(EngineError, "does not exist"):
            _validate_fstab("UUID=missing /data ext4 defaults 0 2", guest)
        guest.findfs_uuid.reset_mock()
        _validate_fstab("UUID=future /data ext4 defaults,nofail 0 2", guest)
        guest.findfs_uuid.assert_not_called()
        with self.assertRaisesRegex(EngineError, "does not exist"):
            _validate_fstab("UUID=missing / ext4 nofail 0 1", guest)

    def test_label_resolution_preserves_escaped_spaces(self):
        from unittest.mock import Mock
        guest = Mock()
        _validate_fstab("LABEL=My\\040Disk /data ext4 defaults", guest)
        guest.findfs_label.assert_called_once_with("My Disk")


class CommandTests(unittest.TestCase):
    def test_guest_script_uses_private_file_and_cleans_it_on_success_or_failure(self):
        script = "set -eu\necho public-diagnostic"
        for fails in (False, True):
            with self.subTest(fails=fails):
                paths = []
                def run(command, log):
                    path = Path(command[command.index("--run") + 1])
                    paths.append(path)
                    self.assertEqual(path.read_text(), "#!/bin/sh\n" + script + "\n")
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                    self.assertIn("--network", command)
                    self.assertIn("--selinux-relabel", command)
                    self.assertNotIn(script, command)
                    if fails:
                        raise EngineError("actual guest failure")
                    return "complete"
                with patch("forge.engine._run", side_effect=run):
                    if fails:
                        with self.assertRaisesRegex(EngineError, "actual guest failure"):
                            _run_guest_script(Path("work.qcow2"), script, lambda _: None, allow_network=True)
                    else:
                        self.assertEqual(_run_guest_script(Path("work.qcow2"), script, lambda _: None, allow_network=True), "complete")
                self.assertTrue(paths)
                self.assertFalse(paths[0].parent.exists())

    def test_failure_retains_native_stdout_when_wrapper_stderr_is_long(self):
        program = "import sys; print('native initramfs assertion failed'); sys.stderr.write('wrapper' * 1000); sys.exit(1)"
        with self.assertRaisesRegex(EngineError, "native initramfs assertion failed") as error:
            _run([sys.executable, "-c", program])
        self.assertLess(len(str(error.exception)), 5200)

    def test_tool_output_memory_is_bounded(self):
        result = _run([sys.executable, "-c", "import sys; sys.stdout.write('x' * (3 * 1024 * 1024))"])
        self.assertEqual(len(result), 2 * MIB)

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    def test_timeout_kills_descendants_not_just_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            orphan = Path(directory) / "orphan"
            child = f"from pathlib import Path; import time; Path({str(ready)!r}).touch(); time.sleep(2); Path({str(orphan)!r}).touch()"
            parent = f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(60)"
            with patch.dict(os.environ, {"FORGE_COMMAND_TIMEOUT": "1"}):
                with self.assertRaisesRegex(EngineError, "process group was stopped"):
                    _run([sys.executable, "-c", parent])
            self.assertTrue(ready.exists(), "Child was running before timeout")
            time.sleep(1.2)
            self.assertFalse(orphan.exists(), "A surviving descendant wrote after timeout")


class RecipeTests(unittest.TestCase):
    def test_preservation_rejects_automatic_mutations_before_disk_commands(self):
        base = {"enabled": True, "strategy": "preserve"}
        for field in ("install_packages", "configure_network", "configure_serial_console"):
            with self.subTest(field=field), self.assertRaisesRegex(EngineError, "Preserve and validate"):
                _validate_recipe({"platform_migration": {**base, field: True}}, inspection())
        for oci in ({}, {"guest": {"prepare": True}}):
            with self.subTest(oci=oci), self.assertRaisesRegex(EngineError, "OCI guest preparation disabled"):
                _validate_recipe({"target": "oci", "platform_migration": base, "oci": oci}, inspection())
        _validate_recipe({"target": "oci", "platform_migration": base,
                          "oci": {"guest": {"prepare": False}}}, inspection())

    def test_xfs_shrink_is_blocked_before_disk_commands(self):
        recipe = {"partition_changes": [{"device": "/dev/sda2", "size_mib": 512}]}
        with self.assertRaisesRegex(EngineError, "XFS and LVM"):
            _validate_recipe(recipe, inspection())

    def test_ext4_shrink_allowed_and_lvm_size_change_rejected(self):
        _validate_recipe({"partition_changes": [{"device": "/dev/sda1", "size_mib": 4096}]}, inspection())
        with self.assertRaisesRegex(EngineError, "unique inspected"):
            _validate_recipe({"partition_changes": [{"device": "/dev/vg/root", "size_mib": 4096}]}, inspection())

    def test_incompatible_target_is_rejected(self):
        with self.assertRaisesRegex(EngineError, "requires raw"):
            _validate_recipe({"target": "aws", "output_format": "qcow2"}, inspection())

    def test_package_and_file_injection_are_rejected(self):
        for recipe in ({"packages_remove": ["--all"]}, {"packages_install": ["kernel; touch /host"]},
                       {"files": [{"path": "/../../etc/passwd", "content": "bad"}]},
                       {"services": [{"name": "sshd.service;id", "action": "enable"}]}):
            with self.subTest(recipe=recipe), self.assertRaises(EngineError):
                _validate_recipe(recipe, inspection())

    def test_install_requires_explicit_network(self):
        with self.assertRaisesRegex(EngineError, "network access"):
            _validate_recipe({"packages_install": ["kernel"]}, inspection())

    def test_grub_assignment_escapes_shell_values_and_backslashes(self):
        value = "console=ttyS0 strange='$(touch /tmp/no)' backslash=\\1"
        text = _grub_assignment("GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX=quiet\n", "GRUB_CMDLINE_LINUX", value)
        self.assertIn("GRUB_TIMEOUT=5", text)
        self.assertNotIn("GRUB_CMDLINE_LINUX=quiet", text)
        self.assertIn("backslash=\\1", text)
        import shlex
        self.assertEqual(shlex.split(text.split("GRUB_CMDLINE_LINUX=", 1)[1])[0], value)


class BuildTests(unittest.TestCase):
    def setUp(self):
        # Other orchestration tests isolate disk access; mount reconciliation
        # has separate real-inventory tests and explicit publication tests below.
        receipt = {"version": 1, "changed": False, "warnings": [], "changes": [],
                   "uuid_map": [], "boot_reference_check_required": False}
        for name, value in (("reconcile_mounts", receipt), ("verify_mounts", {"ready": True, "blockers": []}),
                            ("verify_mount_boot_references", {"ready": True, "required": False, "blockers": []})):
            patcher = patch("forge.storage." + name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def test_mount_failure_blocks_artifact_conversion_and_preserves_source(self):
        def reject(work, receipt):
            self.assertFalse((work.parent / "image.qcow2").exists())
            self.assertEqual((work.parent.parent / "source.qcow2").read_bytes(), qcow_header())
            return {"ready": False, "blockers": ["Root UUID changed unexpectedly"]}
        self.verify_mounts.side_effect = reject
        with self.assertRaisesRegex(EngineError, "Final mount verification.*Root UUID"):
            self.run_build()
        self.verify_mount_boot_references.assert_not_called()

    def test_stale_boot_reference_check_survives_later_noop_reconciliation(self):
        common = {"version": 1, "changed": False, "warnings": [], "changes": [], "uuid_map": []}
        self.reconcile_mounts.side_effect = [
            {**common, "changed": True, "boot_reference_check_required": True,
             "changes": [{"mountpoint": "/", "from": "UUID=stale", "to": "UUID=current"}]},
            {**common, "boot_reference_check_required": False}]
        self.verify_mount_boot_references.return_value = {"ready": False, "blockers": ["Stale initramfs root selector"]}
        with self.assertRaisesRegex(EngineError, "Final boot mount verification.*Stale initramfs"):
            self.run_build()
        receipt = self.verify_mount_boot_references.call_args.args[1]
        self.assertTrue(receipt["boot_reference_check_required"])
        self.assertEqual(receipt["changes"][0]["from"], "UUID=stale")

    def test_prepared_inspection_is_reused_only_until_a_later_disk_write(self):
        from forge.oci import OciConfig
        for sparsify in (False, True):
            with self.subTest(sparsify=sparsify), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                source = directory / "source.qcow2"
                source.write_bytes(qcow_header())
                info = inspection()
                prepared = {**info, "prepared_snapshot": True}
                engine = ImageEngine()
                def run(command, log=None):
                    if command[:2] == ["qemu-img", "convert"]:
                        Path(command[-1]).write_bytes(qcow_header())
                    return ""
                with patch("forge.engine._run", side_effect=run), \
                        patch("forge.engine._image_info", return_value={"virtual-size": info["virtual_size"]}), \
                        patch.object(engine, "capabilities", return_value={"available": True}), \
                        patch.object(engine, "inspect", side_effect=[info, prepared] if sparsify else [info]) as inspect, \
                        patch.object(engine, "_customize"), \
                        patch("forge.oci.compatibility_plan", return_value={"blockers": []}), \
                        patch("forge.oci_guest.prepare_guest", return_value={"warnings": [], "_inspection": prepared}):
                    result = engine.build(source, directory / "build", info,
                                          {"target": "oci", "oci": OciConfig().model_dump(), "sparsify": sparsify}, lambda _: None)
                self.assertEqual(inspect.call_count, 2 if sparsify else 1)
                self.assertNotIn("_inspection", result)

    def test_ssh_applies_after_provider_preparation_and_verifies_before_conversion(self):
        from forge.oci import OciConfig
        for ready in (True, False):
            with self.subTest(ready=ready), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                source = directory / "source.qcow2"
                source.write_bytes(qcow_header())
                baseline = source.read_bytes()
                info, events, conversions = inspection(), [], []
                engine = ImageEngine()
                def run(command, log=None):
                    if command[:2] == ["qemu-img", "convert"]:
                        conversions.append(command)
                        Path(command[-1]).write_bytes(qcow_header())
                    return ""
                def provider(*args, **kwargs):
                    events.append("provider")
                    return {"warnings": []}
                def ssh(*args, **kwargs):
                    self.assertEqual(events, ["explicit", "provider"])
                    events.append("ssh")
                    return {"warnings": [], "verified": True}
                def verify(work, receipt):
                    self.assertEqual(events, ["explicit", "provider", "ssh"])
                    self.assertEqual(len(conversions), 1)
                    return {"ready": ready, "blockers": [] if ready else ["SSH file changed"], "verified": ready}
                with patch("forge.engine._run", side_effect=run), \
                        patch("forge.engine._image_info", return_value={"virtual-size": info["virtual_size"]}), \
                        patch.object(engine, "capabilities", return_value={"available": True}), \
                        patch.object(engine, "inspect", return_value=info), \
                        patch.object(engine, "_customize", side_effect=lambda *args: events.append("explicit")), \
                        patch("forge.oci.compatibility_plan", return_value={"blockers": []}), \
                        patch("forge.oci_guest.prepare_guest", side_effect=provider), \
                        patch("forge.ssh_access.apply_access", side_effect=ssh), \
                        patch("forge.ssh_access.verify_access", side_effect=verify):
                    recipe = {"target": "oci", "oci": OciConfig().model_dump(), "sparsify": False,
                              "ssh_access": {"disable_password_auth": True, "users": []}}
                    if ready:
                        result = engine.build(source, directory / "build", info, recipe, lambda _: None)
                        self.assertTrue(result["ssh_access"]["verified"])
                    else:
                        with self.assertRaisesRegex(EngineError, "Final SSH access.*SSH file changed"):
                            engine.build(source, directory / "build", info, recipe, lambda _: None)
                self.assertEqual(len(conversions), 2 if ready else 1)
                self.assertEqual(source.read_bytes(), baseline)

    def test_preservation_validates_after_explicit_edits_and_before_publication(self):
        for final_ready in (True, False):
            with self.subTest(final_ready=final_ready), tempfile.TemporaryDirectory() as directory:
                directory = Path(directory)
                source = directory / "source.qcow2"
                source.write_bytes(qcow_header())
                original = source.read_bytes()
                info = inspection()
                edited = {**info, "test_stage": "after-explicit-edits"}
                final = {**info, "test_stage": "final-working-disk"}
                events, conversions = [], []
                engine = ImageEngine()
                receipt = {"warnings": [], "preservation_manifest": {"kernel": "unchanged-hash"}}
                plan = {"requested": True, "ready": True, "blockers": [], "required_modules": []}
                recipe = {"target": "generic", "output_format": "qcow2", "sparsify": True,
                          "platform_migration": {"enabled": True, "strategy": "preserve"},
                          "kernel_args": "loglevel=4"}

                def run(command, log=None):
                    if command[:2] == ["qemu-img", "convert"]:
                        conversions.append(command)
                        Path(command[-1]).write_bytes(qcow_header())
                    if command[0] == "virt-sparsify":
                        events.append("sparsify")
                    return ""

                def prepare(work, current, *args, **kwargs):
                    self.assertEqual(current, edited)
                    self.assertEqual(events, ["explicit-edits"])
                    events.append("preserve-baseline")
                    return receipt

                def verify(current, *args, **kwargs):
                    self.assertEqual(current, final)
                    self.assertIs(kwargs["receipt"], receipt)
                    self.assertEqual(events, ["explicit-edits", "preserve-baseline", "sparsify"])
                    return {"ready": final_ready, "blockers": [] if final_ready else ["Preserved boot file changed"],
                            "strategy": "preserve", "boot_tested": False}

                with patch("forge.engine._run", side_effect=run), \
                        patch("forge.engine._image_info", return_value={"virtual-size": info["virtual_size"]}), \
                        patch.object(engine, "capabilities", return_value={"available": True}), \
                        patch.object(engine, "inspect", side_effect=[edited, final]), \
                        patch.object(engine, "_customize", side_effect=lambda *a: events.append("explicit-edits")), \
                        patch("forge.platform.plan_platform", return_value=plan), \
                        patch("forge.platform.prepare_platform", side_effect=prepare), \
                        patch("forge.platform.verify_platform", side_effect=verify):
                    if final_ready:
                        result = engine.build(source, directory / "build", info, recipe, lambda _: None)
                        self.assertEqual(result["platform_migration"]["strategy"], "preserve")
                        self.assertFalse(result["platform_migration"]["boot_tested"])
                    else:
                        with self.assertRaisesRegex(EngineError, "Preserved boot file changed"):
                            engine.build(source, directory / "build", info, recipe, lambda _: None)
                self.assertEqual(len(conversions), 2 if final_ready else 1)
                self.assertEqual(source.read_bytes(), original)

    def run_build(self, *, output_format="qcow2", compare_failure=False, virtual_size=10 * GIB,
                  guest_arch="x86_64", architecture_change=False, mount_policy="auto", extra_recipe=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        source = directory / "source.qcow2"
        source.write_bytes(qcow_header())
        baseline = source.read_bytes()
        commands = []
        info = inspection()
        info["virtual_size"] = virtual_size
        info["os"]["arch"] = guest_arch
        final_info = {**info, "os": {"arch": "aarch64" if guest_arch == "x86_64" else "x86_64"}} if architecture_change else info
        engine = ImageEngine()
        recipe = {"output_format": output_format, "sparsify": False, "mount_policy": mount_policy,
                  **(extra_recipe or {})}

        def run(command, log=None):
            commands.append(command)
            if command[:2] == ["qemu-img", "info"]:
                return json.dumps({"format": command[4], "virtual-size": virtual_size})
            if command[:2] == ["qemu-img", "convert"]:
                Path(command[-1]).write_bytes(qcow_header())
            if command[:2] == ["qemu-img", "compare"] and compare_failure:
                raise EngineError("Guest-visible bytes differ")
            return ""

        with patch("forge.engine._run", side_effect=run), \
                patch.object(engine, "capabilities", return_value={"available": True}), \
                patch.object(engine, "inspect", return_value=final_info), \
                patch.object(engine, "_customize"):
            if compare_failure or architecture_change:
                with self.assertRaisesRegex(EngineError, "guest CPU architecture" if architecture_change else "bytes differ"):
                    engine.build(source, directory / "build", info,
                                 recipe, lambda _: None)
                result = None
            else:
                result = engine.build(source, directory / "build", info,
                                      recipe, lambda _: None)
        self.assertEqual(source.read_bytes(), baseline)
        return result, commands

    def test_labels_policy_is_carried_through_reconciliation_and_published_receipt(self):
        result, commands = self.run_build(mount_policy="labels")
        self.assertEqual(result["mount_reconciliation"]["policy"], "labels")
        self.assertEqual(len(self.reconcile_mounts.call_args_list), 2)
        self.assertTrue(all(call.args[2] == "labels" for call in self.reconcile_mounts.call_args_list))
        self.verify_mounts.assert_called_once()
        self.assertTrue(any(command[:2] == ["qemu-img", "compare"] for command in commands))

    def test_arm_export_retains_architecture_and_changes_block_publication(self):
        result, _ = self.run_build(guest_arch="aarch64")
        self.assertEqual(result["architecture"], "aarch64")
        result, commands = self.run_build(guest_arch="aarch64", architecture_change=True)
        self.assertIsNone(result)
        self.assertEqual(sum(command[:2] == ["qemu-img", "convert"] for command in commands), 1)

    def test_qcow_export_compares_content_and_uses_oci_compatible_compression(self):
        result, commands = self.run_build()
        self.assertEqual(len(result["sha256"]), 64)
        self.assertTrue(Path(result["artifact_path"]).exists())
        self.assertIn("compression_type=zlib", " ".join(" ".join(c) for c in commands))
        self.assertTrue(any(c[:2] == ["qemu-img", "compare"] for c in commands))
        self.assertFalse(Path(result["artifact_path"]).with_name("working.qcow2").exists())
        self.assertEqual(result["boot"], inspection()["boot"])

    def test_final_oci_boot_support_is_checked_before_export(self):
        from forge.oci import OciConfig
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "source.qcow2"
            source.write_bytes(qcow_header())
            info = inspection()
            after = inspection()
            after["boot"] = {"mode": "unknown", "supported_firmware": [], "boot_tested": False}
            engine = ImageEngine()
            commands = []

            def run(command, log=None):
                commands.append(command)
                if command[:2] == ["qemu-img", "convert"]:
                    Path(command[-1]).write_bytes(qcow_header())
                return ""

            with patch("forge.engine._run", side_effect=run), \
                    patch("forge.engine._image_info", return_value={"virtual-size": info["virtual_size"]}), \
                    patch.object(engine, "capabilities", return_value={"available": True}), \
                    patch.object(engine, "inspect", return_value=after), \
                    patch.object(engine, "_customize"), \
                    patch("forge.oci.compatibility_plan", return_value={"blockers": []}), \
                    patch("forge.oci_guest.prepare_guest", return_value={"warnings": []}):
                with self.assertRaisesRegex(EngineError, "Final OCI image lacks.*UEFI_64"):
                    engine.build(source, directory / "build", info,
                                 {"target": "oci", "oci": OciConfig().model_dump(), "sparsify": False}, lambda _: None)
            conversions = [command for command in commands if command[:2] == ["qemu-img", "convert"]]
            self.assertEqual(len(conversions), 1, "No published artifact conversion should run")

    def test_failed_byte_comparison_never_returns_success(self):
        result, _ = self.run_build(compare_failure=True)
        self.assertIsNone(result)

    def test_azure_uses_fixed_vhd(self):
        _, commands = self.run_build(output_format="vhd")
        self.assertTrue(any("subformat=fixed,force_size" in c for c in commands))

    def test_gcp_archive_contains_only_root_disk_raw(self):
        import tarfile
        result, _ = self.run_build(output_format="gcp")
        with tarfile.open(result["artifact_path"], "r:gz") as archive:
            self.assertEqual(archive.getnames(), ["disk.raw"])

    def test_oci_archive_wraps_the_checked_qcow2_and_publishes_verified_metadata(self):
        import tarfile
        recipe = {"target": "oci", "oci": {"guest": {"prepare": False}, "import_options": {
            "operating_system": "Ubuntu", "operating_system_version": "26.04.1"}}}
        def prepared(work, inspected, *args, **kwargs):
            return {"_inspection": inspected, "warnings": []}
        with patch("forge.oci.compatibility_plan", return_value={"blockers": []}), \
                patch("forge.oci_guest.prepare_guest", side_effect=prepared):
            result, commands = self.run_build(output_format="oci", extra_recipe=recipe)
        self.assertEqual(result["filename"], "image.oci")
        self.assertEqual(result["format"], "oci")
        self.assertTrue(result["oci_archive"]["verified"])
        self.assertTrue(any(command[:2] == ["qemu-img", "check"] and command[-1].endswith("archive-disk.qcow2") for command in commands))
        self.assertTrue(any(command[:2] == ["qemu-img", "compare"] and command[-1].endswith("archive-disk.qcow2") for command in commands))
        with tarfile.open(result["artifact_path"]) as archive:
            self.assertEqual(set(archive.getnames()), {"image_metadata.json", "output.QCOW2"})
            self.assertEqual(archive.extractfile("output.QCOW2").read(), qcow_header())
            metadata = json.load(archive.extractfile("image_metadata.json"))
            self.assertEqual(metadata["operatingSystem"], "Ubuntu")
        self.assertFalse((Path(result["artifact_path"]).parent / "archive-disk.qcow2").exists())

    def test_failed_qcow_comparison_never_packages_an_oci_archive(self):
        recipe = {"target": "oci", "oci": {"guest": {"prepare": False}, "import_options": {
            "operating_system": "Ubuntu", "operating_system_version": "26.04.1"}}}
        def prepared(work, inspected, *args, **kwargs):
            return {"_inspection": inspected, "warnings": []}
        with patch("forge.oci.compatibility_plan", return_value={"blockers": []}), \
                patch("forge.oci_guest.prepare_guest", side_effect=prepared), \
                patch("forge.oci_archive.write_archive") as package:
            self.run_build(output_format="oci", compare_failure=True, extra_recipe=recipe)
        package.assert_not_called()

    def test_ext4_is_shrunk_before_partition_copy(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        work = directory / "work.qcow2"
        work.write_bytes(qcow_header())
        events = []

        class Guest:
            def e2fsck(self, device, **kwargs):
                events.append(("fsck", device))

            def resize2fs_size(self, device, size):
                events.append(("filesystem", device, size))

        @contextmanager
        def guest(*args, **kwargs):
            yield Guest()

        def run(command, log=None):
            events.append(command)
            return ""

        with patch("forge.engine._guest", guest), patch("forge.engine._run", side_effect=run):
            ImageEngine()._resize(work, directory, inspection(),
                                  {"disk_size_gib": 6, "partition_changes": [{"device": "/dev/sda1", "size_mib": 4096}]}, lambda _: None)
        self.assertEqual(events[0][0], "fsck")
        self.assertEqual(events[1], ("filesystem", "/dev/sda1", 4095 * MIB))
        self.assertEqual(events[-1][0], "virt-resize")
        self.assertIn("/dev/sda1=4294967296b", events[-1])

    def test_repeated_alignment_resize_uses_distinct_files(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            work = directory / "working.qcow2"
            work.write_bytes(qcow_header())
            created = []

            def run(command, log=None):
                if command[:2] == ["qemu-img", "create"]:
                    output = Path(command[-2])
                    self.assertFalse(output.exists())
                    output.write_bytes(qcow_header())
                    created.append(output)
                return ""

            with patch("forge.engine._run", side_effect=run):
                first = ImageEngine()._resize(work, directory, inspection(), {"disk_size_gib": 11}, lambda _: None)
                second = ImageEngine()._resize(first, directory, inspection(), {"disk_size_gib": 12}, lambda _: None)
            self.assertEqual(len(set(created)), 2)
            self.assertTrue(second.exists())
            self.assertFalse(first.exists())


if __name__ == "__main__":
    unittest.main()


def test_automatic_resize_engine_uses_growth_and_keeps_old_copy_until_success(tmp_path):
    from test_growth import image,options
    from forge.engine import ImageEngine
    work=tmp_path/'working.qcow2';work.write_bytes(b'old-copy')
    def grow(source,dest,inspection,config,disk,log):
        assert source.read_bytes()==b'old-copy' and config==options()
        dest.write_bytes(b'grown');return dest
    with patch('forge.growth.grow',grow):
        result=ImageEngine()._resize(work,tmp_path,image(),{'storage_resize':options()},lambda _:None)
    assert not work.exists() and result.read_bytes()==b'grown'


def test_automatic_resize_rejected_before_guest_or_qemu_execution():
    from test_growth import image,options
    with patch('forge.engine._run') as run,patch('forge.engine._guest') as guest:
        with __import__('pytest').raises(EngineError,match='overlap'):
            _validate_recipe({'storage_resize':options('/dev/sda2',1024)},image())
    run.assert_not_called();guest.assert_not_called()
