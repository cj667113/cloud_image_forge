"""Platform plans must correspond to installed drivers and verified guest edits."""
from contextlib import contextmanager
from copy import deepcopy
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from forge.engine import EngineError
from forge.platform import (MODULE_CONFIG, _adapt_args, _boot_args, _fstab_evidence,
                            _fstab_text, _initramfs_script, _inspect_boot_environment, _safe_path,
                            _generated_grub_evidence,
                            _iscsi_archive_ready, _iscsi_backend, iscsi_initramfs_checks,
                            inspect_platform, plan_platform, prepare_platform, verify_platform)


KERNEL = "6.12.0-204.92.el9uek.x86_64"
ROOT_UUID = "11111111-2222-3333-4444-555555555555"
FSTAB = f"UUID={ROOT_UUID} / ext4 defaults 0 1\n"


def options(**changes):
    result = {"enabled": True, "source": "bare_metal", "target": "vm", "boot_attachment": "paravirtualized",
              "network_attachment": "paravirtualized", "nic_driver": None, "install_packages": False,
              "configure_network": False, "configure_serial_console": False}
    result.update(changes)
    return result


def image():
    drivers = sorted(MODULE_CONFIG)
    return {"os": {"distro": "oraclelinux", "arch": "x86_64"},
            "boot": {"supported_firmware": ["UEFI_64"], "recommended_firmware": "UEFI_64"},
            "partitions": [{"device": "/dev/sda1", "mountpoint": "/", "filesystem": "ext4", "uuid": ROOT_UUID}],
            "platform": {"version": 1,
                         "kernels": {KERNEL: {"modules": drivers, "builtin": [],
                                              "initrd": f"/boot/initramfs-{KERNEL}.img", "initrd_modules": drivers,
                                              "initrd_sha256": "a" * 64, "initrd_iscsi_userspace": True}},
                         "tools": {name: True for name in ("dracut", "lsinitrd", "systemctl", "grub2-mkconfig", "grubby", "iscsiadm", "iscsistart", "iscsid", "iscsi-iname", "dnf", "NetworkManager")},
                         "fstab": {"entries": [{"line": 1, "mountpoint": "/", "source": "UUID=" + ROOT_UUID,
                                                 "replacement": "UUID=" + ROOT_UUID}], "errors": [], "root_uuid": ROOT_UUID,
                                   "sha256": hashlib.sha256(FSTAB.encode()).hexdigest()},
                         "boot_files": {"/etc/default/grub": f'GRUB_CMDLINE_LINUX="quiet root=UUID={ROOT_UUID}"\n'},
                         "generated_grub": {"/boot/grub2/grub.cfg": f"linux /vmlinuz-{KERNEL} root=UUID={ROOT_UUID} quiet\n"},
                         "dracut_modules": ["iscsi", "network-manager"],
                         "iscsi_userspace_backend": "iscsiadm",
                         "network_backend": "NetworkManager", "network_ready": True, "network_files": [],
                         "persistent_network_files": [], "serial_console_ready": True, "blacklisted_modules": [], "os_version": {"major": 9, "minor": 8}}}


class Guest:
    def __init__(self, files=None, partitions=None):
        self.files = dict(files or {})
        self.links = set()
        self.members = []
        self.filesystems = deepcopy(partitions if partitions is not None else image()["partitions"])

    def list_filesystems(self):
        return {item["device"]: item.get("filesystem", "ext4") for item in self.filesystems}

    def vfs_uuid(self, device):
        return next(item.get("uuid", "") for item in self.filesystems if item["device"] == device)

    def vfs_label(self, device):
        return "root" if device == "/dev/sda1" else ""

    def lvm_canonical_lv_name(self, device):
        raise RuntimeError("not an LV")

    def part_to_dev(self, device):
        raise RuntimeError("no table fixture")

    def canonical_device_name(self, device):
        return device

    def mountpoints(self):
        return {"/dev/sda1": "/"}

    def statns(self, path):
        return {"st_mode": 0o100644, "st_uid": 0, "st_gid": 0, "st_nlink": 1}

    def is_file(self, path):
        return path in self.files

    def is_dir(self, path):
        return any(name.startswith(path.rstrip("/") + "/") for name in self.files)

    def is_symlink(self, path):
        return path in self.links

    def filesize(self, path):
        return len(self.files[path].encode())

    def read_file(self, path):
        return self.files[path].encode()

    def glob_expand(self, pattern):
        return [path for path in self.files if fnmatch.fnmatch(path, pattern)]

    def initrd_list(self, path):
        return self.members

    def checksum(self, kind, path):
        return hashlib.sha256(self.files[path].encode()).hexdigest()

    def findfs_label(self, label):
        if label == "root":
            return "/dev/sda1"
        raise RuntimeError("not found")

    def findfs_uuid(self, uuid):
        if uuid == ROOT_UUID:
            return "/dev/sda1"
        raise RuntimeError("not found")

    def mkdir_p(self, path):
        pass

    def cp_a(self, source, target):
        self.files[target] = self.files[source]

    def write(self, path, content):
        self.files[path] = content.decode()

    def chmod(self, mode, path):
        pass

    def chown(self, uid, gid, path):
        pass

    def rm(self, path):
        del self.files[path]


class InspectionTests(unittest.TestCase):
    def test_tuned_initrd_resolves_only_saved_or_observed_literal_values(self):
        g = Guest({"/boot/grub2/grubenv": "# GRUB Environment Block\n####\n",
                   "/boot/grub2/grub.cfg": 'set tuned_initrd=""\nexport tuned_initrd\n'})
        environment, errors, _ = _inspect_boot_environment(g)
        self.assertFalse(errors)
        self.assertEqual(_boot_args("/initramfs-test.img $tuned_initrd", environment=environment), ["/initramfs-test.img"])
        g.files["/boot/grub2/grub.cfg"] = "export tuned_initrd\n"
        environment, _, _ = _inspect_boot_environment(g)
        with self.assertRaisesRegex(ValueError, "unresolved"):
            _boot_args("$tuned_initrd", environment=environment)
        g.files["/boot/grub2/grub.cfg"] = 'set tuned_initrd="$(touch /tmp/never)"\n'
        _, errors, _ = _inspect_boot_environment(g)
        self.assertTrue(any("Dynamic tuned_initrd" in error for error in errors))

    def test_generated_grub_reads_actual_esp_mount_and_reports_oversized_files(self):
        path = "/firmware/EFI/vendor/grub.cfg"
        g = Guest({path: f"linuxefi /vmlinuz-{KERNEL} root=/dev/sda1\n"})
        files, errors = _generated_grub_evidence(g, [{"mountpoint": "/firmware", "filesystem": "vfat"}])
        self.assertIn(path, files)
        self.assertFalse(errors)
        with patch.object(g, "filesize", return_value=5 * 1024 * 1024):
            files, errors = _generated_grub_evidence(g, [{"mountpoint": "/firmware", "filesystem": "vfat"}])
        self.assertFalse(files)
        self.assertTrue(errors)

    def test_optional_evidence_failure_does_not_fail_entire_image_import(self):
        with patch("forge.platform._inspect_platform", side_effect=RuntimeError("unsupported optional filesystem query")):
            result = inspect_platform(Guest(), "/dev/sda1", [], [], {})
        self.assertEqual(result["version"], 1)
        self.assertTrue(result["errors"])
        source = image()
        source["platform"] = result
        plan = plan_platform(source, options())
        self.assertFalse(plan["ready"])
        self.assertTrue(any("unsupported optional" in item for item in plan["blockers"]))

    def test_standard_grub_environment_resolves_only_whitelisted_saved_values(self):
        g = Guest({"/boot/grub2/grubenv": "# GRUB Environment Block\nkernelopts=root=UUID=" + ROOT_UUID + " ro\n" + "#" * 128,
                   "/boot/grub2/grub.cfg": 'set tuned_params=""\n'})
        environment, errors, paths = _inspect_boot_environment(g)
        self.assertFalse(errors)
        self.assertEqual(environment["tuned_params"], "")
        self.assertEqual(_boot_args("$kernelopts $tuned_params", environment=environment), ["root=UUID=" + ROOT_UUID, "ro"])
        self.assertEqual(paths, ["/boot/grub2/grubenv"])

    def test_tuned_fallback_requires_valid_environment_and_unambiguous_literal(self):
        environment, _, _ = _inspect_boot_environment(Guest())
        with self.assertRaisesRegex(ValueError, "unresolved"):
            _boot_args("$tuned_params", environment=environment)
        g = Guest({"/boot/grub2/grubenv": "# GRUB Environment Block\n####\n",
                   "/boot/grub2/grub.cfg": 'set tuned_params="cpu_arg=1"\nset tuned_params="cpu_arg=2"\n'})
        _, errors, _ = _inspect_boot_environment(g)
        self.assertTrue(any("ambiguous" in error for error in errors))

    def test_nested_or_unknown_shell_code_is_not_executed_or_accepted(self):
        for text, env in [("$other", {"other": "quiet"}), ("$(touch /tmp/no)", {}),
                          ("$kernelopts", {"kernelopts": "$kernelopts"}),
                          ("$kernelopts", {"kernelopts": "`touch /tmp/no`"})]:
            with self.subTest(text=text, env=env), self.assertRaises(ValueError):
                _boot_args(text, environment=env)

    def test_driver_index_entry_requires_actual_module_file(self):
        module_dir = f"/lib/modules/{KERNEL}"
        g = Guest({"/etc/fstab": FSTAB,
                   module_dir + "/modules.dep": "kernel/drivers/net/virtio_net.ko.xz:\nkernel/drivers/nvme/host/nvme.ko.zst:\n",
                   module_dir + "/kernel/drivers/nvme/host/nvme.ko.zst": "module",
                   module_dir + "/modules.builtin": "kernel/drivers/ata/ahci.ko\n",
                   f"/boot/config-{KERNEL}": "CONFIG_X86_64=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_NET=m\nCONFIG_ISCSI_IBFT=y\n",
                   f"/boot/initramfs-{KERNEL}.img": "archive"})
        g.members = ["usr/lib/modules/test/kernel/nvme.ko.zst", "usr/sbin/iscsistart"]
        base = {"tools": {}, "kernels": {KERNEL: {"initrd": f"/boot/initramfs-{KERNEL}.img"}}}
        result = inspect_platform(g, "/dev/sda1", image()["partitions"], ["/boot/vmlinuz-" + KERNEL], base)
        kernel = result["kernels"][KERNEL]
        self.assertEqual(kernel["modules"], ["nvme"])
        self.assertEqual(kernel["architecture"], "x86_64")
        self.assertEqual(kernel["config"]["CONFIG_X86_64"], "y")
        self.assertIn("virtio_pci", kernel["builtin"])
        self.assertIn("ahci", kernel["builtin"])
        self.assertIn("iscsi_ibft", kernel["builtin"])
        self.assertNotIn("virtio_net", kernel["modules"])
        self.assertFalse(kernel["initrd_iscsi_userspace"], "an unused helper alone cannot prove iSCSI boot")
        self.assertEqual(len(kernel["initrd_sha256"]), 64)

    def test_uuid_duplicate_and_required_external_mount_fail_closed(self):
        g = Guest({"/etc/fstab": FSTAB + "/dev/sdb1 /data xfs defaults 0 0\n"})
        partitions = image()["partitions"]
        result = _fstab_evidence(g, "/dev/sda1", partitions)
        self.assertTrue(any("/data" in error for error in result["errors"]))
        duplicated = partitions + [{"device": "/dev/sda2", "uuid": ROOT_UUID}]
        result = _fstab_evidence(Guest({"/etc/fstab": FSTAB}, duplicated), "/dev/sda1", duplicated)
        self.assertTrue(result["errors"])

    def test_mount_evidence_repairs_only_independently_observed_targets(self):
        text = "UUID=stale-root / ext4 defaults 0 1\n/dev/missing /data ext4 defaults 0 2\n"
        hints = image()["partitions"] + [{"device": "/dev/sda1", "mountpoint": "/data", "uuid": ROOT_UUID}]
        result = _fstab_evidence(Guest({"/etc/fstab": text}), "/dev/sda1", hints)
        self.assertEqual(result["entries"][0]["replacement"], "UUID=" + ROOT_UUID)
        self.assertTrue(result["boot_reference_check_required"])
        self.assertTrue(any("/data" in error for error in result["errors"]))
        self.assertNotIn("replacement", result["entries"][1])

    def test_optional_future_mount_and_bind_mount_are_retained(self):
        text = FSTAB + "/dev/sdb1 /data xfs nofail 0 0\n/var/lib /srv none bind 0 0\n"
        result = _fstab_evidence(Guest({"/etc/fstab": text}), "/dev/sda1", image()["partitions"])
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["entries"][1]["preserve"])
        self.assertTrue(result["entries"][2]["preserve"])

    def test_device_to_uuid_change_preserves_options_comments_and_spacing(self):
        text = "# mounts\n  /dev/sda1\t/\text4\tdefaults,noatime 0 1 # root\n"
        result = _fstab_evidence(Guest({"/etc/fstab": text}), "/dev/sda1", image()["partitions"])
        self.assertFalse(result["errors"])
        item = result["entries"][0]
        updated = _fstab_text(text, [{"line": item["line"], "from": item["source"], "to": item["replacement"]}])
        self.assertEqual(updated, text.replace("/dev/sda1", "UUID=" + ROOT_UUID))

    def test_stale_fstab_plan_cannot_replace_another_source(self):
        with self.assertRaisesRegex(ValueError, "changed"):
            _fstab_text(FSTAB, [{"line": 1, "from": "/dev/sda1", "to": "UUID=" + ROOT_UUID}])


class PlanTests(unittest.TestCase):
    def test_network_dispatcher_does_not_force_uninstalled_networkmanager(self):
        source = image()
        source["platform"]["tools"]["NetworkManager"] = False
        source["platform"]["dracut_modules"] = ["iscsi", "network-manager", "network", "systemd-networkd"]
        profile = options(source="vm", target="bare_metal", boot_attachment="iscsi", network_attachment="vfio", nic_driver="mlx5_core")
        plan = plan_platform(source, profile)
        self.assertTrue(plan["ready"], plan["blockers"])
        self.assertEqual(plan["dracut_network_module"], "network")
        source["platform"]["dracut_modules"] = ["iscsi", "network-manager"]
        self.assertFalse(plan_platform(source, profile)["ready"])

    def test_automatic_nic_bundle_requires_every_selected_driver_in_every_initramfs(self):
        source = image()
        profile = options(source="vm", target="bare_metal", boot_attachment="iscsi", network_attachment="vfio", nic_driver="auto")
        result = plan_platform(source, profile)
        expected = {"bnxt_en", "i40e", "iavf", "ixgbe", "ixgbevf", "mlx4_en", "mlx5_core"}
        self.assertTrue(result["ready"], result["blockers"])
        self.assertEqual(set(result["nic_drivers"]), expected)
        self.assertTrue(expected <= set(result["required_modules"]))
        script = _initramfs_script(source, result, profile)
        for driver in expected:
            self.assertIn(driver.replace("_", "[-_]"), script)
        source["platform"]["kernels"]["second"] = {"modules": [], "builtin": []}
        self.assertTrue(any("automatic bundle" in error for error in plan_platform(source, profile)["blockers"]))

    def test_mount_preserve_validates_but_does_not_normalize_existing_reference(self):
        source = image()
        entry = source["platform"]["fstab"]["entries"][0]
        entry.update(source="/dev/sda1", reason="Resolved current filesystem identity")
        automatic = plan_platform(source, options())
        self.assertTrue(automatic["fstab_changes"])
        preserved = plan_platform(source, options(), mount_policy="preserve")
        self.assertTrue(preserved["ready"], preserved["blockers"])
        self.assertFalse(preserved["fstab_changes"])
        entry.update(source="UUID=stale", reason="Reconciled against independently inspected root")
        preserved = plan_platform(source, options(), mount_policy="preserve")
        self.assertFalse(preserved["ready"])
        self.assertTrue(any("does not resolve" in error for error in preserved["blockers"]))

    def test_ubuntu_dracut_archive_overrides_update_initramfs_command_name(self):
        source = image()
        source["os"]["distro"] = "ubuntu"
        source["platform"]["tools"].update({"update-initramfs": True, "update-grub": True})
        source["platform"]["kernels"][KERNEL]["portability"] = {"readable": True, "dracut_modules": ["systemd", "base"]}
        result = plan_platform(source, options(source="unknown"))
        self.assertTrue(result["ready"], result["blockers"])
        self.assertEqual(result["initramfs_backend"], "dracut")
        self.assertFalse(result["packages"])

    def test_ubuntu_missing_dracut_network_can_be_installed_only_with_both_consents(self):
        source = image()
        source["os"]["distro"] = "ubuntu"
        source["platform"]["tools"].update({"apt-get": True, "update-grub": True})
        source["platform"].update(dracut_modules=[], iscsi_userspace_backend=None)
        profile = options(boot_attachment="iscsi", install_packages=True)
        self.assertFalse(plan_platform(source, profile, False)["ready"])
        result = plan_platform(source, profile, True)
        self.assertTrue(result["ready"], result["blockers"])
        self.assertEqual(result["packages"], ["dracut-network"])

    def test_arm_bare_metal_requires_actual_acpi_pci_and_nic_without_x86_controllers(self):
        source = json.loads(json.dumps(image()).replace(KERNEL, "6.12.0-test.aarch64"))
        source["os"]["arch"] = "aarch64"
        source["boot"].update(architecture="aarch64", efi_loaders=[{"architecture": "aarch64"}])
        kernel = next(iter(source["platform"]["kernels"].values()))
        kernel["config"] = {key: "y" for key in ("CONFIG_ARM64", "CONFIG_EFI", "CONFIG_EFI_STUB", "CONFIG_ACPI", "CONFIG_PCI")}
        for module in ("nvme", "nvme_core", "ahci"):
            kernel["modules"].remove(module)
        profile = options(source="vm", target="bare_metal", boot_attachment="iscsi", network_attachment="vfio", nic_driver="mlx5_core")
        with patch("forge.architecture.worker_arch", return_value="aarch64"):
            ready = plan_platform(source, profile)
            self.assertTrue(ready["ready"], ready["blockers"])
            self.assertFalse(ready["provider_supported"])
            self.assertTrue(ready["experimental"])
            self.assertFalse({"nvme", "ahci"} & set(ready["required_modules"]))
            self.assertTrue({"iscsi_ibft", "iscsi_tcp", "mlx5_core"} <= set(ready["required_modules"]))
            kernel["config"].pop("CONFIG_ACPI")
            self.assertTrue(any("CONFIG_ACPI" in error for error in plan_platform(source, profile)["blockers"]))
            kernel["config"]["CONFIG_ACPI"] = "y"
            profile["nic_driver"] = None
            self.assertTrue(any("actual target" in error for error in plan_platform(source, profile)["blockers"]))

    def test_same_type_reconfiguration_is_valid(self):
        result = plan_platform(image(), options(source="vm", target="vm"))
        self.assertTrue(result["ready"], result["blockers"])
        result = plan_platform(image(), options(source="unknown", target="vm"))
        self.assertTrue(result["ready"], result["blockers"])
        self.assertEqual(result["source"], "unknown")

    def test_arm_reconfiguration_requires_native_worker_and_uses_arm_console(self):
        source = json.loads(json.dumps(image()).replace(KERNEL, "6.12.0-test.aarch64"))
        source["os"]["arch"] = "aarch64"
        source["boot"]["architecture"] = "aarch64"
        source["boot"]["efi_loaders"] = [{"architecture": "aarch64", "path": "/EFI/BOOT/BOOTAA64.EFI"}]
        kernel = next(iter(source["platform"]["kernels"].values()))
        kernel["config"] = {key: "y" for key in ("CONFIG_ARM64", "CONFIG_EFI", "CONFIG_EFI_STUB",
                                                  "CONFIG_SERIAL_AMBA_PL011", "CONFIG_SERIAL_AMBA_PL011_CONSOLE")}
        profile = options(configure_serial_console=True)
        foreign = plan_platform(source, profile)
        self.assertTrue(any("worker cannot run" in error for error in foreign["blockers"]))
        with patch("forge.engine._guest") as guest, patch("forge.engine._run") as run:
            with self.assertRaisesRegex(EngineError, "worker cannot run"):
                prepare_platform(Path("/tmp/arm.qcow2"), source, profile, False, lambda _: None)
        guest.assert_not_called()
        run.assert_not_called()
        with patch("forge.architecture.worker_arch", return_value="aarch64"):
            native = plan_platform(source, profile)
        self.assertTrue(native["ready"], native["blockers"])
        self.assertEqual(native["serial_device"], "ttyAMA0")
        arguments = _adapt_args(["console=ttyAMA0,9600", "quiet"], native, profile)
        self.assertIn("console=ttyAMA0,115200n8", arguments)
        self.assertNotIn("console=ttyS0,115200n8", arguments)
        self.assertNotIn("console=ttyAMA0,9600", arguments)
        self.assertIn("quiet", arguments)
        with patch("forge.architecture.worker_arch", return_value="aarch64"):
            kernel["config"].pop("CONFIG_SERIAL_AMBA_PL011_CONSOLE")
            self.assertTrue(any("PL011" in error for error in plan_platform(source, profile)["blockers"]))

    def test_accelerated_vm_profile_requires_virtio_network_and_distinct_oci_mode(self):
        profile = options(network_attachment="accelerated")
        oci = {"capabilities": {"Storage.BootVolumeType": {"default_value": "PARAVIRTUALIZED"},
                                "Network.AttachmentType": {"default_value": "ACCELERATEDPV"},
                                "Compute.Firmware": {"default_value": "UEFI_64"},
                                "Compute.LaunchMode": {"default_value": "ACCELERATEDPV"}}}
        result = plan_platform(image(), profile, oci_config=oci)
        self.assertTrue(result["ready"], result["blockers"])
        self.assertTrue({"virtio_net", "virtio_pci", "virtio_scsi"} <= set(result["required_modules"]))
        self.assertNotIn("nvme", result["required_modules"])
        self.assertTrue(any("AcceleratedPV" in action for action in result["actions"]))
        oci["capabilities"]["Network.AttachmentType"]["default_value"] = "PARAVIRTUALIZED"
        self.assertTrue(any("Network.AttachmentType" in error for error in plan_platform(image(), profile, oci_config=oci)["blockers"]))
        oci["capabilities"]["Network.AttachmentType"]["default_value"] = "ACCELERATEDPV"
        oci["capabilities"]["Compute.LaunchMode"]["default_value"] = "PARAVIRTUALIZED"
        self.assertTrue(any("Compute.LaunchMode" in error for error in plan_platform(image(), profile, oci_config=oci)["blockers"]))

    def test_accelerated_network_is_not_a_bare_metal_driver_profile(self):
        result = plan_platform(image(), options(source="vm", target="bare_metal", boot_attachment="iscsi",
                                                network_attachment="accelerated", nic_driver="mlx5_core"))
        self.assertFalse(result["ready"])
        self.assertTrue(any("hardware/VFIO" in error for error in result["blockers"]))

    def test_accelerated_profile_blocks_missing_or_unverified_network_driver(self):
        source = image()
        source["platform"]["kernels"][KERNEL]["modules"].remove("virtio_net")
        result = plan_platform(source, options(network_attachment="accelerated"))
        self.assertTrue(any("virtio_net" in error for error in result["blockers"]))
        source = image()
        source["platform"]["kernels"][KERNEL]["initrd_modules"].remove("virtio_net")
        result = verify_platform(source, options(network_attachment="accelerated"))
        self.assertTrue(any("virtio_net" in error and "initramfs" in error for error in result["blockers"]))

    def test_iscsi_adaptation_retains_audited_session_timeout_and_root_policy(self):
        policy = "rd.iscsi.param=node.session.timeo.replacement_timeout=6000"
        original = ["root=/dev/mapper/ocivolume-root", "ro", "rootflags=prjquota", "rd.lvm.vg=ocivolume",
                    "rd.lvm.lv=ocivolume/root", "rd.net.timeout.dhcp=10", "rd.net.timeout.carrier=5",
                    "net.ifnames=1", "rd.luks=0", "rd.md=0", "rd.dm=0", "nvme_core.shutdown_timeout=10",
                    policy, "rd.iscsi.initiator=old-identity", "iscsi_username=old-user",
                    "rd.iscsi.param=node.session.auth.password=old-secret"]
        profile = options(source="vm", target="bare_metal", boot_attachment="iscsi", network_attachment="vfio", nic_driver="mlx5_core")
        result = _adapt_args(original, {"root_uuid": ROOT_UUID}, profile)
        self.assertIn(policy, result)
        for word in original[1:12]:
            self.assertIn(word, result)
        self.assertIn("root=UUID=" + ROOT_UUID, result)
        self.assertTrue({"netroot=iscsi", "rd.iscsi.firmware=1", "rd.neednet=1"} <= set(result))
        self.assertFalse(any("old-" in word for word in result))
        self.assertEqual(result, _adapt_args(result, {"root_uuid": ROOT_UUID}, profile))
        self.assertNotIn(policy, _adapt_args(original, {"root_uuid": ROOT_UUID}, options(network_attachment="accelerated")))

    def test_iscsi_timeout_preservation_is_strictly_numeric_and_bounded(self):
        prefix = "rd.iscsi.param=node.session.timeo.replacement_timeout="
        profile = options(source="vm", target="bare_metal", boot_attachment="iscsi", network_attachment="vfio", nic_driver="mlx5_core")
        for value in ("-2147483648", "-1", "0", "6000", "2147483647"):
            with self.subTest(value=value):
                self.assertIn(prefix + value, _adapt_args([prefix + value], {"root_uuid": ROOT_UUID}, profile))
        for value in ("-2147483649", "2147483648", "6000,other=value", "6000;bad", "6000=bad", ""):
            with self.subTest(value=value):
                self.assertNotIn(prefix + value, _adapt_args([prefix + value], {"root_uuid": ROOT_UUID}, profile))

    def test_older_rpm_efi_menu_layout_is_not_silently_written_to_wrong_path(self):
        source = image()
        source["platform"]["os_version"]["major"] = 8
        self.assertTrue(any("EL9/10" in error for error in plan_platform(source, options())["blockers"]))

    def test_dual_boot_uses_explicit_oci_firmware_preference(self):
        source = image()
        source["boot"]["supported_firmware"] = ["BIOS", "UEFI_64"]
        config = {"capabilities": {"Storage.BootVolumeType": {"default_value": "PARAVIRTUALIZED"},
                                   "Network.AttachmentType": {"default_value": "PARAVIRTUALIZED"},
                                   "Compute.Firmware": {"default_value": "BIOS"},
                                   "Compute.LaunchMode": {"default_value": "PARAVIRTUALIZED"}}}
        result = plan_platform(source, options(), oci_config=config)
        self.assertEqual(result["effective_firmware"], "BIOS")
        self.assertTrue(result["ready"], result["blockers"])

    def test_vm_plan_prepares_real_drivers_and_configuration(self):
        result = plan_platform(image(), options())
        self.assertTrue(result["ready"], result["blockers"])
        self.assertIn("virtio_net", result["required_modules"])
        self.assertIn("virtio_scsi", result["required_modules"])
        self.assertNotIn("iscsi_ibft", result["required_modules"])
        self.assertTrue(any("initramfs" in action for action in result["actions"]))
        self.assertFalse(result["boot_tested"])

    def test_bare_metal_is_experimental_but_not_blocked_only_by_provider_support(self):
        config = options(source="vm", target="bare_metal", boot_attachment="iscsi", network_attachment="vfio", nic_driver="mlx5_core")
        result = plan_platform(image(), config)
        self.assertTrue(result["ready"], result["blockers"])
        self.assertFalse(result["provider_supported"])
        self.assertTrue(result["experimental"])
        self.assertTrue({"nvme", "ahci", "mlx5_core", "iscsi_tcp", "iscsi_ibft"} <= set(result["required_modules"]))
        self.assertTrue(any("does not support" in warning for warning in result["warnings"]))
        self.assertTrue(any("iBFT" in warning for warning in result["warnings"]))

    def test_explicit_physical_nic_and_boot_chain_are_required(self):
        source = image()
        source["boot"]["supported_firmware"] = ["BIOS"]
        result = plan_platform(source, options(source="vm", target="bare_metal", boot_attachment="iscsi", network_attachment="vfio"))
        self.assertFalse(result["ready"])
        self.assertTrue(any("NIC driver" in item for item in result["blockers"]))
        self.assertTrue(any("UEFI" in item for item in result["blockers"]))

    def test_valid_planned_uefi_migration_satisfies_preview_only(self):
        source = image()
        source["boot"]["supported_firmware"] = ["BIOS"]
        config = options(source="vm", target="bare_metal", boot_attachment="iscsi", network_attachment="vfio", nic_driver="mlx5_core")
        with patch("forge.uefi.plan_migration", return_value={"ready_to_migrate": True}):
            result = plan_platform(source, config, boot_migration={"enabled": True})
        self.assertTrue(result["ready"], result["blockers"])
        self.assertEqual(result["planned_firmware"], ["UEFI_64"])
        self.assertFalse(verify_platform(source, config)["ready"])

    def test_every_installed_kernel_must_have_required_drivers(self):
        source = image()
        source["platform"]["kernels"]["old-kernel"] = deepcopy(source["platform"]["kernels"][KERNEL])
        source["platform"]["kernels"]["old-kernel"]["modules"].remove("virtio_scsi")
        result = plan_platform(source, options(install_packages=True), allow_network=True)
        self.assertTrue(any("old-kernel" in error and "virtio_scsi" in error for error in result["blockers"]))
        self.assertEqual(result["packages"], [])

    def test_package_install_requires_both_opt_ins_and_rechecks_later(self):
        source = image()
        source["platform"]["tools"]["lsinitrd"] = False
        for config, network in [(options(), True), (options(install_packages=True), False)]:
            self.assertFalse(plan_platform(source, config, network)["ready"])
        result = plan_platform(source, options(install_packages=True), True)
        self.assertTrue(result["ready"], result["blockers"])
        self.assertEqual(result["packages"], ["dracut"])

    def test_iscsi_requires_initramfs_network_and_userspace_prerequisites(self):
        source = image()
        source["platform"]["dracut_modules"] = []
        source["platform"]["tools"]["iscsid"] = False
        result = plan_platform(source, options(boot_attachment="iscsi"))
        self.assertTrue(any("iscsid" in error for error in result["blockers"]))
        self.assertTrue(any("dracut" in error for error in result["blockers"]))

    def test_firmware_iscsi_requires_ibft_driver_for_every_kernel(self):
        source = image()
        source["platform"]["kernels"]["old-kernel"] = deepcopy(source["platform"]["kernels"][KERNEL])
        old = source["platform"]["kernels"]["old-kernel"]
        old["modules"].remove("iscsi_ibft")
        result = plan_platform(source, options(boot_attachment="iscsi"))
        self.assertTrue(any("old-kernel" in error and "iscsi_ibft" in error for error in result["blockers"]))
        self.assertTrue(plan_platform(source, options())["ready"])
        old["builtin"].append("iscsi_ibft")
        result = plan_platform(source, options(boot_attachment="iscsi"))
        self.assertTrue(result["ready"], result["blockers"])

    def test_network_opt_out_does_not_ignore_nonportable_profiles(self):
        source = image()
        source["platform"]["persistent_network_files"] = ["/etc/systemd/network/old.link"]
        self.assertFalse(plan_platform(source, options())["ready"])
        self.assertTrue(plan_platform(source, options(configure_network=True))["ready"])

    def test_driver_blacklist_and_shell_expansion_are_blockers(self):
        source = image()
        source["platform"]["blacklisted_modules"] = ["virtio_net"]
        source["platform"]["boot_files"]["/boot/loader/entries/test.conf"] = "options $kernelopts\n"
        blockers = " ".join(plan_platform(source, options())["blockers"])
        self.assertIn("blacklisted", blockers)
        self.assertIn("shell expansion", blockers)

    def test_conflicting_oci_boot_or_network_preference_is_blocked(self):
        config = {"capabilities": {"Storage.BootVolumeType": {"default_value": "ISCSI", "values": ["ISCSI"]},
                                   "Network.AttachmentType": {"default_value": "VFIO", "values": ["VFIO"]},
                                   "Compute.Firmware": {"default_value": "UEFI_64", "values": ["UEFI_64"]},
                                   "Compute.LaunchMode": {"default_value": "NATIVE"}}}
        blockers = " ".join(plan_platform(image(), options(), oci_config=config)["blockers"])
        self.assertIn("Storage.BootVolumeType", blockers)
        self.assertIn("Network.AttachmentType", blockers)
        self.assertIn("Compute.LaunchMode", blockers)


class MutationTests(unittest.TestCase):
    def test_receipt_cannot_inherit_proof_for_a_different_initramfs(self):
        source, after = image(), image()
        after["platform"]["kernels"][KERNEL]["initrd"] = f"/boot/initrd.img-{KERNEL}"
        g = Guest({"/etc/fstab": FSTAB, **source["platform"]["boot_files"]})

        @contextmanager
        def guest(*args, **kwargs):
            yield g

        with patch("forge.engine._guest", guest), patch("forge.engine._mount"), patch("forge.engine._roots", return_value="/dev/sda1"), \
                patch("forge.engine._run"), patch("forge.engine.ImageEngine.inspect", return_value=after):
            with self.assertRaisesRegex(EngineError, "not the file"):
                prepare_platform(Path("/tmp/work.qcow2"), source, options(), False, lambda _: None)

    def test_boot_transport_update_preserves_unrelated_arguments(self):
        words = shlex.split("quiet audit=1 rd.lvm.lv=vg/root root=/dev/sda1 netroot=iscsi:old rd.iscsi.initiator=old console=hvc0 ip=ibft")
        result = _adapt_args(words, {"root_uuid": ROOT_UUID}, options(configure_serial_console=True))
        for item in ("quiet", "audit=1", "rd.lvm.lv=vg/root", "console=hvc0", "root=UUID=" + ROOT_UUID, "console=ttyS0,115200n8"):
            self.assertIn(item, result)
        self.assertFalse(any("iscsi" in item or item == "ip=ibft" for item in result))
        self.assertEqual(result, _adapt_args(result, {"root_uuid": ROOT_UUID}, options(configure_serial_console=True)))

    def test_initramfs_script_is_generic_checks_each_kernel_and_has_no_assumed_endpoint(self):
        source, config = image(), options(boot_attachment="iscsi")
        source["platform"]["kernels"][KERNEL]["builtin"] = ["sd_mod"]
        plan = plan_platform(source, config)
        script = _initramfs_script(source, plan, config)
        self.assertIn("--no-hostonly --no-hostonly-cmdline", script)
        self.assertIn("iscsistart", script)
        self.assertIn("lsinitrd -m", script)
        self.assertIn("iscsi_tcp", script)
        self.assertIn("Required platform driver absent from initramfs " + KERNEL + ": iscsi_ibft", script)
        self.assertNotIn("169.254", script)
        self.assertNotIn("iqn.", script)
        self.assertNotIn("Required platform driver absent from initramfs " + KERNEL + ": sd_mod", script)
        source["platform"]["kernels"][KERNEL]["builtin"].append("iscsi_ibft")
        self.assertNotIn("Required platform driver absent from initramfs " + KERNEL + ": iscsi_ibft",
                         _initramfs_script(source, plan, config))

    def test_symlink_ancestor_is_rejected(self):
        g = Guest()
        g.links.add("/etc/dracut.conf.d")
        with self.assertRaisesRegex(ValueError, "symlink"):
            _safe_path(g, "/etc/dracut.conf.d/90-platform.conf")

    def test_disabled_preparation_does_not_open_or_mutate_image(self):
        with patch("forge.engine._guest") as guest, patch("forge.engine._run") as run:
            result = prepare_platform(Path("/tmp/work.qcow2"), {}, {"enabled": False}, False, lambda _: None)
        self.assertFalse(result["requested"])
        guest.assert_not_called()
        run.assert_not_called()

    def test_failed_native_rebuild_prevents_success_report(self):
        source = image()
        g = Guest({"/etc/fstab": FSTAB, **source["platform"]["boot_files"]})

        @contextmanager
        def guest(*args, **kwargs):
            yield g

        with patch("forge.engine._guest", guest), patch("forge.engine._mount"), patch("forge.engine._roots", return_value="/dev/sda1"), \
                patch("forge.engine._run", side_effect=EngineError("required driver absent")), patch("forge.engine.ImageEngine.inspect") as inspect:
            with self.assertRaisesRegex(EngineError, "required driver absent"):
                prepare_platform(Path("/tmp/work.qcow2"), source, options(), False, lambda _: None)
            inspect.assert_not_called()

    def test_preparation_reinspects_and_rejects_lost_driver_proof(self):
        source, after = image(), image()
        after["platform"]["kernels"][KERNEL]["modules"].remove("virtio_net")
        g = Guest({"/etc/fstab": FSTAB, **source["platform"]["boot_files"]})

        @contextmanager
        def guest(*args, **kwargs):
            yield g

        with patch("forge.engine._guest", guest), patch("forge.engine._mount"), patch("forge.engine._roots", return_value="/dev/sda1"), \
                patch("forge.engine._run") as run, patch("forge.engine.ImageEngine.inspect", return_value=after):
            with self.assertRaisesRegex(EngineError, "verification failed"):
                prepare_platform(Path("/tmp/work.qcow2"), source, options(), False, lambda _: None)
            self.assertIn("--no-network", run.call_args.args[0])
            self.assertTrue(any(path.startswith("/etc/dracut.conf.d/") for path in g.files))


class IscsiInitramfsTests(unittest.TestCase):
    common = ["usr/sbin/iscsiroot", "usr/lib/dracut/hooks/cmdline/90-parse-iscsiroot.sh"]
    modern = common + ["usr/sbin/iscsiadm", "usr/sbin/iscsid", "usr/sbin/iscsi-iname",
                       "usr/lib/systemd/system/iscsid.service", "usr/lib/systemd/system/iscsid.socket",
                       "etc/systemd/system/sockets.target.wants/iscsid.socket"]

    def run_native(self, members, handler="iscsiadm -m fw -l -W\n", modules="iscsi\nnetwork-manager\nnetwork\nsystemd\n"):
        # Exercise the actual generated POSIX shell checks against lsinitrd-style
        # metadata, including the whitespace and paths observed on Oracle Linux.
        listing = "\n".join("-rwxr-xr-x 1 root root 123 Jun 30 14:24 " + name for name in members)
        with tempfile.TemporaryDirectory() as folder:
            tool = Path(folder) / "lsinitrd"
            tool.write_text("#!" + sys.executable + "\nimport sys\n"
                            + "print(" + repr(modules) + " if sys.argv[1] == '-m' else " + repr(handler) + ")\n")
            tool.chmod(0o755)
            script = "set -eu\nlisting=" + shlex.quote(listing) + "\n" + "\n".join(iscsi_initramfs_checks("/boot/test.img"))
            return subprocess.run(["/bin/bash", "-c", script], env={**os.environ, "PATH": folder + os.pathsep + os.environ.get("PATH", "")},
                                  capture_output=True, text=True)

    def test_modern_firmware_chain_passes_without_unused_iscsistart(self):
        result = self.run_native(self.modern)
        self.assertEqual(result.returncode, 0, result.stderr)
        source = image()
        source["platform"]["tools"]["iscsistart"] = False
        self.assertTrue(plan_platform(source, options(boot_attachment="iscsi"))["ready"])

    def test_dracut110_var_hook_location_is_exact_and_still_required(self):
        members = [name.replace("usr/lib/dracut/hooks/", "var/lib/dracut/hooks/") for name in self.modern]
        result = self.run_native(members)
        self.assertEqual(result.returncode, 0, result.stderr)
        unknown = [name.replace("var/lib/dracut/hooks/", "tmp/dracut/hooks/") for name in members]
        self.assertNotEqual(self.run_native(unknown).returncode, 0)
        g = Guest()
        with patch.object(g, "initrd_cat", create=True, side_effect=lambda path, name:
                          "iscsiadm -m fw -l\n" if name.endswith("iscsiroot") else "iscsi\nnetwork\nsystemd\n"):
            self.assertTrue(_iscsi_archive_ready(g, "/boot/test.img", members + ["usr/lib/dracut/modules.txt"]))
            self.assertFalse(_iscsi_archive_ready(g, "/boot/test.img", unknown + ["usr/lib/dracut/modules.txt"]))

    def test_each_modern_component_is_required_even_with_unused_legacy_helper(self):
        for missing in self.modern:
            with self.subTest(missing=missing):
                result = self.run_native([name for name in self.modern if name != missing] + ["usr/sbin/iscsistart"])
                self.assertNotEqual(result.returncode, 0, missing)
                self.assertIn("verification failed", result.stderr)

    def test_legacy_handler_requires_its_helper_and_hooks(self):
        result = self.run_native(self.common + ["sbin/iscsistart"], handler="iscsistart -b --param node.session.timeo.replacement_timeout=30\n", modules="iscsi\nnetwork\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_native(self.modern, handler="iscsistart -b\n")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_or_comment_only_handler_and_missing_modules_are_rejected(self):
        for handler, modules in [("# iscsiadm -m fw -l\necho placeholder\n", "iscsi\nnetwork\n"),
                                 ("iscsiadm -m fw -l\n", "network\nsystemd\n"),
                                 ("iscsiadm -m fw -l\n", "iscsi\nsystemd\n")]:
            with self.subTest(handler=handler, modules=modules):
                self.assertNotEqual(self.run_native(self.modern, handler, modules).returncode, 0)

    def test_readonly_archive_evidence_requires_same_complete_chain(self):
        g = Guest()
        members = self.modern + ["usr/lib/dracut/modules.txt"]
        with patch.object(g, "initrd_cat", create=True, side_effect=lambda path, name:
                          "iscsiadm -m fw -l\n" if name.endswith("iscsiroot") else "iscsi\nnetwork\nsystemd\n"):
            self.assertTrue(_iscsi_archive_ready(g, "/boot/test.img", members))
            self.assertFalse(_iscsi_archive_ready(g, "/boot/test.img", [name for name in members if not name.endswith("iscsi-iname")]))
        self.assertEqual(_iscsi_backend("# iscsistart -b\niscsiadm -m fw -l\n"), "iscsiadm")
        self.assertIsNone(_iscsi_backend("# iscsistart -b\n"))


class VerificationTests(unittest.TestCase):
    def test_generated_mapper_and_uuid_must_both_resolve_to_actual_root(self):
        source = image()
        evidence = source["platform"]
        device, alias = "/dev/ubuntu-vg/ubuntu-lv", "/dev/mapper/ubuntu--vg-ubuntu--lv"
        evidence["fstab"]["root_device"] = device
        evidence["portability"] = {"local_devices": [{"device": device, "aliases": [device, alias],
                                                       "is_lv": True, "uuid": ROOT_UUID, "mountpoint": "/"}]}
        def menu(arguments):
            evidence["generated_grub"]["/boot/grub2/grub.cfg"] = f"linux /vmlinuz-{KERNEL} {arguments} quiet\n"
        menu(f"root={alias} root=UUID={ROOT_UUID}")
        self.assertTrue(verify_platform(source, options())["ready"])
        for arguments in (f"root=UUID={ROOT_UUID} root={alias}", f"root=/dev/mapper/other root=UUID={ROOT_UUID}",
                          f"root=/dev/sda1 root=UUID={ROOT_UUID}", f"root=UUID=wrong root=UUID={ROOT_UUID}",
                          f"root={alias} root=UUID={ROOT_UUID} netroot=iscsi:old"):
            with self.subTest(arguments=arguments):
                menu(arguments)
                self.assertFalse(verify_platform(source, options())["ready"])
        menu(f"root={alias} root=UUID={ROOT_UUID}")
        evidence["portability"]["local_devices"].append({"device": "/dev/other/root", "aliases": [],
                                                        "is_lv": True, "uuid": ROOT_UUID, "mountpoint": "/other"})
        self.assertFalse(verify_platform(source, options())["ready"])

    def test_late_grub_override_cannot_pass_correct_default_source(self):
        source = image()
        source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] = f"menuentry 'custom' {{\n linuxefi /vmlinuz-{KERNEL} root=/dev/sdb1 netroot=iscsi:old\n}}\n"
        result = verify_platform(source, options())
        self.assertFalse(result["ready"])
        self.assertTrue(any("Generated GRUB" in error and "conflict" in error for error in result["blockers"]))

    def test_standard_blscfg_uses_verified_bls_entries_and_detects_missing_coverage(self):
        source = image()
        source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] = "insmod blscfg\nif [ -s ${prefix}/grubenv ]; then\n blscfg\nfi\n"
        path = "/boot/loader/entries/installed.conf"
        source["platform"]["boot_files"][path] = f"title Linux\nlinux /vmlinuz-{KERNEL}\noptions root=UUID={ROOT_UUID} quiet\n"
        result = verify_platform(source, options())
        self.assertTrue(result["ready"], result["blockers"])
        source["platform"]["boot_files"][path] = f"title Linux\nlinux /vmlinuz-{KERNEL}\n"
        self.assertTrue(any("boot entries are unverified" in error for error in verify_platform(source, options())["blockers"]))

    def test_generated_menu_resolves_supported_environment_and_rejects_unknown_expansion(self):
        source = image()
        evidence = source["platform"]
        evidence["boot_environment"] = {"kernelopts": "root=UUID=" + ROOT_UUID + " ro", "tuned_params": "audit=1"}
        evidence["generated_grub"]["/boot/grub2/grub.cfg"] = f"linux /boot/vmlinuz-{KERNEL} $kernelopts \\\n $tuned_params\n"
        result = verify_platform(source, options())
        self.assertTrue(result["ready"], result["blockers"])
        evidence["generated_grub"]["/boot/grub2/grub.cfg"] += f"linux /vmlinuz-{KERNEL} $unknown\n"
        self.assertFalse(verify_platform(source, options())["ready"])

    def test_generated_efi_vendor_entry_is_checked_even_with_valid_main_menu(self):
        source = image()
        source["platform"]["generated_grub"]["/efi/EFI/vendor/grub.cfg"] = f"linuxefi /vmlinuz-{KERNEL} root=UUID={ROOT_UUID} rd.iscsi.firmware=1\n"
        self.assertFalse(verify_platform(source, options())["ready"])

    def test_inline_custom_entry_cannot_hide_behind_a_valid_generated_entry(self):
        source = image()
        source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] += f"menuentry 'custom' {{ linuxefi /vmlinuz-{KERNEL} root=/dev/sdb1; }}\n"
        self.assertTrue(any("Generated GRUB" in error and "conflict" in error for error in verify_platform(source, options())["blockers"]))

    def test_missing_generated_menu_and_missing_kernel_entries_fail_closed(self):
        source = image()
        source["platform"]["generated_grub"] = {}
        self.assertFalse(verify_platform(source, options())["ready"])
        source["platform"]["generated_grub"] = {"/boot/grub2/grub.cfg": "# no installed kernels\nlinux /vmlinuz-0-rescue root=UUID=old\n"}
        self.assertFalse(verify_platform(source, options())["ready"])

    def test_identical_console_arguments_added_by_oci_do_not_invalidate_platform(self):
        source, config = image(), options(configure_serial_console=True)
        arguments = f"quiet root=UUID={ROOT_UUID} console=tty0 console=ttyS0,115200n8 console=tty0 console=ttyS0,115200n8"
        source["platform"]["boot_files"]["/etc/default/grub"] = "GRUB_CMDLINE_LINUX=" + shlex.quote(arguments) + "\n"
        source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] = f"linux /vmlinuz-{KERNEL} {arguments}\n"
        self.assertTrue(verify_platform(source, config)["ready"])
        source["platform"]["boot_files"]["/etc/default/grub"] = "GRUB_CMDLINE_LINUX=" + shlex.quote(arguments + " root=/dev/sdb1") + "\n"
        self.assertFalse(verify_platform(source, config)["ready"])

    def test_missing_post_build_root_identity_returns_blockers(self):
        source = image()
        source["platform"]["fstab"]["root_uuid"] = None
        result = verify_platform(source, options())
        self.assertFalse(result["ready"])
        self.assertTrue(result["blockers"])

    def test_prepared_vm_configuration_passes(self):
        result = verify_platform(image(), options())
        self.assertTrue(result["ready"], result["blockers"])
        self.assertTrue(result["verified"])

    def test_native_proof_receipt_must_match_actual_initramfs_hash_and_path(self):
        source = image()
        kernel = source["platform"]["kernels"][KERNEL]
        kernel["initrd_modules"] = None
        receipt = {"verified_initrds": {KERNEL: {"path": kernel["initrd"], "sha256": kernel["initrd_sha256"], "modules": kernel["modules"]}}}
        self.assertTrue(verify_platform(source, options(), receipt=receipt)["ready"])
        for field in ("path", "sha256"):
            changed = deepcopy(receipt)
            changed["verified_initrds"][KERNEL][field] = "different"
            self.assertFalse(verify_platform(source, options(), receipt=changed)["ready"])

    def test_iscsi_driver_proof_cannot_substitute_for_boot_userspace(self):
        source = image()
        source["platform"]["kernels"][KERNEL]["initrd_iscsi_userspace"] = False
        config = options(boot_attachment="iscsi")
        plan = plan_platform(source, config)
        source["platform"]["boot_files"]["/etc/default/grub"] = "GRUB_CMDLINE_LINUX=" + shlex.quote(shlex.join(_adapt_args(["quiet"], plan, config))) + "\n"
        source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] = f"linux /vmlinuz-{KERNEL} " + shlex.join(_adapt_args(["quiet"], plan, config)) + "\n"
        self.assertTrue(any("iSCSI boot userspace" in error for error in verify_platform(source, config)["blockers"]))

    def test_firmware_iscsi_userspace_cannot_substitute_for_ibft_driver(self):
        source, config = image(), options(boot_attachment="iscsi")
        plan = plan_platform(source, config)
        source["platform"]["boot_files"]["/etc/default/grub"] = "GRUB_CMDLINE_LINUX=" + shlex.quote(shlex.join(_adapt_args(["quiet"], plan, config))) + "\n"
        source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] = f"linux /vmlinuz-{KERNEL} " + shlex.join(_adapt_args(["quiet"], plan, config)) + "\n"
        kernel = source["platform"]["kernels"][KERNEL]
        kernel["initrd_modules"] = [module for module in kernel["modules"] if module != "iscsi_ibft"]
        result = verify_platform(source, config)
        self.assertTrue(any("initramfs inclusion is unverified for iscsi_ibft" in error for error in result["blockers"]))
        kernel["builtin"].append("iscsi_ibft")
        result = verify_platform(source, config)
        self.assertTrue(result["ready"], result["blockers"])

    def test_stale_bls_transport_and_supplementary_grub_root_fail(self):
        source = image()
        source["platform"]["boot_files"]["/boot/loader/entries/test.conf"] = "options root=/dev/sda1 quiet\n"
        source["platform"]["boot_files"]["/etc/default/grub"] += 'GRUB_CMDLINE_LINUX_DEFAULT="root=/dev/sdb1"\n'
        blockers = " ".join(verify_platform(source, options())["blockers"])
        self.assertIn("test.conf", blockers)
        self.assertIn("Supplementary", blockers)


if __name__ == "__main__":
    unittest.main()
