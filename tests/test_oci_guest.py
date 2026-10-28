"""Guest preparation must prove prerequisites and fail closed after mutations."""
from contextlib import contextmanager
from copy import deepcopy
import fnmatch
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from forge.engine import EngineError, _validate_recipe
from forge.oci import OciConfig
from forge.oci_guest import (MODULE_CONFIG, _initramfs_script, _network_evidence,
                             _network_files, inspect_guest, plan_guest, prepare_guest)


VERSION = "6.12.0-204.92.4.4.3.el9uek.x86_64"


def config(**guest):
    return OciConfig(capabilities={"Storage.ConsistentVolumeNaming": {"default_value": False}},
                     guest=guest).model_dump()


def inspected():
    return {"os": {"distro": "oraclelinux", "arch": "x86_64"}, "kernels": ["/boot/vmlinuz-" + VERSION],
            "oci_evidence": {"version": 1, "firmware": {"UEFI_64": True, "BIOS": True},
                             "kernels": {VERSION: {"modules": list(MODULE_CONFIG), "builtin": [],
                                                   "config": {"CONFIG_AMD_MEM_ENCRYPT": "y", "CONFIG_IPV6": "y"},
                                                   "initrd": "/boot/initramfs-" + VERSION + ".img",
                                                   "initrd_modules": list(MODULE_CONFIG)}},
                             "tools": {name: True for name in ("dracut", "lsinitrd", "systemctl", "cloud-init", "grubby", "grub2-mkconfig", "iscsiadm", "multipath")},
                             "network_backend": "NetworkManager", "network_ready": True, "network_files": [],
                             "oracle_datasource": True, "cloud_init_ready": True, "serial_console_ready": True,
                             "consistent_naming_rules": [], "blacklisted_modules": [], "iscsi_boot_configured": False,
                             "ipv6_disable_files": [], "boot_arguments": "", "os_version": {"major": 9, "minor": 8}}}


def arm_inspected():
    image = json.loads(json.dumps(inspected()).replace(VERSION, "6.12.0-test.aarch64"))
    image["os"]["arch"] = "aarch64"
    image["boot"] = {"architecture": "aarch64", "supported_firmware": ["UEFI_64"], "efi_loaders": [
        {"path": "/EFI/BOOT/BOOTAA64.EFI", "architecture": "aarch64", "fallback": True}]}
    image["oci_evidence"].update(serial_device="ttyAMA0")
    kernel = next(iter(image["oci_evidence"]["kernels"].values()))
    kernel["config"].update({key: "y" for key in ("CONFIG_ARM64", "CONFIG_EFI", "CONFIG_EFI_STUB",
                                                 "CONFIG_SERIAL_AMBA_PL011", "CONFIG_SERIAL_AMBA_PL011_CONSOLE")})
    return image


class PlanTests(unittest.TestCase):
    def test_arm_validate_only_is_readonly_and_preparation_requires_native_worker(self):
        image = arm_inspected()
        with patch("forge.engine._guest") as guest, patch("forge.engine._run") as run:
            readonly = prepare_guest(Path("/tmp/arm.qcow2"), image, config(prepare=False), False, lambda _: None)
            self.assertEqual(readonly["blockers"], [])
            with self.assertRaisesRegex(EngineError, "worker cannot run"):
                prepare_guest(Path("/tmp/arm.qcow2"), image, config(), False, lambda _: None)
        guest.assert_not_called()
        run.assert_not_called()
        with patch("forge.architecture.worker_arch", return_value="aarch64"):
            plan = plan_guest(image, config())
        self.assertEqual(plan["blockers"], [])
        self.assertEqual(plan["serial_device"], "ttyAMA0")
        self.assertTrue(any("ttyAMA0" in change for change in plan["changes"]))

    def test_arm_requires_actual_kernel_and_firmware_evidence(self):
        image = arm_inspected()
        profile = config(prepare=False)
        kernel = next(iter(image["oci_evidence"]["kernels"].values()))
        kernel["config"].pop("CONFIG_ARM64")
        self.assertTrue(any("CONFIG_ARM64" in error for error in plan_guest(image, profile)["blockers"]))
        kernel["config"]["CONFIG_X86_64"] = "y"
        self.assertTrue(any("targets x86_64" in error for error in plan_guest(image, profile)["blockers"]))
        image = arm_inspected()
        image["boot"]["efi_loaders"][0]["architecture"] = "x86_64"
        self.assertTrue(any("ARM64 UEFI" in error for error in plan_guest(image, profile)["blockers"]))
        image = arm_inspected()
        image["oci_evidence"]["serial_device"] = "ttyS0"
        self.assertTrue(any("Serial-console" in error for error in plan_guest(image, profile)["blockers"]))

    def test_arm_does_not_advertise_bios_sev_or_unvalidated_hardware_profiles(self):
        for key, selected, expected in (("Compute.Firmware", "BIOS", "BIOS"),
                                        ("Compute.AMD_SecureEncryptedVirtualization", True, "AMD SEV"),
                                        ("Storage.BootVolumeType", "ISCSI", "ARM64 OCI"),
                                        ("Network.AttachmentType", "VFIO", "ARM64 OCI")):
            with self.subTest(key=key):
                profile = config(prepare=False)
                profile["capabilities"][key] = {"default_value": selected}
                self.assertTrue(any(expected in error for error in plan_guest(arm_inspected(), profile)["blockers"]))

    def test_validate_only_reuses_verified_bounded_archive_for_the_same_initrd(self):
        image, profile = inspected(), config(prepare=False)
        kernel = image["oci_evidence"]["kernels"][VERSION]
        kernel["initrd_modules"] = None
        self.assertTrue(plan_guest(image, profile)["blockers"])
        archive = {"initrd": kernel["initrd"], "initrd_sha256": "a" * 64,
                   "initrd_modules": list(MODULE_CONFIG), "portability": {"readable": True}}
        image["platform"] = {"kernels": {VERSION: archive}}
        self.assertFalse(plan_guest(image, profile)["blockers"])
        archive["initrd"] = "/boot/different.img"
        self.assertTrue(plan_guest(image, profile)["blockers"])
        archive["initrd"] = kernel["initrd"]
        archive["portability"]["readable"] = False
        self.assertTrue(plan_guest(image, profile)["blockers"])

    def test_verified_oracle_bootstrap_can_preserve_prior_nic_profiles_without_claiming_ipv6(self):
        image, profile = inspected(), config(prepare=False)
        image["oci_evidence"].update(network_ready=False, cloud_init_ready=False)
        self.assertTrue(plan_guest(image, profile)["blockers"])
        image["platform"] = {"portability": {"version": 1, "network_bootstrap": {"version": 1, "ready": True}}}
        self.assertFalse(plan_guest(image, profile)["blockers"])
        self.assertTrue(any("first-boot DHCP" in warning for warning in plan_guest(image, profile)["warnings"]))
        profile["capabilities"]["Network.IPv6Only"] = {"default_value": True, "values": None}
        self.assertTrue(any("network" in item.lower() for item in plan_guest(image, profile)["blockers"]))
        profile["capabilities"]["Network.IPv6Only"]["default_value"] = False
        image["platform"]["portability"]["network_blockers"] = ["Renderer is masked"]
        self.assertTrue(plan_guest(image, profile)["blockers"])

    def test_acceleratedpv_uses_audited_guest_virtio_without_inventing_nvme(self):
        image, profile = inspected(), config()
        profile["capabilities"]["Network.AttachmentType"] = {"default_value": "ACCELERATEDPV", "values": ["ACCELERATEDPV"]}
        before = deepcopy(image)
        plan = plan_guest(image, profile)
        self.assertFalse(plan["blockers"])
        self.assertTrue({"virtio_net", "virtio_pci", "virtio_scsi"} <= set(plan["required_modules"]))
        self.assertNotIn("nvme", plan["required_modules"])
        self.assertNotIn("mlx5_core", plan["required_modules"])
        self.assertTrue(any("E6.Ax" in warning for warning in plan["warnings"]))
        self.assertEqual(image, before, "planning must not mutate or prune the source driver inventory")

    def test_acceleratedpv_requires_modules_and_verified_initramfs_across_kernels(self):
        image, profile = inspected(), config(prepare=False)
        profile["capabilities"]["Network.AttachmentType"] = {"default_value": "ACCELERATEDPV", "values": ["ACCELERATEDPV"]}
        kernel = image["oci_evidence"]["kernels"][VERSION]
        kernel["initrd_modules"].remove("virtio_net")
        self.assertTrue(any("virtio_net" in message and "initramfs" in message for message in plan_guest(image, profile)["blockers"]))
        older = deepcopy(kernel)
        older["modules"].remove("virtio_net")
        older["config"]["CONFIG_VIRTIO_NET"] = "m"
        image["oci_evidence"]["kernels"]["old-kernel"] = older
        profile["guest"]["prepare"] = True
        self.assertTrue(any("old-kernel" in message and "virtio_net" in message for message in plan_guest(image, profile)["blockers"]))
        image["oci_evidence"]["blacklisted_modules"] = ["virtio_pci"]
        self.assertTrue(any("blacklisted" in message and "virtio_pci" in message for message in plan_guest(image, profile)["blockers"]))

    def test_selected_bm_driver_is_required_instead_of_any_available_vf_driver(self):
        image, profile = inspected(), config()
        profile["capabilities"]["Network.AttachmentType"] = {"default_value": "VFIO", "values": ["VFIO"]}
        image["oci_evidence"]["kernels"][VERSION]["modules"].remove("mlx5_core")
        self.assertFalse(plan_guest(image, profile)["blockers"], "generic VF profile can still use its other inventoried drivers")
        self.assertTrue(any("selected physical NIC" in item for item in plan_guest(image, profile, platform_nic_driver="mlx5_core")["blockers"]))

    def test_supported_pv_guest_has_real_changes(self):
        plan = plan_guest(inspected(), config())
        self.assertEqual(plan["blockers"], [])
        self.assertIn("virtio_scsi", plan["required_modules"])
        self.assertTrue(any("initramfs" in change for change in plan["changes"]))
        self.assertTrue(any("cloud-init" in change for change in plan["changes"]))

    def test_every_allowed_firmware_requires_positive_evidence(self):
        image, profile = inspected(), config()
        image["oci_evidence"]["firmware"]["BIOS"] = False
        profile["capabilities"]["Compute.Firmware"]["values"] = ["BIOS", "UEFI_64"]
        self.assertTrue(any("BIOS:" in item for item in plan_guest(image, profile)["blockers"]))

    def test_alternate_nic_driver_is_checked_not_only_default(self):
        image, profile = inspected(), config()
        image["oci_evidence"]["kernels"][VERSION]["modules"].remove("e1000")
        profile["capabilities"]["Network.AttachmentType"]["values"] = ["PARAVIRTUALIZED", "E1000"]
        self.assertTrue(any("e1000" in item for item in plan_guest(image, profile)["blockers"]))

    def test_blacklisted_required_driver_blocks_preparation(self):
        image = inspected()
        image["oci_evidence"]["blacklisted_modules"] = ["virtio_scsi"]
        self.assertTrue(any("blacklisted" in item for item in plan_guest(image, config())["blockers"]))

    def test_modular_config_does_not_substitute_for_installed_driver(self):
        image = inspected()
        kernel = image["oci_evidence"]["kernels"][VERSION]
        kernel["modules"].remove("virtio_scsi")
        kernel["config"]["CONFIG_SCSI_VIRTIO"] = "m"
        self.assertTrue(any("lacks installed" in item for item in plan_guest(image, config())["blockers"]))

    def test_preparation_disabled_accepts_underlying_evidence_without_marker(self):
        plan = plan_guest(inspected(), config(prepare=False))
        self.assertEqual(plan["blockers"], [])
        self.assertEqual(plan["changes"], [])

    def test_preparation_disabled_blocks_unverified_initramfs(self):
        image = inspected()
        image["oci_evidence"]["kernels"][VERSION]["initrd_modules"] = None
        self.assertTrue(any("initramfs inclusion" in item for item in plan_guest(image, config(prepare=False))["blockers"]))

    def test_package_installation_requires_both_opt_ins(self):
        image = inspected()
        image["oci_evidence"]["tools"]["cloud-init"] = False
        self.assertTrue(plan_guest(image, config(install_packages=True))["blockers"])
        plan = plan_guest(image, config(install_packages=True), allow_network=True)
        self.assertEqual(plan["packages"], ["cloud-init"])
        self.assertEqual(plan["blockers"], [])

    def test_missing_native_initramfs_listing_tool_is_not_silently_skipped(self):
        image = inspected()
        image["oci_evidence"]["tools"]["lsinitrd"] = False
        self.assertTrue(any("lsinitrd" in item for item in plan_guest(image, config())["blockers"]))

    def test_iscsi_driver_alone_does_not_prove_native_boot(self):
        profile = config()
        profile["capabilities"]["Storage.BootVolumeType"] = {"default_value": "ISCSI", "values": ["ISCSI"]}
        self.assertTrue(any("firmware discovery" in item for item in plan_guest(inspected(), profile)["blockers"]))

    def test_ibft_driver_is_required_for_firmware_boot_but_not_data_volumes(self):
        image, profile = inspected(), config()
        image["oci_evidence"]["kernels"][VERSION]["modules"].remove("iscsi_ibft")
        image["oci_evidence"]["iscsi_boot_configured"] = True
        profile["capabilities"]["Storage.RemoteDataVolumeType"] = {"default_value": "ISCSI", "values": ["ISCSI"]}
        self.assertNotIn("iscsi_ibft", plan_guest(image, profile)["required_modules"])
        profile["capabilities"]["Storage.BootVolumeType"] = {"default_value": "ISCSI", "values": ["ISCSI"]}
        self.assertTrue(any("iscsi_ibft" in item for item in plan_guest(image, profile)["blockers"]))

    def test_consistent_naming_requires_actual_oci_rules(self):
        profile = config()
        profile["capabilities"]["Storage.ConsistentVolumeNaming"]["default_value"] = True
        self.assertTrue(any("udev rules" in item for item in plan_guest(inspected(), profile)["blockers"]))

    def test_iscsi_multipath_rejects_generic_non_uek_kernel(self):
        image, profile = inspected(), config()
        profile["capabilities"]["Storage.Iscsi.MultipathDeviceSupported"]["default_value"] = True
        image["os"]["distro"] = "ubuntu"
        self.assertTrue(any("UEK6U1" in item for item in plan_guest(image, profile)["blockers"]))

    def test_sev_and_cloud_init_disabled_boot_parameters_block(self):
        image, profile = inspected(), config()
        profile["capabilities"]["Compute.AMD_SecureEncryptedVirtualization"]["default_value"] = True
        image["oci_evidence"]["boot_arguments"] = "mem_encrypt=off cloud-init=disabled"
        blockers = " ".join(plan_guest(image, profile)["blockers"])
        self.assertIn("mem_encrypt=off", blockers)
        self.assertIn("cloud-init=disabled", blockers)

    def test_ipv6_cannot_be_advertised_with_unverified_network(self):
        image, profile = inspected(), config(configure_network=False)
        profile["capabilities"]["Network.IPv6Only"]["default_value"] = True
        image["oci_evidence"]["network_ready"] = False
        self.assertTrue(any("IPv6" in item and "network" in item for item in plan_guest(image, profile)["blockers"]))

    def test_ipv6_modular_config_requires_installed_module(self):
        image, profile = inspected(), config()
        profile["capabilities"]["Network.IPv6Only"]["default_value"] = True
        kernel = image["oci_evidence"]["kernels"][VERSION]
        kernel["modules"].remove("ipv6")
        kernel["config"]["CONFIG_IPV6"] = "m"
        self.assertTrue(any("lacks installed" in item and "ipv6" in item for item in plan_guest(image, profile)["blockers"]))

    def test_oci_configuration_cannot_be_applied_to_other_provider(self):
        with self.assertRaisesRegex(EngineError, "OCI export target"):
            _validate_recipe({"target": "aws", "output_format": "raw", "oci": config()}, inspected())


class FakeGuest:
    def __init__(self, files=None):
        self.files = files or {}

    def is_file(self, path):
        return path in self.files

    def is_symlink(self, path):
        return False

    def is_dir(self, path):
        return path == "/usr/lib/dracut/modules.d/95iscsi"

    def filesize(self, path):
        return len(self.files[path])

    def read_file(self, path):
        return self.files[path]

    def glob_expand(self, pattern):
        return [path for path in self.files if fnmatch.fnmatchcase(path, pattern)]

    def part_get_parttype(self, device):
        return "gpt"

    def part_get_gpt_type(self, device, number):
        return "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"

    def pread(self, path, count, offset):
        return self.files[path][offset:offset + count]

    def pread_device(self, device, count, offset):
        return bytes(count)

    def initrd_list(self, path):
        return ["lib/modules/test/kernel/virtio_scsi.ko.xz"]

    def inspect_get_major_version(self, root):
        return 9

    def inspect_get_minor_version(self, root):
        return 8


class EvidenceTests(unittest.TestCase):
    def test_arm_inspection_retains_kernel_architecture_and_serial_evidence(self):
        boot = {"supported_firmware": ["UEFI_64"], "efi_loaders": [
            {"path": "/EFI/BOOT/BOOTAA64.EFI", "architecture": "aarch64"}]}
        g = FakeGuest({"/boot/config-test": "CONFIG_ARM64=y\nCONFIG_EFI=y\nCONFIG_EFI_STUB=y\n"
                      "CONFIG_SERIAL_AMBA_PL011=y\nCONFIG_SERIAL_AMBA_PL011_CONSOLE=y\n",
                      "/etc/default/grub": 'GRUB_CMDLINE_LINUX="console=ttyAMA0,115200n8"\n',
                      "/etc/systemd/system/getty.target.wants/serial-getty@ttyAMA0.service": ""})
        result = inspect_guest(g, "/dev/sda2", [], ["/boot/vmlinuz-test"], boot=boot, architecture="arm64")
        self.assertEqual(result["architecture"], "aarch64")
        self.assertEqual(result["kernels"]["test"]["architecture"], "aarch64")
        self.assertEqual(result["kernels"]["test"]["config"]["CONFIG_EFI_STUB"], "y")
        self.assertIn("amba_pl011", result["kernels"]["test"]["builtin"])
        self.assertEqual(result["serial_device"], "ttyAMA0")
        self.assertTrue(result["serial_console_ready"])
        g.files["/etc/default/grub"] = 'GRUB_CMDLINE_LINUX="console=ttyS0,115200n8"\n'
        self.assertFalse(inspect_guest(g, "/dev/sda2", [], ["/boot/vmlinuz-test"], boot=boot,
                                      architecture="aarch64")["serial_console_ready"])

    def test_installed_module_evidence_checks_files_and_rejects_stale_or_escaping_paths(self):
        directory = "/lib/modules/test/"
        g = FakeGuest({
            "/boot/config-test": "CONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_NET=m\n",
            directory + "modules.dep": "kernel/net/virtio_net.ko.xz:\nkernel/scsi/virtio_scsi.ko.zst:\n../virtio_blk.ko:\n/absolute/sd_mod.ko:\n",
            directory + "kernel/scsi/virtio_scsi.ko.zst": "compressed module",
            directory + "../virtio_blk.ko": "must not count",
            directory + "modules.builtin": "kernel/virtio/virtio_ring.ko\n",
        })
        result = inspect_guest(g, "/dev/sda1", [], ["/boot/vmlinuz-test"])
        kernel = result["kernels"]["test"]
        self.assertEqual(kernel["modules"], ["virtio_scsi"])
        self.assertIn("virtio_pci", kernel["builtin"])
        self.assertNotIn("virtio_net", kernel["modules"])

    def test_nm_bound_interface_is_not_portable_readiness(self):
        path = "/etc/NetworkManager/system-connections/primary.nmconnection"
        content = _network_files("NetworkManager").popitem()[1].replace("type=ethernet", "type=ethernet\ninterface-name=ens192")
        g = FakeGuest({path: content, "/etc/systemd/system/multi-user.target.wants/NetworkManager.service": ""})
        self.assertFalse(_network_evidence(g, {"NetworkManager": True})[1])

    def test_ifcfg_dhcp_with_disabled_ipv6_is_not_ready(self):
        g = FakeGuest({"/etc/sysconfig/network-scripts/ifcfg-eth0": "BOOTPROTO=dhcp\nIPV6INIT=no\nIPV6_AUTOCONF=no\n", "/etc/systemd/system/multi-user.target.wants/NetworkManager.service": ""})
        self.assertFalse(_network_evidence(g, {"NetworkManager": True})[1])

    def test_multiple_netplan_profiles_need_preparation(self):
        content = _network_files("netplan").popitem()[1]
        g = FakeGuest({"/etc/netplan/10-a.yaml": content, "/etc/netplan/20-b.yaml": "network: {}"})
        self.assertFalse(_network_evidence(g, {"netplan": True})[1])

    def test_inspection_reuses_boot_evidence_and_collects_blacklists(self):
        boot = {"supported_firmware": ["UEFI_64"], "partition_table": "gpt",
                "efi_loaders": [{"device": "/dev/sda1", "path": "/EFI/BOOT/BOOTX64.EFI",
                                 "architecture": "x86_64", "fallback": True}], "bios_evidence": []}
        g = FakeGuest({"/boot/config-test": "CONFIG_VIRTIO_PCI=y\nCONFIG_SCSI_VIRTIO=m\n",
                       "/lib/modules/test/modules.dep": "kernel/virtio_scsi.ko.xz:\n",
                       "/lib/modules/test/kernel/virtio_scsi.ko.xz": "compressed module",
                       "/etc/modprobe.d/local.conf": "blacklist virtio_net\ninstall virtio_scsi /bin/false\n",
                       "/etc/udev/rules.d/comment.rules": '# SYMLINK+="oracleoci/fake"\n',
                       "/etc/udev/rules.d/real.rules": 'SUBSYSTEM=="block", SYMLINK+="oracleoci/%k"\n',
                       "/etc/default/grub": 'GRUB_CMDLINE_LINUX="rd.iscsi.ibft=1"\n'})
        result = inspect_guest(g, "/dev/sda2", [{"device": "/dev/sda1", "mountpoint": None}], ["/boot/vmlinuz-test"], boot=boot)
        self.assertTrue(result["firmware"]["UEFI_64"])
        self.assertTrue(result["iscsi_boot_configured"])
        self.assertEqual(result["blacklisted_modules"], ["virtio_net", "virtio_scsi"])
        self.assertEqual(result["consistent_naming_rules"], ["/etc/udev/rules.d/real.rules"])
        self.assertIn("virtio_pci", result["kernels"]["test"]["builtin"])
        self.assertIn("virtio_scsi", result["kernels"]["test"]["modules"])
        self.assertEqual(result["firmware"]["efi_loaders"], boot["efi_loaders"])
        # A mounted-root caller without the independent boot scan cannot infer
        # firmware support from EFI filenames or partition types.
        self.assertFalse(inspect_guest(g, "/dev/sda2", [], ["/boot/vmlinuz-test"])["firmware"]["UEFI_64"])



class PreparationTests(unittest.TestCase):
    def test_arm_serial_commands_use_pl011_and_never_x86_console(self):
        image = arm_inspected()
        profile = config(configure_network=False, configure_cloud_init=False)
        g = Mock()
        g.is_symlink.return_value = False
        g.is_file.return_value = False
        @contextmanager
        def guest(*args, **kwargs):
            yield g
        with patch("forge.architecture.worker_arch", return_value="aarch64"), patch("forge.engine._guest", guest), \
                patch("forge.engine._mount"), patch("forge.engine._roots", return_value="/dev/sda1"), \
                patch("forge.engine._run") as run, patch("forge.engine.ImageEngine.inspect", return_value=deepcopy(image)):
            result = prepare_guest(Path("/tmp/arm.qcow2"), image, profile, False, lambda _: None)
        commands = " ".join(run.call_args.args[0])
        self.assertIn("console=ttyAMA0,115200n8", commands)
        self.assertIn("serial-getty@ttyAMA0.service", commands)
        self.assertNotIn("ttyS0", commands)
        self.assertEqual(result["architecture"], "aarch64")

    def test_oci_rebuild_preserves_physical_driver_and_returns_hash_bound_receipt(self):
        image = inspected()
        image["oci_evidence"]["kernels"][VERSION]["modules"].remove("ixgbe")
        before = deepcopy(image)
        image["platform"] = {"kernels": {VERSION: {
            "modules": ["ixgbe"], "builtin": [], "initrd": "/boot/initramfs-" + VERSION + ".img",
            "initrd_sha256": "a" * 64,
        }}}
        after = deepcopy(image)
        after["platform"]["kernels"][VERSION]["initrd_sha256"] = "b" * 64
        profile = config(configure_network=False, configure_cloud_init=False, configure_serial_console=False)
        g = Mock()
        g.is_symlink.return_value = False
        g.is_file.return_value = False

        @contextmanager
        def guest(*args, **kwargs):
            yield g

        with patch("forge.engine._guest", guest), patch("forge.engine._mount"), \
                patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._run") as run, \
                patch("forge.engine.ImageEngine.inspect", return_value=after):
            result = prepare_guest(Path("/tmp/working.qcow2"), image, profile, False, lambda _: None,
                                   extra_required_modules=["ixgbe"])
        self.assertIn("ixgbe", result["required_modules"])
        self.assertIn("Required driver ixgbe absent", " ".join(run.call_args.args[0]))
        receipt = result["verified_initrds"][VERSION]
        self.assertIn("ixgbe", receipt["modules"])
        self.assertEqual(receipt["sha256"], "b" * 64)
        self.assertEqual(image["oci_evidence"], before["oci_evidence"])

    def test_additional_driver_must_be_installed_before_mutation(self):
        image = inspected()
        image["oci_evidence"]["kernels"][VERSION]["modules"].remove("ixgbe")
        with patch("forge.engine._guest") as guest, patch("forge.engine._run") as run:
            with self.assertRaisesRegex(EngineError, "lacks required migration drivers"):
                prepare_guest(Path("/tmp/working.qcow2"), image, config(), False, lambda _: None,
                              extra_required_modules=["ixgbe"])
            guest.assert_not_called()
            run.assert_not_called()

    def test_iscsi_initramfs_requires_userspace_and_dracut_module_proof(self):
        script = _initramfs_script(inspected(), {"initramfs_backend": "dracut", "required_modules": ["iscsi_tcp"], "iscsi_boot": True})
        self.assertIn("/iscsistart", script)
        self.assertIn("lsinitrd -m", script)
        with self.assertRaisesRegex(ValueError, "requires dracut"):
            _initramfs_script(inspected(), {"initramfs_backend": "initramfs-tools", "required_modules": ["iscsi_tcp"], "iscsi_boot": True})

    def test_initramfs_creation_and_driver_verification_are_mandatory(self):
        image = inspected()
        image["oci_evidence"]["kernels"][VERSION]["initrd"] = None
        plan = {"initramfs_backend": "initramfs-tools", "required_modules": ["virtio_scsi"], "iscsi_boot": False}
        script = _initramfs_script(image, plan)
        self.assertIn("update-initramfs -c -k", script)
        self.assertIn("lsinitramfs", script)
        self.assertIn("Required driver virtio_scsi absent", script)

    def test_changed_guest_evidence_after_preparation_fails_build(self):
        image = inspected()
        after = deepcopy(image)
        after["oci_evidence"]["firmware"]["UEFI_64"] = False
        profile = config(configure_network=False, configure_cloud_init=False, configure_serial_console=False)
        g = Mock()
        g.is_symlink.return_value = False
        g.is_file.return_value = False

        @contextmanager
        def guest(*args, **kwargs):
            yield g

        with patch("forge.engine._guest", guest), patch("forge.engine._mount"), \
                patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._run") as run, \
                patch("forge.engine.ImageEngine.inspect", return_value=after):
            with self.assertRaisesRegex(EngineError, "verification failed after preparation"):
                prepare_guest(Path("/tmp/working.qcow2"), image, profile, False, lambda _: None)
            self.assertTrue(run.called)
            self.assertIn("--no-network", run.call_args.args[0])

    def test_preexisting_verified_guest_can_skip_mutation(self):
        with patch("forge.engine._guest") as guest, patch("forge.engine._run") as run:
            plan = prepare_guest(Path("/tmp/working.qcow2"), inspected(), config(prepare=False), False, lambda _: None)
            self.assertEqual(plan["blockers"], [])
            guest.assert_not_called()
            run.assert_not_called()


def test_oci_projects_iscsi_only_after_valid_platform_plan_without_mutating_source():
    from forge.oci import compatibility_plan
    image = inspected()
    original = deepcopy(image)
    profile = OciConfig(capabilities={
        "Compute.LaunchMode": {"default_value": "CUSTOM", "values": ["CUSTOM"]},
        "Storage.BootVolumeType": {"default_value": "ISCSI", "values": ["ISCSI"]},
        "Storage.ConsistentVolumeNaming": {"default_value": False},
    })
    options = {"enabled": True, "boot_attachment": "iscsi"}
    for ready in (False, True):
        with patch("forge.platform.plan_platform", return_value={
            "ready": ready, "actions": ["Prepare firmware-discovered iSCSI"],
            "blockers": [] if ready else ["Missing physical NIC driver"], "warnings": [],
        }):
            plan = compatibility_plan(image, profile, platform_migration=options)
            actual = compatibility_plan(image, profile, platform_migration=options, project_platform=False)
        discovery_blocked = any("firmware discovery" in item for item in plan["blockers"])
        assert discovery_blocked is not ready
        assert plan["platform_migration"]["ready"] is ready
        assert any("firmware discovery" in item for item in actual["blockers"])
    assert image == original


if __name__ == "__main__":
    unittest.main()
