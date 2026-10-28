"""Migration planning, disk safety, and failure-before-publication checks."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import struct
import unittest
from unittest.mock import Mock, patch
import zlib

from forge.engine import EngineError
from forge.uefi import (EFI_GUID, GIB, MIB, _fat32, _forward_config, _fstab_with_esp,
                        _install_script, _preserved, _verify_configuration,
                        inspect_layout, migrate, plan_migration)


def inspected(table="msdos", distro="debian"):
    part = {"number": 1, "device": "/dev/sda1", "start": MIB, "end": GIB - 1,
            "size": GIB - MIB, "type": 0x83, "filesystem": "ext4", "uuid": "root-uuid", "active": 0x80}
    layout = {"partition_table": table, "sector_size": 512, "disk_size": GIB,
              "partitions": [part], "free_slot": 2, "hybrid": False,
              "boot_code_sha256": "boot-code", "disk_identity": "disk-id", "errors": []}
    guest = {"tools": {tool: "/usr/bin/" + tool for tool in ("grub-install", "grub-mkconfig", "grub-script-check", "rpm", "dnf", "apt-get")},
             "major": 9, "efi_modules": True, "kernels": [{"path": "/boot/vmlinuz-6.12", "efi": True, "initrd": "/boot/initrd-6.12"}],
             "boot_uuid": "root-uuid", "boot_path": "/boot/grub2/grub.cfg", "esp_candidates": [], "errors": []}
    return {"os": {"arch": "x86_64", "distro": distro}, "virtual_size": GIB,
            "boot": {"mode": "bios", "supported_firmware": ["BIOS"]},
            "uefi_migration": {"version": 1, "layout": layout, "guest": guest}}


OPTIONS = {"enabled": True, "esp_size_mib": 512, "install_packages": False}


class PlanTests(unittest.TestCase):
    def test_disabled_migration_is_an_explicit_noop(self):
        self.assertFalse(plan_migration({}, None)["requested"])

    def test_already_uefi_does_not_require_migration_packages_or_layout(self):
        image = {"os": {"arch": "x86_64"}, "boot": {"supported_firmware": ["UEFI_64"]}}
        plan = plan_migration(image, OPTIONS)
        self.assertTrue(plan["ready_to_migrate"])
        self.assertEqual(plan["layout"]["action"], "already_uefi")
        self.assertEqual(plan["growth_bytes"], 0)

    def test_arm_matching_uefi_is_a_noop_even_on_x86_worker(self):
        image = {"os": {"arch": "arm64"}, "boot": {"architecture": "aarch64", "supported_firmware": ["UEFI_64"],
                 "efi_loaders": [{"architecture": "aarch64", "path": "/EFI/BOOT/BOOTAA64.EFI"}]}}
        plan = plan_migration(image, OPTIONS)
        self.assertTrue(plan["ready_to_migrate"], plan["blockers"])
        self.assertEqual(plan["layout"], {"action": "already_uefi", "preserve_bios": False})
        with patch("forge.engine._guest") as guest, patch("forge.engine._run") as run:
            result = migrate(Path("/tmp/arm.qcow2"), image, OPTIONS, False, lambda _: None)
        self.assertEqual(result["inspection"], image)
        guest.assert_not_called()
        run.assert_not_called()
        image["boot"]["efi_loaders"][0]["architecture"] = "x86_64"
        self.assertFalse(plan_migration(image, OPTIONS)["ready_to_migrate"])

    def test_actual_x86_migration_requires_matching_worker_before_writes(self):
        with patch("forge.architecture.worker_arch", return_value="aarch64"), patch("forge.engine._guest") as guest:
            with self.assertRaisesRegex(EngineError, "worker cannot run"):
                migrate(Path("/tmp/x86.qcow2"), inspected(), OPTIONS, False, lambda _: None)
        guest.assert_not_called()

    def test_simple_mbr_appends_beyond_original_end_without_moving_partition(self):
        image = inspected()
        plan = plan_migration(image, OPTIONS)
        self.assertEqual(plan["blockers"], [])
        self.assertEqual(plan["layout"]["partition_table"], "msdos")
        self.assertEqual(plan["layout"]["start_sector"], GIB // 512)
        self.assertEqual(plan["layout"]["end_sector"] + 1, (GIB + 512 * MIB) // 512)
        self.assertEqual(plan["growth_bytes"], 513 * MIB)
        self.assertEqual(image["uefi_migration"]["layout"]["partitions"][0]["start"], MIB)

    def test_existing_esp_is_reused_without_growth_or_formatting_request(self):
        image = inspected("gpt")
        image["uefi_migration"]["guest"]["esp_candidates"] = [{"device": "/dev/sda2", "fat32": True, "free_bytes": 100 * MIB, "size": 256 * MIB}]
        plan = plan_migration(image, OPTIONS)
        self.assertEqual(plan["layout"]["action"], "reuse")
        self.assertEqual(plan["growth_bytes"], 0)
        self.assertTrue(plan["ready_to_migrate"])

    def test_ambiguous_or_full_existing_esp_is_not_reformatted(self):
        image = inspected()
        esp = {"device": "/dev/sda2", "fat32": True, "free_bytes": 4 * MIB, "size": 256 * MIB}
        for candidates in ([esp], [esp, dict(esp, device="/dev/sda3")]):
            image["uefi_migration"]["guest"]["esp_candidates"] = candidates
            self.assertFalse(plan_migration(image, OPTIONS)["ready_to_migrate"])

    def test_packages_require_both_explicit_opt_ins(self):
        image = inspected()
        image["uefi_migration"]["guest"]["efi_modules"] = False
        self.assertFalse(plan_migration(image, dict(OPTIONS, install_packages=True))["ready_to_migrate"])
        self.assertFalse(plan_migration(image, OPTIONS, True)["ready_to_migrate"])
        plan = plan_migration(image, dict(OPTIONS, install_packages=True), True)
        self.assertTrue(plan["ready_to_migrate"])
        self.assertEqual(plan["requires_packages"], ["grub-efi-amd64-bin", "grub2-common"])
        self.assertNotIn("grub-efi-amd64", plan["requires_packages"], "Do not displace the existing BIOS package")

    def test_legacy_rpm_and_missing_kernel_efi_support_block(self):
        image = inspected(distro="oraclelinux")
        image["uefi_migration"]["guest"]["major"] = 8
        self.assertIn("older EFI", " ".join(plan_migration(image, dict(OPTIONS, install_packages=True), True)["blockers"]))
        image = inspected()
        image["uefi_migration"]["guest"]["kernels"][0]["efi"] = False
        self.assertFalse(plan_migration(image, OPTIONS)["ready_to_migrate"])

    def test_unknown_bios_architecture_and_no_free_slot_block(self):
        for mutate in (lambda image: image["boot"].update(supported_firmware=[]),
                       lambda image: image["os"].update(arch="aarch64"),
                       lambda image: image["uefi_migration"]["layout"].update(free_slot=None),
                       lambda image: image["uefi_migration"]["layout"]["errors"].append("Encrypted partition")):
            image = inspected()
            mutate(image)
            self.assertFalse(plan_migration(image, OPTIONS)["ready_to_migrate"])

    def test_existing_partition_identifiers_and_bios_flags_must_survive(self):
        before = inspected()["uefi_migration"]["layout"]
        for key, value in (("start", 2 * MIB), ("uuid", "changed"), ("active", 0), ("type", 0xEF)):
            after = deepcopy(before)
            after["partitions"][0][key] = value
            self.assertFalse(_preserved(before, after))
        self.assertTrue(_preserved(before, deepcopy(before)))


class MemoryDisk:
    def __init__(self, gpt=False):
        self.data = bytearray(8 * MIB)
        self.gpt = gpt
        self.data[510:512] = b"\x55\xaa"
        self.data[446] = 0 if gpt else 0x80
        self.data[450] = 0xEE if gpt else 0x83
        struct.pack_into("<II", self.data, 454, 1 if gpt else 2048, len(self.data) // 512 - 1 if gpt else 8192)
        self.parts = [{"part_num": 1, "part_start": MIB, "part_end": 5 * MIB - 1, "part_size": 4 * MIB}]
        if gpt:
            self.write_gpt()

    def write_gpt(self, first=34, last=None):
        total = len(self.data) // 512
        last = total - 34 if last is None else last
        entries = bytearray(128 * 128)
        entries[:16] = bytes(range(16))
        entries[16:32] = bytes(range(16, 32))
        struct.pack_into("<QQ", entries, 32, 2048, 10239)
        self.data[1024:1024 + len(entries)] = entries
        self.data[(total - 33) * 512:(total - 1) * 512] = entries
        for current, backup, array in ((1, total - 1, 2), (total - 1, 1, total - 33)):
            header = bytearray(512)
            header[:8] = b"EFI PART"
            struct.pack_into("<II", header, 8, 0x10000, 92)
            struct.pack_into("<QQQQ", header, 24, current, backup, first, last)
            header[56:72] = bytes(range(16))
            struct.pack_into("<QIII", header, 72, array, 128, 128, zlib.crc32(entries))
            struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
            self.data[current * 512:(current + 1) * 512] = header

    def mountpoints(self): return {}
    def blockdev_getsize64(self, device): return len(self.data)
    def blockdev_getss(self, device): return 512
    def part_get_parttype(self, device): return "gpt" if self.gpt else "msdos"
    def part_list(self, device): return self.parts
    def pread_device(self, device, count, offset): return bytes(self.data[offset:offset + count])
    def part_get_gpt_type(self, device, number): return "linux-data"
    def vfs_type(self, device): return "ext4"
    def vfs_uuid(self, device): return "root-uuid"


class LayoutTests(unittest.TestCase):
    def test_valid_gpt_and_simple_mbr_layouts_are_accepted(self):
        for gpt in (False, True):
            with self.subTest(gpt=gpt):
                result = inspect_layout(MemoryDisk(gpt))
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["free_slot"], 2)

    def test_extended_and_hybrid_layouts_are_rejected(self):
        guest = MemoryDisk()
        guest.data[450] = 0x0F
        self.assertIn("Extended", " ".join(inspect_layout(guest)["errors"]))
        guest = MemoryDisk(True)
        guest.data[466] = 0x83
        self.assertIn("Hybrid", " ".join(inspect_layout(guest)["errors"]))

    def test_gpt_checksums_and_usable_boundaries_are_enforced(self):
        guest = MemoryDisk(True)
        guest.data[512 + 16] ^= 1
        self.assertIn("checksum", " ".join(inspect_layout(guest)["errors"]))
        guest = MemoryDisk(True)
        guest.write_gpt(first=4096)
        self.assertIn("boundaries", " ".join(inspect_layout(guest)["errors"]))

    def test_partition_at_disk_boot_sector_is_rejected(self):
        guest = MemoryDisk()
        guest.parts[0]["part_start"] = 0
        self.assertIn("boundaries", " ".join(inspect_layout(guest)["errors"]))


class ConfigurationTests(unittest.TestCase):
    def test_fstab_retains_other_mounts_and_rejects_duplicate_esp(self):
        original = "UUID=root / ext4 defaults 0 1\nUUID=data /data xfs defaults 0 2\n"
        result = _fstab_with_esp(original, "1234-ABCD")
        self.assertTrue(result.startswith(original))
        self.assertIn("UUID=1234-ABCD /boot/efi vfat", result)
        with self.assertRaisesRegex(EngineError, "Multiple"):
            _fstab_with_esp("UUID=a /boot/efi vfat defaults\nUUID=b /boot/efi vfat defaults\n", "1234-ABCD")

    def test_rpm_forwarding_handles_separate_boot_partition(self):
        self.assertIn("set prefix=($forge_boot)/grub2", _forward_config("boot-uuid", "/grub2/grub.cfg"))
        self.assertIn("set prefix=($forge_boot)/boot/grub2", _forward_config("root-uuid", "/boot/grub2/grub.cfg"))

    def test_distribution_install_commands_preserve_bios_and_avoid_nvram(self):
        debian = _install_script({"family": "debian"})
        self.assertIn("--target=x86_64-efi", debian)
        self.assertIn("--no-nvram --removable", debian)
        self.assertIn("--no-uefi-secure-boot", debian)
        self.assertNotIn("--force", debian)
        rpm = _install_script({"family": "rpm", "vendor": "redhat"})
        self.assertNotIn("grub2-install", rpm)
        self.assertIn("rpm -V", rpm)
        self.assertIn("grub2-mkconfig -o /boot/grub2/grub.cfg", rpm)

    def test_bios_only_generated_kernel_commands_fail_verification(self):
        g = Mock()
        with patch("forge.uefi._read", return_value="menuentry linux {\n linux16 /vmlinuz\n}\n"):
            with self.assertRaisesRegex(EngineError, "BIOS-only"):
                _verify_configuration(g, {"family": "debian"}, inspected(), "1234-ABCD")


class ExecutorTests(unittest.TestCase):
    def context(self, image, after=None):
        plan = plan_migration(image, OPTIONS)
        selected = plan["layout"]
        before = image["uefi_migration"]["layout"]
        grown = deepcopy(before)
        grown["disk_size"] = selected["disk_size_after"]
        if selected["action"] == "append":
            grown["partitions"].append({"number": 2, "device": "/dev/sda2", "start": selected["start_sector"] * 512,
                                       "end": (selected["end_sector"] + 1) * 512 - 1, "type": 0xEF})
        after = after or deepcopy(image)
        after["uefi_migration"]["layout"] = grown
        after["boot"] = {"supported_firmware": ["BIOS", "UEFI_64"], "efi_loaders": [{"device": "/dev/sda2", "fallback": True}]}
        g = Mock()
        g.is_symlink.return_value = False
        g.exists.return_value = False
        g.is_dir.return_value = False
        g.is_file.return_value = False
        g.mountpoints.return_value = {}
        g.vfs_uuid.return_value = "1234-ABCD"
        original = [{"part_num": 1, "part_start": MIB, "part_end": GIB - 1}]
        added = original + [{"part_num": 2, "part_start": selected["start_sector"] * 512 if selected["start_sector"] else GIB,
                             "part_end": (selected["end_sector"] + 1) * 512 - 1 if selected["end_sector"] else GIB + 512 * MIB - 1}]
        g.part_list.side_effect = [original, added]

        @contextmanager
        def guest(*args, **kwargs):
            yield g

        return g, guest, before, grown, after

    def test_append_formats_only_new_partition_and_verifies_result(self):
        image = inspected()
        g, guest, before, grown, after = self.context(image)
        with patch("forge.engine._guest", guest), patch("forge.engine._run") as run, \
                patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._mount"), \
                patch("forge.engine._write_guest") as write, \
                patch("forge.uefi.inspect_layout", side_effect=[before, grown]), \
                patch("forge.uefi._fat32", return_value=True), patch("forge.uefi._read", return_value="UUID=root / ext4 defaults 0 1\n"), \
                patch("forge.uefi._verify_configuration"), patch("forge.engine.ImageEngine.inspect", return_value=after):
            result = migrate(Path("working.qcow2"), image, OPTIONS, False, lambda _: None)
        g.mkfs.assert_called_once_with("vfat", "/dev/sda2", label="FORGE_EFI")
        g.part_set_mbr_id.assert_called_once_with("/dev/sda", 2, 0xEF)
        g.part_set_bootable.assert_not_called()
        self.assertEqual(run.call_args_list[0].args[0][:4], ["qemu-img", "resize", "-f", "qcow2"])
        self.assertIn("UUID=1234-ABCD /boot/efi vfat", write.call_args.args[2])
        self.assertEqual(result["inspection"]["boot"]["supported_firmware"], ["BIOS", "UEFI_64"])

    def test_post_migration_missing_uefi_fails(self):
        image = inspected()
        g, guest, before, grown, after = self.context(image)
        after["boot"]["supported_firmware"] = ["BIOS"]
        with patch("forge.engine._guest", guest), patch("forge.engine._run"), \
                patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._mount"), \
                patch("forge.engine._write_guest"), patch("forge.uefi.inspect_layout", side_effect=[before, grown]), \
                patch("forge.uefi._fat32", return_value=True), patch("forge.uefi._read", return_value="UUID=root / ext4 defaults 0 1\n"), \
                patch("forge.uefi._verify_configuration"), patch("forge.engine.ImageEngine.inspect", return_value=after):
            with self.assertRaisesRegex(EngineError, "add verified UEFI"):
                migrate(Path("working.qcow2"), image, OPTIONS, False, lambda _: None)

    def test_reusing_an_esp_never_formats_or_changes_partition_table(self):
        image = inspected()
        esp = {"number": 2, "device": "/dev/sda2", "start": GIB, "end": GIB + 256 * MIB - 1,
               "size": 256 * MIB, "type": 0xEF, "fat32": True, "free_bytes": 100 * MIB, "uuid": "1234-ABCD"}
        image["virtual_size"] += 256 * MIB
        image["uefi_migration"]["layout"]["disk_size"] = image["virtual_size"]
        image["uefi_migration"]["layout"]["partitions"].append(esp)
        image["uefi_migration"]["guest"]["esp_candidates"] = [esp]
        g, guest, before, grown, after = self.context(image)
        with patch("forge.engine._guest", guest), patch("forge.engine._run") as run, \
                patch("forge.engine._roots", return_value="/dev/sda1"), patch("forge.engine._mount"), \
                patch("forge.engine._write_guest"), patch("forge.uefi.inspect_layout", side_effect=[before, grown]), \
                patch("forge.uefi._read", return_value="UUID=root / ext4 defaults 0 1\n"), \
                patch("forge.uefi._verify_configuration"), patch("forge.engine.ImageEngine.inspect", return_value=after):
            migrate(Path("working.qcow2"), image, OPTIONS, False, lambda _: None)
        g.mkfs.assert_not_called()
        g.part_add.assert_not_called()
        g.part_set_mbr_id.assert_not_called()
        self.assertEqual(run.call_args_list[0].args[0][0], "virt-customize")

    def test_wrong_added_partition_is_never_formatted(self):
        image = inspected()
        g, guest, before, grown, after = self.context(image)
        g.part_list.side_effect = [[{"part_num": 1}], [{"part_num": 1}, {"part_num": 3}]]
        with patch("forge.engine._guest", guest), patch("forge.engine._run"), \
                patch("forge.uefi.inspect_layout", return_value=before):
            with self.assertRaisesRegex(EngineError, "nothing was formatted"):
                migrate(Path("working.qcow2"), image, OPTIONS, False, lambda _: None)
        g.mkfs.assert_not_called()


if __name__ == "__main__":
    unittest.main()
