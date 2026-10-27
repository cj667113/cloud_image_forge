"""Synthetic disk structures exercise firmware evidence without guest tools."""
import struct
import unittest

from forge.boot import BIOS_GUID, EFI_GUID, detect_boot


def pe_application(machine=0x8664, subsystem=10, uki=False):
    count = 3 if uki else 1
    data = bytearray(1024 + count * 512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HH", data, 132, machine, count)
    struct.pack_into("<HH", data, 148, 240, 2)
    optional = 152
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 4096)
    struct.pack_into("<II", data, optional + 56, (count + 1) * 4096, 1024)
    struct.pack_into("<H", data, optional + 68, subsystem)
    struct.pack_into("<I", data, optional + 108, 16)
    for number, name in enumerate((b".text", b".linux", b".osrel")[:count]):
        section = optional + 240 + number * 40
        data[section:section + len(name)] = name
        struct.pack_into("<IIII", data, section + 8, 512, (number + 1) * 4096, 512, 1024 + number * 512)
        struct.pack_into("<I", data, section + 36, 0x60000020 if number == 0 else 0x40000040)
        data[1024 + number * 512:1028 + number * 512] = b"code"
    return bytes(data)


class DiskGuest:
    def __init__(self, table="gpt"):
        self.table = table
        self.parts = []
        self.types = {}
        self.files = {}
        self.fs = {}
        self.disk = bytearray(8 * 1024 * 1024)
        self.mounted = None
        self.mount_log = []
        self.bad_mount = set()
        self.bad_read = set()
        self.bad_type = set()
        self.bad_device_read = set()

    def add_partition(self, number, kind, start=2048, sectors=2048, files=None, fs="ext4"):
        self.parts.append({"part_num": number, "part_start": start * 512,
                           "part_end": (start + sectors) * 512 - 1, "part_size": sectors * 512})
        self.types[number] = kind
        device = f"/dev/sda{number}"
        self.files[device] = files or {}
        self.fs[device] = fs
        return device

    def install_grub(self, core_sector=1, payload_sector=2):
        self.disk[:3] = b"\xeb\x63\x90"
        self.disk[300:319] = b"GRUB Geom Read Error"
        struct.pack_into("<Q", self.disk, 0x5C, core_sector)
        self.disk[510:512] = b"\x55\xaa"
        start = core_sector * 512
        self.disk[start:start + 25] = b"loading\0Geom\0Read\0 Error\0!"
        struct.pack_into("<QHH", self.disk, start + 500, payload_sector, 2, 0x820)
        self.disk[payload_sector * 512:(payload_sector + 2) * 512] = bytes(range(256)) * 4

    def mountpoints(self):
        return {self.mounted: "/"} if self.mounted else {}

    def part_get_parttype(self, disk):
        return self.table

    def part_list(self, disk):
        return self.parts

    def part_get_gpt_type(self, disk, number):
        if number in self.bad_type:
            raise RuntimeError("partition type unreadable")
        return self.types[number]

    part_get_mbr_id = part_get_gpt_type

    def vfs_type(self, device):
        return self.fs[device]

    def mount_ro(self, device, path):
        if self.mounted:
            raise AssertionError("A previous partition remains mounted")
        self.mount_log.append((device, path, "ro"))
        if device in self.bad_mount:
            raise RuntimeError("unreadable filesystem")
        self.mounted = device

    def umount_all(self):
        self.mounted = None

    def ls(self, directory):
        prefix = directory.rstrip("/") + "/"
        return sorted({path[len(prefix):].split("/", 1)[0] for path in self.files[self.mounted] if path.startswith(prefix)})

    def is_symlink(self, path):
        return False

    def is_file(self, path):
        return path in self.files[self.mounted]

    def is_dir(self, path):
        return any(name.startswith(path.rstrip("/") + "/") for name in self.files[self.mounted])

    def filesize(self, path):
        return len(self.files[self.mounted][path])

    def pread(self, path, count, offset):
        if (self.mounted, path) in self.bad_read:
            raise RuntimeError("EFI file read failed")
        return self.files[self.mounted][path][offset:offset + count]

    def pread_device(self, device, count, offset):
        if offset in self.bad_device_read:
            raise RuntimeError("disk read failed")
        return bytes(self.disk[offset:offset + count])

    def blockdev_getss(self, disk):
        return 512


class BootTests(unittest.TestCase):
    def esp(self, guest, number=1, **kwargs):
        return guest.add_partition(number, EFI_GUID if guest.table == "gpt" else 0xEF,
                                   files={"/EFI/BOOT/BOOTX64.EFI": pe_application(**kwargs)}, fs="vfat")

    def test_uefi_esp_does_not_need_fstab_or_guest_mountpoint(self):
        guest = DiskGuest()
        device = self.esp(guest)
        before = bytes(guest.disk)
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "uefi")
        self.assertEqual(result["recommended_firmware"], "UEFI_64")
        self.assertEqual(result["supported_firmware"], ["UEFI_64"])
        self.assertTrue(result["efi_loaders"][0]["fallback"])
        self.assertEqual(guest.mount_log, [(device, "/", "ro")])
        self.assertIsNone(guest.mounted)
        self.assertEqual(bytes(guest.disk), before)
        self.assertFalse(result["boot_tested"])

    def test_valid_uefi_boot_also_works_on_mbr_partition_table(self):
        guest = DiskGuest("msdos")
        self.esp(guest)
        self.assertEqual(detect_boot(guest)["mode"], "uefi")

    def test_bios_mbr_requires_grub_core_and_payload(self):
        guest = DiskGuest("msdos")
        guest.add_partition(1, 0x83)
        guest.install_grub()
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "bios")
        self.assertEqual(result["recommended_firmware"], "BIOS")
        self.assertIn("MBR embedding gap", " ".join(result["bios_evidence"]))
        guest.disk[1024:2048] = bytes(1024)
        self.assertEqual(detect_boot(guest)["mode"], "unknown")

    def test_bios_gpt_requires_installed_payload_in_bios_partition(self):
        guest = DiskGuest()
        guest.add_partition(1, BIOS_GUID)
        guest.install_grub(2048, 2049)
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "bios")
        self.assertIn("GPT BIOS Boot Partition", " ".join(result["bios_evidence"]))
        struct.pack_into("<Q", guest.disk, 0x5C, 1)
        self.assertEqual(detect_boot(guest)["mode"], "unknown")

    def test_dual_support_requires_both_actual_boot_chains(self):
        guest = DiskGuest()
        self.esp(guest)
        guest.add_partition(2, BIOS_GUID, start=4096)
        guest.install_grub(4096, 4097)
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "dual")
        self.assertEqual(result["supported_firmware"], ["UEFI_64", "BIOS"])
        self.assertIsNone(result["recommended_firmware"])

    def test_empty_partition_and_partition_styles_do_not_imply_firmware(self):
        for table, kind in (("gpt", EFI_GUID), ("gpt", BIOS_GUID), ("msdos", 0x83)):
            with self.subTest(table=table, kind=kind):
                guest = DiskGuest(table)
                guest.add_partition(1, kind)
                guest.disk[510:512] = b"\x55\xaa"
                self.assertEqual(detect_boot(guest)["mode"], "unknown")
        self.assertEqual(detect_boot(DiskGuest())["mode"], "unknown")

    def test_grub_string_and_boot_signature_without_core_are_not_bios(self):
        guest = DiskGuest("msdos")
        guest.add_partition(1, 0x83)
        guest.install_grub()
        guest.disk[512:1024] = bytes(512)
        self.assertEqual(detect_boot(guest)["mode"], "unknown")

    def test_grub_all_blocklist_entries_must_be_valid(self):
        guest = DiskGuest("msdos")
        guest.add_partition(1, 0x83)
        guest.install_grub()
        struct.pack_into("<QHH", guest.disk, 512 + 488, 5000, 1, 0x860)
        self.assertEqual(detect_boot(guest)["mode"], "unknown")
        struct.pack_into("<QHH", guest.disk, 512 + 488, 4, 1, 0x860)
        guest.disk[2048:2560] = b"x" * 512
        self.assertEqual(detect_boot(guest)["mode"], "bios")
        # A later block must not overlap a previous payload extent.
        struct.pack_into("<QHH", guest.disk, 512 + 488, 3, 1, 0x860)
        self.assertEqual(detect_boot(guest)["mode"], "unknown")

    def test_efi_partition_type_with_nonfat_filesystem_is_not_uefi(self):
        guest = DiskGuest()
        guest.add_partition(1, EFI_GUID, files={"/EFI/BOOT/BOOTX64.EFI": pe_application()}, fs="ext4")
        self.assertEqual(detect_boot(guest)["mode"], "unknown")
        self.assertEqual(guest.mount_log, [])

    def test_efi_drivers_and_other_architectures_are_not_uefi64_support(self):
        for options in ({"subsystem": 11}, {"subsystem": 12}, {"machine": 0xAA64}):
            with self.subTest(options=options):
                guest = DiskGuest()
                self.esp(guest, **options)
                result = detect_boot(guest)
                self.assertEqual(result["mode"], "unknown")
                if options.get("machine"):
                    self.assertEqual(result["efi_loaders"][0]["architecture"], "aarch64")

    def test_auxiliary_efi_apps_are_not_bootloader_evidence(self):
        guest = DiskGuest()
        guest.add_partition(1, EFI_GUID, fs="vfat", files={name: pe_application() for name in
                            ("/EFI/tools/Shell.efi", "/EFI/tools/memtest.efi", "/EFI/ubuntu/mmx64.efi", "/EFI/ubuntu/fwupdx64.efi")})
        self.assertEqual(detect_boot(guest)["mode"], "unknown")

    def test_uki_recognized_by_linux_and_osrel_sections(self):
        guest = DiskGuest()
        guest.add_partition(1, EFI_GUID, fs="vfat", files={"/EFI/Linux/my-linux-6.12.efi": pe_application(uki=True)})
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "uefi")
        self.assertTrue(any("NVRAM" in warning for warning in result["warnings"]))

    def test_malformed_pe_headers_sections_and_short_reads_are_rejected(self):
        valid = pe_application()
        variants = [valid[:64], valid[:1200]]
        for offset, fmt, value in ((60, "<I", 0xFFFFFFFF), (148, "<H", 0),
                                   (152 + 108, "<I", 0xFFFFFFFF), (152 + 16, "<I", 0x80000000),
                                   (152 + 240 + 20, "<I", 0xFFFFFFFE)):
            invalid = bytearray(valid)
            struct.pack_into(fmt, invalid, offset, value)
            variants.append(bytes(invalid))
        for invalid in variants:
            with self.subTest(size=len(invalid)):
                guest = DiskGuest()
                guest.add_partition(1, EFI_GUID, fs="vfat", files={"/EFI/BOOT/BOOTX64.EFI": invalid})
                self.assertEqual(detect_boot(guest)["mode"], "unknown")

    def test_unreadable_esp_does_not_mask_independent_bios_evidence(self):
        guest = DiskGuest()
        esp = self.esp(guest)
        guest.bad_mount.add(esp)
        guest.add_partition(2, BIOS_GUID, start=4096)
        guest.install_grub(4096, 4097)
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "bios")
        self.assertTrue(any("unreadable filesystem" in warning for warning in result["warnings"]))

    def test_one_bad_efi_file_does_not_hide_another_esp(self):
        guest = DiskGuest()
        first = self.esp(guest)
        second = guest.add_partition(2, EFI_GUID, start=4096, fs="vfat", files={"/efi/boot/bootx64.efi": pe_application()})
        guest.bad_read.add((first, "/EFI/BOOT/BOOTX64.EFI"))
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "uefi")
        self.assertEqual(result["efi_loaders"][0]["device"], second)
        self.assertIsNone(guest.mounted)

    def test_bios_read_failure_does_not_mask_uefi(self):
        guest = DiskGuest()
        self.esp(guest)
        guest.bad_device_read.add(0)
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "uefi")
        self.assertTrue(any("disk read failed" in warning for warning in result["warnings"]))

    def test_unmarked_fat_loader_is_reported_without_advertising_support(self):
        guest = DiskGuest("msdos")
        guest.add_partition(1, 0x0B, fs="vfat", files={"/EFI/BOOT/BOOTX64.EFI": pe_application()})
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "unknown")
        self.assertEqual(len(result["efi_loaders"]), 1)
        self.assertTrue(any("partition type" in warning for warning in result["warnings"]))

    def test_existing_mounts_are_never_changed(self):
        guest = DiskGuest()
        guest.mounted = "/dev/sda9"
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "unknown")
        self.assertEqual(guest.mounted, "/dev/sda9")
        self.assertEqual(guest.mount_log, [])

    def test_syslinux_candidates_are_not_supported_without_stage2_verification(self):
        guest = DiskGuest("msdos")
        device = guest.add_partition(1, 0x83, files={"/boot/syslinux/ldlinux.sys": b"loader" * 100,
                                                  "/boot/syslinux/syslinux.cfg": b"DEFAULT linux\n"})
        guest.disk[300:324] = b"Missing operating system"
        guest.disk[446] = 0x80
        guest.disk[510:512] = b"\x55\xaa"
        vbr = 2048 * 512
        guest.disk[vbr + 3:vbr + 11] = b"SYSLINUX"
        guest.disk[vbr + 510:vbr + 512] = b"\x55\xaa"
        result = detect_boot(guest)
        self.assertEqual(result["mode"], "unknown")
        self.assertTrue(any("SYSLINUX" in warning for warning in result["warnings"]))
        del guest.files[device]["/boot/syslinux/ldlinux.sys"]
        self.assertEqual(detect_boot(guest)["mode"], "unknown")


if __name__ == "__main__":
    unittest.main()
