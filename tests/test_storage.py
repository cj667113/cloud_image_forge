"""Rebuild planning, archive integrity, and source/failure ownership tests."""
from contextlib import contextmanager
from copy import deepcopy
import io
import hashlib
import gzip
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from forge.storage import (EFI_GUID, GIB, LINUX_GUID, LVM_GUID, LVM_PIN_ERROR, MIB, StorageError,
                           _archive_manifest, _compare_manifests, _configured_quotas, _inspect_initrd_lvm, _verify_layout,
                           inspect_storage, plan_rebuild, rebuild, verify_rebuild)


def inspected(lvm=True):
    parts = [
        {"number": 1, "device": "/dev/sda1", "start": MIB, "end": 101 * MIB - 1,
         "size": 100 * MIB, "type": EFI_GUID, "filesystem": "vfat", "uuid": "349D-B205",
         "partition_guid": UUID(int=1).bytes_le.hex(), "attributes": 0, "name": "EFI"},
        {"number": 2, "device": "/dev/sda2", "start": 101 * MIB, "end": 613 * MIB - 1,
         "size": 512 * MIB, "type": LINUX_GUID, "filesystem": "xfs", "uuid": "boot-uuid",
         "partition_guid": UUID(int=2).bytes_le.hex(), "attributes": 0, "name": "boot"},
        {"number": 3, "device": "/dev/sda3", "start": 613 * MIB, "end": 12 * GIB - 2 * MIB - 1,
         "size": 12 * GIB - 615 * MIB, "type": LVM_GUID if lvm else LINUX_GUID,
         "filesystem": "LVM2_member" if lvm else "ext4",
         "partition_guid": UUID(int=3).bytes_le.hex(), "attributes": 0, "name": "root"},
    ]
    filesystems = [
        {"device": "/dev/sda1", "filesystem": "vfat", "mountpoint": "/boot/efi", "uuid": "349D-B205",
         "label": "EFI", "size": 100 * MIB, "used": 8 * MIB, "free": 90 * MIB,
         "kind": "efi", "editable": False, "minimum_size_mib": None},
        {"device": "/dev/sda2", "filesystem": "xfs", "mountpoint": "/boot", "uuid": "boot-uuid",
         "label": "", "size": 512 * MIB, "used": 130 * MIB, "free": 280 * MIB,
         "kind": "partition", "editable": True, "minimum_size_mib": 512},
        {"device": "/dev/ocivolume/root" if lvm else "/dev/sda3", "filesystem": "xfs" if lvm else "ext4",
         "mountpoint": "/", "uuid": "root-uuid", "label": "ROOT", "size": 8192 * MIB,
         "used": 5582368768, "free": 2700 * MIB, "kind": "lv" if lvm else "partition",
         "editable": True, "minimum_size_mib": 6911},
    ]
    metadata = {"pvs": [], "vgs": [], "lvs": []}
    if lvm:
        metadata = {"pvs": [{"pv_name": "/dev/sda3", "pv_uuid": "pv-identity", "pv_fmt": "lvm2", "pv_attr": "a--", "pv_tags": ""}],
                    "vgs": [{"vg_name": "ocivolume", "vg_uuid": "vg-identity", "vg_fmt": "lvm2", "vg_extent_size": 4 * MIB,
                              "vg_attr": "wz--n-", "pv_count": 1, "lv_count": 1, "snap_count": 0, "vg_sysid": "", "vg_tags": ""}],
                    "lvs": [{"device": "/dev/ocivolume/root", "lv_name": "root", "lv_uuid": "lv-identity", "lv_attr": "-wi-a-----",
                             "seg_count": 1, "origin": "", "move_pv": "", "mirror_log": "", "modules": "", "lv_tags": ""}]}
    layout = {"partition_table": "gpt", "sector_size": 512, "disk_size": 12 * GIB,
              "partitions": parts, "disk_identity": UUID(int=4).bytes_le.hex(), "hybrid": False, "errors": []}
    return {"format": "qcow2", "virtual_size": 12 * GIB, "os": {"arch": "x86_64", "distro": "oraclelinux"},
            "boot": {"supported_firmware": ["UEFI_64"]},
            "storage": {"version": 1, "layout": layout, "filesystems": filesystems, "lvm": metadata, "errors": [], "warnings": []}}


OPTIONS = {"enabled": True, "sizes": [{"device": "/dev/ocivolume/root", "size_mib": 7680}]}


def fstab_pinned():
    image = inspected()
    original = "/dev/disk/by-id/dm-uuid-LVM-vgidentitylvidentity / xfs defaults 0 1\n"
    normalized = "UUID=root-uuid / xfs defaults 0 1\n"
    digest = hashlib.sha256(original.encode()).hexdigest()
    image["storage"]["errors"] = [LVM_PIN_ERROR]
    image["storage"]["lvm_identity_pins"] = {"version": 1, "paths": ["/etc/fstab"], "config_scan_complete": True, "fstab_sha256": digest}
    image["storage"]["initramfs"] = [{"path": "/boot/initramfs-test.img", "status": "checked"}]
    image["mount_reconciliation"] = {"ready": True, "sha256": digest, "content": normalized,
        "changes": [{"line": 1, "mountpoint": "/", "from": original.split()[0], "to": "UUID=root-uuid"}]}
    return image


class PlanTests(unittest.TestCase):
    def test_label_preview_can_remove_only_verified_fstab_lvm_pins(self):
        from forge.storage import reconcile_fstab
        image = fstab_pinned()
        original = "/dev/disk/by-id/dm-uuid-LVM-vgidentitylvidentity / xfs defaults 0 1\n"
        inventory = deepcopy(image["storage"]["filesystems"])
        root = inventory[-1]
        root["aliases"] = [original.split()[0]]
        evidence = reconcile_fstab(original, inventory, root_device=root["device"])
        evidence.update(filesystems=inventory, root_device=root["device"], mounted={"/": root["device"]})
        image["mount_reconciliation"] = evidence
        result = plan_rebuild(image, OPTIONS, 10, mount_policy="labels")
        self.assertTrue(result["ready"], result["blockers"])
        self.assertEqual(result["projected_mount_changes"][0]["to"], "LABEL=ROOT")
        image["storage"]["lvm_identity_pins"]["paths"].append("/boot/grub/grub.cfg")
        self.assertFalse(plan_rebuild(image, OPTIONS, 10, mount_policy="labels")["ready"])

    def test_only_verified_fstab_pins_can_be_projected_for_auto_preview(self):
        image = fstab_pinned()
        original = deepcopy(image)
        result = plan_rebuild(image, OPTIONS, 10, mount_policy="auto")
        self.assertTrue(result["ready"])
        self.assertEqual(result["projected_mount_changes"], image["mount_reconciliation"]["changes"])
        self.assertEqual(image, original)
        self.assertFalse(plan_rebuild(image, OPTIONS, 10, mount_policy="preserve")["ready"])

    def test_pin_projection_never_waives_boot_pins_unknown_scan_or_stale_evidence(self):
        for change in ("boot", "unknown", "hash", "unresolved", "still-pinned", "initrd", "unreadable-initrd", "old-evidence"):
            with self.subTest(change=change):
                image = fstab_pinned()
                pins, mount = image["storage"]["lvm_identity_pins"], image["mount_reconciliation"]
                if change == "boot": pins["paths"].append("/boot/grub/grub.cfg")
                if change == "unknown": pins["config_scan_complete"] = False
                if change == "hash": pins["fstab_sha256"] = "different"
                if change == "unresolved": mount["ready"] = False
                if change == "still-pinned": mount["content"] += "/dev/disk/by-id/dm-uuid-LVM-vgidentitylvidentity /data xfs defaults 0 1\n"
                if change == "initrd": image["storage"]["errors"].append("Initramfs pins internal LVM identities")
                if change == "unreadable-initrd": image["storage"]["initramfs"][0]["status"] = "unavailable"
                if change == "old-evidence": image["storage"].pop("lvm_identity_pins")
                self.assertFalse(plan_rebuild(image, OPTIONS, 10)["ready"])

    def test_disabled_and_old_inspection_fail_closed(self):
        self.assertFalse(plan_rebuild({}, None)["requested"])
        plan = plan_rebuild({}, OPTIONS)
        self.assertFalse(plan["ready"])
        self.assertIn("refresh inspection", " ".join(plan["blockers"]))

    def test_shrink_fresh_xfs_and_pv_keeps_efi_geometry_and_identifiers(self):
        image = inspected()
        original = deepcopy(image)
        plan = plan_rebuild(image, OPTIONS, 10_000_000_000 / GIB)
        self.assertTrue(plan["ready"], plan["blockers"])
        self.assertEqual(plan["layout"]["disk_size_after"], 10_000_000_000)
        self.assertEqual(plan["layout"]["lvs"][0]["size"], 7680 * MIB)
        self.assertEqual(plan["layout"]["partitions"][0], image["storage"]["layout"]["partitions"][0])
        self.assertLess(plan["layout"]["partitions"][-1]["size"], image["storage"]["layout"]["partitions"][-1]["size"])
        self.assertEqual(image, original)
        self.assertIn("internal IDs", " ".join(plan["warnings"]))

    def test_direct_ext_and_xfs_partition_layout_is_supported(self):
        image = inspected(lvm=False)
        plan = plan_rebuild(image, {"enabled": True, "sizes": [{"device": "/dev/sda3", "size_mib": 7680}]}, 10)
        self.assertTrue(plan["ready"], plan["blockers"])
        self.assertEqual(plan["layout"]["lvs"], [])

    def test_arm64_admission_retains_architecture_and_requires_matching_efi(self):
        for spelling in ("aarch64", "arm64"):
            image = inspected()
            image["os"]["arch"] = spelling
            image["boot"]["efi_loaders"] = [{"architecture": "aarch64", "path": "/EFI/BOOT/BOOTAA64.EFI"}]
            original = deepcopy(image)
            plan = plan_rebuild(image, OPTIONS, 10)
            self.assertTrue(plan["ready"], plan["blockers"])
            self.assertEqual(plan["source_architecture"], "aarch64")
            self.assertEqual(image, original)
            for loaders in ([], [{"architecture": "x86_64", "path": "/EFI/BOOT/BOOTX64.EFI"}]):
                image["boot"]["efi_loaders"] = loaders
                blocked = plan_rebuild(image, OPTIONS, 10)
                self.assertFalse(blocked["ready"])
                self.assertIn("matching AArch64 EFI", " ".join(blocked["blockers"]))
        image["boot"].update(supported_firmware=["UEFI_64", "BIOS"], efi_loaders=[{"architecture": "aarch64"}])
        self.assertFalse(plan_rebuild(image, OPTIONS, 10)["ready"])
        image["os"]["arch"] = "arm"
        self.assertFalse(plan_rebuild(image, OPTIONS, 10)["ready"])

    def test_unknown_data_boot_modes_table_and_missing_measurements_are_blockers(self):
        mutations = [
            lambda i: i["boot"].update(supported_firmware=["BIOS"]),
            lambda i: i["boot"].update(supported_firmware=["UEFI_64", "BIOS"]),
            lambda i: i["storage"]["layout"].update(partition_table="msdos"),
            lambda i: i["storage"]["layout"].update(hybrid=True),
            lambda i: i["storage"]["layout"]["partitions"][1].update(type="unknown"),
            lambda i: i["storage"]["layout"]["partitions"][1].update(attributes=2),
            lambda i: i["storage"]["filesystems"][2].update(minimum_size_mib=None),
            lambda i: i["storage"]["filesystems"][2].update(filesystem="btrfs"),
            lambda i: i["storage"]["filesystems"][2].update(uuid="boot-uuid"),
            lambda i: i["storage"]["filesystems"][2].update(label="EFI"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                image = inspected()
                mutation(image)
                self.assertFalse(plan_rebuild(image, OPTIONS, 10)["ready"])

    def test_complex_lvm_and_external_or_unaccounted_volumes_block(self):
        mutations = [
            lambda m: m["vgs"][0].update(pv_count=2),
            lambda m: m["vgs"][0].update(vg_extent_size=8 * MIB),
            lambda m: m["vgs"][0].update(vg_sysid="foreign"),
            lambda m: m["lvs"][0].update(lv_attr="Vwi-a-tz--"),
            lambda m: m["lvs"][0].update(origin="root-snapshot"),
            lambda m: m["pvs"][0].update(pv_name="/dev/sdb1"),
            lambda m: m["lvs"].append(dict(m["lvs"][0], device="/dev/ocivolume/hidden", lv_name="hidden")),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                image = inspected()
                mutation(image["storage"]["lvm"])
                self.assertFalse(plan_rebuild(image, OPTIONS, 10)["ready"])

    def test_sizes_reject_pv_efi_duplicate_unknown_and_below_minimum(self):
        invalid = [
            [{"device": "/dev/sda1", "size_mib": 100}],
            [{"device": "/dev/sda3", "size_mib": 9000}],
            OPTIONS["sizes"] * 2,
            [{"device": "/dev/ocivolume/root", "size_mib": 1000}],
            [{"device": "/dev/ocivolume/root", "size_mib": True}],
            [{"device": "/dev/ocivolume/missing", "size_mib": 9000}],
        ]
        for sizes in invalid:
            with self.subTest(sizes=sizes):
                self.assertFalse(plan_rebuild(inspected(), {"enabled": True, "sizes": sizes}, 10)["ready"])

    def test_capacity_bound_and_lv_extent_rounding(self):
        for size in (True, float("nan"), float("inf"), -1, 100000, 7):
            self.assertFalse(plan_rebuild(inspected(), OPTIONS, size)["ready"])
        plan = plan_rebuild(inspected(), {"enabled": True, "sizes": [{"device": "/dev/ocivolume/root", "size_mib": 7681}]}, 10)
        self.assertTrue(plan["ready"])
        self.assertEqual(plan["layout"]["lvs"][0]["size"], 7684 * MIB)


def make_archive(path, contents=b"boot and configuration content\n", mode=0o640, hardlink_first="file", uid=123):
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        root = tarfile.TarInfo(".")
        root.type, root.mode, root.mtime = tarfile.DIRTYPE, 0o755, 1000000000
        archive.addfile(root)
        entry = tarfile.TarInfo("./" + hardlink_first)
        entry.size, entry.uid, entry.gid, entry.mode, entry.mtime = len(contents), uid, 456, mode, 1000000000
        entry.pax_headers = {"SCHILY.xattr.user.test": "preserved", "SCHILY.acl.access": "user::rw-,group::r--,other::---",
                             "RHT.security.selinux": "system_u:object_r:etc_t:s0"}
        archive.addfile(entry, io.BytesIO(contents))
        link = tarfile.TarInfo("./" + ("file" if hardlink_first == "link" else "link"))
        link.type, link.linkname = tarfile.LNKTYPE, "./" + hardlink_first
        archive.addfile(link)
        symlink = tarfile.TarInfo("./symlink")
        symlink.type, symlink.linkname = tarfile.SYMTYPE, "/etc/target"
        archive.addfile(symlink)


class ArchiveTests(unittest.TestCase):
    def test_manifest_preserves_contents_metadata_links_and_hardlink_equivalence(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder) / "a.tar.gz", Path(folder) / "b.tar.gz"
            make_archive(a)
            make_archive(b, hardlink_first="link")
            first, second = _archive_manifest(a), _archive_manifest(b)
            _compare_manifests(first, second, "/dev/test")
            for change in ({"contents": b"corrupt"}, {"mode": 0o777}, {"uid": 1}):
                make_archive(b, **change)
                with self.assertRaises(StorageError):
                    _compare_manifests(first, _archive_manifest(b), "/dev/test")

    def test_unsafe_archive_paths_and_dangling_hardlinks_are_never_extracted(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "bad.tar.gz"
            for name in ("../outside", "/absolute", "normal"):
                with tarfile.open(archive, "w:gz") as tar:
                    item = tarfile.TarInfo(name)
                    item.type, item.linkname = tarfile.LNKTYPE, "missing"
                    tar.addfile(item)
                with self.assertRaises(StorageError):
                    _archive_manifest(archive)


class FinalVerificationTests(unittest.TestCase):
    def final(self, arch="x86_64"):
        original = inspected()
        original["os"]["arch"] = arch
        if arch in {"aarch64", "arm64"}:
            original["boot"]["efi_loaders"] = [{"architecture": "aarch64"}]
        plan = plan_rebuild(original, OPTIONS, 10_000_000_000 / GIB)
        final = deepcopy(original)
        final["virtual_size"] = plan["layout"]["disk_size_after"]
        final["storage"]["layout"].update(disk_size=final["virtual_size"], partitions=deepcopy(plan["layout"]["partitions"]))
        final["storage"]["filesystems"] = deepcopy(plan["filesystems"])
        for fs in final["storage"]["filesystems"]:
            fs["size"] = fs["selected_size_mib"] * MIB
        for lv in final["storage"]["lvm"]["lvs"]:
            lv["lv_size"] = next(item["size"] for item in plan["layout"]["lvs"] if item["device"] == lv["device"])
        return final, plan

    def test_final_arm_architecture_and_loader_cannot_change(self):
        final, plan = self.final("arm64")
        final["os"]["arch"] = "aarch64"
        self.assertTrue(verify_rebuild(final, plan)["verified"])
        for mutation in (
            lambda i: i["os"].update(arch="x86_64"),
            lambda i: i["os"].update(arch="unknown"),
            lambda i: i["boot"].update(efi_loaders=[{"architecture": "x86_64"}]),
            lambda i: i["boot"].update(architecture="x86_64"),
            lambda i: i["boot"].update(efi_loaders=[]),
            lambda i: i["boot"].update(supported_firmware=["UEFI_64", "BIOS"]),
        ):
            altered = deepcopy(final)
            mutation(altered)
            self.assertFalse(verify_rebuild(altered, plan)["verified"])

    def test_valid_final_structure_and_explicit_provider_alignment(self):
        final, plan = self.final()
        self.assertTrue(verify_rebuild(final, plan)["verified"])
        final["virtual_size"] = final["storage"]["layout"]["disk_size"] = 10 * GIB
        self.assertFalse(verify_rebuild(final, plan)["ready"], "Unrequested capacity changes must fail")
        result = verify_rebuild(final, plan, expected_disk_size=10 * GIB)
        self.assertTrue(result["ready"], result["blockers"])
        self.assertEqual(result["actual_disk_size"], 10 * GIB)
        self.assertFalse(verify_rebuild(final, plan, expected_disk_size=11 * GIB)["ready"])

    def test_final_changes_to_geometry_uuid_mount_lv_and_boot_are_blocked(self):
        mutations = [
            lambda i: i["storage"]["layout"].update(disk_identity="changed"),
            lambda i: i["storage"]["layout"]["partitions"][1].update(start=102 * MIB),
            lambda i: i["storage"]["layout"]["partitions"][1].update(partition_guid="changed"),
            lambda i: i["storage"]["layout"]["partitions"][1].update(end=12 * GIB),
            lambda i: i["storage"]["filesystems"][1].update(uuid="changed"),
            lambda i: i["storage"]["filesystems"][1].update(filesystem="ext4"),
            lambda i: i["storage"]["filesystems"][1].update(mountpoint="/different"),
            lambda i: i["storage"]["filesystems"][2].update(size=8000 * MIB),
            lambda i: i["storage"]["lvm"]["lvs"][0].update(device="/dev/ocivolume/renamed"),
            lambda i: i["storage"]["lvm"]["lvs"][0].update(lv_size=8192 * MIB),
            lambda i: i["boot"].update(supported_firmware=[]),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                final, plan = self.final()
                mutation(final)
                self.assertFalse(verify_rebuild(final, plan)["verified"])


class InspectionTests(unittest.TestCase):
    def test_quota_aliases_and_rootflags_in_boot_sources_are_detected(self):
        cases = [("/etc/fstab", f"UUID=root / xfs defaults,{option} 0 0") for option in ("quota", "qnoenforce", "usrjquota=aquota.user")]
        cases += [("/etc/default/grub", 'GRUB_CMDLINE_LINUX="root=UUID=root rootflags=quota"'),
                  ("/etc/kernel/cmdline", "root=UUID=root rootflags=noatime,qnoenforce"),
                  ("/boot/loader/entries/kernel.conf", "options root=UUID=root rootflags=pquota"),
                  ("/boot/grub2/grubenv", "kernelopts=root=UUID=root rootflags=uqnoenforce"),
                  ("/boot/grub2/grub.cfg", "linuxefi /vmlinuz root=UUID=root rootflags=grpquota")]
        for path, text in cases:
            with self.subTest(path=path, text=text):
                g = Mock()
                g.is_file.side_effect = lambda name: name == path
                g.filesize.return_value = len(text)
                g.read_file.return_value = text.encode()
                g.glob_expand.return_value = [path] if "entries" in path else []
                self.assertTrue(_configured_quotas(g))
        for text in ('# GRUB_CMDLINE_LINUX="rootflags=quota"',
                     'GRUB_CMDLINE_LINUX="rootflags=noquota,noatime"',
                     'GRUB_DISTRIBUTOR="quota rootflags=quota"'):
            g = Mock()
            g.is_file.side_effect = lambda name: name == "/etc/default/grub"
            g.filesize.return_value = len(text)
            g.read_file.return_value = text.encode()
            g.glob_expand.return_value = []
            self.assertFalse(_configured_quotas(g))

    def guest(self, image):
        g = Mock()
        fs = image["storage"]["filesystems"]
        metadata = image["storage"]["lvm"]
        g.list_devices.return_value = ["/dev/sda"]
        g.part_get_name.side_effect = lambda disk, number: image["storage"]["layout"]["partitions"][number - 1]["name"]
        g.pvs_full.return_value, g.vgs_full.return_value, g.lvs_full.return_value = (deepcopy(metadata[key]) for key in ("pvs", "vgs", "lvs"))
        g.vfs_label.side_effect = lambda device: next(item["label"] for item in fs if item["device"] == device)
        g.xfs_info.return_value = {"xfs_logname": "internal", "xfs_rtblocks": 0}
        g.tune2fs_l.return_value = {"Filesystem features": "has_journal extents"}
        g.is_file.return_value = False
        g.glob_expand.side_effect = lambda pattern: ["/boot/vmlinuz-6.12.0-uek"] if pattern == "/boot/vmlinuz-*" else []
        return g

    def test_optional_probe_failure_is_evidence_and_pv_is_not_mistaken_for_a_filesystem(self):
        image = inspected()
        g = self.guest(image)
        parts = deepcopy(image["storage"]["filesystems"])
        for part in parts:
            part["logical_volume"] = part["kind"] == "lv"
        parts.append({"device": "/dev/sda3", "filesystem": "unknown"})
        result = inspect_storage(g, "/dev/ocivolume/root", parts, image["storage"]["layout"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["filesystems"]), 3)
        g.xfs_info.side_effect = RuntimeError("probe unavailable")
        self.assertIn("probe unavailable", " ".join(inspect_storage(g, "root", parts, image["storage"]["layout"])["errors"]))

    def test_devices_file_and_uuid_pinned_boot_configuration_block(self):
        image = inspected()
        for path, text in (("/etc/lvm/devices/system.devices", "IDTYPE=devname PVID=pvid\n"),
                           ("/etc/default/grub", 'GRUB_CMDLINE_LINUX="root=/dev/disk/by-id/dm-uuid-LVM-lvidentity"'),
                           ("/etc/kernel/cmdline", "root=/dev/disk/by-id/dm-uuid-LVM-lvidentity"),
                           ("/boot/efi/EFI/redhat/grub.cfg", "set root=lvmid/vgidentity/lvidentity")):
            with self.subTest(path=path):
                g = self.guest(image)
                g.is_file.side_effect = lambda target: target == path
                g.filesize.return_value = len(text)
                g.read_file.return_value = text.encode()
                g.glob_expand.side_effect = lambda pattern: ["/boot/vmlinuz-6.12"] if pattern == "/boot/vmlinuz-*" else [path] if (pattern == "/etc/lvm/devices/*" and "devices" in path or pattern == "/boot/efi/EFI/*/grub.cfg" and "EFI" in path) else []
                parts = deepcopy(image["storage"]["filesystems"])
                for part in parts:
                    part["logical_volume"] = part["kind"] == "lv"
                result = inspect_storage(g, "root", parts, image["storage"]["layout"])
                self.assertTrue(result["errors"])

    def test_pin_evidence_identifies_exact_paths_and_original_fstab_hash(self):
        image = inspected()
        g = self.guest(image)
        text = "/dev/disk/by-id/dm-uuid-LVM-vgidentitylvidentity / xfs defaults 0 1\n"
        g.is_file.side_effect = lambda path: path == "/etc/fstab"
        g.is_dir.return_value = True
        g.filesize.return_value = len(text)
        g.read_file.return_value = text.encode()
        parts = deepcopy(image["storage"]["filesystems"])
        for part in parts:
            part["logical_volume"] = part["kind"] == "lv"
        result = inspect_storage(g, "/dev/ocivolume/root", parts, image["storage"]["layout"])
        self.assertEqual(result["lvm_identity_pins"], {"version": 1, "paths": ["/etc/fstab"],
                         "config_scan_complete": True, "fstab_sha256": hashlib.sha256(text.encode()).hexdigest()})
        self.assertIn(LVM_PIN_ERROR, result["errors"])

    def test_embedded_lvm_pins_block_but_unreadable_initrd_is_explicit_warning(self):
        g = Mock()
        g.glob_expand.side_effect = lambda pattern: ["/boot/initramfs-6.12.img"] if pattern == "/boot/initramfs-*.img" else []
        for name, contents in (("etc/lvm/devices/system.devices", b"PVID=old-id"),
                               ("etc/cmdline.d/01-root.conf", b"root=/dev/disk/by-id/dm-uuid-LVM-old-id"),
                               ("etc/lvm/lvm.conf", b"devices { use_devicesfile=1 }")):
            with self.subTest(name=name):
                g.initrd_list.return_value = ["init", name]
                g.initrd_cat.return_value = contents
                errors, warnings = [], []
                _inspect_initrd_lvm(g, ["oldid"], errors, warnings)
                self.assertTrue(errors)
        g.initrd_list.side_effect = RuntimeError("unsupported concatenation")
        errors, warnings = [], []
        _inspect_initrd_lvm(g, ["oldid"], errors, warnings)
        self.assertEqual(errors, [])
        self.assertIn("UEFI boot test", " ".join(warnings))
        g.initrd_list.side_effect = None
        g.initrd_list.return_value = ["early_cpio", "kernel/x86/microcode/GenuineIntel.bin"]
        errors, warnings = [], []
        _inspect_initrd_lvm(g, ["oldid"], errors, warnings)
        self.assertTrue(warnings)
        image = inspected()
        image["storage"]["warnings"] = warnings
        self.assertTrue(plan_rebuild(image, OPTIONS, 10)["warnings"])

    def test_lvm_requires_inspectable_efi_and_scans_its_actual_mountpoint(self):
        image = inspected()
        for mount in (None, "/efi", "/boot/efi"):
            with self.subTest(mount=mount):
                g = self.guest(image)
                parts = deepcopy(image["storage"]["filesystems"])
                parts[0]["mountpoint"] = mount
                for part in parts:
                    part["logical_volume"] = part["kind"] == "lv"
                if mount:
                    path = mount + "/EFI/redhat/grub.cfg"
                    content = "set root=lvmid/vgidentity/lvidentity\n"
                    g.is_file.side_effect = lambda target: target == path
                    g.filesize.return_value = len(content)
                    g.read_file.return_value = content.encode()
                    g.is_dir.return_value = True
                    g.glob_expand.side_effect = lambda pattern: [path] if pattern == mount + "/EFI/*/grub.cfg" else ["/boot/vmlinuz-6.12"] if pattern == "/boot/vmlinuz-*" else []
                result = inspect_storage(g, "root", parts, image["storage"]["layout"])
                self.assertTrue(result["errors"])
                self.assertIn("pins internal LVM UUIDs" if mount else "EFI partition to be mounted", " ".join(result["errors"]))
        g = self.guest(image)
        g.is_dir.return_value = False
        result = inspect_storage(g, "root", image["storage"]["filesystems"], image["storage"]["layout"])
        self.assertIn("unreadable", " ".join(result["errors"]))


class ExecutorTests(unittest.TestCase):
    def test_executor_requires_actual_pin_removal_even_when_preview_can_project_it(self):
        image = fstab_pinned()
        self.assertTrue(plan_rebuild(image, OPTIONS, 10)["ready"])
        with tempfile.TemporaryDirectory() as folder, patch("forge.engine.ImageEngine.inspect", return_value=image), patch("forge.engine._guest") as guest:
            source, output = Path(folder) / "source", Path(folder) / "output"
            source.write_bytes(b"source")
            with self.assertRaisesRegex(StorageError, "pins internal"):
                rebuild(source, output, image, {"storage_rebuild": OPTIONS, "disk_size_gib": 10}, lambda _: None)
            guest.assert_not_called()
            self.assertFalse(output.exists())
            self.assertEqual(source.read_bytes(), b"source")

    def run_rebuild(self, root, corrupt=False, fail_restore=False, arch="x86_64", linux_data_pv=False):
        root = root.resolve()
        image = inspected()
        image["os"]["arch"] = arch
        if linux_data_pv:
            image["storage"]["layout"]["partitions"][-1]["type"] = LINUX_GUID
        if arch == "aarch64":
            image["boot"]["efi_loaders"] = [{"architecture": arch}]
        # Keep the raw-copy fixture small while exercising the same exact-length
        # copy and checksum path; no real filesystem tool is invoked by mocks.
        image["storage"]["filesystems"][0]["size"] = 512
        source, destination = root / "source.qcow2", root / "new.qcow2"
        source.write_bytes(b"immutable source")
        source_archive = root / "source.tar.gz"
        make_archive(source_archive)
        accesses, guests = [], []
        plan = plan_rebuild(image, OPTIONS, 10)

        @contextmanager
        def appliance(path, fmt, readonly=True):
            accesses.append((Path(path), readonly))
            g = Mock()
            guests.append(g)
            fs = {item["device"]: item for item in image["storage"]["filesystems"]}
            g.vfs_type.side_effect = lambda device: fs[device]["filesystem"]
            g.vfs_uuid.side_effect = lambda device: fs[device]["uuid"]
            g.vfs_label.side_effect = lambda device: fs[device]["label"]
            def set_label(device, value):
                if not value:
                    raise RuntimeError("xfs_admin: Usage: empty labels are unsupported")
            g.set_label.side_effect = set_label
            g.download_offset.side_effect = lambda dev, output, offset, size: Path(output).write_bytes(b"E" * size)
            def tar_out(directory, output, **options):
                self.assertTrue(all(options[key] for key in ("numericowner", "xattrs", "selinux", "acls")))
                self.assertNotIn("compress", options)
                selected = source_archive
                if corrupt and Path(path) == destination and readonly:
                    selected = root / "corrupt.tar.gz"
                    make_archive(selected, contents=b"bad restore")
                with gzip.open(selected, "rb") as payload:
                    Path(output).write_bytes(payload.read())
            g.tar_out.side_effect = tar_out
            if fail_restore:
                g.tar_in.side_effect = RuntimeError("restore failed")
            g.is_dir.return_value = False
            g.statvfs.return_value = {"bavail": 100000, "frsize": 4096}
            g.part_get_name.side_effect = lambda disk, number: plan["layout"]["partitions"][number - 1]["name"]
            g.blockdev_getsize64.return_value = 7680 * MIB
            yield g

        actual_layout = {"errors": [], "partition_table": "gpt", "disk_size": 10 * GIB,
                         "disk_identity": plan["layout"]["disk_identity"], "partitions": plan["layout"]["partitions"]}
        with patch("forge.engine.ImageEngine.inspect", return_value=image), patch("forge.engine._guest", side_effect=appliance), \
             patch("forge.engine._run", return_value=""), patch("forge.uefi.inspect_layout", return_value=actual_layout), \
             patch("forge.boot.detect_boot", return_value=image["boot"]) as detect_boot, \
             patch("forge.storage._raw_gpt_names", return_value={part["number"]: part["name"] for part in plan["layout"]["partitions"]}), \
             patch("forge.engine._roots", return_value="/dev/ocivolume/root"), \
             patch("forge.engine._mount", return_value={item["mountpoint"]: item["device"] for item in image["storage"]["filesystems"]}), \
             patch("forge.storage.shutil.disk_usage", return_value=Mock(free=100 * GIB)):
            if corrupt or fail_restore:
                with self.assertRaises((StorageError, RuntimeError)):
                    rebuild(source, destination, image, {"storage_rebuild": OPTIONS, "disk_size_gib": 10}, lambda _: None)
                self.assertFalse(destination.exists())
            else:
                self.assertEqual(rebuild(source, destination, image, {"storage_rebuild": OPTIONS, "disk_size_gib": 10}, lambda _: None), destination)
                self.assertTrue(destination.is_file())
                detect_boot.assert_called_once_with(guests[-1], architecture=arch)
                for guest in guests:
                    guest.command.assert_not_called()
                    guest.sh.assert_not_called()
        self.assertEqual(source.read_bytes(), b"immutable source")
        self.assertTrue(all(readonly for path, readonly in accesses if path == source))
        self.assertEqual(list(root.glob("storage-rebuild-*")), [])
        if not fail_restore:
            layout_guest, write_guest = guests[0], guests[2]
            self.assertEqual(accesses[0], (destination, False), "Layout is verified before archiving the source")
            self.assertEqual(layout_guest.lvcreate.call_args.args, ("root", "ocivolume", 7680))
            layout_guest.pvcreate.assert_called_once_with("/dev/sda3")
            if linux_data_pv:
                self.assertIn(("/dev/sda", 3, LINUX_GUID), [call.args for call in layout_guest.part_set_gpt_type.call_args_list])
            self.assertNotIn("/dev/sda1", [call.args[1] for call in write_guest.mkfs.call_args_list])
            self.assertNotIn("/dev/sda2", [call.args[0] for call in write_guest.set_label.call_args_list],
                             "Fresh XFS with an empty source label must retain its default blank label")
            write_guest.set_label.assert_called_once_with("/dev/ocivolume/root", "ROOT")
            for call in write_guest.tar_in.call_args_list:
                self.assertTrue(all(call.kwargs[key] for key in ("xattrs", "selinux", "acls")))
                self.assertNotIn("compress", call.kwargs)

    def test_success_verifies_copy_keeps_source_and_never_formats_efi(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_rebuild(Path(folder))

    def test_rebuild_creates_proved_pv_under_preserved_linux_data_gpt_type(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_rebuild(Path(folder), linux_data_pv=True)

    def test_arm_rebuild_uses_matching_boot_detection_without_guest_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_rebuild(Path(folder), arch="aarch64")

    def test_corrupt_restore_and_command_failure_remove_only_owned_destination(self):
        for failure in ({"corrupt": True}, {"fail_restore": True}):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                self.run_rebuild(Path(folder), **failure)

    def test_existing_destination_symlink_and_resize_conflicts_fail_before_any_appliance(self):
        with tempfile.TemporaryDirectory() as folder, patch("forge.engine.ImageEngine.inspect") as inspect:
            source, output = Path(folder) / "source", Path(folder) / "output"
            source.write_bytes(b"source")
            output.write_bytes(b"existing")
            with self.assertRaises(StorageError):
                rebuild(source, output, inspected(), {"storage_rebuild": OPTIONS}, lambda _: None)
            self.assertEqual(output.read_bytes(), b"existing")
            output.unlink()
            output.symlink_to(source)
            with self.assertRaises(StorageError):
                rebuild(source, output, inspected(), {"storage_rebuild": OPTIONS}, lambda _: None)
            output.unlink()
            with self.assertRaises(StorageError):
                rebuild(source, output, inspected(), {"storage_rebuild": OPTIONS, "expand_lv": "/dev/ocivolume/root"}, lambda _: None)
            inspect.assert_not_called()

    def test_geometry_verification_rejects_changed_partition_uuid_and_boundaries(self):
        plan = plan_rebuild(inspected(), OPTIONS, 10)
        for field in ("partition_guid", "start", "end", "size"):
            actual = {"errors": [], "partition_table": "gpt", "disk_size": 10 * GIB,
                      "disk_identity": plan["layout"]["disk_identity"], "partitions": deepcopy(plan["layout"]["partitions"])}
            actual["partitions"][0][field] = "changed"
            with patch("forge.uefi.inspect_layout", return_value=actual), patch("forge.storage._raw_gpt_names", return_value={part["number"]: part["name"] for part in plan["layout"]["partitions"]}), self.assertRaises(StorageError):
                _verify_layout(Mock(), plan)


if __name__ == "__main__":
    unittest.main()
