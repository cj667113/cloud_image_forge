"""Mount references follow proven filesystem identity, never disk position."""
from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path

import pytest

from forge.storage import (StorageError, inspect_mount_references, reconcile_fstab,
                           reconcile_mounts, verify_mounts, verify_mount_boot_references,
                           plan_mounts)


def filesystems():
    return [
        {"device": "/dev/vg/root", "filesystem": "ext4", "uuid": "root-current", "label": "ROOT",
         "aliases": ["/dev/mapper/vg-root"], "lv_uuid": "stable-root-lv", "mountpoint": "/"},
        {"device": "/dev/sda2", "filesystem": "ext4", "uuid": "boot-current", "label": "BOOT",
         "partition_guid": "boot-guid", "partuuid": "boot-partuuid", "partlabel": "Boot", "mountpoint": "/boot"},
        {"device": "/dev/sda3", "filesystem": "xfs", "uuid": "data-current", "label": "Data Vol",
         "partition_guid": "data-guid", "partuuid": "data-partuuid", "mountpoint": "/data"},
    ]


ROOT = "UUID=root-current / ext4 defaults 0 1\n"


def plan(text, **kwargs):
    return reconcile_fstab(text, kwargs.pop("filesystems", filesystems()), root_device=kwargs.pop("root_device", "/dev/vg/root"), **kwargs)


def test_transport_normalization_preserves_uuid_and_every_other_byte():
    source = "# Source comment\r\n  /dev/mapper/vg-root\t/  ext4  defaults,errors=remount-ro 0 1  # root\r\n"
    inventory = filesystems()
    old = deepcopy(inventory)
    result = plan(source, filesystems=inventory)
    assert result["ready"]
    assert result["content"] == source.replace("/dev/mapper/vg-root", "UUID=root-current")
    assert inventory == old and not result["boot_update_required"] and not result["root_uuid_changed"]


def test_labels_policy_uses_existing_unique_labels_and_preserves_surrounding_text():
    source = "# unchanged\r\n  /dev/mapper/vg-root\t/ ext4 defaults 0 1 # root\r\nUUID=data-current /data xfs defaults 0 2\n"
    inventory, before = filesystems(), filesystems()
    result = plan(source, filesystems=inventory, policy="labels")
    assert result["ready"]
    assert result["content"] == source.replace("/dev/mapper/vg-root", "LABEL=ROOT").replace("UUID=data-current", r"LABEL=Data\040Vol")
    assert all(entry["reference_kind"] == "label" and entry["fallback_reason"] is None for entry in result["entries"])
    assert inventory == before and result["root_uuid"] == "root-current"
    assert not result["boot_update_required"]


@pytest.mark.parametrize("label,reason", [("", "no label"), ("BOOT", "not unique"), ('root"name', "safely"),
                                         (r"root\name", "safely"), ("root\nname", "safely"), ("root\u2028name", "safely"),
                                         ("data\u00a0disk", "safely"), ("data\u2007disk", "safely"),
                                         ("data\u202fdisk", "safely"), ("data\ud800disk", "safely"),
                                         ("data\udcffdisk", "safely")])
def test_label_fallback_is_explicit_even_when_existing_uuid_needs_no_edit(label, reason):
    inventory = filesystems()
    inventory[0]["label"] = label
    result = plan(ROOT, filesystems=inventory, policy="labels")
    assert result["ready"] and result["content"] == ROOT and not result["changes"]
    entry = result["entries"][0]
    assert entry["reference_kind"] == "uuid" and reason in entry["fallback_reason"]
    assert any(reason in warning for warning in result["warnings"])


@pytest.mark.parametrize("label", ["Données磁盘", "Données 磁盘"])
def test_unicode_labels_remain_usable_and_round_trip_without_identity_changes(label):
    inventory = filesystems()
    inventory[0]["label"] = label
    original = deepcopy(inventory)
    result = plan(ROOT, filesystems=inventory, policy="labels")
    assert result["ready"] and result["entries"][0]["reference_kind"] == "label"
    assert result["entries"][0]["fallback_reason"] is None
    assert result["content"] == ROOT.replace("UUID=root-current", "LABEL=" + label.replace(" ", r"\040"))
    verified = plan(result["content"], filesystems=inventory, policy="labels")
    assert verified["ready"] and not verified["changes"]
    assert inventory == original


def test_tab_label_is_octal_escaped_and_case_sensitive_uniqueness_is_retained():
    inventory = filesystems()
    inventory[0]["label"] = "Root\tFS"
    inventory[1]["label"] = "root\tFS"
    result = plan(ROOT, filesystems=inventory, policy="labels")
    assert result["ready"] and result["content"].startswith(r"LABEL=Root\011FS ")
    assert plan(result["content"], filesystems=inventory, policy="labels")["changes"] == []


def test_label_preference_does_not_guess_an_ambiguous_or_wrong_original_reference():
    inventory = filesystems()
    inventory[0]["label"] = "BOOT"
    assert not plan("LABEL=BOOT / ext4 defaults 0 1\n", filesystems=inventory, policy="labels")["ready"]
    assert not plan("UUID=boot-current / ext4 defaults 0 1\n", policy="labels")["ready"]
    inventory[1]["uuid"] = "root-current"
    assert not plan(ROOT, filesystems=inventory, policy="labels")["ready"]


def test_label_repair_still_requires_independent_root_and_boot_verification():
    result = plan("UUID=stale-root / ext4 defaults 0 1\n", policy="labels")
    assert result["ready"] and result["content"].startswith("LABEL=ROOT ")
    assert result["boot_reference_check_required"]
    assert not plan("UUID=stale-root / ext4 defaults 0 1\n", policy="labels", root_device="/dev/unknown")["ready"]


def test_stale_root_uuid_repaired_only_from_independent_root():
    result = plan("UUID=stale-root / ext4 defaults 0 1\n")
    assert result["ready"] and result["content"] == ROOT
    assert result["boot_reference_check_required"] and not result["root_uuid_changed"]
    assert "independently inspected root" in result["changes"][0]["reason"]


def test_existing_wrong_root_identity_is_not_overridden():
    source = "UUID=boot-current / ext4 defaults 0 1\n"
    result = plan(source)
    assert not result["ready"] and result["content"] == source
    assert any("another filesystem" in error for error in result["errors"])


def test_unknown_root_device_cannot_use_mountpoint_guess():
    assert not plan(ROOT, root_device="/dev/unknown")["ready"]


def test_stale_nonroot_uuid_not_inferred_from_inventory_mountpoint():
    result = plan(ROOT + "UUID=stale /data xfs defaults 0 2\n")
    assert not result["ready"] and "unambiguous" in " ".join(result["errors"])
    observed = plan(ROOT + "UUID=stale /data xfs defaults 0 2\n", mounted={"/data": "/dev/sda3"})
    assert observed["ready"] and "UUID=data-current /data" in observed["content"]


def test_persistent_partition_identity_reconciles_changed_data_uuid():
    previous = deepcopy(filesystems())
    previous[2]["uuid"] = "data-before"
    previous[2]["device"] = "/dev/sda4"
    result = plan(ROOT + "UUID=data-before /data xfs defaults 0 2\n", previous_filesystems=previous)
    assert result["ready"] and "UUID=data-current /data" in result["content"]
    mapping = next(row for row in result["uuid_map"] if row["before"] == "data-before")
    assert mapping == {"previous_device": "/dev/sda4", "device": "/dev/sda3", "before": "data-before", "after": "data-current", "evidence": "partition_guid", "changed": True}
    assert not result["boot_update_required"]


def test_same_position_and_size_are_not_an_identity_mapping():
    previous = deepcopy(filesystems())
    previous[2].pop("partition_guid")
    previous[2]["uuid"] = "data-before"
    assert not plan(ROOT + "UUID=data-before /data xfs defaults 0 2\n", previous_filesystems=previous)["ready"]


def test_actual_root_uuid_change_is_distinguished_from_normalization():
    previous = deepcopy(filesystems())
    previous[0]["uuid"] = "root-before"
    result = plan("UUID=root-before / ext4 defaults 0 1\n", previous_filesystems=previous)
    assert result["ready"] and result["root_uuid_changed"] and result["boot_update_required"]


@pytest.mark.parametrize("selector", ["UUID=boot-current", "/dev/disk/by-uuid/boot-current", "LABEL=BOOT", "PARTUUID=boot-partuuid", "PARTLABEL=Boot"])
def test_duplicate_identity_never_counts_as_stale(selector):
    inventory = filesystems()
    inventory.append({**inventory[1], "device": "/dev/sda9"})
    result = plan(ROOT + selector + " /boot ext4 defaults 0 2\n", filesystems=inventory, mounted={"/boot": "/dev/sda2"})
    assert not result["ready"]


def test_escaped_labels_mounts_comments_and_options_survive():
    source = ROOT + r"LABEL=Data\040Vol /srv/My\040Data xfs defaults,noatime 0 2 # keep this" + "\n"
    result = plan(source)
    assert result["ready"]
    assert result["content"] == source.replace(r"LABEL=Data\040Vol", "UUID=data-current")
    assert result["changes"][0]["mountpoint"] == "/srv/My Data"


def test_optional_remote_bind_and_swapfile_rows_are_preserved():
    rows = ("UUID=future /future ext4 defaults,nofail 0 2\n"
            "/dev/future /offline ext4 noauto 0 2\n"
            "UUID=network /network xfs _netdev 0 2\n"
            "server:/export /remote nfs defaults 0 0\n"
            "/data /bind none bind 0 0\n"
            "/.swapfile none swap sw 0 0\n"
            "/.swapfile none swap sw 0 0\n")
    result = plan(ROOT + rows)
    assert result["ready"] and result["content"] == ROOT + rows
    assert result["changes"] == [] and "Duplicate identical swap" in result["warnings"][0]


def test_observed_mount_conflict_and_wrong_filesystem_type_block():
    assert not plan(ROOT, mounted={"/": "/dev/sda2"})["ready"]
    assert not plan(ROOT + "UUID=data-current /data ext4 defaults 0 2\n")["ready"]
    assert not plan(ROOT + "UUID=data-current /data xfs defaults 0 2\n", mounted={"/data": "/dev/unrecognized"})["ready"]


def test_configuration_is_atomic_when_one_required_mount_is_unknown():
    source = "/dev/vg/root / ext4 defaults 0 1\nUUID=missing /data xfs defaults 0 2\n"
    result = plan(source)
    assert result["changes"] and not result["ready"] and result["content"] == source


@pytest.mark.parametrize("source", [ROOT + "UUID=boot-current relative ext4 defaults 0 2\n", ROOT + ROOT,
                                    ROOT + "bad fields\n", ROOT + "# x\n" * 4097, ROOT + "\0"])
def test_malformed_or_unbounded_fstab_rejected(source):
    assert not plan(source)["ready"]


class MountedGuest:
    def __init__(self, text=ROOT):
        self.text = text
        self.inventory = filesystems()
        self.links = set()
        self.nlink = 1
        self.mounts = {"/dev/vg/root": "/"}
        self.calls = []

    def list_filesystems(self):
        return {item["device"]: item["filesystem"] for item in self.inventory}

    def _item(self, device):
        return next(item for item in self.inventory if item["device"] == device)

    def vfs_uuid(self, device):
        return self._item(device)["uuid"]

    def vfs_label(self, device):
        return self._item(device)["label"]

    def lvm_canonical_lv_name(self, device):
        if device == "/dev/vg/root":
            return device
        raise RuntimeError("Not an LV")

    def lvuuid(self, device):
        return self._item(device)["lv_uuid"]

    def part_to_dev(self, device):
        return "/dev/sda"

    def part_to_partnum(self, device):
        return int(device[-1])

    def part_get_parttype(self, disk):
        return "gpt"

    def part_get_gpt_guid(self, disk, number):
        return "00000000-0000-0000-0000-00000000000" + str(number)

    def part_get_name(self, disk, number):
        return "Partition " + str(number)

    def part_get_gpt_type(self, disk, number):
        return "0fc63daf-8483-4772-8e79-3d69d8477de4"

    def canonical_device_name(self, device):
        return "/dev/vg/root" if device == "/dev/mapper/vg-root" else device

    def is_symlink(self, path):
        return path in self.links

    def is_file(self, path):
        return path == "/etc/fstab"

    def statns(self, path):
        return {"st_mode": 0o100640, "st_uid": 0, "st_gid": 0, "st_nlink": self.nlink}

    def filesize(self, path):
        return len(self.text.encode())

    def read_file(self, path):
        return self.text.encode()

    def mountpoints(self):
        return self.mounts

    def mount_ro(self, root, mount):
        self.calls.append(("mount_ro", root, mount))

    def mount(self, root, mount):
        self.calls.append(("mount", root, mount))


def test_inspection_reads_actual_uuids_and_mounts_not_cached_fstab_hints():
    guest = MountedGuest("UUID=stale / ext4 defaults 0 1\n")
    stale = [{"device": "/dev/sda2", "uuid": "stale", "mountpoint": "/"}]
    result = inspect_mount_references(guest, "/dev/mapper/vg-root", stale)
    assert result["ready"] and result["root_uuid"] == "root-current"
    assert result["content"] == ROOT
    assert result["filesystems"][0]["partuuid"] == "00000000-0000-0000-0000-000000000002"
    assert result["filesystems"][-1]["lv_uuid"] == "stable-root-lv"


def test_fresh_wrapper_cannot_repair_unknown_data_mount_from_cached_hint():
    guest = MountedGuest(ROOT + "UUID=stale /data xfs defaults 0 2\n")
    result = inspect_mount_references(guest, "/dev/vg/root", filesystems())
    assert not result["ready"]
    guest.mounts["/dev/sda3"] = "/data"
    assert inspect_mount_references(guest, "/dev/vg/root")["ready"]


@pytest.mark.parametrize("unsafe", ["symlink", "parent-symlink", "hardlink"])
def test_inspector_rejects_unsafe_mutable_fstab(unsafe):
    guest = MountedGuest()
    if unsafe == "hardlink":
        guest.nlink = 2
    else:
        guest.links.add("/etc" if unsafe == "parent-symlink" else "/etc/fstab")
    result = inspect_mount_references(guest, "/dev/vg/root")
    assert not result["ready"] and result["errors"]


def test_optional_inspector_failure_returns_unknown_not_exception():
    assert not inspect_mount_references(object(), "/dev/sda2")["ready"]


def harness(monkeypatch, guest):
    calls = []

    @contextmanager
    def opened(path, fmt, readonly=True):
        calls.append((str(path), readonly))
        yield guest

    def write(g, path, content):
        assert path == "/etc/fstab"
        calls.append(("write", content))
        g.text = content

    monkeypatch.setattr("forge.engine._guest", opened)
    monkeypatch.setattr("forge.engine._roots", lambda g: "/dev/vg/root")
    monkeypatch.setattr("forge.engine._write_guest", write)
    monkeypatch.setattr("forge.engine._relabel_edited_files", lambda g, paths: calls.append(("relabel", paths)))
    return calls


def test_reconciliation_edits_work_only_relabels_and_verifies_readback(monkeypatch, tmp_path):
    source = tmp_path / "source.qcow2"
    source.write_bytes(b"immutable source")
    work = tmp_path / "work.qcow2"
    work.write_bytes(b"standalone working disk")
    guest = MountedGuest("/dev/vg/root / ext4 defaults 0 1\n")
    calls = harness(monkeypatch, guest)
    receipt = reconcile_mounts(work)
    assert source.read_bytes() == b"immutable source"
    assert receipt["changed"] and receipt["mounts_validated"] and guest.text == ROOT
    assert all(path != str(source) for path, _ in calls)
    assert ("relabel", ["/etc/fstab"]) in calls
    assert verify_mounts(work, receipt)["ready"]
    guest.text += "# late edit\n"
    assert not verify_mounts(work, receipt)["ready"]


def test_label_preview_accepts_only_hash_verified_original_text_and_complete_identity_evidence():
    guest = MountedGuest()
    evidence = inspect_mount_references(guest, "/dev/vg/root")
    original = deepcopy(evidence)
    image = {"mount_reconciliation": evidence, "files": {"/etc/fstab": guest.text}}
    result = plan_mounts(image, "labels")
    assert result["ready"] and result["content"].startswith("LABEL=ROOT ")
    assert evidence == original
    del evidence["source_content"]
    assert plan_mounts(image, "labels")["ready"]  # older record has exact inspection.files text
    image["files"]["/etc/fstab"] += "# changed cached text\n"
    assert not plan_mounts(image, "labels")["ready"]
    image["files"]["/etc/fstab"] = guest.text
    del evidence["mounted"]
    assert not plan_mounts(image, "labels")["ready"]


def test_label_writes_preserve_source_and_final_checks_detect_changed_labels_or_uuid(monkeypatch, tmp_path):
    source, work = tmp_path / "source", tmp_path / "work"
    source.write_bytes(b"source unchanged")
    work.write_bytes(b"working copy")
    guest = MountedGuest()
    calls = harness(monkeypatch, guest)
    receipt = reconcile_mounts(work, policy="labels")
    assert guest.text == "LABEL=ROOT / ext4 defaults 0 1\n"
    assert receipt["policy"] == "labels" and receipt["entries"][0]["reference_kind"] == "label"
    assert source.read_bytes() == b"source unchanged" and all(path != str(source) for path, _ in calls)
    assert verify_mounts(work, receipt)["ready"]
    guest.inventory[0]["label"] = "CHANGED"
    assert not verify_mounts(work, receipt)["ready"]
    guest.inventory[0]["label"] = "ROOT"
    guest.inventory[1]["label"] = "ROOT"
    assert not verify_mounts(work, receipt)["ready"]
    guest.inventory[1]["label"] = "BOOT"
    guest.inventory[0]["uuid"] = "new-root"
    assert not verify_mounts(work, receipt)["ready"]


def test_label_change_between_readonly_preview_and_write_never_applies_stale_plan(monkeypatch):
    guest = MountedGuest()
    calls = harness(monkeypatch, guest)
    original = guest.mount
    def change(root, mount):
        original(root, mount)
        guest.inventory[0]["label"] = "CHANGED"
    guest.mount = change
    with pytest.raises(StorageError, match="changed after reconciliation preflight"):
        reconcile_mounts(Path("work"), policy="labels")
    assert not any(call[0] == "write" for call in calls) and guest.text == ROOT


def test_labels_do_not_bypass_boot_uuid_change_guard(monkeypatch):
    guest = MountedGuest("UUID=root-before / ext4 defaults 0 1\n")
    calls = harness(monkeypatch, guest)
    previous = {"mount_reconciliation": {"version": 1, "filesystems": filesystems()}}
    previous["mount_reconciliation"]["filesystems"][0]["uuid"] = "root-before"
    with pytest.raises(StorageError, match="GRUB and initramfs"):
        reconcile_mounts(Path("work"), previous, policy="labels")
    assert calls == [("work", True)]


def test_preserve_is_readonly_and_does_not_certify_unresolved_mounts(monkeypatch):
    guest = MountedGuest(ROOT + "UUID=missing /data xfs defaults 0 2\n")
    original = guest.text
    calls = harness(monkeypatch, guest)
    receipt = reconcile_mounts(Path("work"), policy="preserve")
    assert not receipt["changed"] and not receipt["mounts_validated"] and receipt["warnings"]
    assert guest.text == original and all(readonly is True for _, readonly in calls)
    assert verify_mounts(Path("work"), receipt)["ready"]


def test_ambiguous_reconciliation_never_opens_readwrite(monkeypatch):
    guest = MountedGuest(ROOT + "UUID=missing /data xfs defaults 0 2\n")
    calls = harness(monkeypatch, guest)
    with pytest.raises(StorageError, match="unambiguous"):
        reconcile_mounts(Path("work"))
    assert calls == [("work", True)]


def test_actual_root_uuid_change_requires_boot_update_before_mutation(monkeypatch):
    guest = MountedGuest("UUID=root-before / ext4 defaults 0 1\n")
    calls = harness(monkeypatch, guest)
    previous = {"mount_reconciliation": {"version": 1, "filesystems": filesystems()}}
    previous["mount_reconciliation"]["filesystems"][0]["uuid"] = "root-before"
    with pytest.raises(StorageError, match="GRUB and initramfs"):
        reconcile_mounts(Path("work"), previous)
    assert calls == [("work", True)]


def test_final_verification_detects_uuid_change_even_with_unchanged_fstab(monkeypatch):
    guest = MountedGuest()
    harness(monkeypatch, guest)
    receipt = reconcile_mounts(Path("work"))
    guest.inventory[0]["uuid"] = "different-root"
    result = verify_mounts(Path("work"), receipt)
    assert not result["ready"] and any("root UUID" in error for error in result["blockers"])


def test_receipt_cannot_be_empty_or_become_trusted_without_actual_evidence():
    assert not verify_mounts(Path("work"), {"version": 1})["ready"]


def boot_inspection(root="UUID=root-current", *, archive=None):
    return {"mount_reconciliation": {"root_uuid": "root-current", "filesystems": filesystems()},
            "platform": {"tools": {"update-grub": True},
                         "kernels": {"6.8": {"initrd": "/boot/initrd.img-6.8", "portability": archive or {"readable": True, "embedded_cmdline": {}, "embedded_fstab_present": False, "embedded_mounts": []}}},
                         "generated_grub": {"/boot/grub/grub.cfg": "linux /boot/vmlinuz-6.8 root=" + root + " ro\ninitrd /boot/initrd.img-6.8\n"}}}


BOOT_RECEIPT = {"boot_reference_check_required": True, "root_uuid": "root-current"}


@pytest.mark.parametrize("root", ["UUID=root-current", "/dev/mapper/vg-root"])
def test_stale_fstab_repair_accepts_already_correct_boot_root(root):
    assert verify_mount_boot_references(boot_inspection(root), BOOT_RECEIPT)["ready"]


def test_stale_fstab_repair_cannot_certify_stale_grub_root():
    result = verify_mount_boot_references(boot_inspection("UUID=stale"), BOOT_RECEIPT)
    assert not result["ready"] and "regenerate" in " ".join(result["blockers"])


@pytest.mark.parametrize("archive", [{"readable": False},
                                    {"readable": True, "embedded_cmdline": {"etc/cmdline": "root=UUID=stale"}},
                                    {"readable": True, "embedded_fstab_present": True, "embedded_mounts": [{"source": "UUID=stale", "mountpoint": "/", "filesystem": "ext4"}]}])
def test_stale_or_unreadable_archived_root_references_fail_closed(archive):
    assert not verify_mount_boot_references(boot_inspection(archive=archive), BOOT_RECEIPT)["ready"]


def test_transport_normalization_does_not_demand_boot_rewrite():
    assert verify_mount_boot_references({}, {"boot_reference_check_required": False}) == {"required": False, "ready": True, "blockers": []}


def test_case_spelling_is_not_filesystem_uuid_change():
    previous = filesystems()
    previous[0]["uuid"] = "ROOT-CURRENT"
    result = plan('UUID="ROOT-CURRENT" / ext4 defaults 0 1\n', previous_filesystems=previous)
    assert result["ready"] and not result["root_uuid_changed"] and not result["boot_update_required"]


def test_quoted_previous_uuid_maps_via_persistent_identity():
    previous = filesystems()
    previous[2]["uuid"] = "old-data"
    result = plan(ROOT + 'UUID="old-data" /data xfs defaults 0 2\n', previous_filesystems=previous)
    assert result["ready"] and "UUID=data-current /data" in result["content"]


def test_previous_uuid_now_identifies_another_device_is_not_silently_repaired():
    previous, current = filesystems(), filesystems()
    previous[2]["uuid"] = "old-data"
    current[1]["uuid"] = "old-data"
    result = plan(ROOT + "UUID=old-data /data xfs defaults 0 2\n", filesystems=current, previous_filesystems=previous)
    assert not result["ready"] and "conflicts" in " ".join(result["errors"])


@pytest.mark.parametrize("mount,typed", [("/efi", False), ("/firmware", True)])
def test_efi_mount_repairs_require_boot_reference_verification(mount, typed):
    inventory = filesystems()
    inventory[1]["filesystem"] = "vfat"
    if typed:
        inventory[1]["partition_type"] = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    result = plan(ROOT + "UUID=old-efi " + mount + " vfat defaults 0 2\n", filesystems=inventory, mounted={mount: "/dev/sda2"})
    assert result["ready"] and result["boot_reference_check_required"]


def test_archived_sysroot_stale_uuid_is_rejected():
    archive = {"readable": True, "embedded_fstab_present": True,
               "embedded_mounts": [{"source": "UUID=stale", "mountpoint": "/sysroot", "filesystem": "ext4"}]}
    assert not verify_mount_boot_references(boot_inspection(archive=archive), BOOT_RECEIPT)["ready"]


def test_quoted_archived_root_and_stable_by_uuid_boot_reference_are_valid():
    archive = {"readable": True, "embedded_fstab_present": True,
               "embedded_mounts": [{"source": 'UUID="root-current"', "mountpoint": "/sysroot", "filesystem": "ext4"}]}
    assert verify_mount_boot_references(boot_inspection("/dev/disk/by-uuid/root-current", archive=archive), BOOT_RECEIPT)["ready"]


def test_ubuntu_dm_uuid_alias_comes_from_actual_vg_and_lv_identifiers():
    vg, lv = "L8GWknAcQHq0sxAoeMbghNXFmoqAtBWn", "dg8aPuWAGRBXwRtDhZGxOwLyRR5LpsHZ"
    alias = "/dev/disk/by-id/dm-uuid-LVM-" + vg + lv
    guest = MountedGuest(alias + " / ext4 defaults 0 1\n")
    guest.inventory[0]["lv_uuid"] = lv
    guest.vguuid = lambda name: vg if name == "vg" else ""
    result = inspect_mount_references(guest, "/dev/vg/root")
    root = next(item for item in result["filesystems"] if item["device"] == "/dev/vg/root")
    assert alias in root["aliases"] and root["vg_uuid"] == vg
    assert result["ready"] and result["changes"][0]["reason"] == "Resolved current filesystem identity"
    assert not result["boot_reference_check_required"]


def test_dm_uuid_with_wrong_vg_is_not_certified_as_an_existing_alias():
    vg, lv = "L8GWknAcQHq0sxAoeMbghNXFmoqAtBWn", "dg8aPuWAGRBXwRtDhZGxOwLyRR5LpsHZ"
    alias = "/dev/disk/by-id/dm-uuid-LVM-" + "A" * 32 + lv
    guest = MountedGuest(alias + " / ext4 defaults 0 1\n")
    guest.inventory[0]["lv_uuid"] = lv
    guest.vguuid = lambda name: vg
    result = inspect_mount_references(guest, "/dev/vg/root")
    assert all(alias not in item["aliases"] for item in result["filesystems"])
    assert result["boot_reference_check_required"]
    assert "independently inspected root" in result["changes"][0]["reason"]


def test_dm_uuid_for_another_existing_lv_cannot_be_reassigned_to_root():
    vg, root_id, other_id = "A" * 32, "B" * 32, "C" * 32
    guest = MountedGuest("/dev/disk/by-id/dm-uuid-LVM-" + vg + other_id + " / ext4 defaults 0 1\n")
    guest.inventory[0]["lv_uuid"] = root_id
    guest.inventory.append({"device": "/dev/vg/other", "filesystem": "ext4", "uuid": "other-uuid", "label": "", "lv_uuid": other_id})
    guest.lvm_canonical_lv_name = lambda device: device if device.startswith("/dev/vg/") else (_ for _ in ()).throw(RuntimeError("not LV"))
    guest.vguuid = lambda name: vg
    result = inspect_mount_references(guest, "/dev/vg/root")
    assert not result["ready"] and "another filesystem" in " ".join(result["errors"])
