"""Preservation accepts proven existing arrangements without normalizing them."""
from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest

from forge.engine import EngineError
from forge.platform import MODULE_CONFIG, plan_platform, prepare_platform, verify_platform
from forge.portability import (_local_root_completion, assess_portability, inspect_archive,
                               inspect_local_devices, inspect_portability)


KERNEL = "6.12.0-test.x86_64"
ROOT_UUID = "11111111-2222-3333-4444-555555555555"
HOOK = '''if [ -n "$iscsi_firmware" ]; then
    echo "${DRACUT_SYSTEMD+systemctl is-active initrd-root-device.target || }[ -f '/tmp/iscsistarted-firmware' ]" > "$hookdir"/initqueue/finished/iscsi_started.sh
fi
for nroot in $(getargs netroot); do
    echo "${DRACUT_SYSTEMD+systemctl is-active initrd-root-device.target || }[ -f '/tmp/iscsistarted-$netroot_enc' ]" > "$hookdir"/initqueue/finished/iscsi_started.sh
done
'''


def options(**changes):
    result = {"enabled": True, "strategy": "preserve", "source": "bare_metal", "target": "vm",
              "boot_attachment": "paravirtualized", "network_attachment": "paravirtualized",
              "nic_driver": "mlx5_core", "install_packages": False,
              "configure_network": False, "configure_serial_console": False}
    result.update(changes)
    return result


def image(words="root=/dev/mapper/ocivolume-root ro netroot=iscsi rd.iscsi.firmware=1"):
    device = {"device": "/dev/ocivolume/root", "aliases": ["/dev/ocivolume/root", "/dev/mapper/ocivolume-root"],
              "is_lv": True, "uuid": ROOT_UUID, "mountpoint": "/", "filesystem": "xfs"}
    archive = {"version": 1, "readable": True, "hostonly": False, "dracut_modules": ["systemd", "dracut-systemd", "iscsi", "lvm"],
               "embedded_cmdline": {"etc/cmdline.d/00-btrfs.conf": "rd.driver.pre=btrfs"},
               "iscsi_local_root_completion": True, "lvm_userspace": True, "errors": []}
    return {"os": {"distro": "oraclelinux", "arch": "x86_64"},
            "boot": {"supported_firmware": ["UEFI_64"], "recommended_firmware": "UEFI_64"},
            "platform": {"version": 1,
                         "kernels": {KERNEL: {"modules": list(MODULE_CONFIG), "builtin": [],
                                               "initrd": f"/boot/initramfs-{KERNEL}.img", "initrd_modules": list(MODULE_CONFIG),
                                               "initrd_sha256": "a" * 64, "initrd_iscsi_userspace": True, "portability": archive}},
                         "tools": {"grub2-mkconfig": True},
                         "fstab": {"root_uuid": ROOT_UUID, "errors": [], "entries": [
                             {"line": 1, "source": "/dev/mapper/ocivolume-root", "mountpoint": "/", "uuid": ROOT_UUID,
                              "replacement": "UUID=" + ROOT_UUID}]},
                         "generated_grub": {"/boot/grub2/grub.cfg": "insmod blscfg\nblscfg\n"},
                         "boot_files": {"/boot/loader/entries/test.conf": f"linux /vmlinuz-{KERNEL}\ninitrd /initramfs-{KERNEL}.img\noptions {words}\n"},
                         "portability": {"version": 1, "local_devices": [device], "network_direct_ready": True,
                                         "network_bootstrap": {"ready": False, "status": "unknown"}, "errors": [],
                                         "hashes": {"/etc/fstab": "sha256:" + "b" * 64,
                                                    f"/boot/vmlinuz-{KERNEL}": "sha256:" + "d" * 64,
                                                    f"/boot/initramfs-{KERNEL}.img": "sha256:" + "a" * 64}}}}


def test_observed_generic_oci_existing_configuration_passes_without_rewrites():
    source = image()
    before = deepcopy(source)
    result = plan_platform(source, options())
    assert result["ready"], result["blockers"]
    assert result["fstab_changes"] == []
    assert result["packages"] == []
    assert result["portability"]["root_transport"] == "optional_firmware_iscsi"
    assert result["portability"]["dual_environment"]["status"] == "ready"
    assert result["portability"]["source_platform"] == "unknown"
    assert not result["portability"]["boot_tested"]
    assert {"xfs", "dm_mod", "virtio_scsi", "virtio_net"} <= set(result["required_modules"])
    assert "nvme" not in result["required_modules"]
    assert "ahci" not in result["required_modules"]
    assert source == before


def test_preserve_allows_same_machine_type_and_reconfigure_retains_old_rule():
    assert plan_platform(image(), options(source="vm"))["ready"]
    result = plan_platform(image(), options(strategy="reconfigure", source="vm"))
    assert not result["ready"]
    assert any("distinct" in error for error in result["blockers"])


@pytest.mark.parametrize("driver", ["virtio_net", "virtio_pci", "virtio_scsi", "xfs", "dm_mod"])
def test_missing_target_or_root_driver_cannot_be_preserved(driver):
    source = image()
    kernel = source["platform"]["kernels"][KERNEL]
    kernel["initrd_modules"].remove(driver)
    assert any(driver in error for error in assess_portability(source, options())["blockers"])
    kernel["builtin"].append(driver)
    assert assess_portability(source, options())["ready"]


def test_target_vm_does_not_require_unused_hardware_drivers_or_dual_support():
    source = image("root=/dev/mapper/ocivolume-root ro")
    kernel = source["platform"]["kernels"][KERNEL]
    for name in ["mlx5_core", "iscsi_tcp", "iscsi_ibft", "nvme", "nvme_core", "ahci"]:
        kernel["modules"].remove(name)
        kernel["initrd_modules"].remove(name)
    kernel["initrd_iscsi_userspace"] = False
    result = assess_portability(source, options())
    assert result["ready"], result["blockers"]
    assert result["dual_environment"]["status"] == "unknown"


@pytest.mark.parametrize("argument", ["rd.neednet=1", "rd.neednet=yes", "rd.neednet", "ip=dhcp", "ip=ibft",
                                       "netroot=iscsi:192.0.2.1::::iqn.example", "root=/dev/nfs", "root=iscsi:example"])
def test_explicit_network_or_remote_root_is_not_optional(argument):
    source = image("root=/dev/mapper/ocivolume-root ro netroot=iscsi rd.iscsi.firmware=1 " + argument)
    result = assess_portability(source, options())
    assert not result["ready"]
    assert result["root_transport"] == "mandatory_network"


def test_embedded_cmdline_is_checked_and_cannot_override_the_root():
    source = image()
    source["platform"]["kernels"][KERNEL]["portability"]["embedded_cmdline"]["etc/cmdline.d/95-root.conf"] = "root=/dev/sdb3 rd.neednet=1"
    assert not assess_portability(source, options())["ready"]


def test_absent_archive_or_completion_proof_is_unknown_not_assumed_ready():
    for mutation in (lambda kernel: kernel["portability"].update(iscsi_local_root_completion=False),
                     lambda kernel: kernel.update(initrd_modules=None, portability={"version": 1, "readable": False}),
                     lambda kernel: kernel["portability"].update(lvm_userspace=False)):
        source = image()
        mutation(source["platform"]["kernels"][KERNEL])
        result = assess_portability(source, options())
        assert result["status"] == "unknown", result
        assert not result["ready"]


def test_every_installed_kernel_must_have_target_coverage():
    source = image()
    old = "5.14.0-old.x86_64"
    kernel = deepcopy(source["platform"]["kernels"][KERNEL])
    kernel["modules"].remove("virtio_net")
    kernel["initrd"] = f"/boot/initramfs-{old}.img"
    source["platform"]["portability"]["hashes"]["/boot/vmlinuz-" + old] = "sha256:" + "d" * 64
    source["platform"]["portability"]["hashes"][kernel["initrd"]] = "sha256:" + "a" * 64
    source["platform"]["kernels"][old] = kernel
    source["platform"]["boot_files"]["/boot/loader/entries/old.conf"] = source["platform"]["boot_files"]["/boot/loader/entries/test.conf"].replace(KERNEL, old)
    result = assess_portability(source, options())
    assert not result["ready"]
    assert any(old in error and "virtio_net" in error for error in result["blockers"])


@pytest.mark.parametrize("replacement", ["/dev/mapper/not-on-this-disk", "/dev/sda3", "UUID=wrong-root"])
def test_looks_stable_is_not_actual_local_root_evidence(replacement):
    source = image("root=" + replacement)
    assert not assess_portability(source, options())["ready"]


def test_boot_entry_must_use_the_inspected_kernel_and_archive():
    source = image()
    path = "/boot/loader/entries/test.conf"
    source["platform"]["boot_files"][path] = source["platform"]["boot_files"][path].replace("initrd /initramfs-", "initrd /old/initramfs-")
    assert any("paths" in error for error in assess_portability(source, options())["blockers"])


def test_bls_optional_tuned_initrd_requires_observed_empty_environment():
    source = image()
    path = "/boot/loader/entries/test.conf"
    source["platform"]["boot_files"][path] = source["platform"]["boot_files"][path].replace(f"initrd /initramfs-{KERNEL}.img", f"initrd /initramfs-{KERNEL}.img $tuned_initrd")
    assert not assess_portability(source, options())["ready"]
    source["platform"]["boot_environment"] = {"tuned_initrd": ""}
    assert assess_portability(source, options())["ready"]
    source["platform"]["boot_environment"]["tuned_initrd"] = "/uninspected.img"
    assert not assess_portability(source, options())["ready"]


def test_legacy_grub_kernel_initrd_pair_is_checked_without_execution():
    source = image("root=UUID=" + ROOT_UUID)
    source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] = f"menuentry 'Test' {{\n linux /vmlinuz-{KERNEL} root=UUID={ROOT_UUID}\n initrd /initramfs-{KERNEL}.img\n}}\n"
    assert assess_portability(source, options())["ready"]
    source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] = f"linux /vmlinuz-{KERNEL} root=UUID={ROOT_UUID}\n"
    assert not assess_portability(source, options())["ready"]


def test_hardware_target_accepts_existing_firmware_discovery_without_new_flags():
    result = assess_portability(image(), options(target="bare_metal", boot_attachment="iscsi", network_attachment="vfio"))
    assert result["ready"], result["blockers"]
    assert "mlx5_core" in result["required_modules"]
    assert "nvme" not in result["required_modules"]


def test_bootstrap_is_an_alternative_to_unbound_network_profile_but_not_a_guess():
    source = image()
    facts = source["platform"]["portability"]
    facts["network_direct_ready"] = False
    assert assess_portability(source, options())["status"] == "unknown"
    facts["network_bootstrap"] = {"ready": True, "evidence": ["Verified Oracle datasource new-instance network path."]}
    assert assess_portability(source, options())["ready"]
    assert not assess_portability(source, options(), target_provider="generic")["ready"]
    facts["network_blockers"] = ["NetworkManager is masked."]
    assert not assess_portability(source, options())["ready"]


def test_optional_iscsi_blacklist_and_wrong_lvm_activation_are_not_ignored():
    for words in ("rd.driver.blacklist=iscsi_tcp", "rd.lvm.lv=other/root", "rd.lvm.vg=other", "rd.lvm=0"):
        source = image("root=/dev/mapper/ocivolume-root ro netroot=iscsi rd.iscsi.firmware=1 " + words)
        assert not assess_portability(source, options())["ready"]
    source = image()
    source["platform"]["blacklisted_modules"] = ["iscsi_ibft"]
    assert not assess_portability(source, options())["ready"]


def test_empty_hash_manifest_is_unknown_and_cannot_create_valid_receipt():
    source = image()
    source["platform"]["portability"]["hashes"] = {}
    result = assess_portability(source, options())
    assert result["status"] == "unknown"
    assert not verify_platform(source, options(), receipt={"preserved_files": {}})["ready"]


def test_identical_duplicate_swap_entries_are_retained_as_warning():
    source = image()
    entry = {"source": "/.swapfile", "filesystem": "swap", "mountpoint": "none", "options": "sw", "preserve": True}
    source["platform"]["fstab"]["entries"] += [entry, deepcopy(entry)]
    result = assess_portability(source, options())
    assert result["ready"]
    assert any("duplicate swap" in warning for warning in result["warnings"])


def test_preserve_preview_cannot_hide_oci_guest_rewrites():
    config = {"guest": {"prepare": True}, "capabilities": {
        "Storage.BootVolumeType": {"default_value": "PARAVIRTUALIZED"},
        "Network.AttachmentType": {"default_value": "PARAVIRTUALIZED"},
        "Compute.Firmware": {"default_value": "UEFI_64"}}}
    result = plan_platform(image(), options(), oci_config=config)
    assert any("guest preparation to be disabled" in error for error in result["blockers"])


def test_manifest_fingerprints_symlink_contents_and_masked_network_cannot_be_overridden():
    class Guest:
        def __init__(self):
            self.contents = {"/boot/grub2/grubenv": b"kernelopts=one"}
            self.links = {"/boot/grub2/grubenv": "/boot/efi/EFI/vendor/grubenv"}
        def lvs(self): return []
        def is_symlink(self, path): return path in self.links
        def readlink(self, path): return self.links[path]
        def is_file(self, path): return path in self.contents
        def glob_expand(self, pattern): return []
        def checksum(self, kind, path): return hashlib.sha256(self.contents[path]).hexdigest()
        def filesize(self, path): return len(self.contents[path])
        def read_file(self, path): return self.contents[path]
    g = Guest()
    evidence = {"boot_environment_paths": ["/boot/grub2/grubenv"]}
    base = {"network_backend": "NetworkManager", "network_ready": True, "network_files": []}
    with patch("forge.cloud_bootstrap.inspect_bootstrap", return_value={"ready": True, "files": []}):
        before = inspect_portability(g, [], evidence, base)
        g.contents["/boot/grub2/grubenv"] = b"kernelopts=two"
        after = inspect_portability(g, [], evidence, base)
        assert before["hashes"]["/boot/grub2/grubenv"] != after["hashes"]["/boot/grub2/grubenv"]
        g.links["/etc/systemd/system/NetworkManager.service"] = "/dev/null"
        after = inspect_portability(g, [], evidence, base)
        assert after["network_blockers"]
        assert not after["network_direct_ready"]


@pytest.mark.parametrize("path,content", [
    ("/etc/NetworkManager/system-connections/local.nmconnection", "[connection]\nautoconnect=false\n"),
    ("/etc/sysconfig/network-scripts/ifcfg-generic", "BOOTPROTO=dhcp\nONBOOT=no\n")])
def test_direct_network_requires_automatic_profile_start(path, content):
    class Guest:
        def lvs(self): return []
        def is_symlink(self, name): return False
        def is_file(self, name): return name == path
        def glob_expand(self, pattern): return []
        def checksum(self, kind, name): return hashlib.sha256(content.encode()).hexdigest()
        def filesize(self, name): return len(content)
        def read_file(self, name): return content.encode()
    with patch("forge.cloud_bootstrap.inspect_bootstrap", return_value={"ready": False, "files": []}):
        result = inspect_portability(Guest(), [], {}, {"network_backend": "NetworkManager", "network_ready": True, "network_files": [path]})
    assert not result["network_direct_ready"]


class ArchiveGuest:
    def __init__(self, hook=HOOK):
        self.files = {"usr/lib/dracut/modules.txt": "systemd\ndracut-systemd\niscsi\nnetwork-manager\nlvm\n",
                      "usr/lib/dracut/hooks/cmdline/90-parse-iscsiroot.sh": hook,
                      "usr/lib/systemd/system/initrd-root-device.target": "[Unit]\n",
                      "usr/sbin/lvm": "binary", "etc/cmdline.d/00-btrfs.conf": "rd.driver.pre=btrfs\n"}

    def initrd_list(self, path):
        return list(self.files)

    def initrd_cat(self, path, member):
        return self.files[member].encode()


def test_archive_proof_reads_real_hook_instead_of_installed_package_or_comments():
    result = inspect_archive(ArchiveGuest(), "/boot/initramfs.img")
    assert result["readable"] and result["iscsi_local_root_completion"]
    assert result["lvm_userspace"]
    assert not _local_root_completion("# " + HOOK.replace("\n", "\n# "))
    assert not _local_root_completion(HOOK.replace(" || ", " && "))
    assert not _local_root_completion(HOOK + 'echo false > "$hookdir"/initqueue/finished/iscsi_started.sh\n')
    assert not inspect_archive(ArchiveGuest(HOOK.replace(" || ", " && ")), "/boot/initramfs.img")["iscsi_local_root_completion"]


def test_archive_read_error_and_unsafe_members_fail_closed():
    g = ArchiveGuest()
    with patch.object(g, "initrd_cat", side_effect=RuntimeError("unsupported compression")):
        assert not inspect_archive(g, "/boot/initramfs.img")["readable"]
    g.files["../escape"] = "text"
    assert not inspect_archive(g, "/boot/initramfs.img")["readable"]
    g = ArchiveGuest()
    with patch.object(g, "initrd_cat", side_effect=AttributeError("optional API unavailable")):
        assert not inspect_archive(g, "/boot/initramfs.img")["readable"]
    for number in range(9):
        g.files[f"usr/lib/dracut/hooks/cmdline/{number}-parse-iscsiroot.sh"] = HOOK
    assert not inspect_archive(g, "/boot/initramfs.img")["readable"]


def test_stable_lvm_aliases_require_actual_lv_inventory_and_escape_hyphens():
    class Guest:
        def lvs(self):
            return ["/dev/vg-name/root-lv"]
    result = inspect_local_devices(Guest(), [{"device": "/dev/vg-name/root-lv"}, {"device": "/dev/mapper/unrelated"}])
    assert "/dev/mapper/vg--name-root--lv" in result[0]["aliases"]
    assert result[0]["is_lv"]
    assert not result[1]["is_lv"]


def test_preservation_does_not_open_writable_guest_or_execute_commands_and_records_baseline():
    source = image()
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "image.qcow2"
        path.write_bytes(b"test image bytes")
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with patch("forge.engine.ImageEngine.inspect", return_value=source) as inspect, patch("forge.engine._guest") as guest, patch("forge.engine._run") as run:
            result = prepare_platform(path, source, options(), False, lambda _: None)
        inspect.assert_called_once_with(path)
        guest.assert_not_called()
        run.assert_not_called()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert result["preserved_files"] == source["platform"]["portability"]["hashes"]
    assert verify_platform(source, options(), receipt=result)["ready"]
    changed = deepcopy(source)
    changed["platform"]["portability"]["hashes"]["/etc/fstab"] = "sha256:" + "c" * 64
    assert not verify_platform(changed, options(), receipt=result)["ready"]
    changed = deepcopy(source)
    changed["platform"]["portability"]["hashes"]["/etc/cloud/cloud-init.disabled"] = "sha256:new"
    assert not verify_platform(changed, options(), receipt=result)["ready"]


def test_preservation_rechecks_work_after_explicit_edits_and_refuses_missing_receipt():
    source, changed = image(), image()
    changed["platform"]["kernels"][KERNEL]["modules"].remove("virtio_net")
    with patch("forge.engine.ImageEngine.inspect", return_value=changed), patch("forge.engine._guest") as guest:
        with pytest.raises(EngineError, match="cannot be preserved"):
            prepare_platform(Path("/tmp/test.qcow2"), source, options(), False, lambda _: None)
        guest.assert_not_called()
    assert not verify_platform(source, options(), receipt={})["ready"]


def test_older_inspection_requests_refresh_and_preserve_rejects_write_toggles():
    source = image()
    del source["platform"]["portability"]
    assert any("Refresh inspection" in item for item in plan_platform(source, options())["blockers"])
    assert not plan_platform(image(), options(configure_network=True))["ready"]
