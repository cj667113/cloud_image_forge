"""A shared rebuild schedules less work without weakening final disk proof."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

import pytest

from forge.engine import EngineError
from forge.oci import OciConfig
from forge.oci_guest import prepare_guest, verify_shared_preparation
from forge.platform import _can_share_oci_rebuild, _adapt_args, plan_platform, prepare_platform
from test_platform import Guest, image, options, KERNEL, FSTAB
from test_oci_guest import inspected, VERSION


def combined_image():
    result = image()
    provider = inspected()["oci_evidence"]
    provider["kernels"] = {KERNEL: provider["kernels"].pop(VERSION)}
    provider["kernels"][KERNEL]["initrd"] = result["platform"]["kernels"][KERNEL]["initrd"]
    result["oci_evidence"] = provider
    result["platform"]["portability"] = {"hashes": {"/boot/vmlinuz-" + KERNEL: "sha256:" + "c" * 64,
                                                   "/etc/default/grub": "sha256:" + "d" * 64}}
    return result


def configuration(**changes):
    return OciConfig(capabilities={"Storage.ConsistentVolumeNaming": {"default_value": False}},
                     guest={"configure_network": False, "configure_cloud_init": False,
                            "configure_serial_console": False, **changes})


def install_fakes(monkeypatch, states):
    before = states[0]
    guest = Guest({"/etc/fstab": FSTAB, **before["platform"]["boot_files"]})
    scripts = []
    @contextmanager
    def mounted(*args, **kwargs):
        yield guest
    monkeypatch.setattr("forge.engine._guest", mounted)
    monkeypatch.setattr("forge.engine._mount", lambda *args: None)
    monkeypatch.setattr("forge.engine._roots", lambda *args: "/dev/sda1")
    monkeypatch.setattr("forge.engine._run_guest_script", lambda work, script, log: scripts.append(script))
    inspected_states = iter(states)
    monkeypatch.setattr("forge.engine.ImageEngine.inspect", lambda *args, **kwargs: deepcopy(next(inspected_states)))
    return guest, scripts


def stage(monkeypatch):
    source = combined_image()
    staged = deepcopy(source)
    staged["platform"]["portability"]["hashes"]["/etc/dracut.conf.d/90-cloud-image-forge-platform.conf"] = "sha256:" + "e" * 64
    after = deepcopy(staged)
    after["platform"]["kernels"][KERNEL]["initrd_sha256"] = "b" * 64
    guest, scripts = install_fakes(monkeypatch, [staged, after])
    settings, hardware = configuration(), options()
    receipt = prepare_platform(Path("work.qcow2"), source, hardware, False, lambda _: None,
                               oci_config=settings, defer_initramfs_to_oci=True, inspected_work=True)
    return source, settings, hardware, receipt, after, guest, scripts


def test_combined_path_rebuilds_each_kernel_once_then_grub_and_verifies_both(monkeypatch):
    source, settings, hardware, pending, after, guest, scripts = stage(monkeypatch)
    assert pending["verified"] is False and pending["ready"] is False
    assert "deferred_initramfs" in pending and "verified_initrds" not in pending
    assert "dracut --force" not in scripts[0] and "grub2-mkconfig" not in scripts[0]
    assert "hostonly_cmdline=\"no\"" in guest.files["/etc/dracut.conf.d/90-cloud-image-forge-platform.conf"]
    completed = prepare_guest(Path("work.qcow2"), pending["_inspection"], settings.model_dump(), False, lambda _: None,
                              platform_migration=hardware, deferred_platform=pending["deferred_initramfs"])
    assert completed["combined_verified"] and completed["combined_platform"]
    assert len(scripts) == 2 and sum(script.count("dracut --force") for script in scripts) == 1
    assert "--no-hostonly --no-hostonly-cmdline" in scripts[1]
    assert scripts[1].rfind("grub2-mkconfig") > scripts[1].rfind("dracut --force")
    assert completed["verified_initrds"][KERNEL]["sha256"] == "b" * 64
    assert verify_shared_preparation(after, settings, hardware, completed)["ready"]
    assert source["platform"]["kernels"][KERNEL]["initrd_sha256"] == "a" * 64


@pytest.mark.parametrize("change", ["provider_disabled", "preserve", "missing_hash", "fingerprint_error", "different_kernel", "different_path", "renderer", "backend", "oci_package"])
def test_unproven_eligibility_keeps_separate_passes(change):
    source, hardware, settings = combined_image(), options(), configuration()
    if change == "provider_disabled":
        settings.guest.prepare = False
    elif change == "preserve":
        hardware["strategy"] = "preserve"
    elif change == "missing_hash":
        source["platform"]["portability"]["hashes"] = {}
    elif change == "fingerprint_error":
        source["platform"]["portability"]["errors"] = ["Cannot fingerprint dracut configuration"]
    elif change == "different_kernel":
        source["oci_evidence"]["kernels"]["other"] = source["oci_evidence"]["kernels"].pop(KERNEL)
    elif change == "different_path":
        source["oci_evidence"]["kernels"][KERNEL]["initrd"] = "/boot/other.img"
    elif change == "renderer":
        source["oci_evidence"]["network_backend"] = "netplan"
    elif change == "backend":
        source["os"]["distro"] = "ubuntu"
        source["oci_evidence"]["tools"].update({"dracut": False, "update-initramfs": True, "lsinitramfs": True})
    elif change == "oci_package":
        settings.guest.configure_cloud_init = True
        settings.guest.install_packages = True
        source["oci_evidence"]["tools"]["cloud-init"] = False
    plan = plan_platform(source, hardware, False, settings)
    assert not _can_share_oci_rebuild(source, hardware, plan, settings, "auto")


def test_requested_defer_falls_back_to_full_platform_rebuild_without_evidence(monkeypatch):
    source = combined_image()
    source["platform"]["portability"]["hashes"] = {}
    _, scripts = install_fakes(monkeypatch, [source])
    result = prepare_platform(Path("work.qcow2"), source, options(), False, lambda _: None,
                              oci_config=configuration(), defer_initramfs_to_oci=True)
    assert result["verified"] and "deferred_initramfs" not in result
    assert scripts[0].count("dracut --force") == 1


@pytest.mark.parametrize("mutation", ["initrd", "kernel", "config", "options", "policy"])
def test_pending_state_invalidated_before_oci_writes(monkeypatch, mutation):
    _, settings, hardware, pending, _, guest, scripts = stage(monkeypatch)
    current = deepcopy(pending["_inspection"])
    policy = "auto"
    if mutation == "initrd":
        current["platform"]["kernels"][KERNEL]["initrd_sha256"] = "f" * 64
    elif mutation == "kernel":
        current["platform"]["portability"]["hashes"]["/boot/vmlinuz-" + KERNEL] = "sha256:" + "f" * 64
    elif mutation == "config":
        current["platform"]["portability"]["hashes"]["/etc/default/grub"] = "sha256:" + "f" * 64
    elif mutation == "options":
        hardware["network_attachment"] = "accelerated"
    else:
        policy = "preserve"
    before = deepcopy(guest.files)
    with pytest.raises(EngineError, match="Deferred hardware preparation changed"):
        prepare_guest(Path("work.qcow2"), current, settings.model_dump(), False, lambda _: None,
                      platform_migration=hardware, deferred_platform=pending["deferred_initramfs"], mount_policy=policy)
    assert guest.files == before and len(scripts) == 1


def test_deferred_work_cannot_be_completed_by_validate_only(monkeypatch):
    _, settings, hardware, pending, _, _, scripts = stage(monkeypatch)
    settings.guest.prepare = False
    with pytest.raises(EngineError, match="requires actual OCI"):
        prepare_guest(Path("work.qcow2"), pending["_inspection"], settings.model_dump(), False, lambda _: None,
                      platform_migration=hardware, deferred_platform=pending["deferred_initramfs"])
    assert len(scripts) == 1


def test_union_includes_actual_hardware_only_driver_in_shared_native_checks(monkeypatch):
    source = combined_image()
    # An extra required platform driver is installed in the hardware inventory,
    # outside the narrower OCI module inventory; never infer it from CONFIG=m.
    settings, hardware = configuration(), options()
    assert "nvme" not in source["oci_evidence"]["kernels"][KERNEL]["modules"]
    after = deepcopy(source)
    after["platform"]["kernels"][KERNEL]["initrd_sha256"] = "b" * 64
    _, scripts = install_fakes(monkeypatch, [source, after])
    pending = prepare_platform(Path("work.qcow2"), source, hardware, False, lambda _: None,
                               oci_config=settings, defer_initramfs_to_oci=True)
    result = prepare_guest(Path("work.qcow2"), pending["_inspection"], settings.model_dump(), False, lambda _: None,
                           platform_migration=hardware, deferred_platform=pending["deferred_initramfs"], extra_required_modules=["nvme"])
    assert "Required driver nvme absent" in scripts[1]
    assert "nvme" in result["verified_initrds"][KERNEL]["modules"]


@pytest.mark.parametrize("mutation", ["digest", "path", "kernel", "kernel_set", "network", "grub", "empty_receipt"])
def test_final_combined_verifier_rejects_changed_archive_or_configuration(monkeypatch, mutation):
    _, settings, hardware, pending, after, _, _ = stage(monkeypatch)
    receipt = prepare_guest(Path("work.qcow2"), pending["_inspection"], settings.model_dump(), False, lambda _: None,
                            platform_migration=hardware, deferred_platform=pending["deferred_initramfs"])
    if mutation == "digest":
        after["platform"]["kernels"][KERNEL]["initrd_sha256"] = "f" * 64
    elif mutation == "path":
        after["platform"]["kernels"][KERNEL]["initrd"] = "/boot/other.img"
    elif mutation == "kernel":
        after["platform"]["portability"]["hashes"]["/boot/vmlinuz-" + KERNEL] = "sha256:" + "f" * 64
    elif mutation == "kernel_set":
        after["platform"]["kernels"]["other"] = deepcopy(after["platform"]["kernels"][KERNEL])
    elif mutation == "network":
        after["oci_evidence"]["network_ready"] = False
    elif mutation == "grub":
        after["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] += f"linux /vmlinuz-{KERNEL} root=UUID=wrong\n"
    else:
        receipt["verified_initrds"] = {}
    proof = verify_shared_preparation(after, settings, hardware, receipt)
    assert not proof["ready"] and proof["blockers"]


def test_native_shared_rebuild_failure_never_returns_completion(monkeypatch):
    _, settings, hardware, pending, _, _, _ = stage(monkeypatch)
    def fail(*args):
        raise EngineError("Required union driver absent")
    monkeypatch.setattr("forge.engine._run_guest_script", fail)
    with pytest.raises(EngineError, match="union driver absent"):
        prepare_guest(Path("work.qcow2"), pending["_inspection"], settings.model_dump(), False, lambda _: None,
                      platform_migration=hardware, deferred_platform=pending["deferred_initramfs"])


def test_two_kernel_iscsi_path_retains_network_checks_and_hardware_only_drivers(monkeypatch):
    source, settings = combined_image(), configuration()
    hardware = options(target="bare_metal", boot_attachment="iscsi", network_attachment="vfio", nic_driver="mlx5_core")
    for key, value in (("Compute.LaunchMode", "CUSTOM"), ("Network.AttachmentType", "VFIO"), ("Storage.BootVolumeType", "ISCSI")):
        settings.capabilities[key].default_value = value
        settings.capabilities[key].values = [value]
    source["oci_evidence"].update(iscsi_boot_configured=True, iscsi_network_handover=True)
    second = KERNEL + ".second"
    for section in ("platform", "oci_evidence"):
        source[section]["kernels"][second] = deepcopy(source[section]["kernels"][KERNEL])
        source[section]["kernels"][second]["initrd"] = f"/boot/initramfs-{second}.img"
    source["platform"]["portability"]["hashes"]["/boot/vmlinuz-" + second] = "sha256:" + "f" * 64
    plan = plan_platform(source, hardware, False, settings)
    words = _adapt_args(["quiet"], plan, hardware)
    staged = deepcopy(source)
    staged["platform"]["boot_files"]["/etc/default/grub"] = 'GRUB_CMDLINE_LINUX="' + " ".join(words) + '"\n'
    after = deepcopy(staged)
    after["platform"]["generated_grub"]["/boot/grub2/grub.cfg"] = "".join(
        f"linux /vmlinuz-{version} {' '.join(words)}\n" for version in (KERNEL, second))
    for kernel in after["platform"]["kernels"].values():
        kernel["initrd_sha256"] = "b" * 64
    guest, scripts = install_fakes(monkeypatch, [staged, after])
    guest.files.update(source["platform"]["boot_files"])
    pending = prepare_platform(Path("work.qcow2"), source, hardware, False, lambda _: None,
                               oci_config=settings, defer_initramfs_to_oci=True)
    result = prepare_guest(Path("work.qcow2"), pending["_inspection"], settings.model_dump(), False, lambda _: None,
                           platform_migration=hardware, deferred_platform=pending["deferred_initramfs"])
    assert result["combined_verified"] and set(result["verified_initrds"]) == {KERNEL, second}
    assert scripts[1].count("dracut --force") == 2 and "dracut --force" not in scripts[0]
    assert "--add 'iscsi network-manager' --omit 'systemd-networkd network-legacy'" in scripts[1]
    assert scripts[1].count("Required driver nvme absent") == 2
    assert "iSCSI initramfs verification failed" in scripts[1]
    assert "nm-initrd-generator" in scripts[1]
    assert "rd.neednet=1" in staged["platform"]["boot_files"]["/etc/default/grub"]


def test_shared_initramfs_tools_keeps_modules_most_and_updates_before_grub(monkeypatch):
    source, settings, hardware = combined_image(), configuration(), options()
    source["os"]["distro"] = "debian"
    for section in ("platform", "oci_evidence"):
        source[section]["tools"].update({"dracut": False, "update-initramfs": True, "lsinitramfs": True, "update-grub": True})
        source[section]["kernels"][KERNEL]["initrd"] = f"/boot/initrd.img-{KERNEL}"
    source["platform"]["generated_grub"] = {"/boot/grub/grub.cfg": source["platform"]["generated_grub"]["/boot/grub2/grub.cfg"]}
    after = deepcopy(source)
    after["platform"]["kernels"][KERNEL]["initrd_sha256"] = "b" * 64
    guest, scripts = install_fakes(monkeypatch, [source, after])
    pending = prepare_platform(Path("work.qcow2"), source, hardware, False, lambda _: None,
                               oci_config=settings, defer_initramfs_to_oci=True)
    result = prepare_guest(Path("work.qcow2"), pending["_inspection"], settings.model_dump(), False, lambda _: None,
                           platform_migration=hardware, deferred_platform=pending["deferred_initramfs"])
    assert result["combined_verified"]
    assert guest.files["/etc/initramfs-tools/conf.d/zz-cloud-image-forge-platform"] == "MODULES=most\n"
    assert "update-initramfs" not in scripts[0]
    assert scripts[1].count("update-initramfs -u -k") == 1
    assert scripts[1].rfind("update-grub") > scripts[1].find("update-initramfs")
