"""Architecture admission and execution boundaries are independent of the host."""
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from forge.architecture import execution_capability, normalize_arch, recipe_execution_blocker
from forge.engine import EngineError, ImageEngine, _relabel_edited_files, _validate_recipe


@pytest.mark.parametrize("raw,expected", [("amd64", "x86_64"), ("ARM64", "aarch64"),
                                         ("aarch64", "aarch64"), ("arm", "arm"), (None, "unknown")])
def test_architecture_aliases_do_not_promote_32_bit_images(raw, expected):
    assert normalize_arch(raw) == expected


@pytest.mark.parametrize("worker,guest,allowed", [("x86_64", "aarch64", False), ("aarch64", "x86_64", False),
                                                 ("aarch64", "arm64", True), ("x86_64", "amd64", True)])
def test_live_worker_decides_execution_not_cached_inspection(monkeypatch, worker, guest, allowed):
    monkeypatch.setattr("forge.architecture.worker_arch", lambda: worker)
    info = {"os": {"arch": guest}, "execution": {"guest_commands": not allowed}}
    assert execution_capability(guest)["guest_commands"] is allowed
    error = recipe_execution_blocker(info, {"rebuild_initramfs": True})
    assert bool(error) is not allowed
    assert recipe_execution_blocker(info, {"files": [{"path": "/etc/cron.d/check", "content": "# check\n"}]}) is None


@pytest.mark.parametrize("recipe", [
    {"packages_install": ["kernel"], "allow_network": True}, {"packages_remove": ["kernel"]},
    {"services": [{"name": "sshd.service", "action": "enable"}]}, {"kernel_args": ""},
    {"kernel_default": "/boot/vmlinuz-test"}, {"rebuild_initramfs": True}, {"regenerate_grub": True},
    {"files": [{"path": "/etc/default/grub", "content": "# changed\n"}]},
    {"oci": {}}, {"platform_migration": {"enabled": True}}, {"boot_migration": {"enabled": True}},
])
def test_foreign_guest_programs_reject_before_writes(recipe):
    info = {"os": {"arch": "aarch64"}}
    with patch("forge.engine._guest") as guest, patch("forge.engine._run") as run:
        with pytest.raises(EngineError, match="aarch64 Linux worker"):
            _validate_recipe(recipe, info)
        guest.assert_not_called()
        run.assert_not_called()


def test_foreign_file_edit_uses_appliance_labeling_without_guest_execution():
    g = Mock()
    g.is_file.side_effect = lambda path: path in {"/etc/selinux/config", "/etc/selinux/targeted/contexts/files/file_contexts"}
    g.filesize.return_value = 64
    g.read_file.return_value = b"SELINUX=enforcing\nSELINUXTYPE=targeted\n"

    @contextmanager
    def guest(*args, **kwargs):
        yield g

    with patch("forge.engine._guest", guest), patch("forge.engine._mount"), patch("forge.engine._roots"), \
            patch("forge.engine._write_guest") as write, patch("forge.engine._run") as run:
        ImageEngine()._customize(Path("working.qcow2"), {"os": {"arch": "aarch64"}},
                                 {"files": [{"path": "/etc/cron.d/check", "content": "# changed\n"}]}, lambda _: None)
        write.assert_called_once_with(g, "/etc/cron.d/check", "# changed\n")
        g.selinux_relabel.assert_called_once_with("/etc/selinux/targeted/contexts/files/file_contexts", "/etc/cron.d/check", force=True)
        run.assert_not_called()


def test_foreign_unsupported_selinux_policy_fails_closed():
    g = Mock()
    g.is_file.return_value = True
    g.filesize.return_value = 64
    g.read_file.return_value = b"SELINUX=enforcing\nSELINUXTYPE=$(guest-command)\n"
    with pytest.raises(EngineError, match="cannot be resolved"):
        _relabel_edited_files(g, ["/etc/cron.d/check"])
    g.selinux_relabel.assert_not_called()


def test_health_reports_native_commands_and_both_disk_architectures(monkeypatch):
    monkeypatch.setattr("forge.architecture.worker_arch", lambda: "aarch64")
    capability = ImageEngine().capabilities()
    assert capability["worker_arch"] == "aarch64"
    assert capability["guest_architectures"] == ["x86_64", "aarch64"]
    assert capability["guest_execution_architectures"] == ["aarch64"]
