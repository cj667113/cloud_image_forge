"""Guest ISA policy; disk manipulation does not translate guest executables."""
from __future__ import annotations

import platform


SUPPORTED_ARCHES = ("x86_64", "aarch64")


def normalize_arch(value):
    value = str(value or "unknown").strip().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(value, value)


def worker_arch():
    return normalize_arch(platform.machine())


def execution_blocker(arch):
    guest, worker = normalize_arch(arch), worker_arch()
    if guest not in SUPPORTED_ARCHES:
        return "Guest command execution requires a detected x86_64 or ARM64 (aarch64) image; refresh inspection."
    if worker != guest:
        return (f"This {worker} worker cannot run {guest} guest programs. Use a {guest} Linux worker for "
                "packages, service actions, kernel/GRUB regeneration or guest preparation. "
                "Inspection, configuration-file edits, supported resizing, preservation and export remain available.")
    return None


def execution_capability(arch):
    reason = execution_blocker(arch)
    return {"guest_arch": normalize_arch(arch), "worker_arch": worker_arch(),
            "guest_commands": reason is None, "reason": reason}


def customization_requires_execution(recipe):
    return bool(any(recipe.get(key) for key in (
        "packages_install", "packages_remove", "services", "kernel_default", "rebuild_initramfs", "regenerate_grub"))
        or recipe.get("kernel_args") is not None
        or any(item.get("path") == "/etc/default/grub" for item in recipe.get("files", [])))


def recipe_execution_blocker(inspection, recipe):
    """Re-evaluate the current worker, never trust cached inspection capabilities."""
    platform_options = recipe.get("platform_migration") or {}
    oci = recipe.get("oci")
    migration = recipe.get("boot_migration") or {}
    requires = customization_requires_execution(recipe)
    requires |= bool(platform_options.get("enabled") and platform_options.get("strategy", "reconfigure") != "preserve")
    requires |= oci is not None and oci.get("guest", {}).get("prepare", True)
    requires |= bool(migration.get("enabled") and "UEFI_64" not in inspection.get("boot", {}).get("supported_firmware", []))
    return execution_blocker(inspection.get("os", {}).get("arch")) if requires else None
