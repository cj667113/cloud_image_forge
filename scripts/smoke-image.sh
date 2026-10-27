#!/bin/sh
# Exercise a real Linux image through inspection, customization, and conversion.
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 /path/to/shut-down-linux-image /path/to/new-output-directory" >&2
    exit 2
fi

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "Run this smoke check on Linux x86_64 or inside the supplied container." >&2
    exit 2
fi

for tool in qemu-img virt-customize virt-resize virt-sparsify; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 2; }
done

export LIBGUESTFS_BACKEND=direct
python - "$1" "$2" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

from forge.engine import ImageEngine

source = Path(sys.argv[1]).resolve(strict=True)
destination = Path(sys.argv[2]).resolve()
if not source.is_file():
    raise SystemExit("Source must be an offline image file.")
if destination.exists():
    raise SystemExit("Output directory must not exist; choose a fresh path.")
expected_boot_mode = os.environ.get("FORGE_EXPECT_BOOT_MODE")
if expected_boot_mode and expected_boot_mode not in {"uefi", "bios", "dual", "unknown"}:
    raise SystemExit("FORGE_EXPECT_BOOT_MODE must be uefi, bios, dual, or unknown.")
migration_setting = os.environ.get("FORGE_SMOKE_UEFI_MIGRATION", "0")
if migration_setting not in {"0", "1"}:
    raise SystemExit("FORGE_SMOKE_UEFI_MIGRATION must be 0 or 1.")
migrate_uefi = migration_setting == "1"

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

original_sha = digest(source)
engine = ImageEngine()
try:
    inspection = engine.inspect(source)
finally:
    if digest(source) != original_sha:
        raise RuntimeError("SOURCE CHANGED: read-only inspection immutability check failed")
print(json.dumps(inspection, indent=2))
if expected_boot_mode:
    actual_boot_mode = inspection.get("boot", {}).get("mode")
    if actual_boot_mode != expected_boot_mode:
        raise RuntimeError(f"Boot detection mismatch: expected {expected_boot_mode}, got {actual_boot_mode!r}")
    print(f"PASS: offline boot detection matches the supplied fixture expectation ({expected_boot_mode}).")
if migrate_uefi and inspection.get("boot", {}).get("mode") != "bios":
    raise RuntimeError("The UEFI migration smoke check requires a BIOS-only source fixture.")
destination.mkdir(parents=True)
recipe = {
    "target": "oci", "output_format": "qcow2", "disk_size_gib": None,
    "partition_changes": [], "expand_partition": None, "expand_lv": None,
    "files": [{"path": "/etc/cron.d/cloud-image-forge-smoke", "content": "# Cloud Image Forge offline smoke check; no scheduled commands.\n"}],
    "services": [], "packages_install": [], "packages_remove": [],
    "kernel_default": None, "kernel_args": None, "rebuild_initramfs": False,
    "regenerate_grub": False, "sparsify": False, "compress": True,
    "allow_network": False,
}
if migrate_uefi:
    recipe["boot_migration"] = {"enabled": True, "esp_size_mib": 512, "install_packages": False}
try:
    result = engine.build(source, destination, inspection, recipe, print)
finally:
    if digest(source) != original_sha:
        raise RuntimeError("SOURCE CHANGED: original image immutability check failed")

artifact = Path(result["artifact_path"])
if digest(artifact) != result["sha256"]:
    raise RuntimeError("Artifact digest does not match engine result")

import guestfs
g = guestfs.GuestFS(python_return_dict=True)
try:
    g.add_drive_opts(str(artifact), format="qcow2", readonly=True)
    g.launch()
    if migrate_uefi:
        from forge.boot import detect_boot
        boot = detect_boot(g)
        if set(boot["supported_firmware"]) != {"UEFI_64", "BIOS"}:
            raise RuntimeError("Migrated output must have UEFI support and retain its detected BIOS support")
        if not any(loader["fallback"] for loader in boot["efi_loaders"]):
            raise RuntimeError("Migrated output has no detected x86_64 EFI fallback loader")
        print("PASS: migrated output has an EFI fallback loader and retains detected BIOS support.")
    roots = g.inspect_os()
    if len(roots) != 1:
        raise RuntimeError("Expected one inspectable operating system")
    mounts = g.inspect_get_mountpoints(roots[0])
    for mountpoint, device in sorted(mounts.items(), key=lambda item: len(item[0])):
        g.mount_ro(device, mountpoint)
    expected = recipe["files"][0]["content"]
    actual = g.read_file("/etc/cron.d/cloud-image-forge-smoke")
    if isinstance(actual, bytes):
        actual = actual.decode()
    if actual != expected:
        raise RuntimeError("Guest customization was not persisted")
finally:
    g.close()

print(json.dumps(result, indent=2))
print("PASS: source unchanged, guest edit persisted, artifact SHA-256 verified.")
print("This check does not boot the guest or import it into a cloud provider.")
PY
