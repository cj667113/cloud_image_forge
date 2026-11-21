#!/usr/bin/env python3
"""Standalone companion: import an uploaded image and apply its public shapes.

This file is copied into OCI configuration ZIPs as apply-oci.py. It needs
Python 3 and a configured OCI CLI; it never uploads disks or launches instances.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


class ApplyError(ValueError):
    pass


def _load(path):
    if path.stat().st_size > 1024 * 1024:
        raise ApplyError(f"Configuration is too large: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _save(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".oci-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def _lock(path):
    # The operator tool targets the Linux/macOS environments supported by OCI
    # CLI. An OS lock releases on crashes without permitting concurrent imports.
    import fcntl
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ApplyError("Another copy is applying this bundle") from exc
        yield


def _image_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"ocid1\.image\.[A-Za-z0-9._-]+", value):
        raise ApplyError("A valid imported image OCID is required")
    return value


def _constraints(value, memory=False):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ApplyError("Invalid shape constraints")
    aliases = {"min-in-gbs": "minInGBs", "max-in-gbs": "maxInGBs"} if memory else {}
    result = {aliases.get(key, key): item for key, item in value.items() if item is not None}
    lower, upper = ("minInGBs", "maxInGBs") if memory else ("min", "max")
    if set(result) - {lower, upper} or any(type(item) is not int or item < 1 for item in result.values()):
        raise ApplyError("Shape limits must be positive integers in OCPUs or GiB")
    if lower in result and upper in result and result[lower] > result[upper]:
        raise ApplyError("Minimum shape limit exceeds maximum")
    return result


def _entries(manifest):
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        raise ApplyError("Unsupported shape compatibility manifest")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) > 100:
        raise ApplyError("Invalid shape compatibility entries")
    seen, result = set(), []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - {"shapeName", "ocpuConstraints", "memoryConstraints"}:
            raise ApplyError("Unexpected shape entry fields")
        name = entry.get("shapeName")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", name) or name in seen:
            raise ApplyError("Invalid or duplicate shape name")
        seen.add(name)
        result.append({"shapeName": name,
                       "ocpuConstraints": _constraints(entry.get("ocpuConstraints")),
                       "memoryConstraints": _constraints(entry.get("memoryConstraints"), True)})
    return result


def _placeholder(value):
    if isinstance(value, str):
        return "REPLACE_" in value
    if isinstance(value, dict):
        return any(_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_placeholder(item) for item in value)
    return False


def _matches(actual, desired):
    return all(all(actual[key].get(name) == value for name, value in desired[key].items())
               for key in ("ocpuConstraints", "memoryConstraints"))


def apply(bundle, *, image_id=None, import_image=False, import_archive=False, profile=None, region=None,
          exact_shapes=False, timeout=3600, run=subprocess.run, sleep=time.sleep):
    """Apply the selected shapes and optionally remove other associations."""
    bundle = Path(bundle).resolve()
    manifest = _load(bundle / "shape-compatibility.json")
    entries = _entries(manifest)
    wanted = {entry["shapeName"] for entry in entries}
    if exact_shapes and not wanted:
        raise ApplyError("--exact-shapes requires at least one selected shape")
    if exact_shapes:
        arch = manifest.get("architecture")
        required = manifest.get("shapeArchitectures") or {}
        if arch not in {"aarch64", "x86_64"} or not isinstance(required, dict) or any(required.get(name) != arch for name in wanted):
            raise ApplyError("--exact-shapes requires a verified guest architecture matching every selected shape")
    imports = _load(bundle / "image-import.json")
    if not isinstance(imports, dict):
        raise ApplyError("Invalid image import configuration")
    if image_id is not None:
        image_id = _image_id(image_id)
    if sum(bool(mode) for mode in (image_id, import_image, import_archive)) > 1:
        raise ApplyError("Choose an existing image or a new import")
    identity = {"imports": imports, "entries": entries, "profile": profile, "region": region}
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True, allow_nan=False).encode()).hexdigest()
    state_path = bundle / ".forge-oci-apply-state.json"
    prefix = ["oci"]
    for flag, value in (("--profile", profile), ("--region", region)):
        if value:
            prefix += [flag, value]

    def cli(arguments, payload=None):
        with tempfile.TemporaryDirectory(prefix=".oci-request-", dir=bundle) as directory:
            command = prefix + arguments + ["--output", "json", "--no-retry"]
            if payload is not None:
                path = Path(directory) / "request.json"
                _save(path, payload)
                command += ["--from-json", "file://" + str(path)]
            try:
                response = run(command, capture_output=True, text=True, timeout=120, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ApplyError("OCI command did not finish; saved state prevents duplicate import. Rerun to resume, or supply --image-id if the import outcome is unknown.") from exc
            if response.returncode:
                # OCI errors can repeat a private object URI. Do not echo them.
                raise ApplyError(f"OCI {' '.join(arguments[:4])} failed (exit {response.returncode}); state is saved. Check the OCI console/CLI credentials, then resume.")
            if arguments[:3] == ["compute", "image-shape-compatibility-entry", "remove"]:
                return  # This operation has no response body.
            if not response.stdout.strip() and arguments[:3] == ["compute", "image-shape-compatibility-entry", "list"]:
                return []
            try:
                value = json.loads(response.stdout)
                return value["data"]
            except (ValueError, KeyError, TypeError) as exc:
                raise ApplyError("OCI returned an unexpected JSON response; state is saved") from exc

    with _lock(bundle / ".forge-oci-apply.lock"):
        state = _load(state_path) if state_path.exists() else {"version": 1, "fingerprint": fingerprint}
        if state.get("fingerprint") != fingerprint:
            raise ApplyError("Bundle or CLI profile/region changed since the saved run; use a separate extracted bundle for a different import")
        if (import_image or import_archive) and state.get("import_started") and bool(state.get("archive_import")) != import_archive:
            raise ApplyError("This bundle already tracks an import in another format. Resume with the original command or --image-id")
        if image_id:
            if state.get("image_id") and state["image_id"] != image_id:
                raise ApplyError("This bundle already tracks a different imported image")
            state["image_id"] = image_id
            _save(state_path, state)
        if state.pop("completed", False):
            state.pop("verified_shapes", None)
            _save(state_path, state)
        if not state.get("image_id"):
            if state.get("import_started"):
                raise ApplyError("The previous import outcome is unknown. Find that image in OCI and rerun with --image-id; another import will not be submitted")
            if not (import_image or import_archive):
                raise ApplyError("Use --import-image, --import-archive or --image-id IMAGE_OCID")
            if _placeholder(imports):
                raise ApplyError("Fill in the REPLACE_* values in image-import.json before importing")
            if import_archive:
                # The configured location must point to the uploaded archive.
                imports.pop("sourceImageType", None)
            if imports.get("sourceImageType") not in (None, "QCOW2", "VMDK"):
                raise ApplyError("The OCI CLI only accepts QCOW2/VMDK sourceImageType; omit that field for an OCI archive")
            method = "from-object-uri" if imports.get("uri") else "from-object"
            required = {"compartmentId", "uri"} if method == "from-object-uri" else {"compartmentId", "namespace", "bucketName", "name"}
            if not all(isinstance(imports.get(key), str) and imports[key] for key in required):
                raise ApplyError("Image import configuration lacks its compartment or object location")
            state["archive_import"] = import_archive
            state["import_started"] = True
            _save(state_path, state)
            imported = cli(["compute", "image", "import", method], imports)
            state["image_id"] = _image_id(imported.get("id") if isinstance(imported, dict) else None)
            _save(state_path, state)  # Save the OCID before any wait or shape write.
        image_id = _image_id(state["image_id"])
        deadline = time.monotonic() + timeout
        while True:
            image = cli(["compute", "image", "get", "--image-id", image_id])
            if not isinstance(image, dict) or image.get("id") != image_id:
                raise ApplyError("OCI returned a different image")
            lifecycle = image.get("lifecycle-state", image.get("lifecycleState"))
            if lifecycle == "AVAILABLE":
                break
            if lifecycle not in {"IMPORTING", "PROVISIONING", "CREATING"}:
                raise ApplyError(f"Imported image is not available: {lifecycle}")
            if time.monotonic() >= deadline:
                raise ApplyError("Timed out waiting for AVAILABLE; rerun the same command to resume without another import")
            sleep(10)

        def current():
            rows = cli(["compute", "image-shape-compatibility-entry", "list", "--image-id", image_id, "--all"])
            if not isinstance(rows, list):
                raise ApplyError("OCI shape list is not an array")
            result = {}
            for row in rows:
                name = row.get("shape") if isinstance(row, dict) else None
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name) or name in result:
                    raise ApplyError("OCI shape list contains malformed or duplicate entries")
                if name not in wanted:
                    result[name] = {}  # Service defaults can have fractional bounds.
                    continue
                result[name] = {
                    "ocpuConstraints": _constraints(row.get("ocpu-constraints", row.get("ocpuConstraints"))),
                    "memoryConstraints": _constraints(row.get("memory-constraints", row.get("memoryConstraints")), True)}
            return result

        actual = current()
        expected = []
        for desired in entries:
            name = desired["shapeName"]
            payload = {"imageId": image_id, "shapeName": name}
            retained = {"shapeName": name}
            for key in ("ocpuConstraints", "memoryConstraints"):
                # Preserve existing bounds that the bundle did not specify.
                bounds = {**actual.get(name, {}).get(key, {}), **desired[key]}
                retained[key] = _constraints(bounds, key == "memoryConstraints")
                if bounds:
                    payload[key] = retained[key]
            expected.append(retained)
            if name in actual and _matches(actual[name], desired):
                continue
            cli(["compute", "image-shape-compatibility-entry", "add", "--force"], payload)
            state["last_applied_shape"] = name
            _save(state_path, state)
        def verified():
            actual = current()
            if any(row["shapeName"] not in actual or not _matches(actual[row["shapeName"]], row) for row in expected):
                raise ApplyError("OCI did not retain every requested shape and limit; rerun to recheck/apply missing entries")
            return actual

        actual = verified()
        removed = []
        if exact_shapes:
            for name in sorted(actual.keys() - wanted):
                cli(["compute", "image-shape-compatibility-entry", "remove", "--image-id", image_id,
                     "--shape-name", name, "--force"])
                removed.append(name)
            if removed:
                actual = verified()
            if actual.keys() - wanted:
                raise ApplyError("OCI still lists additional shapes; rerun to reconcile the current list")
        state.update(completed=True, verified_shapes=[row["shapeName"] for row in entries])
        _save(state_path, state)
        return {"image_id": image_id, "verified_shapes": state["verified_shapes"],
                "additional_shapes": sorted(actual.keys() - wanted), "removed_shapes": removed,
                "unrelated_shapes_removed": bool(removed)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--import-image", action="store_true", help="Import the uploaded object specified in image-import.json")
    mode.add_argument("--import-archive", action="store_true", help="Import a .oci archive at the configured Object Storage location and apply the selected shapes")
    mode.add_argument("--image-id", help="Apply shapes to an existing imported image")
    parser.add_argument("--exact-shapes", action="store_true",
                        help="Remove other compatible shapes after verifying all shapes in this bundle")
    parser.add_argument("--profile", help="OCI CLI profile")
    parser.add_argument("--region", help="OCI region")
    parser.add_argument("--timeout", type=int, default=3600, help="Seconds to wait for AVAILABLE")
    args = parser.parse_args()
    if not 0 < args.timeout <= 86400:
        parser.error("timeout must be between 1 and 86400 seconds")
    try:
        result = apply(Path(__file__).parent, **vars(args))
    except (ApplyError, OSError, ValueError) as exc:
        parser.exit(1, str(exc) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
