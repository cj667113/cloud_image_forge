"""Offline Linux image inspection and transformations.

Guest filesystems are only opened inside a libguestfs appliance. The original
image is never writable; every build starts with a standalone working copy.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import struct
import subprocess
import tarfile
import tempfile
from typing import Callable
from uuid import uuid4


MIB = 1024 * 1024
GIB = 1024 * MIB
CONFIG_FILES = (
    "/etc/fstab", "/etc/default/grub", "/etc/crontab",
    "/etc/modules-load.d/cloud-image-forge.conf",
    "/etc/modprobe.d/cloud-image-forge.conf",
)
TOOLS = ("qemu-img", "virt-resize", "virt-customize", "virt-sparsify")
DEVICE = re.compile(r"/dev/[A-Za-z0-9_+./-]+\Z")
PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+:=~%-]*\Z")
SERVICE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*\.(service|timer|socket|target)\Z")


class EngineError(ValueError):
    """An image or recipe cannot safely be processed."""


def _run(args: list[str], log: Callable[[str], None] | None = None) -> str:
    env = dict(os.environ, LIBGUESTFS_BACKEND="direct")
    if log:
        log("Running " + args[0])
    def terminate_group(process):
        # virt-* tools start QEMU children; terminating only the parent leaves
        # those children holding open an image after the job has failed.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

    def read_tail(stream):
        length = stream.tell()
        stream.seek(max(0, length - 2 * MIB))
        return stream.read().decode("utf-8", errors="replace")

    # Spool tool output to temporary files, bounding retained output in memory.
    # In particular, guest package-manager output must not fill the API heap.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(args, stdout=stdout, stderr=stderr, env=env,
                                       start_new_session=True)
        except FileNotFoundError as exc:
            raise EngineError(f"Missing {args[0]}; use the Linux Docker deployment.") from exc
        try:
            process.wait(timeout=int(os.getenv("FORGE_COMMAND_TIMEOUT", "7200")))
        except subprocess.TimeoutExpired as exc:
            terminate_group(process)
            raise EngineError(f"{args[0]} exceeded the configured execution timeout; its process group was stopped.") from exc
        except BaseException:
            terminate_group(process)
            raise
        output, error = read_tail(stdout), read_tail(stderr)
        if process.returncode:
            detail = (error or output).strip()[-5000:]
            raise EngineError(f"{args[0]} failed ({process.returncode}): {detail}")
        return output


def _input_format(path: Path) -> str:
    """Read headers before QEMU can follow references to external host files."""
    if not path.is_file() or path.is_symlink():
        raise EngineError("Image must be a regular, non-symlink file.")
    with path.open("rb") as stream:
        header = stream.read(512)
        if len(header) < 512:
            raise EngineError("Image is too short to contain a disk.")
        stream.seek(-512, os.SEEK_END)
        footer = stream.read(512)
    if header[:4] == b"QFI\xfb":
        version = struct.unpack_from(">I", header, 4)[0]
        backing_offset, backing_size = struct.unpack_from(">QI", header, 8)
        encrypted = struct.unpack_from(">I", header, 32)[0]
        if version not in (2, 3):
            raise EngineError("Only QCOW2 versions 2 and 3 are supported.")
        if backing_offset or backing_size:
            raise EngineError("Backing-file images are not accepted; flatten the image before importing.")
        if encrypted:
            raise EngineError("Encrypted images are not supported.")
        if version == 3:
            features = struct.unpack_from(">Q", header, 72)[0]
            if features & 4:
                raise EngineError("QCOW2 external data files are not accepted.")
            if features & 2:
                raise EngineError("QCOW2 is marked corrupt.")
            if features & ~31:
                raise EngineError("Unsupported QCOW2 incompatible features.")
        return "qcow2"
    if footer[:8] == b"conectix" or header[:8] == b"conectix":
        selected = footer if footer[:8] == b"conectix" else header
        disk_type = struct.unpack_from(">I", selected, 60)[0]
        if disk_type not in (2, 3):
            raise EngineError("Only standalone fixed or dynamic VHD is supported; differencing VHD is rejected.")
        return "vpc"
    if (header.startswith((b"KDMV", b"COWD", b"# Disk DescriptorFile", b"vhdxfile", b"QED\x00"))
            or path.suffix.lower() in {".vmdk", ".vdi", ".vhdx", ".ova", ".oci", ".tar", ".gz"}
            or b"Oracle VM VirtualBox Disk Image" in header):
        raise EngineError("Import a standalone QCOW2, raw disk, or VHD file; archives and VMDK are not supported.")
    return "raw"


def _image_info(path: Path, fmt: str | None = None) -> dict:
    fmt = fmt or _input_format(path)
    info = json.loads(_run(["qemu-img", "info", "--output=json", "-f", fmt, str(path)]))
    if info.get("backing-filename") or info.get("full-backing-filename") or info.get("encrypted"):
        raise EngineError("Image must be standalone and unencrypted.")
    data = info.get("format-specific", {}).get("data", {})
    if data.get("data-file") or data.get("encrypt"):
        raise EngineError("External data and encrypted images are unsupported.")
    size = info.get("virtual-size", 0)
    max_size = int(os.getenv("FORGE_MAX_VIRTUAL_GIB", "2048")) * GIB
    if not 0 < size <= max_size:
        raise EngineError(f"Virtual disk size must be at most {max_size // GIB} GiB.")
    return info


@contextmanager
def _guest(path: Path, fmt: str, readonly: bool = True):
    try:
        import guestfs
    except ImportError as exc:
        raise EngineError("Python libguestfs is unavailable; use the Linux Docker deployment.") from exc
    handle = guestfs.GuestFS(python_return_dict=True)
    try:
        handle.set_backend("direct")
        handle.set_network(False)
        handle.add_drive_opts(str(path), format=fmt, readonly=readonly)
        handle.launch()
        yield handle
        if not readonly:
            handle.sync()
        handle.umount_all()
        handle.shutdown()
    finally:
        handle.close()


def _mount(handle, root: str, readonly: bool) -> dict:
    points = handle.inspect_get_mountpoints(root)
    for mountpoint, device in sorted(points.items(), key=lambda item: len(item[0])):
        if not mountpoint.startswith("/") or ".." in PurePosixPath(mountpoint).parts:
            raise EngineError("Invalid mountpoint in guest filesystem.")
        try:
            if readonly:
                handle.mount_ro(device, mountpoint)
            else:
                handle.mount(device, mountpoint)
        except RuntimeError as exc:
            raise EngineError(f"Unable to mount guest {mountpoint} ({device}); all configured local filesystems must be available.") from exc
    return points


def _roots(handle) -> str:
    roots = handle.inspect_os()
    if len(roots) != 1:
        raise EngineError("Exactly one Linux operating system on one standalone disk is required.")
    if handle.inspect_get_type(roots[0]) != "linux":
        raise EngineError("Only Linux guest operating systems are supported.")
    if handle.inspect_get_arch(roots[0]) != "x86_64":
        raise EngineError("This deployment supports x86_64 Linux guests only; use an amd64 Linux host or Docker VM.")
    return roots[0]


def _allowed_file(path: str) -> bool:
    return path in CONFIG_FILES or bool(re.fullmatch(
        r"/etc/(cron\.d/[A-Za-z0-9_-]+|systemd/system/[A-Za-z0-9_][A-Za-z0-9_.@:-]*\.service)", path))


def _validate_fstab(content: str, handle=None) -> None:
    """Check edited fstab syntax and mandatory local filesystem identities.

    This intentionally does not claim to validate filesystem-specific options,
    remote mounts, PARTUUID, direct device aliases, or the eventual cloud boot.
    """
    for number, line in enumerate(content.splitlines(), 1):
        fields = []
        for field in line.split():
            if field.startswith("#"):
                break
            fields.append(field)
        if not fields:
            continue
        if not 4 <= len(fields) <= 6:
            raise EngineError(f"fstab line {number} needs 4–6 whitespace-separated fields; escape spaces as \\040.")
        source, mountpoint, filesystem, options = fields[:4]
        if any(not re.fullmatch(r"[0-9]+", value) for value in fields[4:]):
            raise EngineError(f"fstab line {number} dump and fsck fields must be nonnegative integers.")
        if not mountpoint.startswith("/") and not (filesystem == "swap" and mountpoint in {"none", "swap", "-"}):
            raise EngineError(f"fstab line {number} needs an absolute mountpoint (or 'none' for swap).")
        if not handle:
            continue
        optional = bool({"noauto", "nofail", "_netdev"} & set(options.split(",")))
        if optional and mountpoint != "/":
            continue
        tag, _, identity = source.partition("=")
        if tag not in {"UUID", "LABEL"}:
            continue
        if len(identity) >= 2 and identity[0] == identity[-1] and identity[0] in "\"'":
            identity = identity[1:-1]
        identity = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), identity)
        if not identity or "\x00" in identity:
            raise EngineError(f"fstab line {number} has an invalid filesystem identity.")
        try:
            finder = handle.findfs_uuid if tag == "UUID" else handle.findfs_label
            finder(identity)
        except RuntimeError as exc:
            raise EngineError(f"fstab line {number}: required {source} for {mountpoint} does not exist in the image. Use the correct identity, or nofail/noauto for a future optional volume.") from exc


def _write_guest(handle, path: str, content: str) -> None:
    if not _allowed_file(path):
        raise EngineError(f"Editing {path} is not allowed.")
    if len(content.encode()) > MIB or "\x00" in content:
        raise EngineError("Configuration files must be UTF-8 text, at most 1 MiB, without NUL bytes.")
    if path == "/etc/fstab":
        _validate_fstab(content, handle)
    if handle.is_symlink(path):
        raise EngineError(f"Refusing to replace symlink {path}; use a regular configuration file.")
    metadata = handle.statns(path) if handle.is_file(path) else None
    handle.mkdir_p(str(PurePosixPath(path).parent))
    # guestfs.write truncates the existing inode, retaining its extended attributes.
    handle.write(path, content.encode())
    if metadata:
        handle.chmod(metadata["st_mode"] & 0o7777, path)
        handle.chown(metadata["st_uid"], metadata["st_gid"], path)
    else:
        handle.chmod(0o644, path)
        handle.chown(0, 0, path)


def _grub_assignment(content: str, name: str, value: str) -> str:
    line = f"{name}={shlex.quote(value)}"
    pattern = re.compile(rf"^{re.escape(name)}=.*$", re.MULTILINE)
    if pattern.search(content):
        return pattern.sub(lambda _: line, content)
    return content.rstrip("\n") + "\n" + line + "\n"


def _validate_recipe(recipe: dict, inspection: dict) -> None:
    platform = recipe.get("platform_migration") or {}
    if platform.get("enabled") and platform.get("strategy", "reconfigure") == "preserve":
        if any(platform.get(name, False) for name in ("install_packages", "configure_network", "configure_serial_console")):
            raise EngineError("Preserve and validate cannot request hardware configuration changes; select Reconfigure.")
        if recipe.get("oci") is not None and recipe["oci"].get("guest", {}).get("prepare", True):
            raise EngineError("Preserve and validate requires OCI guest preparation disabled.")
    target = recipe.get("target", "generic")
    fmt = recipe.get("output_format", "qcow2")
    target_formats = {"oci": "qcow2", "aws": "raw", "azure": "vhd", "gcp": "gcp"}
    if target not in {*target_formats, "generic"} or fmt not in {"qcow2", "raw", "vhd", "gcp"}:
        raise EngineError("Unknown export target or format.")
    if target in target_formats and fmt != target_formats[target]:
        raise EngineError(f"{target} requires {target_formats[target]} output.")
    if recipe.get("oci") is not None and target != "oci":
        raise EngineError("OCI capability preparation requires the OCI export target.")
    size = recipe.get("disk_size_gib")
    if size is not None and (not math.isfinite(size) or not 0 < size <= int(os.getenv("FORGE_MAX_VIRTUAL_GIB", "2048"))):
        raise EngineError("Requested virtual disk size is outside the allowed range.")
    if (recipe.get("storage_rebuild") or {}).get("enabled"):
        from .storage import plan_rebuild
        if recipe.get("partition_changes") or recipe.get("expand_partition") or recipe.get("expand_lv"):
            raise EngineError("Filesystem rebuild cannot be combined with direct partition or LV expansion actions.")
        storage_plan = plan_rebuild(inspection, recipe["storage_rebuild"], size)
        if not storage_plan["ready"]:
            raise EngineError("Storage rebuild blocked: " + " ".join(storage_plan["blockers"]))
    for item in recipe.get("files", []):
        if not _allowed_file(item["path"]):
            raise EngineError(f"Editing {item['path']} is not allowed.")
        if item["path"] == "/etc/fstab":
            _validate_fstab(item["content"])
    seen = set()
    known = {p["device"]: p for p in inspection.get("partitions", [])}
    for item in recipe.get("partition_changes", []):
        dev, size_mib = item["device"], item["size_mib"]
        if dev in seen or dev not in known or not re.fullmatch(r"/dev/sda[1-9][0-9]*", dev):
            raise EngineError("Partition changes must name unique inspected /dev/sda partitions.")
        if not math.isfinite(size_mib) or size_mib < 16:
            raise EngineError("Partition sizes must be at least 16 MiB.")
        if int(size_mib * MIB) < known[dev]["size"] and known[dev].get("filesystem") not in {"ext2", "ext3", "ext4"}:
            raise EngineError("Direct shrinking requires an ext2/3/4 partition. For XFS and LVM, enable filesystem rebuild and review its supported-layout checks.")
        seen.add(dev)
    expand = recipe.get("expand_partition")
    if expand and (expand not in known or expand in seen or not re.fullmatch(r"/dev/sda[1-9][0-9]*", expand)):
        raise EngineError("Expansion must name an inspected partition without a separate size change.")
    lv = recipe.get("expand_lv")
    if lv and (lv not in known or not known[lv].get("logical_volume") or not expand):
        raise EngineError("LV expansion requires an inspected logical volume and a partition to expand.")
    for item in recipe.get("services", []):
        if not SERVICE.fullmatch(item["name"]) or item["action"] not in {"enable", "disable", "mask", "unmask"}:
            raise EngineError("Invalid systemd unit or action.")
    for package in recipe.get("packages_install", []) + recipe.get("packages_remove", []):
        if not PACKAGE.fullmatch(package):
            raise EngineError("Invalid package name.")
    if recipe.get("packages_install") and not recipe.get("allow_network"):
        raise EngineError("Package installation requires explicit guest network access.")
    kernel = recipe.get("kernel_default")
    if kernel and (kernel not in inspection.get("kernels", []) or not re.fullmatch(r"/boot/vmlinuz-[A-Za-z0-9_.+~-]+", kernel)):
        raise EngineError("Default kernel must name an inspected installed /boot/vmlinuz-* image.")


class ImageEngine:
    def capabilities(self) -> dict:
        missing = [name for name in TOOLS if not shutil.which(name)]
        if importlib.util.find_spec("guestfs") is None:
            missing.append("python3-guestfs")
        return {"available": not missing, "missing": missing,
                "input_formats": ["qcow2", "raw", "vhd"],
                "output_formats": ["qcow2", "raw", "vhd", "gcp"],
                "kvm": os.access("/dev/kvm", os.R_OK | os.W_OK),
                "resize": "Partition and LVM growth, offline ext2/3/4 shrink, and a validated filesystem rebuild for supported GPT/UEFI XFS and LVM layouts."}

    def inspect(self, path: Path) -> dict:
        path = Path(path)
        fmt = _input_format(path)
        path = path.resolve()
        info = _image_info(path, fmt)
        if fmt == "qcow2":
            _run(["qemu-img", "check", "-f", fmt, str(path)])
        with _guest(path, fmt) as g:
            from .boot import detect_boot
            from .uefi import inspect_layout, inspect_prerequisites
            boot = detect_boot(g)
            migration_layout = inspect_layout(g)
            root = _roots(g)
            filesystems = g.list_filesystems()
            points = _mount(g, root, True)
            partitions = []
            lvs = g.lvs()
            for device in list(g.list_partitions()) + list(lvs):
                mountpoint = next((mp for mp, dev in points.items() if dev == device), None)
                try:
                    uuid = g.vfs_uuid(device)
                except RuntimeError:
                    uuid = None
                partition = {"device": device, "size": g.blockdev_getsize64(device),
                             "filesystem": filesystems.get(device, "unknown"),
                             "mountpoint": mountpoint, "uuid": uuid,
                             "logical_volume": device in lvs}
                if mountpoint:
                    stats = g.statvfs(mountpoint)
                    partition["used"] = (stats["blocks"] - stats["bfree"]) * stats["frsize"]
                    partition["free"] = stats["bavail"] * stats["frsize"]
                partitions.append(partition)
            files = {}
            editable = list(CONFIG_FILES)
            for directory, suffix in (("/etc/cron.d", ""), ("/etc/systemd/system", ".service")):
                if g.is_dir(directory):
                    editable.extend(f"{directory}/{name}" for name in g.ls(directory)
                                    if name.endswith(suffix) and _allowed_file(f"{directory}/{name}"))
            for filename in editable:
                if g.is_file(filename) and not g.is_symlink(filename) and g.filesize(filename) <= MIB:
                    value = g.read_file(filename)
                    files[filename] = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
                elif filename in CONFIG_FILES:
                    files[filename] = ""
            services = set()
            for directory in ("/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"):
                if g.is_dir(directory):
                    services.update(name for name in g.ls(directory) if SERVICE.fullmatch(name))
            from .systemd import inspect_systemd
            systemd = inspect_systemd(g)
            os_info = {"name": g.inspect_get_product_name(root), "distro": g.inspect_get_distro(root),
                       "arch": g.inspect_get_arch(root), "root": root}
            kernels = sorted(g.glob_expand("/boot/vmlinuz-*"))
            from .oci_guest import inspect_guest
            oci_evidence = inspect_guest(g, root, partitions, kernels, boot=boot)
            try:
                migration_guest = inspect_prerequisites(g, root, partitions, migration_layout)
            except RuntimeError as exc:
                migration_guest = {"errors": [f"Cannot inspect optional UEFI migration prerequisites: {exc}"]}
            from .storage import inspect_storage
            from .platform import inspect_platform
            storage = inspect_storage(g, root, partitions, migration_layout)
            platform = inspect_platform(g, root, partitions, kernels, oci_evidence=oci_evidence)
        return {"format": fmt, "virtual_size": info["virtual-size"],
                "actual_size": path.stat().st_size, "allocated_size": info.get("actual-size"),
                "os": os_info, "partitions": partitions, "files": files,
                "services": sorted(services), "systemd": systemd, "kernels": kernels, "oci_evidence": oci_evidence, "boot": boot,
                "uefi_migration": {"version": 1, "layout": migration_layout, "guest": migration_guest},
                "storage": storage, "platform": platform,
                "warnings": ["Bootability and cloud-agent compatibility require a test launch after export."]}

    def _resize(self, work: Path, destination: Path, inspection: dict, recipe: dict, log) -> Path:
        if (recipe.get("storage_rebuild") or {}).get("enabled"):
            from .storage import rebuild
            rebuilt = rebuild(work, destination / f"rebuilt-{uuid4().hex}.qcow2", inspection, recipe, log)
            if rebuilt != work:
                work.unlink()
            return rebuilt
        old_size = inspection["virtual_size"]
        new_size = int(recipe["disk_size_gib"] * GIB) if recipe.get("disk_size_gib") else old_size
        changes = recipe.get("partition_changes", [])
        expand = recipe.get("expand_partition")
        if not changes and not expand and new_size == old_size:
            return work
        if new_size < old_size and not changes:
            raise EngineError("Disk shrink requires explicit ext2/3/4 partition size changes; truncation is never used.")
        known = {p["device"]: p for p in inspection["partitions"]}
        shrink = [item for item in changes if int(item["size_mib"] * MIB) < known[item["device"]]["size"]]
        if shrink:
            log("Shrinking ext filesystems offline in the disposable working copy")
            with _guest(work, "qcow2", readonly=False) as g:
                for item in shrink:
                    # Leave 1 MiB below the partition boundary for alignment rounding.
                    size = (int(item["size_mib"] * MIB) // 1024) * 1024 - MIB
                    g.e2fsck(item["device"], forceall=True)
                    g.resize2fs_size(item["device"], size)
        if not changes and not expand and new_size > old_size:
            # virt-resize also relocates GPT backup metadata; qemu-img resize alone does not.
            log("Growing disk capacity; partition sizes remain as specified")
        resized = destination / f"resized-{uuid4().hex}.qcow2"
        _run(["qemu-img", "create", "-f", "qcow2", str(resized), str(new_size)], log)
        command = ["virt-resize", "--format", "qcow2", "--output-format", "qcow2",
                   "--unknown-filesystems", "error", "--align-first", "never", "--no-extra-partition"]
        for item in changes:
            command += ["--resize", f"{item['device']}={int(item['size_mib'] * MIB)}b"]
        if expand:
            command += ["--expand", expand]
        if recipe.get("expand_lv"):
            command += ["--LV-expand", recipe["expand_lv"]]
        command += [str(work), str(resized)]
        _run(command, log)
        work.unlink()
        return resized

    def _customize(self, work: Path, inspection: dict, recipe: dict, log) -> None:
        files = recipe.get("files", [])
        args = recipe.get("kernel_args")
        if files or args is not None:
            log("Writing guest configuration files")
            with _guest(work, "qcow2", readonly=False) as g:
                _mount(g, _roots(g), False)
                for item in files:
                    _write_guest(g, item["path"], item["content"])
                if args is not None:
                    value = g.read_file("/etc/default/grub") if g.is_file("/etc/default/grub") else b""
                    content = value.decode() if isinstance(value, bytes) else value
                    _write_guest(g, "/etc/default/grub", _grub_assignment(content, "GRUB_CMDLINE_LINUX", args))
        command = ["virt-customize", "--format", "qcow2", "-a", str(work),
                   "--network" if recipe.get("allow_network") else "--no-network"]
        changed = bool(files or args is not None)
        for field, option in (("packages_install", "--install"), ("packages_remove", "--uninstall")):
            if recipe.get(field):
                command += [option, ",".join(recipe[field])]
                changed = True
        for item in recipe.get("services", []):
            command += ["--run-command", "systemctl --root=/ " + item["action"] + " " + shlex.quote(item["name"])]
            changed = True
        if recipe.get("kernel_default"):
            command += ["--run-command", "command -v grubby >/dev/null || { echo 'Default kernel selection requires grubby in this guest' >&2; exit 1; }; grubby --set-default=" + shlex.quote(recipe["kernel_default"])]
            changed = True
        if args is not None:
            # BLS distributions store per-entry arguments separately from /etc/default/grub.
            # grubby --args adds arguments and replaces values for existing argument names.
            command += ["--run-command", "if command -v grubby >/dev/null; then grubby --update-kernel=ALL --args=" + shlex.quote(args) + "; fi"]
        if recipe.get("rebuild_initramfs"):
            command += ["--run-command", "if command -v dracut >/dev/null; then dracut --regenerate-all --force; elif command -v update-initramfs >/dev/null; then update-initramfs -u -k all; else echo 'No supported initramfs generator found' >&2; exit 1; fi"]
            changed = True
        if recipe.get("regenerate_grub") or args is not None or any(item["path"] == "/etc/default/grub" for item in files):
            command += ["--run-command", "if command -v update-grub >/dev/null; then update-grub; elif command -v grub2-mkconfig >/dev/null && test -d /boot/grub2; then grub2-mkconfig -o /boot/grub2/grub.cfg; else echo 'No supported GRUB configuration generator found' >&2; exit 1; fi"]
            changed = True
        if changed:
            # This also restores SELinux labels after direct file edits. Older and newer
            # virt-customize releases accept this compatibility option.
            command += ["--selinux-relabel"]
            _run(command, log)

    def build(self, source: Path, destination_dir: Path, inspection: dict, recipe: dict,
              log: Callable[[str], None]) -> dict:
        source, destination_dir = Path(source), Path(destination_dir).resolve()
        fmt = _input_format(source)
        source = source.resolve()
        _validate_recipe(recipe, inspection)
        from .uefi import plan_migration, migrate
        migration_options = recipe.get("boot_migration")
        migration_plan = plan_migration(inspection, migration_options, recipe.get("allow_network", False))
        if migration_plan["requested"] and not migration_plan["ready_to_migrate"]:
            raise EngineError("UEFI migration blocked: " + " ".join(migration_plan["blockers"]))
        from .platform import plan_platform, prepare_platform, verify_platform
        platform_options = recipe.get("platform_migration")
        platform_plan = plan_platform(inspection, platform_options, recipe.get("allow_network", False),
                                      recipe.get("oci"), target_provider=recipe.get("target", "generic"),
                                      boot_migration=migration_options)
        if platform_plan["requested"] and not platform_plan["ready"]:
            raise EngineError("Hardware compatibility blocked: " + " ".join(platform_plan["blockers"]))
        from .storage import plan_rebuild
        storage_plan = plan_rebuild(inspection, recipe.get("storage_rebuild"), recipe.get("disk_size_gib"))
        oci_config = None
        if recipe.get("oci") is not None:
            from .oci import OciConfig, compatibility_plan
            oci_config = OciConfig.model_validate(recipe["oci"])
            preflight = compatibility_plan(inspection, oci_config, recipe.get("allow_network", False), migration_options,
                                           platform_migration=platform_options)
            if preflight["blockers"]:
                raise EngineError("OCI preparation blocked: " + " ".join(preflight["blockers"]))
        if not self.capabilities()["available"]:
            raise EngineError("Image tools are unavailable. Run the supplied Linux Docker container.")
        destination_dir.mkdir(parents=True, exist_ok=True)
        if source.parent == destination_dir:
            raise EngineError("Build output must use a separate directory from the source image.")
        fresh = _image_info(source, fmt)
        if fresh["virtual-size"] != inspection["virtual_size"]:
            raise EngineError("The source image changed after inspection; import it again.")
        work = destination_dir / "working.qcow2"
        if work.exists():
            raise EngineError("Build directory already contains a working image.")
        final_format = recipe.get("output_format", "qcow2")
        target = recipe.get("target", "generic")
        warnings = ["Output format validated; cloud import and boot testing have not been performed."]
        if storage_plan["requested"]:
            warnings.extend(storage_plan["warnings"])
        if target == "oci":
            warnings.append("Import as QCOW2 and verify firmware, launch mode, agents, and destination boot-volume sizing. OCI metadata is not bundled.")
        if recipe.get("kernel_args") is not None:
            warnings.append("On grubby/BLS guests, requested kernel arguments update matching names and retain other existing arguments.")
        log("Creating an independent QCOW2 working copy; source remains unchanged")
        _run(["qemu-img", "convert", "-f", fmt, "-O", "qcow2", str(source), str(work)], log)
        work = self._resize(work, destination_dir, inspection, recipe, log)
        self._customize(work, inspection, recipe, log)
        if migration_plan["requested"]:
            customized = self.inspect(work)
            migration = migrate(work, customized, migration_options, recipe.get("allow_network", False), log)
            migration_plan = migration["plan"]
            warnings.extend(migration["warnings"])
        platform_receipt = None
        if platform_plan["requested"]:
            # Preservation starts after the user's explicit storage/kernel/file
            # edits. It never substitutes planned readiness for this inspection.
            customized = self.inspect(work)
            platform_receipt = prepare_platform(work, customized, platform_options, recipe.get("allow_network", False), log,
                                                oci_config=recipe.get("oci"), target_provider=target)
            warnings.extend(platform_receipt["warnings"])
        if oci_config is not None:
            from .oci_guest import prepare_guest
            # Manual package/configuration edits may invalidate the original evidence.
            customized = self.inspect(work)
            preparation = prepare_guest(work, customized, oci_config.model_dump(),
                                        recipe.get("allow_network", False), log,
                                        extra_required_modules=platform_plan.get("required_modules", []) if platform_plan["requested"] else (),
                                        platform_migration=platform_options)
            warnings.extend(preparation["warnings"])
            if platform_plan["requested"] and preparation.get("verified_initrds"):
                platform_receipt = preparation
        if recipe.get("sparsify", True):
            log("Discarding unused guest filesystem blocks")
            _run(["virt-sparsify", "--in-place", "--format", "qcow2", str(work)], log)
        _run(["qemu-img", "check", "-f", "qcow2", str(work)], log)
        # Reinspection verifies the root filesystem and mounts libguestfs recognizes;
        # it is not a complete fstab validator or a substitute for a boot test.
        log("Inspecting the customized guest")
        result_inspection = self.inspect(work)
        if inspection.get("kernels") and not result_inspection.get("kernels"):
            raise EngineError("Customization removed every detected kernel; at least one boot kernel must remain.")
        virtual_size = result_inspection["virtual_size"]
        alignment = GIB if final_format == "gcp" else MIB if final_format == "vhd" else 1
        if virtual_size % alignment:
            rounded = ((virtual_size + alignment - 1) // alignment) * alignment
            # Relocate GPT metadata via virt-resize, using a second empty output.
            work = self._resize(work, destination_dir, result_inspection,
                                {"disk_size_gib": rounded / GIB}, log)
            virtual_size = rounded
            result_inspection = self.inspect(work)
            if result_inspection["virtual_size"] != rounded:
                raise EngineError("Aligned working image has unexpected virtual capacity.")
        if migration_plan["requested"]:
            final_boot = result_inspection.get("boot") or {}
            if "UEFI_64" not in final_boot.get("supported_firmware", []):
                raise EngineError("Final export lost UEFI support after migration; export was stopped.")
            if migration_plan["layout"]["action"] != "already_uefi":
                from .uefi import _preserved
                preserved = _preserved(migration["inspection"]["uefi_migration"]["layout"], result_inspection.get("uefi_migration", {}).get("layout", {}))
                if not preserved:
                    raise EngineError("Final export changed disk structures after UEFI migration.")
                if "BIOS" not in final_boot.get("supported_firmware", []) or not any(loader.get("fallback") and loader.get("device") == migration_plan["layout"]["esp_device"] for loader in final_boot.get("efi_loaders", [])):
                    raise EngineError("Final export must preserve BIOS and the installed UEFI fallback after migration.")
        if oci_config is not None:
            selected = oci_config.capabilities.get("Compute.Firmware")
            required = (selected.values or [selected.default_value]) if selected else []
            supported = (result_inspection.get("boot") or {}).get("supported_firmware", [])
            missing = [firmware for firmware in required if firmware not in supported]
            if missing:
                raise EngineError("Final OCI image lacks verified installed firmware support for "
                                  + ", ".join(missing) + "; export was stopped.")
        storage_result = None
        if storage_plan["requested"]:
            from .storage import verify_rebuild
            storage_result = verify_rebuild(result_inspection, storage_plan, expected_disk_size=virtual_size)
            if not storage_result["ready"]:
                raise EngineError("Final storage rebuild verification failed: " + " ".join(storage_result["blockers"]))
            storage_result["plan"] = storage_plan
        platform_result = None
        if platform_plan["requested"]:
            platform_result = verify_platform(result_inspection, platform_options, oci_config=recipe.get("oci"),
                                              target_provider=target, receipt=platform_receipt)
            if not platform_result["ready"]:
                raise EngineError("Final hardware compatibility verification failed: " + " ".join(platform_result["blockers"]))
        filenames = {"qcow2": "image.qcow2", "raw": "image.raw", "vhd": "image.vhd", "gcp": "image.tar.gz"}
        output = destination_dir / filenames[final_format]
        conversion = destination_dir / "disk.raw" if final_format == "gcp" else output
        qemu_format = {"qcow2": "qcow2", "raw": "raw", "vhd": "vpc", "gcp": "raw"}[final_format]
        command = ["qemu-img", "convert", "-f", "qcow2", "-O", qemu_format]
        if final_format == "qcow2":
            command += ["-o", "compat=1.1,compression_type=zlib,cluster_size=131072"]
            if recipe.get("compress", True):
                command += ["-c"]
        elif final_format == "vhd":
            command += ["-o", "subformat=fixed,force_size"]
        command += [str(work), str(conversion)]
        log(f"Converting to {final_format}")
        _run(command, log)
        if final_format == "qcow2":
            _run(["qemu-img", "check", "-f", "qcow2", str(conversion)], log)
        log("Comparing every guest-visible byte after format conversion")
        _run(["qemu-img", "compare", "-f", "qcow2", "-F", qemu_format, str(work), str(conversion)], log)
        output_info = _image_info(conversion, qemu_format)
        if output_info["virtual-size"] != virtual_size:
            raise EngineError("Export virtual capacity differs from the prepared disk.")
        if final_format == "gcp":
            log("Packaging a root-level disk.raw for Google Cloud")
            with tarfile.open(output, "w:gz", format=tarfile.GNU_FORMAT) as archive:
                archive.add(conversion, arcname="disk.raw", recursive=False)
            conversion.unlink()
        log("Calculating artifact SHA-256")
        digest = hashlib.sha256()
        with output.open("rb") as stream:
            for chunk in iter(lambda: stream.read(8 * MIB), b""):
                digest.update(chunk)
        work.unlink()
        return {"artifact_path": str(output), "filename": output.name, "format": final_format,
                "virtual_size": virtual_size, "sha256": digest.hexdigest(), "warnings": warnings,
                "boot": result_inspection.get("boot"),
                "storage_rebuild": storage_result,
                "platform_migration": platform_result}
