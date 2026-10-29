"""Identity-preserving growth with inspected, fixed-start partition/LVM mappings."""
from copy import deepcopy
from pathlib import Path
import math

from .storage import MIB, GIB, FILESYSTEMS, LVM_GUID, LVM_PIN_ERROR, StorageError, _ceil, _lvm_errors, _lvm_partition_view


def _integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def plan_growth(inspection, options, disk_size_gib=None):
    result = {"requested": True, "ready": False, "mode": "growth", "root_fill": False,
              "blockers": [], "warnings": [], "changes": [], "filesystems": [], "layout": {},
              "estimated_temporary_bytes": inspection.get("actual_size", 0), "actions": []}
    errors = result["blockers"]
    storage = inspection.get("storage") or {}
    layout = storage.get("layout") or {}
    if storage.get("version") != 1 or not layout.get("partitions"):
        errors.append("Storage identity and layout evidence is missing; refresh inspection")
        return result
    if "growth_errors" in storage and storage["growth_errors"] is None:
        errors.append("Storage filesystem inventory is incomplete; refresh inspection")
    inventory_errors = storage.get("growth_errors", storage.get("errors", [])) or []
    if "growth_errors" not in storage:
        # Older inspections reported this rebuild-only restriction together
        # with inventory errors. Growth retains and verifies every LVM UUID.
        inventory_errors = [error for error in inventory_errors if error != LVM_PIN_ERROR]
    errors.extend(inventory_errors)
    errors.extend(layout.get("errors", []))
    parts, filesystems, lvm = (deepcopy(layout.get("partitions", [])), deepcopy(storage.get("filesystems", [])), deepcopy(storage.get("lvm") or {}))
    result["filesystems"] = filesystems
    before = inspection.get("virtual_size")
    if not _integer(before) or layout.get("disk_size") != before:
        errors.append("Inspected disk capacity disagrees with its partition layout")
        return result
    if layout.get("partition_table") not in {"gpt", "msdos"} or layout.get("sector_size") != 512 or layout.get("hybrid"):
        errors.append("Automatic growth requires a validated GPT or simple primary MBR disk with 512-byte sectors")
    if not layout.get("disk_identity") or not layout.get("boot_code_sha256"):
        errors.append("Disk identity and boot-code preservation evidence is missing; refresh inspection")
    if disk_size_gib is not None and (isinstance(disk_size_gib, bool) or not isinstance(disk_size_gib, (int,float)) or not math.isfinite(disk_size_gib) or disk_size_gib <= 0):
        errors.append("Target disk capacity must be positive and finite")
        return result
    target = _ceil(int(disk_size_gib * GIB), 512) if disk_size_gib is not None else before
    if target < before:
        errors.append("Disk reduction requires the verified filesystem rebuild workflow")
    if layout.get("partition_table") == "msdos" and target >= 2**32 * 512:
        errors.append("A primary MBR disk cannot grow to 2 TiB or larger")
    ordered = sorted(parts, key=lambda part: part.get("start", 0))
    if parts != ordered or len({part.get("device") for part in parts}) != len(parts):
        errors.append("Partition order or device identity is ambiguous")
    end = 512
    for part in parts:
        if (not all(_integer(part.get(key)) for key in ("start","end","size","number"))
                or part["start"] < end or part["start"] % 512 or (part["end"] + 1) % 512
                or part["size"] != part["end"] - part["start"] + 1 or part["end"] >= before):
            errors.append("Partition geometry is invalid or overlapping")
            return result
        end = part["end"] + 1
    known = {fs.get("device"): fs for fs in filesystems}
    if len(known) != len(filesystems) or None in known:
        errors.append("Filesystem device identities are ambiguous")
    sizes = {}
    for item in (options or {}).get("sizes", []):
        device, value = item.get("device"), item.get("size_mib")
        if device in sizes or device not in known or not known[device].get("editable") or known[device].get("filesystem") not in FILESYSTEMS:
            errors.append(f"Size changes must name unique inspected ext/XFS filesystems: {device}")
        elif not _integer(value) or not 32 <= value <= 2097152:
            errors.append(f"Invalid filesystem capacity for {device}")
        else:
            sizes[device] = value * MIB
    fsids = [fs.get("uuid") for fs in filesystems]
    if any(not value for value in fsids) or len(set(fsids)) != len(fsids):
        errors.append("Filesystem UUIDs must be present and unique before automatic growth")
    pvs, vgs, lvs = (lvm.get(key, []) for key in ("pvs","vgs","lvs"))
    pvpart = None
    if pvs or vgs or lvs:
        checked = _lvm_partition_view(lvm, parts)
        errors.extend(_lvm_errors(lvm, checked, filesystems))
        if len(pvs) == len(vgs) == 1:
            pvpart = next((part for part in parts if part["device"] == pvs[0].get("pv_name")), None)
        if pvpart is None:
            errors.append("A unique physical partition for the volume group is required")
        if any(lv.get("seg_count") != 1 for lv in lvs):
            errors.append("Automatic LVM growth requires ordinary single-segment volumes; complex segment mappings need a dedicated workflow")
    partmap = {part["device"]: part for part in parts}
    for fs in filesystems:
        if fs.get("kind") != "lv" and fs["device"] not in partmap:
            errors.append(f"Filesystem {fs['device']} does not map to one inspected partition")
        elif fs.get("kind") != "lv" and fs.get("size") != partmap[fs["device"]]["size"]:
            errors.append(f"Filesystem and partition capacity evidence disagree: {fs['device']}")
        if not _integer(fs.get("size")) or fs["size"] <= 0:
            errors.append(f"Filesystem {fs['device']} lacks current capacity evidence")
    if errors:
        return result
    extent = vgs[0].get("vg_extent_size") if pvpart else MIB
    lvmap = {lv["device"]: lv for lv in lvs}
    if pvpart:
        pv, vg = pvs[0], vgs[0]
        fields = [(pv,key) for key in ("pe_start","pv_size","pv_free","pv_pe_count","pv_pe_alloc_count","pv_mda_count")] + [(vg,key) for key in ("vg_size","vg_free","vg_extent_count","vg_free_count")]
        if (any(not _integer(row.get(key)) for row,key in fields)
                or pv["pv_mda_count"] != 1 or not 0 < pv["pe_start"] < pvpart["size"]
                or pv["pv_pe_count"] != (pvpart["size"] - pv["pe_start"]) // extent
                or pv["pv_size"] != vg["vg_size"] or vg["vg_size"] != vg["vg_extent_count"] * extent
                or pv["pv_pe_count"] != vg["vg_extent_count"] or pv["pv_free"] != vg["vg_free"]
                or vg["vg_free"] != vg["vg_free_count"] * extent
                or pv["pv_pe_alloc_count"] + vg["vg_free_count"] != pv["pv_pe_count"]
                or any(not _integer(lv.get("lv_size")) or lv["lv_size"] != known[lv["device"]]["size"] for lv in lvs)
                or sum(lv["lv_size"] for lv in lvs) + vg["vg_free"] != vg["vg_size"]):
            errors.append("Exact single-PV extent and LV capacity evidence is missing or inconsistent; refresh inspection")
            return result
    for device, wanted in list(sizes.items()):
        if known[device]["kind"] == "lv":
            sizes[device] = _ceil(wanted, extent)
        if sizes[device] < known[device]["size"]:
            errors.append(f"Shrinking {device} requires the verified rebuild workflow")
    guard = max(MIB, layout.get("end_guard_bytes", MIB))
    root_fill = not sizes and target > before
    if root_fill:
        root = inspection.get("os", {}).get("root")
        roots = [fs for fs in filesystems if fs["device"] == root and fs.get("mountpoint") == "/" and fs.get("editable")]
        if len(roots) != 1:
            errors.append("Disk-only growth needs one independently inspected editable root filesystem; set explicit filesystem capacities instead")
            return result
        fs = roots[0]
        container = pvpart if fs["kind"] == "lv" else partmap.get(root)
        if container is None or container != parts[-1]:
            errors.append("Automatic root fill would cross another partition; set explicit filesystem capacities within available space")
            return result
        available = ((target - guard - container["start"]) // MIB) * MIB
        if fs["kind"] == "lv":
            usable = ((available - pvs[0]["pe_start"]) // extent) * extent
            sizes[root] = usable - sum(lv["lv_size"] for lv in lvs if lv["device"] != root)
        else:
            sizes[root] = available
        sizes[root] = max(sizes[root], fs["size"])
        result["root_fill"] = True
        result["warnings"].append("Disk-only growth assigns available capacity to the verified root filesystem; other filesystems retain their sizes.")
    for fs in filesystems:
        desired = sizes.get(fs["device"], fs["size"])
        fs["selected_size_mib"] = math.ceil(desired / MIB)
        fs["selected_size"] = desired
        if desired > fs["size"]:
            result["actions"].append({"device": fs["device"], "filesystem": fs["filesystem"], "kind": fs["kind"], "before": fs["size"], "after": desired})
            result["changes"].append(f"Grow {fs.get('mountpoint') or fs['device']} from {fs['size']/MIB:g} to {desired/MIB:g} MiB")
        if fs["kind"] != "lv" and desired > partmap[fs["device"]]["size"]:
            partmap[fs["device"]]["size"] = desired
    if pvpart:
        selected_lvs = sum(sizes.get(lv["device"], lv["lv_size"]) for lv in lvs)
        pvpart["size"] = max(pvpart["size"], _ceil(pvs[0]["pe_start"] + selected_lvs, MIB))
    for index, part in enumerate(parts):
        part["end"] = part["start"] + part["size"] - 1
        if index + 1 < len(parts) and part["end"] >= parts[index+1]["start"]:
            errors.append(f"Growing {part['device']} would move or overlap the following partition; this layout needs a separate rebuild")
    last_changed = parts[-1]["end"] != layout["partitions"][-1]["end"]
    minimum = max(before, _ceil(parts[-1]["end"] + 1 + guard, 512)) if last_changed else before
    if disk_size_gib is None:
        target = max(before, minimum)
    if target < minimum:
        errors.append(f"Requested filesystems need at least {minimum/GIB:.3f} GiB; increase disk capacity or reduce their sizes")
    if target != before:
        result["changes"].insert(0, f"Grow disk capacity from {before/GIB:g} to {target/GIB:g} GiB")
    result["layout"] = {**deepcopy(layout), "partitions": parts, "disk_size_before": before, "disk_size_after": target,
                        "minimum_disk_size": minimum, "lvs": [{**lv, "size": sizes.get(lv["device"],lv["lv_size"])} for lv in lvs]}
    result["source"] = {"layout": deepcopy(layout), "filesystems": deepcopy(storage["filesystems"]), "lvm": lvm,
                        "architecture": inspection.get("os", {}).get("arch"), "firmware": inspection.get("boot", {}).get("supported_firmware", [])}
    if not result["changes"]:
        result["mode"] = "unchanged"
    result["warnings"].append("Partition starts, filesystem identities and LVM identities are retained. Boot testing is still required after export.")
    result["ready"] = not errors
    return result


def verify_growth(inspection, plan, *, expected_disk_size=None):
    errors = []
    result = {"ready": False, "blockers": errors, "mode": plan.get("mode"), "virtual_size": inspection.get("virtual_size")}
    source = plan.get("source") or {}
    expected = plan.get("layout") or {}
    actual = (inspection.get("storage") or {}).get("layout") or {}
    capacity = expected_disk_size if expected_disk_size is not None else expected.get("disk_size_after")
    if not plan.get("ready") or not source or not expected or not _integer(capacity) or capacity < expected["disk_size_after"]:
        errors.append("A verified growth plan and capacity are required")
        return result
    if inspection.get("virtual_size") != capacity or actual.get("disk_size") != capacity or actual.get("errors"):
        errors.append("Final disk capacity or partition layout is inconsistent")
    for field in ("partition_table","sector_size","disk_identity","boot_code_sha256"):
        if actual.get(field) != source["layout"].get(field):
            errors.append(f"Growth changed disk {field}")
    if inspection.get("os", {}).get("arch") != source["architecture"]:
        errors.append("Growth changed the guest architecture")
    if not set(source["firmware"]).issubset(inspection.get("boot", {}).get("supported_firmware", [])):
        errors.append("Growth lost previously detected firmware support")
    actualparts = {part.get("device"): part for part in actual.get("partitions", [])}
    if set(actualparts) != {part["device"] for part in expected["partitions"]}:
        errors.append("Growth changed the partition inventory")
    for part in expected["partitions"]:
        now = actualparts.get(part["device"], {})
        if any(now.get(field) != part.get(field) for field in ("start","end","size","number","type","partition_guid","attributes","active","name")):
            errors.append(f"Unexpected final partition identity or geometry: {part['device']}")
        if now.get("end",capacity) >= capacity:
            errors.append(f"Partition exceeds final disk capacity: {part['device']}")
    fsmap = {fs.get("device"): fs for fs in inspection.get("storage", {}).get("filesystems", [])}
    if set(fsmap) != {fs["device"] for fs in source["filesystems"]}:
        errors.append("Growth changed filesystem inventory")
    for fs in plan["filesystems"]:
        now = fsmap.get(fs["device"], {})
        if any(now.get(field) != fs.get(field) for field in ("uuid","label","filesystem","mountpoint")) or now.get("size") != fs["selected_size"]:
            errors.append(f"Unexpected final filesystem identity or capacity: {fs['device']}")
        if any(action["device"] == fs["device"] for action in plan["actions"]):
            actual_capacity = now.get("filesystem_capacity")
            if not _integer(actual_capacity) or not fs["selected_size"] - MIB <= actual_capacity <= fs["selected_size"]:
                errors.append(f"Filesystem data capacity did not grow to its selected size: {fs['device']}")
    current_lvm = inspection.get("storage", {}).get("lvm") or {}
    for kind, identity, name in (("pvs","pv_uuid","pv_name"),("vgs","vg_uuid","vg_name"),("lvs","lv_uuid","device")):
        if {(item.get(name),item.get(identity)) for item in current_lvm.get(kind,[])} != {(item.get(name),item.get(identity)) for item in source["lvm"].get(kind,[])}:
            errors.append(f"Growth changed LVM {kind} identities")
    if {lv.get("device"):lv.get("lv_size") for lv in current_lvm.get("lvs",[])} != {lv["device"]:lv["size"] for lv in expected["lvs"]}:
        errors.append("Final LV capacities differ from the requested growth plan")
    result["ready"] = not errors
    return result


def grow(source_work: Path, destination: Path, inspection, options, disk_size_gib, log):
    from .engine import ImageEngine, _guest, _run
    fresh = ImageEngine().inspect(source_work)
    plan = plan_growth(fresh, options, disk_size_gib)
    if not plan["ready"]:
        raise StorageError("Automatic growth blocked: " + " ".join(plan["blockers"]))
    if plan["mode"] == "unchanged":
        return source_work
    if destination.exists() or destination.resolve() == source_work.resolve():
        raise StorageError("Growth destination must be a new independent working file")
    try:
        _run(["qemu-img","convert","-f","qcow2","-O","qcow2",str(source_work),str(destination)],log)
        target = plan["layout"]["disk_size_after"]
        if target != fresh["virtual_size"]:
            _run(["qemu-img","resize","-f","qcow2",str(destination),str(target)],log)
        with _guest(destination,"qcow2",readonly=False) as g:
            if target != fresh["virtual_size"] and plan["layout"]["partition_table"] == "gpt":
                g.part_expand_gpt("/dev/sda")
            before = {part["device"]:part for part in plan["source"]["layout"]["partitions"]}
            for part in plan["layout"]["partitions"]:
                if part["size"] != before[part["device"]]["size"]:
                    log(f"Growing partition {part['device']} without moving its start")
                    g.part_resize("/dev/sda",part["number"],part["end"]//512)
            for pv in plan["source"]["lvm"].get("pvs",[]):
                part = next(part for part in plan["layout"]["partitions"] if part["device"] == pv["pv_name"])
                if part["size"] != before[part["device"]]["size"]:
                    g.pvresize(pv["pv_name"])
            for action in plan["actions"]:
                if action["kind"] == "lv":
                    g.lvresize(action["device"],action["after"]//MIB)
                log(f"Growing {action['filesystem']} filesystem {action['device']}")
                if action["filesystem"] == "xfs":
                    g.mount(action["device"],"/")
                    try:g.xfs_growfs("/")
                    finally:g.umount_all()
                else:
                    g.e2fsck(action["device"],forceall=True)
                    g.resize2fs(action["device"])
            g.sync()
        final = ImageEngine().inspect(destination)
        checked = verify_growth(final,plan)
        if not checked["ready"]:
            raise StorageError("Growth verification failed: " + " ".join(checked["blockers"]))
        _run(["qemu-img","check","-f","qcow2",str(destination)],log)
        return destination
    except Exception:
        destination.unlink(missing_ok=True)
        raise
