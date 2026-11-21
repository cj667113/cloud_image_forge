"""Small persistent registry; every operation uses its own SQLite connection."""
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import shutil
import sqlite3
import uuid


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def artifact_name(record: dict) -> str:
    return record.get("name") or record.get("filename") or Path(record["path"]).name


def _workspace_file(value: str, managed: Path) -> Path | None:
    """Normalize aliases of the workspace root, leaving its contents unresolved."""
    path = Path(value).absolute()
    if ".." in path.parts:
        return None
    for parent in reversed(path.parents):
        if parent.name == managed.name and parent.parent.resolve() == managed.parent:
            return managed / path.relative_to(parent)
    return None


class Store:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "forge.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            # Random, persisted revisions also initialize existing databases.
            # Triggers cover log/queue/recovery writes and direct SQL restores,
            # without hashing or decoding potentially large inspection records.
            db.execute("CREATE TABLE IF NOT EXISTS inventory_versions (kind TEXT PRIMARY KEY, revision TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO inventory_versions SELECT kind, lower(hex(randomblob(16))) FROM records GROUP BY kind")
            db.executemany("INSERT OR IGNORE INTO inventory_versions VALUES (?, lower(hex(randomblob(16))))",
                           [(kind,) for kind in ("image", "job", "artifact")])
            # INSERT OR REPLACE does not fire DELETE triggers with SQLite's
            # default recursive_triggers setting. Invalidate the old kind before
            # such a restore replaces its row with another inventory kind.
            db.execute("""CREATE TRIGGER IF NOT EXISTS forge_inventory_replace
                BEFORE INSERT ON records BEGIN
                UPDATE inventory_versions SET revision=lower(hex(randomblob(16)))
                WHERE kind=(SELECT kind FROM records WHERE id=NEW.id) AND kind != NEW.kind;
                END""")
            for event, reference in (("INSERT", "NEW"), ("DELETE", "OLD")):
                db.execute(f"""CREATE TRIGGER IF NOT EXISTS forge_inventory_{event.lower()}
                    AFTER {event} ON records BEGIN
                    INSERT INTO inventory_versions VALUES ({reference}.kind, lower(hex(randomblob(16))))
                    ON CONFLICT(kind) DO UPDATE SET revision=excluded.revision;
                    END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS forge_inventory_update
                AFTER UPDATE ON records BEGIN
                INSERT INTO inventory_versions VALUES (NEW.kind, lower(hex(randomblob(16))))
                ON CONFLICT(kind) DO UPDATE SET revision=excluded.revision;
                UPDATE inventory_versions SET revision=lower(hex(randomblob(16)))
                WHERE kind=OLD.kind AND OLD.kind != NEW.kind;
                END""")

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def create(self, record_kind: str, **data) -> dict:
        data = {"id": uuid.uuid4().hex, "created_at": now(), **data}
        with self.connect() as db:
            db.execute("INSERT INTO records VALUES (?, ?, ?)", (record_kind, data["id"], json.dumps(data)))
        return data

    def get(self, kind: str, record_id: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT data FROM records WHERE kind=? AND id=?", (kind, record_id)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, kind: str) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT data FROM records WHERE kind=? ORDER BY rowid DESC", (kind,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def inventory(self, kind: str, known_versions: set[str] | None = None, *, any_version=False) -> tuple[str, list[dict] | None]:
        """Read a revision and optional inventory in one consistent snapshot.

        None means the caller already has this version. The matching path never
        selects or decodes record data. A write during the read cannot associate
        rows with a version from another transaction.
        """
        with self.connect() as db:
            db.execute("BEGIN")
            row = db.execute("SELECT revision FROM inventory_versions WHERE kind=?", (kind,)).fetchone()
            if row is None:
                raise ValueError("Unknown inventory kind")
            revision = row[0]
            if any_version or revision in (known_versions or ()):
                return revision, None
            rows = db.execute("SELECT data FROM records WHERE kind=? ORDER BY rowid DESC", (kind,)).fetchall()
        return revision, [json.loads(row[0]) for row in rows]

    def update(self, kind: str, record_id: str, **changes) -> dict:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM records WHERE kind=? AND id=?", (kind, record_id)).fetchone()
            if row is None:
                raise KeyError(record_id)
            data = {**json.loads(row[0]), **changes, "updated_at": now()}
            db.execute("UPDATE records SET data=? WHERE id=?", (json.dumps(data), record_id))
        return data

    def log(self, job_id: str, message: str):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM records WHERE kind='job' AND id=?", (job_id,)).fetchone()
            data = json.loads(row[0])
            data["logs"] = (data.get("logs", []) + [f"{now()}  {message[:8000]}"])[-500:]
            db.execute("UPDATE records SET data=? WHERE id=?", (json.dumps(data), job_id))

    def queue_inspection(self, image_id: str) -> dict:
        """Claim a cached source once, retaining its last successful inspection."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM records WHERE kind='image' AND id=?", (image_id,)).fetchone()
            if row is None:
                raise KeyError(image_id)
            data = json.loads(row[0])
            if data.get("deleting") or data["status"] != "ready" or data.get("inspection_status") in {"queued", "running"}:
                raise ValueError("Wait for the current image inspection to finish")
            data.update(inspection_status="queued", inspection_error=None, updated_at=now())
            db.execute("UPDATE records SET data=? WHERE id=?", (json.dumps(data), image_id))
        return data

    def delete_item(self, kind: str, record_id: str):
        """Claim deletion before touching disk. A failed cleanup is safe to retry."""
        if kind not in {"image", "artifact"}:
            raise ValueError("Unknown item type")
        root = self.path.parent.resolve()
        managed = root / ("images" if kind == "image" else "builds")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM records WHERE kind=? AND id=?", (kind, record_id)).fetchone()
            if not row:
                raise KeyError(record_id)
            item = json.loads(row[0])
            if kind == "image":
                if item.get("status") == "importing" or item.get("inspection_status") in {"running", "queued"}:
                    raise ValueError("Wait for the import or inspection to finish before deleting this image.")
                # An upload uses the exported file independently of its source.
                uses_item = "json_extract(data,'$.image_id')=? AND json_extract(data,'$.kind') IN ('build','inspect','import')"
                directory = managed / record_id
                if item.get("source_path"):
                    source = _workspace_file(item["source_path"], managed)
                    if not source or source.parent != directory:
                        raise ValueError("The source file could not be verified within its import directory.")
            else:
                uses_item = "json_extract(data,'$.artifact_id')=?"
                disk = _workspace_file(item.get("path", ""), managed)
                if not disk:
                    raise ValueError("The export file could not be verified within the Forge workspace.")
                directory = disk.parent
            if db.execute(f"""SELECT 1 FROM records WHERE kind='job'
                            AND json_extract(data,'$.status') IN ('queued','running') AND {uses_item} LIMIT 1""",
                          (record_id,)).fetchone():
                raise ValueError("Wait for the active or queued job to finish before deleting this item.")
            if (directory.parent != managed or directory.name in {"", ".", ".."} or managed.is_symlink()
                    or directory.is_symlink() or (directory.exists() and not directory.is_dir())):
                raise ValueError("The item's directory could not be verified within the Forge workspace.")
            files, shared = set(), set()
            if kind == "artifact":
                files = {_workspace_file(item[key], managed) for key in ("path", "oci_bundle_path") if item.get(key)}
                if any(not path or path.parent != directory for path in files):
                    raise ValueError("The export's files could not be verified within its build directory.")
                # Older or restored entries can refer to the same build folder.
                for disk, bundle in db.execute("""SELECT json_extract(data,'$.path'), json_extract(data,'$.oci_bundle_path')
                                                 FROM records WHERE kind='artifact' AND id!=?""", (record_id,)):
                    for value in (disk, bundle):
                        path = _workspace_file(value, managed) if value else None
                        if path and path.is_relative_to(directory):
                            shared.add(path)
            db.execute("UPDATE records SET data=json_set(data,'$.deleting',json('true')) WHERE id=?", (record_id,))

        if shared:
            for path in files - shared:
                path.unlink(missing_ok=True)
        elif directory.exists():
            shutil.rmtree(directory)

        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            name = artifact_name(item) if kind == "artifact" else item.get("name") or record_id
            if kind == "image":
                db.execute("""UPDATE records SET data=json_set(data,'$.source_name',?)
                              WHERE kind IN ('job','artifact') AND json_extract(data,'$.image_id')=?""", (name, record_id))
            else:
                db.execute("""UPDATE records SET data=json_set(data,'$.artifact_name',?) WHERE kind='job'
                              AND (json_extract(data,'$.artifact_id')=? OR json_extract(data,'$.result.artifact_id')=?)""",
                           (name, record_id, record_id))
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, record_id))

    def recover(self):
        for job in self.list("job"):
            if job["status"] in {"queued", "running"}:
                self.update("job", job["id"], status="failed", error="Server restarted before the job finished. Submit the operation again.")
        images = self.list("image")
        artifacts = self.list("artifact")
        for item in images:
            if item["status"] == "importing":
                self.update("image", item["id"], status="failed", error="Import interrupted by a server restart. Import the source again.")
            elif item.get("inspection_status") in {"queued", "running"}:
                self.update("image", item["id"], inspection_status="failed",
                            inspection_error="Inspection interrupted by a server restart. Refresh inspection again; the previous result is preserved.")
        for kind, items in (("image", images), ("artifact", artifacts)):
            for item in items:
                if item.get("deleting"):
                    try:
                        self.delete_item(kind, item["id"])
                    except (ValueError, OSError):
                        logging.getLogger(__name__).exception("Could not finish deleting %s %s", kind, item["id"])
        # Only named workspace subdirectories are managed here. Published
        # artifacts and successfully imported sources are always retained.
        root = self.path.parent
        keep_sources = {item["id"] for item in images if item["status"] == "ready" or item.get("deleting")}
        keep_builds = {Path(item["path"]).parent.name for item in artifacts}
        for folder, keep in ((root / "images", keep_sources), (root / "builds", keep_builds)):
            if folder.is_dir() and not folder.is_symlink():
                for child in folder.iterdir():
                    if child.name not in keep and child.is_dir() and not child.is_symlink():
                        shutil.rmtree(child)
