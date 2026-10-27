"""Small persistent registry; every operation uses its own SQLite connection."""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import uuid


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "forge.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT PRIMARY KEY, data TEXT NOT NULL)")

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
            if data["status"] != "ready" or data.get("inspection_status") in {"queued", "running"}:
                raise ValueError("Wait for the current image inspection to finish")
            data.update(inspection_status="queued", inspection_error=None, updated_at=now())
            db.execute("UPDATE records SET data=? WHERE id=?", (json.dumps(data), image_id))
        return data

    def recover(self):
        for job in self.list("job"):
            if job["status"] in {"queued", "running"}:
                self.update("job", job["id"], status="failed", error="Server restarted before the job finished. Submit the operation again.")
        for item in self.list("image"):
            if item["status"] == "importing":
                self.update("image", item["id"], status="failed", error="Import interrupted by a server restart. Import the source again.")
            elif item.get("inspection_status") in {"queued", "running"}:
                self.update("image", item["id"], inspection_status="failed",
                            inspection_error="Inspection interrupted by a server restart. Refresh inspection again; the previous result is preserved.")
        # Only named workspace subdirectories are managed here. Published
        # artifacts and successfully imported sources are always retained.
        root = self.path.parent
        keep_sources = {item["id"] for item in self.list("image") if item["status"] == "ready"}
        keep_builds = {Path(item["path"]).parent.name for item in self.list("artifact")}
        for folder, keep in ((root / "images", keep_sources), (root / "builds", keep_builds)):
            if folder.is_dir():
                for child in folder.iterdir():
                    if child.name not in keep and child.is_dir() and not child.is_symlink():
                        shutil.rmtree(child)
