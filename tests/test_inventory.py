import json
import sqlite3

from fastapi.testclient import TestClient
import pytest

from forge.config import Settings
from forge.main import create_app
from forge.store import Store


class Engine:
    def capabilities(self):
        return {"available": True, "missing": []}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path), Engine())) as result:
        yield result


@pytest.mark.parametrize("kind,path", [("image", "images"), ("job", "jobs"), ("artifact", "artifacts")])
def test_conditional_inventory_preserves_public_shape_and_omits_unchanged_body(client, kind, path):
    store = client.app.state.store
    record = store.create(kind, status="ready", path="/private/source", source_path="/private/source",
                          oci_bundle_path="/private/bundle", name="fixture")
    response = client.get(f"/api/{path}")
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    expected = record if kind == "job" else {key: value for key, value in record.items() if key not in {"path", "source_path", "oci_bundle_path"}}
    if kind == "artifact":
        expected["oci_archive_available"] = False
        old_schema = response.headers["etag"].replace("-v2-", "-v1-")
        assert client.get("/api/artifacts", headers={"If-None-Match": old_schema}).status_code == 200
    assert response.json() == [expected]
    tag = response.headers["etag"]
    for validator in (tag, "W/" + tag, '"unrelated", W/' + tag, "*"):
        unchanged = client.get(f"/api/{path}", headers={"If-None-Match": validator})
        assert unchanged.status_code == 304 and unchanged.content == b""
        assert unchanged.headers["etag"] == tag and unchanged.headers["cache-control"] == "no-store"
        assert unchanged.headers["x-content-type-options"] == "nosniff"
    assert client.get(f"/api/{path}", headers={"If-None-Match": "junk" + tag}).status_code == 200
    assert client.get(f"/api/{path}", headers={"If-None-Match": "x" * 8193}).status_code == 200
    store.update(kind, record["id"], name="changed")
    changed = client.get(f"/api/{path}", headers={"If-None-Match": tag})
    assert changed.status_code == 200 and changed.headers["etag"] != tag
    assert changed.json()[0]["name"] == "changed"


def test_per_kind_revisions_cover_logs_queued_inspection_and_deletion(client):
    store = client.app.state.store
    source = store.create("image", status="ready", inspection={"large": "payload"})
    job = store.create("job", status="running", logs=[])
    tags = {path: client.get("/api/" + path).headers["etag"] for path in ("images", "jobs", "artifacts")}
    store.log(job["id"], "Native preparation started")
    assert client.get("/api/jobs", headers={"If-None-Match": tags["jobs"]}).json()[0]["logs"]
    assert client.get("/api/images", headers={"If-None-Match": tags["images"]}).status_code == 304
    store.queue_inspection(source["id"])
    assert client.get("/api/images", headers={"If-None-Match": tags["images"]}).json()[0]["inspection_status"] == "queued"
    assert client.get("/api/artifacts", headers={"If-None-Match": tags["artifacts"]}).status_code == 304
    updated = client.get("/api/jobs").headers["etag"]
    with store.connect() as db:
        db.execute("DELETE FROM records WHERE id=?", (job["id"],))
    response = client.get("/api/jobs", headers={"If-None-Match": updated})
    assert response.status_code == 200 and response.json() == []


def test_authentication_runs_before_conditional_lookup(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path, api_token="fixture-token"), Engine())) as client:
        response = client.get("/api/images", headers={"Authorization": "Bearer fixture-token"})
        tag = response.headers["etag"]
        denied = client.get("/api/images", headers={"If-None-Match": tag})
        assert denied.status_code == 401 and "etag" not in denied.headers
        assert client.get("/api/images", headers={"Authorization": "Bearer fixture-token", "If-None-Match": tag}).status_code == 304


def test_unchanged_inventory_never_reads_or_decodes_record_payload(tmp_path, monkeypatch):
    store = Store(tmp_path)
    store.create("image", status="ready", inspection={"large": "x" * 100_000})
    revision, _ = store.inventory("image")
    statements = []
    connect = store.connect

    def traced():
        connection = connect()
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(store, "connect", traced)
    monkeypatch.setattr("forge.store.json.loads", lambda value: pytest.fail("Unchanged inventory decoded a record"))
    assert store.inventory("image", {revision}) == (revision, None)
    assert any("inventory_versions" in query for query in statements)
    assert not any("FROM records" in query for query in statements)


def test_legacy_database_and_restart_keep_correct_persisted_versions(tmp_path):
    path = tmp_path / "forge.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE records (kind TEXT NOT NULL, id TEXT PRIMARY KEY, data TEXT NOT NULL)")
        db.execute("INSERT INTO records VALUES (?, ?, ?)", ("image", "legacy", json.dumps({"id": "legacy", "status": "ready"})))
    store = Store(tmp_path)
    revision, records = store.inventory("image")
    assert records == [{"id": "legacy", "status": "ready"}]
    assert Store(tmp_path).inventory("image", {revision}) == (revision, None)
    assert Store(tmp_path).inventory("job")[1] == []
    with store.connect() as db:
        db.execute("UPDATE records SET data=? WHERE id='legacy'", (json.dumps({"id": "legacy", "status": "ready", "restored": True}),))
    updated, records = store.inventory("image", {revision})
    assert updated != revision and records[0]["restored"]


def test_record_mutation_and_revision_rollback_together_and_kind_moves_invalidate_both(tmp_path):
    store = Store(tmp_path)
    record = store.create("image", status="ready")
    before, _ = store.inventory("image")
    artifacts, _ = store.inventory("artifact")
    connection = store.connect()
    try:
        connection.execute("BEGIN")
        connection.execute("DELETE FROM records WHERE id=?", (record["id"],))
        connection.rollback()
    finally:
        connection.close()
    assert store.inventory("image", {before}) == (before, None)
    with store.connect() as db:
        db.execute("UPDATE records SET kind='artifact' WHERE id=?", (record["id"],))
    image_version, images = store.inventory("image", {before})
    artifact_version, rows = store.inventory("artifact", {artifacts})
    assert images == [] and image_version != before
    assert rows == [record] and artifact_version != artifacts


def test_recovery_invalidates_only_changed_inventories(tmp_path):
    store = Store(tmp_path)
    store.create("image", status="ready", inspection_status="running")
    store.create("job", status="running")
    versions = {kind: store.inventory(kind)[0] for kind in ("image", "job", "artifact")}
    store.recover()
    for kind, field in (("image", "inspection_status"), ("job", "status")):
        version, rows = store.inventory(kind, {versions[kind]})
        assert version != versions[kind] and rows[0][field] == "failed"
    assert store.inventory("artifact", {versions["artifact"]}) == (versions["artifact"], None)


def test_inventory_version_and_rows_share_snapshot_during_concurrent_write(tmp_path, monkeypatch):
    store = Store(tmp_path)
    record = store.create("image", name="before")
    revision, _ = store.inventory("image")
    connect = store.connect
    written = False

    def race():
        connection = connect()

        def between_version_and_data(query):
            nonlocal written
            if not written and query.startswith("SELECT data FROM records"):
                written = True
                with connect() as writer:
                    writer.execute("UPDATE records SET data=? WHERE id=?", (json.dumps({**record, "name": "after"}), record["id"]))
        connection.set_trace_callback(between_version_and_data)
        return connection

    monkeypatch.setattr(store, "connect", race)
    observed, rows = store.inventory("image")
    assert written and observed == revision and rows[0]["name"] == "before"
    current, rows = store.inventory("image", {revision})
    assert current != revision and rows[0]["name"] == "after"


def test_independent_and_restored_databases_do_not_reuse_row_count_versions(tmp_path):
    first, second = Store(tmp_path / "one"), Store(tmp_path / "two")
    first.create("image", name="one")
    second.create("image", name="two")
    assert first.inventory("image")[0] != second.inventory("image")[0]


def test_sql_replace_restore_invalidates_both_old_and_new_kinds(tmp_path):
    store = Store(tmp_path)
    row = store.create("image", name="restore")
    versions = {kind: store.inventory(kind)[0] for kind in ("image", "artifact")}
    with store.connect() as db:
        db.execute("INSERT OR REPLACE INTO records VALUES (?, ?, ?)", ("artifact", row["id"], json.dumps(row)))
    for kind in versions:
        version, records = store.inventory(kind, {versions[kind]})
        assert version != versions[kind]
        assert records == ([] if kind == "image" else [row])
