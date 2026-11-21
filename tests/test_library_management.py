from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import anyio
from fastapi.testclient import TestClient
import pytest
from starlette.responses import FileResponse

from forge.config import Settings
from forge.main import create_app
from forge.store import Store
from test_api import FakeEngine, client, finished, imported


def build_export(client, source):
    response = client.post(f"/api/images/{source}/build", json={})
    assert response.status_code == 202, response.text
    job = finished(client, response.json()["job_id"])
    assert job["status"] == "succeeded"
    return job["result"]["artifact_id"]


def test_library_management_end_to_end_and_persistence(client, tmp_path):
    image = imported(client)
    source = f"/api/images/{image}"
    export = build_export(client, image)
    artifact = f"/api/artifacts/{export}"
    before = client.get(artifact).json()
    store = client.app.state.store
    disk = Path(store.get("artifact", export)["path"])
    revision = client.get("/api/images").headers["etag"]

    assert client.patch(source, json={"name": "  Original système  "}).json()["name"] == "Original système"
    assert client.get("/api/images", headers={"If-None-Match": revision}).status_code == 200
    renamed = client.patch(artifact, json={"name": "Launch candidate"}).json()
    assert renamed["name"] == "Launch candidate.qcow2" and "path" not in renamed
    assert renamed["sha256"] == before["sha256"]
    assert Store(tmp_path).get("artifact", export)["name"] == renamed["name"]
    assert disk.name == before["filename"] and disk.read_bytes() == b"test-output"

    assert client.delete(source).status_code == 204
    assert client.get(source).status_code == 404 and not (tmp_path / "images" / image).exists()
    assert client.get(artifact + "/manifest").json()["source_name"] == "Original système"
    download = client.get(artifact + "/download", headers={"Range": "bytes=0-3"})
    assert download.status_code == 206 and download.content == b"test"
    assert "Launch%20candidate.qcow2" in download.headers["content-disposition"]
    assert client.delete(artifact).status_code == 204 and not disk.parent.exists()
    assert client.get("/api/artifacts").json() == [] and client.get(artifact + "/download").status_code == 404
    history = client.get("/api/jobs").json()
    assert history[0]["source_name"] == "Original système" and history[0]["artifact_name"] == renamed["name"]
    assert client.delete(source).status_code == client.delete(artifact).status_code == 404


@pytest.mark.parametrize("name", ["", " \t ", ".", "..", "../disk", "bad\\disk", "a\r\nb", "a\u0000b", "x" * 201])
def test_invalid_names_preserve_item(client, name):
    image = client.app.state.store.create("image", name="original", status="failed")
    url = "/api/images/" + image["id"]
    assert client.patch(url, json={"name": name}).status_code == 422
    assert client.get(url).json()["name"] == "original"


def test_preserve_compound_export_suffix_and_length_limit(client, tmp_path):
    item = client.app.state.store.create("artifact", path=str(tmp_path / "builds" / "old" / "disk.tar.gz"), name="disk.tar.gz")
    url = "/api/artifacts/" + item["id"]
    for proposed in ("Image v1.2", "Image v1.2.TAR.GZ"):
        assert client.patch(url, json={"name": proposed}).json()["name"] == "Image v1.2.tar.gz"
    for invalid in (".tar.gz", "x" * 196):
        assert client.patch(url, json={"name": invalid}).status_code == 422
    assert client.delete(url).status_code == 204  # missing file


def test_live_jobs_and_import_states_block_only_the_files_they_use(client, tmp_path):
    store = client.app.state.store
    image = store.create("image", name="guest", status="importing")
    url = "/api/images/" + image["id"]
    assert client.delete(url).status_code == 409
    store.update("image", image["id"], status="ready", inspection_status="queued")
    assert client.delete(url).status_code == 409
    store.update("image", image["id"], inspection_status="ready")
    job = store.create("job", kind="build", image_id=image["id"], status="running")
    assert client.delete(url).status_code == 409
    store.update("job", job["id"], status="succeeded")
    folder = tmp_path / "builds" / "legacy"
    folder.mkdir(parents=True)
    disk = folder / "disk.raw"
    disk.write_bytes(b"export")
    export = store.create("artifact", name="disk.raw", path=str(disk), image_id=image["id"])
    upload = store.create("job", kind="upload", image_id=image["id"], artifact_id=export["id"], status="queued")
    target = "/api/artifacts/" + export["id"]
    assert client.delete(target).status_code == 409
    assert client.delete(url).status_code == 204
    assert disk.read_bytes() == b"export"
    store.update("job", upload["id"], status="failed")
    assert client.delete(target).status_code == 204


def test_delete_failed_import_with_or_without_files(client, tmp_path):
    store = client.app.state.store
    for exists in (True, False):
        image = store.create("image", name="failed", status="failed")
        folder = tmp_path / "images" / image["id"]
        if exists:
            folder.mkdir()
            (folder / "source").write_bytes(b"partial")
        assert client.delete("/api/images/" + image["id"]).status_code == 204
        assert not folder.exists()


def test_partial_cleanup_blocks_new_work_and_restart_completes_request(client, tmp_path, monkeypatch):
    source = imported(client)
    url = "/api/images/" + source
    def interrupted(path):
        (path / "source").unlink()
        raise OSError("filesystem error")
    with monkeypatch.context() as m:
        m.setattr("forge.store.shutil.rmtree", interrupted)
        assert client.delete(url).status_code == 500
    assert client.patch(url, json={"name": "other"}).status_code == 409
    assert client.post(url + "/build", json={}).status_code == 409
    assert client.get("/api/images").json()[0]["deleting"]
    store = Store(tmp_path)
    store.recover()
    assert not store.get("image", source) and not (tmp_path / "images" / source).exists()


def test_shared_export_directory_retains_other_files_and_references(client, tmp_path):
    store = client.app.state.store
    folder = tmp_path / "builds" / "shared"
    folder.mkdir(parents=True)
    a, b, bundle = (folder / name for name in ("first.qcow2", "second.qcow2", "shared.zip"))
    for path in (a, b, bundle):
        path.write_bytes(path.name.encode())
    first, second = [store.create("artifact", path=str(path), name=path.name, oci_bundle_path=str(bundle)) for path in (a, b)]
    assert client.delete("/api/artifacts/" + first["id"]).status_code == 204
    assert not a.exists() and b.is_file() and bundle.is_file()
    assert client.delete("/api/artifacts/" + second["id"]).status_code == 204
    assert not folder.exists()


def test_deletion_never_traverses_unowned_directory_or_symlink(client, tmp_path):
    store = client.app.state.store
    outside = tmp_path / "outside"
    outside.mkdir()
    disk = outside / "keep"
    disk.write_bytes(b"keep")
    builds = tmp_path / "builds"
    builds.mkdir(exist_ok=True)
    link = builds / "link"
    link.symlink_to(outside, target_is_directory=True)
    for path in (disk, link / disk.name, builds / ".." / "outside" / "keep"):
        item = store.create("artifact", path=str(path), name=disk.name)
        assert client.delete("/api/artifacts/" + item["id"]).status_code == 409
    assert disk.read_bytes() == b"keep"


@pytest.mark.parametrize("endpoint", ["download", "oci-bundle"])
def test_streaming_download_claim_blocks_delete_and_releases_after_send(client, tmp_path, monkeypatch, endpoint):
    store = client.app.state.store
    directory = tmp_path / "builds" / "output"
    directory.mkdir(parents=True)
    disk, bundle = directory / "disk.raw", directory / "config.zip"
    disk.write_bytes(b"disk")
    bundle.write_bytes(b"bundle")
    item = store.create("artifact", path=str(disk), name=disk.name, oci_bundle_path=str(bundle))
    url = "/api/artifacts/" + item["id"]
    entered, release = Event(), Event()
    send_file = FileResponse.__call__
    async def pause(response, scope, receive, send):
        entered.set()
        assert await anyio.to_thread.run_sync(release.wait, 4)
        await send_file(response, scope, receive, send)
    monkeypatch.setattr(FileResponse, "__call__", pause)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.get, url + "/" + endpoint)
        try:
            assert entered.wait(4)
            assert client.delete(url).status_code == 409
        finally:
            release.set()
        assert pending.result(timeout=5).status_code == 200
    assert client.delete(url).status_code == 204


def test_mutations_require_auth_and_same_origin(tmp_path):
    store = Store(tmp_path)
    image = store.create("image", name="protected", status="failed")
    with TestClient(create_app(Settings(data_dir=tmp_path, api_token="token"), FakeEngine())) as client:
        url = "/api/images/" + image["id"]
        assert client.patch(url, json={"name": "new"}).status_code == client.delete(url).status_code == 401
        headers = {"Authorization": "Bearer token", "Origin": "https://elsewhere.example"}
        assert client.delete(url, headers=headers).status_code == 403
    assert store.get("image", image["id"])["name"] == "protected"


def test_workspace_root_alias_normalized_for_legacy_shared_files(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    store = Store(alias)
    folder = real / "builds" / "abc"
    folder.mkdir(parents=True)
    disk = folder / "disk.raw"
    disk.write_bytes(b"unchanged")
    aliased = alias / disk.relative_to(real)
    one = store.create("artifact", name="first", path=str(aliased))
    two = store.create("artifact", name="second", path=str(disk))
    # Reopen through the real path, exactly as when restoring older records.
    store = Store(real)
    store.delete_item("artifact", one["id"])
    assert disk.read_bytes() == b"unchanged"
    store.delete_item("artifact", two["id"])
    assert not folder.exists()


def test_download_failure_releases_claim_and_retains_legacy_filename(client, tmp_path, monkeypatch):
    store = client.app.state.store
    directory = tmp_path / "builds" / "legacy"
    directory.mkdir(parents=True)
    disk = directory / "disk.raw"
    item = store.create("artifact", path=str(disk), filename="old.raw", image_id="deleted-source")
    job = store.create("job", kind="upload", artifact_id=item["id"], status="succeeded")
    url = "/api/artifacts/" + item["id"]
    assert client.get(url + "/download").status_code == 410
    disk.write_bytes(b"legacy")
    downloaded = client.get(url + "/download")
    assert downloaded.content == b"legacy" and "old.raw" in downloaded.headers["content-disposition"]
    async def disconnect(*args):
        raise OSError("stream disconnected")
    with monkeypatch.context() as m:
        m.setattr(FileResponse, "__call__", disconnect)
        with pytest.raises(OSError, match="stream disconnected"):
            client.get(url + "/download")
    assert client.delete(url).status_code == 204
    assert store.get("job", job["id"])["artifact_name"] == "old.raw"
