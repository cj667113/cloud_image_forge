import hashlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import io
import json
from pathlib import Path
from threading import Event
import time
import zipfile

from fastapi.testclient import TestClient
import pytest

from forge.config import Settings
from forge.main import create_app
from forge.store import Store
from forge import transfers


class FakeEngine:
    """Exercise orchestration, never claim that fake bytes are a bootable image."""
    fail_build = False

    def capabilities(self):
        return {"available": True, "missing": []}

    def inspect(self, path):
        assert Path(path).read_bytes() == b"test-source"
        return {"format": "raw", "virtual_size": 1024**3, "actual_size": 11,
                "os": {"name": "Test Linux", "distro": "test", "arch": "x86_64", "root": "/dev/sda1"},
                "partitions": [], "files": {"/etc/fstab": "# test\n"}, "services": [], "kernels": [], "warnings": []}

    def build(self, source, directory, inspection, recipe, log):
        assert source.read_bytes() == b"test-source"
        result = directory / "image.qcow2"
        result.write_bytes(b"test-output")
        log("Test engine wrote an output")
        if self.fail_build:
            raise ValueError("Test engine failed validation")
        return {"artifact_path": str(result), "filename": result.name, "format": "qcow2", "virtual_size": 1024**3,
                "sha256": hashlib.sha256(result.read_bytes()).hexdigest(), "warnings": ["Test output only"]}


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(data_dir=tmp_path), FakeEngine())
    with TestClient(app) as client:
        yield client


def finished(client, job_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in {"succeeded", "failed"}:
            return job
        time.sleep(0.01)
    pytest.fail("Job did not finish")


def imported(client):
    response = client.post("/api/images/upload", files={"file": ("../../test.img", b"test-source")})
    assert response.status_code == 202, response.text
    payload = response.json()
    assert finished(client, payload["job_id"])["status"] == "succeeded"
    return payload["image_id"]


def test_import_build_download_persist_and_preserve_source(client, tmp_path):
    image_id = imported(client)
    detail = client.get(f"/api/images/{image_id}").json()
    assert detail["status"] == "ready"
    assert detail["name"] == "test.img"
    assert "source_path" not in detail
    response = client.post(f"/api/images/{image_id}/build", json={"files": [{"path": "/etc/fstab", "content": "# changed\n"}]})
    job = finished(client, response.json()["job_id"])
    assert job["status"] == "succeeded", job
    artifact_id = job["result"]["artifact_id"]
    artifact = client.get(f"/api/artifacts/{artifact_id}").json()
    assert "path" not in artifact
    assert artifact["recipe"]["files"][0]["content"] == "# changed\n"
    download = client.get(f"/api/artifacts/{artifact_id}/download")
    assert download.content == b"test-output"
    assert hashlib.sha256(download.content).hexdigest() == artifact["sha256"]
    assert (tmp_path / "images" / image_id / "source").read_bytes() == b"test-source"
    assert len(Store(tmp_path).list("artifact")) == 1
    assert client.get(f"/api/artifacts/{artifact_id}/manifest").json()["sha256"] == artifact["sha256"]


def test_failed_build_never_publishes_partial_artifact(client, tmp_path):
    image_id = imported(client)
    client.app.state.engine.fail_build = True
    result = client.post(f"/api/images/{image_id}/build", json={}).json()
    job = finished(client, result["job_id"])
    assert job["status"] == "failed"
    assert "validation" in job["error"]
    assert client.get("/api/artifacts").json() == []
    assert list((tmp_path / "builds").iterdir()) == []


def test_refresh_inspection_updates_boot_evidence_and_preserves_source(client, tmp_path, monkeypatch):
    image_id = imported(client)
    previous = client.get(f"/api/images/{image_id}").json()
    engine_inspect = client.app.state.engine.inspect
    boot = {"mode": "bios", "label": "Legacy BIOS", "supported_firmware": ["BIOS"],
            "recommended_firmware": "BIOS", "boot_tested": False}

    def inspect(path):
        result = engine_inspect(path)
        result["boot"] = boot
        return result

    monkeypatch.setattr(client.app.state.engine, "inspect", inspect)
    client.app.state.store.update("image", image_id, import_warnings=["Imported an OCI archive"])
    source = tmp_path / "images" / image_id / "source"
    before_stat = source.stat()
    response = client.post(f"/api/images/{image_id}/inspect")
    assert response.status_code == 202, response.text
    assert response.json()["image_id"] == image_id
    job = finished(client, response.json()["job_id"])
    assert job["kind"] == "inspect" and job["status"] == "succeeded", job
    detail = client.get(f"/api/images/{image_id}").json()
    assert detail["status"] == "ready" and detail["inspection_status"] == "ready"
    assert detail["inspection"]["boot"] == boot
    assert detail["inspection"]["warnings"] == ["Imported an OCI archive"]
    assert detail["inspected_at"] > previous["inspected_at"]
    assert "source_path" not in detail
    assert source.read_bytes() == b"test-source"
    assert source.stat().st_mtime_ns == before_stat.st_mtime_ns
    assert source.stat().st_mode == before_stat.st_mode


def test_refresh_failure_retains_previous_inspection(client, tmp_path, monkeypatch):
    image_id = imported(client)
    previous = client.get(f"/api/images/{image_id}").json()

    def fail_inspection(path):
        raise RuntimeError("Unable to read disk boot metadata")

    monkeypatch.setattr(client.app.state.engine, "inspect", fail_inspection)
    response = client.post(f"/api/images/{image_id}/inspect")
    assert finished(client, response.json()["job_id"])["status"] == "failed"
    detail = client.get(f"/api/images/{image_id}").json()
    assert detail["status"] == "ready" and detail["inspection_status"] == "failed"
    assert detail["inspection"] == previous["inspection"]
    assert detail["inspected_at"] == previous["inspected_at"]
    assert "Unable to read disk" in detail["inspection_error"]
    assert (tmp_path / "images" / image_id / "source").read_bytes() == b"test-source"


def test_refresh_blocks_duplicate_inspection_and_stale_builds(client, monkeypatch):
    image_id = imported(client)
    entered, resume = Event(), Event()
    engine_inspect = client.app.state.engine.inspect

    def wait_inspection(path):
        entered.set()
        assert resume.wait(5), "Test did not release the inspection worker"
        return engine_inspect(path)

    monkeypatch.setattr(client.app.state.engine, "inspect", wait_inspection)
    response = client.post(f"/api/images/{image_id}/inspect")
    try:
        assert entered.wait(3)
        detail = client.get(f"/api/images/{image_id}").json()
        assert detail["status"] == "ready" and detail["inspection_status"] == "running"
        assert detail["inspection"]["files"]["/etc/fstab"] == "# test\n"
        assert client.post(f"/api/images/{image_id}/inspect").status_code == 409
        assert client.post(f"/api/images/{image_id}/build", json={}).status_code == 409
        assert client.post(f"/api/images/{image_id}/oci/plan", json={"oci": {}}).status_code == 409
    finally:
        resume.set()
    assert finished(client, response.json()["job_id"])["status"] == "succeeded"
    assert len([job for job in client.get("/api/jobs").json() if job["kind"] == "inspect"]) == 1


def test_refresh_requires_present_imported_source(client, tmp_path):
    assert client.post("/api/images/missing/inspect").status_code == 404
    incomplete = client.app.state.store.create("image", status="importing", name="incomplete.img")
    assert client.post(f"/api/images/{incomplete['id']}/inspect").status_code == 409
    image_id = imported(client)
    (tmp_path / "images" / image_id / "source").unlink()
    assert client.post(f"/api/images/{image_id}/inspect").status_code == 410


def test_build_admission_cannot_capture_old_evidence_then_queue_after_refresh(client, monkeypatch):
    image_id = imported(client)
    build_entered, refresh_entered, release_build = Event(), Event(), Event()
    jobs = client.app.state.jobs
    original_build, original_inspect = jobs.build, jobs.inspect_image

    def paused_build(image, recipe):
        build_entered.set()
        assert release_build.wait(5)
        return original_build(image, recipe)

    def refresh_attempt(image):
        refresh_entered.set()
        return original_inspect(image)

    monkeypatch.setattr(jobs, "build", paused_build)
    monkeypatch.setattr(jobs, "inspect_image", refresh_attempt)
    with ThreadPoolExecutor(max_workers=2) as requests:
        build_request = requests.submit(client.post, f"/api/images/{image_id}/build", json={})
        try:
            assert build_entered.wait(3)
            refresh_request = requests.submit(client.post, f"/api/images/{image_id}/inspect")
            assert refresh_entered.wait(3)
            # Build already captured the inspection. Refresh must wait until
            # this build is queued, or it could overtake that captured result.
            with pytest.raises(TimeoutError):
                refresh_request.result(timeout=0.1)
        finally:
            release_build.set()
        build_response, refresh_response = build_request.result(5), refresh_request.result(5)
    assert build_response.status_code == refresh_response.status_code == 202
    assert finished(client, build_response.json()["job_id"])["status"] == "succeeded"
    assert finished(client, refresh_response.json()["job_id"])["status"] == "succeeded"
    assert [job["kind"] for job in client.get("/api/jobs").json()] == ["inspect", "build", "import"]


@pytest.mark.parametrize("inspection_status", ["queued", "running"])
def test_restart_recovers_refresh_without_removing_source(tmp_path, inspection_status):
    store = Store(tmp_path)
    previous = {"format": "raw", "boot": {"mode": "uefi"}}
    item = store.create("image", status="ready", name="existing.img", inspection_status=inspection_status,
                        inspection=previous, inspected_at="2026-10-27T00:00:00+00:00")
    source = tmp_path / "images" / item["id"] / "source"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"test-source")
    store.update("image", item["id"], source_path=str(source))
    job = store.create("job", status=inspection_status, kind="inspect", image_id=item["id"], logs=[])
    with TestClient(create_app(Settings(data_dir=tmp_path), FakeEngine())) as client:
        detail = client.get(f"/api/images/{item['id']}").json()
        assert detail["status"] == "ready" and detail["inspection_status"] == "failed"
        assert detail["inspection"] == previous
        assert "restart" in detail["inspection_error"]
        assert client.get(f"/api/jobs/{job['id']}").json()["status"] == "failed"
        assert source.read_bytes() == b"test-source"
        response = client.post(f"/api/images/{item['id']}/inspect")
        assert finished(client, response.json()["job_id"])["status"] == "succeeded"


def test_cookie_auth_and_cross_origin_protection(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path, api_token="test-secret"), FakeEngine())) as client:
        assert client.get("/api/health").json()["auth_required"]
        assert client.get("/api/images").status_code == 401
        assert client.post("/api/session", json={"token": "wrong"}).status_code == 401
        login = client.post("/api/session", json={"token": "test-secret"})
        assert login.status_code == 200
        assert "HttpOnly" in login.headers["set-cookie"]
        assert "test-secret" not in login.headers["set-cookie"]
        assert client.get("/api/images").status_code == 200
        assert client.post("/api/session", json={"token": "test-secret"}, headers={"origin": "https://evil.example"}).status_code == 403
        client.delete("/api/session")
        assert client.get("/api/images").status_code == 401
        assert client.get("/api/images", headers={"Authorization": "Bearer test-secret"}).status_code == 200


def test_local_without_token_rejects_unknown_host(client):
    assert client.get("/api/images", headers={"host": "rebind.example"}).status_code == 400


@pytest.mark.parametrize("recipe", [
    {"target": "azure", "output_format": "qcow2"},
    {"files": [{"path": "/etc/../../tmp/host", "content": "bad"}]},
    {"services": [{"name": "evil;touch /tmp/oops", "action": "enable"}]},
    {"packages_install": ["--config=/tmp/evil"], "allow_network": True},
    {"packages_install": ["kernel"]},
    {"partition_changes": [{"device": "/dev/sda1", "size_mib": 0}]},
    {"disk_size_gib": -1},
    {"kernel_args": "hello\nmalicious"},
    {"boot_migration": {"enabled": True, "esp_size_mib": 511}},
    {"boot_migration": {"enabled": True, "esp_size_mib": 2049}},
    {"boot_migration": {"enabled": True, "host_device": "/dev/disk0"}},
])
def test_invalid_recipe_rejected_before_job(client, recipe):
    assert client.post("/api/images/nonexistent/build", json=recipe).status_code == 422
    assert client.get("/api/jobs").json() == []


def test_missing_engine_is_honest_and_does_not_queue(tmp_path):
    engine = FakeEngine()
    engine.capabilities = lambda: {"available": False, "missing": ["qemu-img"]}
    with TestClient(create_app(Settings(data_dir=tmp_path), engine)) as client:
        assert client.get("/api/health").json()["status"] == "engine_unavailable"
        response = client.post("/api/images/upload", files={"file": ("test.raw", b"test-source")})
        assert response.status_code == 503
        assert client.get("/api/jobs").json() == []


def test_upload_limit(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path, max_upload_gib=8 / 1024**3), FakeEngine())) as client:
        response = client.post("/api/images/upload", files={"file": ("test.img", b"test-source")})
        assert response.status_code == 413
        assert client.get("/api/images").json() == []
        assert client.post("/api/images/upload", content=b"x", headers={"content-length": "999999999"}).status_code == 413


def test_s3_roundtrip_uses_server_transfer(client, monkeypatch):
    calls = []

    def fake_download(location, destination, settings, log):
        calls.append(("download", location))
        destination.write_bytes(b"test-source")

    def fake_upload(location, source, settings, log):
        calls.append(("upload", location))
        assert source.read_bytes() == b"test-output"
        return {"url": location["url"]}

    monkeypatch.setattr(transfers, "download", fake_download)
    monkeypatch.setattr(transfers, "upload", fake_upload)
    imported_job = client.post("/api/images/import", json={"url": "s3://my-bucket/path/disk.qcow2"}).json()
    assert finished(client, imported_job["job_id"])["status"] == "succeeded"
    job_id = client.post(f"/api/images/{imported_job['image_id']}/build", json={}).json()["job_id"]
    artifact = finished(client, job_id)["result"]["artifact_id"]
    job_id = client.post(f"/api/artifacts/{artifact}/upload", json={"url": "s3://my-bucket/new.qcow2"}).json()["job_id"]
    assert finished(client, job_id)["status"] == "succeeded"
    assert [call[0] for call in calls] == ["download", "upload"]


def test_restart_marks_interrupted_jobs_failed(tmp_path):
    store = Store(tmp_path)
    image = store.create("image", status="importing", name="old.raw")
    job = store.create("job", status="running", kind="import", image_id=image["id"], logs=[])
    abandoned_build = tmp_path / "builds" / "incomplete"
    abandoned_build.mkdir(parents=True)
    (abandoned_build / "partial.qcow2").write_bytes(b"partial")
    published_build = tmp_path / "builds" / "published"
    published_build.mkdir()
    (published_build / "result.qcow2").write_bytes(b"published")
    store.create("artifact", path=str(published_build / "result.qcow2"))
    with TestClient(create_app(Settings(data_dir=tmp_path), FakeEngine())) as client:
        assert client.get(f"/api/jobs/{job['id']}").json()["status"] == "failed"
        assert client.get(f"/api/images/{image['id']}").json()["status"] == "failed"
        assert not abandoned_build.exists()
        assert (published_build / "result.qcow2").read_bytes() == b"published"


def test_workspace_cannot_be_opened_by_two_workers(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path), FakeEngine())):
        with pytest.raises(RuntimeError, match="Another Forge process"):
            with TestClient(create_app(Settings(data_dir=tmp_path), FakeEngine())):
                pass


def test_malformed_s3_url_returns_user_error(client):
    response = client.post("/api/images/import", json={"url": "s3://bucket:bad/image.qcow2"})
    assert response.status_code == 400
    assert client.get("/api/jobs").json() == []


def test_oci_catalog_and_global_schema_validation(client):
    assert len(client.get("/api/oci/catalog").json()["capabilities"]) == 13
    schema = {"Compute.Future": {"descriptorType": "boolean", "defaultValue": False}}
    response = client.post("/api/oci/catalog", json={"schema": {"data": {"schema-data": schema}}})
    assert response.status_code == 200
    assert response.json()["capabilities"][0]["key"] == "Compute.Future"
    assert client.post("/api/oci/catalog", json={"schema": {"X": {"descriptorType": "executable"}}}).status_code == 422


def test_oci_plan_blockers_prevent_builds(client, monkeypatch):
    image_id = imported(client)
    monkeypatch.setattr("forge.oci_guest.plan_guest", lambda *a, **k: {"changes": [], "blockers": ["UEFI bootloader is missing"], "warnings": []})
    plan = client.post(f"/api/images/{image_id}/oci/plan", json={"oci": {}})
    assert plan.status_code == 200
    assert not plan.json()["ready_to_build"]
    build = client.post(f"/api/images/{image_id}/build", json={"oci": {}})
    assert build.status_code == 422 and "UEFI" in build.text
    assert len(client.get("/api/jobs").json()) == 1
    secure = client.post(f"/api/images/{image_id}/build", json={"oci": {"capabilities": {"Compute.SecureBoot": {"default_value": True}}}})
    assert secure.status_code == 422


def test_oci_build_publishes_complete_downloadable_configuration(client, monkeypatch):
    image_id = imported(client)
    monkeypatch.setattr("forge.oci_guest.plan_guest", lambda *a, **k: {"changes": [], "blockers": [], "warnings": []})
    response = client.post(f"/api/images/{image_id}/build", json={"oci": {"global_schema_version": "tenancy-version"}})
    assert response.status_code == 202, response.text
    job = finished(client, response.json()["job_id"])
    assert job["status"] == "succeeded", job
    artifact_id = job["result"]["artifact_id"]
    artifact = client.get(f"/api/artifacts/{artifact_id}").json()
    assert artifact["oci_config"]["capability_count"] == 13
    assert "oci_bundle_path" not in artifact
    response = client.get(f"/api/artifacts/{artifact_id}/oci-bundle")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = archive.namelist()
        assert "image-import.json" in names and "image-capability-schema.json" in names
        assert "image.qcow2" not in names
        schema = json.loads(archive.read("image-capability-schema.json"))
        assert len(schema["schemaData"]) == 13
        assert schema["globalImageCapabilitySchemaVersionName"] == "tenancy-version"
        assert "isPvEncryptionInTransitEnabled" in json.loads(archive.read("instance-launch-fragment.json"))


def test_uefi_plan_for_old_import_requires_refresh_and_never_mutates(client, tmp_path):
    image_id = imported(client)
    previous = client.get(f"/api/images/{image_id}").json()
    response = client.post(f"/api/images/{image_id}/uefi/plan", json={"boot_migration": {"enabled": True}})
    assert response.status_code == 200, response.text
    assert not response.json()["ready_to_migrate"]
    assert "refresh" in " ".join(response.json()["blockers"]).lower()
    assert client.get(f"/api/images/{image_id}").json() == previous
    assert len(client.get("/api/jobs").json()) == 1
    assert (tmp_path / "images" / image_id / "source").read_bytes() == b"test-source"
    build = client.post(f"/api/images/{image_id}/build", json={"boot_migration": {"enabled": True}})
    assert build.status_code == 422 and "UEFI migration" in build.text
    assert len(client.get("/api/jobs").json()) == 1


def test_uefi_migration_plan_waits_for_active_inspection(client):
    image_id = imported(client)
    client.app.state.store.update("image", image_id, inspection_status="queued")
    response = client.post(f"/api/images/{image_id}/uefi/plan", json={"boot_migration": {"enabled": True}})
    assert response.status_code == 409
    assert client.post(f"/api/images/{image_id}/uefi/plan", json={"boot_migration": {"esp_size_mib": 1}}).status_code == 422


def test_feasible_migration_recipe_reaches_worker_and_manifest(client, tmp_path, monkeypatch):
    image_id = imported(client)
    seen = []

    def migration_plan(inspection, options, allow_network=False):
        seen.append((options, allow_network))
        return {"requested": True, "ready_to_migrate": True, "blockers": [], "warnings": [],
                "changes": ["Append EFI system partition"], "growth_bytes": 513 * 1024**2,
                "layout": {"action": "append"}, "requires_packages": []}

    monkeypatch.setattr("forge.uefi.plan_migration", migration_plan)
    config = {"enabled": True, "esp_size_mib": 768, "install_packages": True}
    response = client.post(f"/api/images/{image_id}/uefi/plan", json={"boot_migration": config, "allow_network": True})
    assert response.status_code == 200 and response.json()["ready_to_migrate"]
    response = client.post(f"/api/images/{image_id}/build", json={"boot_migration": config, "allow_network": True})
    assert response.status_code == 202, response.text
    result = finished(client, response.json()["job_id"])
    assert result["status"] == "succeeded", result
    artifact = client.get(f"/api/artifacts/{result['result']['artifact_id']}/manifest").json()
    assert artifact["recipe"]["boot_migration"] == config
    assert seen == [(config, True), (config, True)]
    assert (tmp_path / "images" / image_id / "source").read_bytes() == b"test-source"


def test_uefi_migration_growth_respects_server_capacity(client, monkeypatch):
    image_id = imported(client)
    monkeypatch.setattr("forge.uefi.plan_migration", lambda *a, **k: {
        "ready_to_migrate": True, "blockers": [], "growth_bytes": 513 * 1024**2})
    response = client.post(f"/api/images/{image_id}/build", json={
        "disk_size_gib": client.app.state.settings.max_virtual_gib, "boot_migration": {"enabled": True}})
    assert response.status_code == 422 and "FORGE_MAX_VIRTUAL_GIB" in response.text
    assert len(client.get("/api/jobs").json()) == 1


@pytest.mark.parametrize("route,field", [("storage", "storage_rebuild"), ("platform", "platform_migration")])
def test_new_plans_require_refresh_for_old_imports_without_mutating_sources(client, tmp_path, route, field):
    image_id = imported(client)
    before = client.get(f"/api/images/{image_id}").json()
    payload = {field: {"enabled": True}}
    preview = client.post(f"/api/images/{image_id}/{route}/plan", json=payload)
    assert preview.status_code == 200, preview.text
    assert not preview.json()["ready"]
    assert "refresh" in " ".join(preview.json()["blockers"]).lower()
    assert client.get(f"/api/images/{image_id}").json() == before
    assert client.post(f"/api/images/{image_id}/build", json=payload).status_code == 422
    assert len(client.get("/api/jobs").json()) == 1
    assert (tmp_path / "images" / image_id / "source").read_bytes() == b"test-source"


@pytest.mark.parametrize("route,field", [("storage", "storage_rebuild"), ("platform", "platform_migration")])
def test_new_plans_wait_for_in_progress_inspection(client, route, field):
    image_id = imported(client)
    client.app.state.store.update("image", image_id, inspection_status="running")
    assert client.post(f"/api/images/{image_id}/{route}/plan", json={field: {"enabled": True}}).status_code == 409


@pytest.mark.parametrize("recipe", [
    {"storage_rebuild": {"enabled": True, "sizes": [{"device": "/dev/sda1", "size_mib": 512}]},
     "expand_partition": "/dev/sda1"},
    {"storage_rebuild": {"enabled": True, "sizes": [{"device": "/dev/vg/root", "size_mib": 512}] * 2}},
    {"storage_rebuild": {"enabled": True, "sizes": [{"device": "/dev/../etc", "size_mib": 512}]}},
    {"platform_migration": {"enabled": True, "source": "vm", "target": "vm"}},
    {"platform_migration": {"enabled": True, "nic_driver": "mlx5_core; reboot"}},
])
def test_migration_and_rebuild_schema_reject_ambiguous_or_unsafe_inputs(client, recipe):
    image_id = imported(client)
    assert client.post(f"/api/images/{image_id}/build", json=recipe).status_code == 422
    assert len(client.get("/api/jobs").json()) == 1


def test_real_storage_plan_is_admitted_and_recipe_survives_worker_and_manifest(client, tmp_path):
    from test_storage import inspected, OPTIONS
    image_id = imported(client)
    client.app.state.store.update("image", image_id, inspection=inspected())
    recipe = {"storage_rebuild": OPTIONS, "disk_size_gib": 10_000_000_000 / 1024**3}
    preview = client.post(f"/api/images/{image_id}/storage/plan", json=recipe)
    assert preview.status_code == 200 and preview.json()["ready"], preview.text
    assert preview.json()["layout"]["disk_size_after"] == 10_000_000_000
    response = client.post(f"/api/images/{image_id}/build", json=recipe)
    assert response.status_code == 202, response.text
    job = finished(client, response.json()["job_id"])
    assert job["status"] == "succeeded"
    manifest = client.get(f"/api/artifacts/{job['result']['artifact_id']}/manifest").json()
    assert manifest["recipe"]["storage_rebuild"] == OPTIONS
    assert manifest["recipe"]["disk_size_gib"] == recipe["disk_size_gib"]
    assert (tmp_path / "images" / image_id / "source").read_bytes() == b"test-source"


def test_real_vm_plan_and_profile_survive_worker_and_manifest(client):
    from test_platform import image, options
    image_id = imported(client)
    client.app.state.store.update("image", image_id, inspection=image())
    profile = options()
    preview = client.post(f"/api/images/{image_id}/platform/plan", json={"platform_migration": profile})
    assert preview.status_code == 200 and preview.json()["ready"], preview.text
    response = client.post(f"/api/images/{image_id}/build", json={"platform_migration": profile})
    assert response.status_code == 202, response.text
    job = finished(client, response.json()["job_id"])
    manifest = client.get(f"/api/artifacts/{job['result']['artifact_id']}/manifest").json()
    for key, value in profile.items():
        assert manifest["recipe"]["platform_migration"][key] == value
