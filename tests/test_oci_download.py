from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import tarfile
from threading import Event
from unittest.mock import Mock

import pytest

from forge import oci_archive
from test_api import client
from test_oci_archive import qcow


def export(client, tmp_path, **changes):
    store = client.app.state.store
    folder = tmp_path / "builds" / "shared"
    folder.mkdir(parents=True, exist_ok=True)
    disk = qcow(folder / "published.qcow2")
    fields = dict(path=str(disk), filename=disk.name, size=disk.stat().st_size,
                  sha256=hashlib.sha256(disk.read_bytes()).hexdigest(), target="oci", format="qcow2",
                  recipe={"target": "oci", "oci": {"import_options": {
                      "operating_system": "Ubuntu", "operating_system_version": "26.04.1"}}},
                  shape_compatibility_resolution={"effective_shapes": [{"shape": "VM.Standard.A2.Flex", "max_ocpus": 4}]})
    return store.create("artifact", **{**fields, **changes})


def metadata(response):
    assert response.status_code == 200, response.text if response.status_code != 200 else ""
    with tarfile.open(fileobj=io.BytesIO(response.content)) as archive:
        assert archive.getnames() == ["image_metadata.json", "output.QCOW2"]
        return json.load(archive.extractfile("image_metadata.json")), archive.extractfile("output.QCOW2").read()


def test_download_archives_existing_verified_disk_and_honors_ranges_renames_and_delete(client, tmp_path, monkeypatch):
    item = export(client, tmp_path)
    store = client.app.state.store
    sibling = store.create("artifact", path=str(Path(item["path"]).with_name("other.qcow2")), format="qcow2")
    base = "/api/artifacts/" + item["id"]
    url = base + "/oci-archive"
    assert client.get(base).json()["oci_archive_available"]
    assert client.get("/api/artifacts").json()[1]["oci_archive_available"]
    monkeypatch.setattr(client.app.state.jobs, "inspect_export_os", Mock(side_effect=AssertionError("unexpected inspection")))
    response = client.get(url)
    contents, disk = metadata(response)
    assert contents["operatingSystemVersion"] == "26.04.1"
    assert contents["additionalMetadata"]["shapeCompatibilities"] == [
        {"internalShapeName": "VM.Standard.A2.Flex", "ocpuConstraints": {"max": 4}, "memoryConstraints": None}]
    assert contents["externalLaunchOptions"]["networkType"] == "PARAVIRTUALIZED"
    assert hashlib.sha256(disk).hexdigest() == item["sha256"]
    assert client.get(base + "/download").content == disk
    assert "published.oci" in response.headers["content-disposition"]
    assert client.patch(base, json={"name": "Ubuntu ARM"}).json()["oci_archive_available"]
    monkeypatch.setattr(oci_archive, "write_archive", Mock(side_effect=AssertionError("unexpected repackaging")))
    ranged = client.get(url, headers={"Range": "bytes=498-523"})
    assert ranged.status_code == 206 and ranged.content == response.content[498:524]
    assert ranged.headers["etag"] == response.headers["etag"]
    assert "Ubuntu%20ARM.oci" in ranged.headers["content-disposition"]
    assert client.get("/api/jobs").json() == []
    cache = store.archive_cache_dir(item["id"])
    assert cache.is_dir() and client.delete(base).status_code == 204 and not cache.exists()
    assert client.get("/api/artifacts/" + sibling["id"]).status_code == 200


def test_old_export_uses_inspected_os_only_if_configured_and_final_labels_are_incomplete(client, tmp_path, monkeypatch):
    item = export(client, tmp_path, oci_archive_os={"operating_system": "Debian"}, recipe={
        "oci": {"import_options": {"operating_system": "Unknown Linux"}}})
    inspect = Mock(return_value={"operating_system": "Linux", "operating_system_version": "13"})
    monkeypatch.setattr(client.app.state.jobs, "inspect_export_os", inspect)
    contents, _ = metadata(client.get("/api/artifacts/" + item["id"] + "/oci-archive"))
    assert (contents["operatingSystem"], contents["operatingSystemVersion"]) == ("Debian", "13")
    inspect.assert_called_once_with(Path(item["path"]))
    assert client.get("/api/artifacts/" + item["id"] + "/oci-archive").status_code == 200
    assert inspect.call_count == 1


def test_archive_rechecks_corrupt_cache_and_source_checksum_before_serving(client, tmp_path):
    item = export(client, tmp_path)
    cache = client.app.state.store.archive_cache_dir(item["id"])
    url = "/api/artifacts/" + item["id"] + "/oci-archive"
    good = client.get(url).content
    path = cache / "image.oci"
    with path.open("r+b") as handle:
        handle.write(b"bad")
    assert client.get(url).content == good
    disk = Path(item["path"])
    with disk.open("r+b") as handle:
        handle.seek(-1, 2)
        handle.write(b"X")
    damaged = client.get(url)
    assert damaged.status_code == 409 and "checksum" in damaged.json()["detail"]
    assert not cache.exists()
    disk.unlink()
    assert client.get(url).status_code == 410


def test_concurrent_downloads_package_once_and_block_deletion(client, tmp_path, monkeypatch):
    item = export(client, tmp_path)
    base = "/api/artifacts/" + item["id"]
    entered, release = Event(), Event()
    real = oci_archive.write_archive
    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return real(*args, **kwargs)
    package = Mock(side_effect=delayed)
    monkeypatch.setattr(oci_archive, "write_archive", package)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(client.get, base + "/oci-archive")
        assert entered.wait(5)
        second = pool.submit(client.get, base + "/oci-archive")
        try:
            assert client.delete(base).status_code == 409
        finally:
            release.set()
        assert first.result().content == second.result().content
        assert first.result().status_code == second.result().status_code == 200
    assert package.call_count == 1


@pytest.mark.parametrize("changes", [{"target": "generic"}, {"format": "raw"}, {"recipe": {"oci": None}}])
def test_other_exports_have_no_alternate_download(client, tmp_path, changes):
    item = export(client, tmp_path, **changes)
    url = "/api/artifacts/" + item["id"]
    assert not client.get(url).json()["oci_archive_available"]
    assert client.get(url + "/oci-archive").status_code == 404
    assert client.get(url + "/download").status_code == 200
