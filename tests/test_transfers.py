import io
from pathlib import Path
import socket
import tarfile

import pytest

from forge.config import Settings
from forge.jobs import public_error
from forge.transfers import TransferError, copy_bounded, parse_s3, resolve_url, unpack_oci, pin_s3_endpoint


def test_s3_keys_and_reject_embedded_credentials():
    assert parse_s3("s3://my-bucket/path/a%20b.qcow2") == ("my-bucket", "path/a b.qcow2")
    for value in ["s3://bucket", "s3://user:password@bucket/x", "https://bucket/x", "s3://bucket/x?token=secret", "s3://bucket:bad/x", "s3://bucket:99999/x"]:
        with pytest.raises(ValueError):
            parse_s3(value)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.1.1", "169.254.169.254", "::1", "192.168.1.1"])
def test_remote_url_blocks_private_resolution(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))])
    with pytest.raises(TransferError, match="Private"):
        resolve_url("https://storage.example/image")
    assert resolve_url("http://storage.example/image", allow_private=True)[1] == ip


def test_bounded_stream_detects_truncation_and_limit(tmp_path):
    with pytest.raises(TransferError, match="limit"):
        copy_bounded(io.BytesIO(b"12345"), tmp_path / "limited", 4)
    with pytest.raises(TransferError, match="expected"):
        copy_bounded(io.BytesIO(b"123"), tmp_path / "truncated", 10, expected=4)


def archive(path, members):
    with tarfile.open(path, "w") as tar:
        for name, data, kind in members:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.type = kind
            tar.addfile(member, io.BytesIO(data))


def test_oci_two_member_archive_preserves_metadata(tmp_path):
    source = tmp_path / "incoming"
    archive(source, [("image_metadata.json", b'{"firmware":"UEFI"}', tarfile.REGTYPE), ("output.QCOW2", b"disk-bytes", tarfile.REGTYPE)])
    image, warnings = unpack_oci(source, "exported-image", Settings(data_dir=tmp_path), lambda _: None)
    assert image.read_bytes() == b"disk-bytes"
    assert (tmp_path / "image_metadata.json").read_bytes() == b'{"firmware":"UEFI"}'
    assert warnings and not source.exists()


@pytest.mark.parametrize("name,kind", [("../escape", tarfile.REGTYPE), ("output.QCOW2", tarfile.SYMTYPE), ("unexpected", tarfile.REGTYPE)])
def test_archive_rejects_paths_links_and_unexpected_members(tmp_path, name, kind):
    source = tmp_path / "incoming"
    archive(source, [(name, b"data", kind)])
    with pytest.raises(TransferError):
        unpack_oci(source, "input.tar", Settings(data_dir=tmp_path), lambda _: None)
    assert not (tmp_path.parent / "escape").exists()


def test_errors_do_not_persist_presigned_query():
    error = public_error(ValueError("Download failed https://example.com/image?X-Amz-Signature=secret"))
    assert "secret" not in error and "[remote endpoint]" in error


def test_custom_s3_pins_connection_and_preserves_tls_hostname(monkeypatch):
    from types import SimpleNamespace
    from urllib.parse import urlsplit

    calls = []
    monkeypatch.setattr("urllib3.util.connection.create_connection", lambda address, *args, **kwargs: calls.append(address))
    session = SimpleNamespace(_manager=SimpleNamespace())
    client = SimpleNamespace(_endpoint=SimpleNamespace(http_session=session))
    pin_s3_endpoint(client, urlsplit("https://s3.example.com"), "93.184.215.14")
    cls = session._manager.pool_classes_by_scheme["https"].ConnectionCls
    connection = cls("s3.example.com", port=443)
    connection._new_conn()
    assert calls == [("93.184.215.14", 443)]
    assert connection.host == "s3.example.com"
    with pytest.raises(TransferError, match="different origin"):
        cls("169.254.169.254", port=443)._new_conn()
    http_cls = session._manager.pool_classes_by_scheme["http"].ConnectionCls
    with pytest.raises(TransferError, match="different origin"):
        http_cls("s3.example.com", port=443)._new_conn()
