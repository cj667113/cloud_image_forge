"""Bounded transfers; credentials are resolved only by the server's AWS SDK."""
import http.client
import ipaddress
from pathlib import Path
import shutil
import socket
import ssl
import tarfile
import time
from urllib.parse import unquote, urlsplit

from .config import Settings


class TransferError(ValueError):
    pass


def split_url(url: str):
    try:
        if any(char in url for char in "\r\n\t"):
            raise ValueError("Control character in URL")
        parsed = urlsplit(url)
        _ = parsed.port
        return parsed
    except ValueError as exc:
        raise TransferError("Malformed object-storage URL") from exc


def check_space(path: Path, required: int):
    if shutil.disk_usage(path).free < required + 64 * 1024**2:
        raise TransferError("Insufficient workspace disk space for this operation")


def parse_s3(url: str) -> tuple[str, str]:
    parsed = split_url(url)
    if parsed.scheme != "s3" or not parsed.hostname or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        raise TransferError("Use s3://bucket/object-key without embedded credentials or query parameters")
    key = unquote(parsed.path.lstrip("/"))
    if not key or len(key.encode()) > 1024:
        raise TransferError("S3 URL must include an object key of at most 1024 bytes")
    return parsed.hostname, key


def resolve_url(url: str, allow_private: bool = False) -> tuple[object, str]:
    parsed = split_url(url)
    if parsed.scheme not in ({"https", "http"} if allow_private else {"https"}):
        raise TransferError("Use HTTPS; HTTP is allowed only with FORGE_ALLOW_PRIVATE_ENDPOINTS=true")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise TransferError("URL must have a host, without embedded credentials or a fragment")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except (OSError, ValueError) as exc:
        raise TransferError("Unable to resolve the object-storage host") from exc
    ips = list(dict.fromkeys(item[4][0] for item in addresses))
    if not ips or (not allow_private and any(not ipaddress.ip_address(ip).is_global for ip in ips)):
        raise TransferError("Private, loopback, and link-local endpoints require FORGE_ALLOW_PRIVATE_ENDPOINTS=true")
    return parsed, ips[0]


def validate_location(location: dict, settings: Settings, s3_only: bool = False):
    url = location["url"]
    if url.startswith("s3://"):
        parse_s3(url)
    elif s3_only:
        raise TransferError("The upload destination must be s3://bucket/object-key")
    else:
        resolve_url(url, settings.allow_private_endpoints)
    endpoint = location.get("endpoint_url")
    if endpoint:
        if not url.startswith("s3://"):
            raise TransferError("Custom S3 endpoints apply only to s3:// URLs")
        parsed, _ = resolve_url(endpoint, settings.allow_private_endpoints)
        if parsed.query or parsed.path not in {"", "/"}:
            raise TransferError("S3 endpoint must be an origin such as https://s3.example.com")


def s3_client(location: dict, settings: Settings):
    import boto3
    from botocore.config import Config

    validate_location(location, settings, s3_only=True)
    client = boto3.client("s3", endpoint_url=location.get("endpoint_url"), region_name=location.get("region") or None,
                        config=Config(connect_timeout=30, read_timeout=120, retries={"max_attempts": 3},
                                      proxies={} if location.get("endpoint_url") else None,
                                      s3={"addressing_style": "path" if location.get("endpoint_url") else "auto"}))
    if location.get("endpoint_url"):
        parsed, ip = resolve_url(location["endpoint_url"], settings.allow_private_endpoints)
        pin_s3_endpoint(client, parsed, ip)
    return client


def pin_s3_endpoint(client, parsed, ip: str):
    """Pin custom endpoint sockets without changing HTTP Host, TLS SNI, or signatures.

    Botocore exposes no public transport factory. This small adapter is tested
    against the locked SDK version; it modifies only this client's pools.
    Redirects to other origins fail closed and proxies are disabled above.
    """
    from botocore.awsrequest import AWSHTTPConnection, AWSHTTPSConnection, AWSHTTPConnectionPool, AWSHTTPSConnectionPool
    from urllib3.util.connection import create_connection
    from urllib3.exceptions import ConnectTimeoutError, NewConnectionError

    expected_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    class PinnedConnection:
        def _new_conn(self):
            if (self.host.lower().rstrip(".") != parsed.hostname.lower().rstrip(".")
                    or self.port != expected_port or self.scheme != parsed.scheme):
                raise TransferError("Custom S3 endpoint redirected to a different origin")
            try:
                return create_connection((ip, self.port), self.timeout,
                                         source_address=self.source_address, socket_options=self.socket_options)
            except socket.timeout as exc:
                raise ConnectTimeoutError(self, "Custom S3 endpoint connection timed out") from exc
            except OSError as exc:
                raise NewConnectionError(self, "Cannot connect to custom S3 endpoint") from exc

    class PinnedHTTP(PinnedConnection, AWSHTTPConnection):
        scheme = "http"

    class PinnedHTTPS(PinnedConnection, AWSHTTPSConnection):
        scheme = "https"

    class HTTPPool(AWSHTTPConnectionPool):
        ConnectionCls = PinnedHTTP

    class HTTPSPool(AWSHTTPSConnectionPool):
        ConnectionCls = PinnedHTTPS

    session = client._endpoint.http_session
    pools = {"http": HTTPPool, "https": HTTPSPool}
    session._pool_classes_by_scheme = pools
    session._manager.pool_classes_by_scheme = pools


def copy_bounded(stream, destination: Path, limit: int, log=lambda _: None, expected: int | None = None) -> int:
    if expected is not None and expected > limit:
        raise TransferError("Source exceeds the configured import size limit")
    check_space(destination.parent, expected if expected is not None else 0)
    count = 0
    last_report = time.monotonic()
    with destination.open("xb") as output:
        while chunk := stream.read(4 * 1024**2):
            count += len(chunk)
            if count > limit:
                raise TransferError("Source exceeds the configured import size limit")
            check_space(destination.parent, len(chunk))
            output.write(chunk)
            if time.monotonic() - last_report > 10:
                log(f"Transferred {count / 1024**2:,.0f} MiB")
                last_report = time.monotonic()
    if expected is not None and count != expected:
        raise TransferError("Source transfer ended before the expected number of bytes arrived")
    if count == 0:
        raise TransferError("The source file is empty")
    return count


def download(location: dict, destination: Path, settings: Settings, log):
    validate_location(location, settings)
    if location["url"].startswith("s3://"):
        client = s3_client(location, settings)
        bucket, key = parse_s3(location["url"])
        response = client.get_object(Bucket=bucket, Key=key)
        try:
            return copy_bounded(response["Body"], destination, settings.max_upload_bytes, log, response.get("ContentLength"))
        finally:
            response["Body"].close()

    parsed, ip = resolve_url(location["url"], settings.allow_private_endpoints)
    # Pin the validated address, while preserving hostname verification and SNI.
    # Redirects and environment HTTP proxies are intentionally not followed.
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    conn = http.client.HTTPConnection(parsed.hostname, port, timeout=60)
    sock = socket.create_connection((ip, port), timeout=60)
    try:
        if parsed.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
        conn.sock = sock
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        conn.request("GET", target, headers={"User-Agent": "CloudImageForge/1", "Accept-Encoding": "identity"})
        response = conn.getresponse()
        if response.status != 200:
            raise TransferError(f"Object download returned HTTP {response.status}; provide a direct object URL (redirects are not followed)")
        length = response.getheader("Content-Length")
        return copy_bounded(response, destination, settings.max_upload_bytes, log, int(length) if length else None)
    finally:
        conn.close()
        sock.close()


def upload(location: dict, source: Path, settings: Settings, log):
    from boto3.s3.transfer import TransferConfig

    client = s3_client(location, settings)
    bucket, key = parse_s3(location["url"])
    log("Uploading artifact to the selected S3 object")
    # Managed multipart transfer aborts incomplete multipart uploads on failure.
    client.upload_file(str(source), bucket, key, Config=TransferConfig(multipart_threshold=32 * 1024**2, max_concurrency=3))
    log("S3 upload completed")
    return {"url": f"s3://{bucket}/{key}", "size": source.stat().st_size}


def unpack_oci(source: Path, name: str, settings: Settings, log) -> tuple[Path, list[str]]:
    """Accept the reference's two-member OCI export, never generic tar extraction."""
    with source.open("rb") as handle:
        header = handle.read(512)
    looks_archive = header[257:262] == b"ustar" or header[:2] == b"\x1f\x8b" or name.lower().endswith((".oci", ".tar", ".tar.gz", ".tgz"))
    if not looks_archive:
        return source, []
    log("Reading an OCI export bundle")
    seen = set()
    image_path = source.parent / "disk.qcow2"
    try:
        with tarfile.open(source, mode="r|*") as archive:
            for member in archive:
                if not member.isfile() or member.name not in {"output.QCOW2", "image_metadata.json"} or member.name in seen:
                    raise TransferError("An OCI bundle must contain only regular root-level output.QCOW2 and image_metadata.json files")
                seen.add(member.name)
                fileobj = archive.extractfile(member)
                target = image_path if member.name == "output.QCOW2" else source.parent / "image_metadata.json"
                limit = settings.max_upload_bytes if member.name == "output.QCOW2" else 1024**2
                copy_bounded(fileobj, target, limit, log, member.size)
    except tarfile.TarError as exc:
        raise TransferError("The OCI archive is damaged or unsupported") from exc
    if seen != {"output.QCOW2", "image_metadata.json"}:
        raise TransferError("An OCI bundle must include output.QCOW2 and image_metadata.json")
    source.unlink()
    return image_path, ["OCI metadata was retained with the source. Standalone exports do not apply that metadata; verify firmware and launch options when importing into OCI."]
