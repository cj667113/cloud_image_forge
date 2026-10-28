"""HTTP application and streaming local-file import."""
from contextlib import asynccontextmanager
import fcntl
import hashlib
import hmac
from pathlib import Path
import shutil
import time
from urllib.parse import urlsplit, unquote

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Settings
from .jobs import Jobs
from .models import (ObjectLocation, Recipe, OciPlanRequest, OciSchemaRequest, UefiPlanRequest,
                     StoragePlanRequest, PlatformPlanRequest)
from .oci import catalog as oci_catalog, compatibility_plan
from .store import Store
from . import transfers


class BodyLimitMiddleware:
    def __init__(self, app, max_upload_bytes: int):
        self.app, self.max_upload_bytes = app, max_upload_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = self.max_upload_bytes + 1024**2 if scope["path"] == "/api/images/upload" else 8 * 1024**2
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length"}, 400)(scope, receive, send)
        if length > limit:
            return await JSONResponse({"detail": "Request exceeds the configured size limit"}, 413)(scope, receive, send)
        received = 0

        async def bounded_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise StarletteHTTPException(413, "Request exceeds the configured size limit")
            return message

        await self.app(scope, bounded_receive, send)


def public(record: dict) -> dict:
    return {key: value for key, value in record.items() if key not in {"path", "source_path", "oci_bundle_path"}}


def session_cookie(secret: str, expires: int) -> str:
    signature = hmac.new(secret.encode(), f"forge-session:{expires}".encode(), hashlib.sha256).hexdigest()
    return f"{expires}.{signature}"


def valid_session(secret: str, cookie: str) -> bool:
    try:
        expires = int(cookie.split(".", 1)[0])
        return time.time() < expires <= time.time() + 86401 and hmac.compare_digest(cookie, session_cookie(secret, expires))
    except (ValueError, TypeError):
        return False


def create_app(settings: Settings | None = None, engine=None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        nonlocal engine
        if engine is None:
            from .engine import ImageEngine
            engine = ImageEngine()
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        with (settings.data_dir / ".worker.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("Another Forge process owns this data directory. Use one worker per workspace.") from exc
            (settings.data_dir / "images").mkdir(exist_ok=True)
            (settings.data_dir / "tmp").mkdir(exist_ok=True)
            store = Store(settings.data_dir)
            store.recover()
            app.state.store, app.state.engine = store, engine
            app.state.jobs = Jobs(settings, store, engine)
            app.state.settings = settings
            try:
                yield
            finally:
                await run_in_threadpool(app.state.jobs.close)
                fcntl.flock(lock, fcntl.LOCK_UN)

    app = FastAPI(title="Cloud Image Forge", version="0.1.0", lifespan=lifespan, redoc_url=None)
    app.add_middleware(BodyLimitMiddleware, max_upload_bytes=settings.max_upload_bytes)
    hosts = ["*"] if settings.api_token else ["localhost", "127.0.0.1", "[::1]", "testserver"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    @app.middleware("http")
    async def boundaries(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            if origin and origin != f"{request.url.scheme}://{request.headers.get('host', '')}":
                return JSONResponse({"detail": "Cross-origin requests are not allowed"}, 403)
            if request.headers.get("sec-fetch-site") == "cross-site":
                return JSONResponse({"detail": "Cross-site requests are not allowed"}, 403)
        if settings.api_token and request.url.path.startswith("/api/") and request.url.path not in {"/api/health", "/api/session"}:
            bearer = request.headers.get("authorization", "")
            authenticated = hmac.compare_digest(bearer, f"Bearer {settings.api_token}") or valid_session(settings.api_token, request.cookies.get("forge_session", ""))
            if not authenticated:
                return JSONResponse({"detail": "Sign in with the server's API token"}, 401)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if request.url.path in {"/docs", "/docs/oauth2-redirect"}:
            # FastAPI's documentation uses Swagger's CDN assets and an inline
            # initializer. The image editor remains entirely local/offline.
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(transfers.TransferError)
    async def transfer_error(request, exc):
        return JSONResponse({"detail": str(exc)}, 400)

    def get_record(kind: str, record_id: str):
        record = app.state.store.get(kind, record_id)
        if record is None:
            raise HTTPException(404, f"{kind.capitalize()} not found")
        return record

    def queue_capacity():
        pending = [j for j in app.state.store.list("job") if j["status"] in {"queued", "running"}]
        if len(pending) >= 32:
            raise HTTPException(429, "The job queue is full. Wait for an active job to finish.")

    def ready_engine():
        info = app.state.engine.capabilities()
        if not info.get("available"):
            raise HTTPException(503, "Image processing requires the Linux container. Missing: " + ", ".join(info.get("missing", [])))
        queue_capacity()

    @app.get("/api/health")
    def health():
        capability = app.state.engine.capabilities()
        return {"status": "ok" if capability.get("available") else "engine_unavailable", "engine": capability,
                "limits": {"max_upload_gib": settings.max_upload_gib, "max_virtual_gib": settings.max_virtual_gib},
                "auth_required": bool(settings.api_token)}

    class Login(BaseModel):
        token: str = Field(max_length=4096)

    @app.post("/api/session")
    def login(body: Login, request: Request):
        if settings.api_token and not hmac.compare_digest(body.token, settings.api_token):
            raise HTTPException(401, "Incorrect API token")
        response = JSONResponse({"authenticated": True})
        if settings.api_token:
            response.set_cookie("forge_session", session_cookie(settings.api_token, int(time.time()) + 86400),
                                max_age=86400, httponly=True, secure=request.url.scheme == "https", samesite="strict")
        return response

    @app.delete("/api/session")
    def logout():
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("forge_session")
        return response

    @app.get("/api/images")
    def images():
        return [public(item) for item in app.state.store.list("image")]

    @app.get("/api/oci/catalog")
    def get_oci_catalog():
        return oci_catalog()

    @app.post("/api/oci/catalog")
    def supplied_oci_catalog(body: OciSchemaRequest):
        try:
            return oci_catalog(body.schema_data)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/images/{image_id}/oci/plan")
    def plan_oci(image_id: str, body: OciPlanRequest):
        with app.state.jobs.inspection_lock:
            image = get_record("image", image_id)
            if image["status"] != "ready" or image.get("inspection_status") in {"queued", "running"}:
                raise HTTPException(409, "Wait for successful inspection before planning OCI preparation")
            return compatibility_plan(image["inspection"], body.oci, body.allow_network,
                                      body.boot_migration.model_dump() if body.boot_migration else None,
                                      platform_migration=body.platform_migration.model_dump() if body.platform_migration else None)

    @app.post("/api/images/{image_id}/uefi/plan")
    def plan_uefi(image_id: str, body: UefiPlanRequest):
        from .uefi import plan_migration
        with app.state.jobs.inspection_lock:
            image = get_record("image", image_id)
            if image["status"] != "ready" or image.get("inspection_status") in {"queued", "running"}:
                raise HTTPException(409, "Wait for successful inspection before planning boot migration")
            return plan_migration(image["inspection"], body.boot_migration.model_dump(), body.allow_network)

    @app.post("/api/images/{image_id}/storage/plan")
    def plan_storage(image_id: str, body: StoragePlanRequest):
        from .storage import plan_rebuild
        with app.state.jobs.inspection_lock:
            image = get_record("image", image_id)
            if image["status"] != "ready" or image.get("inspection_status") in {"queued", "running"}:
                raise HTTPException(409, "Wait for successful inspection before planning storage changes")
            if body.disk_size_gib and body.disk_size_gib > settings.max_virtual_gib:
                raise HTTPException(422, "Requested virtual size exceeds FORGE_MAX_VIRTUAL_GIB")
            return plan_rebuild(image["inspection"], body.storage_rebuild.model_dump(), body.disk_size_gib)

    @app.post("/api/images/{image_id}/platform/plan")
    def plan_machine(image_id: str, body: PlatformPlanRequest):
        from .platform import plan_platform
        with app.state.jobs.inspection_lock:
            image = get_record("image", image_id)
            if image["status"] != "ready" or image.get("inspection_status") in {"queued", "running"}:
                raise HTTPException(409, "Wait for successful inspection before planning machine migration")
            return plan_platform(image["inspection"], body.platform_migration.model_dump(), body.allow_network,
                                 body.oci.model_dump() if body.oci else None, target_provider=body.target,
                                 boot_migration=body.boot_migration.model_dump() if body.boot_migration else None)

    @app.get("/api/images/{image_id}")
    def image_detail(image_id: str):
        return public(get_record("image", image_id))

    @app.post("/api/images/{image_id}/inspect", status_code=202)
    def refresh_inspection(image_id: str):
        ready_engine()
        image = get_record("image", image_id)
        if image["status"] != "ready":
            raise HTTPException(409, "Only a successfully imported image can be inspected again")
        if not Path(image.get("source_path", "")).is_file():
            raise HTTPException(410, "The source file is no longer present. Import the image again.")
        try:
            job = app.state.jobs.inspect_image(image)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"image_id": image["id"], "job_id": job["id"]}

    @app.post("/api/images/upload", status_code=202)
    async def local_import(file: UploadFile = File(...)):
        ready_engine()
        filename = Path((file.filename or "disk.img").replace("\\", "/")).name[:200]
        if file.size is not None and file.size > settings.max_upload_bytes:
            raise HTTPException(413, "Image exceeds the configured import size limit")
        image = app.state.store.create("image", name=filename, status="importing")
        directory = settings.data_dir / "images" / image["id"]
        directory.mkdir()
        incoming = directory / "source"
        try:
            await run_in_threadpool(transfers.copy_bounded, file.file, incoming, settings.max_upload_bytes)
            job = app.state.jobs.import_image(image, incoming)
        except Exception as exc:
            shutil.rmtree(directory, ignore_errors=True)
            app.state.store.update("image", image["id"], status="failed", error="Local upload failed")
            if isinstance(exc, transfers.TransferError):
                raise HTTPException(413 if "limit" in str(exc) else 400, str(exc)) from exc
            raise
        finally:
            await file.close()
        return {"image_id": image["id"], "job_id": job["id"]}

    @app.post("/api/images/import", status_code=202)
    def remote_import(location: ObjectLocation):
        ready_engine()
        data = location.model_dump()
        transfers.validate_location(data, settings)
        filename = Path(unquote(urlsplit(location.url).path)).name[:200] or "remote-image"
        image = app.state.store.create("image", name=filename, status="importing")
        directory = settings.data_dir / "images" / image["id"]
        directory.mkdir()
        job = app.state.jobs.import_image(image, directory / "source", data)
        return {"image_id": image["id"], "job_id": job["id"]}

    @app.post("/api/images/{image_id}/build", status_code=202)
    def build(image_id: str, recipe: Recipe):
        ready_engine()
        with app.state.jobs.inspection_lock:
            image = get_record("image", image_id)
            if image["status"] != "ready" or image.get("inspection_status") in {"queued", "running"}:
                raise HTTPException(409, "Wait for a successful image inspection before building")
            if recipe.disk_size_gib and recipe.disk_size_gib > settings.max_virtual_gib:
                raise HTTPException(422, "Requested virtual size exceeds FORGE_MAX_VIRTUAL_GIB")
            from .architecture import recipe_execution_blocker
            execution_error = recipe_execution_blocker(image["inspection"], recipe.model_dump())
            if execution_error:
                raise HTTPException(422, execution_error)
            migration = recipe.boot_migration.model_dump() if recipe.boot_migration else None
            if recipe.storage_rebuild and recipe.storage_rebuild.enabled:
                from .storage import plan_rebuild
                storage_plan = plan_rebuild(image["inspection"], recipe.storage_rebuild.model_dump(), recipe.disk_size_gib)
                if not storage_plan["ready"]:
                    raise HTTPException(422, "Storage rebuild: " + " ".join(storage_plan["blockers"]))
            if recipe.platform_migration and recipe.platform_migration.enabled:
                from .platform import plan_platform
                platform_plan = plan_platform(image["inspection"], recipe.platform_migration.model_dump(), recipe.allow_network,
                                              recipe.oci.model_dump() if recipe.oci else None, target_provider=recipe.target,
                                              boot_migration=migration)
                if not platform_plan["ready"]:
                    raise HTTPException(422, "Machine migration: " + " ".join(platform_plan["blockers"]))
            if migration and migration["enabled"]:
                from .uefi import plan_migration
                migration_plan = plan_migration(image["inspection"], migration, recipe.allow_network)
                if not migration_plan["ready_to_migrate"]:
                    raise HTTPException(422, "UEFI migration: " + (" ".join(migration_plan["blockers"]) or "The image is not eligible for migration"))
                capacity = recipe.disk_size_gib * 1024**3 if recipe.disk_size_gib else image["inspection"]["virtual_size"]
                if capacity + migration_plan.get("growth_bytes", 0) > settings.max_virtual_gib * 1024**3:
                    raise HTTPException(422, "UEFI migration would exceed FORGE_MAX_VIRTUAL_GIB")
            if recipe.oci:
                plan = compatibility_plan(image["inspection"], recipe.oci, recipe.allow_network, migration,
                                          platform_migration=recipe.platform_migration.model_dump() if recipe.platform_migration else None)
                if plan["blockers"]:
                    raise HTTPException(422, "OCI compatibility: " + " ".join(plan["blockers"]))
            job = app.state.jobs.build(image, recipe.model_dump())
        return {"job_id": job["id"]}

    @app.get("/api/jobs")
    def jobs():
        return app.state.store.list("job")

    @app.get("/api/jobs/{job_id}")
    def job_detail(job_id: str):
        return get_record("job", job_id)

    @app.get("/api/artifacts")
    def artifacts():
        return [public(item) for item in app.state.store.list("artifact")]

    @app.get("/api/artifacts/{artifact_id}")
    def artifact_detail(artifact_id: str):
        return public(get_record("artifact", artifact_id))

    @app.get("/api/artifacts/{artifact_id}/download")
    def download_artifact(artifact_id: str):
        artifact = get_record("artifact", artifact_id)
        if not Path(artifact["path"]).is_file():
            raise HTTPException(410, "The artifact file is no longer present")
        return FileResponse(artifact["path"], media_type="application/octet-stream", filename=artifact["name"])

    @app.get("/api/artifacts/{artifact_id}/manifest")
    def artifact_manifest(artifact_id: str):
        artifact = public(get_record("artifact", artifact_id))
        return JSONResponse(artifact, headers={"Content-Disposition": f'attachment; filename="forge-{artifact_id}.json"'})

    @app.get("/api/artifacts/{artifact_id}/oci-bundle")
    def oci_bundle(artifact_id: str):
        artifact = get_record("artifact", artifact_id)
        path = artifact.get("oci_bundle_path")
        if not path:
            raise HTTPException(404, "This artifact has no OCI capability configuration")
        if not Path(path).is_file():
            raise HTTPException(410, "OCI configuration file is no longer present")
        return FileResponse(path, media_type="application/zip", filename=f"oci-configuration-{artifact_id[:8]}.zip")

    @app.post("/api/artifacts/{artifact_id}/upload", status_code=202)
    def upload_artifact(artifact_id: str, location: ObjectLocation):
        queue_capacity()
        artifact = get_record("artifact", artifact_id)
        transfers.validate_location(location.model_dump(), settings, s3_only=True)
        if not Path(artifact["path"]).is_file():
            raise HTTPException(410, "The artifact file is no longer present")
        job = app.state.jobs.upload(artifact, location.model_dump())
        return {"job_id": job["id"]}

    static = Path(__file__).parent / "static"
    app.mount("/", StaticFiles(directory=static, html=True, check_dir=False), name="ui")
    return app


app = create_app()
