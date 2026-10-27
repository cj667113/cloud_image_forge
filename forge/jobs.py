"""One job worker prevents concurrent appliances from exhausting the host."""
from concurrent.futures import ThreadPoolExecutor
import re
import shutil
from pathlib import Path
from threading import RLock

from .config import Settings
from .store import Store, now
from . import transfers


def public_error(exc: Exception) -> str:
    # SDK errors may contain presigned URLs. Never persist their query strings.
    message = str(exc)
    message = re.sub(r"https?://[^\s'\"<>]+", "[remote endpoint]", message)
    return message[:4000] or type(exc).__name__


class Jobs:
    def __init__(self, settings: Settings, store: Store, engine):
        self.settings, self.store, self.engine = settings, store, engine
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="forge-worker")
        # Coordinate request admission with refresh claims, so a build cannot
        # capture old evidence and then be enqueued behind a newer inspection.
        self.inspection_lock = RLock()

    def submit(self, kind: str, action, image_id=None, **details) -> dict:
        job = self.store.create("job", kind=kind, image_id=image_id, status="queued", logs=[], **details)
        self.executor.submit(self._run, job["id"], action)
        return job

    def _run(self, job_id, action):
        self.store.update("job", job_id, status="running", started_at=now())
        try:
            result = action(lambda message: self.store.log(job_id, str(message)))
        except Exception as exc:
            self.store.update("job", job_id, status="failed", error=public_error(exc), finished_at=now())
        else:
            self.store.update("job", job_id, status="succeeded", result=result, finished_at=now())

    def import_image(self, image: dict, incoming: Path, location: dict | None = None):
        def perform(log):
            try:
                if location:
                    log("Downloading source image")
                    transfers.download(location, incoming, self.settings, log)
                source, warnings = transfers.unpack_oci(incoming, image["name"], self.settings, log)
                log("Inspecting the source read-only in the libguestfs appliance")
                inspection = self.engine.inspect(source)
                if inspection["virtual_size"] > self.settings.max_virtual_gib * 1024**3:
                    raise ValueError("Virtual disk exceeds FORGE_MAX_VIRTUAL_GIB")
                inspection.setdefault("warnings", []).extend(warnings)
                source.chmod(0o444)
                self.store.update("image", image["id"], status="ready", source_path=str(source), inspection=inspection,
                                  import_warnings=warnings, inspection_status="ready", inspected_at=now())
                log("Source is ready. Builds will use a separate working copy.")
                return {"image_id": image["id"]}
            except Exception as exc:
                self.store.update("image", image["id"], status="failed", error=public_error(exc))
                shutil.rmtree(incoming.parent, ignore_errors=True)
                raise
        return self.submit("import", perform, image_id=image["id"])

    def inspect_image(self, image: dict):
        with self.inspection_lock:
            return self._inspect_image(image)

    def _inspect_image(self, image: dict):
        image = self.store.queue_inspection(image["id"])

        def perform(log):
            self.store.update("image", image["id"], inspection_status="running")
            try:
                log("Refreshing inspection of the preserved source read-only")
                inspection = self.engine.inspect(Path(image["source_path"]))
                if inspection["virtual_size"] > self.settings.max_virtual_gib * 1024**3:
                    raise ValueError("Virtual disk exceeds FORGE_MAX_VIRTUAL_GIB")
                inspection.setdefault("warnings", []).extend(image.get("import_warnings", []))
                self.store.update("image", image["id"], inspection=inspection, inspection_status="ready",
                                  inspected_at=now(), inspection_error=None)
                log("Inspection refreshed. The source image is unchanged.")
                return {"image_id": image["id"]}
            except Exception as exc:
                self.store.update("image", image["id"], inspection_status="failed", inspection_error=public_error(exc))
                raise

        try:
            return self.submit("inspect", perform, image_id=image["id"])
        except Exception as exc:
            self.store.update("image", image["id"], inspection_status="failed", inspection_error=public_error(exc))
            raise

    def build(self, image: dict, recipe: dict):
        import uuid
        work_dir = self.settings.data_dir / "builds" / uuid.uuid4().hex

        def perform(log):
            try:
                work_dir.mkdir(parents=True)
                log("Building from the preserved source image")
                result = self.engine.build(Path(image["source_path"]), work_dir, image["inspection"], recipe, log)
                artifact_path = Path(result.pop("artifact_path")).resolve()
                if not artifact_path.is_relative_to(work_dir.resolve()) or not artifact_path.is_file():
                    raise RuntimeError("Engine returned an invalid artifact path")
                oci_data = {}
                if recipe.get("oci"):
                    from .oci import OciConfig, write_bundle
                    config = OciConfig.model_validate(recipe["oci"])
                    bundle = work_dir / "oci-configuration.zip"
                    write_bundle(bundle, config, {**result, "name": result.get("filename", artifact_path.name)})
                    oci_data = {"oci_bundle_path": str(bundle), "oci_config": {
                        "capability_count": len(config.capabilities),
                        "schema_version": config.global_schema_version,
                        "guest_preparation": config.guest.prepare,
                        "cloud_boot_tested": False,
                    }}
                    log("OCI import, capability schema, launch options and shape configuration are ready to download")
                # Publish only complete, verified output. Keep the original recipe for reproducibility.
                artifact = self.store.create("artifact", **result, name=result.get("filename", artifact_path.name),
                                             path=str(artifact_path), image_id=image["id"], target=recipe["target"],
                                             size=artifact_path.stat().st_size, recipe=recipe, **oci_data)
                log("Artifact verified and ready to download")
                return {"artifact_id": artifact["id"]}
            except Exception:
                shutil.rmtree(work_dir, ignore_errors=True)
                raise
        return self.submit("build", perform, image_id=image["id"], recipe=recipe)

    def upload(self, artifact: dict, location: dict):
        return self.submit("upload", lambda log: transfers.upload(location, Path(artifact["path"]), self.settings, log),
                           image_id=artifact["image_id"], artifact_id=artifact["id"])

    def close(self):
        self.executor.shutdown(wait=True, cancel_futures=True)
