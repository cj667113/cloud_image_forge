FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

# The appliance uses its own Linux kernel; it never mounts guest disks on the host.
# Keep the distro Python ABI so python3-guestfs is available inside the venv.
RUN case "$(dpkg --print-architecture)" in \
        amd64) set -- qemu-system-x86 linux-image-amd64 ;; \
        arm64) set -- qemu-system-arm linux-image-arm64 ;; \
        *) echo "Forge requires an amd64 or arm64 Linux container" >&2; exit 1 ;; \
    esac \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl python3 python3-venv python3-guestfs \
        libguestfs-tools libguestfs-xfs guestfs-tools \
        qemu-utils "$@" supermin \
        lvm2 xfsprogs e2fsprogs dosfstools gdisk \
    && chmod a+r /boot/vmlinuz-* \
    && rm -rf /var/lib/apt/lists/*

# Debian's minimal appliance omits SELinux tools unless requested explicitly.
# Install them in the worker and include them when supermin builds its appliance.
RUN apt-get update \
    && apt-get install -y --no-install-recommends policycoreutils selinux-utils libzstd1 ipxe-qemu \
    && set -- /usr/lib/*/guestfs/supermin.d/packages \
    && test "$#" -eq 1 && test -f "$1" \
    && printf 'policycoreutils\nselinux-utils\n' > "${1%/*}/zz-forge-selinux-packages" \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin forge \
    && mkdir -p /app /data/tmp /var/tmp/forge \
    && chown forge:forge /data /data/tmp /var/tmp/forge \
    && python3 -m venv --system-site-packages /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LIBGUESTFS_BACKEND=direct \
    LIBGUESTFS_BACKEND_SETTINGS=force_tcg \
    LIBGUESTFS_CACHEDIR=/var/tmp/forge \
    TMPDIR=/data/tmp \
    FORGE_DATA_DIR=/data

WORKDIR /app
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY --chown=forge:forge forge ./forge
COPY --chown=forge:forge scripts ./scripts

USER forge
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import json, sys, urllib.request; health = json.load(urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4)); sys.exit(0 if health.get('status') == 'ok' and health.get('engine', {}).get('available') is True else 1)" || exit 1

# One process owns the persistent queue. Do not add uvicorn workers.
CMD ["uvicorn", "forge.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
