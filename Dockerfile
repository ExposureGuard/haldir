# syntax=docker/dockerfile:1.7
#
# Haldir production Dockerfile — multi-stage, non-root, HEALTHCHECK.
#
# Stages:
#   builder  compiles wheels for every dep into /wheels, keeping
#            gcc/libpq-dev out of the final image.
#   runtime  thin python:3.12-slim with only the wheels installed, a
#            non-root user, and a HEALTHCHECK that hits /healthz.
#
# Result: smaller image, no build tools on the attack surface, runs
# as uid 1000 instead of root. SBOM for the installed wheel set is
# generated into /app/sbom.json at build time for procurement review.
#
# Reproducible-ish: every `pip install` uses --no-cache-dir. The build
# stage compiles wheels once; the runtime stage copies + installs them
# without the compiler. Python 3.12 (not 3.14) because that's what the
# test/CI matrix pins and we want the image to match prod.

FROM python:3.12-slim AS builder

# Keep build tools in this stage only. libpq-dev lets psycopg2 link
# its C extension; the runtime stage only needs libpq5.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# ── Runtime ────────────────────────────────────────────────────────────

FROM python:3.12-slim AS runtime

# Runtime-only deps: libpq5 for psycopg2, curl for HEALTHCHECK, tini
# as PID 1 so gunicorn's workers forward signals correctly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libpq5 curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 haldir \
    && useradd  --system --uid 1000 --gid haldir \
                --home-dir /app --shell /usr/sbin/nologin haldir

WORKDIR /app

# Install dependencies from pre-built wheels — no compiler needed.
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

# Copy the app itself AFTER deps so rebuilds on code-only changes stay
# fast (the pip-install layer gets cached).
COPY --chown=haldir:haldir . .

# Generate a CycloneDX SBOM for the installed wheel set. Fails-open:
# if the script isn't present or errors, the build still succeeds —
# the SBOM is a procurement-friendly extra, not a blocking dependency.
RUN python scripts/gen_sbom.py --out /app/sbom.json || true

# A writable data dir for SQLite when not using Postgres. Declared as
# a VOLUME so bind-mounts from the host are the supported path.
RUN mkdir -p /data && chown haldir:haldir /data
VOLUME ["/data"]
ENV HALDIR_DB_PATH=/data/haldir.db

USER haldir:haldir

EXPOSE 8080

# HEALTHCHECK targets /livez (process is alive) — the right semantic
# for Docker's container-level probe. /readyz exists for Kubernetes
# load balancers that need to pull a pod from rotation without
# restarting the container.
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8080/livez || exit 1

# tini handles signal forwarding; gunicorn runs 1 worker + 4 threads
# by default (override with GUNICORN_WORKERS / _THREADS at runtime).
ENTRYPOINT ["/usr/bin/tini", "--"]
# Run migrations before gunicorn binds. `|| true` keeps the container
# alive if migrations fail (operator sees the traceback in logs and
# decides — better than a restart loop that hides the real error).
# Set HALDIR_AUTO_MIGRATE=0 to opt out; the operator then runs
# `python -m haldir_migrate up` in a separate job before deploy.
CMD ["sh", "-c", "\
    if [ \"${HALDIR_AUTO_MIGRATE:-1}\" = \"1\" ]; then \
        python -m haldir_migrate up || true; \
    fi && \
    exec gunicorn api:app \
        --bind 0.0.0.0:8080 \
        --workers ${GUNICORN_WORKERS:-1} \
        --threads ${GUNICORN_THREADS:-4} \
        --timeout 120 \
        --access-logfile - \
        --error-logfile -"]
