# syntax=docker/dockerfile:1
FROM python:3.13-slim

# uv for fast, locked installs (pinned)
COPY --from=ghcr.io/astral-sh/uv:0.10.10 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    HOME=/tmp

# Install runtime deps from the lockfile (no dev deps), then the package.
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --frozen --no-dev

# Run as a non-root, no-login user; own /app so a read-only rootfs still works.
RUN useradd -r -u 10001 mida && chown -R mida:mida /app
USER mida
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8080
# Factory mode: import doesn't require config; accounts/token load at startup.
CMD ["uvicorn", "--factory", "maropost_id_authenticator.api:create_app", \
     "--host", "0.0.0.0", "--port", "8080"]
