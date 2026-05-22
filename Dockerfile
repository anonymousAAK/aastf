# Multi-stage build for minimal image
FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir build && \
    python -m build --wheel && \
    pip install --no-cache-dir dist/*.whl

FROM python:3.12-slim AS runtime

# Security: non-root user
RUN groupadd -r aastf && useradd -r -g aastf -d /home/aastf -s /sbin/nologin aastf
WORKDIR /home/aastf

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/aastf /usr/local/bin/aastf

# Default config location
RUN mkdir -p /home/aastf/.aastf && chown -R aastf:aastf /home/aastf
USER aastf

ENTRYPOINT ["aastf"]
CMD ["--help"]

LABEL org.opencontainers.image.source="https://github.com/anonymousAAK/aastf"
LABEL org.opencontainers.image.description="AASTF - Agentic AI Security Testing Framework"
LABEL org.opencontainers.image.licenses="MIT"
