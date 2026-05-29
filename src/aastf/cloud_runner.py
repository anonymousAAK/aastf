"""Cloud runner — containerised AASTF execution on Kubernetes."""

from __future__ import annotations

import json
import textwrap
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


class CloudRunnerConfig(BaseModel):
    """Configuration for cloud-based AASTF execution."""

    image: str = "ghcr.io/anonymousaak/aastf:latest"
    timeout: int = 1800  # seconds
    memory_limit: str = "2Gi"
    cpu_limit: str = "2"
    namespace: str = "aastf"

    @field_validator("timeout")
    @classmethod
    def _positive_timeout(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"timeout must be >= 1, got {v}")
        return v


class HelmValues(BaseModel):
    """Helm chart values for deploying AASTF."""

    replicaCount: int = 1
    image: dict[str, Any] = Field(default_factory=dict)
    resources: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("replicaCount")
    @classmethod
    def _positive_replicas(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"replicaCount must be >= 1, got {v}")
        return v


# ---------------------------------------------------------------------------
# Cloud runner
# ---------------------------------------------------------------------------


class CloudRunner:
    """Generates Kubernetes manifests and infrastructure for containerised AASTF."""

    def __init__(self, config: CloudRunnerConfig | None = None) -> None:
        self._config = config or CloudRunnerConfig()

    @property
    def config(self) -> CloudRunnerConfig:
        return self._config

    # ------------------------------------------------------------------ public

    def generate_dockerfile(self) -> str:
        """Return Dockerfile content for a containerised AASTF runner."""
        return textwrap.dedent("""\
            # AASTF Security Scanner — production image
            FROM python:3.12-slim AS base

            LABEL org.opencontainers.image.source="https://github.com/anonymousAAK/aastf"
            LABEL org.opencontainers.image.description="Agentic AI Security Testing Framework"

            RUN groupadd -r aastf && useradd -r -g aastf aastf

            WORKDIR /app

            COPY pyproject.toml README.md ./
            COPY src/ src/

            RUN pip install --no-cache-dir . && \\
                pip install --no-cache-dir uvicorn

            USER aastf

            EXPOSE 8080

            HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\
                CMD python -c "import aastf; print('ok')"

            ENTRYPOINT ["python", "-m", "aastf"]
            CMD ["--help"]
        """)

    def generate_helm_values(self) -> dict[str, Any]:
        """Return Helm chart values.yaml content as a dict."""
        image_parts = self._config.image.rsplit(":", 1)
        repository = image_parts[0]
        tag = image_parts[1] if len(image_parts) > 1 else "latest"

        return {
            "replicaCount": 1,
            "image": {
                "repository": repository,
                "tag": tag,
                "pullPolicy": "IfNotPresent",
            },
            "resources": {
                "limits": {
                    "cpu": self._config.cpu_limit,
                    "memory": self._config.memory_limit,
                },
                "requests": {
                    "cpu": "500m",
                    "memory": "512Mi",
                },
            },
            "config": {
                "timeout": self._config.timeout,
                "namespace": self._config.namespace,
            },
            "service": {
                "type": "ClusterIP",
                "port": 8080,
            },
            "serviceAccount": {
                "create": True,
                "name": "aastf-runner",
            },
        }

    def generate_k8s_job(self, scan_config: dict[str, Any]) -> dict[str, Any]:
        """Generate a Kubernetes Job manifest for a scan run."""
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": f"aastf-scan-{scan_config.get('run_id', 'default')}",
                "namespace": self._config.namespace,
                "labels": {
                    "app": "aastf",
                    "component": "scanner",
                },
            },
            "spec": {
                "backoffLimit": 2,
                "activeDeadlineSeconds": self._config.timeout,
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "aastf",
                            "component": "scanner",
                        },
                    },
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [
                            {
                                "name": "aastf-scanner",
                                "image": self._config.image,
                                "resources": {
                                    "limits": {
                                        "cpu": self._config.cpu_limit,
                                        "memory": self._config.memory_limit,
                                    },
                                    "requests": {
                                        "cpu": "500m",
                                        "memory": "512Mi",
                                    },
                                },
                                "env": [
                                    {
                                        "name": "AASTF_SCAN_CONFIG",
                                        "value": json.dumps(scan_config),
                                    },
                                ],
                                "command": [
                                    "python", "-m", "aastf", "scan",
                                    "--config", "/tmp/scan-config.json",
                                ],
                                "volumeMounts": [
                                    {
                                        "name": "results",
                                        "mountPath": "/results",
                                    },
                                ],
                            },
                        ],
                        "volumes": [
                            {
                                "name": "results",
                                "emptyDir": {},
                            },
                        ],
                    },
                },
            },
        }

    def generate_github_webhook_handler(self) -> str:
        """Return a Python webhook handler snippet for triggering cloud scans."""
        return textwrap.dedent("""\
            \"\"\"GitHub webhook handler for triggering AASTF cloud scans.\"\"\"

            from __future__ import annotations

            import hashlib
            import hmac
            import json
            import os
            from http.server import BaseHTTPRequestHandler


            WEBHOOK_SECRET = os.environ.get("AASTF_WEBHOOK_SECRET", "")


            class AastfWebhookHandler(BaseHTTPRequestHandler):
                \"\"\"Handles GitHub webhook events to trigger AASTF scans.\"\"\"

                def do_POST(self) -> None:
                    content_length = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(content_length)

                    # Verify signature
                    signature = self.headers.get("X-Hub-Signature-256", "")
                    if WEBHOOK_SECRET and not self._verify_signature(body, signature):
                        self.send_response(403)
                        self.end_headers()
                        return

                    event = self.headers.get("X-GitHub-Event", "")
                    payload = json.loads(body)

                    if event == "push" and payload.get("ref") == "refs/heads/main":
                        self._trigger_scan(payload)
                        self.send_response(202)
                    elif event == "pull_request" and payload.get("action") == "opened":
                        self._trigger_scan(payload)
                        self.send_response(202)
                    else:
                        self.send_response(200)

                    self.end_headers()

                def _verify_signature(self, body: bytes, signature: str) -> bool:
                    expected = "sha256=" + hmac.new(
                        WEBHOOK_SECRET.encode(),
                        body,
                        hashlib.sha256,
                    ).hexdigest()
                    return hmac.compare_digest(expected, signature)

                def _trigger_scan(self, payload: dict) -> None:
                    # Integration point: submit K8s Job or enqueue scan task
                    repo = payload.get("repository", {}).get("full_name", "unknown")
                    print(f"Triggering AASTF scan for {repo}")
        """)

    def estimated_cost(self, scenarios: int) -> dict[str, Any]:
        """Estimate cloud execution cost for a given number of scenarios.

        Assumptions (conservative):
        - ~2 seconds per scenario on average
        - vCPU cost: $0.048/hr (e2-standard-2 equivalent)
        - Memory cost: $0.006/hr per GiB
        - Startup overhead: 30 seconds
        """
        cpu_count = float(self._config.cpu_limit.rstrip("m")) if "m" in self._config.cpu_limit else float(self._config.cpu_limit)
        mem_gib = _parse_memory_gib(self._config.memory_limit)

        seconds_per_scenario = 2.0
        startup_seconds = 30.0
        total_seconds = (scenarios * seconds_per_scenario) + startup_seconds
        total_hours = total_seconds / 3600.0

        cpu_cost_per_hour = 0.048 * cpu_count
        mem_cost_per_hour = 0.006 * mem_gib
        total_cost_per_hour = cpu_cost_per_hour + mem_cost_per_hour
        estimated_total = round(total_cost_per_hour * total_hours, 4)

        return {
            "scenarios": scenarios,
            "estimated_duration_seconds": round(total_seconds, 1),
            "estimated_duration_minutes": round(total_seconds / 60, 1),
            "cpu": self._config.cpu_limit,
            "memory": self._config.memory_limit,
            "cost_per_hour_usd": round(total_cost_per_hour, 4),
            "estimated_cost_usd": estimated_total,
            "assumptions": {
                "seconds_per_scenario": seconds_per_scenario,
                "startup_overhead_seconds": startup_seconds,
                "cpu_rate_per_hour": 0.048,
                "memory_rate_per_gib_hour": 0.006,
            },
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_memory_gib(mem_str: str) -> float:
    """Parse a Kubernetes memory string (e.g. '2Gi', '512Mi') to GiB."""
    mem_str = mem_str.strip()
    if mem_str.endswith("Gi"):
        return float(mem_str[:-2])
    if mem_str.endswith("Mi"):
        return float(mem_str[:-2]) / 1024.0
    if mem_str.endswith("Ki"):
        return float(mem_str[:-2]) / (1024.0 * 1024.0)
    # Assume bytes
    try:
        return float(mem_str) / (1024.0 ** 3)
    except ValueError:
        return 2.0  # default fallback
