"""AASTF exception hierarchy."""


class AASFError(Exception):
    """Base exception for all AASTF errors."""


class ScenarioValidationError(AASFError):
    """Raised when a YAML scenario fails Pydantic validation."""

    def __init__(self, path: str, errors: list) -> None:
        self.path = path
        self.errors = errors
        super().__init__(f"Invalid scenario at {path}: {len(errors)} error(s)\n" +
                         "\n".join(str(e) for e in errors))


class AdapterNotFoundError(AASFError):
    """Raised when the requested adapter is not installed or recognized."""


class SandboxStartError(AASFError):
    """Raised when the sandbox server fails to start within the timeout."""


class EvaluationError(AASFError):
    """Raised when an evaluator encounters an unexpected or unhandled state."""


class RunnerTimeoutError(AASFError):
    """Raised when a scenario execution exceeds its configured timeout."""
