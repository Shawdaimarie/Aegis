"""Domain exception hierarchy. Every error raised by Aegis descends from PlatformError."""


class PlatformError(Exception):
    """Root of all Aegis exceptions."""


class ConfigurationError(PlatformError):
    """A configuration value is missing, malformed, or contradictory."""


class IsolationViolationError(PlatformError):
    """An independent training context attempted to access another context."""


class GovernanceViolationError(PlatformError):
    """A BLOCKING or HALT boundary was breached."""

    def __init__(self, boundary_id: str, severity: str, detail: str) -> None:
        """Record which boundary fired and why.

        Args:
            boundary_id: Stable identifier of the boundary.
            severity: Severity label at time of breach.
            detail: Human-readable rationale from the boundary definition.
        """
        self.boundary_id = boundary_id
        self.severity = severity
        self.detail = detail
        super().__init__(f"{severity} boundary '{boundary_id}' breached: {detail}")


class IntegrityError(PlatformError):
    """A hash, signature, or chain check failed."""


class StateUnavailableError(PlatformError):
    """Required authorization state cannot be safely read or committed."""
