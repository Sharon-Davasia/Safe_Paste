"""Safe-Paste — local-first clipboard sanitizer middleware.

Core engine: pure stdlib, no runtime dependencies.
Desktop layer (tray + hotkeys + toasts): optional, see desktop_app.py.
"""

__version__ = "0.1.0"

from .engine import RestoreResult, SafePasteEngine, SanitizeResult  # noqa: F401
from .secure_map import Secret, SecureMap  # noqa: F401

__all__ = [
    "SafePasteEngine",
    "SecureMap",
    "Secret",
    "SanitizeResult",
    "RestoreResult",
    "__version__",
]
