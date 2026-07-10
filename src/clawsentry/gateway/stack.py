"""Compatibility wrapper for the gateway stack entry point."""

from __future__ import annotations

from .runtime import stack as _runtime_stack
from .runtime.stack import main


for _name in dir(_runtime_stack):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_runtime_stack, _name)

__all__ = [name for name in dir(_runtime_stack) if not name.startswith("__")]
del _name


if __name__ == "__main__":
    main()
