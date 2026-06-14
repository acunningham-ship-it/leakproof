"""leakproof.tui — live leak dashboard (L3, co-owned with audit.py).

Public API the CLI dispatches to:
    watch(audit_path=None) -> int     # live tail + repaint
    render_frame(events) -> str       # pure render (testable, screenshots)
    main(argv=None) -> int            # standalone `python -m leakproof.tui`
"""

from .dashboard import main, render_frame, watch

__all__ = ["watch", "render_frame", "main"]
