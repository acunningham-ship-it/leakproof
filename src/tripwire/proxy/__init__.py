"""Egress-intercept proxy lane (L1). Owner: worker-opus-5.

Public surface the rest of the package (cli/, adapters/) builds against:
    Proxy, run_proxy, serve, DEFAULT_PORT, UPSTREAMS
"""
from .server import (
    DEFAULT_PORT,
    UPSTREAMS,
    BackgroundProxy,
    Proxy,
    run_proxy,
    serve,
    start_background,
)

__all__ = [
    "Proxy",
    "BackgroundProxy",
    "run_proxy",
    "start_background",
    "serve",
    "DEFAULT_PORT",
    "UPSTREAMS",
]
