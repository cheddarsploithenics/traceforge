"""FastAPI application: the single backend shared by every interface."""

from traceforge.api.app import create_app

__all__ = ["create_app"]
