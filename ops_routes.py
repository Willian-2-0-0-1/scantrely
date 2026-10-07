"""Compatibility shim. Import `routes.ops` (or this module) — do not duplicate routes.

Tests import `from ops_routes import create_ops_blueprint`. Keep this file as a re-export only.
"""
from routes.ops import *  # noqa: F401,F403
