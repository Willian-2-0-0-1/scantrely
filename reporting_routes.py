"""Compatibility shim. Import `routes.reporting` (or this module) — do not duplicate routes.

Tests import `from reporting_routes import create_reporting_blueprint`. Keep this file as a re-export only.
"""
from routes.reporting import *  # noqa: F401,F403
