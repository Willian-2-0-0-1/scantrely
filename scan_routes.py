"""Compatibility shim. Import `routes.scans` (or this module) — do not duplicate routes.

Tests import `from scan_routes import create_scan_blueprint`. Keep this file as a re-export only.
"""
from routes.scans import *  # noqa: F401,F403
from routes.scans import _gowitness_name_to_url  # noqa: F401
