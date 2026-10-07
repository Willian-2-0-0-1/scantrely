"""Compatibility shim. Import `routes.core` (or this module) — do not duplicate routes.

Tests import `from core_routes import create_core_blueprint`. The live server
registers `routes.core`. Keep this file as a re-export only.
"""
from routes.core import *  # noqa: F401,F403
