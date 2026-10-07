"""Compatibility shim. Import `routes.assets` (or this module) — do not duplicate routes.

Tests import `from asset_routes import create_asset_blueprint`. Keep this file as a re-export only.
"""
from routes.assets import *  # noqa: F401,F403
