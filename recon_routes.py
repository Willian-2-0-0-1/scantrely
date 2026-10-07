"""Compatibility shim. Import `routes.recon` (or this module) — do not duplicate routes.

Tests and older scripts import `from recon_routes import create_recon_blueprint`.
The live server registers `routes.recon`. Keep this file as a re-export only.
"""
from routes.recon import *  # noqa: F401,F403
