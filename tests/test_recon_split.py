"""core.recon é só o índice: tudo vive em core/reconlib/*.py e continua importável de core.recon."""
import importlib
import pkgutil

import core.reconlib as pkg
import core.recon as recon


def test_every_reconlib_module_imports_and_is_reexported():
    for info in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"core.reconlib.{info.name}")
        for name, obj in vars(mod).items():
            if getattr(obj, "__module__", None) == mod.__name__ and callable(obj) and not name.startswith("__"):
                assert getattr(recon, name) is obj, f"{name} de {info.name} não reexportado em core.recon"


def test_gated_subprocess_is_one_shared_instance():
    from core.reconlib import base
    assert recon.subprocess is base.subprocess


def test_xss_scan_and_salesforce_helpers_resolve():
    # antes da divisão: NameError ('_is_responsive' e 'dns' indefinidos)
    assert recon.run_xss_scan([], mode="balanced")["total"] == 0
    from core.reconlib import salesforce
    assert salesforce._is_responsive({"status_code": 200}) and not salesforce._is_responsive({})
