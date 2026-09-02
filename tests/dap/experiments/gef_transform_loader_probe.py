"""Observe which Python hooks a normal GDB ``source gef.py`` traverses.

Source this probe before GEF and run ``gef-transform-loader-report`` after it.
It does not alter the source passed to GDB.  The result distinguishes a normal
Python import (which can be handled by ``sys.meta_path``) from GDB's direct
script execution path.
"""

import builtins
import json
import os
import sys
import threading

import gdb

_PWNC_GEF_TARGET = os.path.realpath(os.environ.get("PWNC_GEF_TRANSFORM_GEF", "/home/ctf/bata24-gef/gef.py"))
_pwnc_compile_original = builtins.compile
_pwnc_compile_calls = []
_pwnc_audit_compile_calls = []
_pwnc_import_find_calls = []


def _pwnc_filename(value):
    try:
        return os.path.realpath(os.fspath(value))
    except (TypeError, ValueError):
        return repr(value)


def _pwnc_compile(source, filename, *args, **kwargs):
    normalized = _pwnc_filename(filename)
    if normalized == _PWNC_GEF_TARGET:
        _pwnc_compile_calls.append({"filename": normalized, "threadId": threading.get_ident()})
    return _pwnc_compile_original(source, filename, *args, **kwargs)


def _pwnc_audit(event, args):
    if event != "compile" or len(args) < 2:
        return
    normalized = _pwnc_filename(args[1])
    if normalized == _PWNC_GEF_TARGET:
        _pwnc_audit_compile_calls.append({"filename": normalized, "threadId": threading.get_ident()})


class _PwncMetaFinder:
    def find_spec(self, fullname, path=None, target=None):
        paths = [] if path is None else [os.path.realpath(p) for p in path]
        if any(_PWNC_GEF_TARGET.startswith(p + os.sep) for p in paths):
            _pwnc_import_find_calls.append(
                {
                    "fullname": fullname,
                    "path": paths,
                    "threadId": threading.get_ident(),
                }
            )


_pwnc_meta_finder = _PwncMetaFinder()
builtins.compile = _pwnc_compile
sys.addaudithook(_pwnc_audit)
sys.meta_path.insert(0, _pwnc_meta_finder)


class _PwncLoaderReport(gdb.Command):
    def __init__(self):
        super().__init__("gef-transform-loader-report", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        report = {
            "target": _PWNC_GEF_TARGET,
            "builtinCompileCalls": list(_pwnc_compile_calls),
            "auditCompileCalls": list(_pwnc_audit_compile_calls),
            "metaPathFindCalls": list(_pwnc_import_find_calls),
            "compileWrapperStillInstalled": builtins.compile is _pwnc_compile,
            "metaFinderStillInstalled": _pwnc_meta_finder in sys.meta_path,
        }
        print("PWNC_GEF_TRANSFORM_LOADER_REPORT=" + json.dumps(report, sort_keys=True))


_PwncLoaderReport()
