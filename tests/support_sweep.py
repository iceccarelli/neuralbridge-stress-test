"""Discover every CLI verb from the product's own parsers and build bad-input argv for it.

Discovery only: the product tells us which verbs and arguments exist; what counts as a correct
reaction (no uncaught exception, a message on stderr when it refuses) is decided in the tests.
"""
from __future__ import annotations

import argparse
import importlib
from collections.abc import Iterator

LEDGERY = ("ledger", "db", "store", "accounts")
OUTPUTY = ("out", "output", "dest", "dir", "target", "log", "key", "public", "keys", "folder")
TEXTY = ("actor", "by", "role", "reason", "note", "description", "email", "name", "id", "serial",
         "tier", "org", "site", "label", "because", "product", "version")
SKIP_DOMAINS = {"billing"}      # operator store commands: covered by the product's own tests


def _walk(parser: argparse.ArgumentParser, path: tuple[str, ...] = ()):
    subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    if not subs:
        yield path, parser
        return
    for sub in subs:
        for name, child in sub.choices.items():
            yield from _walk(child, path + (name,))


def verbs() -> list[tuple[str, tuple[str, ...]]]:
    """``[(domain, ("verb", ...)), ...]`` for every domain that exposes ``build_parser``."""
    from assurance.cli import _DOMAINS
    found = []
    for domain, module_name in _DOMAINS.items():
        if domain in SKIP_DOMAINS:
            continue
        module = importlib.import_module(module_name)
        if not hasattr(module, "build_parser"):
            continue
        found.extend((domain, path) for path, _ in _walk(module.build_parser()))
    return found


def _leaf(domain: str, path: tuple[str, ...]) -> argparse.ArgumentParser:
    from assurance.cli import _DOMAINS
    parser = importlib.import_module(_DOMAINS[domain]).build_parser()
    for p, leaf in _walk(parser):
        if p == path:
            return leaf
    raise KeyError((domain, path))


def _role(action: argparse.Action) -> str:
    dest = (action.dest or "").lower()
    if any(k in dest for k in LEDGERY):
        return "ledger"
    if any(dest == k or dest.endswith("_" + k) or dest.startswith(k + "_") for k in OUTPUTY):
        return "output"
    return "input"


def argv_for(domain: str, path: tuple[str, ...], *, bad: str, bad_role: str, fresh: str,
             output: str) -> list[str]:
    """Fill every required argument; the ones of role ``bad_role`` get the bad path ``bad``."""
    argv = [domain, *path]
    for a in _leaf(domain, path)._actions:
        if isinstance(a, (argparse._HelpAction, argparse._SubParsersAction)):
            continue
        if a.option_strings and not a.required:
            continue
        if a.choices:
            value = str(list(a.choices)[0])
        elif a.type is int:
            value = "1"
        elif a.type is float:
            value = "1.0"
        elif any(k in (a.dest or "").lower() for k in TEXTY):
            value = "x"
        else:
            role = _role(a)
            value = bad if role == bad_role else (output if role == "output" else fresh)
        if a.option_strings:
            argv.append(a.option_strings[0])
            if a.nargs != 0:
                argv.append(value)
        else:
            argv.append(value)
    return argv


def iter_cases() -> Iterator[tuple[str, tuple[str, ...]]]:
    yield from verbs()
