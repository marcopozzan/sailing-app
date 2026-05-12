"""
patch_p4a_pip.py
================

Patcha python-for-android per impedire l'auto-upgrade di pip dentro la
venv di build. Quel comando ('pip install -U pip') tira sempre pip 25.x
che ha un pip._vendor.resolvelib incompatibile e causa:

    ImportError: cannot import name 'RequirementInformation'
                 from 'pip._vendor.resolvelib.structs'

Lo script va eseguito:
  1) dopo 'pip install python-for-android==...' (patcha il pacchetto installato)
  2) dopo il git clone manuale di p4a in .buildozer/... (patcha il clone)

Idempotente: se il pattern non c'e' piu', non fa nulla.
"""
import sys
import pathlib
import re


def find_targets():
    """Restituisce la lista dei file pythonforandroid/build.py da patchare."""
    targets = []

    # 1) Clone locale fatto dal workflow
    local = pathlib.Path(
        ".buildozer/android/platform/python-for-android/pythonforandroid/build.py"
    )
    if local.exists():
        targets.append(local)

    # 2) Pacchetto installato via pip
    try:
        import pythonforandroid.build as m  # noqa: WPS433
        installed = pathlib.Path(m.__file__)
        if installed.exists() and installed not in targets:
            targets.append(installed)
    except Exception:  # pragma: no cover
        pass

    return targets


PATTERNS = [
    (r'pip install -U pip\b',            'pip install "pip<24.2"'),
    (r'pip install --upgrade pip\b',     'pip install "pip<24.2"'),
    (r'python -m pip install -U pip\b',  'python -m pip install "pip<24.2"'),
]


def patch_file(path: pathlib.Path) -> bool:
    txt = path.read_text()
    new = txt
    changed = False
    for pat, rep in PATTERNS:
        nxt = re.sub(pat, rep, new)
        if nxt != new:
            print(f"  - {pat!r}  ->  {rep!r}")
            new = nxt
            changed = True
    if changed:
        path.write_text(new)
        print(f"  scritto: {path}")
    else:
        print(f"  nessuna occorrenza in: {path}")
    return changed


def main() -> int:
    targets = find_targets()
    if not targets:
        print("patch_p4a_pip: nessun pythonforandroid/build.py trovato, salto.")
        return 0

    any_changed = False
    for t in targets:
        print(f"patch_p4a_pip: target = {t}")
        if patch_file(t):
            any_changed = True

    if not any_changed:
        print("patch_p4a_pip: tutto gia' patchato.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
