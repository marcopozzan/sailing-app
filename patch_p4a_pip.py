"""
patch_p4a_pip.py
================

Patcha python-for-android per impedire l'auto-upgrade di pip dentro la
venv di build. Quel comando ('pip install -U pip') tira pip 25.x che
ha un pip._vendor.resolvelib incompatibile e causa:

    ImportError: cannot import name 'RequirementInformation'
                 from 'pip._vendor.resolvelib.structs'

Strategia: NON aggiungiamo virgolette nel rimpiazzo (rompono la stringa
Python che le contiene). Usiamo un pin a versione ESATTA con '==' che
non contiene caratteri shell-speciali e non ha bisogno di quoting:

    pip install -U pip        ->  pip install -U pip==24.0
    pip install --upgrade pip ->  pip install --upgrade pip==24.0

Inoltre ripariamo eventuali patch precedenti che avessero introdotto
'pip<24.2' con virgolette annidate rompendo la sintassi del file.

Idempotente: se la sostituzione e' gia' presente, non fa nulla.
Verifica la sintassi del file con py_compile dopo ogni modifica.

Va eseguito:
  1) dopo 'pip install python-for-android==...'  (patcha il pacchetto)
  2) dopo il git clone manuale di p4a in .buildozer/...  (patcha il clone)
"""
import sys
import pathlib
import re

PIN = "pip==24.0"  # ultima 24.x prima del breaking change su resolvelib


def find_targets():
    """Restituisce la lista di pythonforandroid/build.py da patchare."""
    targets = []

    local = pathlib.Path(
        ".buildozer/android/platform/python-for-android/pythonforandroid/build.py"
    )
    if local.exists():
        targets.append(local)

    try:
        import pythonforandroid.build as m  # noqa: WPS433
        installed = pathlib.Path(m.__file__)
        if installed.exists() and installed not in targets:
            targets.append(installed)
    except Exception:  # pragma: no cover
        pass

    return targets


# Riparazione di patch precedenti rotte (con virgolette annidate):
# qualsiasi forma di "pip<24.2" o 'pip<24.2' va riportata a pip==24.0
REPAIR_PATTERNS = [
    (r'"pip<24\.2"', PIN),
    (r"'pip<24\.2'", PIN),
]

# Patch principale: niente virgolette nel rimpiazzo
PATCH_PATTERNS = [
    (r'\bpip install -U pip\b(?!=)',           f"pip install -U {PIN}"),
    (r'\bpip install --upgrade pip\b(?!=)',    f"pip install --upgrade {PIN}"),
    (r'\bpython -m pip install -U pip\b(?!=)', f"python -m pip install -U {PIN}"),
]


def patch_file(path: pathlib.Path) -> bool:
    txt = path.read_text()
    new = txt
    changed = False

    # Step 1: ripara patch rotte da versioni precedenti dello script
    for pat, rep in REPAIR_PATTERNS:
        nxt = re.sub(pat, rep, new)
        if nxt != new:
            print(f"  REPAIR  {pat!r}  ->  {rep!r}")
            new = nxt
            changed = True

    # Step 2: applica la patch normale se non gia' presente
    for pat, rep in PATCH_PATTERNS:
        nxt = re.sub(pat, rep, new)
        if nxt != new:
            print(f"  PATCH   {pat!r}  ->  {rep!r}")
            new = nxt
            changed = True

    if changed:
        path.write_text(new)
        print(f"  scritto: {path}")
        import py_compile
        try:
            py_compile.compile(str(path), doraise=True)
            print(f"  sintassi OK: {path}")
        except py_compile.PyCompileError as exc:
            print(f"  ERRORE SINTASSI dopo patch: {exc}")
            return False
    else:
        print(f"  nessuna modifica: {path}")

    return True


def main() -> int:
    targets = find_targets()
    if not targets:
        print("patch_p4a_pip: nessun pythonforandroid/build.py trovato, salto.")
        return 0

    ok = True
    for t in targets:
        print(f"patch_p4a_pip: target = {t}")
        if not patch_file(t):
            ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
