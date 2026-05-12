# Fix Build SOAR APK — istruzioni operative

## File da committare

Tre file vanno aggiornati nel repo `sailing-app`:

```
sailing-app/
├── constraints.txt                       (NUOVO — root)
├── patch_p4a_pip.py                      (NUOVO — root)
└── .github/workflows/build_apk.yml       (SOSTITUITO)
```

`patch_buildozer.py`, `buildozer.spec` e `main.py` restano invariati.

## Comandi git (copia/incolla)

Dal terminale, nella cartella `sailing-app`:

```bash
# 1. allineati a main pulito
git checkout main
git pull

# 2. crea branch di fix
git checkout -b fix/p4a-pip-resolvelib

# 3. pulisci la cache locale (la venv rotta vive qui)
rm -rf .buildozer

# 4. metti i tre file scaricati al posto giusto:
#    - constraints.txt          → root del repo
#    - patch_p4a_pip.py         → root del repo
#    - build_apk.yml            → .github/workflows/build_apk.yml

# 5. stage + commit + push
git add constraints.txt patch_p4a_pip.py .github/workflows/build_apk.yml
git commit -m "fix(android): block pip auto-upgrade in p4a venv

Risolve ImportError 'RequirementInformation' da pip._vendor.resolvelib.structs
durante il build APK.

- constraints.txt + env.PIP_CONSTRAINT nel job: forza pip<24.2 ovunque,
  inclusa la venv creata da p4a
- patch_p4a_pip.py: riscrive 'pip install -U pip' in pythonforandroid/build.py
  a 'pip install -U pip==24.0' (pin esatto, niente virgolette annidate).
  Include auto-repair per file gia' rotti da patch precedenti.
- workflow: nuovi step di patch dopo install e dopo clone p4a
- cache key bumped a v2 per scartare la cache con build.py corrotto"

git push -u origin fix/p4a-pip-resolvelib
```

## Far partire il build

Il workflow ha trigger `on: push: branches: [main]` quindi il push sul branch
di fix NON parte da solo. Lancialo manualmente via `workflow_dispatch`:

1. GitHub → repo `sailing-app` → tab **Actions**
2. Sidebar sinistra → **Build SOAR APK**
3. Bottone **Run workflow** in alto a destra
4. **Branch**: `fix/p4a-pip-resolvelib`
5. Clic su **Run workflow** verde

Aspetta 30-60 minuti.

## Verifica nei log

Nello step **Patch p4a pip auto-upgrade (installed package)** devi leggere:

```
patch_p4a_pip: target = .../pythonforandroid/build.py
  PATCH   '\bpip install -U pip\b(?!=)'  ->  'pip install -U pip==24.0'
  scritto: .../pythonforandroid/build.py
  sintassi OK: .../pythonforandroid/build.py
```

In fondo allo step **Setup p4a and patch recipes**, di nuovo:

```
patch_p4a_pip: target = .buildozer/.../pythonforandroid/build.py
  PATCH   ...  ->  'pip install -U pip==24.0'
  scritto: ...
```

E nello step **Build APK** non deve piu' apparire:

```
ImportError: cannot import name 'RequirementInformation'
```

## A build finito

Bottom del run → sezione **Artifacts** → scarica `soar-debug-apk`.

## Merge su main

Quando il run di fix e' verde:

```bash
git checkout main
git merge fix/p4a-pip-resolvelib
git push
```

Oppure apri PR su GitHub e mergia da li'.

## In caso di problemi

Se vedi un errore diverso, manda le ultime 100-200 righe del log del
job fallito e diagnostichiamo.
