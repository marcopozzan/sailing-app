# SOAR — Sailing Racing App

App Android per regate a vela. Build automatico via GitHub Actions.

## Come fare il build

### Metodo 1: push su main (automatico)
Ogni push sul branch `main` lancia automaticamente il build.

### Metodo 2: lancio manuale
1. Vai su https://github.com/marcopozzan/sailing-app/actions
2. Clicca su **Build SOAR APK**
3. Clicca **Run workflow** → **Run workflow**

### Scaricare l'APK
Al termine del workflow (20-40 min):
1. Clicca sul run completato
2. Scorri fino a **Artifacts**
3. Scarica **soar-debug-apk**

## Struttura repository
```
sailing-app/
├── main.py           # Applicazione principale
├── buildozer.spec    # Configurazione build Android
└── .github/
    └── workflows/
        └── build_apk.yml  # Workflow GitHub Actions
```
