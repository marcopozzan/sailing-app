[app]

# =============================================================================
# Informazioni app
# =============================================================================
title           = SOAR
package.name    = soar
package.domain  = it.regolofarm

source.dir          = .
source.include_exts = py,png,jpg,kv,json,csv,ttf

# Versione: bump a 1.6 (allineata con main.py corrente che include
# TrackUploader, formato CSV 20 colonne, tactical advice, formato DM)
version             = 1.6.0

# =============================================================================
# Dipendenze Python
# =============================================================================
# - python3, kivy: base
# - pynmea2: parsing frame NMEA dal trasduttore Arduino via TCP
# - certifi: bundle CA per TLS (necessario per HTTPS verso Azure)
# - pyjnius: bridge Java/Android. Serve perche' il main.py usa jnius.autoclass
#   per: (a) forzare landscape via ActivityInfo, (b) creare socket Java legate
#   alla rete cellulare per upload anche con WiFi captive, (c) bindProcessToNetwork.
#   Senza pyjnius l'app crasha all'avvio quando tocca queste sezioni.
requirements        = python3,kivy==2.3.0,pynmea2,certifi,pyjnius

# =============================================================================
# Orientamento e display
# =============================================================================
orientation         = landscape
fullscreen          = 1

# Icona e splash (decommenta se hai i file)
# icon.filename       = %(source.dir)s/icon.png
# presplash.filename  = %(source.dir)s/presplash.png
# android.presplash_color = #1B3A6B

# =============================================================================
# Android SDK / NDK
# =============================================================================
android.minapi      = 21
android.api         = 33
android.ndk         = 25c
android.archs       = arm64-v8a, armeabi-v7a

# Accetta le licenze SDK in CI
android.accept_sdk_license = True

# =============================================================================
# Permessi Android
# =============================================================================
# - INTERNET: chiamate HTTPS al backend
# - ACCESS_NETWORK_STATE: lettura stato connessione (WiFi/cellular)
# - CHANGE_NETWORK_STATE: necessario per requestNetwork + bindProcessToNetwork
#   (force-cellular per upload quando il WiFi e' captive del trasduttore)
# - WAKE_LOCK: tiene il tablet sveglio durante regate lunghe
#
# WRITE/READ_EXTERNAL_STORAGE NON servono: l'app salva i file in
# getExternalFilesDir() (sandbox dell'app), che su Android 10+ non richiede
# permessi. Li teniamo solo per retro-compatibilita' Android <10.
android.permissions = INTERNET, ACCESS_NETWORK_STATE, CHANGE_NETWORK_STATE, WAKE_LOCK, WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE

# =============================================================================
# Build
# =============================================================================
log_level           = 2
warn_on_root        = 1


[buildozer]
log_level           = 2
warn_on_root        = 1
