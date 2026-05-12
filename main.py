"""
Sailing Racing System — Android TABLET v1.18
Grafica originale mantenuta (bussola, canvas tattico, grafico velocita).
Layout adattivo: _cols_h() usa Window.height - no altezze fisse sui container.
Fix SIGABRT: Clock.schedule_once su tutti canvas draw + guard width/height.

v1.5: download/upload polari, waypoints e tracks via Azure Blob Storage diretto.
v1.6: polar.json v2 con sezione 'sails' (definitions + crossover).
v1.7: Fix crash "Scarica dal cloud": niente piu' riuso di widget Kivy.
v1.8: Refactor totale dei popup cloud con pattern bulletproof.
v1.9: UI Settings: rimossa COMPLETAMENTE la sezione Azure Blob.
v1.10: Sostituiti i 3 SAS token con un'unica blob_account_key (Shared Key).
v1.11: Fix bug crash su Scarica da web (waypoints/polare).
v1.12: Rimossi pulsanti "Carica al cloud" da WaypointsScreen e PolarScreen.
v1.13: Fix bug "Polare DISATTIVATA" anche con polare attiva.
v1.14: Fix errore SSL CERTIFICATE_VERIFY_FAILED su Android.
v1.15: StartLineScreen: pulsante "Invia al cloud" sotto al toggle log.
v1.16: Sostituita LoggingScreen con WeatherScreen (previsioni meteo dal blob).
v1.17: Rimossa COMPLETAMENTE tutta la funzionalita' di logging tracks.
v1.18: REINTRODOTTA la schermata LOG con pattern semplice e dedicato:
       - TrackLogger semplificato (CSV una riga ogni 5s) con nome file
         track_YYYY-MM-DD_HH-MM-SS.csv basato su istante di START.
       - LoggingScreen nuova: colonna SX con Start/Stop e pulsante
         "Invia al cloud" (one-shot upload del CSV chiuso al blob storage
         tracks/{boat}/<file>.csv, Shared Key auth).
         Colonna DX con CLOUD UPLOAD LIVE: toggle ON/OFF + selettore
         intervallo (30s, 1m, 2m, 5m, 10m). Quando ON, snapshot HTTPS
         a backend ogni N secondi -> SQL Server tabella 'traks' di
         sailing-sql-7645.database.windows.net.
       - cloud_interval_min sostituito da cloud_interval_s (granulare al
         secondo, min 30s). Migrazione automatica config esistenti.
       - Sezione CLOUD UPLOAD rimossa dalla SettingsScreen (spostata in
         LoggingScreen). Settings: solo NMEA, twd window, utility diag.
       - NOTA SQL Server: il tablet NON puo' parlare direttamente con
         Azure SQL via TDS (no driver pyodbc su Android Kivy). Usa il
         backend Azure Functions (cloud_url) come proxy: il tablet manda
         JSON via HTTPS, il backend fa l'INSERT su SQL.
"""

import math, json, os, csv, socket, threading, time
import ssl, urllib.request, urllib.error
from collections import deque
from datetime import datetime, timezone

# =============================================================================
# SSL CONTEXT per HTTPS (cloud upload)
# =============================================================================
# Su Android il sistema non espone le CA root in formato leggibile da Python:
# servono o (a) il pacchetto certifi nei requirements del buildozer.spec,
# o (b) un fallback che cerca i CA nei path standard del sistema Android.
#
# Logica usata (in ordine di preferenza):
# 1) certifi: ideale (CA Mozilla aggiornati, ~250KB)
# 2) Path Android conosciuti: /system/etc/security/cacerts/ (cartella di pem)
#    o /etc/ssl/certs/ca-certificates.crt (bundle Linux/Termux)
# 3) ssl.create_default_context() di base (su Android puro NON funziona, su
#    desktop si')
# 4) Per le richieste verso Azure Blob Storage abilitiamo un fallback
#    automatico: se la verifica TLS fallisce, ritentiamo con context
#    unverified. La sicurezza non e' compromessa perche' tutte le richieste
#    al blob sono firmate con HMAC-SHA256 (Shared Key) sui contenuti:
#    l'integrita' del payload e' garantita anche senza TLS verification.
#    Vedi _make_blob_ssl_context() e i siti d'uso piu' sotto.

_SSL_DIAG = '?'
_SSL_CTX_VERIFIED = None    # con verifica (usato di default)
_SSL_CTX_UNVERIFIED = None  # senza verifica (fallback per Azure / test)

def _find_android_ca_bundle():
    """Cerca un CA bundle nei path standard del sistema Android/Linux.
    Restituisce path al file .crt se trovato e leggibile (>1KB), altrimenti None.

    Path comuni:
    - /system/etc/security/cacerts/  (Android: directory di pem singoli, NON
      compatibile con cafile= che vuole UN solo file. Skip in questa funzione.)
    - /etc/ssl/certs/ca-certificates.crt  (Linux/Termux/Debian: bundle unico)
    - /system/etc/security/cacerts.bks    (Android: BouncyCastle, non usabile)
    """
    candidates = [
        '/etc/ssl/certs/ca-certificates.crt',  # Termux/Debian-like
        '/etc/pki/tls/certs/ca-bundle.crt',     # RHEL-like
    ]
    for p in candidates:
        try:
            if os.path.exists(p) and os.path.getsize(p) > 1024:
                return p
        except OSError:
            continue
    return None

try:
    import certifi
    _ca_path = certifi.where()
    if os.path.exists(_ca_path) and os.path.getsize(_ca_path) > 1000:
        _SSL_CTX_VERIFIED = ssl.create_default_context(cafile=_ca_path)
        _SSL_DIAG = f'certifi OK ({os.path.getsize(_ca_path)//1024}KB)'
    else:
        _SSL_CTX_VERIFIED = ssl.create_default_context()
        _SSL_DIAG = f'certifi vuoto:{_ca_path}'
except ImportError:
    # certifi NON installato: prova path Android prima di arrenderti
    _ca_android = _find_android_ca_bundle()
    if _ca_android:
        try:
            _SSL_CTX_VERIFIED = ssl.create_default_context(cafile=_ca_android)
            _SSL_DIAG = f'CA Android: {_ca_android}'
        except Exception:
            _SSL_CTX_VERIFIED = ssl.create_default_context()
            _SSL_DIAG = f'CA Android falliti: default'
    else:
        _SSL_CTX_VERIFIED = ssl.create_default_context()
        _SSL_DIAG = 'NO certifi (default - su Android probabilmente fallira\')'
except Exception as _e:
    _SSL_CTX_VERIFIED = ssl.create_default_context()
    _SSL_DIAG = f'certifi err:{_e}'

# Context SENZA verifica: usato come fallback per test endpoint e per
# Azure Blob Storage quando i CA non sono disponibili (la firma Shared Key
# garantisce l'integrita' del payload anche senza TLS verification).
try:
    _SSL_CTX_UNVERIFIED = ssl._create_unverified_context()
except Exception:
    _SSL_CTX_UNVERIFIED = None

# Domini whitelisted per il fallback senza verifica (servizi di test).
# Per backend reali NON aggiungerli qui: il certificato deve verificare.
_SSL_TEST_HOSTS = ('webhook.site', 'requestbin.com', 'beeceptor.com',
                    'pipedream.com', 'mockbin.com')

def _is_blob_url(url):
    """True se l'URL punta ad Azure Blob Storage (qualsiasi account).
    Usato per decidere se attivare il fallback automatico SSL unverified
    in caso di errore di verifica certificato. Sicuro perche' le richieste
    al blob sono firmate con HMAC-SHA256 sui contenuti."""
    return '.blob.core.windows.net' in (url or '').lower()

def _is_ssl_cert_error(exc):
    """True se l'eccezione e' un errore di verifica certificato SSL.
    Cattura ssl.SSLCertVerificationError (Python 3.7+) e i casi dove
    URLError wrappa un SSLError sottostante (la maggior parte su Android)."""
    if isinstance(exc, ssl.SSLError):
        msg = str(exc).lower()
        return ('certificate' in msg or 'cert_verify' in msg
                or 'self signed' in msg or 'unable to get local issuer' in msg)
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, 'reason', None)
        if isinstance(reason, ssl.SSLError):
            msg = str(reason).lower()
            return ('certificate' in msg or 'cert_verify' in msg
                    or 'unable to get local issuer' in msg)
    return False

def urlopen_with_ssl_fallback(req, timeout=30):
    """urllib.request.urlopen con fallback automatico SSL unverified per
    Azure Blob Storage. Comportamento:

    1. Tenta con _SSL_CTX_VERIFIED (CA bundle se trovato).
    2. Se fallisce con errore di verifica certificato E l'URL e' del blob
       storage Azure, ritenta con _SSL_CTX_UNVERIFIED.
    3. Per altri errori SSL (su domini non-Azure), ri-solleva l'eccezione
       (la verifica TLS resta importante per altri servizi).

    Questo e' sicuro per Azure Blob perche' tutte le richieste sono firmate
    con HMAC-SHA256 (Shared Key) sui contenuti: l'integrita' del payload e'
    garantita anche senza TLS verification. Su Android puro dove i CA
    Mozilla non sono disponibili, questo evita il blocco totale.

    Restituisce il context manager di urlopen (usalo in 'with' come al solito)."""
    try:
        return urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX_VERIFIED)
    except (ssl.SSLError, urllib.error.URLError) as e:
        if _is_ssl_cert_error(e) and _is_blob_url(req.full_url):
            if _SSL_CTX_UNVERIFIED is not None:
                print(f'urlopen_with_ssl_fallback: SSL verify fallita per '
                      f'{req.full_url[:60]}, retry unverified (Shared Key '
                      f'garantisce integrita\')')
                return urllib.request.urlopen(req, timeout=timeout,
                                                context=_SSL_CTX_UNVERIFIED)
        raise

os.environ.setdefault('KIVY_NO_ENV_CONFIG', '1')

from kivy.config import Config

# Forza orientamento landscape su tutte le piattaforme
Config.set('graphics', 'orientation', 'landscape')

try:
    from android import mActivity
    IS_ANDROID = True
except ImportError:
    IS_ANDROID = False
    # Su desktop usiamo dimensioni landscape
    Config.set('graphics', 'width',  '1280')
    Config.set('graphics', 'height', '800')


def _force_landscape_android():
    """Forza l'Activity Android in landscape via JNI.

    Va chiamata DOPO che l'Activity e' completamente costruita
    (es. da App.on_start() o tramite Clock.schedule_once), altrimenti
    Android puo' applicare la richiesta a meta' della creazione del surface
    SDL e causare una seconda rotazione visibile dopo lo splash.
    """
    if not IS_ANDROID: return
    try:
        from jnius import autoclass
        ActivityInfo = autoclass('android.content.pm.ActivityInfo')
        # SCREEN_ORIENTATION_SENSOR_LANDSCAPE = 6 (ruota auto se tablet
        # capovolto orizzontalmente). Per orientamento fisso usa
        # SCREEN_ORIENTATION_LANDSCAPE = 0.
        mActivity.setRequestedOrientation(
            ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE)
    except Exception as e:
        print(f'Orient:{e}')

from kivy.app               import App
from kivy.clock             import Clock, mainthread
from kivy.core.window       import Window
from kivy.graphics          import Color, Ellipse, Line, Rectangle, Triangle
from kivy.metrics           import dp, sp
from kivy.properties        import NumericProperty
from kivy.uix.boxlayout     import BoxLayout
from kivy.uix.button        import Button
from kivy.uix.gridlayout    import GridLayout
from kivy.uix.label         import Label
from kivy.uix.popup         import Popup
from kivy.uix.screenmanager import Screen, ScreenManager, FadeTransition
from kivy.uix.scrollview    import ScrollView
from kivy.uix.textinput     import TextInput
from kivy.uix.widget        import Widget

try:
    import pynmea2
    HAS_PYNMEA2 = True
except ImportError:
    HAS_PYNMEA2 = False

BG       = (0,    0,    0,    1)
PANEL    = (0.06, 0.13, 0.25, 1)
SIDEBAR  = (0.03, 0.07, 0.15, 1)
ACCENT   = (0,    0.67, 1,    1)
GREEN    = (0,    1,    0,    1)
RED      = (1,    0.27, 0.27, 1)
ORANGE   = (1,    0.67, 0,    1)
WHITE    = (1,    1,    1,    1)
MUTED    = (0.55, 0.55, 0.55, 1)
YELLOW   = (1,    1,    0,    1)
# Sfondo standard dei pulsanti: grigio medio leggibile su tutti i pannelli.
# Sostituisce il vecchio uso di PANEL come sfondo bottoni (che spariva
# letteralmente sui pannelli scuri come Start/Waypoints).
BTN_GRAY = (0.30, 0.30, 0.32, 1)

CONFIG_FILE    = 'sailing_config.json'
POLAR_FILE     = 'polar.json'
WAYPOINTS_FILE = 'waypoints.json'
LOG_DIR        = 'logs'
SIDEBAR_W   = dp(155)
TITLE_H     = dp(60)
BOX_H       = dp(200)  # Mantenuto solo per riferimento (non piu' usato come altezza fissa)
# URL di default per il cloud upload "legacy" (HTTPS POST a endpoint REST).
# Dal v1.19 il CloudUploader fa PUT diretto al container 'trackslive' del
# blob storage, quindi questo campo e' IGNORATO dal flusso live. Resta nel
# config per backward-compat (vecchie versioni che leggevano l'URL).
CLOUD_URL_DEFAULT = 'https://sailing-api-7960.azurewebsites.net/api/track'

# =============================================================================
# AZURE BLOB STORAGE -- accesso diretto con Shared Key auth (v1.10+)
# =============================================================================
# Architettura cloud:
# - Storage account: sailingapp.blob.core.windows.net
# - Container 'polars'      polare per barca
#       https://sailingapp.blob.core.windows.net/polars/{boat}/polar.json
# - Container 'waypoints'   waypoint per barca
#       https://sailingapp.blob.core.windows.net/waypoints/{boat}/waypoints.json
# - Container 'meteo'       previsioni meteo precaricate dal backend per barca
#       https://sailingapp.blob.core.windows.net/meteo/{boat}/forecast.json
#
# Identificativo barca: 'cloud_boat_id' nel sailing_config.json (default 'soar').
#
# Nota: il container 'tracks' (log CSV) non e' piu' usato dal tablet a partire
# dalla v1.17. Tutto il flusso di logging e upload tracks e' stato rimosso.
#
# Identificativo barca: 'cloud_boat_id' nel sailing_config.json (default 'soar').
#
# Autenticazione: Shared Key (HMAC-SHA256) con la chiave master dell'account
#   (campo 'blob_account_key' di sailing_config.json). Tutte le richieste
#   (GET/PUT/LIST) sono firmate dall'helper azure_sign_request().
#   Nessun SAS token richiesto: la chiave permette qualsiasi operazione.
#   ATTENZIONE: chi ha la chiave master ha controllo totale dello storage
#   account. Non condividere il sailing_config.json con altri tablet/utenti.
BLOB_BASE_DEFAULT       = 'https://sailingapp.blob.core.windows.net'
BLOB_CONTAINER_POLARS   = 'polars'
BLOB_CONTAINER_WAYPOINTS = 'waypoints'
BLOB_CONTAINER_METEO    = 'meteo'
BLOB_CONTAINER_TRACKS   = 'tracks'  # log CSV regata, uploadato come file unico
BLOB_CONTAINER_TRACKSLIVE = 'trackslive'  # snapshot JSON live, 1 file per ciclo
BLOB_CONTAINER_CONFIG   = 'config'   # config remoto, fallback al primo avvio
BLOB_CONTAINER_LOGS     = 'logs'     # log errori uploadati on-demand
BOAT_ID_DEFAULT         = 'soar'
# File previsioni meteo precaricate dal backend nel blob 'meteo/{boat}/'.
# Formato JSON definito in WeatherScreen.parse_forecast() (vedi docstring).
METEO_FILE              = 'forecast.json'

# Base URL del servizio cloud (legacy: backward-compat per config esistenti).
# Il campo 'api_base' nel sailing_config.json e' ora ignorato dal flusso
# download (sostituito da blob_base) ma resta letto per non rompere config
# vecchi. Tenuto solo per compatibilita'.
API_BASE_DEFAULT = 'https://sailing-api-7960.azurewebsites.net/api/boats'

# ---- Parametri switch automatico waypoint target ----
# Soglia in NM sotto la quale consideriamo "vicini" alla boa. 0.027 NM ~= 50m.
# Per boe di regata serve vicinanza prima di accettare il superamento, perche'
# pin/RC e mark possono essere a poche decine di metri di distanza.
MARK_PASS_RADIUS_NM = 0.027
# Numero di tick consecutivi con distanza in aumento per concludere che
# abbiamo superato il CPA (Closest Point of Approach). 3 tick a 1Hz = ~3s
# di trend in aumento, riduce i falsi positivi da rumore GPS.
MARK_PASS_TICKS_INCREASING = 3
# Anti-rimbalzo: minimo intervallo tra due switch automatici (secondi).
# Evita che dopo uno switch lo stesso meccanismo scatti subito di nuovo
# se la distanza dalla boa nuova oscilla.
MARK_PASS_COOLDOWN_S = 5.0

# =============================================================================
# AZURE STORAGE SHARED KEY (HMAC-SHA256) -- firma richieste HTTP al blob
# =============================================================================
# Implementazione minimale dell'algoritmo "Shared Key" descritto in:
#   https://learn.microsoft.com/rest/api/storageservices/authorize-with-shared-key
#
# L'app firma le richieste HTTP al blob storage con la chiave master
# dell'account (blob_account_key in sailing_config.json). Non richiede
# librerie esterne (azure-storage-blob): usa solo stdlib (hmac, hashlib,
# base64, urllib.parse). Questo evita dipendenze nel build Android.
#
# Usage:
#   from urllib.request import Request
#   url = 'https://sailingapp.blob.core.windows.net/tracks?restype=container&comp=list&prefix=soar/'
#   req = Request(url, method='GET')
#   azure_sign_request(req, account_name='sailingapp', account_key='base64key==')
#   urlopen(req)
#
# Funziona per GET, PUT, DELETE, HEAD su blob. PUT richiede aggiungere
# l'header 'x-ms-blob-type: BlockBlob' al Request PRIMA della firma.

import hmac as _hmac
import hashlib as _hashlib
import base64 as _b64
from email.utils import formatdate as _formatdate
from urllib.parse import urlsplit as _urlsplit, parse_qs as _parse_qs

def _azure_canonical_resource(account_name, parsed_url):
    """Costruisce CanonicalizedResource per Shared Key.
    Formato: /{account_name}{path}\n{header}:{val1,val2,...}\n... (query
    parameters ordinati alfabeticamente, valori comma-joined ordinati).
    """
    res = f'/{account_name}{parsed_url.path}'
    if parsed_url.query:
        # parse_qs ritorna dict[str, list[str]]; chiavi case-insensitive (lower).
        params = _parse_qs(parsed_url.query, keep_blank_values=True)
        # Ordino alfabeticamente sulle chiavi (lowercase)
        items = sorted(params.items(), key=lambda kv: kv[0].lower())
        for key, vals in items:
            joined = ','.join(sorted(vals))
            res += f'\n{key.lower()}:{joined}'
    return res

def _azure_canonical_headers(headers_dict):
    """Costruisce CanonicalizedHeaders per Shared Key.
    Tutti gli header che iniziano con 'x-ms-', case-insensitive, ordinati
    alfabeticamente, formato '{name}:{value}\n' (valore trimmed)."""
    ms = []
    for k, v in headers_dict.items():
        kl = k.lower()
        if kl.startswith('x-ms-'):
            ms.append((kl, str(v).strip()))
    ms.sort(key=lambda kv: kv[0])
    return ''.join(f'{k}:{v}\n' for k, v in ms)

def azure_sign_request(req, account_name, account_key):
    """Firma una urllib.request.Request con Azure Shared Key.
    Aggiunge gli header 'x-ms-date', 'x-ms-version', 'Authorization'.

    req: urllib.request.Request gia' costruito (con method, headers, data se PUT).
    account_name: nome dello storage account (es. 'sailingapp').
    account_key: chiave master in base64 (dal portal Azure > Access Keys).

    Per PUT di blob, l'utente deve gia' aver settato:
      - Content-Type
      - x-ms-blob-type (di solito 'BlockBlob')
    PRIMA di chiamare questa funzione, perche' fanno parte della firma.
    """
    # Timestamp HTTP RFC 1123 obbligatorio (formato: 'Mon, 27 Jan 2025 ...')
    date_str = _formatdate(timeval=None, localtime=False, usegmt=True)
    # Header obbligatori per Shared Key
    req.add_header('x-ms-date', date_str)
    req.add_header('x-ms-version', '2020-04-08')

    # === Calcolo StringToSign ===
    # Ordine FISSO definito da Microsoft per l'algoritmo Shared Key (no Lite).
    # Tutti i valori sono dell'header se presente, altrimenti stringa vuota.
    method = req.get_method().upper()
    h = {k.lower(): v for k, v in req.header_items()}

    content_length = h.get('content-length', '')
    if content_length == '0':  # Microsoft: 0 va trattato come empty string
        content_length = ''

    fields = [
        method,
        h.get('content-encoding', ''),
        h.get('content-language', ''),
        content_length,
        h.get('content-md5', ''),
        h.get('content-type', ''),
        '',  # Date: empty perche' usiamo x-ms-date (header alternativo)
        h.get('if-modified-since', ''),
        h.get('if-match', ''),
        h.get('if-none-match', ''),
        h.get('if-unmodified-since', ''),
        h.get('range', ''),
    ]
    string_to_sign = '\n'.join(fields) + '\n'
    string_to_sign += _azure_canonical_headers(h)
    string_to_sign += _azure_canonical_resource(account_name,
                                                 _urlsplit(req.full_url))

    # === HMAC-SHA256 ===
    try:
        key_bytes = _b64.b64decode(account_key)
    except Exception as e:
        raise ValueError(f'blob_account_key non e\' base64 valido: {e}')
    sig = _b64.b64encode(
        _hmac.new(key_bytes, string_to_sign.encode('utf-8'),
                  _hashlib.sha256).digest()
    ).decode('ascii')
    req.add_header('Authorization', f'SharedKey {account_name}:{sig}')
    return req

def _account_name_from_blob_base(blob_base):
    """Estrae il nome account da un URL tipo
    'https://sailingapp.blob.core.windows.net' -> 'sailingapp'."""
    try:
        host = _urlsplit(blob_base).hostname or ''
        # host = 'sailingapp.blob.core.windows.net'
        return host.split('.')[0] if host else ''
    except Exception:
        return ''

def get_data_dir():
    """Restituisce la directory dove salvare config, polari e log.

    Path PRIMARIO (Android): /storage/sdcard0/Android/data/it.regolofarm.soar/files/
    - Path della sandbox dell'app (no permessi runtime richiesti)
    - Sotto questa dir l'app crea logs/, sailing_config.json e polar.json
    - Visibile da PC come 'Memoria/Android/data/it.regolofarm.soar/files'

    FALLBACK 1: /storage/emulated/0/Android/data/it.regolofarm.soar/files/
    (alcuni device non hanno il symlink /storage/sdcard0/)

    FALLBACK 2: cartella sandbox dinamica restituita da getExternalFilesDir()
    (qualunque package name reale dell'APK)

    Su desktop usa la directory corrente.
    """
    # Path "ufficiali" che vogliamo (richiede package name = it.regolofarm.soar
    # configurato in buildozer.spec)
    PKG = 'it.regolofarm.soar'
    candidates = [
        f'/storage/sdcard0/Android/data/{PKG}/files',
        f'/storage/emulated/0/Android/data/{PKG}/files',
    ]
    try:
        from android import mActivity  # noqa: F401 (test su Android)
        # Provo i path canonici (sandbox app, no permessi richiesti)
        for path in candidates:
            try:
                os.makedirs(path, exist_ok=True)
                test_file = os.path.join(path, '.write_test')
                with open(test_file, 'w') as f: f.write('x')
                os.remove(test_file)
                return path
            except Exception as e:
                print(f'DataDir try {path}: {e}')
        # Fallback finale: chiedo direttamente ad Android la sua sandbox
        # (funziona qualunque sia il package name effettivo dell'APK)
        try:
            ext_dir = mActivity.getExternalFilesDir(None)
            if ext_dir is not None:
                path = ext_dir.getAbsolutePath()
                os.makedirs(path, exist_ok=True)
                return path
        except Exception as e:
            print(f'DataDir getExternalFilesDir: {e}')
    except Exception as e:
        print(f'DataDir:{e}')
    # Fallback desktop
    return os.getcwd()

# Path assoluti completi calcolati una sola volta
DATA_DIR        = get_data_dir()
CONFIG_PATH     = os.path.join(DATA_DIR, CONFIG_FILE)
POLAR_PATH      = os.path.join(DATA_DIR, POLAR_FILE)
WAYPOINTS_PATH  = os.path.join(DATA_DIR, WAYPOINTS_FILE)
LOG_PATH        = os.path.join(DATA_DIR, LOG_DIR)
# Sottocartella dedicata ai log errori (separata dai track CSV cosi'
# l'upload tracks non si "porta dietro" log di sistema e viceversa).
ERROR_LOG_DIR   = os.path.join(LOG_PATH, 'errors')


# =============================================================================
# ERROR LOGGER -- raccolta centralizzata di errori e crash
# =============================================================================
#
# Quattro canali di cattura:
#   1) log_err(msg, exc=...)  chiamato esplicitamente nel codice
#   2) sys.excepthook         eccezioni non gestite nel main thread
#   3) threading.excepthook   eccezioni non gestite nei thread (Py 3.8+)
#   4) sys.stderr (via tee)   tutto cio' che finisce su stderr e contiene
#                             "Error"/"Exception"/"Traceback"/"ERROR"/"CRITICAL"
#                             viene duplicato nel file di log
#
# File di log locali: uno al giorno
#   {LOG_PATH}/errors/errors_YYYY-MM-DD.log
# Cosi' non si accumulano migliaia di file ne' un unico file gigante.
#
# Upload al blob storage: ErrorLogger.upload_to_blob(dm, only_today=...)
# carica il/i file in {blob_base}/logs/{boat_id}/errors_YYYY-MM-DD.log
# usando il SAS token gia' configurato per 'tracks'.
import traceback
import sys


class ErrorLogger:
    """Logger di errori thread-safe con file giornaliero locale + upload blob.

    Threadsafe: tutte le scritture sono protette da lock. Le append al file
    sono singole chiamate write() che il filesystem garantisce atomiche per
    payload < PIPE_BUF (~4KB), sufficienti per i messaggi tipici.

    Non solleva mai eccezioni: se il logger stesso fallisce (disco pieno,
    permessi negati), stampa l'errore originale su stderr ORIGINALE e prosegue.
    """

    def __init__(self, dir_path):
        self.dir_path = dir_path
        self._lock = threading.Lock()
        # Contatori per UI
        self.count = 0
        self.last_error_ts = None
        self.last_error_msg = None
        try:
            os.makedirs(self.dir_path, exist_ok=True)
        except Exception as e:
            # Non blocchiamo l'app: l'app deve partire anche se il logger no
            print(f'ErrorLogger init: cannot create {dir_path}: {e}',
                  file=sys.__stderr__)

    def _current_file(self):
        """Path del file di log per oggi (YYYY-MM-DD)."""
        day = datetime.now().strftime('%Y-%m-%d')
        return os.path.join(self.dir_path, f'errors_{day}.log')

    def log_error(self, msg, exc=None):
        """Registra un errore. Se exc e' un'eccezione, include lo stacktrace.

        Formato di una riga (su piu' righe se stacktrace):
            [2026-05-13T14:23:05Z] [thread-name] msg
              (eventuale stacktrace indentato)
        """
        try:
            ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            tname = threading.current_thread().name
            head = f'[{ts}] [{tname}] {msg}'
            tail = ''
            if exc is not None:
                if isinstance(exc, tuple) and len(exc) == 3:
                    tb_lines = traceback.format_exception(*exc)
                else:
                    tb_lines = traceback.format_exception(
                        type(exc), exc, exc.__traceback__)
                tail = '\n' + ''.join('  ' + l for l in tb_lines)
            full = head + tail + '\n'
            with self._lock:
                self.count += 1
                self.last_error_ts = time.time()
                self.last_error_msg = msg[:200]
                try:
                    with open(self._current_file(), 'a', encoding='utf-8') as f:
                        f.write(full)
                except Exception as e:
                    # Disco pieno / permessi: stampa su stderr ORIGINALE
                    # (non self.stderr che reindirizzerebbe ricorsivamente)
                    print(f'ErrorLogger write fail: {e}',
                          file=sys.__stderr__)
        except Exception as e:
            # Difesa estrema: il logger non deve mai propagare
            try:
                print(f'ErrorLogger meta-error: {e}', file=sys.__stderr__)
            except Exception:
                pass

    def install_global_hooks(self):
        """Installa hook per catturare:
        - eccezioni non gestite nel main thread (sys.excepthook)
        - eccezioni non gestite nei thread (threading.excepthook, Py 3.8+)
        - tutto cio' che viene scritto su sys.stderr (stack trace di terzi,
          print con file=sys.stderr, warnings, ecc.)
        """
        # 1) Eccezioni non gestite main thread
        orig_excepthook = sys.excepthook
        def _hook(exc_type, exc_value, tb):
            try:
                self.log_error(
                    f'Unhandled exception: {exc_type.__name__}: {exc_value}',
                    exc=(exc_type, exc_value, tb))
            finally:
                try: orig_excepthook(exc_type, exc_value, tb)
                except Exception: pass
        sys.excepthook = _hook

        # 2) Eccezioni nei thread (Python 3.8+)
        if hasattr(threading, 'excepthook'):
            orig_t_hook = threading.excepthook
            def _t_hook(args):
                try:
                    self.log_error(
                        f'Thread "{args.thread.name}" exception: '
                        f'{args.exc_type.__name__}: {args.exc_value}',
                        exc=(args.exc_type, args.exc_value, args.exc_traceback))
                finally:
                    try: orig_t_hook(args)
                    except Exception: pass
            threading.excepthook = _t_hook

        # 3) Redirect stderr (duplica nel file le righe sospette)
        sys.stderr = _StderrTee(sys.__stderr__, self)

    def list_log_files(self):
        """Restituisce lista di tuple (filename, path, size_bytes), ordinata
        dalla piu' recente. Solo file .log nella dir."""
        out = []
        try:
            if os.path.isdir(self.dir_path):
                for fn in sorted(os.listdir(self.dir_path), reverse=True):
                    if not fn.endswith('.log'):
                        continue
                    p = os.path.join(self.dir_path, fn)
                    try:
                        sz = os.path.getsize(p)
                    except Exception:
                        sz = 0
                    out.append((fn, p, sz))
        except Exception as e:
            print(f'ErrorLogger list_log_files: {e}', file=sys.__stderr__)
        return out

    def upload_to_blob(self, dm, only_today=True, timeout=30):
        """Upload dei file di log al container 'logs/{boat_id}/' del blob.

        Usa l'autenticazione Shared Key (HMAC-SHA256) via azure_sign_request,
        coerente col resto dell'app (v1.10+). La chiave e' in
        dm.blob_account_key.

        Args:
          dm: DataManager (per blob_base, cloud_boat_id, blob_account_key)
          only_today: True = solo file di oggi, False = tutti
          timeout: timeout per ogni PUT in secondi

        Restituisce (ok_bool, msg_str)."""
        if not dm.cloud_boat_id:
            return False, 'cloud_boat_id non configurato'
        if not (dm.blob_account_key or '').strip():
            return False, 'blob_account_key non configurato'
        base = (dm.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        account_name = _account_name_from_blob_base(base)
        if not account_name:
            return False, 'blob_base non valido'

        files = self.list_log_files()
        if only_today:
            today_file = os.path.basename(self._current_file())
            files = [t for t in files if t[0] == today_file]
        if not files:
            return False, ('Nessun log oggi'
                           if only_today else 'Cartella log vuota')

        from urllib.parse import quote
        uploaded = []
        errors = []
        for fn, path, sz in files:
            safe = quote(fn, safe='._-')
            url = (f'{base}/{BLOB_CONTAINER_LOGS}/{dm.cloud_boat_id}/{safe}')
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                req = urllib.request.Request(
                    url, data=data, method='PUT',
                    headers={
                        'Content-Type':   'text/plain; charset=utf-8',
                        'x-ms-blob-type': 'BlockBlob',
                        'Content-Length': str(len(data)),
                    })
                azure_sign_request(req, account_name, dm.blob_account_key)
                ctx = _SSL_CTX_VERIFIED or ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=timeout,
                                             context=ctx) as resp:
                    if resp.status < 300:
                        uploaded.append((fn, sz))
                    else:
                        errors.append(f'{fn}: HTTP {resp.status}')
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode('utf-8', errors='replace')[:120]
                except Exception:
                    body = ''
                errors.append(f'{fn}: HTTP {e.code} {body}')
            except Exception as e:
                errors.append(f'{fn}: {type(e).__name__}: {e}')

        if errors and not uploaded:
            return False, '; '.join(errors[:3])
        if errors:
            return False, (f'{len(uploaded)} OK, {len(errors)} errori: '
                           + '; '.join(errors[:3]))
        sizes = sum(sz for _, sz in uploaded)
        return True, (f'{len(uploaded)} file caricato/i ({sizes//1024} KB)')


class _StderrTee:
    """File-like che duplica le scritture sia su stderr originale (visibile
    in logcat) sia nel file di log via ErrorLogger.

    Filtro: solo le righe contenenti pattern di errore vanno nel file log;
    le altre (rumore di librerie, warning normali) vanno solo a stderr.
    """
    _ERROR_PATTERNS = ('Error', 'Exception', 'Traceback', 'ERROR', 'CRITICAL')

    def __init__(self, original_stream, logger):
        self.stream = original_stream
        self.logger = logger
        self._buffer = ''

    def write(self, data):
        try:
            self.stream.write(data)
        except Exception:
            pass
        try:
            self._buffer += data
            while '\n' in self._buffer:
                line, self._buffer = self._buffer.split('\n', 1)
                if any(p in line for p in self._ERROR_PATTERNS):
                    self.logger.log_error(f'[stderr] {line}')
        except Exception:
            pass

    def flush(self):
        try: self.stream.flush()
        except Exception: pass

    def isatty(self):
        try: return self.stream.isatty()
        except Exception: return False


# Istanza singleton del logger. Creata QUI subito perche' molti `print(...)`
# e blocchi try/except del modulo possono essere chiamati gia' a import-time.
# install_global_hooks() viene chiamata da SailingTabletApp.build().
_error_logger = ErrorLogger(ERROR_LOG_DIR)


def log_err(msg, exc=None):
    """Wrapper conciso per registrare un errore. Usabile da qualsiasi parte
    del codice come:
        log_err(f'_load_cfg: {e}')
        log_err('failed parse', exc=e)
    """
    _error_logger.log_error(msg, exc=exc)


def parse_coord(s, is_lat=True):
    """Converte una stringa di coordinata in gradi decimali (float).

    Formato accettato: gradi-minuti decimali (DM).
    Esempi validi:
        "45°45.164'N"   -> 45.752733
        "13°37.074'E"   -> 13.617900
        "45 45.164 N"   -> 45.752733
        "45 45.164'"    -> 45.752733  (senza emisfero, segno positivo)
        "13°31.269'W"   -> -13.521150 (W e S danno segno negativo)

    Il segno e' determinato dall'emisfero (N/S/E/W) se presente, altrimenti
    e' positivo. is_lat serve per i messaggi di errore e per il range di
    validita' (-90..90 vs -180..180).

    Solleva ValueError se la stringa non e' nel formato gradi-minuti
    decimali o se i valori sono fuori range."""
    import re
    if s is None:
        raise ValueError('coordinata vuota')
    raw = str(s).strip()
    if not raw:
        raise ValueError('coordinata vuota')

    # Normalizza: virgola decimale -> punto, lettere in maiuscolo
    raw = raw.replace(',', '.').upper()

    # Estrai emisfero se presente (lettera isolata N/S/E/W)
    hemi = None
    m_h = re.search(r'\b([NSEW])\b', raw)
    if m_h:
        hemi = m_h.group(1)
        raw = raw.replace(hemi, ' ').strip()

    # Sostituisci tutti i simboli unicode/ASCII di gradi/minuti
    # con spazi: ° º ' ’ ′ e tab.
    for ch in ['°', 'º', "'", '’', '′', '\t']:
        raw = raw.replace(ch, ' ')

    raw = raw.strip()

    # Formato richiesto: ESATTAMENTE due numeri (gradi + minuti decimali)
    parts = raw.split()
    if len(parts) != 2:
        raise ValueError(
            f"formato richiesto: gradi-minuti (es. 45°45.164'N), "
            f"ricevuto: {s!r}")
    try:
        deg_int = float(parts[0])
        minutes = float(parts[1])
    except ValueError:
        raise ValueError(f'numeri non validi: {s!r}')

    if minutes < 0 or minutes >= 60:
        raise ValueError(f'minuti fuori range [0..60): {minutes}')
    if deg_int < 0:
        raise ValueError(
            f"gradi negativi non ammessi, usa l'emisfero (es. W o S): {s!r}")

    deg = deg_int + minutes / 60.0

    # Applica segno: emisfero W/S = negativo, N/E o nessuno = positivo
    if hemi in ('S', 'W'):
        deg = -deg

    # Validazione range
    limit = 90.0 if is_lat else 180.0
    if not (-limit <= deg <= limit):
        kind = 'Latitudine' if is_lat else 'Longitudine'
        raise ValueError(f'{kind} fuori range (+/-{int(limit)}): {deg}')
    return deg


def format_coord_dm(deg, is_lat=True):
    """Inverso di parse_coord: converte gradi decimali (float) in stringa
    gradi-minuti decimali con simbolo emisfero.

    Esempi:
        format_coord_dm(45.752733, True)   -> "45°45.164'N"
        format_coord_dm(13.617900, False)  -> "13°37.074'E"
        format_coord_dm(-13.521150, False) -> "13°31.269'W"

    Tre cifre decimali sui minuti: precisione ~1.85 metri, sufficiente
    per qualsiasi posizionamento di boa di regata. Se deg e' None o non
    valido, ritorna stringa vuota."""
    if deg is None:
        return ''
    try:
        d = float(deg)
    except (TypeError, ValueError):
        return ''
    if is_lat:
        hemi = 'N' if d >= 0 else 'S'
    else:
        hemi = 'E' if d >= 0 else 'W'
    a = abs(d)
    deg_int = int(a)
    minutes = (a - deg_int) * 60.0
    # Rounding edge case: se minutes arrotonda a 60.000 dobbiamo riportare
    # il carry sui gradi (es. 45.999992 -> 46 0.000 invece di 45 60.000).
    if round(minutes, 3) >= 60.0:
        deg_int += 1
        minutes = 0.0
    return f"{deg_int}°{minutes:06.3f}'{hemi}"


def coord_in(value, is_lat=True):
    """Converte un valore di coordinata (qualsiasi formato accettato) in
    float gradi decimali. Helper centrale per leggere lat/lon da file:
    accetta sia il formato canonico DM in stringa ("45°45.164'N") sia il
    formato legacy in numero decimale (45.752733). Cosi' i file salvati
    da versioni precedenti dell'app continuano a funzionare.

    Solleva ValueError se il valore non e' interpretabile."""
    if value is None:
        raise ValueError('valore None')
    # Numero (int/float) -> gia' in gradi decimali
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    # Stringa -> tenta DM tramite parse_coord; come fallback prova float diretto
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError('stringa vuota')
        # Se contiene simboli tipici DM (° ' N S E W) usa il parser DM
        if any(ch in s.upper() for ch in ['°', 'º', "'", '’', 'N', 'S', 'E', 'W']):
            return parse_coord(s, is_lat=is_lat)
        # Altrimenti prova come float decimale (retrocompat)
        try:
            return float(s.replace(',', '.'))
        except ValueError:
            # Ultimo tentativo: parser DM su stringa di soli numeri (es. "45 45.164")
            return parse_coord(s, is_lat=is_lat)
    raise ValueError(f'tipo non supportato: {type(value).__name__}')


def _format_waypoints_file(wpts):
    """Restituisce la stringa JSON formattata per il file waypoints.json.

    Formato richiesto: ogni waypoint ha le chiavi (name, lat, lon, side) su
    righe separate SENZA indentazione interna, mentre la lista esterna e
    l'oggetto sono indentati a 2 spazi. Esempio:

        {
          "waypoints": [
            {
        "name": "Boa1",
        "lat": "45°46.154'N",
        "lon": "13°36.165'E",
        "side": "port"
            },
            ...
          ]
        }

    json.dump con indent= non puo' produrre questo layout perche' indenta
    uniformemente tutti i livelli annidati. Costruiamo la stringa a mano:
    e' un formato fisso a 4 chiavi per waypoint, quindi semplice e robusto.

    Le stringhe vengono passate per json.dumps cosi' eventuali caratteri
    speciali (apici, backslash) sono correttamente escapati. ensure_ascii=
    False per scrivere il simbolo ° letterale."""
    if not wpts:
        return '{\n  "waypoints": []\n}\n'
    parts = ['{', '  "waypoints": [']
    for i, w in enumerate(wpts):
        name = json.dumps(str(w.get('name', '')), ensure_ascii=False)
        lat  = json.dumps(str(w.get('lat',  '')), ensure_ascii=False)
        lon  = json.dumps(str(w.get('lon',  '')), ensure_ascii=False)
        side = json.dumps(str(w.get('side', 'port')), ensure_ascii=False)
        parts.append('    {')
        parts.append(f'"name": {name},')
        parts.append(f'"lat": {lat},')
        parts.append(f'"lon": {lon},')
        parts.append(f'"side": {side}')
        # Virgola tra waypoint, non sull'ultimo
        parts.append('    }' + (',' if i < len(wpts) - 1 else ''))
    parts.append('  ]')
    parts.append('}')
    return '\n'.join(parts) + '\n'


def fetch_remote_config(blob_base, boat_id, blob_account_key, timeout=8):
    """Scarica sailing_config.json dal blob storage cloud per la barca data.

    URL pattern:
        {blob_base}/config/{boat_id}/sailing_config.json

    Usa Shared Key auth (HMAC-SHA256) come tutto il resto del v1.10+.

    Restituisce:
        (True, dict_config, None) se download e parse OK
        (False, None, 'msg_errore')

    Casi di fallimento gestiti (tutti finiscono in fallback ai default):
    - 404 (blob non esistente per questa barca, caso normale)
    - 403 (chiave non valida o container con restrizioni)
    - Timeout/DNS/rete (offline al primo avvio)
    - JSON malformato sul cloud
    """
    if not blob_base or not boat_id:
        return (False, None, 'blob_base/boat_id non configurati')
    if not (blob_account_key or '').strip():
        return (False, None, 'blob_account_key non configurato')
    account_name = _account_name_from_blob_base(blob_base)
    if not account_name:
        return (False, None, 'blob_base non valido')
    url = (f'{blob_base.rstrip("/")}'
           f'/{BLOB_CONTAINER_CONFIG}/{boat_id}/{CONFIG_FILE}')
    try:
        req = urllib.request.Request(url, method='GET')
        azure_sign_request(req, account_name, blob_account_key)
        ctx = _SSL_CTX_VERIFIED or ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status != 200:
                return (False, None, f'HTTP {resp.status}')
            raw = resp.read()
    except urllib.error.HTTPError as e:
        return (False, None, f'HTTP {e.code}')
    except urllib.error.URLError as e:
        return (False, None, f'rete: {e.reason}')
    except socket.timeout:
        return (False, None, f'timeout dopo {timeout}s')
    except Exception as e:
        return (False, None, f'{type(e).__name__}: {e}')
    try:
        data = json.loads(raw.decode('utf-8'))
        if not isinstance(data, dict):
            return (False, None, 'JSON non e\' un oggetto')
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return (False, None, f'JSON invalido: {e}')
    return (True, data, None)


def default_config():
    """Restituisce il dict con TUTTI i valori di default dell'applicazione.

    Questa e' l'UNICA fonte di verita' per i default: viene usata sia da
    DataManager.__init__ (per inizializzare gli attributi) sia da _load_cfg
    quando il file sailing_config.json non esiste (per crearlo al primo avvio).

    Modifica qui per cambiare i default 'fabbrica' dell'app."""
    return {
        # Connessione NMEA TCP (router di bordo)
        'nmea_ip':            '192.168.1.4',
        'nmea_port':          60001,
        # Path file
        'polar_path':         POLAR_PATH,
        'log_dir':            LOG_PATH,
        # Tattica: finestra TWD per analisi lato buono / vira (minuti)
        'twd_window_minutes': 5,
        # Cloud upload live (snapshot periodico). Dal v1.19 fa PUT diretto
        # al container 'trackslive' del blob storage. Il campo 'cloud_url'
        # resta nel config per backward-compat ma e' IGNORATO dal flusso.
        'cloud_enabled':      False,
        'cloud_url':          CLOUD_URL_DEFAULT,
        'cloud_boat_id':      BOAT_ID_DEFAULT,
        'cloud_token':        '016WFv2hWiOedqR4v5qgMP30SLRPOp2kWUR-0pBkfPE',
        # Intervallo upload in secondi. Valori UI ammessi: 30,60,120,300,600.
        # Min hard floor 30s nel CloudUploader._loop().
        'cloud_interval_s':   60,
        # Base URL del servizio cloud (legacy, non piu' usato per download).
        'api_base':           API_BASE_DEFAULT,
        # === Azure Blob Storage (autenticazione via Shared Key) ===
        # blob_base: URL base dello storage account.
        # blob_account_key: chiave master dello storage account (da Azure
        # Portal > Storage Account > Access Keys). Usata per firmare le
        # richieste HTTP al blob storage con HMAC-SHA256 (Shared Key auth).
        # Container usati (sotto-cartella per boat_id):
        #   {blob_base}/polars/{cloud_boat_id}/polar.json     (download GET)
        #   {blob_base}/waypoints/{cloud_boat_id}/waypoints.json (download GET)
        #   {blob_base}/meteo/{cloud_boat_id}/meteo.json       (download GET)
        #   {blob_base}/tracks/{cloud_boat_id}/{filename}.csv (upload PUT)
        #   {blob_base}/trackslive/{cloud_boat_id}/{ts}.json   (upload PUT live)
        #   {blob_base}/config/{cloud_boat_id}/sailing_config.json (download GET)
        #   {blob_base}/logs/{cloud_boat_id}/errors_*.log     (upload PUT log)
        # ATTENZIONE: la chiave da' accesso completo allo storage account.
        # Non condividere il sailing_config.json con altri tablet/utenti.
        'blob_base':          BLOB_BASE_DEFAULT,
        'blob_account_key':   ('ruLSMqmQjnqYRQVXrFtmZmfB4JHXU4nRwyy5px7p'
                               'WplJgsbgHIsTl8mwk7lrxRz8W+Y+UV2zxA+j+ASt/NKXhQ=='),
        # Polare: flag globale ON/OFF. Quando False tutti i calcoli polar-aware
        # (target speed, laylines, ETA, tactical advice on layline) tornano al
        # comportamento "raw" senza polare. La polare resta caricata in memoria,
        # solo non viene consultata. Toggle dalla PolarScreen.
        'polar_enabled':      True,
        # Stato corrente
        'waypoints':          [],
        'target_mark':        None,
    }

def default_waypoints():
    """Restituisce la lista di waypoint di default usata al primo avvio
    quando waypoints.json non esiste sul disco. Vedi _ensure_waypoints_file()
    per il punto in cui questi valori finiscono su disco.

    Coordinate in Golfo di Trieste (zona Grado/Monfalcone), formato
    gradi-minuti decimali con simbolo emisfero. Sono valori di esempio
    sostituibili dall'utente: l'app crea questo file solo al primo avvio
    se non esiste.

    NOTA: nel JSON le coordinate sono SEMPRE stringhe DM tipo "45°45.164'N".
    Il parser coord_in() converte automaticamente in float al caricamento;
    il formatter format_coord_dm() riformatta in DM al salvataggio. La
    rappresentazione interna in memoria resta float in gradi decimali, cosi'
    le formule di calcolo (calc_dist_brg, laylines, ecc.) lavorano native.
    """
    return [
        {'name': 'Pin',  'lat': "45°45.164'N", 'lon': "13°37.074'E", 'side': 'starboard'},
        {'name': 'Boa1', 'lat': "45°41.539'N", 'lon': "13°35.631'E", 'side': 'starboard'},
        {'name': 'Boa2', 'lat': "45°41.268'N", 'lon': "13°31.269'E", 'side': 'port'},
    ]

def default_polar():
    """Restituisce la polare di default (boat_name vuoto, 7 TWS x 18 TWA)
    usata al primo avvio quando polar.json non esiste sul disco. Vedi
    _ensure_polar_file() per la creazione effettiva sul disco."""
    return {
        'boat_name': '',
        'polar': {
            '6.0':  {'30.0': 3.2, '35.0': 3.8, '40.0': 4.5, '45.0': 5.0,
                     '52.0': 5.2, '60.0': 5.5, '70.0': 5.7, '80.0': 5.9,
                     '90.0': 6.0, '100.0': 6.1, '110.0': 6.2, '120.0': 6.4,
                     '130.0': 6.5, '140.0': 6.6, '150.0': 6.7, '160.0': 6.7,
                     '170.0': 6.6, '180.0': 6.5},
            '8.0':  {'30.0': 4.1, '35.0': 4.8, '40.0': 5.6, '45.0': 6.2,
                     '52.0': 6.5, '60.0': 6.9, '70.0': 7.2, '80.0': 7.5,
                     '90.0': 7.7, '100.0': 7.8, '110.0': 8.0, '120.0': 8.2,
                     '130.0': 8.4, '140.0': 8.5, '150.0': 8.6, '160.0': 8.6,
                     '170.0': 8.5, '180.0': 8.3},
            '10.0': {'30.0': 4.8, '35.0': 5.5, '40.0': 6.4, '45.0': 7.0,
                     '52.0': 7.4, '60.0': 7.9, '70.0': 8.3, '80.0': 8.7,
                     '90.0': 8.9, '100.0': 9.1, '110.0': 9.3, '120.0': 9.6,
                     '130.0': 9.8, '140.0': 10.0, '150.0': 10.1, '160.0': 10.1,
                     '170.0': 10.0, '180.0': 9.8},
            '12.0': {'30.0': 5.3, '35.0': 6.1, '40.0': 7.0, '45.0': 7.6,
                     '52.0': 8.1, '60.0': 8.6, '70.0': 9.1, '80.0': 9.5,
                     '90.0': 9.8, '100.0': 10.0, '110.0': 10.3, '120.0': 10.6,
                     '130.0': 10.9, '140.0': 11.1, '150.0': 11.2, '160.0': 11.2,
                     '170.0': 11.1, '180.0': 10.9},
            '14.0': {'30.0': 5.7, '35.0': 6.5, '40.0': 7.4, '45.0': 8.1,
                     '52.0': 8.6, '60.0': 9.2, '70.0': 9.8, '80.0': 10.3,
                     '90.0': 10.6, '100.0': 10.9, '110.0': 11.2, '120.0': 11.6,
                     '130.0': 12.0, '140.0': 12.3, '150.0': 12.5, '160.0': 12.5,
                     '170.0': 12.4, '180.0': 12.1},
            '16.0': {'30.0': 6.0, '35.0': 6.9, '40.0': 7.8, '45.0': 8.5,
                     '52.0': 9.0, '60.0': 9.7, '70.0': 10.4, '80.0': 11.0,
                     '90.0': 11.4, '100.0': 11.7, '110.0': 12.1, '120.0': 12.6,
                     '130.0': 13.1, '140.0': 13.5, '150.0': 13.8, '160.0': 13.9,
                     '170.0': 13.7, '180.0': 13.4},
            '20.0': {'30.0': 6.5, '35.0': 7.4, '40.0': 8.3, '45.0': 9.0,
                     '52.0': 9.6, '60.0': 10.3, '70.0': 11.1, '80.0': 11.8,
                     '90.0': 12.3, '100.0': 12.7, '110.0': 13.2, '120.0': 13.8,
                     '130.0': 14.4, '140.0': 14.9, '150.0': 15.2, '160.0': 15.4,
                     '170.0': 15.2, '180.0': 14.9},
        }
    }

def _ensure_waypoints_file():
    """Se waypoints.json NON esiste in DATA_DIR, lo crea con default_waypoints().
    Idempotente: se il file esiste (anche vuoto) non lo tocca. Pensata per
    essere chiamata UNA volta all'avvio, prima del primo _load_waypoints_json."""
    if os.path.exists(WAYPOINTS_PATH):
        return False
    try:
        parent = os.path.dirname(WAYPOINTS_PATH)
        if parent: os.makedirs(parent, exist_ok=True)
        tmp = WAYPOINTS_PATH + '.tmp'
        with open(tmp, 'w') as f:
            # Formato custom: ogni campo del waypoint su riga separata.
            # Vedi _format_waypoints_file() per il layout esatto.
            f.write(_format_waypoints_file(default_waypoints()))
            f.flush()
            try: os.fsync(f.fileno())
            except: pass
        os.replace(tmp, WAYPOINTS_PATH)
        print(f'waypoints.json creato con default in {WAYPOINTS_PATH}')
        return True
    except Exception as e:
        print(f'_ensure_waypoints_file ERROR: {type(e).__name__}: {e}')
        return False

def _ensure_polar_file():
    """Se polar.json NON esiste in DATA_DIR (path POLAR_PATH), lo crea con
    default_polar(). Idempotente. Chiamata una volta all'avvio prima della
    load della polare."""
    if os.path.exists(POLAR_PATH):
        return False
    try:
        parent = os.path.dirname(POLAR_PATH)
        if parent: os.makedirs(parent, exist_ok=True)
        tmp = POLAR_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(default_polar(), f, indent=2)
            f.flush()
            try: os.fsync(f.fileno())
            except: pass
        os.replace(tmp, POLAR_PATH)
        print(f'polar.json creato con default in {POLAR_PATH}')
        return True
    except Exception as e:
        print(f'_ensure_polar_file ERROR: {type(e).__name__}: {e}')
        return False

def avail_h():
    """Altezza disponibile per il contenuto dopo titlebar e padding."""
    return max(dp(200), Window.height - TITLE_H - dp(20))

# =============================================================================
# UTILITY
# =============================================================================

def calc_true_wind(awa, aws, spd):
    if None in (awa, aws, spd): return None
    try:
        r = math.radians(awa)
        tx = aws*math.cos(r)-spd; ty = aws*math.sin(r)
        return (math.degrees(math.atan2(ty,tx))+360)%360, math.sqrt(tx**2+ty**2)
    except: return None

def calc_dist_brg(la1,lo1,la2,lo2):
    if None in (la1,lo1,la2,lo2): return None,None
    try:
        R=6371; r1,r2=math.radians(la1),math.radians(la2)
        dl,dL=math.radians(la2-la1),math.radians(lo2-lo1)
        a=math.sin(dl/2)**2+math.cos(r1)*math.cos(r2)*math.sin(dL/2)**2
        d=R*2*math.atan2(math.sqrt(a),math.sqrt(1-a))/1.852
        b=(math.degrees(math.atan2(math.sin(dL)*math.cos(r2),
           math.cos(r1)*math.sin(r2)-math.sin(r1)*math.cos(r2)*math.cos(dL)))+360)%360
        return d,b
    except: return None,None

def calc_vmg(spd,hdg,brg):
    if None in (spd,hdg,brg): return None
    try:
        diff=abs(brg-hdg)
        if diff>180: diff=360-diff
        return spd*math.cos(math.radians(diff))
    except: return None

# =============================================================================
# POLAR DATA
# =============================================================================

class PolarData:
    """Modello della polare di una barca + crossover delle vele.

    Formato JSON v1 (legacy, ancora supportato in lettura/scrittura):
        {
          "boat_name": "...",
          "polar": { "tws": { "twa": bsp, ... }, ... }
        }

    Formato JSON v2 (con crossover vele):
        {
          "boat_name": "...",
          "polar": { ... come sopra ... },
          "sails": {
            "definitions": {
              "Gen+F": {"label": "Genoa + randa full", "color": "#ffe55c"},
              ...
            },
            "crossover": {
              "tws": { "Beat": "Gen+F", "52": "Gen+F", "60": "Gen+F",
                       "75": "...", "90": "...", "110": "...", "120": "...",
                       "135": "...", "150": "...", "Run": "..." },
              ...
            }
          }
        }

    Backward compat: i polar.json senza sezione 'sails' continuano a
    funzionare normalmente; in quel caso get_sail() restituisce None.
    """

    # Bin TWA del crossover. Posizioni: 'Beat'=bolina, 'Run'=poppa piena.
    # Le chiavi numeriche sono punti TWA in gradi. Ordine importante: TWA
    # crescente da bolina a poppa.
    SAIL_BINS = ['Beat', '52', '60', '75', '90', '110', '120', '135', '150', 'Run']
    # Mappatura bin -> angolo TWA centrale (per il binning di un TWA arbitrario).
    # 'Beat' usa ~42° (bolina target tipica) e 'Run' usa 180°.
    _SAIL_BIN_ANGLES = {
        'Beat': 42.0, '52': 52.0, '60': 60.0, '75': 75.0, '90': 90.0,
        '110': 110.0, '120': 120.0, '135': 135.0, '150': 150.0, 'Run': 180.0,
    }

    def __init__(self):
        self.data = {}
        self.loaded = False
        self.boat_name = ''
        # === Crossover vele (v2) ===
        # sail_definitions: {sail_id: {'label': str, 'color': '#rrggbb'}}
        self.sail_definitions = {}
        # sail_crossover: {tws_float: {bin_str: sail_id}}
        # I bin sono SAIL_BINS (stringhe). tws_float e' float (es. 12.0).
        self.sail_crossover = {}

    def has_sails(self):
        """True se il polar.json caricato include la sezione crossover."""
        return bool(self.sail_definitions and self.sail_crossover)

    def get_tws_list(self): return sorted(self.data.keys())
    def get_twa_list(self):
        t=set()
        for d in self.data.values(): t.update(d.keys())
        return sorted(t)

    def get_bsp(self,tws,twa):
        if not self.data: return None
        twa=abs(twa)
        if twa>180: twa=360-twa
        keys=self.get_tws_list()
        if not keys: return None
        if tws<=keys[0]:  return self._itwa(self.data[keys[0]],twa)
        if tws>=keys[-1]: return self._itwa(self.data[keys[-1]],twa)
        for i in range(len(keys)-1):
            t0,t1=keys[i],keys[i+1]
            if t0<=tws<=t1:
                b0=self._itwa(self.data[t0],twa); b1=self._itwa(self.data[t1],twa)
                if b0 is None or b1 is None: return b0 or b1
                return b0+(tws-t0)/(t1-t0)*(b1-b0)
        return None

    def _itwa(self,d,twa):
        if not d: return None
        keys=sorted(d.keys())
        if twa<=keys[0]: return d[keys[0]]
        if twa>=keys[-1]: return d[keys[-1]]
        for i in range(len(keys)-1):
            a0,a1=keys[i],keys[i+1]
            if a0<=twa<=a1: return d[a0]+(twa-a0)/(a1-a0)*(d[a1]-d[a0])
        return None

    def get_target_vmg(self,tws,upwind=True):
        if not self.data: return None
        rng=range(30,90) if upwind else range(90,175)
        best,btwa=-999,None
        for twa in rng:
            bsp=self.get_bsp(tws,twa)
            if bsp is None: continue
            vmg=bsp*math.cos(math.radians(twa))
            vmg=abs(vmg) if upwind else -vmg
            if vmg>best: best,btwa=vmg,twa
        return (btwa,best) if btwa else None

    # ---------- Crossover vele ----------

    def _twa_to_bin(self, twa):
        """Mappa un TWA (gradi, valore assoluto) al bin del crossover piu'
        vicino. Restituisce una stringa fra SAIL_BINS.

        Strategia: trova il bin con angolo centrale piu' vicino al TWA dato.
        Tutti i TWA<=42 vanno a 'Beat', TWA>=170 vanno a 'Run'.
        """
        twa = abs(float(twa))
        if twa > 180: twa = 360 - twa
        # Edge: bolina stretta -> Beat
        if twa <= self._SAIL_BIN_ANGLES['Beat']:
            return 'Beat'
        # Edge: poppa piena -> Run
        if twa >= 170:
            return 'Run'
        # Trova il bin con angolo piu' vicino
        best_bin = 'Beat'
        best_dist = 1e9
        for b in self.SAIL_BINS:
            d = abs(self._SAIL_BIN_ANGLES[b] - twa)
            if d < best_dist:
                best_dist = d
                best_bin = b
        return best_bin

    def _crossover_tws_keys(self):
        """Lista ordinata dei TWS (float) presenti nella tabella crossover."""
        return sorted(self.sail_crossover.keys())

    def get_sail(self, tws, twa):
        """Restituisce l'identificativo della vela suggerita per TWS/TWA dati,
        oppure None se la sezione 'sails' non e' presente nel polar.json
        oppure se la combinazione non e' coperta dal crossover.

        Logica:
        - TWA viene mappato al bin piu' vicino fra SAIL_BINS.
        - Per TWS si sceglie il primo step di vento >= TWS richiesto (pattern
          standard delle tabelle crossover: la vela cambia quando il vento
          'sale' a quella soglia). Se TWS >= max, prende l'ultimo step. Se
          TWS < min, prende il primo step.
        """
        if not self.has_sails():
            return None
        try:
            tws_f = float(tws)
        except (TypeError, ValueError):
            return None
        keys = self._crossover_tws_keys()
        if not keys:
            return None
        # Scelta TWS step
        if tws_f <= keys[0]:
            tws_key = keys[0]
        elif tws_f >= keys[-1]:
            tws_key = keys[-1]
        else:
            # primo step >= tws (cambio vela quando il vento 'sale')
            tws_key = next(k for k in keys if k >= tws_f)
        bin_str = self._twa_to_bin(twa)
        return self.sail_crossover.get(tws_key, {}).get(bin_str)

    def get_sail_label(self, sail_id):
        """Etichetta human-readable di una vela (es. 'Genoa + randa full').
        Se la vela non e' definita, restituisce sail_id stesso."""
        if not sail_id: return ''
        d = self.sail_definitions.get(sail_id)
        if isinstance(d, dict):
            return d.get('label') or sail_id
        return sail_id

    def get_sail_color(self, sail_id):
        """Colore hex (es. '#ffe55c') di una vela. Default '#888888'."""
        if not sail_id: return '#888888'
        d = self.sail_definitions.get(sail_id)
        if isinstance(d, dict):
            return d.get('color') or '#888888'
        return '#888888'

    # ---------- I/O ----------

    def load(self,path):
        try:
            with open(path) as f: d=json.load(f)
            self.boat_name=d.get('boat_name','')
            self.data={float(k):{float(ka):float(v) for ka,v in kv.items()}
                       for k,kv in d.get('polar',{}).items()}
            # === Sails: opzionale, backward-compat con polar.json v1 ===
            sails = d.get('sails') or {}
            self.sail_definitions = {}
            self.sail_crossover = {}
            if isinstance(sails, dict):
                defs = sails.get('definitions') or {}
                if isinstance(defs, dict):
                    # Validazione minima: ogni voce deve essere dict con
                    # almeno 'label' o 'color' (o entrambi).
                    for sail_id, info in defs.items():
                        if isinstance(info, dict):
                            self.sail_definitions[str(sail_id)] = {
                                'label': str(info.get('label', sail_id)),
                                'color': str(info.get('color', '#888888')),
                            }
                cross = sails.get('crossover') or {}
                if isinstance(cross, dict):
                    for tws_k, bins in cross.items():
                        if not isinstance(bins, dict):
                            continue
                        try:
                            tws_f = float(tws_k)
                        except (TypeError, ValueError):
                            continue
                        # Filtro: tieni solo i bin riconosciuti, cosi'
                        # eventuali chiavi spurie nel JSON non rompono il lookup.
                        clean = {}
                        for bin_k, sail_id in bins.items():
                            bk = str(bin_k)
                            if bk in self.SAIL_BINS:
                                clean[bk] = str(sail_id) if sail_id else ''
                        if clean:
                            self.sail_crossover[tws_f] = clean
            self.loaded=bool(self.data); return self.loaded
        except Exception as e: print(f'Polar:{e}'); return False

    def load_csv(self,path):
        try:
            with open(path,newline='') as f:
                rd=csv.reader(f); hdr=next(rd)
                tws_list=[float(x.strip()) for x in hdr[1:] if x.strip()]
                self.data={t:{} for t in tws_list}
                for row in rd:
                    if not row or not row[0].strip(): continue
                    twa=float(row[0].strip())
                    for i,tws in enumerate(tws_list):
                        try: self.data[tws][twa]=float(row[i+1].strip())
                        except: pass
            # CSV non porta info sul crossover: azzera la sezione vele.
            self.sail_definitions = {}
            self.sail_crossover = {}
            self.loaded=bool(self.data); return self.loaded
        except Exception as e: print(f'CSV:{e}'); return False

    def save(self,path):
        """Salva la polare. Se sono presenti dati di crossover vele, vengono
        inclusi nel JSON (formato v2); altrimenti si mantiene il formato v1
        per compatibilita' con file pre-esistenti."""
        payload = {
            'boat_name': self.boat_name,
            'polar': {str(k):{str(ka):v for ka,v in kv.items()}
                      for k,kv in self.data.items()},
        }
        if self.has_sails():
            payload['sails'] = {
                'definitions': dict(self.sail_definitions),
                'crossover': {str(k): dict(v)
                              for k, v in self.sail_crossover.items()},
            }
        with open(path,'w') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

# =============================================================================
# CLOUD UPLOADER -- invio dati barca a endpoint REST
# =============================================================================

class CloudUploader:
    """Invia periodicamente snapshot dei dati barca al Blob Storage Azure
    (container 'trackslive'). Ogni snapshot e' UN file JSON separato.

    URL pattern:
        {blob_base}/trackslive/{cloud_boat_id}/{timestamp}.json
    Esempio:
        https://sailingapp.blob.core.windows.net/trackslive/soar/
        2026-05-13T14-23-05Z.json

    Caratteristiche:
    - Thread separato: non blocca mai la UI o il parsing NMEA.
    - Buffer offline su file (.jsonl): garantisce zero perdita dati se
      la rete cellulare e' assente o instabile. Quando la rete torna,
      ogni record nella coda diventa un file separato nel blob.
    - Force-cellular su Android: bypassa il WiFi senza uplink (caso tipico
      del WiFi di bordo isolato) e usa la SIM dati per HTTPS.
    - Rate limit lato client: max 1 invio "manuale" ogni 60s.

    Cambio architetturale v1.19:
    - Prima: POST JSON a un endpoint REST (Azure Function -> SQL Server).
    - Adesso: PUT diretto al Blob Storage, riusando la Shared Key esistente.
    """

    def __init__(self, dm):
        self.dm = dm
        self._thread = None
        self._stop = threading.Event()
        self._last_manual = 0.0
        # Counters per UI
        self.sent_count = 0
        self.last_sent_ts = None
        self.last_error = None
        # Path del buffer offline (in DATA_DIR cosi' segue i path utente)
        self.queue_path = os.path.join(DATA_DIR, 'cloud_queue.jsonl')
        # Cache della rete cellulare ottenuta via JNI (Android)
        self._cell_network = None

    # ----- ciclo di vita -----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    # ----- thread principale -----

    def _loop(self):
        """Loop di upload. Si sveglia ogni `cloud_interval_s` secondi, fa snapshot
        e invia (drenando anche la coda offline)."""
        # Aspetta 5s al primo avvio per dare tempo al sistema di stabilizzarsi
        if self._stop.wait(5):
            return
        while not self._stop.is_set():
            try:
                self._upload_cycle()
            except Exception as e:
                self.last_error = f'Loop:{e}'
                print(f'CloudUploader loop:{e}')
                log_err(f'CloudUploader loop: {e}', exc=e)
            # Sleep N secondi (configurato in DataManager). Minimo 30s per non
            # saturare la rete cellulare e per dare al backend tempo di risp.
            interval_s = max(30, int(self.dm.cloud_interval_s or 60))
            if self._stop.wait(interval_s):
                return

    def _upload_cycle(self):
        """Un ciclo: drena coda offline, poi invia il dato corrente."""
        if not self.dm.cloud_enabled:
            return
        if not self.dm.cloud_boat_id:
            self.last_error = 'cloud_boat_id non configurato'
            return
        if not (self.dm.blob_account_key or '').strip():
            self.last_error = 'blob_account_key non configurato'
            return
        if not (self.dm.blob_base or '').strip():
            self.last_error = 'blob_base non configurato'
            return

        # 1) Drena la coda offline (max 50 record per ciclo per non
        # saturare la rete cellulare in caso di accumulo lungo).
        # Ogni record offline diventa un file separato nel blob trackslive.
        queued = self._read_queue(max_records=50)
        for rec in queued:
            ok, err = self._post_json(rec)
            if not ok:
                # Se anche un record vecchio fallisce, fermati e accumula
                # il dato corrente in coda. Riproveremo al prossimo ciclo.
                self._enqueue(self._build_snapshot())
                self.last_error = f'Drain:{err}'
                return
            self.sent_count += 1
        if queued:
            self._truncate_queue(len(queued))

        # 2) Invia il dato corrente
        snap = self._build_snapshot()
        ok, err = self._post_json(snap)
        if ok:
            self.sent_count += 1
            self.last_sent_ts = time.time()
            self.last_error = None
        else:
            self._enqueue(snap)
            self.last_error = err

    # ----- snapshot dei dati -----

    def _build_snapshot(self):
        """Raccoglie lo stato corrente del DataManager in dict JSON-friendly."""
        dm = self.dm
        advice, shift = dm.tactical_advice()
        twd_avg = dm.get_twd_average()
        snap = {
            'boat_id': dm.cloud_boat_id,
            'token':   dm.cloud_token,
            'ts':      datetime.now(timezone.utc).isoformat(),
            'gps': {
                'lat': dm.gps_lat,
                'lon': dm.gps_lon,
                'sog_kn': dm.boat_speed,
                'cog_deg': dm.boat_course,
            },
            'wind': {
                'tws_kn':  dm.true_wind_speed,
                'twa_deg': dm.true_wind_angle,
                'twd_deg': ((dm.boat_heading + dm.true_wind_angle) % 360
                            if dm.true_wind_angle is not None else None),
                'aws_kn':  dm.apparent_wind_speed,
                'awa_deg': dm.apparent_wind_angle,
            },
            'boat': {
                'heading_deg': dm.boat_heading,
                'depth_m':     dm.depth if dm.depth > 0 else None,
                'vmg_kn':      dm.vmg,
                'target_bsp_kn': dm.target_bsp,
            },
            'tactical': {
                'advice':    advice,
                'shift_deg': shift,
                'twd_avg_deg': twd_avg,
                'window_min': dm.twd_window_minutes,
            },
            'mark': {
                'name':        dm.target_mark,
                'bearing_deg': dm.bearing_to_mark,
                'distance_nm': dm.distance_to_mark,
            },
        }
        return snap

    # ----- coda offline (jsonl append-only) -----

    def _enqueue(self, record):
        try:
            with open(self.queue_path, 'a') as f:
                f.write(json.dumps(record) + '\n')
        except Exception as e:
            print(f'CloudUploader enqueue:{e}')

    def _read_queue(self, max_records=50):
        if not os.path.exists(self.queue_path):
            return []
        records = []
        try:
            with open(self.queue_path) as f:
                for i, line in enumerate(f):
                    if i >= max_records: break
                    line = line.strip()
                    if not line: continue
                    try: records.append(json.loads(line))
                    except: pass
        except Exception as e:
            print(f'CloudUploader read_queue:{e}')
        return records

    def _truncate_queue(self, n_drained):
        """Rimuove i primi n record drenati (rimane il resto da inviare)."""
        if not os.path.exists(self.queue_path): return
        try:
            with open(self.queue_path) as f:
                lines = f.readlines()
            remaining = lines[n_drained:]
            with open(self.queue_path, 'w') as f:
                f.writelines(remaining)
        except Exception as e:
            print(f'CloudUploader truncate:{e}')

    def queue_size(self):
        if not os.path.exists(self.queue_path): return 0
        try:
            with open(self.queue_path) as f:
                return sum(1 for _ in f if _.strip())
        except: return 0

    # ----- HTTP PUT al Blob Storage con force-cellular su Android -----
    #
    # CAMBIO ARCHITETTURALE (v1.19):
    # Prima il CloudUploader faceva POST JSON a un endpoint REST esterno
    # (webhook.site / Azure Function), che a sua volta scriveva su SQL Server.
    # Adesso fa PUT diretto al container 'trackslive' del Blob Storage, come
    # TrackUploader fa con i CSV in 'tracks'. Vantaggi:
    # - Niente backend intermedio da mantenere (no Function, no DB).
    # - Stesso meccanismo Shared Key gia' collaudato per i CSV.
    # - Coerente con il resto dell'app (download polar/waypoints/meteo via blob).
    #
    # Il campo 'cloud_url' nel config e' ora IGNORATO da questo flusso (resta
    # per compat ma non usato). L'URL e' composto al volo come:
    #   {blob_base}/trackslive/{cloud_boat_id}/{timestamp}.json
    # Filename: timestamp UTC con ':' sostituiti da '-' (i ':' non sono validi
    # nei nomi blob su alcuni client). Un file per snapshot, niente collisioni.

    def _post_json(self, payload):
        """PUT snapshot JSON al container 'trackslive' del blob storage.

        Restituisce (ok: bool, err: str|None). In caso di errore il chiamante
        accumula nella coda offline."""
        # Genera filename univoco per questo snapshot
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%SZ')
        filename = f'{ts}.json'

        if not self.dm.cloud_boat_id:
            return False, 'cloud_boat_id non configurato'
        if not (self.dm.blob_account_key or '').strip():
            return False, 'blob_account_key non configurato'

        base = (self.dm.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        account_name = _account_name_from_blob_base(base)
        if not account_name:
            return False, 'blob_base non valido'
        from urllib.parse import quote
        safe = quote(filename, safe='._-')
        url = (f'{base}/{BLOB_CONTAINER_TRACKSLIVE}/'
               f'{self.dm.cloud_boat_id}/{safe}')

        return self._put_to_blob_attempt(url, payload, account_name,
                                          self.dm.blob_account_key,
                                          _SSL_CTX_VERIFIED)

    def _is_test_host(self, url):
        """Legacy: usato in passato per il fallback SSL su webhook.site.
        Mantenuto solo per compat: blob.core.windows.net richiede sempre
        SSL verificato, quindi questo metodo restituira' sempre False."""
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ''
            return any(host.endswith(h) for h in _SSL_TEST_HOSTS)
        except Exception:
            return False

    def _put_to_blob_attempt(self, url, payload, account_name, account_key,
                              ssl_ctx):
        """Singolo tentativo PUT al blob storage di UN snapshot JSON.

        Header obbligatori Azure Blob:
        - x-ms-blob-type: BlockBlob
        - Content-Type:   application/json
        - Content-Length: (necessario per la firma Shared Key)

        Firma Shared Key (HMAC-SHA256) via azure_sign_request().

        Su Android forza la rete cellulare se disponibile (bypassa il WiFi
        di bordo senza uplink).
        """
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                url, data=data, method='PUT',
                headers={
                    'Content-Type':   'application/json',
                    'x-ms-blob-type': 'BlockBlob',
                    'Content-Length': str(len(data)),
                })
            azure_sign_request(req, account_name, account_key)
            sock_factory = self._cellular_socket_factory()
            if sock_factory:
                orig = socket.create_connection
                socket.create_connection = sock_factory
                try:
                    with urllib.request.urlopen(req, timeout=15,
                                                 context=ssl_ctx) as resp:
                        return (resp.status < 300,
                                None if resp.status < 300
                                else f'HTTP {resp.status}')
                finally:
                    socket.create_connection = orig
            else:
                with urllib.request.urlopen(req, timeout=15,
                                             context=ssl_ctx) as resp:
                    return (resp.status < 300,
                            None if resp.status < 300
                            else f'HTTP {resp.status}')

        except ssl.SSLError as e:
            reason = getattr(e, 'reason', None) or str(e)
            return False, f'SSL: {reason}'
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode('utf-8', errors='replace')[:200]
            except Exception:
                body = ''
            return False, f'HTTP {e.code}: {body}'.strip()
        except urllib.error.URLError as e:
            r = getattr(e, 'reason', e)
            if isinstance(r, ssl.SSLError):
                reason = getattr(r, 'reason', None) or str(r)
                return False, f'SSL: {reason}'
            return False, f'URL: {r}'
        except socket.timeout:
            return False, 'Timeout'
        except Exception as e:
            return False, f'{type(e).__name__}: {e}'

    def _cellular_socket_factory(self):
        """Restituisce una factory per socket bindati alla rete cellulare,
        o None se non in Android o se la cellulare non e' disponibile."""
        if not IS_ANDROID:
            return None
        net = self._get_cellular_network()
        if net is None:
            return None
        try:
            from jnius import autoclass
            JavaSocket = autoclass('java.net.Socket')
            InetSocketAddress = autoclass('java.net.InetSocketAddress')

            def _create_connection(address, timeout=15, *args, **kwargs):
                # address e' (host, port). Creiamo socket Java, lo bindiamo
                # alla rete cellulare e lo wrappiamo come socket Python.
                # NOTA: questo e' un fallback semplificato. Per produzione
                # serio servirebbe uno SocketFactory completo.
                # Nel nostro caso (1 POST ogni 10 min) usiamo l'approccio
                # piu' diretto: bindProcessToNetwork.
                return socket.create_connection(address, timeout)

            # Approccio semplificato e robusto: invece di patchare ogni socket,
            # bindiamo l'INTERO processo alla rete cellulare. Effetto: tutte
            # le connessioni durante questo upload usano cellulare.
            from jnius import autoclass as _ac
            ConnectivityManager = _ac('android.net.ConnectivityManager')
            cm = mActivity.getSystemService(_ac('android.content.Context').CONNECTIVITY_SERVICE)
            cm.bindProcessToNetwork(net)
            return _create_connection
        except Exception as e:
            print(f'CloudUploader cell_factory:{e}')
            return None

    def _get_cellular_network(self):
        """Ottiene un Network Android di tipo cellulare. Cached.
        Restituisce un oggetto Network Java o None."""
        if self._cell_network is not None:
            return self._cell_network
        if not IS_ANDROID:
            return None
        try:
            from jnius import autoclass
            from android import mActivity as _ma
            ConnectivityManager = autoclass('android.net.ConnectivityManager')
            NetworkRequest = autoclass('android.net.NetworkRequest$Builder')
            NetworkCapabilities = autoclass('android.net.NetworkCapabilities')
            Context = autoclass('android.content.Context')

            cm = _ma.getSystemService(Context.CONNECTIVITY_SERVICE)
            # Cerco la rete cellulare gia' attiva fra le reti del sistema
            for net in cm.getAllNetworks():
                caps = cm.getNetworkCapabilities(net)
                if caps and caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR):
                    if caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET):
                        self._cell_network = net
                        return net
            return None
        except Exception as e:
            print(f'CloudUploader get_cell:{e}')
            return None

    # ----- API per il pulsante "Invia ora" -----

    def trigger_now(self):
        """Invio manuale immediato (in thread separato per non bloccare UI).
        Rate-limited: max 1 ogni 60s."""
        now = time.time()
        if now - self._last_manual < 60:
            return False, f'Aspetta {int(60 - (now - self._last_manual))}s'
        self._last_manual = now
        threading.Thread(target=self._upload_cycle, daemon=True).start()
        return True, None


# =============================================================================
# TRACK LOGGER -- scrittura locale del log regata in formato CSV
# =============================================================================
# Scrive una riga ogni 5 secondi nel file:
#   {log_dir}/track_YYYY-MM-DD_HH-MM-SS.csv
# (timestamp = istante di START log).
#
# Header CSV: ts_iso,lat,lon,sog_kn,cog,hdg,tws_kn,twa,aws_kn,awa,vmg_kn,depth_m
# I valori non disponibili sono lasciati vuoti.
#
# Lifecycle:
# - L'utente preme Start -> si crea il file CSV e parte il timer Kivy a 5s.
# - L'utente preme Stop -> si chiude il file. Il path resta in self._last_path
#   per consentire l'upload one-shot al blob via UI.
# - Se l'app va in pausa o esce, on_stop chiude il file (no perdita dati).
class TrackLogger:
    """Logger CSV semplice. Una riga ogni 5s, niente upload automatico."""

    INTERVAL_S = 5.0   # frequenza scrittura riga CSV
    HEADER = ('ts_iso,lat,lon,sog_kn,cog,hdg,'
              'tws_kn,twa,aws_kn,awa,vmg_kn,depth_m\n')

    def __init__(self, dm):
        self.dm = dm
        self._fh = None             # file handle aperto in append-text
        self._path = None           # path del file corrente
        self._last_path = None      # ultimo file chiuso (per "Invia al cloud")
        self._cnt = 0               # righe scritte nel log corrente
        self._started_at = None     # datetime di START
        self._stopped_at = None     # datetime di STOP
        self._timer = None          # event Clock di scrittura periodica
        self._last_error = None

    def is_active(self):
        return self._fh is not None

    def get_path(self):
        """Path del file in scrittura (None se non attivo)."""
        return self._path

    def get_last_path(self):
        """Path dell'ULTIMO file chiuso (None se mai stato fermato)."""
        return self._last_path

    def get_count(self):
        return self._cnt

    def get_last_error(self):
        return self._last_error

    def get_started_at(self):
        """datetime di start del log corrente, o None se non attivo."""
        return self._started_at

    def start(self):
        """Apre un nuovo file CSV con timestamp di adesso. Restituisce
        (ok, path_or_msg)."""
        if self._fh is not None:
            return False, 'gia in registrazione'
        # Path: log_dir/track_YYYY-MM-DD_HH-MM-SS.csv
        log_dir = self.dm.log_dir or LOG_PATH
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception as e:
            self._last_error = f'mkdir log_dir: {e}'
            return False, self._last_error
        ts_now = datetime.now()
        fname = ts_now.strftime('track_%Y-%m-%d_%H-%M-%S.csv')
        path = os.path.join(log_dir, fname)
        try:
            fh = open(path, 'w', encoding='utf-8', newline='')
            fh.write(self.HEADER)
            fh.flush()
        except Exception as e:
            self._last_error = f'open {path}: {e}'
            return False, self._last_error
        self._fh = fh
        self._path = path
        self._cnt = 0
        self._started_at = ts_now
        self._stopped_at = None
        self._last_error = None
        # Timer Kivy (esegue sul main thread, non serve lock)
        self._timer = Clock.schedule_interval(self._tick, self.INTERVAL_S)
        # Scrivo subito la prima riga
        self._tick(0)
        return True, path

    def stop(self):
        """Chiude il file in modo sicuro. Idempotente: se gia' fermo no-op."""
        if self._timer is not None:
            try: self._timer.cancel()
            except Exception: pass
            self._timer = None
        if self._fh is not None:
            try:
                self._fh.flush()
                try: os.fsync(self._fh.fileno())
                except: pass
                self._fh.close()
            except Exception as e:
                self._last_error = f'close: {e}'
            self._last_path = self._path
            self._fh = None
            self._path = None
            self._stopped_at = datetime.now()

    def _tick(self, dt):
        """Scrive UNA riga col snapshot corrente. Resta no-op se file chiuso."""
        if self._fh is None:
            return
        try:
            dm = self.dm
            ts = datetime.now().isoformat(timespec='seconds')
            def fmt(v, prec=2):
                return f'{v:.{prec}f}' if v is not None else ''
            row = (
                f'{ts},'
                f'{fmt(dm.gps_lat, 6)},'
                f'{fmt(dm.gps_lon, 6)},'
                f'{fmt(dm.boat_speed, 2)},'
                f'{fmt(dm.boat_course, 1)},'
                f'{fmt(dm.boat_heading, 1)},'
                f'{fmt(dm.true_wind_speed, 2)},'
                f'{fmt(dm.true_wind_angle, 1)},'
                f'{fmt(dm.apparent_wind_speed, 2)},'
                f'{fmt(dm.apparent_wind_angle, 1)},'
                f'{fmt(dm.vmg, 2)},'
                f'{fmt(dm.depth, 1)}'
                f'\n')
            self._fh.write(row)
            self._fh.flush()
            self._cnt += 1
            self._last_error = None
        except Exception as e:
            self._last_error = f'write: {e}'
            print(f'TrackLogger:{e}')


class DataManager:
    def __init__(self):
        self.connected=False; self.sock=None; self.recv_thread=None
        # Path configurabili (di default puntano a DATA_DIR)
        self.config_path = CONFIG_PATH
        self._lock=threading.Lock()
        # Stato runtime (non persistito)
        self.gps_lat=self.gps_lon=None
        self.boat_heading=self.boat_speed=self.boat_course=0.0
        self.apparent_wind_angle=self.apparent_wind_speed=None
        self.true_wind_angle=self.true_wind_speed=None
        self.depth=0.0
        self.distance_to_mark=None
        self.bearing_to_mark=None; self.vmg=None
        self.polar=PolarData(); self.target_bsp=None
        self.polar_vmg_target=None; self.polar_twa_target=None
        # Storico TWD per analisi tattica
        self._twd_history = deque(maxlen=4000)
        # ---- Stato per lo switch automatico della boa target ----
        # Quando la barca supera la boa attiva, advance_target_if_passed()
        # passa automaticamente al waypoint successivo nella lista. La logica
        # combina due segnali:
        #  1) la distanza scende sotto MARK_PASS_RADIUS_NM (siamo "vicini")
        #  2) la distanza inizia ad aumentare per N tick consecutivi (CPA
        #     superato: il waypoint si sta allontanando)
        # Solo quando entrambi sono veri scattiamo lo switch.
        self._mark_min_dist_nm = None      # distanza minima vista in questo passaggio
        self._mark_increasing_count = 0    # N tick consecutivi con dist in aumento
        self._auto_advance_enabled = True  # se False, niente switch automatico
        self._last_auto_advance_ts = 0.0   # timestamp ultimo switch (anti-rimbalzo)
        # Inizializza TUTTI gli attributi persistenti dai default. Cosi' c'e'
        # un'unica fonte di verita' (default_config) e siamo certi che ogni
        # campo abbia un valore iniziale anche se _load_cfg fallisce.
        self._apply_config(default_config())
        # Carica config da file (o crealo se non esiste)
        self._load_cfg()
        # Se waypoints.json non esiste, crealo con i default (Boa1, Boa2, Arrivo).
        # Va fatto PRIMA di _load_waypoints_json cosi' al primo avvio l'utente
        # trova subito la lista popolata.
        _ensure_waypoints_file()
        # Carica i waypoint dal file (sovrascrive quelli letti dal config).
        self._load_waypoints_json()
        # Crea log dir
        try: os.makedirs(self.log_dir,exist_ok=True)
        except Exception as e: print(f'Logdir:{e}')
        # ----- Caricamento polare -----
        #
        # Strategia "self-healing":
        # 1) Se il file POLAR_PATH (default) non esiste, lo crea con i
        #    valori di default_polar(). Questo e' il caso "primo avvio".
        # 2) Tenta self.polar.load(self.polar_path) sul path configurato
        #    (puo' essere POLAR_PATH o un path custom impostato dall'utente
        #    da PolarScreen).
        # 3) Se il caricamento FALLISCE (file mancante OPPURE file presente
        #    ma JSON malformato/illeggibile), facciamo fallback:
        #       a) Se eravamo gia' su POLAR_PATH: ricreiamo il file da
        #          default_polar() e ricarichiamo. Cosi' un file corrotto
        #          si auto-ripara al boot.
        #       b) Se eravamo su un path custom non leggibile: torniamo al
        #          POLAR_PATH (default) e applichiamo il caso (a). Salviamo
        #          anche la rettifica nel config cosi' al prossimo avvio
        #          non si ripete il fallback.
        #
        # In tutti i casi, dopo questo blocco self.polar.loaded e' True
        # con dati validi (o solo allora ci diamo per vinti).

        # Step 1: assicura che POLAR_PATH abbia un file (anche se non e' il
        # path corrente, ci serve come destinazione del fallback).
        _ensure_polar_file()

        # Step 2: tenta il caricamento dal path configurato
        load_ok = False
        if os.path.exists(self.polar_path):
            load_ok = self.polar.load(self.polar_path)

        # Step 3: fallback se il load non e' andato a buon fine
        if not load_ok:
            print(f'Polare non caricata da {self.polar_path}, applico fallback')
            if self.polar_path != POLAR_PATH:
                # Path custom illeggibile: torna al default
                print(f'  path custom non valido, torno a {POLAR_PATH}')
                self.polar_path = POLAR_PATH
                self.save_cfg_safe()
            # A questo punto self.polar_path == POLAR_PATH. Se per qualunque
            # motivo (file corrotto, parse fallito) il file esiste ma non
            # carica, lo riscriviamo da default e riproviamo.
            try:
                with open(POLAR_PATH, 'w') as f:
                    json.dump(default_polar(), f, indent=2)
                    f.flush()
                    try: os.fsync(f.fileno())
                    except: pass
                load_ok = self.polar.load(POLAR_PATH)
                if load_ok:
                    print(f'  polar.json riscritto con default e ricaricato')
            except Exception as e:
                print(f'  fallback polar ERROR: {type(e).__name__}: {e}')
        # CloudUploader: lo creo sempre, viene avviato solo se cloud_enabled=True.
        # Manda snapshot live (un POST ogni cloud_interval_s secondi) al backend
        # HTTPS, che a sua volta INSERT su SQL Server tabella 'traks' di
        # sailing-sql-7645.database.windows.net.
        self.cloud = CloudUploader(self)
        if self.cloud_enabled:
            self.cloud.start()
        # TrackLogger: scrittura locale CSV una riga ogni 5s. Avviato/fermato
        # manualmente dalla LoggingScreen.
        self.track_logger = TrackLogger(self)

    def _apply_config(self, c):
        """Applica un dict di configurazione agli attributi del DataManager.
        Usato sia da default_config che da _load_cfg (post-parse JSON).
        Esegue validazione di valori critici (frequenze ammesse)."""
        self.nmea_ip   = c.get('nmea_ip',   '192.168.4.1')
        self.nmea_port = c.get('nmea_port', 60001)
        self.polar_path = c.get('polar_path', POLAR_PATH)
        self.log_dir    = c.get('log_dir',    LOG_PATH)
        tw = c.get('twd_window_minutes', 5)
        self.twd_window_minutes = tw if tw in (2, 5, 10, 15, 20) else 5
        self.cloud_enabled      = bool(c.get('cloud_enabled', False))
        url_in_cfg = (c.get('cloud_url', '') or '').strip()
        self.cloud_url          = url_in_cfg if url_in_cfg else CLOUD_URL_DEFAULT
        # boat_id: default 'soar' se mancante o vuoto (era 'regolofarm-1')
        bid = (c.get('cloud_boat_id', '') or '').strip()
        self.cloud_boat_id      = bid if bid else BOAT_ID_DEFAULT
        self.cloud_token        = c.get('cloud_token',   '')
        # Intervallo upload in secondi. Migrazione automatica dal vecchio
        # 'cloud_interval_min' (minuti) se presente in config legacy.
        cs = c.get('cloud_interval_s')
        if cs is None:
            # Legacy: accetta cloud_interval_min e converti
            cm = c.get('cloud_interval_min')
            cs = (cm * 60) if cm else 60
        # Whitelist di valori UI: 30s, 1m, 2m, 5m, 10m
        try: cs = int(cs)
        except (TypeError, ValueError): cs = 60
        self.cloud_interval_s = cs if cs in (30, 60, 120, 300, 600) else 60
        # Base URL del servizio cloud (legacy, mantenuto per compat config).
        # Retrocompatibilita': accetta anche il vecchio nome
        # 'waypoints_api_base' usato in versioni precedenti.
        wb = (c.get('api_base', '') or
              c.get('waypoints_api_base', '') or '').strip()
        self.api_base = wb if wb else API_BASE_DEFAULT
        # === Azure Blob Storage ===
        bb = (c.get('blob_base', '') or '').strip().rstrip('/')
        self.blob_base = bb if bb else BLOB_BASE_DEFAULT
        # blob_account_key: chiave master dello storage account, usata per
        # firmare le richieste con Shared Key (HMAC-SHA256). Se vuota, le
        # operazioni cloud (upload/download tracks, upload polari/waypoints)
        # falliranno con "blob_account_key non configurata".
        self.blob_account_key = (c.get('blob_account_key', '') or '').strip()
        # === Backward-compat con config v1.7-1.9 (SAS token) ===
        # Se il config ha ancora i vecchi tracks_sas_token/polars/waypoints
        # li leggiamo per non rompere setup esistenti, ma il flusso primario
        # usa blob_account_key. Vengono ignorati nei nuovi flussi.
        self.tracks_sas_token    = (c.get('tracks_sas_token',    '') or '').strip()
        self.polars_sas_token    = (c.get('polars_sas_token',    '') or '').strip()
        self.waypoints_sas_token = (c.get('waypoints_sas_token', '') or '').strip()
        # Polare ON/OFF: default True per non rompere comportamento esistente
        # quando si aggiorna l'app su un config gia' salvato.
        self.polar_enabled = bool(c.get('polar_enabled', True))
        wpts = c.get('waypoints', [])
        if isinstance(wpts, list):
            self.waypoints = []
            for w in wpts:
                if not (isinstance(w, dict) and 'name' in w
                        and 'lat' in w and 'lon' in w):
                    continue
                # Normalizza side: accetta 'port'/'starboard' (default 'port')
                side = str(w.get('side', 'port')).lower()
                if side not in ('port', 'starboard'):
                    side = 'port'
                # coord_in accetta sia stringhe DM ("45°45.164'N") sia float
                # legacy in gradi decimali, per retrocompat con vecchi file.
                try:
                    lat_d = coord_in(w['lat'], is_lat=True)
                    lon_d = coord_in(w['lon'], is_lat=False)
                except ValueError as e:
                    print(f'_apply_config: waypoint {w.get("name")} scartato: {e}')
                    continue
                self.waypoints.append({
                    'name': str(w['name']),
                    'lat':  lat_d,
                    'lon':  lon_d,
                    'side': side,
                })
        else:
            self.waypoints = []
        self.target_mark = c.get('target_mark', None) or None

    def _load_cfg(self):
        """Carica config con strategia a tre livelli di fallback.

        Gerarchia (la prima fonte che risponde, vince):
          1) sailing_config.json LOCALE (DATA_DIR/sailing_config.json)
             -> caso normale, dopo il primo avvio.
          2) sailing_config.json CLOUD (blob storage container 'config')
             -> URL: {blob_base}/config/{boat_id}/sailing_config.json
             -> caso "factory provisioning": nuovo tablet al primo avvio
                scarica la sua config dal cloud automaticamente.
          3) default_config() hardcoded nel codice
             -> caso "primo avvio + niente cloud": l'app parte comunque
                con valori sensati.

        Dopo il caricamento da cloud o da default, il file viene SEMPRE
        scritto su disco in locale. Cosi':
          - i prossimi avvii usano direttamente il file locale (livello 1);
          - l'utente puo' editare il config sul tablet senza che venga
            sovrascritto da remoto.

        Se il file locale ESISTE ma proviene da una versione precedente
        dell'app che non aveva tutti i campi attuali, vengono aggiunti i
        nuovi campi con i default (migrazione automatica).
        """
        if not os.path.exists(self.config_path):
            # Primo avvio: niente file locale. Provo il cloud, poi default.
            #
            # Per il fetch cloud uso i valori CORRENTI di self.blob_base e
            # self.cloud_boat_id, che sono gia' stati popolati in __init__
            # da _apply_config(default_config()).
            print(f'_load_cfg: file locale assente ({self.config_path}), '
                  'tento fetch da cloud...')
            ok, cloud_cfg, err = fetch_remote_config(
                self.blob_base, self.cloud_boat_id, self.blob_account_key)
            if ok:
                try:
                    self._apply_config(cloud_cfg)
                    self.save_cfg()
                    print('_load_cfg: config CLOUD scaricato e salvato in '
                          f'{self.config_path}')
                except Exception as e:
                    log_err(f'_load_cfg cloud apply/save: {e}', exc=e)
                    print(f'_load_cfg: cloud OK ma apply/save ERROR: '
                          f'{type(e).__name__}: {e}')
                    try: self.save_cfg()
                    except Exception as e2:
                        log_err(f'_load_cfg fallback save: {e2}', exc=e2)
            else:
                print(f'_load_cfg: cloud non disponibile ({err}), '
                      'uso default hardcoded')
                try:
                    self.save_cfg()
                    print(f'Config creato con default in {self.config_path}')
                except Exception as e:
                    log_err(f'_load_cfg create-default: {e}', exc=e)
                    print(f'_load_cfg create-default ERROR: '
                          f'{type(e).__name__}: {e}')
            return
        try:
            with open(self.config_path) as f:
                c = json.load(f)
            self._apply_config(c)
            # Migrazione automatica: se il file in lettura non aveva tutti i
            # campi previsti dalla versione corrente di default_config(), li
            # aggiungiamo (con i default) riscrivendo il file. Questo accade
            # quando l'utente aggiorna l'app a una versione che introduce
            # nuovi campi (es. 'blob_account_key' aggiunto nella v1.10 per
            # autenticazione Shared Key).
            # NB: il valore di 'cloud_boat_id' NON viene rimpiazzato: se il
            # config aveva 'regolofarm-1', resta tale. Per usare 'soar' va
            # cambiato esplicitamente da Settings o nel file.
            expected_keys = set(default_config().keys())
            actual_keys   = set(c.keys()) if isinstance(c, dict) else set()
            missing = expected_keys - actual_keys
            has_legacy_name = 'waypoints_api_base' in actual_keys
            if missing or has_legacy_name:
                if missing:
                    print(f'Config: campi mancanti {sorted(missing)}, riscrivo con default')
                if has_legacy_name:
                    print('Config: rinomino "waypoints_api_base" in "api_base"')
                try:
                    self.save_cfg()
                except Exception as e:
                    log_err(f'_load_cfg migration: {e}', exc=e)
                    print(f'_load_cfg migration ERROR: {type(e).__name__}: {e}')
        except Exception as e:
            log_err(f'_load_cfg parse {self.config_path}: {e}', exc=e)
            print(f'_load_cfg ERROR ({self.config_path}): {type(e).__name__}: {e}')

    def _serialize_waypoints(self, wpts=None):
        """Converte la lista di waypoint da rappresentazione interna (lat/lon
        float in gradi decimali) a rappresentazione su disco (lat/lon stringhe
        in formato DM "45°45.164'N").

        E' la funzione chiamata DA OGNI scrittura su file: cosi' il formato
        del file e' coerente. La rappresentazione interna in memoria resta
        sempre float — convertiamo SOLO al momento di scrivere su disco.

        Se wpts e' None usa self.waypoints. I waypoint con coordinate non
        valide vengono saltati silenziosamente."""
        if wpts is None:
            wpts = self.waypoints
        out = []
        for w in wpts:
            try:
                lat_str = format_coord_dm(w.get('lat'), is_lat=True)
                lon_str = format_coord_dm(w.get('lon'), is_lat=False)
                if not lat_str or not lon_str:
                    continue
                out.append({
                    'name': str(w.get('name', '')),
                    'lat':  lat_str,
                    'lon':  lon_str,
                    'side': str(w.get('side', 'port')),
                })
            except Exception as e:
                print(f'_serialize_waypoints: scartato {w.get("name")}: {e}')
                continue
        return out

    def save_cfg(self):
        """Salva il config in modo atomico. Lancia eccezione in caso di errore
        (il chiamante puo' decidere se mostrare un popup all'utente)."""
        # Costruisci il payload. I waypoint vengono serializzati in formato
        # DM ("45°45.164'N") per coerenza con waypoints.json.
        payload = {'nmea_ip':            self.nmea_ip,
                   'nmea_port':          self.nmea_port,
                   'polar_path':         self.polar_path,
                   'log_dir':            self.log_dir,
                   'twd_window_minutes': self.twd_window_minutes,
                   'cloud_enabled':      self.cloud_enabled,
                   'cloud_url':          self.cloud_url,
                   'cloud_boat_id':      self.cloud_boat_id,
                   'cloud_token':        self.cloud_token,
                   'cloud_interval_s':   self.cloud_interval_s,
                   'api_base':           self.api_base,
                   'blob_base':          self.blob_base,
                   'blob_account_key':   self.blob_account_key,
                   'polar_enabled':      self.polar_enabled,
                   'waypoints':          self._serialize_waypoints(),
                   'target_mark':        self.target_mark}
        # Crea la directory parent se manca (DATA_DIR potrebbe essere stato
        # cancellato o non ancora creato in caso di path personalizzato)
        parent = os.path.dirname(self.config_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Scrittura atomica: scrivo in .tmp, poi rinomino (no file corrotto
        # se l'app crasha durante la scrittura)
        tmp_path = self.config_path + '.tmp'
        with open(tmp_path, 'w') as f:
            # ensure_ascii=False per scrivere il simbolo ° letterale nelle
            # coordinate dei waypoint (formato DM "45°45.164'N"), cosi' il
            # file e' leggibile e modificabile a mano.
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.flush()
            try: os.fsync(f.fileno())  # forza la scrittura su disco
            except: pass  # fsync puo' fallire su alcuni filesystem Android
        os.replace(tmp_path, self.config_path)

    # -------- Waypoints: file esterno waypoints.json --------
    #
    # I waypoint sono salvati in DUE posti:
    # 1) waypoints.json (file dedicato in DATA_DIR): formato pulito, importabile
    #    ed esportabile dall'utente. E' la fonte primaria al boot.
    # 2) sailing_config.json (campo 'waypoints'): mantenuto per retrocompatibilita'.
    #    Se waypoints.json esiste, viene letto e SOVRASCRIVE quanto in config.
    #    Se waypoints.json NON esiste, vengono usati quelli del config (se presenti).
    #
    # Ogni waypoint nel FILE ha la struttura:
    #   {"name": "Mark1", "lat": "45°45.164'N", "lon": "13°37.074'E", "side": "port"}
    # con lat/lon stringhe in formato gradi-minuti decimali.
    # In MEMORIA invece self.waypoints conserva lat/lon come float in gradi
    # decimali, perche' tutte le formule trigonometriche di calc_dist_brg /
    # laylines lavorano native su quei float. La conversione DM<->float
    # avviene solo ai bordi (load/save) tramite coord_in / format_coord_dm.
    # 'side' = 'port' (sx) | 'starboard' (dx): da che lato lasciare la boa.

    def _load_waypoints_json(self):
        """Se waypoints.json esiste in DATA_DIR, carica i waypoint da li' e
        sovrascrive self.waypoints. Se non esiste, lascia inalterato cio' che
        e' stato caricato dal config (gestione retrocompatibilita')."""
        if not os.path.exists(WAYPOINTS_PATH):
            return False
        try:
            with open(WAYPOINTS_PATH) as f:
                data = json.load(f)
            # Accetta sia un array diretto sia {"waypoints": [...]}
            if isinstance(data, dict):
                wpts = data.get('waypoints', [])
            elif isinstance(data, list):
                wpts = data
            else:
                wpts = []
            cleaned = []
            for w in wpts:
                if not (isinstance(w, dict) and 'name' in w
                        and 'lat' in w and 'lon' in w):
                    continue
                side = str(w.get('side', 'port')).lower()
                if side not in ('port', 'starboard'):
                    side = 'port'
                # coord_in accetta sia stringhe DM ("45°45.164'N") sia float
                # legacy. Cosi' file vecchi continuano a caricarsi.
                try:
                    cleaned.append({
                        'name': str(w['name']),
                        'lat':  coord_in(w['lat'], is_lat=True),
                        'lon':  coord_in(w['lon'], is_lat=False),
                        'side': side,
                    })
                except (TypeError, ValueError) as e:
                    print(f'_load_waypoints_json: scartato {w.get("name")}: {e}')
                    continue
            self.waypoints = cleaned
            print(f'Waypoints caricati da {WAYPOINTS_PATH}: {len(cleaned)} punti')
            return True
        except Exception as e:
            print(f'_load_waypoints_json ERROR: {type(e).__name__}: {e}')
            return False

    def download_waypoints_url(self):
        """URL completo da cui scaricare il file waypoints.json.

        Nuovo flusso (Azure Blob Storage diretto, container 'waypoints'):
            {blob_base}/waypoints/{cloud_boat_id}/waypoints.json
        Esempio:
            https://sailingapp.blob.core.windows.net/waypoints/soar/waypoints.json

        Il container deve avere "Anonymous read access for blobs" (no auth
        client-side per la lettura).

        Restituisce None se boat_id o blob_base non configurati."""
        if not self.cloud_boat_id:
            return None
        base = (self.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        return f'{base}/{BLOB_CONTAINER_WAYPOINTS}/{self.cloud_boat_id}/{WAYPOINTS_FILE}'

    def download_polar_url(self):
        """URL completo da cui scaricare il file polar.json.

        Nuovo flusso (Azure Blob Storage diretto, container 'polars'):
            {blob_base}/polars/{cloud_boat_id}/polar.json
        Esempio:
            https://sailingapp.blob.core.windows.net/polars/soar/polar.json

        Il container deve avere "Anonymous read access for blobs".
        Restituisce None se boat_id o blob_base non configurati."""
        if not self.cloud_boat_id:
            return None
        base = (self.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        return f'{base}/{BLOB_CONTAINER_POLARS}/{self.cloud_boat_id}/{POLAR_FILE}'

    def download_meteo_url(self):
        """URL completo da cui scaricare il file forecast.json delle previsioni
        meteo per la regata.

        Pattern: {blob_base}/meteo/{cloud_boat_id}/forecast.json
        Esempio:
            https://sailingapp.blob.core.windows.net/meteo/soar/forecast.json

        Il file viene generato dal backend (script periodico che chiama
        Open-Meteo) e contiene previsioni gia' pre-elaborate per i waypoint
        della barca. Il formato JSON e' descritto nella WeatherScreen.

        Restituisce None se boat_id o blob_base non configurati."""
        if not self.cloud_boat_id:
            return None
        base = (self.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        return f'{base}/{BLOB_CONTAINER_METEO}/{self.cloud_boat_id}/{METEO_FILE}'

    # Nota: track_blob_url(), track_upload_url() e tutto il flusso di upload
    # tracks CSV automatico via TrackUploader sono stati rimossi nella v1.17.
    # Resta il metodo upload_csv_to_blob() per upload one-shot manuale via
    # pulsante "Invia al cloud" della LoggingScreen (v1.18).

    def upload_csv_to_blob(self, csv_path, timeout=60):
        """Upload one-shot di un file CSV al blob storage.
        Pattern URL: {blob_base}/tracks/{cloud_boat_id}/{filename}
        Restituisce (ok, msg).

        Usa Shared Key auth. Sicuro perche' la firma HMAC-SHA256 e' calcolata
        sui contenuti, anche senza TLS verification l'integrita' e' garantita."""
        if not os.path.exists(csv_path):
            return False, f'File non trovato: {csv_path}'
        if not self.cloud_boat_id:
            return False, 'cloud_boat_id non configurato'
        account_key = (self.blob_account_key or '').strip()
        if not account_key:
            return False, 'blob_account_key non configurata'
        base = (self.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        account_name = _account_name_from_blob_base(base)
        if not account_name:
            return False, 'blob_base non valido'
        try:
            with open(csv_path, 'rb') as f:
                csv_data = f.read()
        except Exception as e:
            return False, f'lettura file: {type(e).__name__}: {e}'
        from urllib.parse import quote
        filename = os.path.basename(csv_path)
        safe = quote(filename, safe='._-')
        url = f'{base}/{BLOB_CONTAINER_TRACKS}/{self.cloud_boat_id}/{safe}'
        try:
            req = urllib.request.Request(
                url, data=csv_data, method='PUT',
                headers={'Content-Type': 'text/csv',
                         'x-ms-blob-type': 'BlockBlob'})
            azure_sign_request(req, account_name, account_key)
            with urlopen_with_ssl_fallback(req, timeout=timeout) as resp:
                if resp.status >= 300:
                    return False, f'HTTP {resp.status}'
            kb = len(csv_data) // 1024
            return True, f'Inviato: {filename} ({kb} KB)'
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode('utf-8', errors='replace')[:200]
            except Exception:
                body = ''
            return False, f'HTTP {e.code}: {body[:120]}'
        except urllib.error.URLError as e:
            return False, f'rete: {e.reason}'
        except socket.timeout:
            return False, f'timeout dopo {timeout}s'
        except Exception as e:
            return False, f'{type(e).__name__}: {e}'

    def _http_get_json(self, url, timeout=15):
        """Helper centrale per le GET HTTPS che restituiscono JSON.
        Restituisce (ok, data_or_msg). Cattura TUTTI gli errori comuni
        (rete, timeout, HTTP, JSON, encoding) e li trasforma in messaggi
        leggibili. Usato sia da download_waypoints sia da download_polar
        per evitare duplicazione.

        Auto-firma Shared Key: se l'URL punta al blob storage configurato
        (self.blob_base) E blob_account_key e' settata, aggiunge gli header
        Azure (x-ms-date, x-ms-version, Authorization). Altrimenti GET in
        chiaro (caso legacy api_base o container pubblici).

        SSL fallback automatico: per URL del blob storage, in caso di errore
        di verifica certificato (tipico su Android puro senza CA bundle),
        ritenta automaticamente con context unverified. Sicuro perche' le
        richieste blob sono firmate HMAC-SHA256 sui contenuti (Shared Key)."""
        try:
            req = urllib.request.Request(url, headers={
                'Accept': 'application/json',
                'User-Agent': 'regolofarm-soar/1.0',
            })
            # Se URL e' del blob storage configurato e abbiamo la chiave,
            # firma con Shared Key. Altrimenti procedi senza auth.
            blob_base = (self.blob_base or '').strip().rstrip('/')
            account_key = (self.blob_account_key or '').strip()
            if blob_base and account_key and url.startswith(blob_base):
                account_name = _account_name_from_blob_base(blob_base)
                if account_name:
                    try:
                        azure_sign_request(req, account_name, account_key)
                    except Exception as e:
                        # Firma fallita: probabile chiave malformata. Lascio
                        # andare la richiesta unsigned: se il container e'
                        # pubblico funziona comunque.
                        print(f'_http_get_json: firma Shared Key fallita: {e}')
            with urlopen_with_ssl_fallback(req, timeout=timeout) as resp:
                status = resp.getcode()
                if status != 200:
                    return (False, f'HTTP {status}')
                raw = resp.read()
        except urllib.error.HTTPError as e:
            return (False, f'HTTP {e.code}: {e.reason}')
        except urllib.error.URLError as e:
            return (False, f'rete: {e.reason}')
        except socket.timeout:
            return (False, f'timeout dopo {timeout}s')
        except Exception as e:
            return (False, f'{type(e).__name__}: {e}')
        try:
            data = json.loads(raw.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return (False, f'JSON invalido: {e}')
        return (True, data)

    def download_waypoints_from_web(self, timeout=15):
        """Scarica il file waypoints.json dal cloud e lo salva localmente
        (sovrascrive WAYPOINTS_PATH). Restituisce (ok, msg).

        Pipeline:
        1. Compone l'URL: {api_base}/{cloud_boat_id}/waypoints.json
        2. GET HTTPS via _http_get_json
        3. Valida che sia nel formato atteso ({"waypoints":[...]} o lista)
        4. Per ogni waypoint converte lat/lon con coord_in() (accetta sia DM
           sia float legacy) e ricostruisce la lista pulita
        5. Salva su disco con _format_waypoints_file (layout custom)
        6. Ricarica self.waypoints chiamando _load_waypoints_json()"""
        url = self.download_waypoints_url()
        if not url:
            return (False, 'cloud_boat_id non configurato')
        ok, data = self._http_get_json(url, timeout=timeout)
        if not ok:
            return (False, data)  # data qui e' il messaggio d'errore

        # Estrai la lista waypoint (accetta sia {"waypoints":[...]} sia [...])
        if isinstance(data, dict):
            wpts = data.get('waypoints', [])
        elif isinstance(data, list):
            wpts = data
        else:
            return (False, 'formato JSON inatteso')

        if not isinstance(wpts, list):
            return (False, 'campo "waypoints" non e una lista')

        # Valida e converte ogni waypoint. coord_in accetta sia DM sia float.
        cleaned = []
        for i, w in enumerate(wpts):
            if not (isinstance(w, dict) and 'name' in w
                    and 'lat' in w and 'lon' in w):
                continue
            side = str(w.get('side', 'port')).lower()
            if side not in ('port', 'starboard'):
                side = 'port'
            try:
                cleaned.append({
                    'name': str(w['name']),
                    'lat':  coord_in(w['lat'], is_lat=True),
                    'lon':  coord_in(w['lon'], is_lat=False),
                    'side': side,
                })
            except (TypeError, ValueError) as e:
                print(f'download_waypoints: scartato wpt {i}: {e}')
                continue

        if not cleaned:
            return (False, 'nessun waypoint valido nel file remoto')

        try:
            self._write_waypoints_file(cleaned)
        except Exception as e:
            return (False, f'errore salvataggio: {type(e).__name__}: {e}')

        self._load_waypoints_json()
        return (True, f'{len(cleaned)} waypoint scaricati')

    def download_polar_from_web(self, timeout=15):
        """Scarica il file polar.json dal cloud e lo salva localmente
        (sovrascrive self.polar_path). Restituisce (ok, msg).

        Pipeline:
        1. Compone URL: {api_base}/{cloud_boat_id}/polar.json
        2. GET HTTPS via _http_get_json
        3. Valida formato atteso: {"boat_name": "...", "polar": {tws: {twa: bsp}}}
        4. Salva il payload su self.polar_path in modo atomico (tmp + replace)
        5. Ricarica self.polar.load(self.polar_path) cosi' i calcoli polar-aware
           usano subito i nuovi valori senza aspettare un riavvio.
        6. Aggiorna self.polar_enabled = True (assumiamo che chi scarica voglia
           usare la polare; resta disattivabile dal toggle se serve)."""
        url = self.download_polar_url()
        if not url:
            return (False, 'cloud_boat_id non configurato')
        ok, data = self._http_get_json(url, timeout=timeout)
        if not ok:
            return (False, data)

        # Validazione formato: deve essere un dict con campi 'boat_name' e
        # 'polar'. Il campo 'polar' e' a sua volta un dict {tws: {twa: bsp}}.
        if not isinstance(data, dict):
            return (False, 'formato JSON inatteso (atteso oggetto)')
        polar_dict = data.get('polar')
        if not isinstance(polar_dict, dict) or not polar_dict:
            return (False, 'campo "polar" mancante o non oggetto')
        # Smoke check: almeno un valore convertibile a float per tws/twa/bsp
        try:
            any_tws = next(iter(polar_dict))
            any_twa_dict = polar_dict[any_tws]
            if not isinstance(any_twa_dict, dict) or not any_twa_dict:
                raise ValueError('curve TWA vuote')
            any_twa = next(iter(any_twa_dict))
            float(any_tws); float(any_twa); float(any_twa_dict[any_twa])
        except (StopIteration, TypeError, ValueError) as e:
            return (False, f'struttura polare invalida: {e}')

        # Salvataggio atomico su self.polar_path
        try:
            parent = os.path.dirname(self.polar_path)
            if parent: os.makedirs(parent, exist_ok=True)
            tmp = self.polar_path + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                try: os.fsync(f.fileno())
                except: pass
            os.replace(tmp, self.polar_path)
        except Exception as e:
            return (False, f'errore salvataggio: {type(e).__name__}: {e}')

        # Ricarica subito in memoria. Se il caricamento fallisce per qualche
        # ragione (improbabile, dato che abbiamo gia' validato), riportiamo
        # l'errore all'utente.
        if not self.polar.load(self.polar_path):
            return (False, 'file salvato ma load fallita')

        boat = self.polar.boat_name or '(senza nome)'
        n_tws = len(self.polar.get_tws_list())
        n_twa = len(self.polar.get_twa_list())
        sails_info = ''
        if self.polar.has_sails():
            n_def = len(self.polar.sail_definitions)
            sails_info = f' + crossover ({n_def} vele)'
        return (True, f'Polare "{boat}" scaricata ({n_tws} TWS x {n_twa} TWA){sails_info}')

    # Nota: i metodi upload_waypoints_to_cloud/upload_polar_to_cloud/_put_blob
    # sono stati rimossi nella v1.12 (pulsanti UI eliminati). Idem TrackLogger
    # e TrackUploader e relative funzioni sono stati rimossi nella v1.17
    # insieme alla schermata Logging.

    def save_waypoints_json(self):
        """Salva self.waypoints in waypoints.json (scrittura atomica).
        I waypoint vengono serializzati in formato DM ("45°45.164'N") con
        layout custom (vedi _format_waypoints_file: ogni campo su riga
        separata).
        Lancia eccezione su errore (chiamare via save_waypoints_safe per UI)."""
        wpts_dm = self._serialize_waypoints()
        parent = os.path.dirname(WAYPOINTS_PATH)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp_path = WAYPOINTS_PATH + '.tmp'
        with open(tmp_path, 'w') as f:
            f.write(_format_waypoints_file(wpts_dm))
            f.flush()
            try: os.fsync(f.fileno())
            except: pass
        os.replace(tmp_path, WAYPOINTS_PATH)

    def save_waypoints_safe(self):
        """Wrapper che salva sia waypoints.json sia il config (per coerenza)
        senza sollevare eccezioni: per le modifiche dalla UI."""
        try:
            self.save_waypoints_json()
        except Exception as e:
            print(f'save_waypoints_json ERROR: {type(e).__name__}: {e}')
        # Salva anche nel config per retrocompatibilita'
        self.save_cfg_safe()

    # -------- Operazioni atomiche FILE-FIRST sui waypoints --------
    #
    # Queste funzioni implementano il pattern "leggi-da-file -> modifica ->
    # scrivi-su-file -> ricarica-in-memoria". Cosi' la fonte di verita' e'
    # SEMPRE il file su disco, e self.waypoints (memoria) e' solo una cache
    # di lettura. Pensate per la WaypointsScreen.
    #
    # Vantaggi:
    #   - se due processi/thread modificano il file in parallelo, ogni
    #     operazione vede uno stato fresco
    #   - la UI non puo' "perdere" modifiche fatte fuori (editor manuale,
    #     sync esterno) tra una modifica e l'altra
    #   - la save e' atomica (write-tmp + os.replace) e gia' presente
    #
    # Svantaggi accettati:
    #   - leggera latenza I/O: trascurabile su pochi waypoint
    #   - una modifica fatta a self.waypoints senza chiamare questi metodi
    #     viene persa quando arriva il prossimo _load_waypoints_json. Di
    #     proposito: la UI deve passare di qui per persistere.

    def _read_waypoints_file(self):
        """Legge il file waypoints.json e restituisce la lista pulita.
        Se il file non esiste o e' rotto, restituisce []. Non tocca
        self.waypoints."""
        if not os.path.exists(WAYPOINTS_PATH):
            return []
        try:
            with open(WAYPOINTS_PATH) as f:
                data = json.load(f)
            if isinstance(data, dict):
                wpts = data.get('waypoints', [])
            elif isinstance(data, list):
                wpts = data
            else:
                wpts = []
            cleaned = []
            for w in wpts:
                if not (isinstance(w, dict) and 'name' in w
                        and 'lat' in w and 'lon' in w):
                    continue
                side = str(w.get('side', 'port')).lower()
                if side not in ('port', 'starboard'): side = 'port'
                try:
                    cleaned.append({'name': str(w['name']),
                                    'lat':  coord_in(w['lat'], is_lat=True),
                                    'lon':  coord_in(w['lon'], is_lat=False),
                                    'side': side})
                except (TypeError, ValueError):
                    continue
            return cleaned
        except Exception as e:
            print(f'_read_waypoints_file ERROR: {type(e).__name__}: {e}')
            return []

    def _write_waypoints_file(self, wpts):
        """Scrive `wpts` in waypoints.json in modo atomico (tmp + replace).
        I waypoint vengono serializzati in formato DM con layout custom
        (ogni campo su riga separata, vedi _format_waypoints_file).
        Solleva eccezione su errore (la UI deve gestirla)."""
        wpts_dm = self._serialize_waypoints(wpts)
        parent = os.path.dirname(WAYPOINTS_PATH)
        if parent: os.makedirs(parent, exist_ok=True)
        tmp = WAYPOINTS_PATH + '.tmp'
        with open(tmp, 'w') as f:
            f.write(_format_waypoints_file(wpts_dm))
            f.flush()
            try: os.fsync(f.fileno())
            except: pass
        os.replace(tmp, WAYPOINTS_PATH)

    def waypoint_add(self, name, lat, lon, side='port'):
        """Aggiunge un waypoint al file. Restituisce (ok, err_msg).
        Rifiuta se il nome e' gia' presente (dopo aver letto il file)."""
        wpts = self._read_waypoints_file()
        if any(w.get('name') == name for w in wpts):
            return False, f'Esiste gia un waypoint con nome "{name}"'
        wpts.append({'name': name, 'lat': lat, 'lon': lon, 'side': side})
        try:
            self._write_waypoints_file(wpts)
        except Exception as e:
            return False, f'Errore scrittura file: {e}'
        # Ricarica in memoria
        self._load_waypoints_json()
        return True, None

    def waypoint_update(self, old_name, new_name, lat, lon, side='port'):
        """Aggiorna un waypoint esistente identificato da old_name.
        Se cambia il nome, aggiorna anche target_mark se necessario.
        Restituisce (ok, err_msg)."""
        wpts = self._read_waypoints_file()
        # Cerca il waypoint da aggiornare
        idx = next((i for i, w in enumerate(wpts)
                    if w.get('name') == old_name), -1)
        if idx < 0:
            return False, f'Waypoint "{old_name}" non trovato sul file'
        # Verifica univocita' nome (se diverso da old_name)
        if new_name != old_name:
            if any(w.get('name') == new_name for w in wpts):
                return False, f'Esiste gia un waypoint con nome "{new_name}"'
        wpts[idx] = {'name': new_name, 'lat': lat, 'lon': lon, 'side': side}
        try:
            self._write_waypoints_file(wpts)
        except Exception as e:
            return False, f'Errore scrittura file: {e}'
        # Aggiorna boa attiva se ne aveva il nome vecchio
        if self.target_mark == old_name and new_name != old_name:
            self.target_mark = new_name
            self.save_cfg_safe()
        self._load_waypoints_json()
        return True, None

    def waypoint_delete(self, name):
        """Rimuove un waypoint dal file per nome.
        Se era la boa attiva, deseleziona target_mark.
        Restituisce (ok, err_msg)."""
        wpts = self._read_waypoints_file()
        new_wpts = [w for w in wpts if w.get('name') != name]
        if len(new_wpts) == len(wpts):
            return False, f'Waypoint "{name}" non trovato sul file'
        try:
            self._write_waypoints_file(new_wpts)
        except Exception as e:
            return False, f'Errore scrittura file: {e}'
        if self.target_mark == name:
            self.target_mark = None
            self.save_cfg_safe()
        self._load_waypoints_json()
        return True, None

    def cfg_diagnostics(self):
        """Restituisce un dict con info utili per debug del config."""
        info = {
            'config_path': self.config_path,
            'data_dir':    DATA_DIR,
        }
        try:
            info['data_dir_exists']   = os.path.isdir(DATA_DIR)
            info['data_dir_writable'] = os.access(DATA_DIR, os.W_OK) if info['data_dir_exists'] else False
            info['config_exists']     = os.path.isfile(self.config_path)
            if info['config_exists']:
                info['config_size'] = os.path.getsize(self.config_path)
        except Exception as e:
            info['diag_error'] = str(e)
        return info

    def save_cfg_safe(self):
        """Wrapper che non solleva eccezioni: per i chiamanti che modificano
        un setting al volo (toggle, frequenze) e non vogliono interrompere
        il flusso UI in caso di errore di scrittura."""
        try:
            self.save_cfg()
            return True
        except Exception as e:
            print(f'save_cfg_safe ERROR: {type(e).__name__}: {e}')
            return False

    # =========================================================================
    # ANALISI TATTICA: lato buono / vira
    # =========================================================================

    def get_twd_average(self, window_seconds=None):
        """Calcola TWD medio negli ultimi `window_seconds` secondi.
        Se window_seconds e' None usa self.twd_window_minutes * 60.
        Usa media circolare (vettoriale) per gestire correttamente il wrap a 360.
        Restituisce None se mancano dati sufficienti."""
        if window_seconds is None:
            window_seconds = self.twd_window_minutes * 60
        if len(self._twd_history) < 5:
            return None
        cutoff = time.time() - window_seconds
        # Filtra campioni recenti
        recent = [twd for ts, twd in self._twd_history if ts >= cutoff]
        if len(recent) < 5:
            return None
        # Media circolare via componenti cartesiane (no wrap issues a 0/360)
        sx = sum(math.sin(math.radians(d)) for d in recent)
        sy = sum(math.cos(math.radians(d)) for d in recent)
        if sx == 0 and sy == 0:
            return None
        avg = math.degrees(math.atan2(sx, sy)) % 360
        return avg

    def get_wind_shift(self, window_seconds=None):
        """Differenza tra TWD attuale e TWD medio recente.
        Positivo = vento ruotato in senso orario (destrorso)
        Negativo = vento ruotato in senso antiorario (sinistrorso)
        Range normalizzato a -180/+180.
        Restituisce None se manca lo storico."""
        if self.true_wind_angle is None:
            return None
        avg = self.get_twd_average(window_seconds)
        if avg is None:
            return None
        twd_now = (self.boat_heading + self.true_wind_angle) % 360
        diff = (twd_now - avg + 540) % 360 - 180  # normalizza a -180/+180
        return diff

    # =========================================================================
    # CALCOLI POLAR-AWARE
    # =========================================================================
    # Questi metodi fanno da "single source of truth" per tutti i calcoli che
    # dipendono dalla polare: layline angles, ETA con VMG, target speed.
    # Tutte le schermate (Navigation, LayLine) chiamano queste funzioni invece
    # di fare i calcoli localmente, cosi' la logica e' uniforme e basta
    # modificarla in un solo posto.

    def polar_active(self):
        """True se la polare e' caricata E abilitata dall'utente.

        Doppio gate: self.polar.loaded indica che il file e' stato letto con
        successo, self.polar_enabled e' il toggle ON/OFF della PolarScreen.
        Quando False (anche solo uno dei due), tutti i calcoli polar-aware
        tornano al comportamento "raw" (boat_speed/distanza diretta) e la
        UI mostra esplicitamente che la polare non e' attiva."""
        return self.polar.loaded and self.polar_enabled

    def target_speed_kn(self):
        """Restituisce la velocita' target (kn) attesa alle condizioni attuali.

        - Se la polare e' caricata e abbiamo TWS+TWA: ritorna get_bsp(TWS, TWA).
          Equivalente a self.target_bsp gia' calcolato in _parse(), ma esposto
          come metodo cosi' i chiamanti fanno una chiamata semantica invece di
          leggere un attributo.
        - Se la polare NON e' caricata o disabilitata dal toggle: ritorna None
          (i chiamanti devono gestire il caso mostrando un placeholder o avviso).
          Mai inventare un valore tipo boat_speed*1.1 che nasconde il problema."""
        if not self.polar_active():
            return None
        if self.true_wind_speed is None or self.true_wind_angle is None:
            return None
        return self.polar.get_bsp(self.true_wind_speed, self.true_wind_angle)

    def layline_target_twa(self, upwind=True):
        """Restituisce il TWA (in gradi, valore positivo) ottimale per VMG
        nelle condizioni attuali, letto dalla polare.

        - Bolina (upwind=True): tipicamente 38-45 gradi a seconda della barca.
          E' l'angolo da tenere per massimizzare la VMG verso il vento.
        - Poppa  (upwind=False): tipicamente 140-160 gradi.

        Restituisce None se la polare non e' caricata o se TWS non disponibile.

        Nota: questo TWA e' la stessa quantita' che _parse() salva in
        self.polar_twa_target quando in bolina. La differenza e' che qui
        possiamo chiederlo per entrambi i lati anche quando stiamo navigando
        a un'andatura diversa."""
        if not self.polar_active() or self.true_wind_speed is None:
            return None
        rv = self.polar.get_target_vmg(self.true_wind_speed, upwind=upwind)
        if rv is None:
            return None
        twa, _vmg = rv
        return float(twa)

    def laylines_to_mark(self):
        """Calcola le laylines geometriche verso la boa attiva, in BOLINA,
        usando il TWA target dalle polari.

        Concetto: in bolina la barca non puo' puntare direttamente sul vento;
        il TWA minimo utile e' ~40 gradi (dipende dalla polare). La layline
        e' il bearing che, se mantenuto a TWA target, conduce alla boa
        senza ulteriori virate.

        Restituisce un dict con:
            'twa_target':    TWA target in bolina (gradi, sempre positivo)
            'twd':           direzione vera del vento (gradi, 0..360)
            'cog_port':      rotta da tenere su mura sinistra (gradi, 0..360)
            'cog_starboard': rotta da tenere su mura dritta  (gradi, 0..360)
            'brg_to_mark':   bearing alla boa (gradi)
            'on_layline':    'port' | 'starboard' | None se non sei su nessuna
            'dist_along_port':  NM da percorrere su mura sx (proiezione su cog_port)
                                prima di poter virare e arrivare a boa di bolina
            'dist_along_starboard': idem per mura dx

        Restituisce None se manca la polare, TWS, o la boa attiva.

        Nota tecnica: la formula della distanza sul layline usa la legge dei
        seni nel triangolo formato da (posizione_attuale, punto_di_virata, boa).
        Se la barca e' gia' sul layline, una delle due distanze coincide con
        la distanza alla boa e l'altra e' zero.
        """
        if not self.polar_active():                return None
        if self.true_wind_speed is None:           return None
        if self.true_wind_angle is None:           return None
        if self.target_mark is None:               return None
        if self.distance_to_mark is None:          return None
        if self.bearing_to_mark is None:           return None

        twa_t = self.layline_target_twa(upwind=True)
        if twa_t is None or twa_t <= 0 or twa_t >= 90:
            return None

        # TWD = direzione DA cui spira il vento (true wind direction)
        # twd = (heading + TWA) % 360 con TWA signed
        twd = (self.boat_heading + self.true_wind_angle) % 360

        # Su mura SINISTRA (port tack) il vento arriva da sinistra: la barca
        # naviga con bearing = TWD + twa_target (tenendo il vento sui ~40 sx).
        # Su mura DRITTA (starboard) il vento arriva da dritta: bearing = TWD - twa_target.
        cog_port      = (twd + twa_t) % 360
        cog_starboard = (twd - twa_t) % 360

        brg = self.bearing_to_mark
        # Differenza tra bearing alla boa e ciascuna rotta di bolina
        # (normalizzata a -180/+180, valore assoluto = quanto siamo "fuori")
        def _ang_diff(a, b):
            return ((a - b + 540) % 360) - 180

        d_port_brg = _ang_diff(brg, cog_port)
        d_stbd_brg = _ang_diff(brg, cog_starboard)

        # On-layline: la rotta di bolina coincide (entro qualche grado) col
        # bearing alla boa. Se sono entro 3 gradi consideriamo "sul layline".
        on_lay = None
        if   abs(d_port_brg) < 3.0: on_lay = 'port'
        elif abs(d_stbd_brg) < 3.0: on_lay = 'starboard'

        # Distanza da percorrere su ciascuna mura prima del punto di virata.
        # Triangolo: A = posizione attuale, M = boa, T = punto di virata.
        # Angolo in A tra il bearing alla boa e la rotta di bolina = d_*_brg.
        # Angolo in T tra le due laylines = 2*twa_target (apertura del cono).
        # Per la legge dei seni: dist_along / sin(angle_at_M) = dist_AM / sin(angle_at_T)
        # angle_at_T = 180 - 2*twa_target (angolo interno al vertice di virata)
        # angle_at_A = |d_brg|
        # angle_at_M = 180 - angle_at_A - angle_at_T = 2*twa_target - |d_brg|
        # dist_along = dist_AM * sin(angle_at_M) / sin(angle_at_T)
        d_AM = self.distance_to_mark
        ang_T = math.radians(180 - 2*twa_t)
        sin_T = math.sin(ang_T)
        if abs(sin_T) < 1e-6:
            dist_port = dist_stbd = None
        else:
            ang_M_port = math.radians(max(0.0, 2*twa_t - abs(d_port_brg)))
            ang_M_stbd = math.radians(max(0.0, 2*twa_t - abs(d_stbd_brg)))
            dist_port = d_AM * math.sin(ang_M_port) / sin_T
            dist_stbd = d_AM * math.sin(ang_M_stbd) / sin_T

        return {
            'twa_target':           twa_t,
            'twd':                  twd,
            'cog_port':             cog_port,
            'cog_starboard':        cog_starboard,
            'brg_to_mark':          brg,
            'on_layline':           on_lay,
            'dist_along_port':      dist_port,
            'dist_along_starboard': dist_stbd,
        }

    def eta_polar_aware(self):
        """ETA in minuti verso la boa attiva, calcolato considerando la
        polare quando siamo in bolina o in poppa stretta.

        - Se NON c'e' boa attiva o GPS: None.
        - Se NON c'e' polare caricata: usa boat_speed e distanza diretta
          (fallback). Lo stesso calcolo che faceva il vecchio codice.
        - Se polare caricata E |TWA| < 50 (bolina): usa la VMG target dalla
          polare. La barca non puo' puntare direttamente alla boa, deve
          bordeggiare; l'ETA realistico e' distanza_diretta / VMG_target.
        - Altrimenti (lasco/poppa larga): usa la BSP target alla rotta
          attuale, che e' un proxy ragionevole del progresso reale.

        Restituisce minuti (int) o None."""
        if self.distance_to_mark is None:    return None
        if self.distance_to_mark <= 0:       return 0

        # Fallback: polare assente o disabilitata -> usa boat_speed se disponibile
        if not self.polar_active() or self.true_wind_speed is None:
            if self.boat_speed and self.boat_speed > 0.1:
                return int((self.distance_to_mark / self.boat_speed) * 60)
            return None

        twa = self.true_wind_angle
        if twa is None:
            return int((self.distance_to_mark / max(self.boat_speed, 0.1)) * 60)

        # Bolina: VMG target verso vento
        if abs(twa) < 50:
            rv = self.polar.get_target_vmg(self.true_wind_speed, upwind=True)
            if rv:
                _twa_t, vmg = rv
                if vmg and vmg > 0.1:
                    return int((self.distance_to_mark / vmg) * 60)
        # Poppa larga: VMG target sotto vento
        elif abs(twa) > 130:
            rv = self.polar.get_target_vmg(self.true_wind_speed, upwind=False)
            if rv:
                _twa_t, vmg = rv
                if vmg and vmg > 0.1:
                    return int((self.distance_to_mark / vmg) * 60)

        # Lasco / traverso: BSP target alla rotta attuale
        bsp_t = self.polar.get_bsp(self.true_wind_speed, twa)
        if bsp_t and bsp_t > 0.1:
            return int((self.distance_to_mark / bsp_t) * 60)
        # Ultimo fallback: boat_speed reale
        if self.boat_speed and self.boat_speed > 0.1:
            return int((self.distance_to_mark / self.boat_speed) * 60)
        return None

    def tactical_advice(self, layline_threshold_nm=0.05, shift_threshold_deg=5.0):
        """Restituisce un consiglio tattico per la prossima virata.

        Logica:
        - Solo in bolina (|TWA| <= 60). Altrimenti None.
        - Se siamo molto vicini al layline geometrico verso la boa (entro
          `layline_threshold_nm`): "VIRA" prioritario.
        - Altrimenti confronta TWD attuale con TWD medio:
            * Mura a sinistra (TWA<0): orario=header (vira), antiorario=lift (lato buono)
            * Mura a dritta  (TWA>0): orario=lift (lato buono), antiorario=header (vira)
        - Se shift |x| < threshold: "OK" (nessuna azione raccomandata)

        Restituisce: ('LATO BUONO'|'VIRA'|'OK'|'LAYLINE', shift_deg) o (None, None).
        """
        twa = self.true_wind_angle
        if twa is None:
            return (None, None)
        # Solo in bolina (TWA stretto): se si naviga in poppa il concetto non vale.
        if abs(twa) > 60:
            return (None, None)

        # Check layline: in bolina, il layline e' il punto da cui possiamo
        # raggiungere la boa navigando a TWA target (non a bearing diretto).
        # Se la polare e' caricata usiamo laylines_to_mark() che fa il calcolo
        # geometrico corretto basato sul TWA target. Se la polare manca,
        # fallback al vecchio criterio "bearing entro 8 gradi" (meno preciso
        # ma comunque utile per il warning).
        if (self.target_mark and self.distance_to_mark
                and self.bearing_to_mark is not None
                and self.distance_to_mark < 5.0):  # solo se boa entro 5 NM
            if self.polar_active() and self.true_wind_speed:
                lay = self.laylines_to_mark()
                if lay and lay['on_layline'] is not None:
                    # Stiamo navigando vicino al layline corretto: VIRA per
                    # arrivare alla boa di bolina.
                    return ('LAYLINE', None)
            else:
                # Fallback senza polare (assente o disabilitata): criterio
                # geometrico approssimato basato sul bearing diretto.
                brg_diff = abs((self.bearing_to_mark - self.boat_heading + 540) % 360 - 180)
                if brg_diff < 8.0:
                    return ('LAYLINE', None)

        shift = self.get_wind_shift()
        if shift is None:
            return ('OK', None)

        # Mura a sinistra: TWA negativo (vento da sinistra)
        # In questo caso uno shift negativo (TWD ruotato a sinistra) ci alza
        # (lift), uno positivo ci abbassa (header).
        # Mura a dritta: TWA positivo. Inverso.
        on_port = twa < 0  # mura a sinistra (port tack)
        if on_port:
            tactical_shift = -shift  # lift se shift negativo
        else:
            tactical_shift = shift   # lift se shift positivo

        if tactical_shift > shift_threshold_deg:
            return ('LATO BUONO', shift)
        elif tactical_shift < -shift_threshold_deg:
            return ('VIRA', shift)
        else:
            return ('OK', shift)

    # =========================================================================
    # SWITCH AUTOMATICO BOA TARGET: rileva quando la barca ha superato la boa
    # attiva e avanza al waypoint successivo nella lista.
    # =========================================================================

    def _next_target_after(self, current_name):
        """Restituisce il nome del waypoint successivo a `current_name` nella
        lista self.waypoints, o None se non esiste (ultimo waypoint).

        L'ordine d'avanzamento e' quello della lista: il primo waypoint dopo
        quello con `name == current_name` e' il successore. La barca segue
        i waypoint nell'ordine in cui appaiono in waypoints.json."""
        if not self.waypoints:
            return None
        names = [w.get('name') for w in self.waypoints]
        try:
            idx = names.index(current_name)
        except ValueError:
            return None
        if idx + 1 < len(names):
            return names[idx + 1]
        return None

    def _reset_mark_pass_state(self):
        """Resetta lo stato del rilevatore CPA. Va chiamato ogni volta che
        cambia target_mark (manualmente da UI o automaticamente dopo uno
        switch) cosi' il rilevamento riparte pulito sulla nuova boa."""
        self._mark_min_dist_nm = None
        self._mark_increasing_count = 0

    def advance_target_if_passed(self):
        """Verifica se la barca ha superato la boa attiva e in tal caso
        passa al waypoint successivo. Ritorna True se ha avanzato.

        Logica del rilevatore:
        1) Calcolo distanza corrente dalla boa
        2) Tengo traccia della distanza minima vista in questo passaggio
        3) Se distanza < MARK_PASS_RADIUS_NM E distanza > min_distanza
           registrata per MARK_PASS_TICKS_INCREASING tick consecutivi,
           significa che il CPA e' passato e ci stiamo allontanando -> switch.

        Edge cases gestiti:
        - GPS non disponibile o target non impostato: no-op
        - Cooldown: dopo uno switch aspetta MARK_PASS_COOLDOWN_S prima
          di poterne fare un altro
        - Auto-advance disabilitato: rispetta il flag
        - Ultimo waypoint: se non c'e' un successore, no-op (rimane sulla
          stessa boa)
        - Target invalido (nome non in lista): resetta target_mark a None"""
        if not self._auto_advance_enabled:
            return False
        if not self.target_mark:
            self._reset_mark_pass_state()
            return False
        if self.distance_to_mark is None or self.gps_lat is None:
            return False
        # Cooldown post-switch: evita rimbalzi
        now = time.time()
        if (now - self._last_auto_advance_ts) < MARK_PASS_COOLDOWN_S:
            return False

        d = self.distance_to_mark
        # Aggiorno la distanza minima vista
        if self._mark_min_dist_nm is None or d < self._mark_min_dist_nm:
            self._mark_min_dist_nm = d
            self._mark_increasing_count = 0  # eravamo in avvicinamento
            return False

        # Distanza in aumento rispetto al minimo: incremento il contatore
        # SOLO se siamo gia' stati abbastanza vicini (sotto la soglia).
        # Altrimenti l'allontanamento e' irrilevante (non siamo neanche
        # arrivati al CPA della boa).
        if self._mark_min_dist_nm > MARK_PASS_RADIUS_NM:
            return False

        # Siamo entrati nella sfera, ora la distanza e' in aumento
        self._mark_increasing_count += 1
        if self._mark_increasing_count < MARK_PASS_TICKS_INCREASING:
            return False

        # Trigger! Cerca il prossimo waypoint
        next_name = self._next_target_after(self.target_mark)
        if next_name is None:
            # Eravamo sull'ultimo: niente switch ma resetto comunque lo
            # stato cosi' se l'utente sceglie un altro target manualmente
            # ripartiamo puliti
            self._reset_mark_pass_state()
            return False

        prev_name = self.target_mark
        self.target_mark = next_name
        self._last_auto_advance_ts = now
        self._reset_mark_pass_state()
        # Persisto il nuovo target nel config (come fa _set_mark da UI)
        self.save_cfg_safe()
        print(f'Auto-advance target: {prev_name} -> {next_name} '
              f'(dist_min={self._mark_min_dist_nm} NM passata)')
        return True

    def connect(self,ip,port):
        if self.connected: return True
        try:
            self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.sock.settimeout(5); self.sock.connect((ip,int(port)))
            self.connected=True
            self.recv_thread=threading.Thread(target=self._recv,daemon=True)
            self.recv_thread.start(); return True
        except Exception as e: print(f'Conn:{e}'); self.connected=False; return False

    def disconnect(self):
        self.connected=False
        try:
            if self.sock: self.sock.close()
        except: pass
        self.sock=None

    def _recv(self):
        buf=''
        while self.connected:
            try:
                data=self.sock.recv(4096).decode('utf-8',errors='ignore')
                if not data: self.connected=False; break
                buf+=data
                while '\n' in buf:
                    line,buf=buf.split('\n',1); line=line.strip()
                    if line: self._parse(line)
            except socket.timeout: continue
            except Exception as e:
                if self.connected: print(f'Recv:{e}')
                break

    def _parse(self,raw):
        if not HAS_PYNMEA2: return
        try: msg=pynmea2.parse(raw)
        except: return
        def _f(a):
            v=getattr(msg,a,None)
            try: return float(v) if v else None
            except: return None
        with self._lock:
            if _f('latitude'):  self.gps_lat=_f('latitude')
            if _f('longitude'): self.gps_lon=_f('longitude')
            s=_f('spd_over_grnd')
            if s is not None: self.boat_speed=s
            c=_f('true_track')
            if c is not None: self.boat_course=c
            for a in ('heading','heading_magnetic','heading_true'):
                v=_f(a)
                if v is not None: self.boat_heading=v; break
            wa=_f('wind_angle'); ws=_f('wind_speed')
            if wa is not None and ws is not None:
                self.apparent_wind_angle=wa; self.apparent_wind_speed=ws
                if self.boat_speed>0.1:
                    res=calc_true_wind(wa,ws,self.boat_speed)
                    if res:
                        self.true_wind_angle,self.true_wind_speed=res
                        # Calcolo TWD assoluto e lo aggiungo allo storico
                        # TWD = (heading + TWA) mod 360
                        # TWA e' signed: negativo = vento da sinistra, positivo da dritta
                        twd = (self.boat_heading + self.true_wind_angle) % 360
                        self._twd_history.append((time.time(), twd))
                        if self.polar_active():
                            self.target_bsp=self.polar.get_bsp(
                                self.true_wind_speed,self.true_wind_angle)
                            up=abs(self.true_wind_angle)<90
                            rv=self.polar.get_target_vmg(self.true_wind_speed,up)
                            if rv: self.polar_twa_target,self.polar_vmg_target=rv
                        else:
                            # Polare disattivata o non caricata: azzera i
                            # valori derivati cosi' la UI mostra '--' invece
                            # di valori stantii dell'ultima volta che la
                            # polare era attiva.
                            self.target_bsp=None
                            self.polar_twa_target=None
                            self.polar_vmg_target=None
            dm_=_f('depth_meters')
            if dm_ is not None: self.depth=dm_
            if self.target_mark and self.gps_lat:
                wpt=next((w for w in self.waypoints
                          if w.get('name')==self.target_mark),None)
                if wpt:
                    d,b=calc_dist_brg(self.gps_lat,self.gps_lon,wpt['lat'],wpt['lon'])
                    self.distance_to_mark=d; self.bearing_to_mark=b
                    self.vmg=calc_vmg(self.boat_speed,self.boat_heading,b)
                    # Verifica auto-advance al prossimo waypoint. La chiamata
                    # e' qui perche' abbiamo appena aggiornato distance_to_mark
                    # con un dato fresco. Se la barca ha superato il CPA della
                    # boa attuale sotto la soglia di vicinanza, target_mark
                    # viene cambiato al prossimo waypoint.
                    self.advance_target_if_passed()

# =============================================================================
# WIDGET CONDIVISI
# =============================================================================

def _bg(widget,color):
    with widget.canvas.before:
        Color(*color)
        r=Rectangle(pos=widget.pos,size=widget.size)
    widget.bind(pos=lambda w,_:setattr(r,'pos',w.pos),
                size=lambda w,_:setattr(r,'size',w.size))

def mk_btn(text,cb,fs=None):
    """Pulsante standard: sfondo grigio leggibile su qualsiasi pannello.
    Prima usavamo PANEL come sfondo, ma su pannelli scuri (StartLine,
    Waypoints) i bottoni sparivano. Ora il default e' BTN_GRAY, cosi' il
    bottone e' sempre visibile."""
    b=Button(text=text,font_size=fs or sp(13),
              background_color=BTN_GRAY,background_normal='',
              background_down='',color=WHITE,bold=True)
    b.bind(on_release=lambda _:cb())
    return b

def mk_btn_gray(text,cb,fs=None):
    """Alias storico mantenuto per compatibilita': ora identico a mk_btn.
    In passato i due differivano (PANEL vs GRAY); abbiamo unificato sul
    grigio per leggibilita' uniforme."""
    return mk_btn(text, cb, fs)

class DataBox(BoxLayout):
    def __init__(self,label='',value='--',unit='',**kw):
        # size_hint_y=1 di default: si adatta all'altezza della row che lo contiene.
        kw.setdefault('size_hint_y', 1)
        super().__init__(orientation='vertical',padding=[dp(4),dp(3)],
                         spacing=dp(1),**kw)
        _bg(self,PANEL)
        self._l=Label(text=label,font_size=sp(18),color=MUTED,size_hint_y=0.22)
        self._v=Label(text=value,font_size=sp(54),bold=True,color=WHITE,size_hint_y=0.56)
        self._u=Label(text=unit, font_size=sp(18),color=MUTED,size_hint_y=0.22)
        for w in (self._l,self._v,self._u): self.add_widget(w)
    def set_value(self,v,color=None):
        self._v.text=str(v); self._v.color=color or WHITE

def row3(*b):
    # size_hint_y=1: la riga si scala all'altezza disponibile nel contenitore.
    r=BoxLayout(spacing=dp(5),size_hint_y=1)
    for w in b: r.add_widget(w)
    return r

def kv_row(parent,label,default='--',color=WHITE,big=False):
    if big:
        row=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(70))
        row.add_widget(Label(text=label,font_size=sp(30),color=MUTED,
                              size_hint_x=0.42,halign='right',valign='middle'))
        lbl=Label(text=default,font_size=sp(33),bold=True,color=color,valign='middle')
    else:
        row=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(46))
        row.add_widget(Label(text=label,font_size=sp(18),color=MUTED,
                              size_hint_x=0.42,halign='right',valign='middle'))
        lbl=Label(text=default,font_size=sp(20),bold=True,color=color,valign='middle')
    row.add_widget(lbl); parent.add_widget(row); return lbl

# =============================================================================
# SIDEBAR
# =============================================================================

class Sidebar(BoxLayout):
    # Etichette pulite, senza emoji o icone, ben leggibili
    ITEMS=[('Nav',       'navigation'),
           ('Start',     'start'),
           ('Lay',       'layline'),
           ('WPT',       'waypoints'),
           ('Polar',     'polar'),
           ('Log',       'logging'),
           ('Set',       'settings')]

    def __init__(self,sm,**kw):
        super().__init__(orientation='vertical',size_hint_x=None,
                         width=SIDEBAR_W,spacing=dp(2),padding=[dp(4),dp(8)],**kw)
        self.sm=sm; _bg(self,SIDEBAR)
        # Logo testuale, niente emoji
        logo=Label(text='Sailing\nRacing',font_size=sp(18),bold=True,
                    color=ACCENT,size_hint_y=None,height=dp(84),
                    halign='center',valign='middle')
        logo.bind(size=logo.setter('text_size'))
        self.add_widget(logo)
        self._btns={}
        for label,name in self.ITEMS:
            b=Button(text=label,font_size=sp(21),bold=True,
                      background_color=(0,0,0,0),background_normal='',
                      color=MUTED,size_hint_y=None,height=dp(77),
                      halign='center',valign='middle')
            b.bind(size=b.setter('text_size'))
            b.bind(on_release=lambda _,n=name:setattr(self.sm,'current',n))
            self.add_widget(b); self._btns[name]=b
        self.add_widget(Widget())
        self._conn=Label(text='Offline',font_size=sp(15),bold=True,color=RED,
                          size_hint_y=None,height=dp(35))
        self.add_widget(self._conn)

    def highlight(self,name):
        for n,b in self._btns.items():
            b.color=WHITE if n==name else MUTED
            b.background_color=PANEL if n==name else (0,0,0,0)

    def set_connected(self,ok):
        self._conn.text='Online' if ok else 'Offline'
        self._conn.color=GREEN   if ok else RED

# =============================================================================
# BASE SCREEN
# =============================================================================

class TabScreen(Screen):
    def __init__(self,dm,title='',**kw):
        # Ignoro 'scrollable' se passato per compatibilita' (non si scrolla mai piu')
        kw.pop('scrollable', None)
        super().__init__(**kw); self.dm=dm
        root=BoxLayout(orientation='vertical',spacing=0)
        self.add_widget(root); _bg(self,BG)
        tb=BoxLayout(size_hint_y=None,height=TITLE_H,padding=[dp(12),dp(6)])
        _bg(tb,PANEL)
        tb.add_widget(Label(text=title,font_size=sp(20),bold=True,color=WHITE))
        self._gps=Label(text='GPS --',font_size=sp(15),color=MUTED,
                         size_hint_x=None,width=dp(260),halign='right')
        tb.add_widget(self._gps)
        root.add_widget(tb)
        # Body sempre a tutto schermo, niente ScrollView
        self.body=BoxLayout(orientation='vertical',spacing=dp(8),
                             padding=dp(8),size_hint=(1,1))
        root.add_widget(self.body)
        Window.bind(size=self._on_win_resize)

    def _on_win_resize(self,win,size):
        Clock.schedule_once(self._do_resize,0)

    def _do_resize(self,dt): pass

    def on_enter(self):
        app=App.get_running_app()
        if hasattr(app,'sidebar'): app.sidebar.highlight(self.name)
        self.refresh()

    def _upd_gps(self):
        dm=self.dm
        if dm.gps_lat and dm.gps_lon:
            self._gps.text=f'{dm.gps_lat:.4f}  {dm.gps_lon:.4f}'
            self._gps.color=GREEN
        else:
            self._gps.text='GPS --'; self._gps.color=MUTED

    def refresh(self): pass
    def tick(self,dt): self._upd_gps()

# =============================================================================
# 1 -- NAVIGAZIONE
# =============================================================================

class CompassWidget(Widget):
    heading=NumericProperty(0); twa=NumericProperty(0)

    def __init__(self,**kw):
        super().__init__(**kw)
        self.bind(heading=self._req,twa=self._req,pos=self._req,size=self._req)

    def _req(self,*_): Clock.schedule_once(self._draw,0)

    def _draw(self,*_):
        # Guard anti-SIGSEGV: non disegnare se il widget non e' ancora attaccato
        # all'albero, se non ha dimensioni, o se Kivy sta chiudendo.
        try:
            if self.get_root_window() is None: return
            if self.width<dp(10) or self.height<dp(10): return
            self.canvas.clear()
        except Exception: return
        cx,cy=self.center; r=min(self.width,self.height)*0.44-dp(6)
        if r<dp(8): return
        with self.canvas:
            Color(0.04,0.10,0.20,1); Ellipse(pos=(cx-r,cy-r),size=(r*2,r*2))
            Color(*ACCENT); Line(circle=(cx,cy,r),width=dp(1.8))
            for deg in range(0,360,10):
                a=math.radians(deg-self.heading)
                r1=r-(dp(14) if deg%30==0 else dp(6))
                Color(*(WHITE if deg%90==0 else MUTED))
                Line(points=[cx+r1*math.sin(a),cy+r1*math.cos(a),
                              cx+r *math.sin(a),cy+r *math.cos(a)],
                     width=dp(1.5) if deg%30==0 else dp(0.8))
            an=math.radians(-self.heading); nr=r-dp(20)
            Color(*RED); Ellipse(pos=(cx+nr*math.sin(an)-dp(7),cy+nr*math.cos(an)-dp(7)),
                                  size=(dp(14),dp(14)))
            Color(*WHITE)
            Line(points=[cx,cy,cx,cy+r-dp(8)],width=dp(3))
            Triangle(points=[cx-dp(8),cy+r-dp(26),cx+dp(8),cy+r-dp(26),cx,cy+r-dp(8)])
            if self.twa:
                Color(*GREEN); a=math.radians(self.twa-90)
                Line(points=[cx,cy,cx+(r-dp(14))*math.cos(a),cy+(r-dp(14))*math.sin(a)],
                     width=dp(2.5))


class NavigationScreen(TabScreen):
    def __init__(self,dm,**kw):
        super().__init__(dm,'Nav  Navigazione',name='navigation',**kw)
        self._build()

    def _build(self):
        self.b_stw=DataBox('STW','--','kn')
        self.b_tgt=DataBox('TARGET','--','kn')
        self.b_vmg=DataBox('VMG','--','kn')
        # Top row: una row3 con size_hint_y=1 (prende ~22% dello spazio)
        top=row3(self.b_stw,self.b_tgt,self.b_vmg)
        self.body.add_widget(top)

        # _mid: prende il resto (size_hint_y=3 vs top=1, quindi 75%/25%)
        self._mid=BoxLayout(orientation='horizontal',spacing=dp(8),
                             size_hint_y=3.5)
        self.body.add_widget(self._mid)

        left=BoxLayout(orientation='vertical',spacing=dp(4),size_hint_x=0.45)
        self.compass=CompassWidget(size_hint=(1,1))
        left.add_widget(self.compass)
        # Riga inferiore: HDG a sinistra, advice tattico a destra
        hdg_row=BoxLayout(orientation='horizontal',spacing=dp(8),
                           size_hint_y=None,height=dp(85))
        self._hdg=Label(text='HDG 000',font_size=sp(45),bold=True,
                         color=WHITE,size_hint_x=0.55)
        self._tac=Label(text='—',font_size=sp(38),bold=True,
                         color=MUTED,size_hint_x=0.45,halign='center',valign='middle')
        self._tac.bind(size=self._tac.setter('text_size'))
        hdg_row.add_widget(self._hdg); hdg_row.add_widget(self._tac)
        left.add_widget(hdg_row)
        self._mid.add_widget(left)

        right=BoxLayout(orientation='vertical',spacing=dp(5),size_hint_x=0.55)
        self.b_tws=DataBox('TWS','--','kn')
        self.b_twa=DataBox('TWA','--','deg')
        self.b_dep=DataBox('DEPTH','--','m')
        right.add_widget(row3(self.b_tws,self.b_twa,self.b_dep))
        self.b_awa=DataBox('AWA','--','deg')
        self.b_aws=DataBox('AWS','--','kn')
        self.b_cog=DataBox('COG','--','deg')
        right.add_widget(row3(self.b_awa,self.b_aws,self.b_cog))
        self.b_brg=DataBox('BRG BOA','--','deg')
        self.b_dist=DataBox('DIST','--','NM')
        self.b_eta=DataBox('ETA','--','min')
        right.add_widget(row3(self.b_brg,self.b_dist,self.b_eta))
        self._polar_lbl=Label(text='Polare: non caricata',font_size=sp(20),
                               color=MUTED,size_hint_y=None,height=dp(40))
        right.add_widget(self._polar_lbl)
        self._mid.add_widget(right)

    def _do_resize(self,dt):
        # _mid usa size_hint=(1,1) quindi si adatta da solo. Solo il compass
        # va ridisegnato perche' il suo canvas e' immediate-mode.
        try: Clock.schedule_once(self.compass._draw,0)
        except: pass

    def tick(self,dt):
        super().tick(dt); dm=self.dm
        self.b_stw.set_value(f'{dm.boat_speed:.1f}')
        self.b_cog.set_value(f'{dm.boat_course:03.0f}')
        self._hdg.text=f'HDG  {dm.boat_heading:03.0f}'

        # Consiglio tattico: lato buono / vira
        advice, shift = dm.tactical_advice()
        if advice is None:
            self._tac.text='—'
            self._tac.color=MUTED
        elif advice == 'LATO BUONO':
            self._tac.text=f'LATO BUONO\n+{shift:.0f}°' if shift else 'LATO BUONO'
            self._tac.color=GREEN
        elif advice == 'VIRA':
            self._tac.text=f'VIRA\n{shift:+.0f}°' if shift else 'VIRA'
            self._tac.color=ORANGE
        elif advice == 'LAYLINE':
            self._tac.text='VIRA\n(layline)'
            self._tac.color=YELLOW
        else:  # 'OK'
            self._tac.text=f'OK\n{shift:+.0f}°' if shift else 'OK'
            self._tac.color=WHITE
        if dm.polar_active() and dm.target_bsp is not None:
            pct=dm.boat_speed/dm.target_bsp*100
            col=GREEN if pct>=95 else ORANGE
            self.b_tgt.set_value(f'{dm.target_bsp:.1f}',col)
            # Vela suggerita dal crossover (se polare v2 con sezione 'sails').
            # Append non invasivo: niente cambia se la polare e' v1.
            sail_id = None
            if (dm.polar.has_sails() and dm.true_wind_speed
                    and dm.true_wind_angle is not None):
                sail_id = dm.polar.get_sail(dm.true_wind_speed,
                                              dm.true_wind_angle)
            sail_str = f'  [{sail_id}]' if sail_id else ''
            self._polar_lbl.text=(f'{dm.polar.boat_name}  '
                                   f'{dm.target_bsp:.1f}kn  ({pct:.0f}%)'
                                   f'{sail_str}')
            self._polar_lbl.color=col
        else:
            # 3 casi distinti per la label di stato:
            # 1. polare non caricata        -> "NON CARICATA" (rosso)
            # 2. polare caricata ma toggle OFF -> "DISATTIVATA" (arancio)
            # 3. polare ATTIVA ma manca dato vento NMEA -> "Attesa vento NMEA" (grigio)
            # Senza il caso 3 distinto, l'app diceva DISATTIVATA anche con la
            # polare ON ogni volta che il router NMEA non spediva True Wind,
            # confondendo l'utente.
            self.b_tgt.set_value('--', RED)
            if not dm.polar.loaded:
                self._polar_lbl.text='Polare: NON CARICATA - target N/D'
                self._polar_lbl.color=RED
            elif not dm.polar_enabled:
                self._polar_lbl.text='Polare: DISATTIVATA - target N/D'
                self._polar_lbl.color=ORANGE
            else:
                # Polare attiva ma niente target_bsp -> in attesa di TWS/TWA
                # validi dall'NMEA. Mostro nome barca per confermare che la
                # polare e' caricata e attiva.
                boat = dm.polar.boat_name or '(senza nome)'
                self._polar_lbl.text=(f'{boat}  ATTIVA  -- '
                                       f'attesa vento NMEA')
                self._polar_lbl.color=MUTED
        if dm.vmg is not None:
            self.b_vmg.set_value(f'{dm.vmg:.1f}',GREEN if dm.vmg>0 else RED)
        if dm.true_wind_speed:     self.b_tws.set_value(f'{dm.true_wind_speed:.1f}')
        if dm.true_wind_angle:     self.b_twa.set_value(f'{dm.true_wind_angle:.0f}')
        if dm.apparent_wind_angle: self.b_awa.set_value(f'{dm.apparent_wind_angle:.0f}')
        if dm.apparent_wind_speed: self.b_aws.set_value(f'{dm.apparent_wind_speed:.1f}')
        if dm.depth>0: self.b_dep.set_value(f'{dm.depth:.1f}',RED if dm.depth<3 else GREEN)
        if dm.bearing_to_mark:  self.b_brg.set_value(f'{dm.bearing_to_mark:.0f}')
        if dm.distance_to_mark:
            self.b_dist.set_value(f'{dm.distance_to_mark:.2f}')
            # ETA polar-aware: in bolina considera la VMG target dalla polare
            # (la barca deve bordeggiare e percorre piu' strada di quella
            # diretta). Se polare assente, fallback su distanza/boat_speed.
            eta_min = dm.eta_polar_aware()
            if eta_min is not None:
                self.b_eta.set_value(f'{eta_min}')
        self.compass.heading=dm.boat_heading; self.compass.twa=dm.true_wind_angle or 0
        # Nota: setter di heading/twa triggerano gia' _req tramite il bind,
        # non serve un secondo schedule_once che potrebbe causare race condition.

# =============================================================================
# 2 -- PARTENZA
# =============================================================================

class StartLineScreen(TabScreen):
    def __init__(self,dm,**kw):
        super().__init__(dm,'Start  Partenza',name='start',**kw)
        self._secs=300; self._run=False; self._t0=None; self._pin=self._rc=None
        self._build()

    def _build(self):
        self._cols=BoxLayout(orientation='horizontal',spacing=dp(8),
                              size_hint=(1,1))
        self.body.add_widget(self._cols)

        left=BoxLayout(orientation='vertical',spacing=dp(8),
                        padding=dp(10),size_hint_x=0.42)
        _bg(left,PANEL)
        left.add_widget(Label(text='CONTO ALLA ROVESCIA',font_size=sp(28),
                               color=ACCENT,bold=True,size_hint_y=None,height=dp(55)))
        self._t=Label(text='5:00',font_size=sp(145),bold=True,color=GREEN,
                       size_hint_y=None,height=dp(195))
        left.add_widget(self._t)
        br=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(80))
        for txt,fn in [('START',self._start),('STOP',self._stop),('RESET',self._reset)]:
            br.add_widget(mk_btn(txt,fn,sp(20)))
        left.add_widget(br)
        prev=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(70))
        for m in (1,3,5,10):
            s=m*60; prev.add_widget(mk_btn(f'{m}m',lambda s=s:self._set(s),sp(20)))
        left.add_widget(prev)
        # NOTA: il blocco "log + invia al cloud" e' stato rimosso nella v1.17
        # insieme alla schermata Logging. Il tablet non scrive piu' tracks CSV
        # ne' fa upload al cloud. Per registrare i log delle uscite usa il
        # plotter di bordo o un'altra app dedicata.
        left.add_widget(Widget())
        self._cols.add_widget(left)

        right=BoxLayout(orientation='vertical',spacing=dp(8),
                         padding=dp(10),size_hint_x=0.58)
        _bg(right,PANEL)
        right.add_widget(Label(text='LINEA DI PARTENZA',font_size=sp(28),
                                color=ACCENT,bold=True,size_hint_y=None,height=dp(55)))
        self._pin_lbl=Label(text='Pin (SX): non impostato',font_size=sp(33),
                             color=WHITE,size_hint_y=None,height=dp(70))
        self._rc_lbl=Label(text='RC  (DX): non impostato',font_size=sp(33),
                             color=WHITE,size_hint_y=None,height=dp(70))
        right.add_widget(self._pin_lbl); right.add_widget(self._rc_lbl)
        br2=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(80))
        br2.add_widget(mk_btn('Segna PIN',self._set_pin,sp(20)))
        br2.add_widget(mk_btn('Segna RC', self._set_rc, sp(20)))
        right.add_widget(br2)
        self._line_lbl=Label(text='Lung: --   Brg: --',font_size=sp(30),
                              color=MUTED,size_hint_y=None,height=dp(60))
        self._dist_lbl=Label(text='Distanza: --  m',font_size=sp(65),bold=True,
                              color=YELLOW,size_hint_y=None,height=dp(105))
        right.add_widget(self._line_lbl); right.add_widget(self._dist_lbl)
        right.add_widget(Widget())
        self._cols.add_widget(right)

    def _do_resize(self,dt): pass  # _cols ora e' size_hint=(1,1), si auto-adatta

    def _set(self,s): self._secs=s; self._disp()
    def _start(self):
        if self._run: return
        self._run=True; self._t0=time.time()
        Clock.schedule_interval(self._tick_t,0.25)
    def _stop(self): self._run=False; Clock.unschedule(self._tick_t)
    def _reset(self): self._stop(); self._secs=300; self._disp()
    def _disp(self):
        m,s=divmod(self._secs,60); self._t.text=f'{m}:{s:02d}'; self._t.color=GREEN
    def _tick_t(self,dt):
        if not self._run: return False
        rem=self._secs-(time.time()-self._t0)
        if rem<=0: self._t.text='0:00'; self._t.color=RED; self._run=False; return False
        m,s=int(rem//60),int(rem%60)
        self._t.text=f'{m}:{s:02d}'; self._t.color=RED if rem<60 else GREEN; return True
    def _set_pin(self):
        """Memorizza la posizione GPS corrente come pin di sinistra (boa di
        partenza). Ogni pressione di 'Segna PIN' SOVRASCRIVE il valore
        precedente con la posizione GPS attuale: non c'e' alcun accumulo
        ne' storico, e' un override puro.

        Pin e RC sono volatili: vivono solo in memoria nell'istanza dello
        screen e NON vengono salvati su file. Al riavvio dell'app la linea
        di partenza va ri-impostata. Intenzionale: la linea cambia ad ogni
        regata e non avrebbe senso persistirla."""
        dm = self.dm
        if dm.gps_lat is None or dm.gps_lon is None:
            self._pin_lbl.text = 'Pin (SX): GPS NON DISPONIBILE'
            self._pin_lbl.color = RED
            return
        # Sovrascrittura esplicita: il valore vecchio (se c'era) viene perso.
        had_previous = self._pin is not None
        self._pin = (dm.gps_lat, dm.gps_lon)
        prefix = 'Pin (SX) [aggiornato]:' if had_previous else 'Pin (SX):'
        self._pin_lbl.text = f'{prefix} {dm.gps_lat:.5f}  {dm.gps_lon:.5f}'
        self._pin_lbl.color = GREEN
        self._upd_line()

    def _set_rc(self):
        """Memorizza la posizione GPS corrente come committee boat (boa di
        destra). Come 'Segna PIN', ogni pressione SOVRASCRIVE il valore
        precedente. Vedi _set_pin per la nota sulla volatilita'."""
        dm = self.dm
        if dm.gps_lat is None or dm.gps_lon is None:
            self._rc_lbl.text = 'RC  (DX): GPS NON DISPONIBILE'
            self._rc_lbl.color = RED
            return
        had_previous = self._rc is not None
        self._rc = (dm.gps_lat, dm.gps_lon)
        prefix = 'RC  (DX) [aggiornato]:' if had_previous else 'RC  (DX):'
        self._rc_lbl.text = f'{prefix} {dm.gps_lat:.5f}  {dm.gps_lon:.5f}'
        self._rc_lbl.color = GREEN
        self._upd_line()
    def _upd_line(self):
        if self._pin and self._rc:
            d,b=calc_dist_brg(self._pin[0],self._pin[1],self._rc[0],self._rc[1])
            if d: self._line_lbl.text=f'Lung: {d*1852:.0f}m   Brg: {b:.1f}'

    def tick(self,dt):
        super().tick(dt); dm=self.dm
        if self._pin and dm.gps_lat:
            d,_=calc_dist_brg(dm.gps_lat,dm.gps_lon,self._pin[0],self._pin[1])
            if d is not None: self._dist_lbl.text=f'Distanza: {d*1852:.0f}  m'

# =============================================================================
# 3 -- LAYLINE
# =============================================================================

class TacticalCanvas(Widget):
    def __init__(self,dm,**kw):
        super().__init__(**kw); self.dm=dm
        self.bind(pos=self._req,size=self._req)

    def _req(self,*_): Clock.schedule_once(lambda dt:self.redraw(),0)

    def redraw(self,*_):
        try:
            if self.get_root_window() is None: return
            if self.width<dp(10) or self.height<dp(10): return
            self.canvas.clear()
        except Exception: return
        dm=self.dm; cx,cy=self.center; r=min(self.width,self.height)*0.43
        if r<dp(8): return
        with self.canvas:
            Color(0.03,0.07,0.14,1); Ellipse(pos=(cx-r,cy-r),size=(r*2,r*2))
            Color(*ACCENT); Line(circle=(cx,cy,r),width=dp(1.5))
            for frac in (0.33,0.66):
                Color(*MUTED[:3],0.2); rr=r*frac; Line(circle=(cx,cy,rr),width=dp(0.7))
            Color(*WHITE)
            Triangle(points=[cx,cy+dp(20),cx-dp(8),cy-dp(13),cx+dp(8),cy-dp(13)])
            if dm.true_wind_angle:
                Color(*GREEN); a=math.radians(dm.true_wind_angle-90)
                Line(points=[cx,cy,cx+r*0.72*math.cos(a),cy+r*0.72*math.sin(a)],width=dp(2))
            if dm.bearing_to_mark and dm.distance_to_mark:
                scale=min(r*0.85,dp(180))
                a=math.radians(dm.bearing_to_mark-dm.boat_heading-90)
                mx=cx+scale*math.cos(a); my=cy+scale*math.sin(a)
                Color(*ORANGE); Ellipse(pos=(mx-dp(11),my-dp(11)),size=(dp(22),dp(22)))
                Color(*ORANGE[:3],0.4); Line(points=[cx,cy,mx,my],width=dp(1))
            if dm.true_wind_angle:
                for side,col in ((-1,GREEN),(1,ACCENT)):
                    a=math.radians(dm.true_wind_angle*side-90)
                    Color(*col[:3],0.5)
                    Line(points=[cx,cy,cx+r*0.88*math.cos(a),cy+r*0.88*math.sin(a)],
                         width=dp(1.5))


class LayLineScreen(TabScreen):
    def __init__(self,dm,**kw):
        super().__init__(dm,'Lay  LayLine',name='layline',**kw)
        self._build()

    def _build(self):
        self._cols=BoxLayout(orientation='horizontal',spacing=dp(8),
                              size_hint=(1,1))
        self.body.add_widget(self._cols)

        # Colonna sinistra: radar tattico SOPRA + consiglio tattico SOTTO
        left=BoxLayout(orientation='vertical',spacing=dp(6),size_hint_x=0.55)
        self.tact=TacticalCanvas(dm=self.dm,size_hint=(1,1))
        left.add_widget(self.tact)
        # Label tattica grossa sotto il radar
        self._tac=Label(text='—',font_size=sp(46),bold=True,color=MUTED,
                         size_hint_y=None,height=dp(120),
                         halign='center',valign='middle')
        self._tac.bind(size=self._tac.setter('text_size'))
        _bg(self._tac, PANEL)
        left.add_widget(self._tac)
        self._cols.add_widget(left)

        right=BoxLayout(orientation='vertical',spacing=dp(5),
                         padding=dp(10),size_hint_x=0.45)
        _bg(right,PANEL)
        right.add_widget(Label(text='BOA e ROTTA',font_size=sp(28),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(55)))
        self._r={}
        for k,c in [('Boa',WHITE),('Bearing',WHITE),('Distanza',WHITE),
                    ('VMG',GREEN),('TWA',ACCENT),('TWS',ACCENT),('ETA',YELLOW)]:
            self._r[k]=kv_row(right,k+':',color=c,big=True)
        right.add_widget(Label(text='LAYLINES (rotta - distanza)',
                                font_size=sp(20),color=MUTED,
                                size_hint_y=None,height=dp(35)))
        self._rp=kv_row(right,'Port:',color=GREEN,big=True)
        self._rs=kv_row(right,'Stbd:',color=ACCENT,big=True)
        right.add_widget(Widget())
        self._cols.add_widget(right)

    def _do_resize(self,dt):
        try: Clock.schedule_once(lambda dt:self.tact.redraw(),0)
        except: pass

    def tick(self,dt):
        super().tick(dt); dm=self.dm
        self._r['Boa'].text     =dm.target_mark or '--'
        self._r['Bearing'].text =f'{dm.bearing_to_mark:.0f}'    if dm.bearing_to_mark  else '--'
        self._r['Distanza'].text=f'{dm.distance_to_mark:.3f}NM' if dm.distance_to_mark else '--'
        self._r['VMG'].text     =f'{dm.vmg:.2f}kn'              if dm.vmg              else '--'
        self._r['TWA'].text     =f'{dm.true_wind_angle:.1f}'    if dm.true_wind_angle  else '--'
        self._r['TWS'].text     =f'{dm.true_wind_speed:.1f}kn'  if dm.true_wind_speed  else '--'

        # ETA polar-aware (gestisce internamente bolina/poppa/lasco e fallback
        # a boat_speed se la polare manca)
        eta_min = dm.eta_polar_aware()
        self._r['ETA'].text = f'{eta_min}m' if eta_min is not None else '--'

        # LAYLINES REALI: usano il TWA target dalla polare per calcolare
        #   - cog_port      = rotta da tenere su mura sinistra
        #   - cog_starboard = rotta da tenere su mura dritta
        #   - dist_along_*  = NM da percorrere su quella mura prima di virare
        # Se la polare manca o non c'e' boa attiva, mostriamo '--'.
        lay = dm.laylines_to_mark() if dm.target_mark else None
        if lay:
            dp_ = lay['dist_along_port']
            ds_ = lay['dist_along_starboard']
            on  = lay['on_layline']
            mark_p = ' *' if on == 'port'      else ''
            mark_s = ' *' if on == 'starboard' else ''
            self._rp.text = (f"{lay['cog_port']:03.0f}  "
                             f"{dp_:.2f}NM{mark_p}" if dp_ is not None
                             else f"{lay['cog_port']:03.0f}  --")
            self._rs.text = (f"{lay['cog_starboard']:03.0f}  "
                             f"{ds_:.2f}NM{mark_s}" if ds_ is not None
                             else f"{lay['cog_starboard']:03.0f}  --")
        else:
            # Senza polare o senza boa non possiamo calcolare le laylines vere.
            # Mostriamo '--' invece di un ETA ingannevole.
            self._rp.text = '--'
            self._rs.text = '--'

        # Consiglio tattico (stessa logica della schermata Navigation)
        advice, shift = dm.tactical_advice()
        if advice is None:
            self._tac.text='—'
            self._tac.color=MUTED
        elif advice == 'LATO BUONO':
            self._tac.text=f'LATO BUONO  +{shift:.0f}°' if shift else 'LATO BUONO'
            self._tac.color=GREEN
        elif advice == 'VIRA':
            self._tac.text=f'VIRA  {shift:+.0f}°' if shift else 'VIRA'
            self._tac.color=ORANGE
        elif advice == 'LAYLINE':
            self._tac.text='VIRA (layline)'
            self._tac.color=YELLOW
        else:  # 'OK'
            self._tac.text=f'OK  {shift:+.0f}°' if shift else 'OK'
            self._tac.color=WHITE

        Clock.schedule_once(lambda dt:self.tact.redraw(),0)

# =============================================================================
# 4 -- WAYPOINTS
# =============================================================================

class WaypointMapWidget(Widget):
    """Mini-mappa per la schermata WPT: disegna i waypoint nell'ordine in cui
    sono in self.dm.waypoints, li collega con linee (rotta), evidenzia la boa
    attiva (target_mark) in giallo e mostra la posizione barca (pallino verde)
    se il GPS e' fissato.

    Proiezione: equirettangolare semplice — corretta per longitudine con
    cos(lat_centro). Sufficiente per campi di regata di pochi NM, dove non
    serve la complessita' di una proiezione conica/Mercatore.

    Implementazione: tutto il rendering avviene su self.canvas (Color/Line/
    Ellipse/Rectangle con texture per il testo). NON usiamo Label child:
    aggiungere child con pos= assolute dentro un BoxLayout parent porta a
    instabilita' (il parent layout li riposiziona, e una clear_widgets()
    durante un draw scatena eventi on_size/on_pos ricorsivi che possono
    causare crash).
    """

    def __init__(self, dm, **kw):
        super().__init__(**kw)
        self.dm = dm
        # Cache delle CoreLabel: ricreare la texture ad ogni redraw e' costoso
        # per le label che non cambiano (es. nomi waypoint). La cache e'
        # invalidata quando cambia il testo o il colore.
        self._lbl_cache = {}  # key -> (CoreLabel, texture)
        self.bind(pos=self._req, size=self._req)

    def _req(self, *_):
        Clock.schedule_once(lambda dt: self.redraw(), 0)

    def _label_texture(self, text, font_size_sp, color, bold=False):
        """Restituisce (texture, w, h) per un dato testo. Usa una cache per
        riutilizzare le CoreLabel quando il testo non cambia."""
        from kivy.core.text import Label as CoreLabel
        key = (text, int(font_size_sp), tuple(color), bold)
        cached = self._lbl_cache.get(key)
        if cached is not None:
            return cached
        cl = CoreLabel(text=text, font_size=sp(font_size_sp),
                       color=color, bold=bold)
        cl.refresh()
        tex = cl.texture
        if tex is None:
            return None
        result = (tex, tex.width, tex.height)
        # Cache size guard: 200 entries massimo per evitare memory leak
        if len(self._lbl_cache) > 200:
            self._lbl_cache.clear()
        self._lbl_cache[key] = result
        return result

    def _draw_text(self, text, x, y, font_size_sp=12, color=WHITE, bold=False):
        """Disegna `text` sul canvas a partire da (x, y) (angolo basso-sinistra
        della texture). Va chiamato DENTRO un `with self.canvas:` block."""
        result = self._label_texture(text, font_size_sp, color, bold)
        if result is None:
            return
        tex, w, h = result
        # Color(1,1,1,1) prima del Rectangle: la texture ha gia' i colori,
        # noi serviamo solo come "pennello bianco" che non altera la texture.
        Color(1, 1, 1, 1)
        Rectangle(texture=tex, pos=(x, y), size=(w, h))

    def redraw(self, *_):
        # Guard standard: non disegnare se non attaccato/dimensionato
        try:
            if self.get_root_window() is None: return
            if self.width < dp(10) or self.height < dp(10): return
            self.canvas.clear()
        except Exception:
            return

        # Sfondo + bordo
        with self.canvas:
            Color(0.03, 0.07, 0.14, 1)
            Rectangle(pos=self.pos, size=self.size)
            Color(*ACCENT[:3], 0.6)
            Line(rectangle=(self.x, self.y, self.width, self.height),
                 width=dp(1))

        wpts = list(self.dm.waypoints) if self.dm.waypoints else []
        boat_lat, boat_lon = self.dm.gps_lat, self.dm.gps_lon

        # Bounding box su tutti i punti rilevanti (waypoint + barca)
        pts = [(w['lat'], w['lon']) for w in wpts
               if 'lat' in w and 'lon' in w]
        if boat_lat is not None and boat_lon is not None:
            pts.append((boat_lat, boat_lon))

        if not pts:
            with self.canvas:
                self._draw_text('Nessun waypoint',
                                self.x + self.width/2 - dp(60),
                                self.y + self.height/2 - dp(8),
                                font_size_sp=14, color=MUTED)
            return

        if len(pts) == 1:
            lat0, lon0 = pts[0]
            min_lat, max_lat = lat0 - 0.005, lat0 + 0.005
            min_lon, max_lon = lon0 - 0.005, lon0 + 0.005
        else:
            lats = [p[0] for p in pts]; lons = [p[1] for p in pts]
            min_lat, max_lat = min(lats), max(lats)
            max_lat = max_lat if max_lat > min_lat else min_lat + 1e-6
            min_lon, max_lon = min(lons), max(lons)
            max_lon = max_lon if max_lon > min_lon else min_lon + 1e-6

        # Padding 12% attorno al bbox per non incollare i punti al bordo,
        # con riserva extra a destra per le label dei nomi.
        d_lat = max(max_lat - min_lat, 1e-6)
        d_lon = max(max_lon - min_lon, 1e-6)
        min_lat -= d_lat * 0.12; max_lat += d_lat * 0.12
        min_lon -= d_lon * 0.10; max_lon += d_lon * 0.18  # piu' spazio a dx

        # Correzione equirettangolare per longitudine
        center_lat = (min_lat + max_lat) / 2.0
        cos_lat = max(0.1, math.cos(math.radians(center_lat)))

        range_lat = max_lat - min_lat
        range_lon_eq = (max_lon - min_lon) * cos_lat

        # Area di disegno con margine interno (lascio piu' spazio a sx per
        # eventuali label spostate a sinistra)
        margin = dp(10)
        draw_w = self.width - 2 * margin
        draw_h = self.height - 2 * margin
        if draw_w <= 0 or draw_h <= 0:
            return

        # Scale: il piu' restrittivo per fit-to-bbox mantenendo aspect ratio
        if range_lat == 0 and range_lon_eq == 0:
            scale = 1.0
        else:
            sx_ = draw_w / range_lon_eq if range_lon_eq > 0 else 1e9
            sy_ = draw_h / range_lat if range_lat > 0 else 1e9
            scale = min(sx_, sy_)

        # Centro del bbox proiettato -> centro del widget
        cx_proj = ((min_lon + max_lon) / 2.0) * cos_lat
        cy_proj = (min_lat + max_lat) / 2.0
        widget_cx = self.x + self.width / 2.0
        widget_cy = self.y + self.height / 2.0

        def project(lat, lon):
            return (widget_cx + (lon * cos_lat - cx_proj) * scale,
                    widget_cy + (lat - cy_proj) * scale)

        # Posizione delle label: di default a destra del punto (offset +dp(8)),
        # ma se il punto e' troppo vicino al bordo destro, sposto la label a
        # SINISTRA del punto. Evita che i nomi escano fuori dal widget.
        def label_pos(px, py, text_w):
            """Restituisce (lx, ly) per piazzare il testo. Sceglie destra o
            sinistra del punto in base allo spazio disponibile."""
            ly = py - dp(7)
            # Spazio disponibile a destra del punto
            space_right = self.x + self.width - margin - (px + dp(8))
            if space_right >= text_w:
                # Ci sta a destra
                lx = px + dp(8)
            else:
                # Metti a sinistra del punto, allineato a destra
                lx = px - dp(8) - text_w
                # Se anche a sinistra non ci sta, clamp al margine sinistro
                if lx < self.x + margin:
                    lx = self.x + margin
            return (lx, ly)

        # 1) Linee del percorso (in ordine), almeno 2 wpt
        if len(wpts) >= 2:
            line_pts = []
            for w in wpts:
                if 'lat' not in w or 'lon' not in w: continue
                px, py = project(w['lat'], w['lon'])
                line_pts.extend([px, py])
            if len(line_pts) >= 4:
                with self.canvas:
                    Color(*ACCENT[:3], 0.85)
                    Line(points=line_pts, width=dp(1.8))

        # 2) Waypoint: arancione standard, giallo per la boa attiva.
        # Per ogni waypoint ricavo prima la dimensione della texture di testo
        # cosi' posso decidere il posizionamento (dx o sx del punto).
        target = self.dm.target_mark
        for w in wpts:
            if 'lat' not in w or 'lon' not in w: continue
            px, py = project(w['lat'], w['lon'])
            is_active = (w.get('name') == target)
            r = dp(7) if is_active else dp(5)
            name = w.get('name', '?')
            lbl_color = YELLOW if is_active else WHITE
            tex_info = self._label_texture(name, 12, lbl_color, bold=True)
            text_w = tex_info[1] if tex_info else dp(40)
            lx, ly = label_pos(px, py, text_w)
            with self.canvas:
                if is_active: Color(*YELLOW)
                else: Color(*ORANGE)
                Ellipse(pos=(px - r, py - r), size=(r * 2, r * 2))
                if is_active:
                    Color(*WHITE)
                    Line(circle=(px, py, r + dp(2)), width=dp(1.2))
                self._draw_text(name, lx, ly, font_size_sp=12,
                                color=lbl_color, bold=True)

        # 3) Posizione barca (pallino verde + freccia heading)
        if boat_lat is not None and boat_lon is not None:
            bx, by = project(boat_lat, boat_lon)
            br = dp(6)
            with self.canvas:
                Color(*GREEN)
                Ellipse(pos=(bx - br, by - br), size=(br * 2, br * 2))
                if self.dm.boat_heading is not None:
                    a = math.radians(self.dm.boat_heading)
                    tip_x = bx + math.sin(a) * dp(14)
                    tip_y = by + math.cos(a) * dp(14)
                    Color(*GREEN[:3], 0.8)
                    Line(points=[bx, by, tip_x, tip_y], width=dp(1.5))


class WaypointsScreen(TabScreen):
    def __init__(self,dm,**kw):
        super().__init__(dm,'WPT  Waypoints',name='waypoints',**kw)
        self._sel=None; self._build()

    def _build(self):
        self._cols=BoxLayout(orientation='horizontal',spacing=dp(8),
                              size_hint=(1,1))
        self.body.add_widget(self._cols)

        # Colonna SINISTRA: lista (sopra, ridotta) + mappa (sotto)
        left=BoxLayout(orientation='vertical',spacing=dp(6),
                        padding=dp(8),size_hint_x=0.55)
        _bg(left,PANEL)
        left.add_widget(Label(text='WAYPOINTS',font_size=sp(16),color=ACCENT,
                               bold=True,size_hint_y=None,height=dp(32)))
        # Lista interna scrollabile (occupa ~45% dell'area utile della colonna)
        list_container = BoxLayout(orientation='vertical', size_hint_y=0.45)
        sv=ScrollView(size_hint=(1,1),do_scroll_x=False)
        self._lb=BoxLayout(orientation='vertical',spacing=dp(3),size_hint_y=None)
        self._lb.bind(minimum_height=self._lb.setter('height'))
        sv.add_widget(self._lb); list_container.add_widget(sv)
        left.add_widget(list_container)
        # Etichetta sezione mappa
        left.add_widget(Label(text='MAPPA PERCORSO',font_size=sp(16),color=ACCENT,
                               bold=True,size_hint_y=None,height=dp(28)))
        # Canvas mappa: occupa il resto della colonna sinistra (~50%)
        self._map = WaypointMapWidget(dm=self.dm, size_hint=(1, 0.55))
        left.add_widget(self._map)
        self._cols.add_widget(left)

        # Colonna DESTRA: azioni invariate
        right=BoxLayout(orientation='vertical',spacing=dp(10),
                         padding=dp(10),size_hint_x=0.45)
        _bg(right,PANEL)
        right.add_widget(Label(text='AZIONI',font_size=sp(16),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(32)))
        for txt,fn in [('Aggiungi',     self._add),
                        ('Modifica',     self._edit),
                        ('Imposta boa',  self._set_mark),
                        ('Rimuovi',      self._del),
                        ('Carica da file', self._reload_from_file),
                        ('Scarica da web', self._download_from_web)]:
            right.add_widget(mk_btn(txt,fn,sp(18)))
        right.add_widget(Label(text='BOA ATTIVA',font_size=sp(16),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(32)))
        self._mark=Label(text='--',font_size=sp(28),bold=True,color=YELLOW,
                          size_hint_y=None,height=dp(50))
        self._d2=kv_row(right,'Distanza:'); self._b2=kv_row(right,'Bearing:')
        right.add_widget(self._mark); right.add_widget(Widget())
        self._cols.add_widget(right)
        self._refresh()

    def on_enter(self):
        """Ogni volta che si entra nella schermata WPT ricarica i waypoint
        dal file: cosi' eventuali modifiche fatte fuori (editor esterno o
        sync da altra source) sono subito visibili. La selezione precedente
        viene scartata perche' i riferimenti agli oggetti dict cambiano."""
        # Ricarico dal file (sovrascrive self.dm.waypoints con dict NUOVI:
        # le reference precedenti a self._sel non valgono piu')
        self.dm._load_waypoints_json()
        self._sel = None
        # super().on_enter() gestisce highlight sidebar e _upd_gps, ma
        # NON chiama _refresh (la base TabScreen.refresh() e' vuota di
        # default). Quindi richiamo io _refresh per ridisegnare lista+mappa
        # con i dati appena ricaricati dal file.
        super().on_enter()
        self._refresh()

    def _do_resize(self,dt):
        try: Clock.schedule_once(lambda dt:self._map.redraw(),0)
        except: pass

    def _refresh(self):
        self._lb.clear_widgets()
        self._mark.text = self.dm.target_mark or '--'
        # Calcolo qual e' il prossimo waypoint dopo quello attivo, cosi' lo
        # marchio nella lista con una freccia: l'utente vede in anticipo dove
        # l'auto-advance lo portera' dopo il superamento della boa attiva.
        next_after = (self.dm._next_target_after(self.dm.target_mark)
                      if self.dm.target_mark else None)
        for wpt in self.dm.waypoints:
            name = wpt.get('name', '?')
            is_active = (name == self.dm.target_mark)
            is_next = (name == next_after)
            # Marker prefix: '*' = boa attiva, '>' = prossima dopo la attiva
            if is_active:
                marker = '* '
            elif is_next:
                marker = '> '
            else:
                marker = '  '
            side = wpt.get('side', 'port')
            side_lbl = 'SX' if side == 'port' else 'DX'
            # Padding iniziale di 2 spazi non basta su display larghi: il
            # testo viene allineato a sinistra dal Button ma se halign='left'
            # senza padding visuale risulta incollato al bordo. Aggiungo
            # spazi e uso text_size con margine per evitare il taglio.
            txt = (f"   {marker}{name}    "
                   f"{wpt.get('lat',0):.4f}  {wpt.get('lon',0):.4f}   "
                   f"[{side_lbl}]")
            # Evidenzia in arancio se selezionato
            is_sel = (self._sel is wpt)
            bg_col = ACCENT if is_sel else SIDEBAR
            txt_col = (0, 0, 0, 1) if is_sel else WHITE
            b = Button(text=txt,
                       font_size=sp(18), size_hint_y=None, height=dp(60),
                       background_color=bg_col, background_normal='',
                       color=txt_col, halign='left', valign='middle',
                       padding=(dp(12), dp(4)))
            # text_size dimensionato sulla larghezza disponibile della COLONNA
            # SINISTRA (sl' della WaypointsScreen, ~55% di Window meno
            # sidebar e padding). Senza limite la halign='left' non
            # allinea correttamente, e con il valore vecchio (Window.width
            # intero) il testo eccedeva la larghezza del button e finiva
            # tagliato a sinistra al rendering.
            col_w = (Window.width - SIDEBAR_W) * 0.55 - dp(40)
            b.text_size = (max(col_w, dp(150)), None)
            b.bind(on_release=lambda _, w=wpt: self._select(w))
            self._lb.add_widget(b)
        # Aggiorna anche la mappa (dopo modifiche/selezioni cambia il target)
        if hasattr(self, '_map') and self._map is not None:
            Clock.schedule_once(lambda dt: self._map.redraw(), 0)

    def _select(self, wpt):
        """Selezione waypoint: aggiorna evidenziazione."""
        self._sel = wpt
        self._refresh()

    # ---- Dialog inserimento/modifica ----

    def _open_dialog(self, wpt=None):
        """Apre il popup di inserimento/modifica.
        Se wpt is None: nuovo waypoint (precompila lat/lon con GPS attuale).
        Se wpt e' un dict: modifica del waypoint esistente."""

        def _fmt_dm(deg, is_lat):
            """Formatta gradi decimali in stringa DM: GG MM.mmm H.
            Es. 45.752733, is_lat=True -> "45 45.164 N"."""
            if deg is None:
                return ''
            if is_lat:
                hemi = 'N' if deg >= 0 else 'S'
            else:
                hemi = 'E' if deg >= 0 else 'W'
            d = abs(deg)
            deg_int = int(d)
            minutes = (d - deg_int) * 60.0
            return f"{deg_int} {minutes:.3f} {hemi}"

        is_new = wpt is None
        if is_new:
            # Nome di default progressivo, lat/lon dalla posizione GPS corrente
            # in formato gradi-minuti decimali (DM): GG MM.mmm H.
            init_name = f'WPT{len(self.dm.waypoints)+1}'
            init_lat  = _fmt_dm(self.dm.gps_lat, True)  if self.dm.gps_lat else ''
            init_lon  = _fmt_dm(self.dm.gps_lon, False) if self.dm.gps_lon else ''
            init_side = 'port'
            title = 'Nuovo waypoint'
        else:
            init_name = str(wpt.get('name',''))
            init_lat  = _fmt_dm(wpt.get('lat'), True)
            init_lon  = _fmt_dm(wpt.get('lon'), False)
            init_side = wpt.get('side','port')
            title = f"Modifica: {wpt.get('name','?')}"

        # Layout del popup
        content = BoxLayout(orientation='vertical', spacing=dp(8),
                            padding=dp(10))

        def _row(lbl_text, widget):
            r = BoxLayout(orientation='horizontal', spacing=dp(8),
                          size_hint_y=None, height=dp(54))
            r.add_widget(Label(text=lbl_text, font_size=sp(18), color=MUTED,
                               size_hint_x=0.30, halign='right',
                               valign='middle'))
            r.add_widget(widget)
            return r

        # Campo Nome
        inp_name = TextInput(text=init_name, multiline=False,
                             font_size=sp(18), size_hint_y=None, height=dp(54))
        # Campo Latitudine
        inp_lat = TextInput(text=init_lat, multiline=False, input_type='text',
                            font_size=sp(18), size_hint_y=None, height=dp(54))
        # Campo Longitudine
        inp_lon = TextInput(text=init_lon, multiline=False, input_type='text',
                            font_size=sp(18), size_hint_y=None, height=dp(54))

        # Toggle Sinistra/Destra (mutually exclusive)
        side_row = BoxLayout(orientation='horizontal', spacing=dp(8),
                             size_hint_y=None, height=dp(54))
        side_row.add_widget(Label(text='Lascia a:', font_size=sp(18),
                                  color=MUTED, size_hint_x=0.30,
                                  halign='right', valign='middle'))
        # Lista mutabile per chiusura
        cur_side = [init_side]
        btn_sx = Button(text='SINISTRA', font_size=sp(16), bold=True,
                        background_normal='')
        btn_dx = Button(text='DESTRA',  font_size=sp(16), bold=True,
                        background_normal='')

        def _refresh_side_btns():
            if cur_side[0] == 'port':
                btn_sx.background_color = GREEN
                btn_sx.color = (0, 0, 0, 1)
                btn_dx.background_color = BTN_GRAY
                btn_dx.color = WHITE
            else:
                btn_sx.background_color = BTN_GRAY
                btn_sx.color = WHITE
                btn_dx.background_color = RED
                btn_dx.color = (0, 0, 0, 1)

        def _set_sx(_):
            cur_side[0] = 'port';      _refresh_side_btns()
        def _set_dx(_):
            cur_side[0] = 'starboard'; _refresh_side_btns()

        btn_sx.bind(on_release=_set_sx)
        btn_dx.bind(on_release=_set_dx)
        _refresh_side_btns()
        side_row.add_widget(btn_sx)
        side_row.add_widget(btn_dx)

        # Etichetta errori
        err_lbl = Label(text='', font_size=sp(14), color=RED,
                        size_hint_y=None, height=dp(28))

        # Bottoniera OK / Annulla
        btn_row = BoxLayout(orientation='horizontal', spacing=dp(8),
                            size_hint_y=None, height=dp(54))

        # Aggiungi tutti i widget. I campi accettano gradi-minuti decimali
        # nel formato: GG MM.mmm H  (es. 45°45.164'N oppure 45 45.164 N).
        # H = N/S per latitudine, E/W per longitudine. Senza emisfero il
        # segno e' positivo.
        content.add_widget(_row('Nome:', inp_name))
        content.add_widget(_row("Lat (GG MM.mmm N/S):",  inp_lat))
        content.add_widget(_row("Lon (GG MM.mmm E/W):", inp_lon))
        content.add_widget(side_row)
        content.add_widget(err_lbl)
        content.add_widget(Widget())  # spacer
        content.add_widget(btn_row)

        popup = Popup(title=title, content=content,
                      size_hint=(0.75, 0.85), auto_dismiss=False)

        def _on_ok(_):
            # Validazione campi
            name = inp_name.text.strip()
            if not name:
                err_lbl.text = 'Nome obbligatorio'
                return
            try:
                lat = parse_coord(inp_lat.text, is_lat=True)
            except ValueError as e:
                err_lbl.text = f'Lat non valida: {e}'
                return
            try:
                lon = parse_coord(inp_lon.text, is_lat=False)
            except ValueError as e:
                err_lbl.text = f'Lon non valida: {e}'
                return

            # Persistenza FILE-FIRST: la modifica viene scritta direttamente
            # su waypoints.json e poi self.dm.waypoints viene ricaricato dal
            # file. Cosi' la fonte di verita' resta sempre il file.
            if is_new:
                ok, err = self.dm.waypoint_add(name, lat, lon, cur_side[0])
            else:
                old_name = wpt.get('name', '')
                ok, err = self.dm.waypoint_update(old_name, name, lat, lon,
                                                   cur_side[0])
            if not ok:
                err_lbl.text = err or 'Errore non specificato'
                return

            # Dopo la ricarica, ritrovo il waypoint per nome per aggiornare
            # la selezione (i riferimenti vecchi non valgono piu')
            self._sel = next((w for w in self.dm.waypoints
                              if w.get('name') == name), None)
            popup.dismiss()
            self._refresh()

        def _on_cancel(_):
            popup.dismiss()

        btn_ok     = mk_btn('OK',      _on_ok,     sp(18))
        btn_cancel = mk_btn_gray('Annulla', _on_cancel, sp(18))
        btn_row.add_widget(btn_cancel)
        btn_row.add_widget(btn_ok)

        popup.open()

    def _add(self):
        """Apre il dialog per inserire un nuovo waypoint."""
        self._open_dialog(wpt=None)

    def _edit(self):
        """Apre il dialog per modificare il waypoint selezionato."""
        if not self._sel:
            Popup(title='Modifica',
                  content=Label(text='Seleziona prima un waypoint dalla lista.'),
                  size_hint=(0.45, 0.22)).open()
            return
        self._open_dialog(wpt=self._sel)

    def _set_mark(self):
        """Imposta il waypoint selezionato come boa attiva (target_mark).
        Persiste nel config (sailing_config.json) cosi' al riavvio resta.
        I waypoint stessi NON vengono toccati: questa modifica riguarda solo
        la 'destinazione corrente'.

        Da qui in poi, advance_target_if_passed() vigilera' sul superamento
        di questa boa per fare lo switch automatico al prossimo waypoint."""
        if self._sel:
            self.dm.target_mark = self._sel.get('name')
            # Reset del rilevatore CPA: stiamo iniziando il tracking di una
            # nuova boa, non vogliamo che il vecchio min_distance influenzi
            # la nuova decisione di switch.
            self.dm._reset_mark_pass_state()
            self.dm.save_cfg_safe()
            self._refresh()

    def _del(self):
        """Cancella il waypoint selezionato dal file. File-first:
        la rimozione viene fatta direttamente sul waypoints.json e poi
        self.dm.waypoints viene ricaricato dal file."""
        if not self._sel:
            return
        name = self._sel.get('name', '')
        ok, err = self.dm.waypoint_delete(name)
        if not ok:
            Popup(title='Errore rimozione',
                  content=Label(text=err or 'Errore non specificato'),
                  size_hint=(0.5, 0.22)).open()
            return
        self._sel = None
        self._refresh()

    def _reload_from_file(self):
        """Forza la ricarica dei waypoint dal file waypoints.json sul disco.

        Caso d'uso: l'utente ha modificato il file dall'esterno (editor di
        testo, sync, copia da altro device) e vuole che l'app legga subito
        i nuovi valori senza dover uscire e rientrare nella schermata.

        Comportamento:
        - Se il file NON esiste, lo crea con i default (Boa1/Boa2/Arrivo)
          chiamando _ensure_waypoints_file(), poi ricarica.
        - Se il file esiste, lo legge e sovrascrive self.dm.waypoints.
        - Mostra un popup con esito (numero di waypoint caricati) o errore.
        - La selezione viene scartata perche' i nuovi dict non sono gli
          stessi oggetti di prima.
        - Se la boa attiva (target_mark) non e' piu' presente nei waypoint
          ricaricati, viene azzerata."""
        # 1) Se il file manca, crealo dai default. Cosi' il pulsante e'
        #    "self-healing": funziona sempre, non lascia l'utente con UI
        #    vuota se per qualche motivo il file e' stato cancellato.
        created = _ensure_waypoints_file()

        # 2) Ricarica dal file
        ok = self.dm._load_waypoints_json()
        n = len(self.dm.waypoints)

        # 3) Se la boa attiva non c'e' piu', azzera target_mark
        if self.dm.target_mark and not any(
                w.get('name') == self.dm.target_mark
                for w in self.dm.waypoints):
            self.dm.target_mark = None
            self.dm._reset_mark_pass_state()
            self.dm.save_cfg_safe()

        # 4) Reset selezione e refresh UI
        self._sel = None
        self._refresh()

        # 5) Feedback all'utente
        if created:
            msg = (f'File mancante: creato con default.\n'
                   f'Caricati {n} waypoint.')
        elif ok:
            msg = f'Caricati {n} waypoint da file.'
        else:
            msg = ('Errore lettura waypoints.json\n'
                   '(il file esiste ma non e\' valido).')
        Popup(title='Carica da file',
              content=Label(text=msg, halign='center', valign='middle'),
              size_hint=(0.5, 0.28)).open()

    def _download_from_web(self):
        """Scarica waypoints.json dal cloud blob storage e lo salva localmente.

        URL: {blob_base}/waypoints/{cloud_boat_id}/waypoints.json
        I parametri sono in sailing_config.json.

        Pattern UI bulletproof (idem _download_from_cloud):
        - Un solo Popup, un solo Label, un solo Button creati a inizio.
        - Worker aggiorna SOLO il testo della label (mai widget nuovi).
        - try/except globale: errori inattesi visibili nel popup, no crash."""
        url = self.dm.download_waypoints_url()
        if not url:
            Popup(title='Scarica da web',
                  content=Label(text='cloud_boat_id non configurato.\n'
                                     'Imposta il valore in sailing_config.json',
                                halign='center', valign='middle'),
                  size_hint=(0.6, 0.30)).open()
            return

        # Popup costruito UNA volta, mai modificato strutturalmente
        box = BoxLayout(orientation='vertical', spacing=dp(8), padding=dp(8))
        status_lbl = Label(text=f'Scaricamento da:\n{url}\n\nAttendere...',
                            halign='center', valign='middle', color=WHITE)
        status_lbl.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        box.add_widget(status_lbl)
        close_btn = Button(text='Attendere...',
                            size_hint_y=None, height=dp(48),
                            background_color=BTN_GRAY, background_normal='',
                            color=WHITE, bold=True, disabled=True)
        box.add_widget(close_btn)

        pop = Popup(title='Scarica da web', content=box,
                     size_hint=(0.80, 0.55), auto_dismiss=False)
        close_btn.bind(on_release=lambda _: pop.dismiss())
        pop.open()

        def _finish(text, color, refresh_ui=False):
            try:
                if refresh_ui:
                    # Aggiorno UI: nuova lista + reset selezione + check target
                    if self.dm.target_mark and not any(
                            w.get('name') == self.dm.target_mark
                            for w in self.dm.waypoints):
                        self.dm.target_mark = None
                        self.dm._reset_mark_pass_state()
                        self.dm.save_cfg_safe()
                    self._sel = None
                    self._refresh()
                status_lbl.text  = text
                status_lbl.color = color
                close_btn.text   = 'Chiudi'
                close_btn.disabled = False
                pop.auto_dismiss = True
            except Exception as e:
                print(f'_download_from_web waypoints _finish: {e}')

        def _worker():
            try:
                ok, msg = self.dm.download_waypoints_from_web()
                if ok:
                    Clock.schedule_once(lambda dt: _finish(
                        f'OK: {msg}\n\nFile salvato in:\n{WAYPOINTS_PATH}',
                        GREEN, refresh_ui=True), 0)
                else:
                    Clock.schedule_once(lambda dt, m=msg: _finish(
                        f'Errore download:\n{m}', RED), 0)
            except Exception as e:
                import traceback
                print(f'_download_from_web waypoints CRASH:\n{traceback.format_exc()}')
                Clock.schedule_once(
                    lambda dt, m=f'{type(e).__name__}: {e}': _finish(
                        f'Errore inatteso:\n{m}', RED), 0)

        threading.Thread(target=_worker, daemon=True).start()

# =============================================================================
# 5 -- POLARI
# =============================================================================

class PolarScreen(TabScreen):
    """Schermata Polari: visualizza la polare caricata e permette di
    attivarla/disattivarla globalmente con un toggle.

    Filosofia: la polare e' un dato statico della barca, NON modificabile
    dall'interfaccia grafica. Si modifica SOLO editando il file polar.json
    (formato {"boat_name":"...", "polar":{tws:{twa:bsp}}}) sul tablet, poi
    si usa il pulsante 'Ricarica da file' per riportarla in memoria.

    Toggle ATTIVA/DISATTIVA: quando DISATTIVA, tutti i calcoli polar-aware
    (target speed, laylines basate su TWA target, ETA con VMG, layline
    detection in tactical_advice) tornano al fallback "raw" basato su
    boat_speed. La polare resta caricata in memoria, semplicemente non
    viene consultata. Persistente in sailing_config.json (campo
    polar_enabled)."""
    def __init__(self,dm,**kw):
        super().__init__(dm,'Polar  Polari',name='polar',**kw)
        self._build()

    def _build(self):
        self._cols=BoxLayout(orientation='horizontal',spacing=dp(8),
                              size_hint=(1,1))
        self.body.add_widget(self._cols)
        # ----- Colonna sinistra: stato + tabella polare -----
        left=BoxLayout(orientation='vertical',spacing=dp(5),
                        padding=dp(8),size_hint_x=0.60)
        _bg(left,PANEL)
        self._st=Label(text='Nessuna polare',font_size=sp(18),color=RED,
                        size_hint_y=None,height=dp(38))
        left.add_widget(self._st)
        # ScrollView interno per la tabella polare (puo' essere grande)
        sv=ScrollView(size_hint=(1,1),do_scroll_x=True)
        self._tbl=GridLayout(cols=1,spacing=dp(1),size_hint=(None,None))
        self._tbl.bind(minimum_height=self._tbl.setter('height'),
                        minimum_width=self._tbl.setter('width'))
        sv.add_widget(self._tbl); left.add_widget(sv)
        self._cols.add_widget(left)

        # ----- Colonna destra: toggle attivo + ricarica + VMG ottimale -----
        right=BoxLayout(orientation='vertical',spacing=dp(8),
                         padding=dp(10),size_hint_x=0.40)
        _bg(right,PANEL)

        # Sezione 1: toggle ATTIVA/DISATTIVA
        right.add_widget(Label(text='POLARE',font_size=sp(16),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(32)))
        # Due bottoni mutually exclusive (stesso schema usato per cloud ON/OFF)
        en_row=BoxLayout(orientation='horizontal',spacing=dp(8),
                         size_hint_y=None,height=dp(60))
        self._btn_on  = mk_btn('ATTIVA',
                               lambda: self._set_enabled(True),  sp(18))
        self._btn_off = mk_btn('DISATTIVA',
                               lambda: self._set_enabled(False), sp(18))
        en_row.add_widget(self._btn_on); en_row.add_widget(self._btn_off)
        right.add_widget(en_row)
        # Label di stato sotto i bottoni che riepiloga la situazione
        self._enabled_lbl=Label(text='--',font_size=sp(16),color=MUTED,
                                size_hint_y=None,height=dp(32),
                                halign='center',valign='middle')
        self._enabled_lbl.bind(size=self._enabled_lbl.setter('text_size'))
        right.add_widget(self._enabled_lbl)

        # Sezione 2: caricamento da file (UNICO canale di modifica locale)
        right.add_widget(Label(text='FILE',font_size=sp(16),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(32)))
        right.add_widget(mk_btn('Ricarica da file',
                                self._reload_from_file, sp(18)))
        right.add_widget(mk_btn('Scarica da web',
                                self._download_from_web, sp(18)))
        # Mostra il path da cui si carica (read-only, modificabile solo da
        # config.json). Cosi' l'utente sa esattamente quale file editare.
        self._path_lbl=Label(text=self._fmt_path(),font_size=sp(13),color=MUTED,
                              size_hint_y=None,height=dp(50),
                              halign='center',valign='middle')
        self._path_lbl.bind(size=self._path_lbl.setter('text_size'))
        right.add_widget(self._path_lbl)

        # Sezione 3: VMG ottimale (sempre visibile per riferimento; mostra
        # i valori dalla polare anche se DISATTIVA, cosi' l'utente puo'
        # confrontare).
        right.add_widget(Label(text='VMG OTTIMALE',font_size=sp(16),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(32)))
        self._vu=Label(text='Bolina: --',font_size=sp(18),color=GREEN,
                        size_hint_y=None,height=dp(38))
        self._vd=Label(text='Poppa: --', font_size=sp(18),color=ACCENT,
                        size_hint_y=None,height=dp(38))
        right.add_widget(self._vu); right.add_widget(self._vd)

        # Sezione 4: VELA SUGGERITA (live, da tabella crossover se presente).
        # La label mostra: nome vela + label umana + colore di sfondo.
        # Il pulsante apre il popup con la tabella crossover completa.
        right.add_widget(Label(text='VELA SUGGERITA',font_size=sp(16),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(32)))
        self._sail_lbl = Label(text='--',font_size=sp(20),color=WHITE,bold=True,
                                size_hint_y=None,height=dp(54),
                                halign='center',valign='middle')
        self._sail_lbl.bind(size=self._sail_lbl.setter('text_size'))
        # Sfondo dinamico (Rectangle gestito in _upd_sail). Inizializzo grigio.
        with self._sail_lbl.canvas.before:
            self._sail_bg_color = Color(*MUTED)
            self._sail_bg_rect  = Rectangle(pos=self._sail_lbl.pos,
                                             size=self._sail_lbl.size)
        self._sail_lbl.bind(pos=lambda w,p: setattr(self._sail_bg_rect,'pos',p),
                             size=lambda w,s: setattr(self._sail_bg_rect,'size',s))
        right.add_widget(self._sail_lbl)
        right.add_widget(mk_btn('Tabella vele',
                                 self._show_sail_crossover, sp(16)))

        right.add_widget(Widget())
        self._cols.add_widget(right)
        self._refresh_table()
        self._refresh_enabled_btns()

    def _do_resize(self,dt): pass

    def _fmt_path(self):
        """Formatta il path della polare per il display: tronca se troppo lungo."""
        p = self.dm.polar_path or '(nessuno)'
        if len(p) > 70:
            p = '...' + p[-67:]
        return f'File:\n{p}'

    def _set_enabled(self, enabled):
        """Toggle ON/OFF della polare. Persiste subito nel config.json
        e aggiorna lo stato visuale. I calcoli polar-aware in DataManager
        leggeranno il nuovo valore al prossimo tick."""
        self.dm.polar_enabled = bool(enabled)
        # Quando si DISATTIVA, azzero anche i target gia' calcolati cosi'
        # NavigationScreen mostra subito '--' invece dei valori stantii
        # finche' non arriva il prossimo aggiornamento NMEA.
        if not enabled:
            self.dm.target_bsp = None
            self.dm.polar_twa_target = None
            self.dm.polar_vmg_target = None
        self.dm.save_cfg_safe()
        self._refresh_enabled_btns()
        self._refresh_table()  # aggiorna anche la label di stato in alto

    def _refresh_enabled_btns(self):
        """Evidenzia ATTIVA o DISATTIVA in base allo stato corrente."""
        if self.dm.polar_enabled:
            self._btn_on.background_color  = GREEN
            self._btn_on.color             = (0, 0, 0, 1)
            self._btn_off.background_color = BTN_GRAY
            self._btn_off.color            = WHITE
            if self.dm.polar.loaded:
                self._enabled_lbl.text  = 'Calcoli polar-aware: ATTIVI'
                self._enabled_lbl.color = GREEN
            else:
                self._enabled_lbl.text  = ('Toggle ATTIVO ma nessun file caricato:\n'
                                           'i calcoli usano il fallback raw.')
                self._enabled_lbl.color = ORANGE
        else:
            self._btn_on.background_color  = BTN_GRAY
            self._btn_on.color             = WHITE
            self._btn_off.background_color = RED
            self._btn_off.color            = (0, 0, 0, 1)
            self._enabled_lbl.text  = 'Calcoli polar-aware: DISATTIVATI\n(fallback su boat_speed)'
            self._enabled_lbl.color = ORANGE

    def _reload_from_file(self):
        """Ricarica la polare dal file gia' configurato in dm.polar_path.
        Non chiede il path: per cambiare path bisogna editare il config.json
        (campo "polar_path") e riavviare l'app."""
        path = self.dm.polar_path
        if not path:
            self._msg('Errore', 'Nessun path configurato.')
            return
        if not os.path.exists(path):
            self._msg('Errore', f'File non trovato:\n{path}')
            return
        if self.dm.polar.load(path):
            self._refresh_table()
            self._refresh_enabled_btns()
            self._msg('OK', f'Polare ricaricata:\n{self.dm.polar.boat_name or "(senza nome)"}')
        else:
            self._msg('Errore', f'File non valido:\n{path}')

    def _download_from_web(self):
        """Scarica polar.json dal cloud blob storage e lo salva in self.dm.polar_path.

        URL: {blob_base}/polars/{cloud_boat_id}/polar.json
        Pattern UI bulletproof: stesso schema delle altre operazioni cloud."""
        url = self.dm.download_polar_url()
        if not url:
            Popup(title='Scarica da web',
                  content=Label(text='cloud_boat_id non configurato.\n'
                                     'Imposta il valore in sailing_config.json',
                                halign='center', valign='middle'),
                  size_hint=(0.6, 0.30)).open()
            return

        # Popup costruito UNA volta sola
        box = BoxLayout(orientation='vertical', spacing=dp(8), padding=dp(8))
        status_lbl = Label(text=f'Scaricamento da:\n{url}\n\nAttendere...',
                            halign='center', valign='middle', color=WHITE)
        status_lbl.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        box.add_widget(status_lbl)
        close_btn = Button(text='Attendere...',
                            size_hint_y=None, height=dp(48),
                            background_color=BTN_GRAY, background_normal='',
                            color=WHITE, bold=True, disabled=True)
        box.add_widget(close_btn)

        pop = Popup(title='Scarica da web', content=box,
                     size_hint=(0.80, 0.55), auto_dismiss=False)
        close_btn.bind(on_release=lambda _: pop.dismiss())
        pop.open()

        def _finish(text, color, refresh_ui=False):
            try:
                if refresh_ui:
                    self._refresh_table()
                    self._refresh_enabled_btns()
                status_lbl.text  = text
                status_lbl.color = color
                close_btn.text   = 'Chiudi'
                close_btn.disabled = False
                pop.auto_dismiss = True
            except Exception as e:
                print(f'_download_from_web polar _finish: {e}')

        def _worker():
            try:
                ok, msg = self.dm.download_polar_from_web()
                if ok:
                    Clock.schedule_once(lambda dt: _finish(
                        f'OK: {msg}\n\nFile salvato in:\n{self.dm.polar_path}',
                        GREEN, refresh_ui=True), 0)
                else:
                    Clock.schedule_once(lambda dt, m=msg: _finish(
                        f'Errore download:\n{m}', RED), 0)
            except Exception as e:
                import traceback
                print(f'_download_from_web polar CRASH:\n{traceback.format_exc()}')
                Clock.schedule_once(
                    lambda dt, m=f'{type(e).__name__}: {e}': _finish(
                        f'Errore inatteso:\n{m}', RED), 0)

        threading.Thread(target=_worker, daemon=True).start()

    def _msg(self,t,m):
        Popup(title=t,content=Label(text=m),size_hint=(0.55,0.30)).open()

    def _refresh_table(self):
        self._tbl.clear_widgets(); p=self.dm.polar
        if not p.data:
            self._st.text='Nessuna polare'; self._st.color=RED; self._tbl.cols=1
            self._tbl.add_widget(Label(text='Nessun file polare caricato.\n'
                                            f'Edita {POLAR_FILE} sul tablet '
                                            'e premi "Ricarica da file".',
                                        font_size=sp(13),
                                        color=MUTED,size_hint_y=None,height=dp(80)))
            return
        tws_l=p.get_tws_list(); twa_l=p.get_twa_list()
        # Indicatore crossover vele: [+sails] se la polare ha la sezione vele
        sails_tag = ' [+sails]' if p.has_sails() else ''
        # Stato in alto: distingue caricata+attiva vs caricata+disattivata
        if self.dm.polar_enabled:
            self._st.text=f'OK  {p.boat_name or "--"}  {len(tws_l)}x{len(twa_l)}{sails_tag}  [ATTIVA]'
            self._st.color=GREEN
        else:
            self._st.text=f'OK  {p.boat_name or "--"}  {len(tws_l)}x{len(twa_l)}{sails_tag}  [DISATTIVATA]'
            self._st.color=ORANGE
        self._tbl.cols=len(tws_l)+1
        ch=dp(40); cw=dp(80)
        def cell(text,color=MUTED,bold=False):
            l=Label(text=text,font_size=sp(15),color=color,bold=bold,
                     size_hint=(None,None),width=cw,height=ch,
                     halign='center',valign='middle')
            l.text_size=(cw,ch); return l
        self._tbl.add_widget(cell('TWA/TWS',ACCENT,True))
        for t in tws_l: self._tbl.add_widget(cell(f'{t:.0f}kn',ACCENT,True))
        for twa in twa_l:
            self._tbl.add_widget(cell(f'{twa:.0f}',WHITE,True))
            for tws in tws_l:
                bsp=p.data.get(tws,{}).get(twa)
                self._tbl.add_widget(cell(f'{bsp:.2f}' if bsp else '--'))
        self._upd_vmg()

    def _upd_vmg(self):
        p=self.dm.polar; tws=self.dm.true_wind_speed or 10.0
        up=p.get_target_vmg(tws,upwind=True); dn=p.get_target_vmg(tws,upwind=False)
        self._vu.text=f'Bolina: {up[0]:.0f}  VMG {up[1]:.2f}kn' if up else 'Bolina: --'
        self._vd.text=f'Poppa:  {dn[0]:.0f}  VMG {dn[1]:.2f}kn' if dn else 'Poppa: --'

    def _upd_sail(self):
        """Aggiorna in real-time la label "vela suggerita" leggendo TWS/TWA
        correnti dal DataManager e consultando la tabella crossover.
        Niente crossover (polar v1) -> mostra '(no crossover)' in grigio."""
        p   = self.dm.polar
        tws = self.dm.true_wind_speed
        twa = self.dm.true_wind_angle
        if not p.has_sails():
            self._sail_lbl.text  = '(no crossover)'
            self._sail_lbl.color = MUTED
            self._sail_bg_color.rgba = (0.18, 0.18, 0.18, 1)
            return
        if tws is None or twa is None:
            self._sail_lbl.text  = '(no wind data)'
            self._sail_lbl.color = MUTED
            self._sail_bg_color.rgba = (0.18, 0.18, 0.18, 1)
            return
        sail_id = p.get_sail(tws, twa)
        if not sail_id:
            self._sail_lbl.text  = '(N/D)'
            self._sail_lbl.color = MUTED
            self._sail_bg_color.rgba = (0.18, 0.18, 0.18, 1)
            return
        label    = p.get_sail_label(sail_id)
        col_hex  = p.get_sail_color(sail_id)
        rgba     = self._hex_to_rgba(col_hex, alpha=1.0)
        self._sail_lbl.text  = f'{sail_id}\n{label}'
        # Calcola colore testo: nero su sfondi chiari, bianco su scuri.
        # Heuristic: luminanza > 0.5 -> testo nero.
        r, g, b, _ = rgba
        lum = 0.299*r + 0.587*g + 0.114*b
        self._sail_lbl.color = (0, 0, 0, 1) if lum > 0.55 else (1, 1, 1, 1)
        self._sail_bg_color.rgba = rgba

    @staticmethod
    def _hex_to_rgba(hex_str, alpha=1.0):
        """Converte '#rrggbb' (con o senza '#') in tupla (r,g,b,a) [0..1].
        Su input invalido restituisce un grigio neutro."""
        try:
            s = (hex_str or '').lstrip('#')
            if len(s) == 3:
                s = ''.join(c*2 for c in s)
            r = int(s[0:2], 16) / 255.0
            g = int(s[2:4], 16) / 255.0
            b = int(s[4:6], 16) / 255.0
            return (r, g, b, alpha)
        except Exception:
            return (0.5, 0.5, 0.5, alpha)

    def _show_sail_crossover(self, *_):
        """Popup con la tabella crossover: righe = TWS, colonne = bin TWA.
        Ogni cella ha sfondo del colore della vela definito in 'sails.definitions'.
        Se la polare non ha la sezione vele, mostra un messaggio informativo."""
        p = self.dm.polar
        if not p.has_sails():
            Popup(title='Tabella vele',
                  content=Label(text='Questa polare non ha la sezione "sails".\n'
                                     'Aggiorna polar.json al formato v2 con:\n'
                                     '  "sails": {"definitions": {...},\n'
                                     '            "crossover": {...}}',
                                halign='center', valign='middle'),
                  size_hint=(0.7, 0.40)).open()
            return

        bins = p.SAIL_BINS
        tws_keys = p._crossover_tws_keys()

        # Layout: ScrollView -> GridLayout(cols=len(bins)+1) per scroll su tablet.
        outer = BoxLayout(orientation='vertical', spacing=dp(6))
        # Legenda compatta in alto: una riga per definizione vela
        legend = BoxLayout(orientation='vertical',
                            size_hint_y=None,
                            height=dp(28) * max(1, len(p.sail_definitions)))
        for sid, info in p.sail_definitions.items():
            row = BoxLayout(orientation='horizontal',
                             size_hint_y=None, height=dp(26),
                             spacing=dp(6))
            sw = Label(text='', size_hint_x=None, width=dp(40))
            with sw.canvas.before:
                Color(*self._hex_to_rgba(info.get('color', '#888888')))
                rect = Rectangle(pos=sw.pos, size=sw.size)
            sw.bind(pos=lambda w,pp,r=rect: setattr(r,'pos',pp),
                     size=lambda w,ss,r=rect: setattr(r,'size',ss))
            row.add_widget(sw)
            row.add_widget(Label(text=f'{sid}  --  {info.get("label","")}',
                                  font_size=sp(13),
                                  halign='left', valign='middle',
                                  color=WHITE))
            legend.add_widget(row)
        outer.add_widget(legend)

        # Tabella crossover
        sv = ScrollView(do_scroll_x=True, do_scroll_y=True)
        cw = dp(70); ch = dp(40)
        grid = GridLayout(cols=len(bins) + 1, spacing=dp(1),
                           size_hint=(None, None))
        grid.bind(minimum_height=grid.setter('height'),
                   minimum_width=grid.setter('width'))

        def hdr(text):
            l = Label(text=text, font_size=sp(13), color=ACCENT, bold=True,
                       size_hint=(None, None), width=cw, height=ch,
                       halign='center', valign='middle')
            l.text_size = (cw, ch)
            return l

        def cell(text, bg_rgba):
            box = BoxLayout(size_hint=(None, None), width=cw, height=ch)
            with box.canvas.before:
                Color(*bg_rgba)
                rect = Rectangle(pos=box.pos, size=box.size)
            box.bind(pos=lambda w,pp,r=rect: setattr(r,'pos',pp),
                      size=lambda w,ss,r=rect: setattr(r,'size',ss))
            # Testo nero o bianco a seconda della luminanza
            r, g, b, _ = bg_rgba
            lum = 0.299*r + 0.587*g + 0.114*b
            txt_col = (0,0,0,1) if lum > 0.55 else (1,1,1,1)
            l = Label(text=text, font_size=sp(13), color=txt_col, bold=True,
                       halign='center', valign='middle')
            l.bind(size=l.setter('text_size'))
            box.add_widget(l)
            return box

        # Header riga 0
        grid.add_widget(hdr('TWS / TWA'))
        for b in bins:
            grid.add_widget(hdr(b))
        # Righe
        for tws_k in tws_keys:
            grid.add_widget(hdr(f'{tws_k:.0f} kn'))
            row_map = p.sail_crossover.get(tws_k, {})
            for b in bins:
                sail_id = row_map.get(b, '')
                if sail_id:
                    rgba = self._hex_to_rgba(p.get_sail_color(sail_id))
                    grid.add_widget(cell(sail_id, rgba))
                else:
                    grid.add_widget(cell('--', (0.12, 0.12, 0.12, 1)))
        sv.add_widget(grid)
        outer.add_widget(sv)

        # Bottone chiudi
        close = Button(text='Chiudi', size_hint_y=None, height=dp(46),
                       background_color=BTN_GRAY, background_normal='',
                       color=WHITE, bold=True)
        outer.add_widget(close)

        title_txt = f'Tabella vele -- {p.boat_name or "polare"}'
        pop = Popup(title=title_txt, content=outer,
                     size_hint=(0.95, 0.92), auto_dismiss=True)
        close.bind(on_release=lambda _: pop.dismiss())
        pop.open()

    def tick(self,dt):
        super().tick(dt)
        if self.dm.polar.loaded:
            self._upd_vmg()
            self._upd_sail()

# =============================================================================
# 6 -- LOG REGATA (registrazione locale + upload one-shot + cloud live)
# =============================================================================
# Tre funzioni in un'unica schermata:
# 1. REGISTRAZIONE LOCALE: pulsante Start/Stop. Crea un CSV in log_dir
#    chiamato track_YYYY-MM-DD_HH-MM-SS.csv e ci scrive una riga ogni 5s
#    (gestito da TrackLogger del DataManager). Header e formato sono in
#    TrackLogger.HEADER. La data nel nome file e' quella di START.
# 2. INVIO ONE-SHOT AL BLOB: a registrazione fermata, pulsante "Invia al
#    cloud" carica l'intero CSV su:
#      {blob_base}/tracks/{cloud_boat_id}/{filename.csv}
#    via Shared Key auth (vedi DataManager.upload_csv_to_blob).
# 3. CLOUD UPLOAD LIVE: toggle ON/OFF + selettore intervallo (30s, 1m, 2m,
#    5m, 10m). Quando ON, il CloudUploader del DataManager invia uno
#    snapshot HTTPS ogni N secondi al backend (cloud_url), che a sua volta
#    fa l'INSERT su SQL Server tabella 'traks' di sailing-sql-7645.
#    Indipendente dal logger locale: si puo' avere live ON anche senza
#    registrazione e viceversa.

class LoggingScreen(TabScreen):
    """Schermata "Log": gestione completa logging regata."""

    # Frequenze upload selezionabili (secondi -> etichetta breve UI)
    FREQ_CHOICES = [(30, '30s'), (60, '1m'), (120, '2m'),
                     (300, '5m'), (600, '10m')]

    def __init__(self, dm, **kw):
        super().__init__(dm, 'Log  Registrazione', name='logging', **kw)
        self._build()

    def _build(self):
        outer = BoxLayout(orientation='horizontal', spacing=dp(8),
                           size_hint=(1, 1))
        self.body.add_widget(outer)

        # ---- COLONNA SINISTRA: registrazione locale + invio one-shot ----
        left = BoxLayout(orientation='vertical', spacing=dp(8),
                          padding=dp(12), size_hint_x=0.5)
        _bg(left, PANEL)
        left.add_widget(Label(text='REGISTRAZIONE LOCALE', font_size=sp(20),
                                color=ACCENT, bold=True,
                                size_hint_y=None, height=dp(40)))
        # Stato a caratteri grandi
        self._rec_status = Label(text='Non in registrazione',
                                   font_size=sp(22), color=MUTED, bold=True,
                                   size_hint_y=None, height=dp(60),
                                   halign='center', valign='middle')
        self._rec_status.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        left.add_widget(self._rec_status)
        # Filename + conteggio righe
        self._rec_info = Label(text='Premi START per registrare un nuovo log',
                                 font_size=sp(15), color=MUTED,
                                 size_hint_y=None, height=dp(80),
                                 halign='center', valign='middle')
        self._rec_info.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        left.add_widget(self._rec_info)
        # Pulsante Start / Stop (cambia testo+colore in base allo stato)
        self._toggle_btn = mk_btn('START', self._toggle_log, sp(28))
        self._toggle_btn.size_hint_y = None
        self._toggle_btn.height = dp(80)
        left.add_widget(self._toggle_btn)
        # Spazio
        left.add_widget(Label(text='', size_hint_y=None, height=dp(8)))
        # Pulsante Invia al cloud (one-shot, abilitato solo se log fermo
        # e c'e' un last_path disponibile)
        left.add_widget(Label(text='INVIO AL BLOB STORAGE', font_size=sp(18),
                                color=ACCENT, bold=True,
                                size_hint_y=None, height=dp(36)))
        # Info: dove va caricato
        info_url = (f'Destinazione:\n{self.dm.blob_base or BLOB_BASE_DEFAULT}'
                    f'/{BLOB_CONTAINER_TRACKS}/{self.dm.cloud_boat_id}/<file>.csv')
        self._upload_dest_lbl = Label(text=info_url,
                                        font_size=sp(13), color=MUTED,
                                        size_hint_y=None, height=dp(60),
                                        halign='center', valign='middle')
        self._upload_dest_lbl.bind(
            size=lambda l, _: setattr(l, 'text_size', l.size))
        left.add_widget(self._upload_dest_lbl)
        self._upload_btn = mk_btn('Invia al cloud',
                                    self._upload_last_csv, sp(20))
        self._upload_btn.size_hint_y = None
        self._upload_btn.height = dp(70)
        self._upload_btn.disabled = True
        left.add_widget(self._upload_btn)
        # Status invio
        self._upload_status = Label(text='', font_size=sp(14),
                                      color=MUTED, halign='center',
                                      valign='top',
                                      size_hint_y=None, height=dp(60))
        self._upload_status.bind(
            size=lambda l, _: setattr(l, 'text_size', l.size))
        left.add_widget(self._upload_status)
        left.add_widget(Widget())
        outer.add_widget(left)

        # ---- COLONNA DESTRA: cloud upload live ----
        right = BoxLayout(orientation='vertical', spacing=dp(8),
                           padding=dp(12), size_hint_x=0.5)
        _bg(right, PANEL)
        right.add_widget(Label(text='CLOUD UPLOAD LIVE', font_size=sp(20),
                                 color=ACCENT, bold=True,
                                 size_hint_y=None, height=dp(40)))
        right.add_widget(Label(
            text='Invia uno snapshot HTTPS ogni N secondi al backend.\n'
                 'Il backend scrive su SQL Server (tabella "traks").',
            font_size=sp(13), color=MUTED,
            size_hint_y=None, height=dp(60),
            halign='center', valign='middle'))

        # Toggle ON/OFF (due pulsanti)
        en_row = BoxLayout(spacing=dp(6), size_hint_y=None, height=dp(60))
        self._cloud_on = mk_btn('ON',
                                  lambda: self._set_cloud_enabled(True),
                                  sp(20))
        self._cloud_off = mk_btn('OFF',
                                   lambda: self._set_cloud_enabled(False),
                                   sp(20))
        en_row.add_widget(self._cloud_on)
        en_row.add_widget(self._cloud_off)
        right.add_widget(en_row)

        # Selettore intervallo
        right.add_widget(Label(text='Frequenza upload:',
                                 font_size=sp(15), color=MUTED,
                                 size_hint_y=None, height=dp(28),
                                 halign='left', valign='middle'))
        fr_row = BoxLayout(spacing=dp(4), size_hint_y=None, height=dp(56))
        self._cloud_freq_btns = {}
        for secs, label in self.FREQ_CHOICES:
            b = mk_btn(label,
                        lambda s=secs: self._set_cloud_interval(s),
                        sp(16))
            self._cloud_freq_btns[secs] = b
            fr_row.add_widget(b)
        right.add_widget(fr_row)

        # Status cloud (multi-linea)
        right.add_widget(Label(text='Stato:',
                                 font_size=sp(15), color=MUTED,
                                 size_hint_y=None, height=dp(28),
                                 halign='left', valign='middle'))
        self._cloud_status = Label(text='--', font_size=sp(15),
                                     color=MUTED, halign='left', valign='top',
                                     size_hint_y=None, height=dp(180))
        self._cloud_status.bind(
            size=lambda l, _: setattr(l, 'text_size', l.size))
        _bg(self._cloud_status, BG)
        right.add_widget(self._cloud_status)

        # Pulsante "Invia ora" (forza un ciclo immediato)
        self._cloud_send_btn = mk_btn_gray('Invia subito',
                                             self._cloud_send_now, sp(16))
        self._cloud_send_btn.size_hint_y = None
        self._cloud_send_btn.height = dp(56)
        right.add_widget(self._cloud_send_btn)

        # ----- LOG ERRORI: invio al cloud dei log di errore -----
        # I log vengono raccolti automaticamente in {LOG_PATH}/errors/ con
        # un file al giorno. Il pulsante "Invia log oggi" carica il file
        # del giorno corrente nel container 'logs/{boat_id}/' del blob.
        # "Invia tutti" carica anche i file dei giorni precedenti.
        right.add_widget(Label(text='LOG ERRORI', font_size=sp(20),
                                color=ACCENT, bold=True,
                                size_hint_y=None, height=dp(40)))
        be = BoxLayout(spacing=dp(6), size_hint_y=None, height=dp(60))
        self._errlog_today_btn = mk_btn('Invia log oggi',
                                          self._upload_error_log_today, sp(16))
        self._errlog_all_btn   = mk_btn('Invia tutti',
                                          self._upload_error_log_all,   sp(16))
        be.add_widget(self._errlog_today_btn)
        be.add_widget(self._errlog_all_btn)
        right.add_widget(be)
        self._errlog_status = Label(text='--', font_size=sp(14),
                                      color=MUTED, halign='center',
                                      valign='middle',
                                      size_hint_y=None, height=dp(60))
        self._errlog_status.bind(
            size=lambda l, _: setattr(l, 'text_size', l.size))
        right.add_widget(self._errlog_status)

        right.add_widget(Widget())
        outer.add_widget(right)

        # Stato iniziale
        self._refresh_cloud_buttons()

    # ------------------------------------------------------------------
    # Registrazione locale
    # ------------------------------------------------------------------
    def _toggle_log(self, *_):
        tl = self.dm.track_logger
        if tl.is_active():
            tl.stop()
            self._upload_status.text = ''
        else:
            ok, msg = tl.start()
            if not ok:
                self._upload_status.text = f'Errore avvio: {msg}'
                self._upload_status.color = RED
        # Refresh subito (anche se tick lo fara' ad ogni ciclo)
        self._refresh_log_ui()

    def _refresh_log_ui(self):
        tl = self.dm.track_logger
        if tl.is_active():
            self._rec_status.text = 'IN REGISTRAZIONE'
            self._rec_status.color = GREEN
            fn = os.path.basename(tl.get_path() or '')
            started = tl.get_started_at()
            elapsed = ''
            if started:
                delta = (datetime.now() - started).total_seconds()
                m, s = int(delta // 60), int(delta % 60)
                elapsed = f' ({m:02d}:{s:02d})'
            self._rec_info.text = (f'File: {fn}{elapsed}\n'
                                     f'Righe scritte: {tl.get_count()}')
            self._rec_info.color = WHITE
            self._toggle_btn.text = 'STOP'
            self._toggle_btn.background_color = RED
            self._toggle_btn.color = (0, 0, 0, 1)
            # Disabilita upload mentre registriamo (file ancora aperto)
            self._upload_btn.disabled = True
        else:
            self._rec_status.text = 'Non in registrazione'
            self._rec_status.color = MUTED
            last = tl.get_last_path()
            cnt = tl.get_count()
            if last:
                fn = os.path.basename(last)
                self._rec_info.text = (f'Ultimo log: {fn}\n'
                                         f'Righe: {cnt}')
                self._rec_info.color = WHITE
                self._upload_btn.disabled = False
            else:
                self._rec_info.text = 'Premi START per registrare un nuovo log'
                self._rec_info.color = MUTED
                self._upload_btn.disabled = True
            self._toggle_btn.text = 'START'
            self._toggle_btn.background_color = BTN_GRAY
            self._toggle_btn.color = WHITE

    # ------------------------------------------------------------------
    # Upload one-shot del CSV al blob storage
    # ------------------------------------------------------------------
    def _upload_last_csv(self, *_):
        tl = self.dm.track_logger
        last = tl.get_last_path()
        if not last:
            self._upload_status.text = 'Nessun log da inviare'
            self._upload_status.color = ORANGE
            return
        if not (self.dm.blob_account_key or '').strip():
            self._upload_status.text = ('blob_account_key non configurata\n'
                                         '(modifica sailing_config.json)')
            self._upload_status.color = RED
            return
        # Disabilita pulsante e fai upload in thread separato
        self._upload_btn.disabled = True
        self._upload_status.text = 'Caricamento in corso...'
        self._upload_status.color = WHITE

        def _worker(path=last):
            try:
                ok, msg = self.dm.upload_csv_to_blob(path)
                Clock.schedule_once(
                    lambda dt, o=ok, m=msg: self._on_upload_done(o, m), 0)
            except Exception as e:
                import traceback
                print(f'_upload_last_csv CRASH:\n{traceback.format_exc()}')
                Clock.schedule_once(
                    lambda dt, m=f'{type(e).__name__}: {e}':
                        self._on_upload_done(False, m), 0)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_upload_done(self, ok, msg):
        if ok:
            self._upload_status.text = msg or 'OK'
            self._upload_status.color = GREEN
        else:
            self._upload_status.text = f'Errore: {msg}'
            self._upload_status.color = RED
        # Riabilita pulsante (anche su errore: l'utente puo' riprovare)
        self._upload_btn.disabled = False

    # ------------------------------------------------------------------
    # Cloud upload live (snapshot ogni N secondi)
    # ------------------------------------------------------------------
    def _set_cloud_enabled(self, enabled):
        self.dm.cloud_enabled = bool(enabled)
        self.dm.save_cfg_safe()
        if enabled:
            self.dm.cloud.start()
        else:
            self.dm.cloud.stop()
        self._refresh_cloud_buttons()

    def _set_cloud_interval(self, secs):
        if secs not in (30, 60, 120, 300, 600):
            return
        self.dm.cloud_interval_s = secs
        self.dm.save_cfg_safe()
        self._refresh_cloud_buttons()

    def _cloud_send_now(self, *_):
        ok, err = self.dm.cloud.trigger_now()
        if ok:
            self._cloud_status.text = (self._cloud_status.text +
                                          '\n[Invio manuale lanciato]')
        else:
            self._cloud_status.text = (self._cloud_status.text +
                                          f'\n[Attendi: {err}]')

    # ------------------------------------------------------------------
    # Upload log errori al cloud
    # ------------------------------------------------------------------
    def _upload_error_log_today(self, *_):
        """Pulsante 'Invia log oggi': PUT del file di errore odierno
        al container 'logs/{boat_id}/' del blob storage.

        Lavora in thread separato per non bloccare la UI (il file puo'
        essere grande in caso di molti crash)."""
        self._upload_error_log(only_today=True)

    def _upload_error_log_all(self, *_):
        """Pulsante 'Invia tutti': PUT di tutti i file di errore presenti
        in {LOG_PATH}/errors/, non solo quello di oggi."""
        self._upload_error_log(only_today=False)

    def _upload_error_log(self, only_today):
        """Implementazione comune per i due bottoni di upload log errori.
        Avvia un thread che chiama _error_logger.upload_to_blob() e aggiorna
        la label di stato col risultato."""
        self._errlog_status.text = ('Invio log oggi...' if only_today
                                     else 'Invio tutti i log...')
        self._errlog_status.color = MUTED

        dm = self.dm
        def _worker():
            try:
                ok, msg = _error_logger.upload_to_blob(
                    dm, only_today=only_today)
            except Exception as e:
                ok, msg = False, f'{type(e).__name__}: {e}'
                log_err(f'upload_error_log: {e}', exc=e)

            @mainthread
            def _update():
                self._errlog_status.text = msg or '--'
                self._errlog_status.color = GREEN if ok else ORANGE
            _update()
        threading.Thread(target=_worker, daemon=True).start()

    def _refresh_cloud_buttons(self):
        # ON/OFF
        if self.dm.cloud_enabled:
            self._cloud_on.background_color = GREEN
            self._cloud_on.color = (0, 0, 0, 1)
            self._cloud_off.background_color = BTN_GRAY
            self._cloud_off.color = WHITE
        else:
            self._cloud_on.background_color = BTN_GRAY
            self._cloud_on.color = WHITE
            self._cloud_off.background_color = RED
            self._cloud_off.color = (0, 0, 0, 1)
        # Frequenza
        cur = self.dm.cloud_interval_s
        for s, btn in self._cloud_freq_btns.items():
            if s == cur:
                btn.background_color = ACCENT
                btn.color = (0, 0, 0, 1)
            else:
                btn.background_color = BTN_GRAY
                btn.color = WHITE

    def _refresh_cloud_status(self):
        cu = self.dm.cloud
        running = cu.is_running()
        last_str = '--'
        if cu.last_sent_ts:
            last_str = datetime.fromtimestamp(
                cu.last_sent_ts).strftime('%H:%M:%S')
        qsize = cu.queue_size()
        state = ('ATTIVO' if (self.dm.cloud_enabled and running)
                 else 'INATTIVO')
        # Costruisco messaggio multi-linea
        lines = [f'Stato: {state}',
                 f'Inviati: {cu.sent_count}',
                 f'Ultimo: {last_str}',
                 f'In coda: {qsize}',
                 f'URL: {self.dm.cloud_url[:50]}...'
                    if len(self.dm.cloud_url) > 50 else
                    f'URL: {self.dm.cloud_url}']
        if cu.last_error:
            err_msg = cu.last_error[:120]
            lines.append(f'ERRORE: {err_msg}')
        self._cloud_status.text = '\n'.join(lines)
        # Colore status
        if not self.dm.cloud_enabled:
            self._cloud_status.color = MUTED
        elif cu.last_error:
            self._cloud_status.color = ORANGE
        else:
            self._cloud_status.color = GREEN

    def tick(self, dt):
        super().tick(dt)
        self._refresh_log_ui()
        self._refresh_cloud_status()
        self._refresh_errlog_status()

    def _refresh_errlog_status(self):
        """Aggiorna lo stato passivo del log errori (conteggio + ultimo).
        Lo facciamo SOLO se l'utente non ha appena cliccato un upload: in
        quel caso _errlog_status mostra "Invio log..." o l'esito, e non
        dobbiamo sovrascriverlo. Riconosciamo il caso "passivo" dai
        prefissi transient che impostiamo noi."""
        try:
            current = self._errlog_status.text
            transient_prefixes = ('Invio log', 'Invio tutti')
            if any(current.startswith(p) for p in transient_prefixes):
                return
            cnt = _error_logger.count
            last_msg = _error_logger.last_error_msg
            last_ts = _error_logger.last_error_ts
            if cnt == 0:
                self._errlog_status.text = 'Nessun errore registrato'
                self._errlog_status.color = GREEN
            else:
                age = ''
                if last_ts:
                    sec = max(0, int(time.time() - last_ts))
                    if sec < 60: age = f' ({sec}s fa)'
                    elif sec < 3600: age = f' ({sec//60}m fa)'
                    else: age = f' ({sec//3600}h fa)'
                short = (last_msg or '')[:50]
                self._errlog_status.text = (
                    f'{cnt} errori catturati{age}\nUltimo: {short}')
                self._errlog_status.color = ORANGE
        except Exception:
            pass


# =============================================================================
# 7 -- METEO PREVISIONALE PER REGATA
# =============================================================================
# Schermata che visualizza le previsioni meteo per la regata caricate da
# Azure Blob Storage. Il file sorgente e':
#   {blob_base}/meteo/{cloud_boat_id}/forecast.json
#
# Il file e' generato dal backend (script periodico che chiama Open-Meteo)
# e contiene previsioni gia' pre-elaborate per i waypoint della barca.
#
# Formato JSON atteso (compatibile con il sito web in frontend/weather.js):
# {
#   "generated_at": "2026-05-08T14:00:00Z",      # ISO timestamp generazione
#   "boat_id": "soar",
#   "model": "AROME HD",                          # nome modello meteo usato
#   "reference_time": "2026-05-09T10:00:00Z",     # data partenza regata (opt)
#   "thresholds": {                               # soglie alert (opt)
#       "wind": 22, "gust": 28, "wave": 2.0, "precip": 2.0
#   },
#   "waypoints": [
#     {
#       "name": "Pin",
#       "lat": 45.66, "lon": 13.78,
#       "horizons": {                             # 4 orizzonti rispetto a ref_time
#           "0":  {"ts": "...", "wind_speed": 12.0, "wind_direction": 280,
#                  "wind_gusts": 18.0, "wave_height": 0.5,
#                  "precipitation": 0, "temperature": 18},
#           "6":  {...},
#           "12": {...},
#           "24": {...}
#       }
#     },
#     ...
#   ]
# }
#
# La schermata mostra:
# 1. Card riassuntive lungo la rotta (+0/+6/+12/+24h): vento medio, raffica
#    max, onda media, classe Beaufort colorata, badge ALERT se soglia superata.
# 2. Tabella per waypoint con valori a +0h e +12h.
# 3. Pulsante "Aggiorna" per ricaricare il file da blob storage.
# =============================================================================

class WeatherScreen(TabScreen):
    """Schermata Meteo: previsioni precaricate da blob storage.

    Layout:
    - Header: nome modello + timestamp generazione + data partenza + pulsante Aggiorna
    - Card +0h / +6h / +12h / +24h con vento/onda/pioggia medi sulla rotta
    - Tabella waypoint con valori a +0h e +12h
    """
    # 4 orizzonti previsti nelle card (in ore dal reference_time)
    HORIZONS = (0, 6, 12, 24)

    # Soglie default per badge ALERT (sovrascritte da forecast['thresholds'])
    DEFAULT_THR = {'wind': 22.0, 'gust': 28.0, 'wave': 2.0, 'precip': 2.0}

    # Categorie Beaufort -> colore card (gradiente di sfondo)
    # Identico al frontend (weather.js -> windClass) per coerenza grafica.
    @staticmethod
    def wind_class_color(kn):
        """Tinta del background card in base al vento (kn).
        Restituisce (r, g, b, a) RGBA float 0..1."""
        if kn is None:
            return (0.10, 0.13, 0.20, 1)        # grigio scuro neutro
        if kn < 5:    return (0.13, 0.18, 0.26, 1)   # calm
        if kn < 11:   return (0.13, 0.23, 0.18, 1)   # light
        if kn < 17:   return (0.16, 0.25, 0.13, 1)   # mod
        if kn < 22:   return (0.27, 0.24, 0.10, 1)   # fresh
        if kn < 28:   return (0.32, 0.20, 0.09, 1)   # strong
        if kn < 34:   return (0.35, 0.13, 0.10, 1)   # near gale
        return (0.30, 0.06, 0.06, 1)                  # gale+

    @staticmethod
    def deg_to_cardinal(deg):
        """Direzione in gradi (0=N) -> punto cardinale stringa breve."""
        if deg is None:
            return '--'
        dirs = ('N','NNE','NE','ENE','E','ESE','SE','SSE',
                'S','SSW','SW','WSW','W','WNW','NW','NNW')
        idx = int(round(((deg % 360) + 360) % 360 / 22.5)) % 16
        return dirs[idx]

    def __init__(self, dm, **kw):
        super().__init__(dm, 'Meteo  Previsioni', name='weather', **kw)
        self._forecast = None     # dict caricato dal blob (None = non caricato)
        self._last_err = None
        self._loading = False
        self._build()

    def _build(self):
        # Layout: colonna unica, scrollabile per tablet piu' piccoli.
        from kivy.uix.scrollview import ScrollView
        outer = BoxLayout(orientation='vertical', spacing=dp(8),
                           padding=dp(8), size_hint=(1, 1))
        self.body.add_widget(outer)

        # ---- HEADER: pulsante refresh + label stato ----
        hdr = BoxLayout(orientation='horizontal', spacing=dp(8),
                         size_hint_y=None, height=dp(60))
        self._refresh_btn = mk_btn('Aggiorna previsione',
                                    self._do_refresh, sp(18))
        hdr.add_widget(self._refresh_btn)
        outer.add_widget(hdr)

        self._status_lbl = Label(
            text='(Premi "Aggiorna previsione" per scaricare il forecast.)',
            font_size=sp(15), color=MUTED,
            size_hint_y=None, height=dp(40),
            halign='center', valign='middle')
        self._status_lbl.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        outer.add_widget(self._status_lbl)

        self._meta_lbl = Label(
            text='', font_size=sp(13), color=MUTED,
            size_hint_y=None, height=dp(36),
            halign='center', valign='middle')
        self._meta_lbl.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        outer.add_widget(self._meta_lbl)

        # ---- BODY scrollabile ----
        self._scroll = ScrollView(size_hint=(1, 1),
                                    do_scroll_x=False, do_scroll_y=True)
        self._body_box = BoxLayout(orientation='vertical', spacing=dp(10),
                                     size_hint_y=None)
        self._body_box.bind(minimum_height=self._body_box.setter('height'))
        self._scroll.add_widget(self._body_box)
        outer.add_widget(self._scroll)

        # All'avvio: prova caricamento automatico se il file e' gia'
        # disponibile nel cache locale (futuro). Per ora resta vuoto.

    # -------------------------------------------------------------------
    # Refresh handler: scarica il file forecast.json dal blob.
    # -------------------------------------------------------------------
    def _do_refresh(self, *_):
        if self._loading:
            return
        url = self.dm.download_meteo_url()
        if not url:
            self._set_status('cloud_boat_id non configurato in sailing_config.json',
                              RED)
            return
        if not (self.dm.blob_account_key or '').strip():
            self._set_status('blob_account_key non configurata.', RED)
            return
        self._loading = True
        self._refresh_btn.disabled = True
        self._set_status(f'Scaricamento da:\n{url[:80]}...', WHITE)

        def _worker():
            try:
                ok, data = self.dm._http_get_json(url, timeout=20)
                if ok:
                    Clock.schedule_once(
                        lambda dt, d=data: self._on_loaded(d), 0)
                else:
                    Clock.schedule_once(
                        lambda dt, m=str(data): self._on_error(m), 0)
            except Exception as e:
                import traceback
                print(f'WeatherScreen worker CRASH:\n{traceback.format_exc()}')
                Clock.schedule_once(
                    lambda dt, m=f'{type(e).__name__}: {e}': self._on_error(m),
                    0)
            finally:
                Clock.schedule_once(lambda dt: self._unlock_refresh(), 0)

        threading.Thread(target=_worker, daemon=True).start()

    def _unlock_refresh(self):
        self._loading = False
        self._refresh_btn.disabled = False

    def _on_error(self, msg):
        self._last_err = msg
        self._set_status(f'Errore download:\n{msg}', RED)
        # Tieni la UI vuota / mantenuta: non azzero le card precedenti
        # cosi' si vede ancora la previsione vecchia se c'era.

    def _on_loaded(self, data):
        """Validazione di base + render UI."""
        if not isinstance(data, dict):
            return self._on_error('JSON non e\' un oggetto')
        wps = data.get('waypoints')
        if not isinstance(wps, list) or not wps:
            return self._on_error('forecast.json: campo "waypoints" mancante o vuoto')
        # OK: salva e renderizza
        self._forecast = data
        self._last_err = None
        self._render_meta()
        self._render_cards()
        self._render_table()
        n_wp = len(wps)
        self._set_status(f'Previsione caricata: {n_wp} waypoint, '
                          f'{len(self.HORIZONS)} orizzonti.', GREEN)

    def _set_status(self, text, color):
        try:
            self._status_lbl.text = text
            self._status_lbl.color = color
        except Exception:
            pass

    # -------------------------------------------------------------------
    # Rendering
    # -------------------------------------------------------------------
    def _render_meta(self):
        f = self._forecast or {}
        gen = f.get('generated_at', '?')
        model = f.get('model', '?')
        ref = f.get('reference_time', '')
        # Mostro orario generazione in formato leggibile (gg/mm hh:mm)
        gen_disp = gen
        try:
            # Parsing ISO 8601 senza external libs
            from datetime import datetime
            dt = datetime.fromisoformat(gen.replace('Z', '+00:00'))
            gen_disp = dt.strftime('%d/%m %H:%M')
        except Exception:
            pass
        line = f'Modello: {model}    Generato: {gen_disp}'
        if ref:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(ref.replace('Z', '+00:00'))
                line += f'    Partenza: {dt.strftime("%d/%m %H:%M")}'
            except Exception:
                line += f'    Partenza: {ref}'
        self._meta_lbl.text = line

    def _render_cards(self):
        """Crea 4 card (+0/+6/+12/+24h) con valori medi lungo la rotta."""
        # Sezione titolo
        self._body_box.clear_widgets()
        title = Label(text='Riepilogo lungo la rotta',
                        font_size=sp(18), color=ACCENT, bold=True,
                        size_hint_y=None, height=dp(34),
                        halign='left', valign='middle')
        title.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        self._body_box.add_widget(title)

        # Card row: 4 card affiancate (responsive: il tablet e' largo)
        cards = BoxLayout(orientation='horizontal', spacing=dp(8),
                           size_hint_y=None, height=dp(170))
        thr = (self._forecast.get('thresholds') or self.DEFAULT_THR)
        for h in self.HORIZONS:
            agg = self._aggregate_horizon(h)
            cards.add_widget(self._make_card(h, agg, thr))
        self._body_box.add_widget(cards)

    def _aggregate_horizon(self, hours):
        """Aggrega vento/onda/pioggia su tutti i waypoint per un orizzonte.
        Usa media vettoriale per la direzione (sin/cos) per evitare wraparound."""
        wps = self._forecast.get('waypoints') or []
        speeds, gusts, waves, precs, dirs_sin, dirs_cos = [], [], [], [], [], []
        n_dir = 0
        for wp in wps:
            hh = (wp.get('horizons') or {}).get(str(hours))
            if not hh:
                continue
            ws = hh.get('wind_speed')
            wg = hh.get('wind_gusts')
            wd = hh.get('wind_direction')
            wave = hh.get('wave_height')
            pr = hh.get('precipitation')
            if ws is not None: speeds.append(ws)
            if wg is not None: gusts.append(wg)
            if wave is not None: waves.append(wave)
            if pr is not None: precs.append(pr)
            if wd is not None:
                rad = math.radians(wd)
                dirs_sin.append(math.sin(rad))
                dirs_cos.append(math.cos(rad))
                n_dir += 1
        out = {
            'wind_speed':    (sum(speeds) / len(speeds)) if speeds else None,
            'wind_gusts':    max(gusts) if gusts else None,   # max raffica, non media
            'wave_height':   (sum(waves) / len(waves)) if waves else None,
            'precipitation': (sum(precs) / len(precs)) if precs else None,
            'wind_direction': None,
        }
        if n_dir:
            ds = sum(dirs_sin) / n_dir
            dc = sum(dirs_cos) / n_dir
            out['wind_direction'] = (math.degrees(math.atan2(ds, dc)) + 360) % 360
        return out

    def _make_card(self, hours, agg, thr):
        """Crea il widget visuale per UNA card orizzonte.
        Layout verticale: titolo orizzonte / vento + freccia / raffica / onda+pioggia."""
        # Sfondo colorato in base alla classe vento
        from kivy.graphics import Color, RoundedRectangle
        ws = agg.get('wind_speed')
        bg = self.wind_class_color(ws)
        # Alert: una qualsiasi soglia superata?
        alert = self._check_alert(agg, thr)

        card = BoxLayout(orientation='vertical', spacing=dp(2),
                          padding=dp(8), size_hint_y=None, height=dp(170))
        with card.canvas.before:
            Color(*bg)
            card._bg_rect = RoundedRectangle(pos=card.pos, size=card.size,
                                              radius=[dp(6)])
            # Bordo: rosso se alert, sottile altrimenti
            if alert:
                Color(0.85, 0.20, 0.15, 1)
            else:
                Color(0.30, 0.40, 0.55, 0.5)
            card._bg_border = RoundedRectangle(
                pos=card.pos, size=card.size, radius=[dp(6)])
        # Aggiorna il rettangolo quando il widget si riposiziona
        def _upd_rect(w, *_):
            try:
                card._bg_rect.pos = w.pos; card._bg_rect.size = w.size
                card._bg_border.pos = w.pos; card._bg_border.size = w.size
            except Exception: pass
        card.bind(pos=_upd_rect, size=_upd_rect)

        # Header riga: orizzonte + badge ALERT se serve
        h_row = BoxLayout(orientation='horizontal',
                           size_hint_y=None, height=dp(22))
        hrz_lbl = Label(text=f'+{hours}h', font_size=sp(15), bold=True,
                         color=ACCENT, halign='left', valign='middle')
        hrz_lbl.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        h_row.add_widget(hrz_lbl)
        if alert:
            al = Label(text='[ALERT]', font_size=sp(13), bold=True,
                        color=RED, halign='right', valign='middle')
            al.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
            h_row.add_widget(al)
        card.add_widget(h_row)

        # Vento principale (grande): "12 kn  W"
        if ws is not None:
            wd_str = self.deg_to_cardinal(agg.get('wind_direction'))
            txt = f'{ws:.0f} kn  {wd_str}'
        else:
            txt = '-- kn'
        wind_lbl = Label(text=txt, font_size=sp(28), bold=True, color=WHITE,
                          size_hint_y=None, height=dp(40),
                          halign='center', valign='middle')
        wind_lbl.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        card.add_widget(wind_lbl)

        # Raffica
        wg = agg.get('wind_gusts')
        gust_txt = f'Raffica max: {wg:.0f} kn' if wg is not None else 'Raffica: --'
        gust_color = RED if (wg and wg >= thr.get('gust', 28)) else MUTED
        gust_lbl = Label(text=gust_txt, font_size=sp(13), color=gust_color,
                          size_hint_y=None, height=dp(20),
                          halign='center', valign='middle')
        gust_lbl.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        card.add_widget(gust_lbl)

        # Onda + pioggia
        wave = agg.get('wave_height')
        prec = agg.get('precipitation')
        wave_str = f'{wave:.1f}m' if wave is not None else '--'
        prec_str = f'{prec:.1f}mm/h' if prec is not None else '--'
        oc_color = WHITE
        if (wave and wave >= thr.get('wave', 2.0)) or \
           (prec and prec >= thr.get('precip', 2.0)):
            oc_color = ORANGE
        oc_lbl = Label(text=f'Onda: {wave_str}    Pioggia: {prec_str}',
                        font_size=sp(13), color=oc_color,
                        size_hint_y=None, height=dp(20),
                        halign='center', valign='middle')
        oc_lbl.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        card.add_widget(oc_lbl)
        return card

    def _check_alert(self, agg, thr):
        """True se almeno UNA metrica supera la soglia corrispondente."""
        ws = agg.get('wind_speed')
        wg = agg.get('wind_gusts')
        wave = agg.get('wave_height')
        prec = agg.get('precipitation')
        if ws is not None and ws >= thr.get('wind', 22.0):    return True
        if wg is not None and wg >= thr.get('gust', 28.0):    return True
        if wave is not None and wave >= thr.get('wave', 2.0): return True
        if prec is not None and prec >= thr.get('precip', 2.0): return True
        return False

    def _render_table(self):
        """Tabella con dettaglio per waypoint a +0h e +12h.
        Colonne: Waypoint | +0h: vento (kn) dir / raffica / onda
                          | +12h: vento (kn) dir / raffica / onda"""
        # Sezione titolo
        title = Label(text='Dettaglio per waypoint (+0h / +12h)',
                        font_size=sp(18), color=ACCENT, bold=True,
                        size_hint_y=None, height=dp(34),
                        halign='left', valign='middle')
        title.bind(size=lambda l, _: setattr(l, 'text_size', l.size))
        self._body_box.add_widget(title)

        from kivy.uix.gridlayout import GridLayout
        thr = (self._forecast.get('thresholds') or self.DEFAULT_THR)
        wps = self._forecast.get('waypoints') or []
        # Header + righe = (1 + len(wps))
        n_rows = 1 + len(wps)
        grid = GridLayout(cols=4, size_hint_y=None,
                           row_default_height=dp(32),
                           row_force_default=True,
                           spacing=(dp(2), dp(2)))
        grid.height = dp(32) * n_rows + dp(2) * (n_rows - 1)

        def _hdr(text):
            l = Label(text=text, font_size=sp(13), bold=True, color=ACCENT,
                       halign='center', valign='middle')
            l.bind(size=lambda lab, _: setattr(lab, 'text_size', lab.size))
            return l

        def _cell(text, color=WHITE):
            l = Label(text=text, font_size=sp(13), color=color,
                       halign='center', valign='middle')
            l.bind(size=lambda lab, _: setattr(lab, 'text_size', lab.size))
            return l

        grid.add_widget(_hdr('Waypoint'))
        grid.add_widget(_hdr('+0h vento/raff.'))
        grid.add_widget(_hdr('+12h vento/raff.'))
        grid.add_widget(_hdr('Onda max'))

        for wp in wps:
            name = wp.get('name', '?')
            hh = wp.get('horizons') or {}
            h0 = hh.get('0') or {}
            h12 = hh.get('12') or {}
            # +0h cell
            ws0 = h0.get('wind_speed'); wg0 = h0.get('wind_gusts')
            wd0 = h0.get('wind_direction')
            txt0 = '--'
            if ws0 is not None:
                txt0 = f'{ws0:.0f}/{wg0:.0f} kn' if wg0 is not None else f'{ws0:.0f} kn'
                txt0 += f' {self.deg_to_cardinal(wd0)}'
            color0 = RED if (ws0 and ws0 >= thr.get('wind', 22.0)) else WHITE
            # +12h cell
            ws12 = h12.get('wind_speed'); wg12 = h12.get('wind_gusts')
            wd12 = h12.get('wind_direction')
            txt12 = '--'
            if ws12 is not None:
                txt12 = (f'{ws12:.0f}/{wg12:.0f} kn'
                         if wg12 is not None else f'{ws12:.0f} kn')
                txt12 += f' {self.deg_to_cardinal(wd12)}'
            color12 = RED if (ws12 and ws12 >= thr.get('wind', 22.0)) else WHITE
            # Onda max tra h0 e h12
            wave_max = None
            for hd in (h0, h12):
                w = hd.get('wave_height')
                if w is not None:
                    wave_max = w if wave_max is None else max(wave_max, w)
            wave_txt = f'{wave_max:.1f}m' if wave_max is not None else '--'
            wave_color = (RED if (wave_max and wave_max >= thr.get('wave', 2.0))
                          else WHITE)

            grid.add_widget(_cell(name))
            grid.add_widget(_cell(txt0, color0))
            grid.add_widget(_cell(txt12, color12))
            grid.add_widget(_cell(wave_txt, wave_color))

        self._body_box.add_widget(grid)

    def tick(self, dt):
        # La WeatherScreen non ha aggiornamenti realtime; refresh manuale via
        # pulsante "Aggiorna previsione". Tick e' no-op qui.
        pass



# =============================================================================
# 8 -- IMPOSTAZIONI
# =============================================================================

class SettingsScreen(TabScreen):
    def __init__(self,dm,**kw):
        super().__init__(dm,'Set  Impostazioni',name='settings',**kw)
        self._build()

    def _build(self):
        self._cols=BoxLayout(orientation='horizontal',spacing=dp(8),
                              size_hint=(1,1))
        self.body.add_widget(self._cols)

        # COLONNA SINISTRA: NMEA + TATTICA + PERCORSI FILE (tutti read-only)
        left=BoxLayout(orientation='vertical',spacing=dp(10),
                        padding=dp(14),size_hint_x=0.55)
        _bg(left,PANEL)
        left.add_widget(Label(text='NMEA TCP',font_size=sp(18),color=ACCENT,
                               bold=True,size_hint_y=None,height=dp(36)))
        # IP/Porta editabili (gli altri parametri restano read-only)
        self._ip   = self._field(left, 'IP Server:', str(self.dm.nmea_ip))
        self._port = self._field(left, 'Porta:',     str(self.dm.nmea_port), 'number')
        self._conn=Label(text='Non connesso',font_size=sp(20),color=RED,
                          bold=True,size_hint_y=None,height=dp(46))
        left.add_widget(self._conn)
        br=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(70))
        br.add_widget(mk_btn_gray('Connetti',    self._connect,    sp(18)))
        br.add_widget(mk_btn_gray('Disconnetti', self._disconnect, sp(18)))
        left.add_widget(br)

        # SEZIONE TATTICA: finestra temporale per il calcolo del TWD medio
        left.add_widget(Label(text='TATTICA',font_size=sp(18),color=ACCENT,
                               bold=True,size_hint_y=None,height=dp(36)))
        self._twd_btns = {}
        twd_row = BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(60))
        for m in (2, 5, 10, 15, 20):
            b = mk_btn(f'{m}m', lambda mm=m: self._set_twd_window(mm), sp(18))
            self._twd_btns[m] = b
            twd_row.add_widget(b)
        left.add_widget(twd_row)
        self._refresh_twd_buttons()

        # PERCORSI FILE: pulsanti utility, niente preview path (vedi "Mostra path completo")
        left.add_widget(Label(text='CONFIGURAZIONE',font_size=sp(18),color=ACCENT,
                               bold=True,size_hint_y=None,height=dp(36)))
        sv_row=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(70))
        sv_row.add_widget(mk_btn_gray('Salva configurazione', self._save_cfg,    sp(18)))
        sv_row.add_widget(mk_btn_gray('Path default',         self._reset_paths, sp(18)))
        left.add_widget(sv_row)

        # NOTA: la sezione Azure Blob e' stata rimossa dalla UI per richiesta
        # utente. Tutti i parametri sono editabili SOLO via sailing_config.json.
        # Defaults applicati al primo avvio:
        #   - cloud_boat_id    = 'soar'
        #   - blob_base        = 'https://sailingapp.blob.core.windows.net'
        #   - blob_account_key = chiave master dello storage account

        left.add_widget(Widget())
        self._cols.add_widget(left)

        # COLONNA DESTRA: utility (CLOUD UPLOAD spostato in LoggingScreen v1.18)
        info=BoxLayout(orientation='vertical',spacing=dp(8),
                        padding=dp(14),size_hint_x=0.45)
        _bg(info,PANEL)
        info.add_widget(Label(text='UTILITY',font_size=sp(18),color=ACCENT,
                               bold=True,size_hint_y=None,height=dp(36)))
        info.add_widget(Label(
            text='Le impostazioni CLOUD UPLOAD (snapshot live verso il database\n'
                 'SQL del backend) sono ora nella schermata LOG. Qui restano\n'
                 'solo i pulsanti diagnostici.',
            font_size=sp(14), color=MUTED,
            size_hint_y=None, height=dp(120),
            halign='left', valign='top'))
        # Tre pulsanti azione su un'unica riga
        action_row=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(60))
        action_row.add_widget(mk_btn_gray('Valori path', self._show_path,  sp(14)))
        action_row.add_widget(mk_btn_gray('Ric. conf',   self._reload_cfg, sp(14)))
        info.add_widget(action_row)
        info.add_widget(Widget())
        self._cols.add_widget(info)

    def _do_resize(self,dt): pass

    def _show_path(self):
        """Popup grande con path + valori in memoria, per debug."""
        dm = self.dm
        cfg_size = '?'
        cfg_raw = '(file non trovato)'
        try:
            if os.path.isfile(dm.config_path):
                cfg_size = f'{os.path.getsize(dm.config_path)} byte'
                with open(dm.config_path) as f:
                    cfg_raw = f.read()
        except Exception as e:
            cfg_raw = f'(errore lettura: {e})'
        # Stato file waypoints.json
        if os.path.isfile(WAYPOINTS_PATH):
            wpts_status = f'presente ({os.path.getsize(WAYPOINTS_PATH)} byte)'
        else:
            wpts_status = '(non presente — usa quelli del config)'
        # Valori effettivamente in memoria (dopo _load_cfg)
        bid_disp = dm.cloud_boat_id if dm.cloud_boat_id else '(VUOTO)'
        tok_disp = '(impostato)' if dm.cloud_token else '(VUOTO)'
        msg = (f"--- PATH ---\n"
                f"Config:     {dm.config_path}  ({cfg_size})\n"
                f"Polare:     {dm.polar_path}\n"
                f"Waypoints:  {WAYPOINTS_PATH}\n"
                f"            {wpts_status}\n"
                f"Log:        {dm.log_dir}\n"
                f"Coda:       {dm.cloud.queue_path}\n\n"
                f"--- VALORI IN MEMORIA ---\n"
                f"NMEA:        {dm.nmea_ip}:{dm.nmea_port}\n"
                f"TWD window:  {dm.twd_window_minutes} min\n"
                f"Cloud:       {'ON' if dm.cloud_enabled else 'OFF'} ({dm.cloud_interval_s}s)\n"
                f"Cloud URL:   {dm.cloud_url}\n"
                f"Cloud BoatID:{bid_disp}\n"
                f"Cloud Token: {tok_disp}\n"
                f"Waypoints:   {len(dm.waypoints)}\n"
                f"Boa attiva:  {dm.target_mark or '(nessuna)'}\n\n"
                f"--- FILE GREZZO sul disco ---\n"
                f"{cfg_raw}")
        # Uso ScrollView se il testo e' lungo
        sv=ScrollView(do_scroll_x=False)
        lbl=Label(text=msg,font_size=sp(12),halign='left',valign='top',
                   size_hint_y=None)
        lbl.bind(width=lambda l,w: setattr(l,'text_size',(w,None)),
                 texture_size=lambda l,ts: setattr(l,'height',ts[1]))
        sv.add_widget(lbl)
        Popup(title='Configurazione attuale',content=sv,
              size_hint=(0.95,0.92)).open()

    def _reload_cfg(self):
        """Ricarica il config dal file, utile dopo edit manuale del JSON."""
        try:
            self.dm._load_cfg()
            # Aggiorna le label read-only nella UI
            self._ip.text   = str(self.dm.nmea_ip)
            self._port.text = str(self.dm.nmea_port)
            # boat_id, blob_base e blob_account_key: solo via JSON, niente UI
            self._refresh_twd_buttons()
            Popup(title='OK',
                  content=Label(text='Config ricaricato dal file.\n'
                                       'Tap "Valori path" per\n'
                                       'verificare i valori in memoria.'),
                  size_hint=(0.6,0.3)).open()
        except Exception as e:
            Popup(title='Errore ricarica',
                  content=Label(text=f'{type(e).__name__}: {e}'),
                  size_hint=(0.6,0.3)).open()

    def _request_storage(self):
        """Richiede permessi storage runtime (Android 6+).
        Necessario per leggere/scrivere fuori dalla sandbox dell'app
        (es. /sdcard/Download, /sdcard/Documents)."""
        if not IS_ANDROID:
            return
        try:
            from android.permissions import request_permissions, Permission
            request_permissions([
                Permission.READ_EXTERNAL_STORAGE,
                Permission.WRITE_EXTERNAL_STORAGE,
            ])
            Popup(title='Permessi richiesti',
                  content=Label(text='Concedi i permessi nel popup di sistema,\n'
                                      'poi tocca Salva tutto e riavvia.'),
                  size_hint=(0.6,0.30)).open()
        except Exception as e:
            Popup(title='Errore permessi',content=Label(text=str(e)),
                  size_hint=(0.5,0.25)).open()

    def _reset_paths(self):
        """Riporta i path ai default (cartella dati app) e salva subito."""
        self.dm.polar_path = POLAR_PATH
        self.dm.log_dir    = LOG_PATH
        self.dm.save_cfg_safe()
        Popup(title='OK',content=Label(text='Path ripristinati ai default.'),
              size_hint=(0.4,0.20)).open()

    def _save_cfg(self):
        """Forza la riscrittura del file di configurazione con i valori
        attualmente in memoria. Prima committa eventuali modifiche dei campi
        editabili (IP, Porta, Boat ID, Blob base) al DataManager. In caso di
        errore mostra un popup con la diagnostica completa per facilitare il
        debug sul tablet."""
        # 1) COMMIT dei campi UI editabili al DataManager.
        # Senza questo step, le modifiche fatte nei TextInput vanno perse al
        # salvataggio (rimangono solo nei widget, non nel dm).
        try:
            self.dm.nmea_ip = self._ip.text.strip()
            try:
                self.dm.nmea_port = int(self._port.text.strip())
            except ValueError:
                self.dm.nmea_port = self._port.text.strip()  # tieni come stringa, _load_cfg gestira'
            # boat_id, blob_base e SAS token: gestiti SOLO via sailing_config.json
            # (no UI). Restano i valori caricati in memoria.
        except Exception as e:
            print(f'_save_cfg commit fields: {e}')

        # 2) Salva
        try:
            # Uso save_cfg() (non _safe) per ricevere l'eccezione e mostrarla
            self.dm.save_cfg()
            cfg = self.dm.config_path
            if os.path.isfile(cfg) and os.path.getsize(cfg) > 0:
                # Mostro nel popup anche un breve sommario di cosa e' stato salvato
                summary = (f'IP: {self.dm.nmea_ip}:{self.dm.nmea_port}\n'
                            f'TWD window: {self.dm.twd_window_minutes} min\n'
                            f'Cloud: {"ON" if self.dm.cloud_enabled else "OFF"} '
                            f'({self.dm.cloud_interval_s} s)\n'
                            f'Boat ID: {self.dm.cloud_boat_id or "(vuoto)"}')
                msg = (f'Salvato {os.path.getsize(cfg)} byte in:\n{cfg}\n\n'
                        f'{summary}')
                Popup(title='OK',content=Label(text=msg,halign='left',valign='top'),
                      size_hint=(0.8,0.45)).open()
            else:
                d = self.dm.cfg_diagnostics()
                msg = ('Salva: nessuna eccezione ma file mancante.\n\n'
                        + '\n'.join(f'{k}: {v}' for k,v in d.items()))
                Popup(title='Errore (silente)',content=Label(text=msg),
                      size_hint=(0.85,0.45)).open()
        except Exception as e:
            d = self.dm.cfg_diagnostics()
            msg = (f'Errore nel salvataggio:\n{type(e).__name__}: {e}\n\n'
                    + '\n'.join(f'{k}: {v}' for k,v in d.items()))
            lbl = Label(text=msg,halign='left',valign='top',font_size=sp(13))
            lbl.bind(size=lbl.setter('text_size'))
            Popup(title='Errore salvataggio',content=lbl,
                  size_hint=(0.9,0.55)).open()

    def _set_twd_window(self, minutes):
        """Imposta la finestra di analisi TWD (2/5/10/15/20 minuti) e
        salva immediatamente nel config."""
        if minutes not in (2, 5, 10, 15, 20):
            return
        self.dm.twd_window_minutes = minutes
        self._refresh_twd_buttons()
        # Salvo subito perche' e' un setting che vuole essere persistente
        # senza richiedere "Salva tutto"
        self.dm.save_cfg_safe()

    def _refresh_twd_buttons(self):
        """Evidenzia il pulsante della finestra TWD attualmente selezionata."""
        cur = getattr(self.dm, 'twd_window_minutes', 5)
        for m, btn in self._twd_btns.items():
            if m == cur:
                btn.background_color = ACCENT
                btn.color = (0, 0, 0, 1)  # nero per contrasto su accento
            else:
                btn.background_color = BTN_GRAY
                btn.color = WHITE

    # ---- Cloud upload helpers ----

    # NOTA: i metodi _set_cloud_enabled, _set_cloud_freq, _refresh_cloud_buttons,
    # _cloud_send_now sono stati spostati nella LoggingScreen (v1.18) insieme
    # all'intera UI di gestione cloud.

    def _reset_cloud_url(self):
        """Ripristina l'URL del webhook di default e salva nel config."""
        self.dm.cloud_url = CLOUD_URL_DEFAULT
        self.dm.save_cfg_safe()

    def _readonly_value_row(self,parent,label,value,font_value=None):
        """Riga generica con label sx + valore in sola lettura.
        Tap apre il popup 'Mostra path completo' che riassume tutti i settaggi."""
        row=BoxLayout(spacing=dp(8),size_hint_y=None,height=dp(64))
        row.add_widget(Label(text=label,font_size=sp(18),color=MUTED,
                              size_hint_x=0.30,halign='right',valign='middle'))
        b=Button(text=str(value),font_size=font_value or sp(15),
                  color=WHITE,background_color=PANEL,
                  background_normal='',halign='left',valign='middle')
        b.bind(size=lambda l,_: setattr(l,'text_size',l.size))
        b.bind(on_release=lambda _: self._show_path())
        row.add_widget(b); parent.add_widget(row); return b

    def _mask_token(self, token):
        """Maschera il token per non mostrarlo in chiaro a video.
        Mostra solo i primi 4 e ultimi 4 caratteri."""
        if not token: return '(non impostato)'
        if len(token) <= 8: return '*' * len(token)
        return f'{token[:4]}...{token[-4:]}  ({len(token)} car.)'

    def _field(self,parent,label,value,kbtype='text'):
        """Campo testo editabile (label sx + TextInput dx)."""
        row=BoxLayout(spacing=dp(8),size_hint_y=None,height=dp(64))
        row.add_widget(Label(text=label,font_size=sp(18),color=MUTED,
                              size_hint_x=0.30,halign='right',valign='middle'))
        inp=TextInput(text=value,multiline=False,input_type=kbtype,
                       font_size=sp(16),size_hint_y=None,height=dp(54))
        row.add_widget(inp); parent.add_widget(row); return inp

    def _connect(self):
        """Legge IP/Porta dai campi editabili, persiste nel config e connetti."""
        ip   = self._ip.text.strip()
        port_s = self._port.text.strip()
        try: port = int(port_s)
        except: port = 10110
        # Aggiorna dm + persisti subito nel config.json
        self.dm.nmea_ip   = ip
        self.dm.nmea_port = port
        self.dm.save_cfg_safe()
        ok = self.dm.connect(ip, port)
        self._conn.text  = 'Connesso' if ok else 'Connessione fallita'
        self._conn.color = GREEN if ok else RED

    def _disconnect(self):
        self.dm.disconnect(); self._conn.text='Disconnesso'; self._conn.color=MUTED

    def tick(self,dt):
        super().tick(dt)
        if self.dm.connected: self._conn.text='Connesso'; self._conn.color=GREEN
        else: self._conn.text='Non connesso'; self._conn.color=RED
        # NOTA: aggiornamento status cloud rimosso v1.18: la UI cloud e' stata
        # spostata nella LoggingScreen che ha il suo tick dedicato.

# =============================================================================
# APP
# =============================================================================

class SailingTabletApp(App):
    def build(self):
        # Installa hook globali per catturare TUTTE le eccezioni non gestite
        # (main thread, thread Kivy/uploader, librerie). Da qui in poi ogni
        # crash finisce nel file errors_YYYY-MM-DD.log oltre che in logcat.
        try:
            _error_logger.install_global_hooks()
            log_err(f'App start: pid={os.getpid()} android={IS_ANDROID}')
        except Exception as e:
            print(f'ErrorLogger hook install failed: {e}')

        Window.clearcolor=BG
        self.dm=DataManager()
        self.sm=ScreenManager(transition=FadeTransition(duration=0.10))
        for cls in (NavigationScreen,StartLineScreen,LayLineScreen,
                    WaypointsScreen,PolarScreen,LoggingScreen,WeatherScreen,
                    SettingsScreen):
            self.sm.add_widget(cls(self.dm))
        self.sidebar=Sidebar(self.sm)
        root=BoxLayout(orientation='horizontal',spacing=0)
        root.add_widget(self.sidebar); root.add_widget(self.sm)
        Clock.schedule_interval(self._tick,1.0)
        return root

    @mainthread
    def _tick(self,dt):
        try:
            self.sidebar.set_connected(self.dm.connected)
            cur=self.sm.current_screen
            if hasattr(cur,'tick'): cur.tick(dt)
        except Exception as e: print(f'Tick:{e}')

    def on_start(self):
        # Forza landscape DOPO che la finestra Kivy/SDL e' stata creata.
        # Triplo schedule per coprire race conditions con il sistema:
        # - 0s: subito appena App e' partito
        # - 0.5s: dopo che SDL ha stabilizzato il surface
        # - 1.5s: dopo eventuali config-changes Android di startup
        Clock.schedule_once(lambda dt: _force_landscape_android(), 0)
        Clock.schedule_once(lambda dt: _force_landscape_android(), 0.5)
        Clock.schedule_once(lambda dt: _force_landscape_android(), 1.5)

    def on_pause(self):  return True
    def on_resume(self):
        # Riapplica orientamento dopo resume (alcuni device lo resettano
        # quando l'app torna in foreground dopo un periodo lungo)
        Clock.schedule_once(lambda dt: _force_landscape_android(), 0.2)
    def on_stop(self):
        try: self.dm.cloud.stop()
        except: pass
        # Chiudi il file CSV se ancora aperto, cosi' i dati flushed sopravvivono
        try: self.dm.track_logger.stop()
        except: pass
        self.dm.disconnect()

if __name__=='__main__':
    SailingTabletApp().run()
