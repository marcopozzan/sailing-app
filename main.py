"""
Sailing Racing System — Android TABLET v1.5
Grafica originale mantenuta (bussola, canvas tattico, grafico velocita).
Layout adattivo: _cols_h() usa Window.height - no altezze fisse sui container.
Fix SIGABRT: Clock.schedule_once su tutti canvas draw + guard width/height.

v1.5: download/upload polari, waypoints e tracks via Azure Blob Storage diretto
      (https://sailingapp.blob.core.windows.net). Sostituisce il flusso API.
      Container: polars, waypoints, tracks (sottocartella per boat_id, default 'soar').
      Doppia scrittura: file locali (sandbox app) + cloud (blob).
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
# o (b) un fallback senza verifica per servizi di test come webhook.site.
#
# Logica usata:
# 1) Provo a creare un context con certifi: ideale per backend reali in HTTPS
# 2) Se certifi manca o il file CA e' assente, uso comunque context default
# 3) Se il POST fallisce con errore SSL E l'URL e' whitelisted (webhook.site /
#    requestbin / beeceptor), riprovo UNA VOLTA con context unverified.
#    Questo evita di richiedere il rebuild APK solo per test.
# 4) La diagnostica _SSL_DIAG e' visibile nello status box di Settings.

_SSL_DIAG = '?'
_SSL_CTX_VERIFIED = None    # con verifica (usato di default)
_SSL_CTX_UNVERIFIED = None  # senza verifica (fallback per test endpoints)

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
    _SSL_CTX_VERIFIED = ssl.create_default_context()
    _SSL_DIAG = 'NO certifi (default)'
except Exception as _e:
    _SSL_CTX_VERIFIED = ssl.create_default_context()
    _SSL_DIAG = f'certifi err:{_e}'

# Context senza verifica: usato come fallback per test endpoint (webhook.site).
try:
    _SSL_CTX_UNVERIFIED = ssl._create_unverified_context()
except Exception:
    _SSL_CTX_UNVERIFIED = None

# Domini whitelisted per il fallback senza verifica (servizi di test).
# Per backend reali NON aggiungerli qui: il certificato deve verificare.
_SSL_TEST_HOSTS = ('webhook.site', 'requestbin.com', 'beeceptor.com',
                    'pipedream.com', 'mockbin.com')

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
# URL di default per il cloud upload. webhook.site e' un servizio di test che
# riceve POST e li mostra in tempo reale. Sostituibile da Settings.
CLOUD_URL_DEFAULT = 'https://webhook.site/7935ad3e-065c-4780-8c76-5eeccd95a74c'

# =============================================================================
# AZURE BLOB STORAGE -- accesso diretto (no API intermedia)
# =============================================================================
# Architettura cloud:
# - Storage account: sailingapp.blob.core.windows.net
# - Container 'polars'      (lettura pubblica): polari per barca
#       https://sailingapp.blob.core.windows.net/polars/{boat}/polar.json
# - Container 'waypoints'   (lettura pubblica): waypoint per barca
#       https://sailingapp.blob.core.windows.net/waypoints/{boat}/waypoints.json
# - Container 'tracks'      (write con SAS):    log CSV per barca
#       https://sailingapp.blob.core.windows.net/tracks/{boat}/{filename}.csv
#
# Identificativo barca: 'cloud_boat_id' nel sailing_config.json (default 'soar').
#
# Lettura (download): GET diretto al blob -- richiede solo che il container abbia
#   "Anonymous read access for blobs". Nessun token client-side.
# Scrittura (upload tracks): PUT con SAS token a livello container, configurato
#   in 'tracks_sas_token' nel sailing_config.json. Esempio di SAS token:
#       sv=2022-11-02&sr=c&sp=cw&se=2027-...&sig=...
#   La URL finale per il PUT diventa:
#       {blob_url}?{sas_token}
BLOB_BASE_DEFAULT       = 'https://sailingapp.blob.core.windows.net'
BLOB_CONTAINER_POLARS   = 'polars'
BLOB_CONTAINER_WAYPOINTS = 'waypoints'
BLOB_CONTAINER_TRACKS   = 'tracks'
BOAT_ID_DEFAULT         = 'soar'

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


def default_config():
    """Restituisce il dict con TUTTI i valori di default dell'applicazione.

    Questa e' l'UNICA fonte di verita' per i default: viene usata sia da
    DataManager.__init__ (per inizializzare gli attributi) sia da _load_cfg
    quando il file sailing_config.json non esiste (per crearlo al primo avvio).

    Modifica qui per cambiare i default 'fabbrica' dell'app."""
    return {
        # Connessione NMEA TCP (router di bordo)
        'nmea_ip':            '192.168.4.1',
        'nmea_port':          60001,
        # Path file
        'polar_path':         POLAR_PATH,
        'log_dir':            LOG_PATH,
        # Tattica: finestra TWD per analisi lato buono / vira (minuti)
        'twd_window_minutes': 5,
        # Cloud upload (legacy webhook -- mantenuto per backward-compat)
        'cloud_enabled':      False,
        'cloud_url':          CLOUD_URL_DEFAULT,
        'cloud_boat_id':      BOAT_ID_DEFAULT,
        'cloud_token':        'il_mio_token_segreto',
        'cloud_interval_min': 10,
        # Base URL del servizio cloud (legacy, non piu' usato per download).
        'api_base':           API_BASE_DEFAULT,
        # === Azure Blob Storage (nuovo flusso download/upload) ===
        # Storage account URL: i container sono 'polars', 'waypoints', 'tracks'.
        # URL composti come:
        #   {blob_base}/polars/{cloud_boat_id}/polar.json
        #   {blob_base}/waypoints/{cloud_boat_id}/waypoints.json
        #   {blob_base}/tracks/{cloud_boat_id}/{filename}.csv
        'blob_base':          BLOB_BASE_DEFAULT,
        # SAS token (solo SCRITTURA) per il container 'tracks'. Da generare nel
        # portale Azure: container 'tracks' -> Generate SAS -> permessi 'Write'
        # + 'Create'. Esempio:
        #   sv=2022-11-02&sr=c&sp=cw&se=2027-01-01T00:00:00Z&sig=...
        # NB: NON includere il '?' iniziale.
        'tracks_sas_token':   '',
        # SAS token per upload polare/waypoint (Write + Create). I container
        # 'polars' e 'waypoints' sono in lettura pubblica (no SAS per il GET);
        # questi token servono SOLO se vuoi caricare al cloud dal tablet.
        # Lascia stringa vuota se non vuoi abilitare il pulsante upload.
        'polars_sas_token':    '',
        'waypoints_sas_token': '',
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
    def __init__(self):
        self.data={}; self.loaded=False; self.boat_name=''

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

    def load(self,path):
        try:
            with open(path) as f: d=json.load(f)
            self.boat_name=d.get('boat_name','')
            self.data={float(k):{float(ka):float(v) for ka,v in kv.items()}
                       for k,kv in d.get('polar',{}).items()}
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
            self.loaded=bool(self.data); return self.loaded
        except Exception as e: print(f'CSV:{e}'); return False

    def save(self,path):
        with open(path,'w') as f:
            json.dump({'boat_name':self.boat_name,
                       'polar':{str(k):{str(ka):v for ka,v in kv.items()}
                                for k,kv in self.data.items()}},f,indent=2)

# =============================================================================
# CLOUD UPLOADER -- invio dati barca a endpoint REST
# =============================================================================

class CloudUploader:
    """Invia periodicamente snapshot dei dati barca a un endpoint REST.

    Caratteristiche:
    - Thread separato: non blocca mai la UI o il parsing NMEA.
    - Buffer offline su file (.jsonl): garantisce zero perdita dati se
      la rete cellulare e' assente o instabile.
    - Backoff esponenziale sui retry per non saturare il modem.
    - Force-cellular su Android: bypassa il WiFi senza uplink (caso tipico
      del WiFi di bordo isolato) e usa la SIM dati per HTTPS.
    - Rate limit lato client: max 1 invio "manuale" ogni 60s.
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
        """Loop di upload. Si sveglia ogni `interval_min` minuti, fa snapshot
        e invia (drenando anche la coda offline)."""
        # Aspetta 30s al primo avvio per dare tempo al sistema di stabilizzarsi
        if self._stop.wait(30):
            return
        while not self._stop.is_set():
            try:
                self._upload_cycle()
            except Exception as e:
                self.last_error = f'Loop:{e}'
                print(f'CloudUploader loop:{e}')
            # Sleep N minuti (configurato in DataManager), interrompibile
            interval_s = max(60, self.dm.cloud_interval_min * 60)
            if self._stop.wait(interval_s):
                return

    def _upload_cycle(self):
        """Un ciclo: drena coda offline, poi invia il dato corrente."""
        if not self.dm.cloud_enabled:
            return
        if not self.dm.cloud_url or not self.dm.cloud_boat_id:
            self.last_error = 'URL o boat_id non configurati'
            return

        # 1) Drena la coda offline (max 50 record per ciclo per non
        # saturare la rete cellulare in caso di accumulo lungo)
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

    # ----- HTTP POST con force-cellular su Android e fallback SSL -----

    def _post_json(self, payload):
        """POST JSON al cloud. Restituisce (ok: bool, err: str|None).
        Su Android forza la rete cellulare se disponibile (bypass WiFi
        di bordo senza uplink). Se l'errore e' SSL e l'URL e' un servizio
        di test (webhook.site & co), riprova UNA VOLTA senza verifica."""
        ok, err = self._post_json_attempt(payload, _SSL_CTX_VERIFIED)
        if ok:
            return True, None
        # Fallback: se errore SSL e URL whitelisted, riprova senza verifica
        if err and 'SSL' in err.upper() and self._is_test_host(self.dm.cloud_url):
            if _SSL_CTX_UNVERIFIED is None:
                return False, f'{err} (fallback non disponibile)'
            ok2, err2 = self._post_json_attempt(payload, _SSL_CTX_UNVERIFIED)
            if ok2:
                # Annoto nel log che il fallback ha funzionato (utile per UI)
                return True, None
            return False, f'{err} | retry-noverify: {err2}'
        return False, err

    def _is_test_host(self, url):
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ''
            return any(host.endswith(h) for h in _SSL_TEST_HOSTS)
        except Exception:
            return False

    def _post_json_attempt(self, payload, ssl_ctx):
        """Singolo tentativo HTTP POST con il context SSL fornito."""
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.dm.cloud_url, data=data,
                headers={'Content-Type': 'application/json',
                         'X-Boat-Id': self.dm.cloud_boat_id or '',
                         'Authorization': f'Bearer {self.dm.cloud_token}'
                                          if self.dm.cloud_token else ''})

            # Force-cellular su Android se disponibile
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
            # Errore SSL diretto: stringa di errore breve e chiara
            reason = getattr(e, 'reason', None) or str(e)
            return False, f'SSL: {reason}'
        except urllib.error.HTTPError as e:
            return False, f'HTTP {e.code}'
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
# TRACK UPLOADER -- invia file CSV completi al cloud (Azure Blob Storage)
# =============================================================================
#
# Differenza con CloudUploader:
# - CloudUploader invia snapshot LIVE (un dict per ciclo) all'endpoint /api/track.
# - TrackUploader invia FILE CSV INTERI (chiusi) al Blob Storage Azure direttamente.
#
# Logica (nuovo flusso, blob diretto):
# - Quando il TrackLogger ferma un log, chiama track_uploader.enqueue(path).
# - Il file viene aggiunto a una coda persistente (tracks_to_upload.json).
# - Un thread di sfondo processa la coda: per ogni file
#     1. Compone l'URL del blob: {blob_base}/tracks/{boat}/{filename}?{SAS}
#     2. PUT del CSV direttamente al Blob Storage (header x-ms-blob-type=BlockBlob)
#     3. Rimuove il file dalla coda se l'upload riesce
# - Il SAS token e' preconfigurato in sailing_config.json (campo 'tracks_sas_token')
#   con permessi 'Write' + 'Create' (e 'List' + 'Read' se si vuole anche scarico).
# - L'utente puo' forzare l'upload dal pulsante "Invia al cloud" nella UI.
# - Se manca connettivita', il file resta in coda e si riprova al prossimo
#   ciclo o al prossimo "force_upload".
# - Niente cancellazione del file CSV locale: resta sempre disponibile per
#   replay anche dopo upload riuscito (doppia copia: locale + cloud).
class TrackUploader:
    """Upload diretto di file CSV ad Azure Blob Storage (container 'tracks').

    Coda persistente: i file in attesa di upload sono salvati in
    tracks_to_upload.json (lista di path). Sopravvive a riavvii dell'app.
    Thread separato: non blocca mai la UI.
    Force-cellular su Android: riusa la stessa logica di CloudUploader.
    Espone anche list_remote_tracks() e download_remote_track() per il
    download dei CSV gia' caricati dal cloud verso il locale.
    """

    # Pattern URL blob per upload (PUT) e download (GET):
    #   {blob_base}/tracks/{boat}/{filename}?{tracks_sas_token}
    # Permessi SAS richiesti:
    #   - PUT (upload):                Write + Create
    #   - GET (download remoto):       Read
    #   - LIST (lista file remoti):    List + Read

    def __init__(self, dm):
        self.dm = dm
        self._thread = None
        self._stop = threading.Event()
        self._wake = threading.Event()  # per svegliare il thread su force_upload
        self._queue_path = os.path.join(DATA_DIR, 'tracks_to_upload.json')
        self._queue_lock = threading.Lock()
        # Counters per UI
        self.uploaded_count = 0
        self.last_uploaded_ts = None
        self.last_error = None
        self.last_uploaded_filename = None

    # ----- ciclo di vita -----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    # ----- gestione coda persistente -----

    def _read_queue(self):
        """Legge la coda da disco. Restituisce lista di path (puo' essere vuota)."""
        try:
            if not os.path.exists(self._queue_path):
                return []
            with open(self._queue_path) as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                return []
        except Exception as e:
            print(f'TrackUploader._read_queue: {e}')
            return []

    def _write_queue(self, paths):
        """Salva la coda su disco."""
        try:
            os.makedirs(os.path.dirname(self._queue_path), exist_ok=True)
            with open(self._queue_path, 'w') as f:
                json.dump(paths, f)
        except Exception as e:
            print(f'TrackUploader._write_queue: {e}')

    def queue_size(self):
        """Numero di file in coda (per UI)."""
        with self._queue_lock:
            return len(self._read_queue())

    def enqueue(self, csv_path):
        """Aggiunge un file CSV alla coda di upload. Idempotente.
        Sveglia il thread cosi' processa subito."""
        if not csv_path or not os.path.exists(csv_path):
            return
        with self._queue_lock:
            q = self._read_queue()
            if csv_path not in q:
                q.append(csv_path)
                self._write_queue(q)
        # Sveglia il thread per processare subito
        self._wake.set()

    def force_upload(self):
        """Pulsante 'Invia al cloud': sveglia immediatamente il thread.
        Restituisce (ok, msg) per feedback alla UI.

        Precondition check (nuovo flusso blob diretto):
        - cloud_enabled = True
        - cloud_boat_id non vuoto
        - tracks_sas_token non vuoto (serve per il PUT)
        """
        if not self.dm.cloud_enabled:
            return False, 'Cloud disabilitato (vedi Impostazioni)'
        if not self.dm.cloud_boat_id:
            return False, 'cloud_boat_id non configurato'
        if not (self.dm.tracks_sas_token or '').strip():
            return False, 'tracks_sas_token non configurato'
        n = self.queue_size()
        if n == 0:
            return False, 'Nessun file in coda di upload'
        # Wake the thread
        self._wake.set()
        return True, f'{n} file in coda, upload in corso...'

    # ----- thread principale -----

    def _loop(self):
        """Loop di upload. Si sveglia quando _wake e' settato (force o enqueue)
        oppure ogni 5 minuti come safety net per riprovare upload falliti."""
        # Aspetta 30s al primo avvio per dare tempo al sistema di stabilizzarsi
        if self._stop.wait(30):
            return
        # All'avvio, processa subito eventuale coda residua
        self._wake.set()

        while not self._stop.is_set():
            # Aspetta wake o timeout di 5 min
            self._wake.wait(timeout=300)
            self._wake.clear()
            if self._stop.is_set():
                return
            try:
                self._process_queue()
            except Exception as e:
                self.last_error = f'Loop:{e}'
                print(f'TrackUploader loop: {e}')

    def _process_queue(self):
        """Tenta upload di tutti i file in coda. Si ferma al primo errore
        (probabilmente niente connettivita') e riprova al prossimo wake.

        Nuovo flusso: PUT diretto al blob 'tracks/{boat}/{filename}' con SAS
        token preconfigurato (no piu' richiesta SAS al backend).
        """
        if not self.dm.cloud_enabled:
            return
        if not self.dm.cloud_boat_id:
            self.last_error = 'cloud_boat_id non configurato'
            return
        if not (self.dm.tracks_sas_token or '').strip():
            self.last_error = 'tracks_sas_token non configurato'
            return

        with self._queue_lock:
            q = self._read_queue()

        if not q:
            return

        successful = []
        for path in q:
            if self._stop.is_set():
                break
            ok, err = self._upload_one(path)
            if ok:
                successful.append(path)
                self.uploaded_count += 1
                self.last_uploaded_ts = time.time()
                self.last_uploaded_filename = os.path.basename(path)
                self.last_error = None
            else:
                # Errore: probabile mancanza connettivita'. Fermati qui,
                # i file rimangono in coda per il prossimo tentativo.
                self.last_error = err
                print(f'TrackUploader: upload fallito {path}: {err}')
                break

        # Rimuovi dalla coda i file uploadati con successo
        if successful:
            with self._queue_lock:
                q = self._read_queue()
                q = [p for p in q if p not in successful]
                self._write_queue(q)

    def _upload_one(self, csv_path):
        """Upload di UN file CSV come blob in 'tracks/{boat}/{filename}'.

        Flusso semplificato (no SAS round-trip al backend):
        1. Compone l'URL del blob con SAS token preconfigurato.
        2. PUT del CSV con header Azure 'x-ms-blob-type: BlockBlob'.

        Restituisce (ok, err)."""
        try:
            if not os.path.exists(csv_path):
                # File scomparso: lo consideriamo "uploadato" per rimuoverlo dalla coda
                return True, None
            filename = os.path.basename(csv_path)

            sas_url = self.dm.track_upload_url(filename)
            if not sas_url:
                return False, 'SAS URL non componibile (boat_id/token mancanti)'

            with open(csv_path, 'rb') as f:
                csv_data = f.read()

            return self._put_to_blob(sas_url, csv_data)
        except Exception as e:
            return False, str(e)

    def _put_to_blob(self, sas_url, csv_data):
        """PUT del contenuto CSV al blob storage. Restituisce (ok, err).

        Header obbligatori per Azure Blob Storage:
        - x-ms-blob-type: BlockBlob (block blob, non append/page)
        - Content-Type: text/csv
        Il SAS token nella query string autentica la richiesta.
        Su Android forza la rete cellulare se disponibile (riusa CloudUploader).
        """
        try:
            req = urllib.request.Request(
                sas_url, data=csv_data, method='PUT',
                headers={
                    'Content-Type':    'text/csv',
                    'x-ms-blob-type':  'BlockBlob',
                })
            sock_factory = self._cellular_socket_factory()
            if sock_factory:
                orig = socket.create_connection
                socket.create_connection = sock_factory
                try:
                    with urllib.request.urlopen(req, timeout=60,
                                                context=_SSL_CTX_VERIFIED) as resp:
                        return (resp.status < 300,
                                None if resp.status < 300 else f'HTTP {resp.status}')
                finally:
                    socket.create_connection = orig
            else:
                with urllib.request.urlopen(req, timeout=60,
                                            context=_SSL_CTX_VERIFIED) as resp:
                    return (resp.status < 300,
                            None if resp.status < 300 else f'HTTP {resp.status}')
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode('utf-8', errors='replace')[:200]
            except Exception:
                body = ''
            return False, f'HTTP {e.code}: {body}'
        except Exception as e:
            return False, str(e)

    def list_remote_tracks(self, timeout=15):
        """Lista i blob CSV presenti in 'tracks/{boat}/' usando il SAS token
        (richiede permesso 'List' nel SAS, oltre a 'Read').

        Restituisce (ok, lista_filename) oppure (False, msg_errore).
        Se il SAS non ha permesso 'list', l'API restituisce 403.
        """
        if not self.dm.cloud_boat_id:
            return False, 'cloud_boat_id non configurato'
        sas = (self.dm.tracks_sas_token or '').lstrip('?').strip()
        if not sas:
            return False, 'tracks_sas_token non configurato'
        base = (self.dm.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        # Endpoint LIST dei blob nel container, filtrato per prefisso boat:
        #   {base}/{container}?restype=container&comp=list&prefix={boat}/&{sas}
        prefix = f'{self.dm.cloud_boat_id}/'
        from urllib.parse import quote
        list_url = (f'{base}/{BLOB_CONTAINER_TRACKS}'
                    f'?restype=container&comp=list&prefix={quote(prefix)}&{sas}')
        try:
            req = urllib.request.Request(list_url, method='GET')
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_SSL_CTX_VERIFIED) as resp:
                if resp.status >= 300:
                    return False, f'HTTP {resp.status}'
                xml_body = resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return False, f'HTTP {e.code} (serve permesso List nel SAS)'
        except Exception as e:
            return False, str(e)
        # Parse XML minimale: cerco <Name>...</Name>. Il payload Azure ha forma:
        #   <EnumerationResults><Blobs><Blob><Name>soar/log.csv</Name>...
        import re
        names = re.findall(r'<Name>([^<]+)</Name>', xml_body)
        # Estraggo solo il filename (rimuovo prefisso "{boat}/")
        files = []
        for n in names:
            if n.startswith(prefix):
                fn = n[len(prefix):]
                if fn and '/' not in fn:  # ignora eventuali sottocartelle
                    files.append(fn)
        return True, files

    def download_remote_track(self, filename, dest_path, timeout=60):
        """Scarica UN file di track dal blob e lo salva in dest_path.
        Riusa il SAS token (serve permesso 'Read').
        Restituisce (ok, err)."""
        if not filename:
            return False, 'filename mancante'
        sas_url = self.dm.track_upload_url(filename)  # stesso URL+SAS, GET method
        if not sas_url:
            return False, 'URL non componibile'
        try:
            req = urllib.request.Request(sas_url, method='GET')
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_SSL_CTX_VERIFIED) as resp:
                if resp.status >= 300:
                    return False, f'HTTP {resp.status}'
                data = resp.read()
            # Scrittura atomica
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            tmp = dest_path + '.tmp'
            with open(tmp, 'wb') as f:
                f.write(data)
                f.flush()
                try: os.fsync(f.fileno())
                except: pass
            os.replace(tmp, dest_path)
            return True, None
        except urllib.error.HTTPError as e:
            return False, f'HTTP {e.code}'
        except Exception as e:
            return False, str(e)

    def _cellular_socket_factory(self):
        """Su Android, restituisce una socket factory che forza la rete
        cellulare. Riusa la stessa logica di CloudUploader."""
        # Per non duplicare il codice: deleghiamo all'istanza CloudUploader.
        # Se non c'e', restituiamo None (no force-cellular).
        cu = getattr(self.dm, 'cloud', None)
        if cu and hasattr(cu, '_cellular_socket_factory'):
            return cu._cellular_socket_factory()
        return None


# =============================================================================
# DATA MANAGER
# =============================================================================

# =============================================================================
# TRACK LOGGER -- scrittura CSV indipendente dalla schermata corrente
# =============================================================================
#
# Logica del logging:
# - L'utente attiva/disattiva il log dalla schermata Start (toggle button).
# - Il timer di scrittura e' un Clock.schedule_interval DEDICATO (ogni 5s),
#   non e' agganciato al tick(dt) della schermata corrente. Cosi' anche se
#   l'utente passa a Navigation/LayLine/altre schermate, il log continua.
# - I dati scritti sono quelli che si vedono nella schermata Navigation:
#   posizione GPS + tutti i campi degli strumenti (vento, profondita',
#   waypoint target, VMG, TARGET da polare, advice tattico).
# - Ogni writerow() e' seguito da flush() + fsync(): in caso di crash o
#   batteria scarica si perdono al massimo gli ultimi 5s.
# - File CSV creato in DataManager.log_dir (default: <data_dir>/logs/).
class TrackLogger:
    """Logger CSV autonomo che scrive ogni LOG_INTERVAL_S secondi i dati di
    navigazione su file. Indipendente dalla UI: una volta avviato continua
    finche' non viene fermato esplicitamente, indipendentemente da quale
    schermata e' visibile."""

    LOG_INTERVAL_S = 5.0   # frequenza scrittura su disco (richiesta utente)

    # Ordine colonne CSV: corrisponde a tutti i campi visibili in Navigation
    # (i 3 box in alto + bussola/HDG + i 9 box centrali + advice tattico).
    HEADER = [
        'Timestamp', 'Lat', 'Lon',
        'SOG_kn', 'COG_deg', 'HDG_deg',
        'STW_kn', 'TARGET_kn', 'VMG_kn',
        'TWS_kn', 'TWA_deg', 'TWD_deg',
        'AWS_kn', 'AWA_deg',
        'Depth_m',
        'BRG_mark_deg', 'DIST_mark_NM', 'ETA_mark_min',
        'TacticalAdvice', 'Shift_deg',
    ]

    def __init__(self, dm):
        self.dm = dm
        self._active = False
        self._fh = None
        self._wr = None
        self._path = None
        self._cnt = 0
        self._event = None       # handle del Clock.schedule_interval
        self._last_error = None

    # ---- API pubblica ----

    def is_active(self):
        return self._active

    def get_path(self):
        return self._path

    def get_count(self):
        return self._cnt

    def get_last_error(self):
        return self._last_error

    def start(self):
        """Apre un nuovo file CSV in log_dir e schedula la scrittura periodica.
        Restituisce (ok, msg) per feedback alla UI."""
        if self._active:
            return True, 'Log gia attivo'
        log_dir = self.dm.log_dir
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception as e:
            self._last_error = f'mkdir: {e}'
            return False, self._last_error
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = os.path.join(log_dir, f'track_{ts}.csv')
        try:
            self._fh = open(path, 'w', newline='')
            self._wr = csv.writer(self._fh)
            self._wr.writerow(self.HEADER)
            self._fh.flush()
            try: os.fsync(self._fh.fileno())
            except: pass
        except Exception as e:
            self._last_error = f'open: {e}'
            try:
                if self._fh: self._fh.close()
            except: pass
            self._fh = self._wr = None
            return False, self._last_error
        self._path = path
        self._cnt = 0
        self._active = True
        self._last_error = None
        # Schedula il timer dedicato. Cattura un riferimento 'self' nella
        # lambda cosi' resta vivo finche' l'evento e' schedulato.
        self._event = Clock.schedule_interval(
            lambda dt: self._tick(), self.LOG_INTERVAL_S)
        # Scrivo subito una prima riga cosi' l'utente vede il file popolato
        # senza dover aspettare 5s.
        self._tick()
        return True, path

    def stop(self):
        """Ferma il timer e chiude il file. Idempotente.
        Se il TrackUploader e' configurato, accoda il file CSV per upload
        automatico al cloud (Azure Blob Storage)."""
        if not self._active:
            return
        self._active = False
        try:
            if self._event is not None:
                self._event.cancel()
        except Exception:
            pass
        self._event = None
        closed_path = self._path
        try:
            if self._fh:
                self._fh.flush()
                try: os.fsync(self._fh.fileno())
                except: pass
                self._fh.close()
        except Exception as e:
            self._last_error = f'close: {e}'
        self._fh = self._wr = None

        # Accoda per upload al cloud se l'uploader e' configurato
        try:
            tu = getattr(self.dm, 'track_uploader', None)
            if tu and closed_path and self._cnt > 0:
                tu.enqueue(closed_path)
        except Exception as e:
            print(f'TrackLogger.stop: enqueue failed: {e}')

    # ---- interno ----

    def _tick(self):
        """Callback del timer: scrive una riga CSV con i dati correnti del
        DataManager. Protetto da try/except cosi' un errore di scrittura
        non interrompe il timer (continueremo a riprovare ogni 5s)."""
        if not self._active or self._wr is None or self._fh is None:
            return
        dm = self.dm
        try:
            # Calcolo ETA stimato verso la boa target (in minuti).
            eta_min = ''
            if (dm.distance_to_mark is not None
                    and dm.boat_speed is not None
                    and dm.boat_speed > 0.1):
                eta_min = f'{(dm.distance_to_mark / dm.boat_speed) * 60:.1f}'
            # TWD medio (direzione vento vera) e advice tattico
            try:
                twd = dm.get_twd_average()
            except Exception:
                twd = None
            try:
                advice, shift = dm.tactical_advice()
            except Exception:
                advice, shift = (None, None)
            row = [
                datetime.now().isoformat(timespec='seconds'),
                f'{dm.gps_lat:.6f}'              if dm.gps_lat              is not None else '',
                f'{dm.gps_lon:.6f}'              if dm.gps_lon              is not None else '',
                f'{dm.boat_speed:.2f}',
                f'{dm.boat_course:.1f}',
                f'{dm.boat_heading:.1f}',
                f'{dm.boat_speed:.2f}',                                       # STW = SOG (no log separato)
                f'{dm.target_bsp:.2f}'           if dm.target_bsp           is not None else '',
                f'{dm.vmg:.2f}'                  if dm.vmg                  is not None else '',
                f'{dm.true_wind_speed:.1f}'      if dm.true_wind_speed      else '',
                f'{dm.true_wind_angle:.1f}'      if dm.true_wind_angle      else '',
                f'{twd:.1f}'                     if twd                     is not None else '',
                f'{dm.apparent_wind_speed:.1f}'  if dm.apparent_wind_speed  else '',
                f'{dm.apparent_wind_angle:.1f}'  if dm.apparent_wind_angle  else '',
                f'{dm.depth:.1f}',
                f'{dm.bearing_to_mark:.1f}'      if dm.bearing_to_mark      is not None else '',
                f'{dm.distance_to_mark:.3f}'     if dm.distance_to_mark     is not None else '',
                eta_min,
                advice or '',
                f'{shift:.1f}'                   if shift                   is not None else '',
            ]
            self._wr.writerow(row)
            # flush+fsync ogni scrittura: a 5s di intervallo l'overhead e'
            # trascurabile e protegge dal data loss su crash/batteria.
            self._fh.flush()
            try: os.fsync(self._fh.fileno())
            except: pass
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
        # CloudUploader: lo creo sempre, viene avviato solo se cloud_enabled=True
        self.cloud = CloudUploader(self)
        if self.cloud_enabled:
            self.cloud.start()
        # TrackLogger: scrittura CSV ogni 5s, indipendente dalla schermata
        # corrente. Non viene avviato in automatico: l'utente lo attiva dal
        # pulsante "Avvia log" nella schermata Start.
        self.track_logger = TrackLogger(self)
        # TrackUploader: invia file CSV al cloud (Azure Blob Storage).
        # Si avvia sempre cosi' processa eventuale coda residua all'apertura.
        self.track_uploader = TrackUploader(self)
        self.track_uploader.start()

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
        ci = c.get('cloud_interval_min', 10)
        self.cloud_interval_min = ci if ci in (5, 10, 15, 30) else 10
        # Base URL del servizio cloud (legacy, mantenuto per compat config).
        # Retrocompatibilita': accetta anche il vecchio nome
        # 'waypoints_api_base' usato in versioni precedenti.
        wb = (c.get('api_base', '') or
              c.get('waypoints_api_base', '') or '').strip()
        self.api_base = wb if wb else API_BASE_DEFAULT
        # === Azure Blob Storage ===
        bb = (c.get('blob_base', '') or '').strip().rstrip('/')
        self.blob_base = bb if bb else BLOB_BASE_DEFAULT
        # SAS token per il container 'tracks' (solo upload). Lo storiamo cosi'
        # come arriva dal config; il leading '?' viene rimosso al momento dell'uso.
        self.tracks_sas_token = (c.get('tracks_sas_token', '') or '').strip()
        # SAS opzionali per upload polare/waypoints (vuoto = upload disabilitato).
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
        """Carica config da file. Se il file non esiste, lo crea con i default
        cosi' al primo avvio l'utente trova un sailing_config.json gia' pronto
        e popolato dai valori di default_config().

        Se il file esiste ma proviene da una versione precedente dell'app che
        non aveva tutti i campi attuali (es. 'api_base' aggiunto in una nuova
        versione), il loader rileva i campi mancanti e RISCRIVE il file con
        i default per i nuovi campi. Cosi' l'utente trova sempre tutti i campi
        nel file dopo il primo avvio della nuova versione, senza dover
        toccare manualmente le impostazioni perche' venga rigenerato."""
        if not os.path.exists(self.config_path):
            # Primo avvio: il file non c'e'. I default sono gia' applicati
            # in __init__ via _apply_config(default_config()), quindi basta
            # persisterli su disco.
            try:
                self.save_cfg()
                print(f'Config creato con default in {self.config_path}')
            except Exception as e:
                print(f'_load_cfg create-default ERROR: {type(e).__name__}: {e}')
            return
        try:
            with open(self.config_path) as f:
                c = json.load(f)
            self._apply_config(c)
            # Migrazione automatica: se il file in lettura non aveva tutti i
            # campi previsti dalla versione corrente di default_config(), li
            # aggiungiamo (con i default) riscrivendo il file. Questo accade
            # quando l'utente aggiorna l'app a una versione che introduce
            # nuovi campi (es. 'api_base', 'blob_base', 'tracks_sas_token',
            # 'polars_sas_token', 'waypoints_sas_token' aggiunti per il
            # passaggio ad Azure Blob Storage diretto).
            # NB: il valore di 'cloud_boat_id' NON viene rimpiazzato: se il
            # config aveva 'regolofarm-1', resta tale. Per usare 'soar' va
            # cambiato esplicitamente da Settings o nel file.
            expected_keys = set(default_config().keys())
            actual_keys   = set(c.keys()) if isinstance(c, dict) else set()
            missing = expected_keys - actual_keys
            # Il vecchio nome 'waypoints_api_base' (se presente) deve essere
            # rimosso dal file e sostituito dal nuovo 'api_base'. Forziamo
            # quindi una riscrittura anche in questo caso.
            has_legacy_name = 'waypoints_api_base' in actual_keys
            if missing or has_legacy_name:
                if missing:
                    print(f'Config: campi mancanti {sorted(missing)}, riscrivo con default')
                if has_legacy_name:
                    print('Config: rinomino "waypoints_api_base" in "api_base"')
                try:
                    self.save_cfg()
                except Exception as e:
                    print(f'_load_cfg migration ERROR: {type(e).__name__}: {e}')
        except Exception as e:
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
                   'cloud_interval_min': self.cloud_interval_min,
                   'api_base':           self.api_base,
                   'blob_base':          self.blob_base,
                   'tracks_sas_token':   self.tracks_sas_token,
                   'polars_sas_token':    self.polars_sas_token,
                   'waypoints_sas_token': self.waypoints_sas_token,
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

    def track_blob_url(self, filename):
        """URL completo del blob per UN file di track (CSV).

        Pattern: {blob_base}/tracks/{cloud_boat_id}/{filename}
        Esempio:
            https://sailingapp.blob.core.windows.net/tracks/soar/log_2026-05-05.csv

        L'upload richiede SAS token (vedi tracks_sas_token); la GET richiede
        SAS o lettura pubblica. Restituisce None se manca config."""
        if not self.cloud_boat_id or not filename:
            return None
        base = (self.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        # Encode minimo del filename: spazi, ma di norma sono safe i timestamp
        from urllib.parse import quote
        safe = quote(filename, safe='._-')
        return f'{base}/{BLOB_CONTAINER_TRACKS}/{self.cloud_boat_id}/{safe}'

    def track_upload_url(self, filename):
        """URL con SAS token per fare PUT del file CSV nel container 'tracks'.
        Restituisce None se SAS token o boat_id non configurati."""
        base_url = self.track_blob_url(filename)
        if not base_url:
            return None
        sas = (self.tracks_sas_token or '').lstrip('?').strip()
        if not sas:
            return None
        return f'{base_url}?{sas}'

    def _http_get_json(self, url, timeout=15):
        """Helper centrale per le GET HTTPS che restituiscono JSON.
        Restituisce (ok, data_or_msg). Cattura TUTTI gli errori comuni
        (rete, timeout, HTTP, JSON, encoding) e li trasforma in messaggi
        leggibili. Usato sia da download_waypoints sia da download_polar
        per evitare duplicazione."""
        try:
            req = urllib.request.Request(url, headers={
                'Accept': 'application/json',
                'User-Agent': 'regolofarm-soar/1.0',
            })
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
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
        return (True, f'Polare "{boat}" scaricata ({n_tws} TWS x {n_twa} TWA)')

    # ----- Upload waypoints / polar al blob storage -----
    # I container 'waypoints' e 'polars' sono in lettura pubblica, quindi il
    # download (GET) non richiede credenziali. L'upload (PUT) richiede invece
    # un SAS token con permessi Write+Create, configurato nei campi
    # 'waypoints_sas_token' / 'polars_sas_token' del sailing_config.json.

    def _put_blob(self, container, sas_token, filename, payload_bytes,
                  content_type='application/json', timeout=30):
        """Helper interno: PUT del payload nel blob {blob_base}/{container}/
        {boat_id}/{filename} usando il SAS token specificato.
        Restituisce (ok, msg)."""
        if not self.cloud_boat_id:
            return (False, 'cloud_boat_id non configurato')
        sas = (sas_token or '').lstrip('?').strip()
        if not sas:
            return (False, f'SAS token per {container} non configurato')
        from urllib.parse import quote
        base = (self.blob_base or BLOB_BASE_DEFAULT).rstrip('/')
        safe = quote(filename, safe='._-')
        url = f'{base}/{container}/{self.cloud_boat_id}/{safe}?{sas}'
        try:
            req = urllib.request.Request(
                url, data=payload_bytes, method='PUT',
                headers={
                    'Content-Type':   content_type,
                    'x-ms-blob-type': 'BlockBlob',
                })
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status >= 300:
                    return (False, f'HTTP {resp.status}')
            return (True, None)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode('utf-8', errors='replace')[:200]
            except Exception:
                body = ''
            return (False, f'HTTP {e.code}: {body}')
        except urllib.error.URLError as e:
            return (False, f'rete: {e.reason}')
        except socket.timeout:
            return (False, f'timeout dopo {timeout}s')
        except Exception as e:
            return (False, f'{type(e).__name__}: {e}')

    def upload_waypoints_to_cloud(self):
        """Carica il file waypoints.json LOCALE (WAYPOINTS_PATH) sul blob
        'waypoints/{boat_id}/waypoints.json'. Restituisce (ok, msg).

        Richiede waypoints_sas_token con permessi Write+Create."""
        if not os.path.exists(WAYPOINTS_PATH):
            return (False, f'File locale non trovato: {WAYPOINTS_PATH}')
        try:
            with open(WAYPOINTS_PATH, 'rb') as f:
                payload = f.read()
        except Exception as e:
            return (False, f'lettura file: {type(e).__name__}: {e}')
        ok, err = self._put_blob(BLOB_CONTAINER_WAYPOINTS,
                                 self.waypoints_sas_token,
                                 WAYPOINTS_FILE, payload)
        if ok:
            return (True, f'{len(self.waypoints)} waypoint caricati')
        return (False, err)

    def upload_polar_to_cloud(self):
        """Carica il file polar.json LOCALE (self.polar_path) sul blob
        'polars/{boat_id}/polar.json'. Restituisce (ok, msg).

        Richiede polars_sas_token con permessi Write+Create."""
        if not os.path.exists(self.polar_path):
            return (False, f'File locale non trovato: {self.polar_path}')
        try:
            with open(self.polar_path, 'rb') as f:
                payload = f.read()
        except Exception as e:
            return (False, f'lettura file: {type(e).__name__}: {e}')
        ok, err = self._put_blob(BLOB_CONTAINER_POLARS,
                                 self.polars_sas_token,
                                 POLAR_FILE, payload)
        if ok:
            boat = self.polar.boat_name or '(senza nome)'
            return (True, f'Polare "{boat}" caricata')
        return (False, err)

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
            self._polar_lbl.text=f'{dm.polar.boat_name}  {dm.target_bsp:.1f}kn  ({pct:.0f}%)'
            self._polar_lbl.color=col
        else:
            # Polare assente o disattivata: NON inventiamo un target fittizio,
            # lo segnaliamo chiaramente con '--' e label colorata. Distinguiamo
            # i due casi cosi' l'utente sa se serve caricare un file o
            # riattivare il toggle nella PolarScreen.
            self.b_tgt.set_value('--', RED)
            if not dm.polar.loaded:
                self._polar_lbl.text='Polare: NON CARICATA - target N/D'
                self._polar_lbl.color=RED
            else:
                self._polar_lbl.text='Polare: DISATTIVATA - target N/D'
                self._polar_lbl.color=ORANGE
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
        # ---- Toggle logging CSV ----
        # Pulsante che attiva/disattiva il TrackLogger del DataManager.
        # L'etichetta e il colore cambiano in base allo stato:
        #   - "Avvia log"   (grigio) quando inattivo
        #   - "Ferma log"   (rosso)  quando attivo
        # Una piccola label sotto mostra il path del file e il conteggio righe
        # cosi' l'utente ha conferma visiva che il log sta lavorando anche
        # mentre resta sulla schermata Start.
        log_box=BoxLayout(orientation='vertical',spacing=dp(4),
                          size_hint_y=None,height=dp(120))
        self._log_btn=mk_btn('Avvia log',self._toggle_log,sp(22))
        log_box.add_widget(self._log_btn)
        self._log_status=Label(text='Log non attivo',font_size=sp(15),
                                color=MUTED,size_hint_y=None,height=dp(40),
                                halign='center',valign='middle')
        self._log_status.bind(size=lambda l,_: setattr(l,'text_size',l.size))
        log_box.add_widget(self._log_status)
        left.add_widget(log_box)
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

    def _toggle_log(self):
        """Toggle del TrackLogger. Aggiorna etichetta/colore del pulsante e
        la label di stato. Il timer di scrittura e' gestito dal TrackLogger
        stesso (Clock dedicato a 5s), quindi continua a girare anche se
        l'utente lascia questa schermata."""
        tl = self.dm.track_logger
        if tl.is_active():
            tl.stop()
        else:
            ok, msg = tl.start()
            if not ok:
                # Errore in avvio: mostra il motivo nella label
                self._log_status.text = f'Errore: {msg}'
                self._log_status.color = RED
                return
        self._refresh_log_ui()

    def _refresh_log_ui(self):
        """Sincronizza pulsante e label con lo stato attuale del logger."""
        tl = self.dm.track_logger
        if tl.is_active():
            self._log_btn.text = 'Ferma log'
            self._log_btn.background_color = RED
            self._log_btn.color = (0, 0, 0, 1)
            # Mostro solo il filename (non l'intero path) per leggibilita'
            fn = os.path.basename(tl.get_path() or '')
            self._log_status.text = f'{fn}\n{tl.get_count()} righe (ogni 5s)'
            self._log_status.color = GREEN
        else:
            self._log_btn.text = 'Avvia log'
            self._log_btn.background_color = BTN_GRAY
            self._log_btn.color = WHITE
            cnt = tl.get_count()
            if cnt > 0:
                self._log_status.text = f'Log fermato ({cnt} righe)'
                self._log_status.color = MUTED
            else:
                self._log_status.text = 'Log non attivo'
                self._log_status.color = MUTED

    def tick(self,dt):
        super().tick(dt); dm=self.dm
        if self._pin and dm.gps_lat:
            d,_=calc_dist_brg(dm.gps_lat,dm.gps_lon,self._pin[0],self._pin[1])
            if d is not None: self._dist_lbl.text=f'Distanza: {d*1852:.0f}  m'
        # Aggiorno UI del logger ad ogni tick: il contatore righe va su
        # in autonomia (timer separato) ma serve riflesso visivo qui.
        self._refresh_log_ui()

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
                        ('Scarica da web', self._download_from_web),
                        ('Carica al cloud', self._upload_to_cloud)]:
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
        """Scarica waypoints.json dal cloud e lo salva localmente.

        URL: {api_base}/{cloud_boat_id}/waypoints.json
        Entrambi i parametri sono in sailing_config.json.

        Il download e' fatto in un thread separato per non bloccare la UI
        (la rete su 4G/5G puo' avere latenze di parecchi secondi). Mentre
        e' in corso, mostriamo un popup con messaggio "Scaricamento...";
        a fine download il popup viene aggiornato con esito (successo o
        errore) e l'utente lo chiude."""
        url = self.dm.download_waypoints_url()
        if not url:
            Popup(title='Scarica da web',
                  content=Label(text='cloud_boat_id non configurato.\n'
                                     'Imposta il valore in sailing_config.json',
                                halign='center', valign='middle'),
                  size_hint=(0.6, 0.30)).open()
            return

        # Popup con label che aggiorneremo a fine download.
        status_lbl = Label(text=f'Scaricamento da:\n{url}\n\nAttendere...',
                           halign='center', valign='middle')
        pop = Popup(title='Scarica da web', content=status_lbl,
                    size_hint=(0.7, 0.40), auto_dismiss=False)
        # Bottone Chiudi disabilitato finche' il download non finisce
        # (auto_dismiss=False blocca anche il tap fuori dal popup).
        pop.open()

        def _worker():
            ok, msg = self.dm.download_waypoints_from_web()
            # Torno sul main thread per toccare la UI (Kivy non e' thread-safe)
            Clock.schedule_once(lambda dt: _on_done(ok, msg), 0)

        def _on_done(ok, msg):
            if ok:
                # Aggiorno UI: nuova lista + reset selezione + check target
                if self.dm.target_mark and not any(
                        w.get('name') == self.dm.target_mark
                        for w in self.dm.waypoints):
                    self.dm.target_mark = None
                    self.dm._reset_mark_pass_state()
                    self.dm.save_cfg_safe()
                self._sel = None
                self._refresh()
                status_lbl.text = (f'OK: {msg}\n\n'
                                   f'File salvato in:\n{WAYPOINTS_PATH}')
                status_lbl.color = GREEN
            else:
                status_lbl.text = f'Errore download:\n{msg}'
                status_lbl.color = RED
            # Riabilita la chiusura: ora l'utente puo' chiudere tappando fuori
            pop.auto_dismiss = True
            # Aggiungi un bottone Chiudi sotto il messaggio
            box = BoxLayout(orientation='vertical', spacing=dp(8))
            box.add_widget(status_lbl)
            close_btn = Button(text='Chiudi', size_hint_y=None, height=dp(48),
                               background_color=BTN_GRAY, background_normal='',
                               color=WHITE, bold=True)
            close_btn.bind(on_release=lambda _: pop.dismiss())
            box.add_widget(close_btn)
            pop.content = box

        threading.Thread(target=_worker, daemon=True).start()

    def _upload_to_cloud(self):
        """Carica waypoints.json LOCALE sul blob storage cloud.

        URL destinazione: {blob_base}/waypoints/{cloud_boat_id}/waypoints.json
        Richiede waypoints_sas_token configurato in sailing_config.json
        (permessi Write+Create sul container 'waypoints')."""
        if not (self.dm.waypoints_sas_token or '').strip():
            Popup(title='Carica al cloud',
                  content=Label(text='waypoints_sas_token non configurato.\n'
                                     'Genera un SAS (Write+Create) sul container\n'
                                     '"waypoints" e settalo in sailing_config.json.',
                                halign='center', valign='middle'),
                  size_hint=(0.7, 0.34)).open()
            return

        status_lbl = Label(text='Caricamento in corso...',
                           halign='center', valign='middle')
        pop = Popup(title='Carica al cloud', content=status_lbl,
                    size_hint=(0.7, 0.40), auto_dismiss=False)
        pop.open()

        def _worker():
            ok, msg = self.dm.upload_waypoints_to_cloud()
            Clock.schedule_once(lambda dt: _on_done(ok, msg), 0)

        def _on_done(ok, msg):
            if ok:
                url = self.dm.download_waypoints_url() or '(URL non disponibile)'
                status_lbl.text = (f'OK: {msg}\n\nDestinazione:\n{url}')
                status_lbl.color = GREEN
            else:
                status_lbl.text = f'Errore upload:\n{msg}'
                status_lbl.color = RED
            pop.auto_dismiss = True
            box = BoxLayout(orientation='vertical', spacing=dp(8))
            box.add_widget(status_lbl)
            close_btn = Button(text='Chiudi', size_hint_y=None, height=dp(48),
                               background_color=BTN_GRAY, background_normal='',
                               color=WHITE, bold=True)
            close_btn.bind(on_release=lambda _: pop.dismiss())
            box.add_widget(close_btn)
            pop.content = box

        threading.Thread(target=_worker, daemon=True).start()

        # _refresh completo: cosi' nella lista si aggiornano i marker
        # ('*' boa attiva, '>' prossima) e la mappa evidenzia la nuova boa.
        cur_target = dm.target_mark
        prev_target = getattr(self, '_last_seen_target', None)
        if cur_target != prev_target:
            self._last_seen_target = cur_target
            self._refresh()
        else:
            # Solo redraw mappa: la posizione barca cambia ad ogni tick ma
            # la lista no, evitiamo di ricostruire i bottoni inutilmente
            try: Clock.schedule_once(lambda dt: self._map.redraw(), 0)
            except: pass

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
        right.add_widget(mk_btn('Carica al cloud',
                                self._upload_to_cloud, sp(18)))
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
        """Scarica polar.json dal cloud e lo salva in self.dm.polar_path.

        URL: {api_base}/{cloud_boat_id}/polar.json
        Stessa logica della WaypointsScreen._download_from_web: thread
        separato per non bloccare la UI, popup non chiudibile mentre
        scarica, esito a video con bottone Chiudi."""
        url = self.dm.download_polar_url()
        if not url:
            Popup(title='Scarica da web',
                  content=Label(text='cloud_boat_id non configurato.\n'
                                     'Imposta il valore in sailing_config.json',
                                halign='center', valign='middle'),
                  size_hint=(0.6, 0.30)).open()
            return

        status_lbl = Label(text=f'Scaricamento da:\n{url}\n\nAttendere...',
                           halign='center', valign='middle')
        pop = Popup(title='Scarica da web', content=status_lbl,
                    size_hint=(0.7, 0.40), auto_dismiss=False)
        pop.open()

        def _worker():
            ok, msg = self.dm.download_polar_from_web()
            Clock.schedule_once(lambda dt: _on_done(ok, msg), 0)

        def _on_done(ok, msg):
            if ok:
                self._refresh_table()
                self._refresh_enabled_btns()
                status_lbl.text = (f'OK: {msg}\n\n'
                                   f'File salvato in:\n{self.dm.polar_path}')
                status_lbl.color = GREEN
            else:
                status_lbl.text = f'Errore download:\n{msg}'
                status_lbl.color = RED
            pop.auto_dismiss = True
            box = BoxLayout(orientation='vertical', spacing=dp(8))
            box.add_widget(status_lbl)
            close_btn = Button(text='Chiudi', size_hint_y=None, height=dp(48),
                               background_color=BTN_GRAY, background_normal='',
                               color=WHITE, bold=True)
            close_btn.bind(on_release=lambda _: pop.dismiss())
            box.add_widget(close_btn)
            pop.content = box

        threading.Thread(target=_worker, daemon=True).start()

    def _upload_to_cloud(self):
        """Carica polar.json LOCALE sul blob storage cloud.

        URL destinazione: {blob_base}/polars/{cloud_boat_id}/polar.json
        Richiede polars_sas_token configurato in sailing_config.json
        (permessi Write+Create sul container 'polars')."""
        if not (self.dm.polars_sas_token or '').strip():
            Popup(title='Carica al cloud',
                  content=Label(text='polars_sas_token non configurato.\n'
                                     'Genera un SAS (Write+Create) sul container\n'
                                     '"polars" e settalo in sailing_config.json.',
                                halign='center', valign='middle'),
                  size_hint=(0.7, 0.34)).open()
            return

        status_lbl = Label(text='Caricamento in corso...',
                           halign='center', valign='middle')
        pop = Popup(title='Carica al cloud', content=status_lbl,
                    size_hint=(0.7, 0.40), auto_dismiss=False)
        pop.open()

        def _worker():
            ok, msg = self.dm.upload_polar_to_cloud()
            Clock.schedule_once(lambda dt: _on_done(ok, msg), 0)

        def _on_done(ok, msg):
            if ok:
                url = self.dm.download_polar_url() or '(URL non disponibile)'
                status_lbl.text = (f'OK: {msg}\n\nDestinazione:\n{url}')
                status_lbl.color = GREEN
            else:
                status_lbl.text = f'Errore upload:\n{msg}'
                status_lbl.color = RED
            pop.auto_dismiss = True
            box = BoxLayout(orientation='vertical', spacing=dp(8))
            box.add_widget(status_lbl)
            close_btn = Button(text='Chiudi', size_hint_y=None, height=dp(48),
                               background_color=BTN_GRAY, background_normal='',
                               color=WHITE, bold=True)
            close_btn.bind(on_release=lambda _: pop.dismiss())
            box.add_widget(close_btn)
            pop.content = box

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
        # Stato in alto: distingue caricata+attiva vs caricata+disattivata
        if self.dm.polar_enabled:
            self._st.text=f'OK  {p.boat_name or "--"}  {len(tws_l)}x{len(twa_l)}  [ATTIVA]'
            self._st.color=GREEN
        else:
            self._st.text=f'OK  {p.boat_name or "--"}  {len(tws_l)}x{len(twa_l)}  [DISATTIVATA]'
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

    def tick(self,dt):
        super().tick(dt)
        if self.dm.polar.loaded: self._upd_vmg()

# =============================================================================
# 6 -- LOGGING
# =============================================================================

class LoggingScreen(TabScreen):
    """Schermata "Log": mostra il grafico della velocita' e i dati real-time.
    Il logging vero e proprio e' gestito dal TrackLogger del DataManager
    (timer dedicato a 5s, indipendente dalla schermata corrente). Qui c'e'
    solo il toggle e il feedback di stato -- duplica il pulsante della
    schermata Start per comodita' dell'utente."""
    def __init__(self,dm,**kw):
        super().__init__(dm,'Log  Logging',name='logging',**kw)
        self._hist=[]
        self._build()

    def _build(self):
        self._cols=BoxLayout(orientation='horizontal',spacing=dp(8),
                              size_hint=(1,1))
        self.body.add_widget(self._cols)
        left=BoxLayout(orientation='vertical',spacing=dp(6),
                        padding=dp(8),size_hint_x=0.54)
        _bg(left,PANEL)
        left.add_widget(Label(text='VELOCITA SOG -- ultimi 120s',font_size=sp(16),
                               color=ACCENT,bold=True,size_hint_y=None,height=dp(32)))
        self._chart=Widget(size_hint=(1,1))
        self._chart.bind(pos=self._req_chart,size=self._req_chart)
        left.add_widget(self._chart)
        self._cols.add_widget(left)
        right=BoxLayout(orientation='vertical',spacing=dp(8),
                         padding=dp(10),size_hint_x=0.46)
        _bg(right,PANEL)
        # Pulsante toggle: stesso comportamento della schermata Start.
        # Etichetta dinamica ("Avvia log" / "Ferma log") gestita in tick().
        br=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(70))
        self._log_btn=mk_btn('Avvia log',self._toggle_log,sp(20))
        br.add_widget(self._log_btn)
        right.add_widget(br)
        self._st=Label(text='Log non attivo',font_size=sp(16),color=MUTED,
                        size_hint_y=None,height=dp(60),halign='center',valign='middle')
        self._st.bind(size=lambda l,_: setattr(l,'text_size',l.size))
        right.add_widget(self._st)

        # ----- UPLOAD CLOUD: pulsante "Invia al cloud" + status coda -----
        # Permette upload manuale anche in caso di mancata connettivita'
        # durante la chiusura del log. Lo status mostra n. file in coda
        # e l'esito dell'ultimo tentativo.
        right.add_widget(Label(text='UPLOAD CLOUD',font_size=sp(14),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(24)))
        bu=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(60))
        self._upload_btn=mk_btn('Invia al cloud',self._force_upload,sp(18))
        self._download_btn=mk_btn('Scarica dal cloud',self._download_from_cloud,sp(18))
        bu.add_widget(self._upload_btn)
        bu.add_widget(self._download_btn)
        right.add_widget(bu)
        self._upload_status=Label(text='--',font_size=sp(14),color=MUTED,
                                   size_hint_y=None,height=dp(60),halign='center',valign='middle')
        self._upload_status.bind(size=lambda l,_: setattr(l,'text_size',l.size))
        right.add_widget(self._upload_status)

        right.add_widget(Label(text='DATI REAL-TIME',font_size=sp(16),color=ACCENT,
                                bold=True,size_hint_y=None,height=dp(32)))
        self._rows={}
        for k in ('SOG kn','COG','HDG','TWS kn','TWA','AWS kn','Depth m','VMG kn','Lat','Lon'):
            self._rows[k]=kv_row(right,k+':')
        right.add_widget(Widget())
        self._cols.add_widget(right)

    def _do_resize(self,dt):
        try: Clock.schedule_once(lambda dt:self._draw_chart(),0)
        except: pass

    def _req_chart(self,*_): Clock.schedule_once(lambda dt:self._draw_chart(),0)

    def _toggle_log(self):
        """Stesso toggle della StartLineScreen, opera sul TrackLogger condiviso."""
        tl = self.dm.track_logger
        if tl.is_active():
            tl.stop()
        else:
            ok, msg = tl.start()
            if not ok:
                self._st.text = f'Errore: {msg}'
                self._st.color = RED
                return
        self._refresh_log_ui()

    def _refresh_log_ui(self):
        """Sincronizza pulsante + label di stato col TrackLogger."""
        tl = self.dm.track_logger
        if tl.is_active():
            self._log_btn.text = 'Ferma log'
            self._log_btn.background_color = RED
            self._log_btn.color = (0, 0, 0, 1)
            fn = os.path.basename(tl.get_path() or '')
            self._st.text = f'Attivo (5s): {fn}\n{tl.get_count()} righe'
            self._st.color = GREEN
        else:
            self._log_btn.text = 'Avvia log'
            self._log_btn.background_color = BTN_GRAY
            self._log_btn.color = WHITE
            err = tl.get_last_error()
            if err:
                self._st.text = f'Fermato. Ultimo errore: {err}'
                self._st.color = ORANGE
            elif tl.get_count() > 0:
                self._st.text = f'Fermato -- {tl.get_count()} righe'
                self._st.color = MUTED
            else:
                self._st.text = 'Log non attivo'
                self._st.color = MUTED
        # Aggiorna anche lo status di upload cloud
        self._refresh_upload_ui()

    def _force_upload(self):
        """Pulsante 'Invia al cloud': forza upload dei file in coda.
        L'upload e' asincrono in un thread, qui aggiorniamo solo la UI."""
        tu = getattr(self.dm, 'track_uploader', None)
        if not tu:
            self._upload_status.text = 'Track uploader non disponibile'
            self._upload_status.color = RED
            return
        ok, msg = tu.force_upload()
        # Mostra subito il messaggio (sara' aggiornato dal tick)
        self._upload_status.text = msg or '--'
        self._upload_status.color = GREEN if ok else ORANGE

    def _download_from_cloud(self):
        """Pulsante 'Scarica dal cloud': lista i CSV nel container 'tracks/{boat}/'
        e li scarica tutti localmente in LOG_PATH (sovrascrive se gia' presenti).

        Richiede tracks_sas_token con permessi List+Read (oltre a Write+Create
        gia' usati per l'upload). Lavora in thread separato per non bloccare
        la UI; popup mostra progresso e esito."""
        tu = getattr(self.dm, 'track_uploader', None)
        if not tu:
            self._msg_simple('Errore', 'Track uploader non disponibile')
            return
        if not (self.dm.tracks_sas_token or '').strip():
            self._msg_simple('Scarica dal cloud',
                             'tracks_sas_token non configurato.\n'
                             'Serve SAS con permessi List+Read+Write.')
            return

        status_lbl = Label(text='Lettura lista file remoti...',
                           halign='center', valign='middle')
        pop = Popup(title='Scarica dal cloud', content=status_lbl,
                    size_hint=(0.7, 0.50), auto_dismiss=False)
        pop.open()

        def _worker():
            ok, payload = tu.list_remote_tracks()
            if not ok:
                Clock.schedule_once(
                    lambda dt: _on_done(False, 0, 0, str(payload)), 0)
                return
            files = payload or []
            if not files:
                Clock.schedule_once(
                    lambda dt: _on_done(True, 0, 0,
                                         'Nessun file remoto da scaricare'), 0)
                return

            log_dir = self.dm.log_dir or LOG_PATH
            os.makedirs(log_dir, exist_ok=True)
            ok_count = 0
            err_count = 0
            errors = []
            for i, fn in enumerate(files):
                # Aggiorna progress sul main thread
                Clock.schedule_once(
                    lambda dt, idx=i, tot=len(files), name=fn:
                        setattr(status_lbl, 'text',
                                f'Download {idx+1}/{tot}: {name}'), 0)
                dest = os.path.join(log_dir, fn)
                ok2, err = tu.download_remote_track(fn, dest)
                if ok2:
                    ok_count += 1
                else:
                    err_count += 1
                    errors.append(f'{fn}: {err}')
            summary = (f'{ok_count} scaricati, {err_count} errori')
            if errors:
                # Mostra max 3 errori per non riempire il popup
                summary += '\n\nErrori:\n' + '\n'.join(errors[:3])
                if len(errors) > 3:
                    summary += f'\n... e altri {len(errors)-3}'
            Clock.schedule_once(
                lambda dt: _on_done(err_count == 0, ok_count, err_count,
                                     summary), 0)

        def _on_done(ok, ok_count, err_count, msg):
            log_dir = self.dm.log_dir or LOG_PATH
            status_lbl.text = f'{msg}\n\nDestinazione locale:\n{log_dir}'
            status_lbl.color = GREEN if ok else (ORANGE if ok_count else RED)
            pop.auto_dismiss = True
            box = BoxLayout(orientation='vertical', spacing=dp(8))
            box.add_widget(status_lbl)
            close_btn = Button(text='Chiudi', size_hint_y=None, height=dp(48),
                               background_color=BTN_GRAY, background_normal='',
                               color=WHITE, bold=True)
            close_btn.bind(on_release=lambda _: pop.dismiss())
            box.add_widget(close_btn)
            pop.content = box

        threading.Thread(target=_worker, daemon=True).start()

    def _msg_simple(self, title, text):
        """Helper popup informativo semplice."""
        Popup(title=title,
              content=Label(text=text, halign='center', valign='middle'),
              size_hint=(0.6, 0.30)).open()

    def _refresh_upload_ui(self):
        """Aggiorna la label upload con stato coda + esito ultimo tentativo."""
        tu = getattr(self.dm, 'track_uploader', None)
        if not tu:
            self._upload_status.text = '--'
            return
        n = tu.queue_size()
        parts = []
        if n == 0:
            parts.append('Coda vuota')
        else:
            parts.append(f'{n} file in coda')
        if tu.last_uploaded_filename:
            ts = tu.last_uploaded_ts
            if ts:
                age = max(0, int(time.time() - ts))
                if age < 60:
                    parts.append(f'Ultimo: {tu.last_uploaded_filename} ({age}s fa)')
                elif age < 3600:
                    parts.append(f'Ultimo: {tu.last_uploaded_filename} ({age//60}m fa)')
                else:
                    parts.append(f'Ultimo: {tu.last_uploaded_filename}')
        if tu.last_error:
            parts.append(f'Err: {tu.last_error[:40]}')
        self._upload_status.text = '\n'.join(parts)
        # Colore in base allo stato
        if tu.last_error and n > 0:
            self._upload_status.color = ORANGE
        elif n > 0:
            self._upload_status.color = MUTED
        elif tu.last_uploaded_ts:
            self._upload_status.color = GREEN
        else:
            self._upload_status.color = MUTED

    def _draw_chart(self,*_):
        w=self._chart
        try:
            if w.get_root_window() is None: return
            if w.width<dp(10) or w.height<dp(10): return
            w.canvas.clear()
        except Exception: return
        if len(self._hist)<2: return
        cw,ch=w.width,w.height; mx=max(self._hist) or 1
        hist=self._hist[-120:]; n=len(hist); pts=[]
        for i,v in enumerate(hist):
            x=w.x+dp(5)+i*(cw-dp(10))/max(n-1,1)
            y=w.y+dp(5)+(v/mx)*(ch-dp(10)); pts+=[x,y]
        with w.canvas:
            Color(*MUTED[:3],0.15)
            for i in range(1,4):
                yy=w.y+(ch/4)*i; Line(points=[w.x,yy,w.x+cw,yy],width=dp(0.5))
            Color(*WHITE[:3],0.3)
            Line(points=[w.x+dp(4),w.y+ch-dp(4),w.x+dp(4),w.y+dp(4),
                          w.x+cw-dp(4),w.y+dp(4)],width=dp(1))
            Color(*ACCENT)
            if len(pts)>=4: Line(points=pts,width=dp(2))

    def tick(self,dt):
        super().tick(dt); dm=self.dm
        self._rows['SOG kn'].text=f'{dm.boat_speed:.1f}'
        self._rows['COG'].text   =f'{dm.boat_course:.0f}'
        self._rows['HDG'].text   =f'{dm.boat_heading:.0f}'
        self._rows['TWS kn'].text=f'{dm.true_wind_speed:.1f}'     if dm.true_wind_speed     else '--'
        self._rows['TWA'].text   =f'{dm.true_wind_angle:.0f}'     if dm.true_wind_angle     else '--'
        self._rows['AWS kn'].text=f'{dm.apparent_wind_speed:.1f}' if dm.apparent_wind_speed else '--'
        self._rows['Depth m'].text=f'{dm.depth:.1f}'
        self._rows['VMG kn'].text=f'{dm.vmg:.2f}'                 if dm.vmg                 else '--'
        self._rows['Lat'].text   =f'{dm.gps_lat:.5f}'             if dm.gps_lat             else '--'
        self._rows['Lon'].text   =f'{dm.gps_lon:.5f}'             if dm.gps_lon             else '--'
        self._hist.append(dm.boat_speed)
        if len(self._hist)>120: self._hist.pop(0)
        # NB: NON scriviamo piu' qui il CSV. Lo fa il TrackLogger del dm
        # con un timer dedicato a 5s, indipendente dalla schermata corrente.
        self._refresh_log_ui()
        Clock.schedule_once(lambda dt:self._draw_chart(),0)

# =============================================================================
# 7 -- IMPOSTAZIONI
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

        # ---- SEZIONE AZURE BLOB STORAGE ----
        # Identifica la barca (sottocartella nei container) e il base URL.
        # I SAS token sono mostrati in sola lettura (presente/assente) per
        # sicurezza: l'edit avviene via JSON.
        left.add_widget(Label(text='AZURE BLOB',font_size=sp(18),color=ACCENT,
                               bold=True,size_hint_y=None,height=dp(36)))
        self._boat   = self._field(left, 'Boat ID:',
                                    str(self.dm.cloud_boat_id or BOAT_ID_DEFAULT))
        self._blob_b = self._field(left, 'Blob base:',
                                    str(self.dm.blob_base or BLOB_BASE_DEFAULT))
        # SAS token: 3 indicatori read-only (presente/vuoto). Tap apre _show_path
        # per il riepilogo completo.
        self._sas_lbl = Label(
            text=self._format_sas_status(),
            font_size=sp(13), color=MUTED,
            halign='left', valign='middle',
            size_hint_y=None, height=dp(70))
        self._sas_lbl.bind(size=lambda l,_: setattr(l,'text_size',l.size))
        left.add_widget(self._sas_lbl)

        left.add_widget(Widget())
        self._cols.add_widget(left)

        # COLONNA DESTRA: CLOUD + utility
        info=BoxLayout(orientation='vertical',spacing=dp(8),
                        padding=dp(14),size_hint_x=0.45)
        _bg(info,PANEL)

        # ---- SEZIONE CLOUD UPLOAD ----
        info.add_widget(Label(text='CLOUD UPLOAD',font_size=sp(18),color=ACCENT,
                               bold=True,size_hint_y=None,height=dp(36)))
        # Toggle ON/OFF
        en_row=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(60))
        self._cloud_on  = mk_btn('ON',  lambda: self._set_cloud_enabled(True),  sp(18))
        self._cloud_off = mk_btn('OFF', lambda: self._set_cloud_enabled(False), sp(18))
        en_row.add_widget(self._cloud_on); en_row.add_widget(self._cloud_off)
        info.add_widget(en_row)
        # Status label: font ingrandito, altezza generosa per messaggi di errore
        # SSL lunghi. valign='top' cosi' i messaggi cominciano dall'alto se
        # ce ne sono molti.
        self._cloud_st = Label(text='--',font_size=sp(16),color=MUTED,
                                halign='left',valign='top',
                                size_hint_y=None,height=dp(180))
        self._cloud_st.bind(size=self._cloud_st.setter('text_size'))
        _bg(self._cloud_st, BG)  # sfondo scuro per evidenziarla dal pannello
        info.add_widget(self._cloud_st)
        # Token: mascherato per sicurezza, click apre il popup riepilogo
        self._cloud_tok_lbl = Button(
            text=self._mask_token(self.dm.cloud_token),
            font_size=sp(13), color=WHITE,
            background_color=PANEL, background_normal='',
            halign='left', valign='middle',
            size_hint_y=None, height=dp(50))
        self._cloud_tok_lbl.bind(size=lambda l,_: setattr(l,'text_size',l.size))
        self._cloud_tok_lbl.bind(on_release=lambda _: self._show_path())
        info.add_widget(self._cloud_tok_lbl)
        # Frequenza preset
        self._cloud_freq_btns = {}
        fr_row = BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(56))
        for m in (5, 10, 15, 30):
            b = mk_btn(f'{m}m', lambda mm=m: self._set_cloud_freq(mm), sp(16))
            self._cloud_freq_btns[m] = b
            fr_row.add_widget(b)
        info.add_widget(fr_row)
        # I 3 pulsanti azione su un'unica riga: label brevi per stare in larghezza
        action_row=BoxLayout(spacing=dp(6),size_hint_y=None,height=dp(60))
        action_row.add_widget(mk_btn_gray('Valori path', self._show_path,       sp(14)))
        action_row.add_widget(mk_btn_gray('Invia',       self._cloud_send_now,  sp(14)))
        action_row.add_widget(mk_btn_gray('Ric. conf',   self._reload_cfg,      sp(14)))
        info.add_widget(action_row)
        info.add_widget(Widget())
        self._cols.add_widget(info)

        # Inizializza highlight pulsanti cloud
        self._refresh_cloud_buttons()

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
        # Stato SAS token (mostra solo se sono settati, mai il valore)
        tracks_sas_disp    = '(impostato)' if dm.tracks_sas_token    else '(VUOTO)'
        polars_sas_disp    = '(impostato)' if dm.polars_sas_token    else '(VUOTO)'
        waypoints_sas_disp = '(impostato)' if dm.waypoints_sas_token else '(VUOTO)'
        # URL composti per i tre flussi blob
        wp_url    = dm.download_waypoints_url() or '(boat_id mancante)'
        po_url    = dm.download_polar_url()     or '(boat_id mancante)'
        tracks_url_pattern = (
            f'{(dm.blob_base or "").rstrip("/")}'
            f'/{BLOB_CONTAINER_TRACKS}/{bid_disp}/<filename>.csv')
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
                f"Cloud:       {'ON' if dm.cloud_enabled else 'OFF'} ({dm.cloud_interval_min}m)\n"
                f"Cloud URL:   {dm.cloud_url}\n"
                f"Cloud BoatID:{bid_disp}\n"
                f"Cloud Token: {tok_disp}\n"
                f"Waypoints:   {len(dm.waypoints)}\n"
                f"Boa attiva:  {dm.target_mark or '(nessuna)'}\n\n"
                f"--- AZURE BLOB STORAGE ---\n"
                f"Blob base:   {dm.blob_base}\n"
                f"Boat:        {bid_disp}\n"
                f"Waypoints:   {wp_url}\n"
                f"Polare:      {po_url}\n"
                f"Tracks:      {tracks_url_pattern}\n"
                f"SAS tracks:    {tracks_sas_disp}\n"
                f"SAS polars:    {polars_sas_disp}\n"
                f"SAS waypoints: {waypoints_sas_disp}\n\n"
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
            self._cloud_tok_lbl.text = self._mask_token(self.dm.cloud_token)
            self._ip.text   = str(self.dm.nmea_ip)
            self._port.text = str(self.dm.nmea_port)
            # Refresh campi blob editabili
            if hasattr(self, '_boat'):
                self._boat.text = str(self.dm.cloud_boat_id or BOAT_ID_DEFAULT)
            if hasattr(self, '_blob_b'):
                self._blob_b.text = str(self.dm.blob_base or BLOB_BASE_DEFAULT)
            if hasattr(self, '_sas_lbl'):
                self._sas_lbl.text = self._format_sas_status()
            self._refresh_twd_buttons()
            self._refresh_cloud_buttons()
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
            # Boat ID: se l'utente lo cancella, applica default
            bid = self._boat.text.strip() if hasattr(self, '_boat') else ''
            self.dm.cloud_boat_id = bid if bid else BOAT_ID_DEFAULT
            # Blob base: rimuovi trailing slash e applica default se vuoto
            bb = self._blob_b.text.strip().rstrip('/') if hasattr(self, '_blob_b') else ''
            self.dm.blob_base = bb if bb else BLOB_BASE_DEFAULT
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
                            f'({self.dm.cloud_interval_min} min)\n'
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

    def _set_cloud_enabled(self, enabled):
        """Toggle ON/OFF del cloud uploader."""
        self.dm.cloud_enabled = enabled
        self.dm.save_cfg_safe()
        if enabled:
            self.dm.cloud.start()
        else:
            self.dm.cloud.stop()
        self._refresh_cloud_buttons()

    def _set_cloud_freq(self, minutes):
        """Frequenza upload (5/10/15/30 min)."""
        if minutes not in (5, 10, 15, 30):
            return
        self.dm.cloud_interval_min = minutes
        self.dm.save_cfg_safe()
        self._refresh_cloud_buttons()

    def _refresh_cloud_buttons(self):
        """Evidenzia ON/OFF e il pulsante di frequenza attivo."""
        # ON/OFF
        if self.dm.cloud_enabled:
            self._cloud_on.background_color  = GREEN
            self._cloud_on.color             = (0, 0, 0, 1)
            self._cloud_off.background_color = BTN_GRAY
            self._cloud_off.color            = WHITE
        else:
            self._cloud_on.background_color  = BTN_GRAY
            self._cloud_on.color             = WHITE
            self._cloud_off.background_color = RED
            self._cloud_off.color            = (0, 0, 0, 1)
        # Frequenza
        cur = self.dm.cloud_interval_min
        for m, btn in self._cloud_freq_btns.items():
            if m == cur:
                btn.background_color = ACCENT
                btn.color = (0, 0, 0, 1)
            else:
                btn.background_color = BTN_GRAY
                btn.color = WHITE

    def _cloud_send_now(self):
        """Trigger manuale di un invio immediato. I valori usati sono quelli
        in self.dm (caricati dal config.json)."""
        ok, err = self.dm.cloud.trigger_now()
        if ok:
            Popup(title='Invio',content=Label(text='Invio in corso...'),
                  size_hint=(0.4,0.20)).open()
        else:
            Popup(title='Attendi',content=Label(text=err or 'Rate-limited'),
                  size_hint=(0.4,0.20)).open()

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

    def _format_sas_status(self):
        """Riassunto stato SAS token (presente/vuoto) per la label di Settings.
        Non mostra MAI il valore del token a video, per sicurezza."""
        dm = self.dm
        def m(t):
            t = (t or '').strip()
            if not t:
                return 'VUOTO'
            return f'OK ({len(t)} car.)'
        return ('SAS TOKEN (edit via JSON):\n'
                f'  tracks:    {m(dm.tracks_sas_token)}\n'
                f'  polars:    {m(dm.polars_sas_token)}\n'
                f'  waypoints: {m(dm.waypoints_sas_token)}')

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
        # Aggiorna stato cloud uploader
        cu = self.dm.cloud
        running = cu.is_running()
        last_str = '--'
        if cu.last_sent_ts:
            last_str = datetime.fromtimestamp(cu.last_sent_ts).strftime('%H:%M:%S')
        qsize = cu.queue_size()
        state = 'ATTIVO' if (self.dm.cloud_enabled and running) else 'INATTIVO'
        # Costruzione messaggio: ogni info su riga separata per leggibilita'
        lines = [f'Stato: {state}',
                 f'Inviati: {cu.sent_count}   Ultimo: {last_str}',
                 f'In coda: {qsize}',
                 f'SSL: {_SSL_DIAG}']
        if cu.last_error:
            # Wrap dell'errore su piu' righe se troppo lungo
            err_msg = cu.last_error
            if len(err_msg) > 60:
                # Spezza ogni 60 char circa, sui delimitatori naturali
                err_msg = err_msg.replace(' | ', '\n  ')
            lines.append(f'ERRORE:\n  {err_msg}')
        self._cloud_st.text = '\n'.join(lines)
        # Colore status: verde se attivo e nessun errore, arancio errore, grigio off
        if not self.dm.cloud_enabled:
            self._cloud_st.color = MUTED
        elif cu.last_error:
            self._cloud_st.color = ORANGE
        else:
            self._cloud_st.color = GREEN
        # Aggiorna anche lo stato SAS token (in caso l'utente abbia
        # editato il JSON e fatto "Ric. conf")
        if hasattr(self, '_sas_lbl'):
            self._sas_lbl.text = self._format_sas_status()

# =============================================================================
# APP
# =============================================================================

class SailingTabletApp(App):
    def build(self):
        Window.clearcolor=BG
        self.dm=DataManager()
        self.sm=ScreenManager(transition=FadeTransition(duration=0.10))
        for cls in (NavigationScreen,StartLineScreen,LayLineScreen,
                    WaypointsScreen,PolarScreen,LoggingScreen,SettingsScreen):
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
        # Chiudi il file di log se ancora aperto, cosi' i dati flushed sopravvivono
        try: self.dm.track_logger.stop()
        except: pass
        self.dm.disconnect()

if __name__=='__main__':
    SailingTabletApp().run()
