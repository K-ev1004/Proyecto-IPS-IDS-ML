# =============================================================================
# ids.py v5 — Motor principal del IDS (Intrusion Detection System)
# Captura tráfico de red en tiempo real, detecta patrones de ataque,
# clasifica con ML, persiste en SQLite/CSV y notifica por Telegram
# Universidad UNIPAZ
# =============================================================================
#
# CAMBIOS PRINCIPALES vs v2:
# - Integración de flujos_red.py para cálculo de variables complejas.
# - Integración de mikrotik_api.py para respuesta activa.
# - Análisis de VLANs (Dot1Q) para segmentación.
# =============================================================================

# Módulos estándar del sistema
import os           
import time         
import re           
import socket       
import struct       
import ipaddress    
import sqlite3      
import joblib       
import json         
import pandas as pd
import numpy as np
from datetime import datetime, timezone

# Módulos de concurrencia
from threading import Thread           
from collections import defaultdict, deque  

# Scapy: Framework de captura y análisis de paquetes de red
import scapy.all as scapy              
from scapy.all import AsyncSniffer, conf    
conf.use_pcap = True                        

# Módulos internos del proyecto IDS
from telegram_alert import enviar_alerta          
import mikrotik_api
from flujos_red import FlowTracker

# Importar el módulo de exportador de logs
from log_exporter import registrar_bloqueo_log

# PyQt5: Señales para comunicación entre el motor IDS y la interfaz gráfica
from PyQt5.QtCore import QObject, pyqtSignal


# =============================================================================
# BASE_DIR: Ruta absoluta al directorio del proyecto
# =============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# =============================================================================
# FUNCIÓN: ip_to_int
# =============================================================================
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except socket.error:
        return 0


# =============================================================================
# CLASE: ComunicadorIDS
# =============================================================================
class ComunicadorIDS(QObject):
    nuevo_evento = pyqtSignal(list)
    nuevo_bloqueo = pyqtSignal(list)
    nuevo_trafico = pyqtSignal(str)
    actualizacion_dashboard = pyqtSignal(dict) # Para enviar métricas al dashboard PyQt

comunicador = ComunicadorIDS()


# =============================================================================
# VARIABLES GLOBALES DE ESTADO Y CONFIGURACIÓN
# =============================================================================
sniffing_activo = False
ips_activo = False

# P1/P2: modo autónomo de bloqueo. Se activa en el LAB sin tocar el código:
#   IDS_IPS_AUTONOMO=1  (env)  ->  True = Bloquea via MikroTik
#   default: False (Semi-Autónomo, solo alerta)
modo_ips_autonomo = os.environ.get('IDS_IPS_AUTONOMO', '0') == '1'
sniffer: AsyncSniffer = None

# --- UMBRALES BASE DE DETECCIÓN ---
BASE_THRESHOLD_SYN_FLOOD  = 50    
BASE_THRESHOLD_DDOS       = 500   
BASE_THRESHOLD_UDP_FLOOD  = 500   
TIEMPO_ENTRE_ALERTAS = 30    

# --- ESCANEO DE PUERTOS (v5) ---
# La métrica es "puertos distintos hacia UN MISMO destino dentro de una ventana".
# Los parámetros se pueden ajustar sin tocar código (útil durante la calibración).
PORT_SCAN_WINDOW_S           = int(os.environ.get('IDS_SCAN_WINDOW', 60))
PORT_SCAN_THRESHOLD          = int(os.environ.get('IDS_SCAN_THRESHOLD', 50))
PORT_SCAN_THRESHOLD_INTERNAL = int(os.environ.get('IDS_SCAN_THRESHOLD_INT', 25))
PORT_SCAN_MIN_DESTINOS       = int(os.environ.get('IDS_SCAN_MIN_DST', 20))
PORT_SCAN_WINDOW_LENTA_S     = int(os.environ.get('IDS_SCAN_WINDOW_SLOW', 300))
PORT_SCAN_THRESHOLD_LENTA    = int(os.environ.get('IDS_SCAN_THRESHOLD_SLOW', 80))

# Límites de memoria del detector (evitan fugas en redes de alto tráfico).
PORT_SCAN_MAX_PAQUETES_PAR = 5000      # paquetes guardados por par (src, dst)
PORT_SCAN_MAX_CLAVES       = 50000     # pares (src, dst) simultáneos
LIMPIEZA_SCAN_CADA         = 5000      # paquetes entre purgas oportunistas

# Compatibilidad con la interfaz anterior (obsoleto: usar PORT_SCAN_THRESHOLD).
BASE_PORT_SCAN_THRESHOLD = PORT_SCAN_THRESHOLD

# Versión del motor y de la corrida (trazabilidad de cada alerta).
VERSION_MOTOR = 'ids-5.0.0'
RUN_ID = os.environ.get('IDS_RUN_ID') or datetime.now().strftime('run-%Y%m%d-%H%M%S')

# Modo observación: persiste y muestra los candidatos, pero NO alerta ni bloquea.
IDS_MODO_OBSERVACION = os.environ.get('IDS_MODO_OBSERVACION', '1') == '1'

# --- VARIABLES PARA EWMA (UMBRALES DINÁMICOS) ---
ewma_pps = 0.0
alpha_ewma = 0.1
_pkts_ultimo_segundo = 0

def calcular_umbral_dinamico(base, max_mult=10.0):
    # Base baseline de paquetes por segundo considerados 'normales' para la red
    baseline_esperado = 200.0
    if ewma_pps <= baseline_esperado:
        return base
    
    factor = ewma_pps / baseline_esperado
    factor = min(factor, max_mult) # Evitar que suba indefinidamente
    return int(base * factor)

# --- PROTOCOLOS DE DISCOVERY (RUIDO) ---
DISCOVERY_PORTS = {5353, 5355, 1900, 137, 138}

# Puertos de servicio con tráfico legítimo masivo (p. ej. 7680 = Delivery
# Optimization de Windows Update): excluidos de los contadores de flood.
PUERTOS_SERVICIO_EXCLUIDOS = {7680}

# Persistencia mínima entre eventos de la familia flood (ver guardar_ataque).
# Posible Exploit se incluye: un equipo que habla SMB todo el día generaría
# miles de filas idénticas (misma evidencia, mismo par).
TIPO_FLOOD_EXPLOIT        = ('SYN Flood', 'DDoS Distribuido', 'UDP Flood', 'Posible Exploit')
THROTTLE_PERSISTENCIA_FLOOD = 10
_ultimo_persist_por_clave = {}

# Enfriamiento por par (src, dst) tras alertar un escaneo: un barrido largo
# cruza el umbral una y otra vez al vaciarse la ventana; una alerta cada
# PORT_SCAN_COOLDOWN_PAR segundos por pareja es suficiente.
PORT_SCAN_COOLDOWN_PAR = int(os.environ.get('IDS_SCAN_COOLDOWN', 120))
_ultimo_alerta_scan_par = {}

# Hosts internos de gestión/monitorización: se conectan de forma legítima y
# continua a puertos de explotación (SMB, RDP, VNC...). En 191 h de la v1,
# 172.10.0.57 y 172.10.0.59 concentraron el 45 % de las alertas de exploit.
# VERIFICAR con redes que la lista esté actualizada. Vaciar con
# IDS_HOSTS_GESTION="" para desactivar la exención.
HOSTS_GESTION = set(
    ip.strip() for ip in
    os.environ.get('IDS_HOSTS_GESTION', '172.10.0.57,172.10.0.59').split(',')
    if ip.strip()
)

# IP local del sistema
try:
    from scapy.all import get_if_addr
    MI_IP = get_if_addr(conf.iface)
    print(f"[OK] IP local detectada: {MI_IP}")
except Exception:
    MI_IP = "127.0.0.1"

# --- ESTRUCTURAS DE DATOS DE DETECCIÓN ---
syn_por_src        = defaultdict(list)   # SYN flood: ventana por IP origen
flood_por_dst      = defaultdict(list)   # DDoS / UDP flood: ventana por IP destino
eventos_detectados = deque(maxlen=100)
advertencias_cont  = defaultdict(int)
_ultimo_alerta_por_clave = {}           # (ip_src, tipo_ataque) -> timestamp

# Escaneo de puertos v5: ventana deslizante por par (src, dst).
# Cada entrada guarda (timestamp, puerto, protocolo).
ventana_scan       = defaultdict(deque)
_ultimo_ts_scan    = {}
# Barrido horizontal: (src, puerto) -> {dst: timestamp}
barrido_horizontal = defaultdict(dict)
_ultimo_ts_horizontal = {}
_pkts_desde_limpieza  = 0

# Métricas para el Dashboard
metricas_trafico = {
    'docentes_pkts': 0,
    'admin_pkts': 0,
    'estudiantes_pkts': 0,
    'externos_pkts': 0,
    'pps_actual': 0,
    'flujos_activos': 0,
    'flujos_totales': 0,
    'detecciones_ataque': 0,
    'detecciones_normal': 0,
}


def _clasificar_departamento_ip(ip):
    """Clasifica IP en departamento según subredes UNIPAZ."""
    try:
        partes = ip.strip().split('.')
        if len(partes) != 4:
            return 'externos'
        o1, o2 = int(partes[0]), int(partes[1])
        if o1 == 172 and o2 == 20:
            return 'docentes'
        if o1 == 172 and o2 == 10:
            return 'admin'
        if o1 == 172 and o2 == 30:
            return 'estudiantes'
        return 'externos'
    except Exception:
        return 'externos'


# =============================================================================
# WHITELIST: IPs y rangos de red de confianza — AMPLIADO PARA UNIPAZ
# =============================================================================
IPS_CONFIABLES = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222",
}

RANGOS_CONFIABLES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('20.0.0.0/11'),       
    ipaddress.ip_network('40.0.0.0/8'),        
    ipaddress.ip_network('52.0.0.0/8'),        
    ipaddress.ip_network('54.0.0.0/8'),        
    ipaddress.ip_network('104.16.0.0/12'),     
    ipaddress.ip_network('140.82.0.0/16'),     
    ipaddress.ip_network('143.204.0.0/16'),    
    ipaddress.ip_network('172.217.0.0/16'),    
    ipaddress.ip_network('2.22.20.0/24'),      
    ipaddress.ip_network('13.107.0.0/16'),     
    ipaddress.ip_network('52.114.0.0/16'),     
    ipaddress.ip_network('34.192.0.0/12'),     
    ipaddress.ip_network('35.192.0.0/12'),     
    ipaddress.ip_network('142.250.0.0/16'),    
    ipaddress.ip_network('151.101.0.0/16'),    
]

def ip_en_rangos(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in RANGOS_CONFIABLES)
    except ValueError:
        return False


# =============================================================================
# EXENCIONES DEL DETECTOR DE ESCANEO (v5)
# =============================================================================
# IMPORTANTE: estas exenciones aplican SOLO al origen del escaneo. No se usa
# RANGOS_CONFIABLES aquí porque contiene 172.16.0.0/12, que cubre las subredes
# internas 172.20.x y 172.30.x: eximirlas cegaría el escaneo lateral interno
# (el 20,6 % de las alertas de la v1 venían de orígenes internos).
REDES_UNIPAZ = [
    ipaddress.ip_network('172.10.0.0/16'),
    ipaddress.ip_network('172.20.0.0/16'),
    ipaddress.ip_network('172.30.0.0/16'),
]

IPS_SCAN_EXENTAS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9",
    "208.67.222.222", "208.67.220.220",
}

# CDN y servicios que generaron ~60 % de las alertas de la v1.
# Se usan rangos /16 o más específicos (nunca /8) para no cegar proveedores
# cloud completos donde también puede alojarse un atacante.
RANGOS_SCAN_EXENTOS = [
    ipaddress.ip_network('34.117.0.0/16'),    # Google Cloud LB
    ipaddress.ip_network('57.144.0.0/16'),    # Meta
    ipaddress.ip_network('149.154.0.0/16'),   # Telegram
    ipaddress.ip_network('172.217.0.0/16'),   # Google
    ipaddress.ip_network('142.250.0.0/15'),   # Google
    ipaddress.ip_network('104.16.0.0/13'),    # Cloudflare
]


# =============================================================================
# CARGA DE MODELOS V5 + SQLIGUARD (2a etapa)
# =============================================================================
model_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'pipeline_catboost_v5.pkl')
features_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'selected_features_v5.pkl')
le_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'label_encoder_v5.pkl')

sqli_guard_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'sqli_guard.pkl')
sqli_guard_meta_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'sql_guard_features.pkl')

modelo_ml = None
features_seleccionadas = None
tipo_ataque_encoder = None

sqli_guard = None
SQLI_GUARD_FEATURES = None
UMBRAL_SQLI_GUARD = 0.30

if os.path.exists(model_path) and os.path.exists(features_path) and os.path.exists(le_path):
    try:
        modelo_ml = joblib.load(model_path)
        features_seleccionadas = joblib.load(features_path)
        tipo_ataque_encoder = joblib.load(le_path)
        print("[OK] Modelo ML v5 (Multi-Dataset) cargado correctamente.")
    except Exception as e:
        print(f"[X] Error cargando modelo v5: {e}")
        modelo_ml = None
else:
    print("[!] No se encontró modelo ML v5. Se usará solo detección heurística.")

# SQLiGuard: detector binario dedicado de Inyeccion SQL (2ª etapa)
if os.path.exists(sqli_guard_path) and os.path.exists(sqli_guard_meta_path):
    try:
        sqli_guard = joblib.load(sqli_guard_path)
        _sqli_meta = joblib.load(sqli_guard_meta_path)
        SQLI_GUARD_FEATURES = _sqli_meta['features']
        UMBRAL_SQLI_GUARD = float(_sqli_meta.get('umbral', 0.30))
        print("[OK] SQLiGuard (detector binario SQLi) cargado correctamente.")
        print(f"       Umbral confirmación SQLi: {UMBRAL_SQLI_GUARD}")
    except Exception as e:
        print(f"[X] Error cargando SQLiGuard: {e}")
        sqli_guard = None
else:
    print("[!] No se encontró SQLiGuard. La clase Inyeccion_SQL dependerá solo del modelo v5.")

# Convierte las features CIC del flujo en las features NetFlow que espera
# SQLiGuard (mismas unidades y orden usados en entrenar_sqli_guard.py).
def _features_sqli_guard(features_dict):
    fwd_pkts  = float(features_dict.get('Tot Fwd Pkts', 0) or 0)
    bwd_pkts  = float(features_dict.get('Tot Bwd Pkts', 0) or 0)
    fwd_bytes = float(features_dict.get('TotLen Fwd Pkts', 0) or 0)
    bwd_bytes = float(features_dict.get('TotLen Bwd Pkts', 0) or 0)
    # 'Flow Duration' está en microsegundos (CIC); SQLiGuard se entrenó en ms.
    dur_ms = max(float(features_dict.get('Flow Duration', 0) or 0) / 1000.0, 1e-6)
    # Bitmask TCP OR (0-31) reconstruido desde los contadores de flags.
    tcp_flags = 0
    if float(features_dict.get('FIN Flag Cnt', 0) or 0) > 0: tcp_flags |= 1
    if float(features_dict.get('SYN Flag Cnt', 0) or 0) > 0: tcp_flags |= 2
    if float(features_dict.get('RST Flag Cnt', 0) or 0) > 0: tcp_flags |= 4
    if float(features_dict.get('PSH Flag Cnt', 0) or 0) > 0: tcp_flags |= 8
    if float(features_dict.get('ACK Flag Cnt', 0) or 0) > 0: tcp_flags |= 16
    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    return {
        'src_port':       float(features_dict.get('Src Port', 0) or 0),
        'dst_port':       float(features_dict.get('Dst Port', 0) or 0),
        'protocol':       float(features_dict.get('Protocol', 0) or 0),
        'flow_duration_ms': dur_ms,
        'total_packets':  total_pkts,
        'total_bytes':    total_bytes,
        'flow_byts_s':    float(features_dict.get('Flow Byts/s', 0) or 0),
        'flow_pkts_s':    float(features_dict.get('Flow Pkts/s', 0) or 0),
        'tcp_flags':      float(tcp_flags),
    }


# =============================================================================
# BASE DE DATOS SQLite
# =============================================================================
# Esquema ÚNICO de la tabla `ataques` (v5). Incluye la evidencia de la
# heurística como columnas de primera clase: en la v1 el conteo de puertos se
# perdía guardando la cadena "Múltiples" en `puerto`, lo que hizo imposible
# auditar o recalibrar el detector.
ESQUEMA_ATAQUES = '''
    CREATE TABLE IF NOT EXISTS ataques (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_utc         TEXT NOT NULL,
        timestamp      TEXT,
        tipo_ataque    TEXT NOT NULL,
        origen         TEXT NOT NULL DEFAULT 'heuristica',
        ip_src         TEXT NOT NULL,
        ip_dst         TEXT NOT NULL DEFAULT 'DESCONOCIDA',
        protocolo      TEXT,
        puerto         INTEGER DEFAULT 0,
        n_puertos      INTEGER DEFAULT 0,
        n_destinos     INTEGER DEFAULT 0,
        ventana_s      INTEGER DEFAULT 0,
        umbral         INTEGER DEFAULT 0,
        confianza_ml   REAL DEFAULT 0.0,
        features_json  TEXT,
        evidencia_json TEXT,
        modo           TEXT DEFAULT 'observacion',
        version_motor  TEXT,
        run_id         TEXT,
        vlan_id        INTEGER DEFAULT 0,
        ttl            INTEGER DEFAULT 0,
        packet_size    INTEGER DEFAULT 0
    )
'''

INDICES_ATAQUES = (
    "CREATE INDEX IF NOT EXISTS idx_ataques_ts   ON ataques(ts_utc)",
    "CREATE INDEX IF NOT EXISTS idx_ataques_tipo ON ataques(tipo_ataque, ts_utc)",
    "CREATE INDEX IF NOT EXISTS idx_ataques_src  ON ataques(ip_src, ts_utc)",
    "CREATE INDEX IF NOT EXISTS idx_ataques_run  ON ataques(run_id)",
)

# Columnas v5 que pueden faltar si se abre una base anterior (por ejemplo una
# copia de la BD de pruebas). En una base nueva no se ejecuta ningún ALTER.
COLUMNAS_V5 = {
    'ts_utc':         "TEXT",
    'origen':         "TEXT DEFAULT 'heuristica'",
    'n_puertos':      "INTEGER DEFAULT 0",
    'n_destinos':     "INTEGER DEFAULT 0",
    'ventana_s':      "INTEGER DEFAULT 0",
    'umbral':         "INTEGER DEFAULT 0",
    'evidencia_json': "TEXT",
    'modo':           "TEXT DEFAULT 'observacion'",
    'version_motor':  "TEXT",
    'run_id':         "TEXT",
}

def crear_tabla_ataques(conn):
    """Asegura la tabla `ataques` con el esquema v5 (idempotente)."""
    cur = conn.cursor()
    cur.execute(ESQUEMA_ATAQUES)
    existentes = {fila[1] for fila in cur.execute("PRAGMA table_info(ataques)")}
    for columna, ddl in COLUMNAS_V5.items():
        if columna not in existentes:
            try:
                cur.execute(f"ALTER TABLE ataques ADD COLUMN {columna} {ddl}")
            except sqlite3.OperationalError:
                pass
    for ddl in INDICES_ATAQUES:
        try:
            cur.execute(ddl)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    return cur


# Base de datos de la NUEVA producción. `IDS_DB_PATH` permite apuntar a otra
# ruta (laboratorio, pruebas, una corrida de calibración).
ruta_bd = os.environ.get('IDS_DB_PATH') or os.path.join(BASE_DIR, 'intrusiones_v5.db')
conn   = sqlite3.connect(ruta_bd, check_same_thread=False)
cursor = conn.cursor()

cursor = crear_tabla_ataques(conn)

cursor.execute('''
    CREATE TABLE IF NOT EXISTS bloqueos (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT,
        ip_src     TEXT,
        tipo_ataque TEXT,
        duracion   INTEGER,
        estado     TEXT,
        comando    TEXT,
        respuesta  TEXT,
        confirmado INTEGER DEFAULT 0
    )
''')

# Compatibilidad con BD legacy (columnas de confirmación de bloqueo)
for columna, ddl in [
    ('comando',    "ALTER TABLE bloqueos ADD COLUMN comando TEXT"),
    ('respuesta',  "ALTER TABLE bloqueos ADD COLUMN respuesta TEXT"),
    ('confirmado', "ALTER TABLE bloqueos ADD COLUMN confirmado INTEGER DEFAULT 0"),
]:
    try:
        cursor.execute(ddl)
    except sqlite3.OperationalError:
        pass
conn.commit()


def _enviar_alerta_async(mensaje: str):
    Thread(target=lambda: enviar_alerta(mensaje), daemon=True).start()

# =============================================================================
# FUNCIÓN DE PREDICCIÓN ML (CALLBACK DE FLUJOS_RED)
# =============================================================================
# Umbral unificado de logueo/bloqueo para clasificaciones ML (v3):
# antes se logueaba con >=0.85 y se bloqueaba con >=0.70 (inconsistente:
# había flujos bloqueados sin registro ML). Ahora AMBOS usan >= UMBRAL_ML.
UMBRAL_ML = 0.85

def on_flow_ready(ip_src, ip_dst, features_dict):
    """
    Este callback es llamado por flujos_red.py cuando un flujo expira/se completa.
    Flujo de decisión v3:
      1) El modelo v5 (multiclase, features CIC) predice la clase del flujo.
      2) SQLiGuard (detector binario, 200K SQLi reales) CONFIRMA/NIEGA el SQLi.
         - Si SQLiGuard confirma (P >= umbral) -> Inyeccion_SQL (precision ~99.8%).
         - Si v5 decía Inyeccion_SQL pero SQLiGuard no confirma -> se trata como
           la clase que v5 asigna para la otra rama pero se registra el caso.
    """
    if modelo_ml is None or features_seleccionadas is None:
        return

    try:
        row = [features_dict.get(f, 0) for f in features_seleccionadas]
        df_in = pd.DataFrame([row], columns=features_seleccionadas)

        pred_idx = modelo_ml.predict(df_in)[0]
        if isinstance(pred_idx, (list, np.ndarray)):
            pred_idx = pred_idx[0]

        probs = modelo_ml.predict_proba(df_in)[0]
        confianza_v5 = float(np.max(probs))
        tipo_str = tipo_ataque_encoder.inverse_transform([pred_idx])[0]

        # --- SQLiGuard (2ª etapa) ---
        confianza_guard = 0.0
        es_sqli_guard = False
        if sqli_guard is not None and SQLI_GUARD_FEATURES is not None:
            try:
                fila_guard = {k: _features_sqli_guard(features_dict)[k] for k in SQLI_GUARD_FEATURES}
                df_guard = pd.DataFrame([fila_guard], columns=SQLI_GUARD_FEATURES)
                prob_guard = sqli_guard.predict_proba(df_guard)[0][1]
                confianza_guard = float(prob_guard)
                es_sqli_guard = confianza_guard >= UMBRAL_SQLI_GUARD
            except Exception as e:
                print(f"[X] Error SQLiGuard: {e}")

        # --- Decisión final ---
        metricas_trafico['flujos_totales'] += 1

        if es_sqli_guard:
            tipo_final = 'Inyeccion_SQL'
            confianza_ml = max(confianza_guard, confianza_v5)
            metricas_trafico['detecciones_ataque'] += 1
            guardar_ataque(ip_src, tipo_final, "TCP/UDP", features_dict.get('Dst Port', 0),
                           ip_dst, flag="SQLiGuard", es_ml_puro=True, confianza_ml=confianza_ml,
                           features_json=json.dumps(_features_sqli_guard(features_dict)))
        elif tipo_str != 'Normal':
            # Endurecimiento SQL (P1): si v5 predice Inyeccion_SQL PERO SQLiGuard
            # no la confirma, NUNCA se persiste como SQLi. Se re-mapea a la
            # siguiente clase más probable de v5 (excluyendo SQLi) y se registra
            # el caso descartado en la métrica sql_no_confirmados.
            if tipo_str == 'Inyeccion_SQL':
                metricas_trafico['sql_no_confirmados'] = metricas_trafico.get('sql_no_confirmados', 0) + 1
                order = np.argsort(probs)[::-1]
                top_idx = next((int(i) for i in order if int(i) != int(pred_idx)),
                               int(order[0]))
                tipo_remapeado = tipo_ataque_encoder.inverse_transform([top_idx])[0]
                confianza_remap = float(probs[top_idx])
                if tipo_remapeado != 'Normal' and confianza_remap >= UMBRAL_ML:
                    metricas_trafico['detecciones_ataque'] += 1
                    guardar_ataque(ip_src, tipo_remapeado, "TCP/UDP",
                                   features_dict.get('Dst Port', 0), ip_dst,
                                   flag="REMAP-SQLi", es_ml_puro=True,
                                   confianza_ml=confianza_remap,
                                   features_json=json.dumps(_features_sqli_guard(features_dict)))
                else:
                    metricas_trafico['detecciones_normal'] += 1
            elif confianza_v5 >= UMBRAL_ML:
                metricas_trafico['detecciones_ataque'] += 1
                guardar_ataque(ip_src, tipo_str, "TCP/UDP", features_dict.get('Dst Port', 0),
                               ip_dst, flag="N/A", es_ml_puro=True, confianza_ml=confianza_v5,
                               features_json=json.dumps(_features_sqli_guard(features_dict)))
            else:
                metricas_trafico['detecciones_normal'] += 1
        else:
            metricas_trafico['detecciones_normal'] += 1

    except Exception as e:
        print(f"[X] Advertencia en ML Predict Flow: {e}")

# Instanciamos el tracker global
flow_tracker = FlowTracker(on_flow_ready)


# =============================================================================
# FUNCIÓN: guardar_ataque
# =============================================================================
def guardar_ataque(ip_src, tipo_ataque, protocolo, puerto, ip_dst="DESCONOCIDA", flag="N/A",
                   es_ml_puro=False, confianza_ml=0.0, features_json=None, vlan_id=0, ttl=0,
                   packet_size=0, n_puertos=0, n_destinos=0, ventana_s=0, umbral=0,
                   meta_heuristica=None, forzar=False, origen=None, modo_forzado=None):
    """Persiste un evento de detección y decide su notificación/bloqueo.

    v5 (lecciones de heuristica.md):
      - La persistencia NUNCA está sujeta al throttle: la evidencia no se descarta.
      - El throttle (TIEMPO_ENTRE_ALERTAS) solo limita la notificación y el
        bloqueo, y su clave es (ip_src, tipo_ataque) para que un detector no
        silencie a otro.
      - Cada fila guarda la evidencia de la heurística (n_puertos, ventana,
        umbral, muestra de puertos) para poder auditar y recalibrar.
    """
    if ip_src == MI_IP:
        return

    # Auto-completar datos del paquete desde el dict global
    datos = _ultimo_datos_paquete.get(ip_src, {})
    if not ip_dst or ip_dst == "DESCONOCIDA":
        ip_dst = datos.get("ip_dst", "DESCONOCIDA")
    if not vlan_id:
        vlan_id = datos.get("vlan_id", 0)
    if not ttl:
        ttl = datos.get("ttl", 0)
    if not packet_size:
        packet_size = datos.get("packet_size", 0)

    ahora = time.time()
    ts_utc = datetime.now(timezone.utc).isoformat(timespec='seconds')
    timestamp = time.ctime()

    if es_ml_puro:
        tipo_final = f"{tipo_ataque} (ML: {confianza_ml*100:.1f}%)"
        origen_final = origen or 'ml'
    else:
        tipo_final = f"{tipo_ataque} (Heuristica)"
        origen_final = origen or 'heuristica'

    # `puerto` es siempre numérico (0 = evento agregado). Cualquier texto va en
    # la evidencia. Esto evita repetir el bug "Múltiples" de la v1.
    try:
        puerto_num = int(puerto)
    except (TypeError, ValueError):
        puerto_num = 0

    evidencia = dict(meta_heuristica) if meta_heuristica else None

    # --- Persistencia ---
    # Escaneo y eventos ML: SIEMPRE (cada fila aporta evidencia distinta).
    # Familia flood + Exploit: un barrido de nmap o un host que habla SMB todo
    # el día genera cientos de eventos idénticos; se conserva el primero y
    # luego uno cada THROTTLE_PERSISTENCIA_FLOOD segundos.
    ahora_persist = ahora
    if tipo_ataque in TIPO_FLOOD_EXPLOIT and not forzar:
        ultima = _ultimo_persist_por_clave.get((ip_src, tipo_ataque), 0)
        if ahora_persist - ultima < THROTTLE_PERSISTENCIA_FLOOD:
            return
        _ultimo_persist_por_clave[(ip_src, tipo_ataque)] = ahora_persist

    # --- Decisión de respuesta activa (antes de persistir, para registrar el modo) ---
    t_lower = tipo_final.lower()
    es_critico = ("exploit" in t_lower or "sql" in t_lower or "flood" in t_lower
                  or "ddos" in t_lower or "escaneo" in t_lower or "scan" in t_lower
                  or "bruteforce" in t_lower)
    severidad_ips = "CRITICA" if ("exploit" in t_lower or "sql" in t_lower) else "ALTA"

    puede_bloquear = False
    if es_critico:
        if es_ml_puro:
            puede_bloquear = confianza_ml >= UMBRAL_ML
        else:
            puede_bloquear = True

    if IDS_MODO_OBSERVACION:
        modo = 'observacion'
    elif ips_activo and puede_bloquear:
        modo = 'bloqueo'
    else:
        modo = 'alerta'

    # Un detector puede degradar su propio evento (p. ej. la heurística regex
    # de SQLi genera candidatos, no alertas: solo ML+SQLiGuard confirma).
    if modo_forzado:
        modo = modo_forzado

    # Persistencia en SQLite (SIEMPRE, incluso en modo observación)
    try:
        cursor.execute('''
            INSERT INTO ataques (ts_utc, timestamp, tipo_ataque, origen, ip_src, ip_dst,
                                 protocolo, puerto, n_puertos, n_destinos, ventana_s, umbral,
                                 confianza_ml, features_json, evidencia_json, modo,
                                 version_motor, run_id, vlan_id, ttl, packet_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ts_utc, timestamp, tipo_final, origen_final, ip_src, ip_dst, protocolo,
              puerto_num, n_puertos, n_destinos, ventana_s, umbral, confianza_ml,
              features_json, json.dumps(evidencia) if evidencia else None, modo,
              VERSION_MOTOR, RUN_ID, vlan_id, ttl, packet_size))
        conn.commit()
    except Exception as e:
        print(f"[!] ERROR persistiendo ataque en BD: {e}")

    # Emitir señal Qt (13 elementos: los 10 originales + evidencia agregada y modo)
    evento = [timestamp, ip_src, ip_dst, puerto, protocolo, flag, tipo_final,
              vlan_id, ttl, packet_size, n_puertos, n_destinos, modo]
    eventos_detectados.append(evento)
    comunicador.nuevo_evento.emit(evento)

    # THROTTLE de notificación: solo afecta a Telegram y al bloqueo, nunca a la BD.
    clave_throttle = (ip_src, tipo_ataque)
    debe_alertar = forzar or (ahora - _ultimo_alerta_por_clave.get(clave_throttle, 0) >= TIEMPO_ENTRE_ALERTAS)
    if debe_alertar:
        _ultimo_alerta_por_clave[clave_throttle] = ahora
        advertencias_cont[ip_src] += 1

    # Alerta Telegram: el modo del MANDA es el del evento, no solo el global
    # (un evento forzado a 'observacion' —p. ej. SQLi regex— nunca notifica).
    if debe_alertar and modo != 'observacion':
        mensaje = (
            f"SISTEMA DE INTRUSION:\n"
            f"ALERT [IDS] {tipo_final} detectado\n"
            f"IP Origen: {ip_src}\n"
            f"IP Destino: {ip_dst}\n"
            f"Protocolo: {protocolo}\n"
            f"Detalle: {n_puertos} puertos / {n_destinos} destinos (umbral {umbral})\n"
        )
        try:
            _enviar_alerta_async(mensaje)
        except Exception:
            pass

    # --- LÓGICA DE RESPUESTA ACTIVA (IPS) ---
    # `modo` ya se decidió antes de persistir: solo se bloquea si el evento se
    # registró como 'bloqueo' (nunca en modo observación).
    if modo == 'bloqueo':
        print(f"ALERT [IPS] Criterios de bloqueo cumplidos para {ip_src} | Tipo: {tipo_ataque} | Severidad: {severidad_ips}")

        duracion = 24 # 24 horas por defecto en MikroTik
        resultado_bloqueo = None
        comando = ''
        respuesta = ''
        confirmado = 0

        if modo_ips_autonomo:
            try:
                # Intento de bloqueo vía MikroTik Core (con readback de confirmación)
                resultado_bloqueo = mikrotik_api.bloquear_ip_mikrotik(ip_src, duracion_horas=duracion)
            except Exception as e:
                print(f"[!] Bloqueo MikroTik fallido: {e}")
                resultado_bloqueo = {'ok': False, 'modo': 'error', 'confirmado': False,
                                     'comando': '', 'respuesta': str(e), 'error': str(e)}
        else:
            print(f"[*] Modo Semi-Autónomo activo. Bloqueo de {ip_src} omitido (Solo Alerta).")

        if isinstance(resultado_bloqueo, dict):
            ok_bloqueo = resultado_bloqueo.get('ok', False)
            modo_respuesta = resultado_bloqueo.get('modo', 'error')
            confirmado = 1 if resultado_bloqueo.get('confirmado', False) else 0
            comando = resultado_bloqueo.get('comando', '')
            respuesta = resultado_bloqueo.get('respuesta', '')
            if confirmado:
                estado_bd = 'CONFIRMADO'
            elif modo_respuesta == 'mock':
                estado_bd = 'SIMULADO'
            elif ok_bloqueo:
                estado_bd = 'ACTIVO'
            else:
                estado_bd = 'ERROR'
        else:
            # Retorno booleano (compatibilidad): True = ACTIVO, False = SIMULADO/SEMI
            ok_bloqueo = bool(resultado_bloqueo)
            estado_bd = 'ACTIVO' if ok_bloqueo else 'SIMULADO/SEMI'

        try:
            cursor.execute('''
                INSERT INTO bloqueos (timestamp, ip_src, tipo_ataque, duracion, estado,
                                      comando, respuesta, confirmado)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, ip_src, tipo_final, duracion, estado_bd,
                  comando, respuesta, confirmado))
            conn.commit()
        except Exception as e:
            print(f"[!] No se pudo registrar el bloqueo en BD: {e}")

        # Registrar el bloqueo en el archivo .log
        registrar_bloqueo_log(ip_src, f"BLOQUEO_{tipo_ataque.upper().replace(' ', '_')}", duracion)

        estado_bd_lower = estado_bd.lower()
        if 'confirmado' in estado_bd_lower:
            accion = "Bloqueo real confirmado (MikroTik)"
        elif estado_bd_lower in ('simulado', 'simulado/semi'):
            accion = "Sin bloqueo real (modo simulado/semi-autónomo)"
        else:
            accion = "Error en bloqueo (MikroTik)"
        comunicador.nuevo_bloqueo.emit([ip_src, accion, duracion, tipo_ataque, severidad_ips])


# =============================================================================
# FUNCIÓN: mostrar_paquete y Métricas Dashboard
# =============================================================================
_ultimo_tiempo_emision = 0

def procesar_metricas(packet):
    # Clasificar por subred IP (departamento UNIPAZ)
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        depto = _clasificar_departamento_ip(ip_src)
    else:
        depto = 'externos'

    if depto == 'docentes':
        metricas_trafico['docentes_pkts'] += 1
    elif depto == 'admin':
        metricas_trafico['admin_pkts'] += 1
    elif depto == 'estudiantes':
        metricas_trafico['estudiantes_pkts'] += 1
    else:
        metricas_trafico['externos_pkts'] += 1

    # Emitir métricas al dashboard cada 1 segundo
    global _ultimo_tiempo_emision, _pkts_ultimo_segundo, ewma_pps
    _pkts_ultimo_segundo += 1
    current_time = time.time()

    if current_time - _ultimo_tiempo_emision > 1.0:
        # Actualización EWMA
        if ewma_pps == 0.0:
            ewma_pps = _pkts_ultimo_segundo
        else:
            ewma_pps = alpha_ewma * _pkts_ultimo_segundo + (1 - alpha_ewma) * ewma_pps

        metricas_trafico['pps_actual'] = _pkts_ultimo_segundo
        metricas_trafico['flujos_activos'] = len(flow_tracker.flujos) if hasattr(flow_tracker, 'flujos') else 0

        comunicador.actualizacion_dashboard.emit(metricas_trafico.copy())

        # Reset contadores por segundo
        metricas_trafico['docentes_pkts'] = 0
        metricas_trafico['admin_pkts'] = 0
        metricas_trafico['estudiantes_pkts'] = 0
        metricas_trafico['externos_pkts'] = 0

        resumen = packet.summary()
        comunicador.nuevo_trafico.emit(resumen)
        _ultimo_tiempo_emision = current_time
        _pkts_ultimo_segundo = 0


# =============================================================================
# DETECTORES DE ATAQUES (HEURÍSTICA DE RESPALDO)
# =============================================================================

def detectar_syn_flood(packet):
    if packet.haslayer(scapy.TCP) and str(packet[scapy.TCP].flags) == 'S':
        ip_src  = packet[scapy.IP].src
        ip_dst  = packet[scapy.IP].dst
        puerto  = packet[scapy.TCP].dport

        if puerto in PUERTOS_SERVICIO_EXCLUIDOS:
            return
        # Exención de origen (CDN/DNS): un CDN abre conexiones reales con SYN,
        # pero nunca a 50 puertos/0,5 s hacia el mismo destino.
        if _es_origen_exento_scan(ip_src):
            return

        t       = time.time()

        # Contador propio de SYN flood (v5: antes compartía dict con DDoS,
        # que indexa por destino -> contaminación cruzada de contadores).
        syn_por_src[ip_src].append(t)
        syn_por_src[ip_src] = [ts for ts in syn_por_src[ip_src] if t - ts <= 0.5]

        if len(syn_por_src[ip_src]) > calcular_umbral_dinamico(BASE_THRESHOLD_SYN_FLOOD):
            guardar_ataque(ip_src, "SYN Flood", 'TCP', puerto, ip_dst, flag='S')

def detectar_ddos(packet):
    if packet.haslayer(scapy.IP):
        ip_dst   = packet[scapy.IP].dst
        ip_src   = packet[scapy.IP].src

        if packet.haslayer(scapy.TCP):
            # Un DDoS es una ráfaga de SYN sin ACK. Contar también data/ACK
            # (como en la v1) convertía el tráfico legítimo de un servidor
            # popular en 'DDoS' (causa de los FP hacia 172.10.12.216).
            flags = str(packet[scapy.TCP].flags)
            if 'A' in flags:
                return
            puerto = packet[scapy.TCP].dport
            protocolo = 'TCP'
        elif packet.haslayer(scapy.UDP):
            puerto = packet[scapy.UDP].dport
            protocolo = 'UDP'
        else:
            return

        if puerto in DISCOVERY_PORTS or puerto in PUERTOS_SERVICIO_EXCLUIDOS:
            return
        # El flood UDP tiene su propio detector y umbral; aquí solo TCP.
        if protocolo != 'TCP':
            return
        # Exención de origen (CDN/DNS): sus SYN son apertura real de conexiones.
        if _es_origen_exento_scan(ip_src):
            return

        t = time.time()
        flood_por_dst[ip_dst].append(t)
        flood_por_dst[ip_dst] = [ts for ts in flood_por_dst[ip_dst] if t - ts <= 1]

        if len(flood_por_dst[ip_dst]) > calcular_umbral_dinamico(BASE_THRESHOLD_DDOS):
            guardar_ataque(ip_src, "DDoS Distribuido", protocolo, puerto, ip_dst)

# =============================================================================
# ESCANEO DE PUERTOS v5 — ventana deslizante por par (src, dst)
# =============================================================================
def _es_ip_interna(ip):
    """True si la IP pertenece a la red UNIPAZ o a un rango privado."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or any(a in red for red in REDES_UNIPAZ)


def _es_origen_exento_scan(ip):
    """Exenciones explícitas para el detector de escaneo (CDN/DNS).

    Deliberadamente NO usa RANGOS_CONFIABLES: incluye 172.16.0.0/12, que cubre
    las subredes internas 172.20.x y 172.30.x, y eximirlas cegaría la
    detección de escaneo lateral interno.
    """
    if ip in IPS_SCAN_EXENTAS:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in red for red in RANGOS_SCAN_EXENTOS)


def _registrar_scan_vertical(ip_src, ip_dst, proto, puertos, ventana_s, umbral, etiqueta):
    meta = {
        "heuristic": etiqueta,
        "n_distinct_ports": len(puertos),
        "threshold": umbral,
        "window_s": ventana_s,
        "ports_sample": sorted(puertos)[:50],
        "policy": "v5",
    }
    guardar_ataque(ip_src, "Escaneo de Puertos", proto, 0, ip_dst,
                   n_puertos=len(puertos), n_destinos=1, ventana_s=ventana_s,
                   umbral=umbral, meta_heuristica=meta)


def detectar_barrido_horizontal(ip_src, ip_dst, puerto, proto, ahora):
    """Detecta `nmap -p <puerto> <subred>`: un puerto hacia muchos destinos."""
    clave = (ip_src, puerto)
    destinos = barrido_horizontal[clave]
    destinos[ip_dst] = ahora
    for d in [d for d, ts in destinos.items() if ahora - ts > PORT_SCAN_WINDOW_S]:
        del destinos[d]
    _ultimo_ts_horizontal[clave] = ahora

    if len(destinos) > PORT_SCAN_MIN_DESTINOS:
        meta = {
            "heuristic": "port_scan_horizontal",
            "n_destinations": len(destinos),
            "threshold": PORT_SCAN_MIN_DESTINOS,
            "window_s": PORT_SCAN_WINDOW_S,
            "port": puerto,
            "destinations_sample": sorted(destinos)[:50],
            "policy": "v5",
        }
        guardar_ataque(ip_src, "Escaneo Horizontal", proto, puerto, ip_dst,
                       n_puertos=1, n_destinos=len(destinos), ventana_s=PORT_SCAN_WINDOW_S,
                       umbral=PORT_SCAN_MIN_DESTINOS, meta_heuristica=meta)
        destinos.clear()


def _limpiar_estructuras_scan(ahora):
    """Purga oportunistas de memoria (cada LIMPIEZA_SCAN_CADA paquetes).

    Sin esto, las claves (src, dst) inactivas se acumulan indefinidamente:
    la v1 nunca limpiaba y la ventana propuesta en el borrador anterior
    ('if not v: del ...') tampoco liberaba nada."""
    global _pkts_desde_limpieza
    _pkts_desde_limpieza += 1
    if _pkts_desde_limpieza < LIMPIEZA_SCAN_CADA:
        return
    _pkts_desde_limpieza = 0

    limite = ahora - PORT_SCAN_WINDOW_LENTA_S
    for clave in [k for k, ts in _ultimo_ts_scan.items() if ts < limite]:
        _ultimo_ts_scan.pop(clave, None)
        ventana_scan.pop(clave, None)
    for clave in [k for k, ts in _ultimo_ts_horizontal.items() if ts < limite]:
        _ultimo_ts_horizontal.pop(clave, None)
        barrido_horizontal.pop(clave, None)
    for clave in [k for k, ts in _ultimo_alerta_scan_par.items() if ts < limite]:
        _ultimo_alerta_scan_par.pop(clave, None)

    # Tope duro de claves: si se supera, se descartan las más antiguas.
    if len(ventana_scan) > PORT_SCAN_MAX_CLAVES:
        exceso = len(ventana_scan) - PORT_SCAN_MAX_CLAVES
        for clave in sorted(_ultimo_ts_scan, key=_ultimo_ts_scan.get)[:exceso]:
            _ultimo_ts_scan.pop(clave, None)
            ventana_scan.pop(clave, None)


def detectar_escaneo_puertos(packet):
    """v5: cuenta puertos DISTINTOS hacia UN destino dentro de una ventana.

    Corrige los cuatro defectos de la v1 (ver heuristica.md):
      1) conteo por par (src, dst), no global por IP origen;
      2) ventana deslizante que caduca (antes el set nunca se vaciaba);
      3) la evidencia (n_puertos, ventana, umbral, muestra) se persiste;
      4) exenciones explícitas de CDN/DNS.
    Solo cuenta paquetes de INICIACIÓN (sin ACK ni RST): las respuestas de un
    servidor (SA/RST) no se confunden con un escaneo, y los escaneos stealth
    (-sF/-sN/-sX) siguen detectándose.
    """
    if not packet.haslayer(scapy.IP):
        return

    ip_src = packet[scapy.IP].src
    ip_dst = packet[scapy.IP].dst

    if ip_src == MI_IP:
        return
    if _es_origen_exento_scan(ip_src):
        return

    if packet.haslayer(scapy.TCP):
        flags = str(packet[scapy.TCP].flags)
        if 'A' in flags or 'R' in flags:
            return
        proto = 'TCP'
        puerto = packet[scapy.TCP].dport
    elif packet.haslayer(scapy.UDP):
        proto = 'UDP'
        puerto = packet[scapy.UDP].dport
        if puerto in DISCOVERY_PORTS:
            return
    else:
        return

    if not (0 < puerto <= 65535):
        return

    ahora = time.time()

    # Barrido horizontal: mismo puerto hacia muchos destinos
    detectar_barrido_horizontal(ip_src, ip_dst, puerto, proto, ahora)

    # Ventana deslizante por par (src, dst): retención hasta la ventana lenta
    clave = (ip_src, ip_dst)
    dq = ventana_scan[clave]
    dq.append((ahora, puerto, proto))
    while dq and ahora - dq[0][0] > PORT_SCAN_WINDOW_LENTA_S:
        dq.popleft()
    while len(dq) > PORT_SCAN_MAX_PAQUETES_PAR:
        dq.popleft()
    _ultimo_ts_scan[clave] = ahora

    interna = _es_ip_interna(ip_dst)
    umbral = PORT_SCAN_THRESHOLD_INTERNAL if interna else PORT_SCAN_THRESHOLD

    # Enfriamiento por par: tras alertar, no repetir hasta que expire
    ultima_alerta = _ultimo_alerta_scan_par.get(clave, 0)
    en_enfriamiento = (ahora - ultima_alerta) < PORT_SCAN_COOLDOWN_PAR

    # Ventana corta: escaneo clásico
    puertos_corta = {p for (t, p, _) in dq if ahora - t <= PORT_SCAN_WINDOW_S}
    if len(puertos_corta) > umbral:
        if not en_enfriamiento:
            _registrar_scan_vertical(ip_src, ip_dst, proto, puertos_corta,
                                     PORT_SCAN_WINDOW_S, umbral, "port_scan_vertical")
            _ultimo_alerta_scan_par[clave] = ahora
        dq.clear()
        return

    # Ventana larga: escaneos lentos (-T1/-T2), severidad equivalente pero
    # umbral más alto para no duplicar la alerta de la ventana corta
    puertos_lenta = {p for (_, p, _) in dq}
    if len(puertos_lenta) > PORT_SCAN_THRESHOLD_LENTA:
        if not en_enfriamiento:
            _registrar_scan_vertical(ip_src, ip_dst, proto, puertos_lenta,
                                     PORT_SCAN_WINDOW_LENTA_S, PORT_SCAN_THRESHOLD_LENTA,
                                     "port_scan_vertical_lento")
            _ultimo_alerta_scan_par[clave] = ahora
        dq.clear()
        return

    _limpiar_estructuras_scan(ahora)

def detectar_exploit(packet):
    if not packet.haslayer(scapy.IP):
        return

    ip_src = packet[scapy.IP].src
    # Exención: DNS/CDN + hosts de gestión (ver HOSTS_GESTION). Se mantiene
    # ip_en_rangos porque cada estación Windows habla SMB/RDP de forma normal:
    # sin esa exención masiva, la detección interna de exploits sería un storm
    # de falsos positivos.
    if ip_src in IPS_CONFIABLES or ip_en_rangos(ip_src) or ip_src in HOSTS_GESTION:
        return

    ip_dst    = packet[scapy.IP].dst
    protocolo = 'TCP' if packet.haslayer(scapy.TCP) else 'UDP' if packet.haslayer(scapy.UDP) else 'OTRO'

    if protocolo not in {'TCP', 'UDP'}:
        return

    puerto = packet[scapy.TCP].dport if protocolo == 'TCP' else packet[scapy.UDP].dport
    flag   = str(packet[scapy.TCP].flags) if protocolo == 'TCP' else 'N/A'

    if puerto == 0:
        return

    PUERTOS_EXPLOIT = {135, 139, 445, 3389, 5900, 21, 22, 23, 69}

    if puerto in PUERTOS_EXPLOIT:
        if protocolo == 'TCP' and flag not in ['S', 'SA']:
            return
        guardar_ataque(ip_src, "Posible Exploit", protocolo, puerto, ip_dst, flag=flag,
                       meta_heuristica={"heuristic": "exploit_port",
                                        "port": puerto, "flag": flag, "policy": "v5"})

_MARCAS_SENSIBLES = ('password', 'passwd', 'pwd=', 'authorization', 'token', 'secret')


def _sanear_muestra_sqli(carga, limite=80):
    """Muestra del payload para evidencia: truncada y sin posibles credenciales."""
    bajo = carga.lower()
    if any(marca in bajo for marca in _MARCAS_SENSIBLES):
        return "<payload omitido: contiene posibles credenciales>"
    return carga[:limite]


def detectar_sql_injection(packet):
    if packet.haslayer(scapy.Raw):
        try:
            ip_src = packet[scapy.IP].src
            if ip_src in IPS_CONFIABLES or ip_en_rangos(ip_src):
                return

            carga = packet[scapy.Raw].load.decode(errors='ignore')

            if not carga.isascii() or len(carga) > 1000:
                return

            puerto = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0
            if puerto == 0 or puerto > 65535:
                return

            exclusiones = ["order=desc", "session=", "csrf", "user-agent", "host"]
            if any(excl in carga.lower() for excl in exclusiones):
                return

            sql_pattern = re.compile(
                r"(?i)(\b(select|union|insert|update|delete|drop|alter|exec|cast)\b"
                r".?(--|#|;|/\|\*/)|"
                r"('(\s)or(\s)\d+=\d+)|"
                r"(\bunion\b.*\bselect\b))"
            )
            if sql_pattern.search(carga):
                ip_dst = packet[scapy.IP].dst
                # v5: la heurística regex genera CANDIDATOS (persiste en modo
                # observación), nunca alerta por sí sola — SQLiGuard es el
                # árbitro (docs/PLAN_LANZAMIENTO_V5.md §3.3).
                guardar_ataque(ip_src, "SQL Injection", "TCP", puerto, ip_dst,
                               modo_forzado='observacion',
                               meta_heuristica={
                                   "heuristic": "sqli_regex",
                                   "muestra": _sanear_muestra_sqli(carga),
                                   "policy": "v5",
                               })
        except Exception:
            pass

def detectar_udp_flood(packet):
    if packet.haslayer(scapy.UDP):
        ip_dst    = packet[scapy.IP].dst
        ip_src    = packet[scapy.IP].src
        puerto    = packet[scapy.UDP].dport

        if puerto in DISCOVERY_PORTS:
            return
        if _es_origen_exento_scan(ip_src):
            return

        t = time.time()
        flood_por_dst[ip_dst].append(t)
        flood_por_dst[ip_dst] = [ts for ts in flood_por_dst[ip_dst] if t - ts <= 1]

        if len(flood_por_dst[ip_dst]) > calcular_umbral_dinamico(BASE_THRESHOLD_UDP_FLOOD):
            guardar_ataque(ip_src, "UDP Flood", 'UDP', puerto, ip_dst)


# =============================================================================
# FUNCIÓN: procesar_paquete
# =============================================================================
# Datos del ultimo paquete por IP (para pasar a guardar_ataque)
_ultimo_datos_paquete = {}

def procesar_paquete(packet):
    try:
        procesar_metricas(packet)

        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            packet_len = len(packet)
            timestamp = packet.time
            ttl = packet[scapy.IP].ttl

            vlan_id = 0
            if packet.haslayer(scapy.Dot1Q):
                vlan_id = packet[scapy.Dot1Q].vlan

            protocolo = 'OTRO'
            puerto_src = 0
            puerto_dst = 0
            tcp_flags = None
            
            if packet.haslayer(scapy.TCP):
                protocolo = 'TCP'
                puerto_src = packet[scapy.TCP].sport
                puerto_dst = packet[scapy.TCP].dport
                tcp_flags = str(packet[scapy.TCP].flags)
            elif packet.haslayer(scapy.UDP):
                protocolo = 'UDP'
                puerto_src = packet[scapy.UDP].sport
                puerto_dst = packet[scapy.UDP].dport

            # Guardar datos del paquete para guardar_ataque()
            _ultimo_datos_paquete[ip_src] = {
                "ip_dst": ip_dst,
                "vlan_id": vlan_id,
                "ttl": ttl,
                "packet_size": packet_len,
            }

            # Alimentar el FlowTracker para ML
            flow_tracker.procesar_paquete(
                ip_src, ip_dst, puerto_src, puerto_dst, 
                protocolo, packet_len, tcp_flags, timestamp
            )

            # Heurística de respaldo (inmediata)
            detectar_syn_flood(packet)
            detectar_ddos(packet)
            detectar_escaneo_puertos(packet)
            detectar_exploit(packet)
            detectar_sql_injection(packet)
            detectar_udp_flood(packet)
    except Exception as e:
        print(f"[X] Excepcion en procesar_paquete: {e}")


# =============================================================================
# CONTROL DEL SNIFFER
# =============================================================================
def iniciar_monitoreo(iface=None):
    global sniffing_activo, sniffer
    if sniffing_activo:
        return

    sniffing_activo = True
    sniffer = AsyncSniffer(iface=iface, prn=procesar_paquete, store=False, filter=None)
    try:
        sniffer.start()
        print("[OK] AsyncSniffer arrancado correctamente.")
    except Exception as e:
        print(f"[X] Error iniciando AsyncSniffer: {e}")
        sniffing_activo = False

def detener_monitoreo():
    global sniffing_activo, sniffer
    if not sniffing_activo:
        return
    sniffing_activo = False
    try:
        if sniffer is not None:
            sniffer.stop()
            sniffer = None
            print("[OK] AsyncSniffer detenido.")
    except Exception as e:
        pass

if __name__ == "__main__":
    iniciar_monitoreo()
    time.sleep(10)
    detener_monitoreo()
    conn.close()
