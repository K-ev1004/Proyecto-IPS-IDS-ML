# -*- coding: utf-8 -*-
# =============================================================================
# t5_routeros_ips.py - PRUEBA T5: IPS sobre RouterOS REAL (CHR) en el LAB.
# Universidad UNIPAZ - Proyecto IDS/IPS (Fase III).
# -----------------------------------------------------------------------------
# ORIGEN DE ESTE ARCHIVO: kit _lab/ (se disena y se ejecuta en la MAQUINA
# OBJETIVO con VirtualBox y capacidad para 3 VMs). Esta maquina actual NO lo
# ejecuta: no hay CHR ni VMs levantadas aqui.
#
# Cadena verificada:
#   1) CHR alcance(SSH) + version RouterOS + reglas de drop presentes.
#   2) Ping BASELINE atacante(10.10.0.50) -> victima(10.10.1.50) OK.
#   3) Deteccion determinista con features SQLi de D2 a traves de la ruta de
#      produccion (ids.on_flow_ready) usando la IP del atacante del lab ->
#      bloqueo autonomo real (bloquear_ip_mikrotik) -> readback CONFIRMADO.
#   4) Diferencial: atacante -> victima deja de responder (drop forward).
#      Corroboracion: contador de la regla forward incrementado + address-list.
#   5) Desbloqueo (readback vacio) -> conectividad restaurada.
#   6) Gates PASS/FAIL + evidencias en docs/lab/.
#
# Uso (maquina objetivo):
#   setx MIKROTIK_PROFILE lab   (o config/mikrotik_lab.json con credenciales CHR)
#   setx IDS_IPS_AUTONOMO 1
#   python t5_routeros_ips.py
# =============================================================================
import os
import sys
import json
import sqlite3
import tempfile

_LAB = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_LAB)
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

# --- Credenciales del entorno de pruebas (lab), nunca en el codigo ---
def _leer_perfil_lab():
    ruta = os.path.join(_PROJ, 'config', 'mikrotik_lab.json')
    if os.path.exists(ruta):
        with open(ruta, encoding='utf-8') as f:
            return json.load(f)
    return {}

def _alpine_creds():
    ruta = os.path.join(_LAB, 'alpine.json')
    cfg = {}
    if os.path.exists(ruta):
        with open(ruta, encoding='utf-8') as f:
            cfg = json.load(f)
    atacante = cfg.get('atacante', {})
    victima = cfg.get('victima', {})
    return {
        'atacante': {
            'host': os.environ.get('LAB_ATACANTE_IP', atacante.get('host', '10.10.0.50')),
            'user': atacante.get('user', 'root'),
            'pass': os.environ.get('LAB_ATACANTE_PASS', atacante.get('pass', '')),
        },
        'victima': {
            'host': os.environ.get('LAB_VICTIMA_IP', victima.get('host', '10.10.1.50')),
            'user': victima.get('user', 'root'),
            'pass': os.environ.get('LAB_VICTIMA_PASS', victima.get('pass', '')),
        },
    }

ATACANTE = '10.10.0.50'
VICTIMA = '10.10.1.50'

_perfil_chr = _leer_perfil_lab()
os.environ.setdefault('MIKROTIK_PROFILE', _perfil_chr.get('perfil', 'lab'))
os.environ.setdefault('MIKROTIK_IP', os.environ.get('MIKROTIK_IP', _perfil_chr.get('ip', '10.10.0.2')))
# LOGS aislados ANTES de importar ids (importa log_exporter).
os.environ['LOG_FOLDER'] = tempfile.mkdtemp(prefix='t5_logs_')

# --- Import del motor con la ruta 100% de produccion ---
import ids                    # noqa: E402
import mikrotik_api           # noqa: E402

try:
    import paramiko
except ImportError:
    sys.exit("[X] Falta 'paramiko'. Instale:  pip install paramiko")

import pandas as pd           # noqa: E402

EVID = os.path.join(_PROJ, 'docs', 'lab')
os.makedirs(EVID, exist_ok=True)

# =============================================================================
# Utilidades SSH
# =============================================================================
def ssh_run(host, user, pwd, cmd, port=22, timeout=10):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, port=port, username=user, password=pwd, timeout=timeout)
    _, out, err = cli.exec_command(cmd, timeout=timeout)
    rc = out.channel.recv_exit_status()
    salida = out.read().decode(errors='replace') or ''
    error = err.read().decode(errors='replace') or ''
    cli.close()
    return rc, salida.strip(), error.strip()

def ssh_chr(cmd):
    return ssh_run(os.environ['MIKROTIK_IP'], mikrotik_api.ROUTER_USER,
                   mikrotik_api.ROUTER_PASS, cmd,
                   port=int(mikrotik_api.ROUTER_PORT))

def guardar_evidencia(nombre, contenido):
    ruta = os.path.join(EVID, nombre)
    with open(ruta, 'w', encoding='utf-8') as f:
        f.write(contenido)
    print(f"      [evidencia] {ruta}")
    return ruta

# =============================================================================
# Convierte fila NetFlow D2 -> features CIC de produccion (igual que T3)
# =============================================================================
def netflow_a_cic_fecha(row):
    dv = abs(float(row['last']) - float(row['first']))
    dur_ms = max(dv, 1e-6)
    prot = int(row.get('prot', 0))
    flags = int(row.get('tcp_flags', 0))
    def cnt(bit):
        return 1 if flags & bit else 0
    total_pkts = int(row.get('dpkts', 0))
    total_bytes = int(row.get('doctets', 0))
    dur_s = dur_ms / 1000.0
    feat = {
        'Src Port': float(row.get('srcport', 0)),
        'Dst Port': float(row.get('dstport', 0)),
        'Protocol': prot,
        'Flow Duration': dur_ms * 1000.0,
        'Tot Fwd Pkts': total_pkts, 'Tot Bwd Pkts': 0,
        'TotLen Fwd Pkts': total_bytes, 'TotLen Bwd Pkts': 0,
        'Flow Byts/s': total_bytes / dur_s,
        'Flow Pkts/s': total_pkts / dur_s,
        'FIN Flag Cnt': cnt(1), 'SYN Flag Cnt': cnt(2),
        'RST Flag Cnt': cnt(4), 'PSH Flag Cnt': cnt(8),
        'ACK Flag Cnt': cnt(16), 'URG Flag Cnt': cnt(32),
        '_y': 1 if int(row.get('Label', 0)) == 1 else 0,
    }
    return feat

# DDL de la tabla bloqueos en la BD temporal (igual a la de produccion)
DDL_BLOQUEOS = '''
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
'''

RESULTADOS = {}
gates = []

def gate(nombre, ok, detalle):
    gates.append({'prueba': nombre, 'pass': bool(ok), 'detalle': detalle})
    print(f"    GATE {nombre}: {'PASS' if ok else 'FAIL'}  ({detalle})")

# =============================================================================
# 0) PRE-REVISIÓN
# =============================================================================
print("[T5] Prueba IPS contra RouterOS real (usando la cadena de producción) ...")
if mikrotik_api.ROUTER_PASS == 'LAB_PENDIENTE_CONFIG':
    sys.exit("[X] Credenciales CHR no configuradas (config/mikrotik_lab.json o MIKROTIK_*).")
chrome = _alpine_creds()
if not chrome['atacante']['pass']:
    sys.exit("[X] _lab/alpine.json sin credenciales root del atacante.")

print(f".. CHR objetivo: {os.environ['MIKROTIK_IP']}  |  atacante={ATACANTE}  victima={VICTIMA}")

# =============================================================================
# 1) CHR ALCANZABLE + VERSION + REGLAS DE DROP
# =============================================================================
rc, ver, err = ssh_chr('/system resource print')
ver = ver or err
gate('chr_ssh', rc == 0 and 'RouterOS' in ver, f"SSH+ver OK: {ver.splitlines()[:1]}")
guardar_evidencia('t5_chr_version.txt', ver)

rc, filtros, err = ssh_chr('/ip firewall filter print terse')
filtros = filtros or err
drop_fwd = 'IDS_BLACKLIST_DROP_FORWARD' in filtros
drop_inp = 'IDS_BLACKLIST_DROP_INPUT' in filtros
gate('reglas_drop', drop_fwd and drop_inp,
     f"forward={drop_fwd} input={drop_inp}")
guardar_evidencia('t5_chr_firewall_terse.txt', filtros)

# =============================================================================
# 2) BASELINE: atacante -> victima
# =============================================================================
a = chrome['atacante']
rc, out, err = ssh_run(a['host'], a['user'], a['pass'],
                       f'ping -c 3 -W 2 {VICTIMA}')
pre_ping = (rc == 0)
gate('pre_ping', pre_ping, f"atacante ping victima rc={rc}")
guardar_evidencia('t5_pre_ping_atacante.txt', out)

# =============================================================================
# 3) DETECCIÓN D2 (ruta de producción) + BLOQUEO AUTÓNOMO REAL
# =============================================================================
ids.conn.close()
tmp_db = tempfile.mktemp(suffix='.db')
ids.ruta_bd = tmp_db
ids.conn = sqlite3.connect(tmp_db, check_same_thread=False)
ids.cursor = ids.conn.cursor()
ids.crear_tabla_ataques(ids.conn)
ids.cursor.execute(DDL_BLOQUEOS)
ids.conn.commit()
ids._enviar_alerta_async = lambda msg: None
ids.ips_activo = True
ids.modo_ips_autonomo = True

d2 = pd.read_csv(os.path.join(_PROJ, 'datasets', 'SQLi_Zenodo', 'D2_test.csv'))
mua = d2[d2['Label'] == 1].head(300)
mue = d2[d2['Label'] == 0].head(25)
lote = pd.concat([mua, mue]).reset_index(drop=True)

n_procesados = 0
bloqueado_confirmado = False
for _, r in lote.iterrows():
    cic = netflow_a_cic_fecha(r)
    ids.on_flow_ready(ATACANTE, VICTIMA, cic)
    n_procesados += 1
    rows = ids.cursor.execute(
        "SELECT estado, confirmado, comando, respuesta FROM bloqueos "
        "WHERE ip_src=? ORDER BY id DESC LIMIT 1", (ATACANTE,)).fetchall()
    if rows and rows[0][0] == 'CONFIRMADO' and rows[0][1] == 1:
        bloqueado_confirmado = True
        _com, _res = rows[0][2], rows[0][3]
        break

gate('bloqueo_confirmado', bloqueado_confirmado,
     f"flujos_procesados={n_procesados} estado=CONFIRMADO(readback)")
if bloqueado_confirmado:
    guardar_evidencia('t5_bloqueo_readback.txt',
                      f"comando:\n{_com}\n\nrespuesta equipo:\n{_res}\n")
else:
    det = ids.cursor.execute(
        "SELECT estado, comando FROM bloqueos WHERE ip_src=? ORDER BY id DESC LIMIT 1",
        (ATACANTE,)).fetchall()
    print("      (última fila bloqueos):", det)

# =============================================================================
# 4) DIFERENCIAL POST-BLOQUEO
# =============================================================================
rc_post, out_post, err = ssh_run(a['host'], a['user'], a['pass'],
                                 f'ping -c 3 -W 2 {VICTIMA}')
post_ping = (rc_post != 0)
gate('post_ping_denegado', post_ping, f"atacante ping victima rc={rc_post} (esperado !=0)")
guardar_evidencia('t5_post_ping_atacante.txt', out_post)

rc, stats, err = ssh_chr('/ip firewall filter print stats where comment="IDS_BLACKLIST_DROP_FORWARD"')
_npks = 0
if 'packets=' in (stats or ''):
    try:
        _npks = int([p for p in stats.replace('packets=', ' ').split() if p.isdigit()][0])
    except (IndexError, ValueError):
        _npks = 0
gate('drop_forward_stats', _npks > 0,
     f"paquetes drop en forward = {_npks} (esperado >0 tras el ataque)")
guardar_evidencia('t5_chr_drop_stats_forward.txt', stats or err)

rc, lista, err = ssh_chr(f'/ip firewall address-list print terse where list="{mikrotik_api.LISTA_BLOQUEO}" and address={ATACANTE}')
gate('address_list_presente', ATACANTE in (lista or err),
     f"print terse: {lista.strip()[:120] or err.strip()[:120]}")
guardar_evidencia('t5_chr_address_list.txt', lista or err)

# =============================================================================
# 5) DESBLOQUEO + RESTAURACIÓN
# =============================================================================
r_des = mikrotik_api.desbloquear_ip_mikrotik(ATACANTE)
gate('desbloqueado', bool(r_des.get('ok')) and not r_des.get('confirmado'),
     f"modo={r_des.get('modo')} confirmado(eliminado)={r_des.get('confirmado')}")

rc_tras, out_tras, err = ssh_run(a['host'], a['user'], a['pass'],
                                 f'ping -c 3 -W 2 {VICTIMA}')
gate('tras_ping_restaurado', rc_tras == 0,
     f"atacante ping victima rc={rc_tras} (esperado 0)")
guardar_evidencia('t5_tras_desbloqueo_ping.txt', out_tras)

# =============================================================================
# Cierre
# =============================================================================
RESULTADOS = {
    'chr_ip': os.environ['MIKROTIK_IP'],
    'atacante': ATACANTE, 'victima': VICTIMA,
    'gates': gates,
    'flujos_procesados_deteccion': n_procesados,
}
out_json = os.path.join(EVID, 'informe_t5.json')
with open(out_json, 'w', encoding='utf-8') as f:
    json.dump(RESULTADOS, f, ensure_ascii=False, indent=2)
print(f"      [informe] {out_json}")

algun_fallo = any(not g['pass'] for g in gates)
print("\n== GATES T5 ==")
for g in gates:
    print(f"  {g['prueba']}: {'PASS' if g['pass'] else 'FAIL'}  ({g['detalle']})")
if algun_fallo:
    print("\n[FAIL] T5: al menos un gate falló. Código de salida: 1")
    sys.exit(1)
print("\n[PASS] T5 superado: bloqueo real en RouterOS confirmado (readback) y "
      "diferencial de conectividad verificado.")
sys.exit(0)