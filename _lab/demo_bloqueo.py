#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
demo_bloqueo.py - Demostración en vivo del bloqueo del IPS sobre RouterOS CHR
==============================================================================
`t5_routeros_ips.py` valida el bloqueo correctamente pero en ~5 s y con 3 pings:
 sirve para un gate, no sirve para una presentación. Aquí el atacante hace ping
cada segundo durante ~50 s y el bloqueo ocurre en medio, de modo que se VE pasar
la línea de "OK" a "TIMEOUT" y volver a "OK".

Por qué hay tres señales en pantalla y no una
---------------------------------------------
  atacante -> victima    el tráfico objeto del bloqueo. Al activarse, SE MUERE.
                         Esta es la prueba principal.
  victima -> ROUTER      ping de CONTROL a 10.10.0.2. Debe seguir respondiendo
                         mientras el de la víctima no: así se descarta que "se
                         cayó el laboratorio" y se demuestra que lo que se cortó
                         es el camino del atacante, no la red.
                         El control NO sale del atacante a propósito: el bloqueo
                         crea además una regla en la chain 'input', así que al
                         atacante también se le corta contra el router.
  contador del router    paquetes contados por IDS_BLACKLIST_DROP_FORWARD. Si el
                         corte fuese una caída de red, este número NO subiría.
                         Es lo que convierte la demo en evidencia.

Honestidad sobre qué es tráfico real
-------------------------------------
El único tráfico REAL en la red es el ping. La detección SQLi NO viene de sniffar
paquetes: el IDS es un clasificador NetFlow que consume features de flujo, así que
aquí se le inyectan filas del dataset D2 por `ids.on_flow_ready`, igual que en T5.
Un `curl` con `' OR 1=1--` real no dispararía nada, porque este motor no inspecciona
payloads. La demo lo presenta como lo que es: una decisión del IDS sobre un flujo.

Uso
---
    $env:MIKROTIK_PROFILE='lab'
    python .\\_lab\\demo_bloqueo.py                 # ~50 s, para grabar
    python .\\_lab\\demo_bloqueo.py --sin-pausas   # ~10 s, prueba de humo

Grabar en MP4 sin instalar nada:
    Win + Alt + R  (o Win + G -> Capturar). Queda en
    C:\\Users\\<tu_usuario>\\Videos\\Captures

Salidas:
    docs/lab/demo_timeline.csv      línea de tiempo cruda (base de las gráficas)
    (las figuras y el GIF los genera graficar_bloqueo.py)
"""
import argparse
import csv
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time

_LAB = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_LAB)
for _ruta in (_PROJ, _LAB):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

# --- Perfil de los nodos CHR del laboratorio (nodos.json + credenciales CHR) ---
from nodos_lab import cargar_nodos  # noqa: E402


def _leer_perfil_lab():
    ruta = os.path.join(_PROJ, 'config', 'mikrotik_lab.json')
    if os.path.exists(ruta):
        with open(ruta, encoding='utf-8-sig') as f:
            return json.load(f)
    return {}


_nodos = cargar_nodos()
ATACANTE = _nodos['atacante']['host']
VICTIMA = _nodos['victima']['host']

_perfil_chr = _leer_perfil_lab()
os.environ.setdefault('MIKROTIK_PROFILE', _perfil_chr.get('perfil', 'lab'))
os.environ.setdefault('MIKROTIK_IP', os.environ.get('MIKROTIK_IP',
                                                    _perfil_chr.get('ip', '10.10.0.2')))
# LOGS aislados ANTES de importar ids (ids importa log_exporter y este lee LOG_FOLDER).
os.environ['LOG_FOLDER'] = tempfile.mkdtemp(prefix='demo_logs_')

# --- Motor por la ruta 100% de producción ---
import ids                      # noqa: E402
import mikrotik_api             # noqa: E402

try:
    import paramiko
except ImportError:
    sys.exit("[X] Falta 'paramiko'. Instale:  pip install paramiko")

try:
    import pandas as pd
except ImportError:
    sys.exit("[X] Falta 'pandas'. Instale:  pip install pandas")

try:
    from colorama import Fore, Style
    from colorama import init as _colorama_init
    _colorama_init(autoreset=False)
    _HAY_COLOR = True
except ImportError:                       # sin colorama: marcadores de texto
    class _Falso:
        def __getattr__(self, _n):
            return ''
    Fore = Style = _Falso()
    _HAY_COLOR = False

EVID = os.path.join(_PROJ, 'docs', 'lab')
os.makedirs(EVID, exist_ok=True)

ROUTER = os.environ.get('MIKROTIK_IP', '10.10.0.2')
RUTA_CSV = os.path.join(EVID, 'demo_timeline.csv')

# =============================================================================
# Reloj y color de la consola
# =============================================================================
_T0 = time.time()
# RLock, no Lock: _fase() toma el candado y dentro llama a _registrar(), que
# vuelve a tomarlo. Un Lock normal NO es reentrante y eso deadlockea el programa
# justo al empezar la etapa 1.
_CANDADO = threading.RLock()
_LOCK_PRINT = threading.Lock()
FILAS = []                    # lineas del CSV (t_rel, fase, evento, ok, detalle)
FASE = {'actual': 'inicio'}
MARCA = {}                    # instantes en que se confirmo bloqueo/desbloqueo


def _ts():
    return time.time() - _T0


def _fmt(seg):
    return '[%02d:%02d]' % (int(seg) // 60, int(seg) % 60)


def _registrar(evento, detalle='', ok=None, fase=None):
    """Anota un evento en la línea de tiempo (CSV) de forma segura entre hilos."""
    with _CANDADO:
        t = _ts()
        f = fase or FASE['actual']
        FILAS.append({'t_rel': round(t, 2), 't_fmt': _fmt(t), 'fase': f,
                      'evento': evento,
                      'ok': '' if ok is None else ('1' if ok else '0'),
                      'detalle': detalle})


def _p(texto=''):
    """Imprime con flush y de forma ATOMICA.

    En una demo en vivo la salida se mira mientras corre: si stdout esta en
    tuberia (redireccion, harness) Python lo bloquea en bloques de 4 KB y las
    lineas aparecen a rafagas o no aparecen; flush=True las fuerza en cada linea.

    El candado es imprescindible ademas porque hay DOS hilos escribiendo a la vez
    (ping a la victima y ping de control). Con colorama, ademas, su envoltorio
    reescribe la linea para quitar los codigos ANSI, y eso parte la escritura en
    variosTrozos: sin serializar, dos lineas salen pegadas y entrecortadas.
    """
    with _LOCK_PRINT:
        print(texto, flush=True)


def _titulo(texto):
    _p()
    _p(Fore.CYAN + Style.BRIGHT + '=' * 78)
    _p('  ' + texto)
    _p('=' * 78 + Style.RESET_ALL)


def _fase(clave, titulo=None):
    """Marca una etapa.

    'clave' es el identificador corto que usan las graficas y el resumen
    (LIBRE, BLOQUEADO, ...). Si se guardara el texto largo, el resumen no
    encontraria ninguna coincidencia y todas las fases saldrian 0/0.
    """
    texto = titulo or clave
    FASE['actual'] = clave
    with _CANDADO:
        _registrar('fase', texto)
    _p()
    _p(Fore.MAGENTA + Style.BRIGHT + '-' * 78)
    _p('  ETAPA: ' + texto)
    _p('-' * 78 + Style.RESET_ALL)


def _evento(texto, nivel='info'):
    color = {'info': Fore.WHITE, 'ok': Fore.GREEN, 'mal': Fore.RED,
             'aviso': Fore.YELLOW}.get(nivel, Fore.WHITE)
    _p(f"{color}{_fmt(_ts())}   {texto}{Style.RESET_ALL}")


# =============================================================================
# Parser del ping continuo de RouterOS
# =============================================================================
# '/ping <ip> interval=1' sin 'count' corre hasta que se corte el canal, y sus
# lineas llegan troceadas: medido, un paquete por segundo y por separado, con
# las lineas completas (68 bytes). No hay envoltura de linea en este caso.
#
# AVISO: los dos formatos de linea NO tienen los mismos campos. Capturado de un
# RouterOS 7 real con el bloqueo puesto:
#
#   con respuesta:  '    0 10.10.1.3     56  63 465us     '
#   con timeout:    '    1 10.10.1.3                    timeout     '
#
# Es decir, en la linea de timeout RouterOS OMITE SIZE y TTL y deja el hueco
# hasta el ancho de columna. Por eso SIZE y TTL son un grupo opcional: si se
# exigian, ninguna linea de timeout casaba, los paquetes se perdian en silencio
# y la etapa 'BLOQUEADO' salia 0/0 aunque el bloqueo funcionase.
#
# El patron no necesita ser tolerante a lineas partidas: la proteccion real ante
# un paquete a medias es el 'hold-back' de abajo, que retiene el ultimo match
# hasta que el siguiente trozo confirma que la linea estaba completa.
RE_PING_PKT = re.compile(
    r'\b(\d+)\s+'                             # SEQ
    r'(\d{1,3}(?:\.\d{1,3}){3})'              # HOST
    r'(?:\s+(\d+)\s+(\d+))?'                  # SIZE + TTL (solo si hay respuesta)
    r'[\s]*'
    r'([0-9]+(?:[.,][0-9]+)?\s*(?:us|ms|s)|timeout)?',   # RTT o TIMEOUT
    re.I)


RE_RTT = re.compile(r'^([0-9]+(?:[.,][0-9]+)?)\s*(us|ms|s)$', re.I)

RE_FILA_STATS = re.compile(r'^\s*\d+\s+\S+\s+\S+\s+(\d+)\s+(\d+)\s*$', re.M)


def _rtt_a_ms(texto):
    """'229us' / '1,4ms' -> milisegundos float. None si no es un RTT."""
    if not texto:
        return None
    m = RE_RTT.match(texto.strip())
    if not m:
        return None
    valor, unidad = float(m.group(1).replace(',', '.')), m.group(2).lower()
    return {'us': 0.001, 'ms': 1.0, 's': 1000.0}[unidad] * valor


class PingContinuo(threading.Thread):
    """Lanza '/ping <destino> interval=N' en un canal y reporta cada paquete.

    RouterOS no tiene ping con cuenta infinita explicita: sin 'count' corre
    hasta que se cierra el canal, que es lo que hace este hilo.
    """

    def __init__(self, destino, etiqueta, intervalo=1, mostrar=True,
                 color=Fore.WHITE, origen='atacante'):
        super().__init__(daemon=True)
        self.destino = destino
        self.etiqueta = etiqueta
        self.intervalo = intervalo
        self.mostrar = mostrar
        self.color = color
        self.origen = origen       # nodo desde el que se lanza el ping
        self.paquetes = []          # (t_rel, seq, ok, rtt_ms)
        self.pendiente = ''
        self.cursor = 0
        self._canal = None
        self._cli = None
        self.error = None
        # Instante de llegada de cada trozo, indexado en coordenadas absolutas
        # sobre el flujo (self._base + offset dentro de 'pendiente').
        self._base = 0
        self._trozos = []           # (ini_abs, fin_abs, t_llegada)

    # -- conexion -----------------------------------------------------------
    def _conectar(self):
        c = _nodos[self.origen]
        self._cli = paramiko.SSHClient()
        self._cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._cli.connect(c['host'], port=c.get('port', 22), username=c['user'],
                          password=c['pass'], timeout=15)
        self._canal = self._cli.get_transport().open_session()
        self._canal.exec_command(
            f'/ping {self.destino} interval={self.intervalo}')

    def parar(self):
        try:
            if self._canal is not None:
                self._canal.close()
        except Exception:                                   # noqa: BLE001
            pass
        try:
            if self._cli is not None:
                self._cli.close()
        except Exception:                                   # noqa: BLE001
            pass

    # --Callbacks de datos --------------------------------------------------
    def _procesar(self, texto, final=False):
        if texto:
            self._trozos.append((self._base + len(self.pendiente),
                                 self._base + len(self.pendiente) + len(texto),
                                 _ts()))
        self.pendiente += texto
        crudos = list(RE_PING_PKT.finditer(self.pendiente))
        # Se emiten todos menos el ultimo: puede estar todavia a medias.
        limite = len(crudos) if final else max(0, len(crudos) - 1)
        for m in crudos[:limite]:
            if m.end() <= self.cursor:
                continue                                    # ya emitido
            self.cursor = m.end()
            self._emitir(m)
        # Recorta lo ya emitido. Sin esto 'pendiente' crece durante toda la demo y
        # finditer lo reescanea entero en cada trozo; ademas el retenido (el
        # ultimo) queda a la espera correctamente porque no se descarta.
        if self.cursor:
            self.pendiente = self.pendiente[self.cursor:]
            self._base += self.cursor
            self._cursor_limpido()
            self.cursor = 0

    def _cursor_limpido(self):
        """Olvida los trozos ya consumidos para que la lista no crezca sin fin."""
        self._trozos = [t for t in self._trozos if t[1] > self._base]

    def _t_de_posicion(self, pos_abs):
        """Instante en que LLEGO el trozo que contenia esa posicion.

        Sin esto el tiempo del paquete se tomaba al emitirse, y el retenido de
        arriba retrasaba cada linea ~1 intervalo (1 s con interval=1): un ping
        enviado justo antes del bloqueo se anotaba un segundo despues, ya dentro
        de la etapa BLOQUEADO, y la demo fallaba por un artefacto de reloj.
        """
        for ini, fin, t in self._trozos:
            if ini <= pos_abs < fin:
                return t
        return _ts()

    def _emitir(self, m):
        seq = int(m.group(1))
        rtt = _rtt_a_ms(m.group(5))
        ok = rtt is not None
        # El instante es el de LLEGADA del trozo que trajo la linea, no el de
        # emision: con el retenido, emitir un intervalo mas tarde no significa que
        # el paquete se enviara mas tarde.
        t = self._t_de_posicion(self._base + m.start())
        with _CANDADO:
            self.paquetes.append((t, seq, ok, rtt))
        detalle = (f"rtt={rtt:.2f}ms" if ok else 'TIMEOUT')
        _registrar(f'ping_{self.etiqueta}' + ('_ok' if ok else '_timeout'),
                   f'seq={seq} {detalle}', ok=ok)
        if self.mostrar:
            marca = (Fore.GREEN + ' OK      ' + Style.RESET_ALL) if ok \
                else (Fore.RED + Style.BRIGHT + ' TIMEOUT ' + Style.RESET_ALL)
            cuerpo = f"{rtt:7.2f}ms" if ok else '   ------'
            _p(f"{self.color}{_fmt(t)}   {self.etiqueta:<18}{marca} "
               f"seq={seq:<4}{cuerpo}{Style.RESET_ALL}")

    # -- hilo ----------------------------------------------------------------
    def run(self):
        try:
            self._conectar()
        except Exception as exc:                            # noqa: BLE001
            self.error = f'{self.etiqueta}: no se pudo abrir el ping ({exc})'
            _registrar('ping_error', str(exc), ok=False)
            _evento(f"[X] {self.error}", 'mal')
            return
        try:
            while True:
                if self._canal.recv_ready():
                    self._procesar(self._canal.recv(65536).decode(errors='replace'))
                elif self._canal.exit_status_ready():
                    break
                else:
                    time.sleep(0.05)
            while self._canal.recv_ready():
                self._procesar(self._canal.recv(65536).decode(errors='replace'))
        except Exception as exc:                            # noqa: BLE001
            self.error = f'{self.etiqueta}: {exc}'
            _registrar('ping_error', str(exc), ok=False)
        finally:
            self._procesar('', final=True)
            self.parar()


class ContadorRouter(threading.Thread):
    """Muestrea los PACKETS de IDS_BLACKLIST_DROP_FORWARD una vez por segundo."""

    def __init__(self, intervalo=1.0):
        super().__init__(daemon=True)
        self.intervalo = intervalo
        self.series = []            # (t_rel, packets)
        self.maximo = 0
        self._parar = threading.Event()

    def leer(self):
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(ROUTER, port=mikrotik_api.ROUTER_PORT,
                        username=mikrotik_api.ROUTER_USER,
                        password=mikrotik_api.ROUTER_PASS, timeout=10)
            _, out, err = cli.exec_command(
                '/ip firewall filter print stats '
                'where comment="IDS_BLACKLIST_DROP_FORWARD"', timeout=10)
            texto = out.read().decode(errors='replace') or err.read().decode(errors='replace')
        finally:
            cli.close()
        m = re.search(r'packets[=:]\s*(\d+)', texto or '')
        if m:
            return int(m.group(1))
        filas = RE_FILA_STATS.findall(texto or '')
        return int(filas[-1][1]) if filas else 0

    def parar(self):
        self._parar.set()

    def run(self):
        while not self._parar.is_set():
            try:
                p = self.leer()
            except Exception:                               # noqa: BLE001
                p = None
            if p is not None:
                t = _ts()
                with _CANDADO:
                    self.series.append((t, p))
                    self.maximo = max(self.maximo, p)
                _registrar('contador_drop', f'packets={p}', ok=None)
            self._parar.wait(self.intervalo)


# =============================================================================
# SSH al router (una consulta, canal propio)
# =============================================================================
def _credenciales(rol):
    """Credenciales unificadas de un nodo.

    El router no viene de nodos.json sino del perfil de mikrotik_api (son
    atributos de modulo, no un dict), asi que se normaliza a la misma forma para
    no tener dos caminos distintos al conectar.
    """
    if rol == 'router':
        return {'host': ROUTER, 'user': mikrotik_api.ROUTER_USER,
                'pass': mikrotik_api.ROUTER_PASS,
                'port': mikrotik_api.ROUTER_PORT}
    c = _nodos[rol]
    return {'host': c['host'], 'user': c['user'], 'pass': c['pass'],
            'port': c.get('port', 22)}


def ssh_a(rol, cmd, timeout=10):
    """Ejecuta un comando en un nodo del laboratorio y devuelve stdout/stderr."""
    c = _credenciales(rol)
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(c['host'], port=c['port'], username=c['user'],
                    password=c['pass'], timeout=timeout)
        _, out, err = cli.exec_command(cmd, timeout=timeout)
        # Leer antes de recv_exit_status: al reves un stdout grande llena el
        # buffer del canal y exec_command se queda esperando el codigo de salida.
        salida = out.read().decode(errors='replace') or ''
        error = err.read().decode(errors='replace') or ''
        return salida or error
    finally:
        cli.close()


def ssh_router(cmd, timeout=10):
    return ssh_a('router', cmd, timeout)


def ssh_atacante(cmd, timeout=10):
    return ssh_a('atacante', cmd, timeout)


# =============================================================================
# Detección D2 por la ruta de producción (idéntica a T5)
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
    return {
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


def preparar_motor():
    """Aisla la BD y el motor igual que T5: nada toca la producción."""
    ids.conn.close()
    tmp_db = tempfile.mktemp(suffix='.db')
    ids.ruta_bd = tmp_db
    ids.conn = sqlite3.connect(tmp_db, check_same_thread=False)
    ids.cursor = ids.conn.cursor()
    ids.crear_tabla_ataques(ids.conn)
    ids.cursor.execute(DDL_BLOQUEOS)
    ids.conn.commit()
    ids._enviar_alerta_async = lambda msg: None      # sin Telegram en la demo
    ids.ips_activo = True
    ids.modo_ips_autonomo = True


LOTE = []


def preparar_lote(limite=300):
    """Deja el lote de NetFlow D2 ya construido y devuelve su tamaño.

    Se hace ANTES de arrancar los medidores, a propósito. Leer 7.8 MB con
    pd.read_csv y recorrerlos con iterrows() mantiene el GIL durante bastante
    tiempo; con los dos pings corriendo en paralelo, sus hilos se quedaban sin
    leer el canal y perdiamos justo los paquetes de la etapa interesante.
    Pagando el coste aquí, en vivo solo queda la evaluación del motor, que es
    rápida. El lote es el dataset real: no cambia lo que la demo demuestra.
    """
    global LOTE
    d2 = pd.read_csv(os.path.join(_PROJ, 'datasets', 'SQLi_Zenodo', 'D2_test.csv'))
    lote = pd.concat([d2[d2['Label'] == 1].head(limite),
                      d2[d2['Label'] == 0].head(25)]).reset_index(drop=True)
    LOTE = [netflow_a_cic_fecha(r) for _, r in lote.iterrows()]
    return len(LOTE)


def detectar_y_bloquear():
    """Devuelve (n_flujos, estado, confirmado). Imprime lo que ve el motor."""
    for n, flujo in enumerate(LOTE, start=1):
        ids.on_flow_ready(ATACANTE, VICTIMA, flujo)
        rows = ids.cursor.execute(
            'SELECT estado, confirmado FROM bloqueos WHERE ip_src=? '
            'ORDER BY id DESC LIMIT 1', (ATACANTE,)).fetchall()
        if rows and rows[0][0] == 'CONFIRMADO' and rows[0][1] == 1:
            return n, rows[0][0], bool(rows[0][1])
    return 0, 'SIN_BLOQUEO', False


# =============================================================================
# Programa
# =============================================================================
def main():
    ap = argparse.ArgumentParser(
        description='Demo en vivo del bloqueo del IPS sobre RouterOS CHR.')
    # default=None en los tres: si no, '--sin-pausas' pisaba los valores dados
    # a mano y no habia forma de pedir 'sin pausa' solo en una etapa.
    ap.add_argument('--libre', type=float, default=None,
                    help='segundos de trafico normal antes de bloquear (def. 14)')
    ap.add_argument('--bloqueado', type=float, default=None,
                    help='segundos con el bloqueo puesto (def. 18)')
    ap.add_argument('--restaurado', type=float, default=None,
                    help='segundos tras desbloquear (def. 9)')
    ap.add_argument('--intervalo', type=int, default=1,
                    help='intervalo del ping continuo en segundos (def. 1)')
    ap.add_argument('--sin-pausas', action='store_true',
                    help='prueba de humo: cada etapa dura 1 s salvo que se indique')
    ap.add_argument('--sin-deteccion', action='store_true',
                    help='no ejecutar el motor (solo pings y contador)')
    ap.add_argument('--evidencia-dir', default=None,
                    help='carpeta donde escribir el CSV de la linea de tiempo '
                         '(def. docs/lab). Permite conservar varias corridas '
                         'sin que una pise a la anterior')
    args = ap.parse_args()

    if args.evidencia_dir:
        global EVID, RUTA_CSV
        EVID = os.path.abspath(args.evidencia_dir)
        os.makedirs(EVID, exist_ok=True)
        RUTA_CSV = os.path.join(EVID, 'demo_timeline.csv')
        print(f"[*] Evidencia de esta corrida en: {EVID}")

    def _duracion(valor, defecto_humo, defecto):
        if valor is not None:
            return valor
        return defecto_humo if args.sin_pausas else defecto

    libre = _duracion(args.libre, 1.0, 14.0)
    bloqueado = _duracion(args.bloqueado, 1.0, 18.0)
    restaurado = _duracion(args.restaurado, 1.0, 9.0)

    print(Fore.CYAN + Style.BRIGHT)
    print('=' * 78)
    print('  DEMOSTRACION EN VIVO DEL BLOQUEO DEL IPS  ·  IDS/IPS UNIPAZ')
    print('=' * 78)
    print(Style.RESET_ALL)
    print(f"  atacante {ATACANTE}   router {ROUTER}   victima {VICTIMA}")
    print(f"  duraciones: libre={libre:g}s  bloqueado={bloqueado:g}s  "
          f"restaurado={restaurado:g}s  ping cada {args.intervalo}s")
    if not _HAY_COLOR:
        print('  (sin colorama: la salida usara marcadores [OK]/[TIMEOUT])')
    print()
    print('  ' + Fore.YELLOW + 'Para.grabar en MP4: pulsa Win+Alt+R ahora '
          '(o Win+G -> Capturar).' + Style.RESET_ALL)
    print('  ' + Fore.YELLOW + 'Se guarda en Videos\\Captures. Pulsa Win+Alt+R '
          'otra vez al terminar.' + Style.RESET_ALL)
    _registrar('inicio', 'demo launched', fase='precheck')

    # ---------------- PRECHECK ----------------
    _titulo('PRECHECK: los tres nodos deben responder por SSH')
    try:
        for rol in ('router', 'atacante', 'victima'):
            c = _credenciales(rol)
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cli.connect(c['host'], port=c['port'], username=c['user'],
                        password=c['pass'], timeout=10)
            _, out, _ = cli.exec_command('/system resource print', timeout=10)
            up = out.read().decode(errors='replace')
            cli.close()
            # 'uptime:' viene con relleno de espacios y RouterOS ENVUELVE la linea,
            # asi que un .split() a pelo daria 'uptime:' sin el valor.
            m_up = re.search(r'uptime:\s*(\S+)', up)
            _evento(f"{rol:<9} {c['host']}:{c['port']}  OK  "
                    f"(uptime {m_up.group(1) if m_up else '?'})", 'ok')
    except Exception as exc:                                # noqa: BLE001
        print(Fore.RED + Style.BRIGHT
              + f"[X] Precheck fallido ({exc}). Encienda las 3 VMs: "
                "VBoxManage startvm CHR-IDS-LAB CHR-ATACANTE-LAB CHR-VICTIMA-LAB --type headless"
              + Style.RESET_ALL)
        return 2

    # Contadores a cero: si no, un ensayo previo inflaria la cifra que se ve.
    ssh_router('/ip firewall filter reset-counters numbers=0')
    _evento('contadores de reglas puestos a 0', 'aviso')

    # ---------------- MEDIDORES ----------------
    print()
    _evento('preparando el motor aislado y el lote de flujos D2', 'aviso')
    preparar_motor()
    n_lote = preparar_lote()
    _evento(f'{n_lote} flujos D2 listos en memoria (fuera de plano: aqui se '
            f'pagaria el GIL y los pings se congelarian)', 'aviso')

    _evento('arrancando los medidores: ping continuo + contador del router', 'aviso')
    # El control NO puede salir del atacante: mikrotik_api crea ademas de la regla
    # de 'forward' una de 'input' (chain=input, drop src-address-list), asi que al
    # bloquear se le corta tambien contra el router. Eso es correcto como
    # aislamiento de un host comprometido, pero invalida un ping atacante->router
    # como prueba de que la red sigue viva. El control lo hace la VICTIMA, que no
    # esta bloqueada: si ella sigue respondiendo, los timeouts son por el bloqueo.
    ping_v = PingContinuo(VICTIMA, 'atacante->victima', args.intervalo, True,
                           Fore.WHITE, origen='atacante')
    ping_r = PingContinuo(ROUTER, 'victima->ROUTER', args.intervalo, True,
                           Fore.BLUE, origen='victima')

    contador = ContadorRouter()
    ping_v.start()
    ping_r.start()
    contador.start()
    time.sleep(0.4)

    # ---------------- ETAPA 1 ----------------
    _fase('LIBRE', '1 · LIBRE  (el atacante SI llega a la victima)')
    _evento('observe las dos lineas: ambas responden', 'aviso')
    time.sleep(libre)

    # ---------------- ETAPA 2 ----------------
    _fase('DETECCION', '2 · DETECCION + BLOQUEO AUTONOMO  (ruta de produccion)')
    if args.sin_deteccion:
        _evento('--sin-deteccion: se omite el motor', 'aviso')
    else:
        _evento(f'inyectando flujos D2 en ids.on_flow_ready '
                f'(atacante={ATACANTE})', 'aviso')
        n_flujos, estado, confirmado = detectar_y_bloquear()
        _registrar('deteccion', f'flujos={n_flujos} estado={estado}', ok=confirmado)
        if confirmado:
            MARCA['bloqueo'] = _ts()
            _evento(f'Deteccion SQLi CONFIRMADA tras {n_flujos} flujo(s); '
                    f'bloqueo verificado por readback', 'ok')
        else:
            _evento(f'No se confirmo el bloqueo (estado={estado})', 'mal')

    # ---------------- ETAPA 3 ----------------
    _fase('BLOQUEADO', '3 · BLOQUEADO  (el atacante YA NO llega a la victima)')
    _evento('la victima pasa a TIMEOUT; el ROUTER debe seguir en OK', 'aviso')
    time.sleep(bloqueado)

    # ---------------- ETAPA 4 ----------------
    _fase('DESBLOQUEO', '4 · DESBLOQUEO')
    r = mikrotik_api.desbloquear_ip_mikrotik(ATACANTE)
    MARCA['desbloqueo'] = _ts()
    _registrar('desbloqueo', f"modo={r.get('modo')} confirmado={r.get('confirmado')}",
               ok=bool(r.get('ok') and r.get('confirmado')))
    if r.get('ok') and r.get('confirmado'):
        _evento('regla eliminada y verificada por readback (address-list vacia)', 'ok')
    else:
        _evento(f"desbloqueo no confirmado: {r.get('respuesta') or r.get('error')}", 'mal')

    # ---------------- ETAPA 5 ----------------
    _fase('RESTAURADO', '5 · RESTAURADO  (la victima vuelve a responder)')
    time.sleep(restaurado)

    # ---------------- CIERRE ----------------
    ping_v.parar()
    ping_r.parar()
    contador.parar()
    time.sleep(0.6)

    _titulo('RESUMEN DE LA DEMOSTRACION')

    # Un paquete ya en vuelo cuando se aplico el bloqueo puede responder igual:
    # salio antes de que existiera la regla. Se cuentan aparte en vez de
    # colarlos en BLOQUEADO, que haria fallar la demo por un artefacto de
    # temporizacion y no por un fallo del IPS.
    #
    # El margen ya no es una holgura inventada: los timestamps de los paquetes son
    # los de LLEGADA (ver PingContinuo._t_de_posicion), asi que basta con el
    # intervalo que separa el envio del bloqueo de su confirmacion por readback.
    # Ese retardo se mide, no se supone: se toma de los propios paquetes que se
    # sabe que salieron libres.
    EN_VUELO = 0.5

    def _margen_real():
        """Retardo real entre el envio de un paquete y su anotacion.

        Se estima con los paquetes OK anteriores al bloqueo: el ultimo de ellos
        fue el mas cercano al corte, asi que su timestamp es el mejor techo. Si
        no hay ninguno anterior, se cae al margen nominal.
        """
        bloqueo = MARCA.get('bloqueo')
        if not bloqueo:
            return EN_VUELO
        previos = [t for t, _s, ok, _r in ping_v.paquetes
                   if ok and t <= bloqueo]
        if not previos:
            return EN_VUELO
        # El margen needed es pequeno: solo cubre el retardo de anotacion, que
        # con la correccion es del orden de milisegundos.
        return max(0.0, min(EN_VUELO, bloqueo - max(previos)))

    def _por_fase(medidor):
        """Cruza cada paquete con la etapa vigente en el momento de su recepcion.

        Los cortes son los instantes en que se abrio cada etapa; un paquete cuenta
        para la ultima etapa que empezo antes de recibirse. Asi un ping que llega
        justo despues del bloqueo ya suma a BLOQUEADO y no a LIBRE.
        """
        with _CANDADO:
            cortes = [(fl['t_rel'], fl['fase'])
                      for fl in sorted(FILAS, key=lambda x: x['t_rel'])
                      if fl['evento'] == 'fase']
        out = {}
        for t, _seq, ok, _rtt in medidor.paquetes:
            etapa = 'FUERA'
            for ct, cf in cortes:
                if t >= ct:
                    etapa = cf
            if (etapa == 'BLOQUEADO' and ok
                    and MARCA.get('bloqueo')
                    and t < MARCA['bloqueo'] + margen):
                etapa = 'EN_VUELO'
            out.setdefault(etapa, []).append(ok)
        return out

    margen = _margen_real()
    if MARCA.get('bloqueo'):
        _registrar('margen_envio',
                   f'margen={margen:.3f}s '
                   f'(bloqueo@{MARCA["bloqueo"]:.2f}s)')
    por_fase = _por_fase(ping_v)
    ctrl = _por_fase(ping_r)

    print()
    print(f"  {'ETAPA':<12}{'victima OK':>16}{'router OK (control)':>24}")
    print('  ' + '-' * 50)
    for ef in ('LIBRE', 'BLOQUEADO', 'RESTAURADO'):
        v = por_fase.get(ef, [])
        c = ctrl.get(ef, [])
        print(f"  {ef:<12}{sum(v)}/{len(v):<14}{sum(c)}/{len(c):<12}")
    if por_fase.get('EN_VUELO'):
        print(f"  {'(en vuelo)':<12}{len(por_fase['EN_VUELO']):>16}   "
              f"salieron antes de que existiera la regla")

    ok_libre = any(por_fase.get('LIBRE', []))
    ok_bloq_cortado = (len(por_fase.get('BLOQUEADO', [])) > 0
                       and not any(por_fase.get('BLOQUEADO', [])))
    ok_restore = any(por_fase.get('RESTAURADO', []))
    # El control mira solo las etapas con trafico real; EN_VUELO tambien es
    # trafico real, pero es del atacante y se espera que no responda.
    etapas_ctrl = [k for k in ctrl if k not in ('FUERA', 'EN_VUELO')]
    ok_control = bool(etapas_ctrl) and all(any(ctrl[k]) for k in etapas_ctrl)
    ok_drop = contador.maximo > 0

    veredictos = [
        ('el atacante llegaba a la victima antes', ok_libre),
        ('dejo de llegar mientras estaba bloqueado', ok_bloq_cortado),
        ('volvio a llegar tras desbloquear', ok_restore),
        ('la red seguia viva (control victima->router)', ok_control),
        (f'el router conto los descartes (max {contador.maximo})', ok_drop),
    ]
    print()
    for texto, ok in veredictos:
        marca = (Fore.GREEN + 'PASA' + Style.RESET_ALL) if ok \
            else (Fore.RED + 'FALLA' + Style.RESET_ALL)
        print(f'  [{marca}] {texto}')
    _registrar('resumen', '; '.join(f'{t}={ok}' for t, ok in veredictos),
               ok=all(ok for _, ok in veredictos))

    # ---------------- CSV ----------------
    _fase('CIERRE', '6 · CIERRE')
    with open(RUTA_CSV, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['t_rel', 't_fmt', 'fase', 'evento',
                                          'ok', 'detalle'])
        w.writeheader()
        for fila in FILAS:
            w.writerow(fila)
    print()
    _evento(f'linea de tiempo guardada en {RUTA_CSV} '
            f'({len(FILAS)} eventos)', 'ok')
    print('  ' + Fore.YELLOW + 'Siguiente paso:  python .\\_lab\\graficar_bloqueo.py'
          + Style.RESET_ALL)
    print('  ' + Fore.YELLOW + 'Para terminar de grabar: Win+Alt+R' + Style.RESET_ALL)

    return 0 if all(ok for _, ok in veredictos) else 1


if __name__ == '__main__':
    sys.exit(main())
