# -*- coding: utf-8 -*-
r"""
grabber_http_benigno.py — Captura de HTTP benigno UNIPAZ (insumo M2 de ML v6).
docs/ML_V6_DESARROLLO.md §3.1: es el dataset que evita repetir C3. Sin
benignos reales, el modelo de payload sobre-aprende a atacar. Objetivo:
>= 500.000 peticiones HTTP en 3-7 dias de trafico del SPAN.

Diseno A PRUEBA DE APAGONES (el servidor puede apagarse de vez en cuando):
  1. PERSISTENCIA INCREMENTAL: cada peticion se guarda en SQLite (modo WAL)
     en lotes pequenos (cada 20 paquetes o 5 s). Un corte pierde a lo sumo
     la ultima ventana de flush, nunca la corrida entera.
  2. REANUDACION: al arrancar reutiliza la BD existente y CONTINUA el conteo
     acumulado (tabla meta). El objetivo se mide por peticiones acumuladas,
     no por tiempo continuo: los apagones no reinician el reloj.
  3. AUTO-ARRANQUE: la tarea programada al iniciar sesion llama a
     scripts\grabber_http_benigno.bat (mismo patron que la produccion:
     corren como usuario porque el venv usa el Python de la Store).
  4. La captura es PASIVA (SPAN, promiscuo, store=False): no genera trafico
     y no toca la BD de produccion ni la del laboratorio.

Privacidad (docs/informe_privacidad_ips.md, misma regla de ids.py):
  - Payload con marcas sensibles (password/token/authorization/...) -> omitido.
  - Ruta con session= -> se guarda sin query. Ruta truncada a 500, cuerpo a 2000.
  - IP truncada a segmento (172.10.x.x). La BD vive en datasets/ (gitignored)
    y NUNCA se versiona; el sello (hash) queda en la ficha del experimento.

Uso:
    venv\\Scripts\\python.exe scripts\\grabber_http_benigno.py --prueba 10
    venv\\Scripts\\python.exe scripts\\grabber_http_benigno.py            # indefinido
"""
import argparse
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Puertos web de ENTRADA (peticiones cliente->servidor). HTTPS (443) no se
# puede leer: el payload llega cifrado; se documenta como limitacion (R6).
PUERTOS_WEB = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888}

_MARCAS_SENSIBLES = ('password', 'passwd', 'pwd=', 'authorization',
                     'token', 'secret')

_RE_PETICION = re.compile(
    r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+) HTTP/\d\.\d')

BD_DEF = BASE_DIR / 'datasets' / 'unipaz_http' / 'captura_http_benigno.db'


class GrabberHTTP:
    def __init__(self, bd_path=BD_DEF, flush_n=20, flush_s=5.0):
        self.bd_path = Path(bd_path)
        self.bd_path.parent.mkdir(parents=True, exist_ok=True)
        self.flush_n = flush_n
        self.flush_s = flush_s
        self._cola = []
        self._ultimo_flush = time.time()
        self._cerrada = False
        self._init_bd()
        self.total = int(self._meta_get('total', 0))

    # ---- BD ---------------------------------------------------------------
    def _init_bd(self):
        self.con = sqlite3.connect(str(self.bd_path), timeout=30)
        self.con.execute('PRAGMA journal_mode=WAL')
        self.con.execute('PRAGMA synchronous=NORMAL')
        self.con.execute('''
            CREATE TABLE IF NOT EXISTS peticiones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL,
                ip_src_segmento TEXT,
                puerto_dst INTEGER,
                metodo TEXT,
                host TEXT,
                ruta TEXT,
                cuerpo TEXT,
                total_len INTEGER
            )''')
        self.con.execute('''
            CREATE TABLE IF NOT EXISTS meta (
                clave TEXT PRIMARY KEY, valor TEXT)''')
        self.con.commit()

    def _meta_get(self, clave, defecto=None):
        fila = self.con.execute('SELECT valor FROM meta WHERE clave=?',
                                (clave,)).fetchone()
        return fila[0] if fila else defecto

    def _meta_set(self, clave, valor):
        self.con.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',
                         (clave, str(valor)))

    # ---- Sanitizacion (regla de ids.py/_sanear_muestra_sqli) --------------
    @staticmethod
    def _sanear(ruta, cuerpo):
        # Ruta con sesion u otra marcada: se guarda sin query (evita fugas)
        if 'session=' in ruta.lower():
            ruta = ruta.split('?', 1)[0]
        ruta = ruta[:500]
        if cuerpo:
            bajo = cuerpo.lower()
            if any(m in bajo for m in _MARCAS_SENSIBLES):
                cuerpo = '<cuerpo omitido: contiene posibles credenciales>'
            cuerpo = cuerpo[:2000]
        return ruta, cuerpo or ''

    @staticmethod
    def _truncar_ip(ip):
        partes = ip.split('.')
        return '.'.join(partes[:2] + ['x', 'x']) if len(partes) == 4 else ip

    # ---- Parser -----------------------------------------------------------
    def _parsear(self, carga_bytes):
        if not carga_bytes or len(carga_bytes) > 8000:
            return None
        texto = carga_bytes.decode('ascii', errors='ignore')
        if not texto.isascii():
            return None
        m = _RE_PETICION.match(texto.lstrip())
        if not m:
            return None  # respuesta del servidor o basura: no es peticion
        metodo, ruta = m.group(1), m.group(2)
        host = ''
        cuerpo = ''
        partes = texto.split('\r\n\r\n', 1)
        for linea in partes[0].split('\r\n')[1:]:
            if linea.lower().startswith('host:'):
                host = linea.split(':', 1)[1].strip()[:200]
        if len(partes) > 1 and metodo in ('POST', 'PUT', 'PATCH'):
            cuerpo = partes[1]
        ruta, cuerpo = self._sanear(ruta, cuerpo)
        return {'metodo': metodo, 'ruta': ruta, 'host': host,
                'cuerpo': cuerpo, 'total_len': len(texto)}

    # ---- Ingesta (callback de scapy) --------------------------------------
    def procesar(self, packet):
        try:
            if self._cerrada:  # race tras el cierre: la BD ya no acepta
                return
            if not (packet.haslayer('TCP') and packet.haslayer('Raw')
                    and packet.haslayer('IP')):
                return
            if packet['TCP'].dport not in PUERTOS_WEB:
                return
            p = self._parsear(bytes(packet['Raw'].load))
            if not p:
                return
            ts = datetime.fromtimestamp(
                float(packet.time), tz=timezone.utc).isoformat(timespec='seconds')
            self._cola.append((
                ts, self._truncar_ip(packet['IP'].src), packet['TCP'].dport,
                p['metodo'], p['host'], p['ruta'], p['cuerpo'], p['total_len']))
            ahora = time.time()
            if len(self._cola) >= self.flush_n or ahora - self._ultimo_flush > self.flush_s:
                self._flush()
        except Exception as e:  # un paquete raro nunca tumba la captura
            print(f'[!] procesar: {e}')

    def _flush(self):
        if not self._cola:
            return
        self.con.executemany(
            'INSERT INTO peticiones (ts_utc, ip_src_segmento, puerto_dst, '
            'metodo, host, ruta, cuerpo, total_len) VALUES (?,?,?,?,?,?,?,?)',
            self._cola)
        self.total += len(self._cola)
        self._meta_set('total', self.total)
        self._meta_set('ultima_utc', datetime.now(timezone.utc)
                       .isoformat(timespec='seconds'))
        self.con.commit()
        self._cola.clear()
        self._ultimo_flush = time.time()

    def cerrar(self):
        if self._cerrada:
            return
        self._cerrada = True
        self._flush()
        self.con.close()

    def informe(self):
        primera = self._meta_get('primera_utc', '-')
        return (f'total={self.total:,} | primera={primera} '
                f'ultima={self._meta_get("ultima_utc", "-")}')

    # ---- Ciclo de vida ----------------------------------------------------
    def iniciar(self, iface, duracion=0, objetivo=500_000, log_cada=300):
        import threading
        from scapy.all import AsyncSniffer
        if self.total == 0:
            self._meta_set('primera_utc', datetime.now(timezone.utc)
                           .isoformat(timespec='seconds'))
        sniffer = AsyncSniffer(iface=iface, prn=self.procesar, store=False,
                               filter=' or '.join(f'tcp dst port {p}'
                                                  for p in sorted(PUERTOS_WEB)))
        sniffer.start()
        print(f'[OK] Capturando en {iface} (puertos {sorted(PUERTOS_WEB)}). '
              f'Ctrl+C para detener.')
        print(f'[*] {self.informe()}')
        # Anclas separadas: la de duracion NUNCA se resetea (bug de la v1:
        # el log reiniciaba t0 y --duracion no terminaba nunca).
        t0 = time.time()
        t_log = time.time()
        try:
            while True:
                time.sleep(1)  # granularidad de 1 s: sale puntual
                if duracion and time.time() - t0 >= duracion:
                    break
                if time.time() - t_log >= log_cada:
                    t_log = time.time()
                    pct = 100.0 * self.total / objetivo if objetivo else 0
                    print(f'[{datetime.now(timezone.utc).strftime("%H:%M:%S")}] '
                          f'{self.informe()} ({pct:.1f}% del objetivo {objetivo:,})')
        except KeyboardInterrupt:
            pass
        finally:
            # AsyncSniffer.stop() puede bloquearse esperando un paquete:
            # cerrar con timeout para que el proceso SIEMPRE salga.
            try:
                t_stop = threading.Thread(target=sniffer.stop, daemon=True)
                t_stop.start()
                t_stop.join(timeout=10)
            except Exception as e:
                print(f'[!] stop: {e}')
            resumen = self.informe()
            self.cerrar()
            print(f'[OK] Captura cerrada. {resumen}')


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--iface', default=(os.environ.get('IDS_IFACE') or '').strip()
                    or None, help='interfaz de captura (defecto: IDS_IFACE)')
    ap.add_argument('--bd', default=str(BD_DEF))
    ap.add_argument('--duracion', type=int, default=0,
                    help='segundos; 0 = hasta detenerlo (defecto)')
    ap.add_argument('--objetivo', type=int, default=500_000)
    ap.add_argument('--log-cada', type=int, default=300,
                    help='segundos entre lineas de progreso')
    ap.add_argument('--prueba', type=int, metavar='SEGUNDOS',
                    help='corrida de prueba de N segundos y sale')
    args = ap.parse_args()
    if args.prueba:
        args.duracion = args.prueba
        args.log_cada = args.duracion + 1

    if not args.iface:
        print('[X] Sin interfaz: definir IDS_IFACE o pasar --iface')
        sys.exit(1)

    g = GrabberHTTP(args.bd)
    if args.duracion:
        print(f'[*] Corrida de {args.duracion}s (modo prueba)')
    g.iniciar(args.iface, duracion=args.duracion, objetivo=args.objetivo,
              log_cada=args.log_cada)


if __name__ == '__main__':
    main()
