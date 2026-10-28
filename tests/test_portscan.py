# -*- coding: utf-8 -*-
"""
test_portscan.py — Pruebas del detector de escaneo v5 (sin red real).

Cubre los criterios de aceptación de docs/PLAN_LANZAMIENTO_V5.md con paquetes
sintéticos de scapy. No abre sockets ni captura tráfico.

Ejecutar:  python -m pytest tests/test_portscan.py -v
"""
import os
import sys
import tempfile
import time

import pytest

# La BD y el modo observación deben configurarse ANTES de importar ids.
_TMP = os.path.join(tempfile.gettempdir(), 'ids_v5_tests')
os.makedirs(_TMP, exist_ok=True)
os.environ.setdefault('IDS_DB_PATH', os.path.join(_TMP, 'test_portscan.db'))
os.environ.setdefault('IDS_MODO_OBSERVACION', '1')

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ids  # noqa: E402
from scapy.all import IP, TCP, UDP  # noqa: E402

GUARDAR_REAL = ids.guardar_ataque  # referencia al original (prueba de persistencia)


def tcp(src, dst, dport, flags='S'):
    return IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags=flags)


def udp(src, dst, dport):
    return IP(src=src, dst=dst) / UDP(sport=40000, dport=dport)


@pytest.fixture(autouse=True)
def entorno(monkeypatch):
    """Aísla cada prueba: ventana vacía y guardar_ataque capturado en memoria."""
    ids.ventana_scan.clear()
    ids.barrido_horizontal.clear()
    ids._ultimo_ts_scan.clear()
    ids._ultimo_ts_horizontal.clear()
    ids._ultimo_alerta_por_clave.clear()
    ids._ultimo_alerta_scan_par.clear()
    ids._ultimo_persist_por_clave.clear()
    capturados = []
    monkeypatch.setattr(ids, 'guardar_ataque',
                        lambda *a, **k: capturados.append((a, k)))
    yield capturados
    monkeypatch.setattr(ids, 'guardar_ataque', GUARDAR_REAL)


# -----------------------------------------------------------------------------
# Exenciones y ruido
# -----------------------------------------------------------------------------

def test_dns_publico_no_alerta(entorno):
    """8.8.8.8 generó 709 alertas en la v1: la exención es obligatoria."""
    for p in range(30000, 30200):
        ids.detectar_escaneo_puertos(tcp('8.8.8.8', '172.10.15.162', p))
    assert entorno == []


def test_respuestas_de_servidor_no_alertan(entorno):
    """50 RST/SA de un servidor busy no son un escaneo (iniciación = sin A/R)."""
    for _ in range(25):
        ids.detectar_escaneo_puertos(tcp('203.0.113.9', '172.10.1.5', 443, flags='SA'))
        ids.detectar_escaneo_puertos(tcp('203.0.113.9', '172.10.1.5', 443, flags='R'))
    assert entorno == []


def test_descubrimiento_y_puerto_cero_no_cuentan(entorno):
    ids.detectar_escaneo_puertos(udp('203.0.113.10', '172.10.1.6', 5353))
    ids.detectar_escaneo_puertos(tcp('203.0.113.10', '172.10.1.6', 0))
    assert entorno == []


# -----------------------------------------------------------------------------
# Detección vertical
# -----------------------------------------------------------------------------

def test_escaneo_vertical_externo_alerta(entorno):
    """100 SYN a puertos distintos de un mismo destino -> 1 alerta con evidencia."""
    for p in range(1, 101):
        ids.detectar_escaneo_puertos(tcp('203.0.113.55', '8.8.4.4', p))
    assert len(entorno) == 1
    args, kwargs = entorno[0]
    assert args[1] == "Escaneo de Puertos"
    # La alerta salta en cuanto se supera el umbral, no al final del barrido
    assert kwargs['n_puertos'] == ids.PORT_SCAN_THRESHOLD + 1
    assert kwargs['ventana_s'] == ids.PORT_SCAN_WINDOW_S
    assert kwargs['umbral'] == ids.PORT_SCAN_THRESHOLD
    meta = kwargs['meta_heuristica']
    assert meta['heuristic'] == 'port_scan_vertical'
    assert meta['ports_sample'][0] == 1


def test_escaneo_stealth_fin_se_detecta(entorno):
    """La v1 exigía flags != 'A'; la v5 no debe perder -sF/-sN/-sX."""
    for p in range(1, 61):
        ids.detectar_escaneo_puertos(tcp('198.51.100.7', '8.8.4.4', p, flags='F'))
    assert len(entorno) == 1
    assert entorno[0][1]['meta_heuristica']['n_distinct_ports'] == ids.PORT_SCAN_THRESHOLD + 1


def test_trabajo_normal_no_alerta(entorno):
    """45 puertos en 10 minutos es uso normal: la ventana de 60 s debe expirar."""
    reloj = [1_000_000.0]

    def tiempo_falso():
        return reloj[0]

    original = ids.time.time
    ids.time.time = tiempo_falso
    try:
        for p in range(1, 46):
            ids.detectar_escaneo_puertos(tcp('198.51.100.8', '8.8.4.4', p))
            reloj[0] += 13.5  # 45 x 13.5 s ≈ 10 min
    finally:
        ids.time.time = original
    assert entorno == []


def test_umbral_interno_mas_estricto(entorno):
    """25 puertos hacia un destino interno alertan; 25 hacia uno externo, no."""
    for p in range(1, 27):
        ids.detectar_escaneo_puertos(tcp('203.0.113.70', '172.20.0.57', p))
    assert len(entorno) == 1
    _, kwargs = entorno[0]
    assert kwargs['umbral'] == ids.PORT_SCAN_THRESHOLD_INTERNAL

    ids.ventana_scan.clear()
    for p in range(1, 27):
        ids.detectar_escaneo_puertos(tcp('203.0.113.70', '8.8.4.4', p))
    assert len(entorno) == 1  # sin nuevas alertas: 25 < 50 externo


def test_escaneo_lateral_interno_no_esta_exento(entorno):
    """El 20,6 % del ruido v1 era interno: eximarlo sería cegar la detección."""
    for p in range(1, 40):
        ids.detectar_escaneo_puertos(tcp('172.20.0.99', '172.10.1.9', p))
    assert len(entorno) == 1


# -----------------------------------------------------------------------------
# Detección horizontal
# -----------------------------------------------------------------------------

def test_barrido_horizontal_alerta(entorno):
    """`nmap -p 445 172.10.0.0/24`: 30 destinos con el mismo puerto."""
    for i in range(1, 31):
        dst = f'172.10.0.{i}'
        ids.detectar_escaneo_puertos(tcp('203.0.113.99', dst, 445))
    horizontales = [(a, k) for a, k in entorno if a[1] == "Escaneo Horizontal"]
    assert len(horizontales) == 1
    _, kwargs = horizontales[0]
    assert kwargs['n_destinos'] > ids.PORT_SCAN_MIN_DESTINOS
    assert kwargs['meta_heuristica']['port'] == 445


# -----------------------------------------------------------------------------
# Persistencia (usa la BD temporal real)
# -----------------------------------------------------------------------------

def test_persistencia_guarda_evidencia():
    """La evidencia nunca se descarta: 2 llamadas seguidas = 2 filas."""
    ids._ultimo_alerta_por_clave.clear()
    GUARDAR_REAL('203.0.113.200', "Escaneo de Puertos", 'TCP', 0, '172.10.1.10',
                 n_puertos=137, ventana_s=60, umbral=50,
                 meta_heuristica={'n_distinct_ports': 137}, forzar=True)
    GUARDAR_REAL('203.0.113.200', "Inyeccion_SQL", 'TCP', 80, '172.10.1.10',
                 es_ml_puro=True, confianza_ml=0.92, forzar=True)

    cur = ids.conn.cursor()
    filas = cur.execute(
        "SELECT tipo_ataque, origen, n_puertos, evidencia_json, puerto, modo, run_id "
        "FROM ataques ORDER BY id DESC LIMIT 2").fetchall()

    assert len(filas) == 2
    # La fila más reciente es el evento ML; la anterior, el escaneo heurístico.
    tipo2, origen2 = filas[0][0], filas[0][1]
    assert origen2 == 'ml' and 'ML' in tipo2

    tipo, origen, n_puertos, evidencia, puerto, modo, run_id = filas[1]
    assert origen == 'heuristica'
    assert n_puertos == 137
    assert evidencia is not None and '137' in evidencia
    assert puerto == 0            # nunca más la cadena "Múltiples"
    assert modo == 'observacion'  # IDS_MODO_OBSERVACION=1 en los tests
    assert run_id.startswith('run-')
