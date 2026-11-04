# -*- coding: utf-8 -*-
"""
test_respuesta.py — Caminos de alerta/bloqueo y detectores no-escaneo (v5).

Complementa test_portscan.py: aquí se prueba el modo ALERTA y BLOQUEO
(IDS_MODO_OBSERVACION=0), el arbitraje de la heurística SQLi, las exenciones
de SYN/DDoS/UDP y el throttle de persistencia.
"""
import os
import sys
import tempfile

import pytest

_TMP = os.path.join(tempfile.gettempdir(), 'ids_v5_tests')
os.makedirs(_TMP, exist_ok=True)
os.environ.setdefault('IDS_DB_PATH', os.path.join(_TMP, 'test_portscan.db'))
os.environ.setdefault('IDS_MODO_OBSERVACION', '1')

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ids  # noqa: E402
from scapy.all import IP, TCP, UDP, Raw  # noqa: E402

GUARDAR_REAL = ids.guardar_ataque


def tcp(src, dst, dport, flags='S', carga=None):
    pkt = IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags=flags)
    if carga:
        pkt = pkt / Raw(load=carga)
    return pkt


@pytest.fixture(autouse=True)
def limpiar_floods():
    """Evita que los contadores de flood de una prueba contaminen la siguiente."""
    ids.syn_por_src.clear()
    ids.flood_por_dst.clear()
    ids._ultimo_metrica_scan.clear()
    ids._ultimo_datos_paquete.clear()
    yield


@pytest.fixture
def modo_produccion(monkeypatch):
    """Simula producción: observación OFF, sin Telegram real ni logs de bloqueo."""
    enviados, bloqueos_log = [], []
    monkeypatch.setattr(ids, 'IDS_MODO_OBSERVACION', False)
    monkeypatch.setattr(ids, '_enviar_alerta_async', lambda m: enviados.append(m))
    monkeypatch.setattr(ids, 'registrar_bloqueo_log',
                        lambda *a, **k: bloqueos_log.append(a))
    monkeypatch.setattr(ids, 'modo_ips_autonomo', False)  # semi: sin MikroTik real
    ids._ultimo_alerta_por_clave.clear()
    ids._ultimo_persist_por_clave.clear()
    return {'telegram': enviados, 'bloqueos_log': bloqueos_log}


@pytest.fixture
def capturados(monkeypatch):
    capturados = []
    monkeypatch.setattr(ids, 'guardar_ataque', lambda *a, **k: capturados.append((a, k)))
    return capturados


# -----------------------------------------------------------------------------
# Modos de respuesta (antes solo existía el comportamiento 'alerta silenciosa')
# -----------------------------------------------------------------------------

def test_modo_alerta_telegram_sin_bloqueo(modo_produccion):
    ids.ips_activo = False
    try:
        GUARDAR_REAL('203.0.113.231', "Escaneo de Puertos", 'TCP', 0, '172.10.1.21',
                     n_puertos=60, ventana_s=60, umbral=50, forzar=True)
    finally:
        ids.ips_activo = False

    cur = ids.conn.cursor()
    fila = cur.execute(
        "SELECT modo, ip_src FROM ataques WHERE ip_src='203.0.113.231' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    assert fila[0] == 'alerta'
    assert len(modo_produccion['telegram']) == 1
    assert cur.execute("SELECT COUNT(*) FROM bloqueos WHERE ip_src='203.0.113.231'"
                       ).fetchone()[0] == 0


def test_bloqueo_semi_autonomo_registra_estado(modo_produccion):
    """IPS activo (semi): heurística crítica -> fila en `bloqueos`, sin MikroTik real."""
    ids.ips_activo = True
    try:
        GUARDAR_REAL('203.0.113.232', "Escaneo de Puertos", 'TCP', 0, '172.10.1.22',
                     n_puertos=90, ventana_s=60, umbral=50, forzar=True)
    finally:
        ids.ips_activo = False

    cur = ids.conn.cursor()
    estado, tipo = cur.execute(
        "SELECT estado, tipo_ataque FROM bloqueos WHERE ip_src='203.0.113.232' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    assert estado == 'SIMULADO/SEMI'           # semi: no toca el router
    assert 'Escaneo' in tipo
    assert len(modo_produccion['bloqueos_log']) == 1
    assert len(modo_produccion['telegram']) >= 1


def test_ml_bajo_umbral_no_bloquea(modo_produccion):
    """ML con confianza < UMBRAL_ML es crítico pero no puede bloquear."""
    ids.ips_activo = True
    try:
        GUARDAR_REAL('203.0.113.233', "Posible_Exploit", 'TCP', 445, '172.10.1.23',
                     es_ml_puro=True, confianza_ml=ids.UMBRAL_ML - 0.01, forzar=True)
    finally:
        ids.ips_activo = False

    cur = ids.conn.cursor()
    fila = cur.execute(
        "SELECT modo FROM ataques WHERE ip_src='203.0.113.233' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    assert fila[0] == 'alerta'                  # alerta, pero no 'bloqueo'
    assert cur.execute("SELECT COUNT(*) FROM bloqueos WHERE ip_src='203.0.113.233'"
                       ).fetchone()[0] == 0


# -----------------------------------------------------------------------------
# SQLi: la heurística regex es candidata, nunca alerta por sí sola
# -----------------------------------------------------------------------------

def test_sqli_heuristica_queda_en_observacion(modo_produccion):
    """Con observación OFF, la heurística regex NO alerta: manda modo_forzado."""
    pkt = tcp('203.0.113.234', '172.10.1.24', 80, flags='PA',
              carga="1' or 1=1 --")
    ids.detectar_sql_injection(pkt)

    cur = ids.conn.cursor()
    fila = cur.execute(
        "SELECT modo, tipo_ataque, evidencia_json FROM ataques WHERE ip_src='203.0.113.234' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    assert fila is not None
    assert fila[0] == 'observacion'             # aunque el motor esté en producción
    assert 'SQL Injection' in fila[1]
    assert 'sqli_regex' in (fila[2] or '')
    assert modo_produccion['telegram'] == []    # y nunca notifica


def test_sqli_muestra_saneada():
    carga = "select * from users where password='x' or 1=1 --"
    muestra = ids._sanear_muestra_sqli(carga)
    assert 'password' not in muestra.lower()
    assert 'omitido' in muestra


# -----------------------------------------------------------------------------
# Exenciones y conteo SYN-only en floods
# -----------------------------------------------------------------------------

def test_syn_flood_cdn_exenta(capturados):
    for _ in range(60):
        ids.detectar_syn_flood(tcp('8.8.8.8', '172.10.1.25', 8080))
    assert capturados == []


def test_ddos_ignora_trafico_ack(capturados):
    """El tráfico legítimo (ACK/data) de un servidor popular no es DDoS."""
    for _ in range(600):
        ids.detectar_ddos(tcp('34.117.41.85', '172.10.12.216', 443, flags='PA'))
    assert capturados == []


def test_ddos_cuenta_solo_syn(capturados):
    ids.BASE_THRESHOLD_DDOS = 500
    # 501 SYN desde 10 fuentes distintas: un DDoS real requiere varias fuentes.
    for i in range(501):
        src = f'198.51.100.{50 + (i % 10)}'
        ids.detectar_ddos(tcp(src, '172.10.12.216', 80, flags='S'))
    assert len(capturados) == 1
    assert capturados[0][0][1] == "DDoS Distribuido"
    assert capturados[0][1]['meta_heuristica']['n_sources'] >= 10


def test_ddos_una_sola_fuente_no_es_ddos(capturados):
    """501 SYN de una IP es SYN flood (otro detector), no ataque distribuido."""
    ids.BASE_THRESHOLD_DDOS = 500
    for _ in range(501):
        ids.detectar_ddos(tcp('198.51.100.77', '172.10.12.217', 80, flags='S'))
    assert capturados == []


def test_udp_flood_cdn_exenta(capturados):
    for _ in range(600):
        ids.detectar_udp_flood(IP(src='1.1.1.1', dst='172.10.1.26') / UDP(sport=53, dport=5000))
    assert capturados == []


# -----------------------------------------------------------------------------
# Lista blanca de hosts de gestión (decisión operativa 2026-10-28)
# -----------------------------------------------------------------------------

def test_hosts_gestion_en_lista_blanca_por_defecto():
    """172.10.0.57/.59 eximidas del detector de exploit (TFTP broadcast en la
    v1 = 45 % del ruido). Decisión registrada en docs/RUNBOOK_C3.md."""
    assert '172.10.0.57' in ids.HOSTS_GESTION
    assert '172.10.0.59' in ids.HOSTS_GESTION


def test_host_gestion_exento_de_exploit(capturados):
    for p in (445, 3389, 21):
        ids.detectar_exploit(tcp('172.10.0.57', '172.10.1.30', p))
    assert capturados == []


def test_host_normal_interno_sigue_detectado_en_exploit(capturados):
    """La exención es solo para HOSTS_GESTION: otro host interno conectándose
    a puertos de explotación (posible movimiento lateral) se registra igual."""
    ids.detectar_exploit(tcp('172.10.0.60', '172.10.1.30', 445))
    assert len(capturados) == 1
    assert capturados[0][0][1] == "Posible Exploit"


def test_exploit_ignora_respuesta_del_servidor(capturados):
    """Un SYN+ACK es respuesta, no un intento de explotación saliente."""
    ids.detectar_exploit(tcp('203.0.113.240', '172.10.1.31', 445, flags='SA'))
    assert capturados == []


def test_exploit_ignora_broadcast(capturados):
    """C3 registró un SYN a 445 hacia 172.10.2.255: es broadcast, no ataque."""
    ids.detectar_exploit(tcp('172.10.2.50', '172.10.2.255', 445))
    assert capturados == []


def test_udp_retorno_de_servicio_no_es_flood(capturados):
    """QUIC 443 -> efímero es retorno al cliente, no un flood entrante."""
    for _ in range(600):
        ids.detectar_udp_flood(
            IP(src='142.250.0.1', dst='172.10.1.32') / UDP(sport=443, dport=52000))
    assert capturados == []


# -----------------------------------------------------------------------------
# El ML no es vía de alerta (defecto)
# -----------------------------------------------------------------------------

def test_ml_no_persiste_alertas_por_defecto():
    assert ids.ML_ALERTAS is False
    ip = '203.0.113.241'
    ids.conn.execute("DELETE FROM ataques WHERE ip_src=?", (ip,))
    ids.conn.commit()

    ids.on_flow_ready(ip, '172.10.1.33', {'Dst Port': 445, 'Protocol': 6})

    n = ids.conn.execute("SELECT COUNT(*) FROM ataques WHERE ip_src=?",
                         (ip,)).fetchone()[0]
    assert n == 0
    assert ids.metricas_trafico.get('ml_suprimidos', 0) >= 1


def test_sqli_firma_fuerte_en_http_alerta(modo_produccion):
    """Una firma inequívoca dentro de una petición HTTP sí alerta."""
    pkt = tcp('203.0.113.242', '172.10.1.34', 80, flags='PA',
              carga="GET /q?id=1%27%20UNION%20SELECT%20name%20FROM%20users-- HTTP/1.1\r\n"
                    "Host: ejemplo\r\n\r\n")
    ids.detectar_sql_injection(pkt)

    fila = ids.conn.execute(
        "SELECT modo, tipo_ataque, evidencia_json FROM ataques "
        "WHERE ip_src='203.0.113.242' ORDER BY id DESC LIMIT 1").fetchone()
    assert fila is not None
    assert fila[0] == 'alerta'
    assert 'SQL Injection' in fila[1]
    assert 'sqli_signature' in (fila[2] or '')
    assert len(modo_produccion['telegram']) == 1


def test_sqli_firma_fuerte_en_respuesta_no_alerta(modo_produccion):
    """La misma firma en una respuesta (sin línea de petición) es candidata."""
    pkt = tcp('203.0.113.243', '172.10.1.35', 52000, flags='PA',
              carga="HTTP/1.1 200 OK\r\n\r\n1 UNION SELECT name FROM users--")
    ids.detectar_sql_injection(pkt)

    fila = ids.conn.execute(
        "SELECT modo FROM ataques WHERE ip_src='203.0.113.243' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    assert fila is not None
    assert fila[0] == 'observacion'
    assert modo_produccion['telegram'] == []


# -----------------------------------------------------------------------------
# Throttle de persistencia (familia flood/exploit)
# -----------------------------------------------------------------------------

def test_throttle_persistencia_exploit():
    """Dos ráfagas del mismo exploit en 10 s -> una sola fila en BD."""
    ipx = '203.0.113.235'
    ids._ultimo_persist_por_clave.clear()
    cur = ids.conn.cursor()
    cur.execute("DELETE FROM ataques WHERE ip_src=?", (ipx,))  # idempotente entre corridas
    ids.conn.commit()

    GUARDAR_REAL(ipx, "Posible Exploit", 'TCP', 445, '172.10.1.27', forzar=False)
    GUARDAR_REAL(ipx, "Posible Exploit", 'TCP', 445, '172.10.1.27', forzar=False)

    n = cur.execute("SELECT COUNT(*) FROM ataques WHERE ip_src=?", (ipx,)).fetchone()[0]
    assert n == 1
