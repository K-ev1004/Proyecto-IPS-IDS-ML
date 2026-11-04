# -*- coding: utf-8 -*-
"""
test_flujos_v6.py — FlowTracker v6 (M1): features direccionales.

Prueba el defecto nº 1 del diagnóstico C3 (flujo sin dirección) y las 11
features nuevas, SIN scapy y SIN importar ids (llamadas directas con
primitivas). Las 24 features v5 deben quedar intactas para compatibilidad.
"""
import os
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import flujos_red  # noqa: E402
from flujos_red import FlujoBidireccional, FlowTracker  # noqa: E402

T0 = 1000.0  # base de tiempo cualquiera


def crear_flujo_syn(win=8192):
    """Flujo iniciado con SYN puro desde 172.10.5.10 hacia 8.8.8.8:443."""
    return FlujoBidireccional('172.10.5.10', '8.8.8.8', 49152, 443, 'TCP',
                              T0, tcp_flags='S', tcp_window=win)


def test_syn_puro_fija_iniciador():
    f = crear_flujo_syn()
    f.add_packet(60, T0 + 0.001, True, 'S', 8192)
    d = f.get_features_dict()
    assert d['dir_init'] == 1            # el src del primer paquete inició
    assert d['init_win_bytes'] == 8192   # window del SYN
    assert d['dst_port_svc'] == 1        # 443 es puerto de servicio
    assert d['src_port_svc'] == 0        # 49152 es efímero
    assert d['unipaz_src'] == 1          # 172.10.x es UNIPAZ
    assert d['unipaz_dst'] == 0          # 8.8.8.8 no


def test_primer_paquete_sin_syn_desconocida():
    """Regla del plan: si el primer paquete no es SYN puro, NO inventar."""
    # SYN-ACK (respuesta del servidor) visto primero: desconocida
    f1 = FlujoBidireccional('8.8.8.8', '172.10.5.10', 443, 49152, 'TCP',
                            T0, tcp_flags='SA', tcp_window=65535)
    assert f1.get_features_dict()['dir_init'] == -1
    # UDP sin SYN: desconocida
    f2 = FlujoBidireccional('8.8.4.4', '172.10.5.10', 53, 50000, 'UDP', T0)
    assert f2.get_features_dict()['dir_init'] == -1
    assert f2.get_features_dict()['init_win_bytes'] == 0


def test_retorno_de_servicio_se_ve_como_respondido():
    """El caso C3: SYN entrante que NO se vio, pero la respuesta sí.
    Aquí dir_init=-1 (no inventar), y el par svc/efímero delata la dirección."""
    f = FlujoBidireccional('142.250.0.1', '172.10.5.10', 5228, 50000, 'TCP',
                           T0, tcp_flags='SA')
    d = f.get_features_dict()
    assert d['dir_init'] == -1
    assert d['src_port_svc'] == 1        # 5228 (Google/WhatsApp) delata retorno
    assert d['dst_port_svc'] == 0


def test_iat_y_ping_pong():
    f = crear_flujo_syn()
    t = T0
    f.add_packet(60, t, True, 'S', 8192)          # SYN cliente
    t += 0.010; f.add_packet(60, t, False, 'SA')  # SYN-ACK 10 ms
    t += 0.020; f.add_packet(120, t, True, 'A')   # ACK 20 ms
    t += 0.030; f.add_packet(500, t, False, 'A')  # datos 30 ms
    t += 0.040; f.add_packet(500, t, True, 'PA')  # datos 40 ms
    d = f.get_features_dict()
    assert len(f.iats_ms) == 4                    # 4 intervalos entre 5 paquetes
    assert abs(d['flow_iat_mean'] - 25.0) < 1e-6  # (10+20+30+40)/4 ms
    assert d['flow_iat_std'] > 0
    assert d['pkt_dir_changes'] == 4              # S->SA->A->A->PA alterna siempre
    assert d['bytes_per_pkt'] == (60+60+120+500+500) / 5
    assert abs(d['fwd_bwd_ratio'] - 3/2) < 1e-9   # 3 fwd / 2 bwd


def test_flujo_un_paquete_no_colapsa():
    """IGMP/1-paquete ya no entra (filtro en ids.py), pero un flujo TCP de un
    solo SYN debe dar features saneadas, no NaN."""
    f = crear_flujo_syn()
    f.add_packet(60, T0, True, 'S', 8192)
    d = f.get_features_dict()
    assert d['fwd_bwd_ratio'] == 1.0          # max(1, 0) en el denominador
    assert d['bytes_per_pkt'] == 60.0
    assert d['flow_iat_mean'] == 0 and d['flow_iat_std'] == 0


def test_compat_v5_features_intactas():
    """Los 23 nombres de features_seleccionadas_v5 siguen presentes y con
    tipos numéricos; SQLiGuard sigue pudiendo derivar sus 9."""
    import joblib
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    feats_v5 = joblib.load(os.path.join(base, 'Modelos_Entrenados',
                                        'selected_features_v5.pkl'))
    f = crear_flujo_syn()
    f.add_packet(60, T0 + 0.001, True, 'S', 8192)
    d = f.get_features_dict()
    for nombre in feats_v5:
        assert nombre in d, f'feature v5 perdida: {nombre}'
        assert isinstance(d[nombre], (int, float))
    # las 9 de SQLiGuard se DERIVAN en ids.py (_features_sqli_guard) desde
    # estos campos fuente: el contrato es que sigan existiendo.
    fuente_guard = ['Src Port', 'Dst Port', 'Protocol', 'Flow Duration',
                    'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts',
                    'TotLen Bwd Pkts', 'Flow Byts/s', 'Flow Pkts/s',
                    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt',
                    'PSH Flag Cnt', 'ACK Flag Cnt']
    for g in fuente_guard:
        assert g in d, f'fuente de SQLiGuard perdida: {g}'


def test_tracker_pasa_features_completas():
    """El callback de FlowTracker recibe el dict COMPLETO (con las v6)."""
    capturado = {}
    ft = FlowTracker(lambda src, dst, feats: capturado.update(feats))
    ft.ultimo_chequeo = time.time() + 9999  # no limpiar durante el test
    ft.procesar_paquete('172.10.5.10', '8.8.8.8', 49152, 443, 'TCP', 60,
                        'S', T0, tcp_window=8192)
    ft.procesar_paquete('8.8.8.8', '172.10.5.10', 443, 49152, 'TCP', 60,
                        'SA', T0 + 0.01)
    flujo = ft.flujos[('172.10.5.10', '8.8.8.8', 49152, 443, 'TCP')]
    flujo.last_time = T0 - flujos_red.FLOW_TIMEOUT - 1  # forzar expiración
    ft._limpiar_flujos_expirados(T0)
    assert capturado, 'el callback no recibió features'
    assert capturado['dir_init'] == 1
    assert 'Flow Duration' in capturado   # la v5 sigue viva en el mismo dict


def test_json_serializable():
    """features_json de ml_candidatos (M4) exige serialización limpia."""
    f = crear_flujo_syn()
    f.add_packet(60, T0 + 0.001, True, 'S', 8192)
    json.dumps(f.get_features_dict())  # no debe lanzar
