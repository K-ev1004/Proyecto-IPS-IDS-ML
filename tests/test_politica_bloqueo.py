# -*- coding: utf-8 -*-
"""
test_politica_bloqueo.py — Matriz de decisión M4 (politica_bloqueo.decidir).

Prueba las 4 combinaciones de fuente, las severidades y duraciones por
severidad, los overrides por clase (reingreso M6) y los modos de operación
(IDS_POLITICA=heuristica / sombra).
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import politica_bloqueo as pb  # noqa: E402


def _recargar():
    """Cada test arranca con la matriz default (el módulo es puro)."""
    os.environ.pop('IDS_POLITICA', None)
    return importlib.reload(pb)


def test_doble_firma_bloquea_24h():
    pb = _recargar()
    d = pb.decidir('SYN_Flood', senal_ml=True, senal_heuristica=True)
    assert d['accion'] == 'bloquear'
    assert d['severidad'] == 'CRITICA'
    assert d['duracion_min'] == 1440
    assert d['etiqueta'] == 'ML+HEUR'
    assert pb.duracion_horas(d) == 24


def test_ml_solo_alerta_1h():
    pb = _recargar()
    d = pb.decidir('SYN_Flood', senal_ml=True, senal_heuristica=False)
    assert d['accion'] == 'alertar'
    assert d['severidad'] == 'MEDIA'
    assert d['duracion_min'] == 60
    assert pb.duracion_horas(d) == 1


def test_heuristica_sola_alerta_24h():
    pb = _recargar()
    d = pb.decidir('DDoS_Distribuido', senal_ml=False, senal_heuristica=True)
    assert d['accion'] == 'alertar'
    assert d['severidad'] == 'NORMAL'
    assert d['duracion_min'] == 1440
    assert d['etiqueta'] == 'HEUR'


def test_sin_senales_solo_graba():
    pb = _recargar()
    d = pb.decidir('Normal', senal_ml=False, senal_heuristica=False)
    assert d['accion'] == 'grabar'
    assert d['duracion_min'] == 0


def test_override_por_clase_reingreso_m6(tmp_path, monkeypatch):
    """Ejemplo M6: Inyeccion_SQL gana 'ml -> bloquear 2h' con evidencia."""
    pb = _recargar()
    cfg = tmp_path / 'politica.json'
    cfg.write_text(
        '{"por_clase": {"Inyeccion_SQL": '
        '{"ml": {"accion": "bloquear", "duracion_min": 120}}}}',
        encoding='utf-8')
    monkeypatch.setattr(pb, 'CONFIG_PATH', cfg)
    d = pb.decidir('Inyeccion_SQL', senal_ml=True, senal_heuristica=False)
    assert d['accion'] == 'bloquear'
    assert d['duracion_min'] == 120
    # las demás clases NO reciben el override
    d_otra = pb.decidir('SYN_Flood', senal_ml=True, senal_heuristica=False)
    assert d_otra['accion'] == 'alertar'
    assert d_otra['duracion_min'] == 60


def test_modo_heuristica_produccion_v5(monkeypatch):
    """IDS_POLITICA=heuristica: colapso a producción v5 exacta."""
    pb = _recargar()
    monkeypatch.setenv('IDS_POLITICA', 'heuristica')
    d_ml = pb.decidir('SYN_Flood', senal_ml=True, senal_heuristica=False)
    assert d_ml['accion'] == 'grabar'          # el ML no decide
    assert d_ml['duracion_min'] == 0
    d_doble = pb.decidir('SYN_Flood', senal_ml=True, senal_heuristica=True)
    assert d_doble['accion'] == 'alertar'      # alerta, no bloqueo
    d_heur = pb.decidir('SYN_Flood', senal_ml=False, senal_heuristica=True)
    assert d_heur['accion'] == 'alertar'       # como hoy


def test_modo_sombra_todo_graba(monkeypatch):
    pb = _recargar()
    monkeypatch.setenv('IDS_POLITICA', 'sombra')
    for ml, heur in [(True, True), (True, False), (False, True)]:
        d = pb.decidir('DDoS_Distribuido', senal_ml=ml, senal_heuristica=heur)
        assert d['accion'] == 'grabar'
        assert d['duracion_min'] == 0


def test_config_invalida_caen_en_defaults(tmp_path, monkeypatch):
    pb = _recargar()
    cfg = tmp_path / 'politica.json'
    cfg.write_text('{"defaults": {"ml": {"accion": "NUCLEAR"}}, '
                   '"por_clase": {"X": {"ml": "no es dict"}}}',
                   encoding='utf-8')
    monkeypatch.setattr(pb, 'CONFIG_PATH', cfg)
    d = pb.decidir('SYN_Flood', senal_ml=True, senal_heuristica=False)
    assert d['accion'] == 'alertar'   # la matriz nunca queda indefinida
    assert d['duracion_min'] == 60
