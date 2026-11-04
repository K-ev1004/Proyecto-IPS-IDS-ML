# -*- coding: utf-8 -*-
"""
politica_bloqueo.py — Matriz de decisión por fuente (M4 de ML v6).

Generaliza el arbitraje fijo (guía ML_V6_DESARROLLO.md §5.3) en una matriz
configurable: cada combinación de fuente (ml / heuristica / ambas) decide
QUÉ hacer y CUÁNTO durar el bloqueo. La severidad escala el tiempo.

Matriz default (conservadora, alineada al plan v6):
    ml+heuristica -> BLOQUEAR  24 h   (doble firma: máxima certeza)
    ml            -> ALERTAR    1 h   (precisa pero sin 2ª firma)
    heuristica    -> ALERTAR   24 h   (comportamiento de producción)

Reingreso por clase (M6): overrides por clase en config/politica_bloqueo.json.
Ej.: Inyeccion_SQL gana "ml -> bloquear 2 h" cuando su precisión medida lo
justifique; una clase "en observación" pone "ml -> grabar".

Overrides de operación (sin tocar el JSON):
    IDS_POLITICA=heuristica  -> colapsa toda la matriz a solo-heurística
                                (equivalente exacto a la producción v5)
    IDS_POLITICA=sombra      -> todo a grabar (nada notifica ni bloquea)

Este módulo NO conoce scapy ni la BD: es decisión pura, testeable.
"""
import json
import os
from pathlib import Path

# Acciones válidas de la matriz
ACCIONES = ('grabar', 'alertar', 'bloquear')

# Severidades por combinación de fuente (viajan en la alerta: BD/Telegram/GUI)
SEVERIDADES = {
    'ml+heuristica': 'CRITICA',
    'ml': 'MEDIA',
    'heuristica': 'NORMAL',
}

# Etiquetas de origen para notificación/GUI
ETIQUETAS = {
    'ml+heuristica': 'ML+HEUR',
    'ml': 'ML',
    'heuristica': 'HEUR',
}

# Duraciones default en minutos (escalan con la severidad: respuesta
# proporcional a la certeza). duracion 0 = hasta apagado (uso manual).
DURACIONES_DEFAULT_MIN = {
    'ml+heuristica': 24 * 60,   # 24 h
    'ml': 60,                    # 1 h: contenido, se autorevierte si es FP
    'heuristica': 24 * 60,       # 24 h, como producción hoy
}

# Overrides por clase (M6): clave = clase, valor = dict de combos a override.
# Poblar con la evidencia de cada fase (M5 sombra / M6 reingreso).
OVERRIDES_POR_CLASE = {}

CONFIG_PATH = Path(__file__).resolve().parent.parent / 'config' / 'politica_bloqueo.json'


def _politica_base():
    """Matriz default (o colapsada por IDS_POLITICA)."""
    return {
        'ml+heuristica': {'accion': 'bloquear',
                          'duracion_min': DURACIONES_DEFAULT_MIN['ml+heuristica']},
        'ml': {'accion': 'alertar',
               'duracion_min': DURACIONES_DEFAULT_MIN['ml']},
        'heuristica': {'accion': 'alertar',
                       'duracion_min': DURACIONES_DEFAULT_MIN['heuristica']},
    }


def _cargar_config():
    """Lee config/politica_bloqueo.json si existe (versionable).
    Estructura:
        {"defaults": {"ml": {"accion": "alertar", "duracion_min": 60}, ...},
         "por_clase": {"Inyeccion_SQL": {"ml": {"accion": "bloquear"}}, ...}}
    Solo se aceptan acciones válidas; entradas inválidas se ignoran con
    advertencia (la matriz nunca queda indefinida).
    """
    base = _politica_base()
    por_clase = {}
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
            for combo, valor in (cfg.get('defaults') or {}).items():
                if combo in base and isinstance(valor, dict):
                    if valor.get('accion') in ACCIONES:
                        base[combo]['accion'] = valor['accion']
                    if 'duracion_min' in valor:
                        base[combo]['duracion_min'] = int(valor['duracion_min'])
            for clase, combos in (cfg.get('por_clase') or {}).items():
                limpio = {}
                for combo, valor in (combos or {}).items():
                    if combo in base and isinstance(valor, dict):
                        celda = {}
                        if valor.get('accion') in ACCIONES:
                            celda['accion'] = valor['accion']
                        if 'duracion_min' in valor:
                            celda['duracion_min'] = int(valor['duracion_min'])
                        if celda:
                            limpio[combo] = celda
                if limpio:
                    por_clase[clase] = limpio
        except (ValueError, OSError) as e:
            print(f"[!] politica_bloqueo: config inválida ({e}); uso defaults")
    return base, por_clase


def decidir(clase, senal_ml, senal_heuristica):
    """Devuelve la decisión de la matriz para un evento.

    Args:
        clase: clase de ataque (Inyeccion_SQL, SYN_Flood, ...). Si la clase
            no tiene override, usa defaults.
        senal_ml: True si el ML (v6 payload o CatBoost, con su umbral por
            clase) marcó el evento.
        senal_heuristica: True si una señal independiente (regex fuerte,
            contadores v5, dirección) confirma.

    Returns:
        dict: {accion, severidad, origen, duracion_min, etiqueta}
        accion en {grabar, alertar, bloquear}; duracion 0 = hasta apagado.
    """
    base, por_clase = _cargar_config()

    modo = (os.environ.get('IDS_POLITICA') or '').strip().lower()
    if modo == 'sombra':
        base = {k: {'accion': 'grabar', 'duracion_min': 0}
                for k in base}

    if senal_ml and senal_heuristica:
        combo = 'ml+heuristica'
    elif senal_ml:
        combo = 'ml'
    elif senal_heuristica:
        combo = 'heuristica'
    else:
        return {'accion': 'grabar', 'severidad': 'BAJA', 'origen': 'sin_señal',
                'duracion_min': 0, 'etiqueta': 'CANDIDATO'}

    celda = dict(base[combo])
    override = (por_clase.get(clase) or {}).get(combo)
    if override:
        celda.update(override)

    if modo == 'heuristica':
        # Producción v5 exacta: solo la heurística decide; ML sin voto.
        if combo == 'ml':
            celda = {'accion': 'grabar', 'duracion_min': 0}
        elif combo == 'ml+heuristica':
            celda['accion'] = 'alertar'

    return {
        'accion': celda['accion'],
        'severidad': SEVERIDADES[combo],
        'origen': 'ml+heuristica' if combo == 'ml+heuristica' else combo,
        'duracion_min': int(celda.get('duracion_min', 0)),
        'etiqueta': ETIQUETAS[combo],
    }


def duracion_horas(decision):
    """Convierte la duración de la política a horas (unidad del bloqueo
    MikroTik / registrar_bloqueo_log). 0 = hasta apagado."""
    return max(0, decision.get('duracion_min', 0)) // 60
