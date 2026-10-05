"""
Genera las figuras del laboratorio a partir de la evidencia ya registrada.

    python _lab/graficar_lab.py                # las tres salidas
    python _lab/graficar_lab.py --solo-png     # sin el GIF (tarda bastante mas)

Tres salidas, con tres_publicos distintos:

  fig_topologia_lab.png   Como esta CONSTRUIDO el laboratorio: el host con sus dos
                          adaptadores host-only, las dos subredes, las tres VMs
                          CHR y por donde pasa el trafico. Es la figura de
                          contexto: la que va antes de explicar cualquier
                          resultado.
  fig_secuencia_demo.png  Como FUNCIONA, en una sola imagen: las cuatro fases de
                          la demostracion sobre el eje de tiempo real, mas los
                          9 gates de T5 en una banda aparte.
  lab_secuencia.gif       Lo mismo en movimiento, para proyectar o defender en
                          vivo: las VMs y las flechas avanzando con el tiempo.

DE DONDE SALEN LOS DATOS, Y POR QUE IMPORTA
    Todo se lee de dos archivos que las corridas dejaron:
      docs/lab/corridas/<corrida>/demo_timeline.csv   la secuencia con t_rel
      docs/lab/corridas/<corrida>/informe_t5.json      los 9 gates
    Las direcciones IP vienen de nodos_lab.py y de la tabla de topologia-lab.md,
    no estan escritas a mano aqui.

    Que estas figuras se deriven de la evidencia, y no de una corrida en vivo, es
    justo lo que las hace defendibles: se pueden regenerar cuando quiera y
    tienen que coincidir con el CSV. Si una figura contradijera al CSV seria un
    bug de este graficador, no del laboratorio.

    Corolario honesto: estas figuras describen una corrida YA REGISTRADA. No son
    capturas del laboratorio funcionando ahora mismo, y no deben presentarse como
    tal.
"""

import argparse
import csv
import json
import os
import sys

import matplotlib
matplotlib.use('Agg')            # servidor sin pantalla: Agg SIEMPRE antes de pyplot
import matplotlib.pyplot as plt                                  # noqa: E402
from matplotlib.animation import FuncAnimation, PillowWriter     # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch   # noqa: E402

_LAB = os.path.dirname(os.path.abspath(__file__))
_PROY = os.path.dirname(_LAB)
if _LAB not in sys.path:
    sys.path.insert(0, _LAB)

RUTA_CSV = os.path.join(_PROY, 'docs', 'lab', 'demo_timeline.csv')
RUTA_T5 = os.path.join(_PROY, 'docs', 'lab', 'informe_t5.json')

RUTA_PNG_TOPO = os.path.join(_PROY, 'docs', 'lab', 'fig_topologia_lab.png')
RUTA_PNG_SEC = os.path.join(_PROY, 'docs', 'lab', 'fig_secuencia_demo.png')
RUTA_GIF = os.path.join(_PROY, 'docs', 'lab', 'lab_secuencia.gif')

# Misma paleta que graficar_bloqueo.py: sobria, legible en proyector y en gris.
C_LIBRE = '#2e7d32'        # verde
C_BLOQ = '#c62828'         # rojo
C_RESTAURADO = '#1565c0'   # azul
C_CONTROL = '#6a1b9a'      # morado
C_CONTADOR = '#ef6c00'     # naranja
C_TINTA = '#37474f'        # gris azulado: cajas y texto
C_FONDO = '#eceff1'
C_RED = '#c8e6c9'          # verde muy claro: cajas de VM sana
C_RED_AV = '#ffcdd2'       # rojo muy claro: VM implicada

# Colores por fase de la demostracion. El orden es el del CSV.
C_FASES = {
    'LIBRE': C_LIBRE,
    'DETECCION': C_CONTADOR,
    'BLOQUEADO': C_BLOQ,
    'DESBLOQUEO': C_CONTROL,
    'RESTAURADO': C_RESTAURADO,
}


# ---------------------------------------------------------------- datos

def cargar_secuencia(ruta_csv):
    """Del CSV de la demo: fases con su ventana, hitos y paquetes por instante."""
    with open(ruta_csv, newline='', encoding='utf-8') as f:
        filas = list(csv.DictReader(f))
    if not filas:
        raise SystemExit(f'[X] CSV vacio: {ruta_csv}')

    fases, hitos, paquetes, control, contador = [], {}, [], [], []
    actual = None
    for fl in filas:
        try:
            t = float(fl['t_rel'])
        except (TypeError, ValueError):
            continue
        fase = (fl.get('fase') or '').strip()
        if fase and fase != actual:
            actual = fase
            fases.append({'fase': fase, 't0': t, 't1': t})
        if fases and fases[-1]['fase'] == fase:
            fases[-1]['t1'] = t

        ev = fl.get('evento') or ''
        if ev in ('deteccion', 'desbloqueo', 'resumen'):
            hitos[ev] = (t, fl.get('detalle') or '')
        elif ev.startswith('ping_atacante->victima'):
            paquetes.append((t, ev.endswith('_ok')))
        elif ev.startswith('ping_victima->ROUTER'):
            control.append((t, ev.endswith('_ok')))
        elif ev == 'contador_drop':
            for tok in (fl.get('detalle') or '').split():
                if tok.startswith('packets='):
                    try:
                        contador.append((t, int(tok.split('=', 1)[1])))
                    except ValueError:
                        pass
    if fases:
        fases[-1]['t1'] = float(filas[-1]['t_rel'])
    return fases, hitos, paquetes, control, contador


def cargar_gates(ruta_t5):
    """Los gates de T5 [(prueba, pass, detalle)], o [] si no hay informe."""
    if not os.path.exists(ruta_t5):
        return []
    with open(ruta_t5, encoding='utf-8') as f:
        datos = json.load(f)
    gates = datos.get('gates') or []
    return [(g.get('prueba', '?'), bool(g.get('pass')), g.get('detalle') or '')
            for g in gates]


def cargar_direcciones():
    """IPs reales del laboratorio.

    Atacante y victima salen de nodos_lab.py y la del router de
    config/mikrotik_lab.json: se leen en vez de fijarse para que, si la topologia
    cambia, las figuras cambien con ella en lugar de quedarse mintiendo.

    Las del host y la del LAN del router NO estan en ninguna configuracion, asi
    que se fijan aqui (o por MIKROTIK_LAN_IP). Son las que habria que tocar si
    se renumera la red.
    """
    from nodos_lab import _leer_json, cargar_nodos, RUTA_PERFIL_CHR
    perfil = _leer_json(RUTA_PERFIL_CHR)
    nodos = cargar_nodos()
    victima = nodos['victima']['host']
    return {
        'wan_host': '10.10.0.1',
        'lan_host': '10.10.1.1',
        'wan_router': os.environ.get('MIKROTIK_IP', perfil.get('ip', '10.10.0.2')),
        'lan_router': os.environ.get('MIKROTIK_LAN_IP',
                                     '.'.join(victima.split('.')[:3] + ['2'])),
        'atacante': nodos['atacante']['host'],
        'victima': victima,
    }


# ------------------------------------------------------- figura: topologia

def _caja(ax, x, y, w, h, titulo, lineas, color_fondo, color_borde,
          titulo_color='#ffffff'):
    """Caja redondeada con titulo y lineas de detalle."""
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle='round,pad=0.012,rounding_size=0.02',
        linewidth=1.6, edgecolor=color_borde, facecolor=color_fondo, zorder=2))
    ax.text(x + w / 2, y + h - 0.055, titulo, ha='center', va='top',
            fontsize=10.5, fontweight='bold', color=titulo_color, zorder=3)
    for i, ln in enumerate(lineas):
        ax.text(x + w / 2, y + h - 0.135 - i * 0.075, ln, ha='center', va='top',
                fontsize=8.2, color=C_TINTA, zorder=3)


def _flecha(ax, p1, p2, color, texto=None, rad=0.0, estilo='-', lw=2.0):
    ax.add_patch(FancyArrowPatch(
        p1, p2, arrowstyle='-|>', mutation_scale=15, linewidth=lw,
        color=color, linestyle=estilo, zorder=4,
        connectionstyle=f'arc3,rad={rad}',
        shrinkA=2, shrinkB=2))
    if texto:
        xm, ym = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2
        ax.text(xm, ym + 0.028, texto, ha='center', va='bottom', fontsize=7.6,
                color=color, fontweight='bold', zorder=5)


def figura_topologia(dir_salida, d):
    """Mapa de construccion del laboratorio: quien esta, donde y por donde pasa."""
    fig, ax = plt.subplots(figsize=(13.2, 7.4), dpi=150)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    fig.patch.set_facecolor('white')

    # Dos bandas de subred, para que se lea de un vistazo que son redes aisladas.
    ax.add_patch(FancyBboxPatch(
        (0.035, 0.60), 0.93, 0.29, boxstyle='round,pad=0.010,rounding_size=0.02',
        linewidth=1.4, edgecolor='#90a4ae', facecolor='#f5f7f8', zorder=0))
    ax.add_patch(FancyBboxPatch(
        (0.035, 0.235), 0.93, 0.29, boxstyle='round,pad=0.010,rounding_size=0.02',
        linewidth=1.4, edgecolor='#90a4ae', facecolor='#f5f7f8', zorder=0))

    ax.text(0.055, 0.865, 'red host-only idslab_wan  -  10.10.0.0/24',
            fontsize=9.5, fontweight='bold', color='#546e7a', va='top')
    ax.text(0.055, 0.500, 'red host-only idslab_lan  -  10.10.1.0/24',
            fontsize=9.5, fontweight='bold', color='#546e7a', va='top')

    # --- Nodos -------------------------------------------------------------
    _caja(ax, 0.075, 0.335, 0.215, 0.175,
          'Host Windows  (el IDS/IPS)',
          [f"{d['wan_host']}  idslab_wan",
           f"{d['lan_host']}  idslab_lan",
           'ids.py + mikrotik_api.py',
           'captura, ML, SQLiGuard'],
          C_TINTA, C_TINTA)

    _caja(ax, 0.385, 0.635, 0.265, 0.215,
          'CHR-IDS-LAB   (el router)',
          ['RouterOS CHR 7.23.7',
           f"ether1  {d['wan_router']}",
           f"ether2  {d['lan_router']}",
           '/ip firewall filter',
           'IDS_BLACKLIST -> drop'],
          '#37474f', '#37474f')

    _caja(ax, 0.075, 0.655, 0.215, 0.175,
          'CHR-ATACANTE-LAB',
          ['RouterOS CHR 7.23.7',
           f"{d['atacante']}  wan",
           'origen del trafico',
           'mismo SO que el router'],
          C_RED, C_LIBRE, C_TINTA)

    _caja(ax, 0.075, 0.275, 0.215, 0.175,
          'CHR-VICTIMA-LAB',
          ['RouterOS CHR 7.23.7',
           f"{d['victima']}  lan",
           'destino del trafico',
           'todo su trafico pasa por el CHR'],
          C_RED, C_LIBRE, C_TINTA)

    # --- Reglas de firewall, al lado del router ---------------------------
    _caja(ax, 0.735, 0.645, 0.205, 0.195,
          'Reglas en el CHR',
          ['address-list',
           '  IDS_BLACKLIST',
           'filter: drop forward',
           '        + input',
           'contador de descartes'],
          C_RED_AV, C_BLOQ, C_TINTA)

    # --- Trafico -----------------------------------------------------------
    _flecha(ax, (0.290, 0.742), (0.385, 0.742), C_LIBRE,
            'trafico que atraviesa el CHR')
    _flecha(ax, (0.650, 0.650), (0.290, 0.362), C_RESTAURADO,
            'ether2 -> victima', rad=0.16)
    _flecha(ax, (0.290, 0.420), (0.385, 0.700), C_CONTROL,
            'SSH de control y readback', rad=-0.16, estilo='--', lw=1.6)
    _flecha(ax, (0.650, 0.790), (0.735, 0.790), C_BLOQ,
            'add/remove', lw=1.8)

    # --- Pie: por que esto es aislante ------------------------------------
    ax.text(0.5, 0.145,
            'Las tres VMs se comunican por dos adaptadores host-only de VirtualBox:\n'
            'ningun paquete sale a la red fisica de la universidad.',
            ha='center', va='top', fontsize=9, color=C_TINTA, style='italic')
    ax.text(0.5, 0.045,
            'El atacante se ve afectado porque su unico camino a la victima es el '
            'router: si el CHR descarta,\nel IPS esta probando algo real, no un '
            'simulador. El control victima -> router\nsigue vivo durante el bloqueo '
            'para demostrar que el corte es del atacante y no de la red.',
            ha='center', va='top', fontsize=8.4, color='#546e7a')

    fig.suptitle('Como esta construido el laboratorio virtual IDS/IPS',
                 fontsize=14.5, fontweight='bold', y=0.985)
    fig.text(0.99, 0.012,
             'UNIPAZ - IDS/IPS | tres VMs RouterOS CHR 7.23.7 sobre dos redes '
             'host-only',
             ha='right', fontsize=7, color='#777')
    fig.tight_layout(rect=(0, 0.075, 1, 0.955))
    fig.savefig(dir_salida, facecolor='white')
    plt.close(fig)
    print(f'[OK] topologia: {dir_salida}')


# ------------------------------------------------------ figura: secuencia

def _nombre_fase(f):
    return {
        'LIBRE': 'LIBRE',
        'DETECCION': 'DETECCION',
        'BLOQUEADO': 'BLOQUEADO',
        'DESBLOQUEO': 'DESBLOQUEO',
        'RESTAURADO': 'RESTAURADO',
    }.get(f, f)


def figura_secuencia(dir_salida, fases, hitos, paquetes, contador, gates):
    """Las cuatro fases sobre el tiempo real, y los 9 gates de T5 en otra banda."""
    fig, (ax, axg) = plt.subplots(
        2, 1, figsize=(12.6, 7.6), dpi=150, sharex=True,
        gridspec_kw={'height_ratios': [2.5, 1], 'hspace': 0.42})

    t0 = min(f['t0'] for f in fases)
    t1 = max(f['t1'] for f in fases)

    # --- Banda de fases ---------------------------------------------------
    visibles = [f for f in fases if f['fase'] in C_FASES]
    for f in visibles:
        c = C_FASES[f['fase']]
        ancho = f['t1'] - f['t0']
        ax.axvspan(f['t0'], f['t1'], color=c, alpha=0.15, zorder=0)
        ax.text((f['t0'] + f['t1']) / 2, 0.80, _nombre_fase(f['fase']),
                ha='center', va='center', fontsize=8.6, fontweight='bold',
                color=c, zorder=3)

    # Paquetes del atacante a la victima: OK arriba, timeout abajo.
    ax.plot([t for t, ok in paquetes if ok], [1.30] * len([1 for _, ok in paquetes if ok]),
            'o', ms=6.5, color=C_LIBRE, label='atacante -> victima  OK', zorder=3)
    ax.plot([t for t, ok in paquetes if not ok],
            [1.06] * len([1 for _, ok in paquetes if not ok]),
            'x', ms=7.5, mew=2.2, color=C_BLOQ,
            label='atacante -> victima  TIMEOUT', zorder=3)

    # Contador del router, en eje propio para no mezclar escalas.
    axc = ax.twinx()
    if contador:
        axc.step([t for t, _ in contador], [v for _, v in contador],
                 where='post', color=C_CONTADOR, lw=1.8, zorder=2)
        axc.set_ylabel('descartes contados\npor el router', color=C_CONTADOR,
                       fontsize=8.5)
        axc.tick_params(axis='y', colors=C_CONTADOR, labelsize=8)
        axc.spines['top'].set_visible(False)
        axc.set_ylim(0, max(v for _, v in contador) * 1.3 + 1)

    # Hitos de la deteccion y el desbloqueo.
    for clave, color in (('deteccion', C_BLOQ), ('desbloqueo', C_CONTROL)):
        if clave in hitos:
            t = hitos[clave][0]
            ax.axvline(t, color=color, lw=1.5, ls='--', zorder=1)
            ax.annotate(clave, xy=(t, 0.55), xytext=(4, 0),
                        textcoords='offset points', color=color,
                        fontsize=8, fontweight='bold', rotation=90, va='center')

    ax.set_xlim(t0 - 0.5, t1 + 0.5)
    ax.set_ylim(0.5, 1.62)
    ax.set_yticks([1.06, 1.30])
    ax.set_yticklabels(['victima', ' victima'], fontsize=8, color='#555')
    ax.set_ylabel('paquetes', fontsize=9)
    ax.set_title('Como funciona el bloqueo, en el tiempo real de la corrida',
                 fontsize=12.5, fontweight='bold', pad=10)
    ax.grid(axis='x', alpha=0.22, ls=':')
    ax.spines['top'].set_visible(False)
    ax.legend(loc='lower left', fontsize=7.8, framealpha=0.92, ncol=2)

    # --- Banda de gates de T5 --------------------------------------------
    n = len(gates)
    for i, (prueba, ok, detalle) in enumerate(gates):
        y = n - i - 1
        c = C_LIBRE if ok else C_BLOQ
        axg.add_patch(FancyBboxPatch(
            (t0 - 0.5, y - 0.34), t1 - t0 + 1.0, 0.68,
            boxstyle='round,pad=0.004,rounding_size=0.03',
            linewidth=1.1, edgecolor=c, facecolor=c, alpha=0.13 if ok else 0.25,
            zorder=1))
        axg.text(t0 - 0.25, y, f'{"OK " if ok else "X  "}{prueba}',
                 ha='left', va='center', fontsize=8, fontweight='bold',
                 color=c, zorder=3)
        axg.text(t1 + 0.25, y, detalle[:58], ha='right', va='center',
                 fontsize=7, color=C_TINTA, zorder=3)

    axg.set_xlim(t0 - 0.5, t1 + 0.5)
    axg.set_ylim(-0.7, n - 0.2)
    axg.set_yticks([])
    axg.set_xlabel('segundos desde el inicio de la demostracion', fontsize=9)
    axg.set_title(f'Los {n} gates de T5 que respaldan la corrida',
                  fontsize=11, fontweight='bold', pad=8)
    for lado in ('top', 'right', 'left'):
        axg.spines[lado].set_visible(False)

    fig.text(0.99, 0.012,
             'UNIPAZ - IDS/IPS | figuras derivadas del CSV y del informe T5 de la '
             'corrida, no capturas del laboratorio en vivo',
             ha='right', fontsize=7, color='#777')
    # tight_layout NO se puede usar con un eje secundario (twinx): se queja y
    # coloca mal las etiquetas del lado derecho. Se reservan los margenes a mano.
    fig.subplots_adjust(left=0.085, right=0.895, top=0.90, bottom=0.11)
    fig.savefig(dir_salida, facecolor='white')
    plt.close(fig)
    print(f'[OK] secuencia: {dir_salida}')


# -------------------------------------------------------------- animacion

class _Escena:
    """Dibuja las VMs y las flechas de trafico en el instante t.

    Se redibuja entera en cada fotograma en lugar de componer subimagenes: asi el
    GIF no sale borroso y las flechas pueden cambiar de color con la fase.
    """

    def __init__(self, fases, paquetes, contador):
        self.fases = [f for f in fases if f['fase'] in C_FASES]
        self.paquetes = paquetes
        self.contador = contador
        self.t0 = min(f['t0'] for f in self.fases)
        self.t1 = max(f['t1'] for f in self.fases)
        self.duracion = max(1.0, self.t1 - self.t0)

    def fase_en(self, t):
        for f in self.fases:
            if f['t0'] <= t <= f['t1']:
                return f['fase']
        return self.fases[-1]['fase'] if t > self.t1 else self.fases[0]['fase']

    def drawn(self, t):
        return (f for f in self.fases if f['t0'] <= t)

    def paquetes_hasta(self, t):
        return [(tt, ok) for tt, ok in self.paquetes if tt <= t]

    def contador_en(self, t):
        v = 0
        for tt, val in self.contador:
            if tt <= t:
                v = val
            else:
                break
        return v


def _nodo(ax, x, y, w, h, titulo, sub, fondo, borde, titulo_fg='#ffffff'):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle='round,pad=0.008,rounding_size=0.02',
        linewidth=1.5, edgecolor=borde, facecolor=fondo, zorder=3))
    ax.text(x + w / 2, y + h * 0.62, titulo, ha='center', va='center',
            fontsize=9.5, fontweight='bold', color=titulo_fg, zorder=4)
    ax.text(x + w / 2, y + h * 0.26, sub, ha='center', va='center',
            fontsize=7.6, color=C_TINTA, zorder=4)


def animacion(dir_salida, escena, fps=12, max_fotogramas=320):
    """Recorre la secuencia completa y muestra el trafico donde toca."""
    n = max(2, int(escena.duracion * fps))
    if n > max_fotogramas:
        fps = max(2, int(max_fotogramas / escena.duracion))
        n = max(2, int(escena.duracion * fps))
        print(f'[*] Se ajusta la animacion a {n} fotogramas a {fps} fps.')

    fig = plt.figure(figsize=(10.4, 6.0), dpi=100)
    ax = fig.add_axes([0, 0, 1, 1])

    def dibujar(i):
        t = escena.t0 + escena.duracion * (i / (n - 1))
        fase = escena.fase_en(t)
        color = C_FASES.get(fase, C_TINTA)

        ax.clear()
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        fig.patch.set_facecolor('white')

        # Bandas de red
        ax.add_patch(FancyBboxPatch(
            (0.04, 0.585), 0.92, 0.255,
            boxstyle='round,pad=0.008,rounding_size=0.02',
            linewidth=1.2, edgecolor='#90a4ae', facecolor='#f5f7f8', zorder=0))
        ax.add_patch(FancyBboxPatch(
            (0.04, 0.245), 0.92, 0.255,
            boxstyle='round,pad=0.008,rounding_size=0.02',
            linewidth=1.2, edgecolor='#90a4ae', facecolor='#f5f7f8', zorder=0))
        ax.text(0.06, 0.822, 'red wan  10.10.0.0/24', fontsize=8,
                fontweight='bold', color='#546e7a', va='top', zorder=1)
        ax.text(0.06, 0.482, 'red lan  10.10.1.0/24', fontsize=8,
                fontweight='bold', color='#546e7a', va='top', zorder=1)

        # El router se pinta del color de la fase: es el actor de la historia.
        _nodo(ax, 0.415, 0.625, 0.20, 0.175, 'CHR-IDS-LAB',
              'router  -  el que bloquea', color, color)
        _nodo(ax, 0.09, 0.645, 0.185, 0.135, 'ATACANTE', '10.10.0.3',
              C_RED, C_LIBRE, C_TINTA)
        _nodo(ax, 0.09, 0.285, 0.185, 0.135, 'VICTIMA', '10.10.1.3',
              C_RED, C_LIBRE, C_TINTA)
        _nodo(ax, 0.415, 0.285, 0.20, 0.135, 'HOST', 'IDS/IPS  -  quien detecta',
              '#eceff1', '#607d8b', C_TINTA)

        # Flecha atacante -> router, coloreada por la fase.
        _flecha(ax, (0.275, 0.712), (0.415, 0.712), color,
                'trafico' if fase != 'BLOQUEADO' else 'descartado', lw=2.4)
        _flecha(ax, (0.615, 0.625), (0.275, 0.352), color,
                'reenviado' if fase != 'BLOQUEADO' else 'no llega', rad=0.15)

        # Paquetes que ya salieron, caminando por la flecha atacante -> router.
        ventana = 2.2
        for tt, ok in escena.paquetes_hasta(t):
            if not (t - ventana <= tt <= t):
                continue
            u = (t - tt) / ventana
            x = 0.275 + u * 0.140
            ax.plot([x], [0.712], marker='o' if ok else 'X',
                    ms=8 if ok else 9,
                    color=C_LIBRE if ok else C_BLOQ, zorder=5)

        # Contador de descartes del router.
        v = escena.contador_en(t)
        ax.text(0.635, 0.712, f'descartes: {v}',
                fontsize=10, fontweight='bold',
                color=C_CONTADOR if v else '#b0bec5', va='center', zorder=5)

        # Regla de firewall
        ax.text(0.635, 0.662, 'IDS_BLACKLIST' + ('  (con la IP del atacante)'
                                                 if fase == 'BLOQUEADO' else '  (vacia)'),
                fontsize=7.6, color=C_BLOQ if fase == 'BLOQUEADO' else '#90a4ae',
                va='center', zorder=5)

        # Fase actual, grande y en su color.
        ax.text(0.5, 0.145, fase, ha='center', va='center', fontsize=20,
                fontweight='bold', color=color, zorder=5)
        ax.text(0.5, 0.085, f't = {t:04.1f} s', ha='center', va='center',
                fontsize=10, color=C_TINTA, zorder=5)
        ax.text(0.5, 0.965,
                'El IPS corta el camino del atacante; la red sigue viva',
                ha='center', va='center', fontsize=11.5, fontweight='bold',
                color=C_TINTA, zorder=5)
        ax.text(0.985, 0.022,
                'UNIPAZ - IDS/IPS | secuencia reconstruida del CSV de la corrida',
                ha='right', fontsize=6.5, color='#90a4ae', zorder=5)
        return []

    anim = FuncAnimation(fig, dibujar, frames=n, interval=1000 / fps, blit=False)
    anim.save(dir_salida, writer=PillowWriter(fps=fps))
    plt.close(fig)
    print(f'[OK] gif: {dir_salida}  ({n} fotogramas, '
          f'{os.path.getsize(dir_salida) // 1024} KB)')


# -------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description='Figuras del laboratorio: topologia, secuencia y animacion.')
    ap.add_argument('--csv', default=RUTA_CSV,
                    help='CSV de la demo (define el tiempo de la secuencia).')
    ap.add_argument('--t5', default=RUTA_T5, help='informe T5 con los gates.')
    ap.add_argument('--salida-dir', default=None,
                    help='carpeta de salida. Por omision, la del CSV, para que '
                         'cada corrida conserve sus propias figuras.')
    ap.add_argument('--solo-png', action='store_true',
                    help='omitir la animacion (tarda bastante mas)')
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        raise SystemExit(f'[X] No existe {args.csv}\n'
                         f'    Ejecuta antes: python _lab/demo_bloqueo.py')

    destino = args.salida_dir or os.path.dirname(os.path.abspath(args.csv))
    os.makedirs(destino, exist_ok=True)

    fases, hitos, paquetes, control, contador = cargar_secuencia(args.csv)
    gates = cargar_gates(args.t5)
    d = cargar_direcciones()

    print(f'[CSV] {len(fases)} fases, {len(paquetes)} paquetes a la victima, '
          f'{len(control)} de control, {len(contador)} muestras del contador')
    print(f'[T5 ] {len(gates)} gates')
    if not any(f['fase'] == 'BLOQUEADO' for f in fases):
        print('[! ] El CSV no tiene fase BLOQUEADO: la secuencia no contara el corte.')

    figura_topologia(os.path.join(destino, 'fig_topologia_lab.png'), d)
    figura_secuencia(os.path.join(destino, 'fig_secuencia_demo.png'),
                     fases, hitos, paquetes, contador, gates)
    if not args.solo_png:
        escena = _Escena(fases, paquetes, contador)
        animacion(os.path.join(destino, 'lab_secuencia.gif'), escena)
    return 0


if __name__ == '__main__':
    sys.exit(main())
