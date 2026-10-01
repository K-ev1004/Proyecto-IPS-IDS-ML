"""
Genera la figura y el GIF de la demostracion del bloqueo a partir del CSV que
deja `_lab/demo_bloqueo.py`.

    python _lab/graficar_bloqueo.py            # figura + GIF
    python _lab/graficar_bloqueo.py --solo-png # solo la figura (mas rapido)

Dos salidas, porque sirven para cosas distintas:

  fig_bloqueo_timeline.png   Es la figura que va en la memoria: se lee de un
                             vistazo, con ejes, leyenda y la franja de bloqueo
                             resaltada. Es estatico, asi que se imprime bien.
  demo_bloqueo.gif           La misma idea en movimiento, para proyectar o
                             poner en un PPT. Se arma redibujando el eje de
                             tiempo por fotograma, no con subimagenes: asi el
                             GIF no depende de la fuente y no sale borroso.

Todo sale del CSV, que es la unica fuente de verdad: si la figura contradice al
CSV, es un bug del graficador, no del laboratorio.
"""

import argparse
import csv
import os
import sys

import matplotlib
matplotlib.use('Agg')            # servidor sin pantalla: hay que usar Agg SIEMPRE
                                 # antes de importar pyplot
import matplotlib.pyplot as plt                                  # noqa: E402
from matplotlib.animation import FuncAnimation, PillowWriter    # noqa: E402
from matplotlib.patches import Patch                             # noqa: E402

_PROY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUTA_CSV = os.path.join(_PROY, 'docs', 'lab', 'demo_timeline.csv')
RUTA_PNG = os.path.join(_PROY, 'docs', 'lab', 'fig_bloqueo_timeline.png')
RUTA_GIF = os.path.join(_PROY, 'docs', 'lab', 'demo_bloqueo.gif')

# Paleta sobria, legible en proyector y en impresion en gris.
C_LIBRE = '#2e7d32'        # verde
C_BLOQ = '#c62828'         # rojo
C_RESTAURADO = '#1565c0'   # azul
C_CONTROL = '#6a1b9a'      # morado
C_CONTADOR = '#ef6c00'     # naranja


def cargar(ruta):
    """Lee el CSV y separa las tres series: paquetes, control y contador."""
    with open(ruta, newline='', encoding='utf-8') as f:
        filas = list(csv.DictReader(f))
    if not filas:
        raise SystemExit(f'[X] CSV vacio: {ruta}')

    paq_v, paq_c, contador, marcas = [], [], [], {}
    for fl in filas:
        try:
            t = float(fl['t_rel'])
        except (TypeError, ValueError):
            continue
        evento = fl['evento']
        if evento == 'contador_drop':
            # 'packets=9'; si RouterOS aun no ha creado la regla, viene vacio.
            for tok in (fl.get('detalle') or '').split():
                if tok.startswith('packets='):
                    try:
                        contador.append((t, int(tok.split('=', 1)[1])))
                    except ValueError:
                        pass
        elif evento.startswith('ping_atacante->victima'):
            paq_v.append((t, evento.endswith('_ok'), fl.get('detalle', '')))
        elif evento.startswith('ping_victima->ROUTER'):
            paq_c.append((t, evento.endswith('_ok'), fl.get('detalle', '')))
        elif evento in ('deteccion', 'desbloqueo'):
            marcas[evento] = t
    return paq_v, paq_c, contador, marcas


def _rango_comun(series, holgura=2.0):
    ts = [t for serie in series for t, *_ in serie]
    if not ts:
        return 0.0, 10.0
    return max(0.0, min(ts) - holgura), max(ts) + holgura


def _twin(ax):
    """Devuelve el eje secundario de 'ax', creandolo solo la primera vez.

    No se puede llamar a ax.twinx() en cada fotograma: cada llamada anade un
    eje NUEVO al figure y lo deja vivo. Repintando 240 veces se acumulaban 240
    ejes y el figure acababa dibujandolos todos en cada frame, que es lo que
    hacia que el GIF tardase minutos en lugar de segundos.
    """
    ax2 = getattr(ax, '_twin_cache', None)
    if ax2 is None:
        ax2 = ax.twinx()
        ax._twin_cache = ax2
    return ax2


def _panel(ax, t0, t1, paq_v, paq_c, contador, marcas, titulo,
           ylim_contador=None):

    """Dibuja el panel principal hasta el instante t1.

    Se reutiliza tal cual en la figura estatica y en cada fotograma del GIF, de
    modo que ambos cuentan exactamente la misma historia.

    `ylim_contador` se fija UNA vez para toda la animacion: si el eje derecho se
    recalculara en cada fotograma, la escala saltaria segun crecen los descartes
    y el GIF se veria temblar.
    """
    ax.clear()

    # Franja de bloqueo: la referencia visual principal.
    tb = marcas.get('deteccion')
    td = marcas.get('desbloqueo')
    if tb is not None:
        ax.axvspan(tb, td if td is not None else t1, color=C_BLOQ, alpha=0.13,
                   zorder=0)
        ax.axvline(tb, color=C_BLOQ, lw=1.4, ls='--', zorder=1)
    if td is not None:
        ax.axvline(td, color=C_CONTROL, lw=1.4, ls=':', zorder=1)

    # Paquetes: OK arriba, TIMEOUT abajo. Usan el eje izquierdo.
    for serie, nivel, color, etiqueta in (
            (paq_v, 1, C_LIBRE, 'atacante->victima'),
            (paq_c, 0.62, C_CONTROL, 'victima->ROUTER (control)')):
        xs_ok = [t for t, ok, _ in serie if ok and t <= t1]
        xs_to = [t for t, ok, _ in serie if not ok and t <= t1]
        ax.plot(xs_ok, [nivel] * len(xs_ok), 'o', ms=7, color=color,
                label=etiqueta, zorder=3, clip_on=False)
        ax.plot(xs_to, [nivel] * len(xs_to), 'x', ms=8, mew=2.2, color=C_BLOQ,
                label=f'{etiqueta.split()[0]} TIMEOUT', zorder=3, clip_on=False)

    # Contador del router: el "cuaderno". Eje derecho para no mezclar escalas.
    ax2 = _twin(ax)
    if contador:

        # En los primeros fotogramas del GIF todavia no hay ni una muestra: se
        # dibuja solo lo que haya llegado, sin indexing a ciegas.
        pares = [(t, v) for t, v in contador if t <= t1]
        if pares:
            xs = [t for t, _ in pares]
            ys = [v for _, v in pares]
            ax2.step(xs, ys, where='post', color=C_CONTADOR, lw=2, zorder=2)
            ax2.scatter(xs[-1:], ys[-1:], color=C_CONTADOR, s=28, zorder=4)
            ax2.annotate(f'{ys[-1]} descartes', xy=(xs[-1], ys[-1]),
                         xytext=(-6, 8), textcoords='offset points',
                         color=C_CONTADOR, fontweight='bold', ha='right')
    ax2.set_ylabel('paquetes descartados\n(IDS_BLACKLIST_DROP_FORWARD)',
                   color=C_CONTADOR, fontsize=9)
    ax2.tick_params(axis='y', colors=C_CONTADOR, labelsize=8)
    ax2.set_ylim(0, ylim_contador or 1)
    ax2.spines['top'].set_visible(False)

    ax.set_xlim(t0, t1 if t1 > t0 else t0 + 1.0)

    ax.set_ylim(0, 1.42)
    ax.set_yticks([0.62, 1.0])
    ax.set_yticklabels(['control', ' victima'], fontsize=8, color='#555')
    ax.set_xlabel('segundos desde el inicio de la demostracion')
    ax.set_title(titulo, fontsize=11, fontweight='bold', pad=10)
    ax.grid(axis='x', alpha=0.25, ls=':')
    ax.spines['top'].set_visible(False)

    # Leyenda propia: sin duplicar entradas por OK/TIMEOUT.
    ax.legend(handles=[
        Patch(facecolor=C_LIBRE, label='atacante->victima  OK'),
        Patch(facecolor=C_BLOQ, label='atacante->victima  TIMEOUT'),
        Patch(facecolor=C_CONTROL, label='victima->ROUTER  OK (control)'),
        Patch(facecolor=C_BLOQ, alpha=0.13, label='bloqueo activo'),
        Patch(facecolor=C_CONTADOR, label='descartes contados por el router'),
    ], loc='upper right', fontsize=7.5, framealpha=0.92, ncol=2)


def _ylim_contador(contador):
    """Altura fija del eje derecho a partir de TODAS las muestras."""
    return max([v for _, v in contador], default=1) * 1.25 + 1


def figura_png(paq_v, paq_c, contador, marcas):
    t0, t1 = _rango_comun([paq_v, paq_c, contador])
    fig, ax = plt.subplots(figsize=(12, 5.4), dpi=150)
    _panel(ax, t0, t1, paq_v, paq_c, contador, marcas,
           'Bloqueo IDS/IPS en accion: el atacante pierde el camino a la victima\n'
           'mientras la red sigue viva y el router cuenta cada descarte',
           ylim_contador=_ylim_contador(contador))

    # Anotaciones de los hitos, con la posicion calculada para no solaparse.
    hitos = [('deteccion', 'deteccion SQLi\n+ bloqueo', C_BLOQ, 1.34, 14),
             ('desbloqueo', 'desbloqueo', C_CONTROL, 1.34, -64)]

    for clave, texto, color, y, dx in hitos:
        t = marcas.get(clave)
        if t is None:
            continue
        ax.annotate(texto, xy=(t, y), xytext=(dx, 0),
                    textcoords='offset points', color=color, fontsize=8.5,
                    fontweight='bold', va='top',
                    arrowprops=dict(arrowstyle='->', color=color, lw=1.2))
    if not any(t is not None for t in (marcas.get('deteccion'),
                                       marcas.get('desbloqueo'))):
        ax.text(0.5, 0.5, 'el CSV no tiene marcas de deteccion/desbloqueo',
                transform=ax.transAxes, ha='center', color=C_BLOQ)

    fig.text(0.99, 0.015,
             'UNIPAZ - IDS/IPS | trafico real de ping | deteccion inyectada por '
             'la ruta de produccion NetFlow',
             ha='right', fontsize=7, color='#777')
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(RUTA_PNG)
    plt.close(fig)
    print(f'[OK] figura: {RUTA_PNG}')


def animacion_gif(paq_v, paq_c, contador, marcas, fps=12):
    """Redibuja el eje de tiempo creciendo hasta el final: el corte se 've' caer."""
    t0, t1 = _rango_comun([paq_v, paq_c, contador])
    ylim = _ylim_contador(contador)
    duracion = max(1.0, t1 - t0)
    n = max(2, int(duracion * fps))       # ~1 fotograma por decima de segundo

    fig, ax = plt.subplots(figsize=(10, 4.6), dpi=100)
    def dibujar(i):
        ahora = t0 + duracion * (i / (n - 1))
        _panel(ax, t0, ahora, paq_v, paq_c, contador, marcas,
               f'Demo del bloqueo IDS/IPS   t = {ahora:04.1f} s',
               ylim_contador=ylim)
        return []


    anim = FuncAnimation(fig, dibujar, frames=n, interval=1000 / fps, blit=False)
    # PillowWriter: no hay ffmpeg en esta maquina, pero para GIF no hace falta.
    anim.save(RUTA_GIF, writer=PillowWriter(fps=fps))
    plt.close(fig)
    print(f'[OK] gif: {RUTA_GIF}  ({n} fotogramas, {os.path.getsize(RUTA_GIF) // 1024} KB)')


def main():
    ap = argparse.ArgumentParser(description='Figura + GIF de la demo del bloqueo.')
    ap.add_argument('--csv', default=RUTA_CSV)
    ap.add_argument('--solo-png', action='store_true',
                    help='omitir el GIF (tarda bastante mas)')
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        raise SystemExit(f'[X] No existe {args.csv}\n'
                         f'    Ejecuta antes: python _lab/demo_bloqueo.py')

    paq_v, paq_c, contador, marcas = cargar(args.csv)
    print(f'[CSV] {len(paq_v)} paquetes a la victima, {len(paq_c)} de control, '
          f'{len(contador)} muestras del contador')
    if not paq_v:
        raise SystemExit('[X] el CSV no tiene paquetes: revisa la corrida anterior')

    figura_png(paq_v, paq_c, contador, marcas)
    if not args.solo_png:
        animacion_gif(paq_v, paq_c, contador, marcas)
    return 0


if __name__ == '__main__':
    sys.exit(main())
