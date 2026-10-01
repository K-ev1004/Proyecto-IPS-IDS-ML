# -*- coding: utf-8 -*-
# =============================================================================
# nodos_lab.py - Perfil de los nodos RouterOS CHR del laboratorio IDS/IPS.
# Universidad UNIPAZ - Proyecto IDS/IPS (Fase III).
# -----------------------------------------------------------------------------
# atacante y victima son CLONES del CHR del router, por lo que comparten su
# usuario SSH. Este modulo centraliza:
#   - la carga del perfil (_lab/nodos.json, con fallback al perfil MikroTik),
#   - el ping entre nodos via RouterOS, parseando la salida real del equipo.
#
# POR QUE HACE FALTA EL PARSER: en RouterOS, '/ping <ip> count=3' devuelve
# codigo de salida 0 aunque no llegue NINGUN paquete. Un wrapper que solo mire
# rc daria por bueno un ping totalmente bloqueado (gate post_ping_denegado
# pasaria con el ataque y sin el). La unica senal fiable es la linea de resumen
#     sent=3 received=0 packet-loss=100%
# =============================================================================
import os
import re
import sys
import json

_LAB = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_LAB)
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

RUTA_NODOS = os.path.join(_LAB, 'nodos.json')
RUTA_PERFIL_CHR = os.path.join(_PROJ, 'config', 'mikrotik_lab.json')

# valores por defecto de la topologia (ver provision_chr.ps1)
DEFECTOS = {
    'atacante': {'vm': 'CHR-ATACANTE-LAB', 'host': '10.10.0.3', 'user': 'ids', 'port': 22},
    'victima':  {'vm': 'CHR-VICTIMA-LAB',  'host': '10.10.1.3', 'user': 'ids', 'port': 22},
}

RE_PING_RUTEROS = re.compile(r'sent=(\d+)\s+received=(\d+)', re.I)

# '/system resource print' NO contiene la palabra 'RouterOS' cuando el canal SSH
# no es interactivo; trae:
#   version: 7.23.7 (long-term)   /   board-name: CHR innotek GmbH VirtualBox
# Buscar 'RouterOS' ahi hace fallar el gate chr_ssh de T5 y el chequeo de vida de
# verificar_lab.py aunque el equipo este perfecto.
RE_VERSION = re.compile(r'version:\s*\S+|board-name:\s*\S+', re.I)


def version_routeros(texto):
    """True si la salida de '/system resource print' corresponde a RouterOS."""
    return bool(RE_VERSION.search(texto or ''))


def _leer_json(ruta):
    if not os.path.exists(ruta):
        return {}
    try:
        with open(ruta, encoding='utf-8-sig') as f:
            return json.load(f)
    except (ValueError, OSError):
        return {}


def cargar_nodos():
    """Devuelve {'atacante': {...}, 'victima': {...}} con host/user/pass/port.

    La clave se resuelve, en este orden:
      1. variable de entorno (LAB_ATACANTE_PASS, LAB_VICTIMA_IP, ...)
      2. clave propia en _lab/nodos.json
      3. clave del perfil MikroTik (config/mikrotik_lab.json), porque los tres
         CHR son el mismo equipo clonado
      4. valores por defecto de la topologia
    """
    nodos = _leer_json(RUTA_NODOS)
    perfil = _leer_json(RUTA_PERFIL_CHR)

    salida = {}
    for rol, base in DEFECTOS.items():
        cfg = dict(base)
        cfg.update({k: v for k, v in nodos.get(rol, {}).items() if v not in (None, '')})

        cfg['host'] = os.environ.get(f'LAB_{rol.upper()}_IP', cfg['host'])
        cfg['user'] = os.environ.get(f'LAB_{rol.upper()}_USER', cfg['user'])
        cfg['port'] = int(os.environ.get(f'LAB_{rol.upper()}_PUERTO', cfg['port']))
        cfg['pass'] = (os.environ.get(f'LAB_{rol.upper()}_PASS')
                       or cfg.get('pass')
                       or perfil.get('pass', '')
                       or '')
        salida[rol] = cfg
    return salida


def _ssh_run(host, user, pwd, cmd, port=22, timeout=15):
    try:
        import paramiko
    except ImportError:
        sys.exit("[X] Falta 'paramiko'. Instale:  pip install paramiko")
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(host, port=port, username=user, password=pwd, timeout=timeout)
        _, out, err = cli.exec_command(cmd, timeout=timeout)
        # Leer antes de recv_exit_status: al reves, un stdout grande llena el
        # buffer del canal y exec_command se queda esperando el codigo de salida.
        salida = out.read().decode(errors='replace') or ''
        error = err.read().decode(errors='replace') or ''
        rc = out.channel.recv_exit_status()
        return rc, salida.strip(), error.strip()
    finally:
        cli.close()


def ping_nodo(cred, destino, count=3, timeout=20):
    """Ping RouterOS desde `cred` hacia `destino`.

    Devuelve un dict con:
      ok       -> True si llego al menos 1 paquete (no mira el codigo de salida)
      recibidos/enviados -> conteos reales extraidos del resumen de RouterOS
      parseado -> False si la salida no tiene 'sent=.. received=..' (fallo de
                  diagnostico: el que llama debe fallar, no asumir exito)
      rc, salida -> salida cruda, util como evidencia
    """
    cmd = f'/ping {destino} count={count}'
    rc, salida, error = _ssh_run(cred['host'], cred['user'], cred['pass'], cmd,
                                 port=cred['port'], timeout=timeout)
    texto = salida or error
    # RouterOS ENVUELVE la salida cuando la tabla no cabe en el ancho del canal y
    # entonces imprime VARIOS bloques con su propio 'sent=.. received=..'. El
    # veredicto es el ULTIMO resumen, no el primero: con count>10 el primer
    # resumen dice 'received=10' y el paquete 11 ya no se contaria.
    resumenes = RE_PING_RUTEROS.findall(texto)
    if not resumenes:
        return {'ok': False, 'parseado': False, 'enviados': 0, 'recibidos': 0,
                'rc': rc, 'salida': texto}
    enviados, recibidos = (int(v) for v in resumenes[-1])
    return {'ok': recibidos > 0, 'parseado': True, 'enviados': enviados,
            'recibidos': recibidos, 'rc': rc, 'salida': texto}


def resumir_ping(p):
    """Texto compacto para el campo 'detalle' de los gates."""
    if not p['parseado']:
        return f"ping sin resumen 'sent/received' (rc={p['rc']}): {p['salida'][:80]}"
    return (f"recibidos={p['recibidos']}/{p['enviados']} "
            f"(rc={p['rc']}, {p['recibidos'] > 0})")
