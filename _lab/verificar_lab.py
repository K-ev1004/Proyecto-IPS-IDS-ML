# -*- coding: utf-8 -*-
# =============================================================================
# verificar_lab.py - Comprobacion de la topologia del laboratorio IDS/IPS.
# Universidad UNIPAZ - Proyecto IDS/IPS (Fase III).
# -----------------------------------------------------------------------------
# Verifica, por SSH, que los 3 nodos CHR estan levantados y que el camino
# atacante -> router -> victima responde. Lo ejecuta provision_chr.ps1 al final
# de -Configurar, y sirve como diagnostico cuando algo no responde.
#
#   python verificar_lab.py
#   python verificar_lab.py --detalle     # imprime /interface print y rutas
#
# Codigo de salida: 0 = todo correcto, 1 = alguna comprobacion fallo.
# =============================================================================
import os
import re
import sys
import json

_LAB = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_LAB)
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

from nodos_lab import (  # noqa: E402
    _leer_json, _ssh_run, ping_nodo, cargar_nodos, version_routeros)

DETALLE = '--detalle' in sys.argv

# El router no esta en nodos.json: es el CHR principal, perfil config/mikrotik_lab.json
_perfil = _leer_json(os.path.join(_PROJ, 'config', 'mikrotik_lab.json'))
ROUTER = {
    'vm': 'CHR-IDS-LAB',
    'host': os.environ.get('MIKROTIK_IP', _perfil.get('ip', '10.10.0.2')),
    'user': _perfil.get('user', 'ids'),
    'pass': _perfil.get('pass', ''),
    'port': int(_perfil.get('port', 22)),
}

CHECKS = []


def check(nombre, ok, detalle):
    CHECKS.append((nombre, bool(ok), detalle))
    print(f"  {'OK  ' if ok else 'FALLA'} {nombre}: {detalle}")
    return bool(ok)


def cr(cred, cmd, timeout=15):
    return _ssh_run(cred['host'], cred['user'], cred['pass'], cmd,
                    port=cred['port'], timeout=timeout)


def main():
    nodos = cargar_nodos()
    atacante, victima = nodos['atacante'], nodos['victima']

    print("== 1) Alcanzabilidad SSH de los 3 nodos ==")
    versiones = {}
    for rol, cred in (('router', ROUTER), ('atacante', atacante), ('victima', victima)):
        if not cred['pass']:
            check(f'ssh_{rol}', False,
                  f"sin clave: defina la clave en config/mikrotik_lab.json, "
                  f"_lab/nodos.json o LAB_{rol.upper()}_PASS")
            continue
        try:
            rc, out, err = cr(cred, '/system resource print')
        except Exception as exc:                       # noqa: BLE001
            check(f'ssh_{rol}', False, f"{cred['host']}:22 inaccesible ({exc})")
            continue
        texto = out or err
        versiones[rol] = texto
        check(f'ssh_{rol}', rc == 0 and version_routeros(texto),
              f"{cred['host']}:22 " +
              (texto.splitlines()[0][:60] if texto else '(sin salida)'))
        if DETALLE and texto:
            for linea in texto.splitlines():
                print(f"        | {linea}")

    if not all(ok for _, ok, _ in CHECKS):
        print("\n[X] Hay nodos inaccesibles: se detiene aqui. Compruebe que las 3 VMs "
              "estan encendidas (VBoxManage list runningvms).")
        return 1

    print("\n== 2) Direcciones IP e interfaces ==")
    esperado = {
        'router': ('10.10.0.2', '10.10.1.2'),
        'atacante': ('10.10.0.3',),
        'victima': ('10.10.1.3',),
    }
    for rol, cred in (('router', ROUTER), ('atacante', atacante), ('victima', victima)):
        # 'print' a secas devuelve una TABLA ('0 10.10.0.2/24  10.10.0.0  ether1'),
        # no pares clave=valor, y el parseo de abajo busca 'address='. Con SSH no
        # interactivo RouterOS parte las tablas largas segun el ancho del canal, de
        # ahi que 'terse', que emite una linea autocontenida por direccion.
        rc, out, err = cr(cred, '/ip address print terse')
        texto = out or err
        direcciones = re.findall(r'address=([0-9.]+/\d+)', texto)
        if DETALLE:
            print(f"    $ /ip address print terse  [{rol}]")
            for linea in (texto or '').splitlines():
                print(f"        | {linea}")
        # 'esperado' son IPs peladas ('10.10.0.2') y RouterOS devuelve CIDR
        # ('10.10.0.2/24'): comparar los dos crudos daba siempre FALTAN.
        # Se normaliza a la parte de direccion para no depender de la mascara.
        encontradas = [d.split('/')[0] for d in direcciones]
        faltan = [ip for ip in esperado[rol] if ip not in encontradas]
        extra = [ip for ip in encontradas if ip not in esperado[rol]]
        check(f'ip_{rol}', not faltan and not extra,
              f"esperadas={list(esperado[rol])} obtenidas={direcciones or '(ninguna)'}"
              + (f" FALTAN {faltan}" if faltan else "")
              + (f" SOBRAN {extra}" if extra else ""))

    # La victima conserva la NIC de gestion (nic1 en wan) porque se booted por ahi;
    # debe quedar deshabilitada para que no sea un camino alterno al laboratorio.
    # RouterOS 7.23.7 no permite leer ese estado con '/interface get ether1 disabled'
    # (devuelve vacio siempre): el unico indicador es el flag 'X' de 'print'.
    rc, filas, err = cr(victima, '/interface print terse')
    estado = None
    patron = re.compile(r'\s*\d+\s+([A-Z]*)\s+name=ether1\b')
    for linea in (filas or err or '').splitlines():
        m = patron.match(linea)
        if m:
            estado = 'X' in m.group(1)
            break
    check('victima_ether1_deshabilitada', estado is True,
          f"flag 'X' en /interface print -> {estado} "
          f"(esperado True; ether1 queda en wan solo como via de bootstrap)")

    print("\n== 3) Reglas de bloqueo del router ==")
    rc, out, err = cr(ROUTER, '/ip firewall filter print terse')
    filtros = out or err
    if DETALLE:
        for linea in filtros.splitlines():
            print(f"        | {linea}")
    for regla in ('IDS_BLACKLIST_DROP_FORWARD', 'IDS_BLACKLIST_DROP_INPUT'):
        check(regla, regla in filtros, "presente" if regla in filtros else "AUSENTE")

    print("\n== 4) Camino atacante -> router -> victima ==")
    p_ata = ping_nodo(atacante, victima['host'])
    check('ping_atacante_a_victima', p_ata['ok'] and p_ata['parseado'],
          f"recibidos={p_ata['recibidos']}/{p_ata['enviados']} "
          f"(parseado={p_ata['parseado']})")
    if DETALLE:
        for linea in (p_ata['salida'] or '').splitlines():
            print(f"        | {linea}")

    p_wan = ping_nodo(atacante, ROUTER['host'])
    check('ping_atacante_a_router_wan', p_wan['ok'] and p_wan['parseado'],
          f"recibidos={p_wan['recibidos']}/{p_wan['enviados']}")

    p_lan = ping_nodo(victima, ROUTER['host'])
    check('ping_victima_a_router', p_lan['ok'] and p_lan['parseado'],
          f"recibidos={p_lan['recibidos']}/{p_lan['enviados']}")

    # El atacante solo tiene una NIC: no debe tener ninguna ruta a la LAN, de modo
    # que todo su trafico al segmento de la victima pase por el router (y por su
    # regla de drop). Es la premisa del experimento.
    rc_iso, out_iso, err_iso = cr(atacante, '/ip route print')
    rutas_lan = re.findall(r'dst-address=10\.10\.1\.\d+/\d+', out_iso or err_iso or '')
    check('atacante_sin_ruta_lan', not rutas_lan,
          "sin ruta a 10.10.1.0/24 (una unica NIC en wan)"
          if not rutas_lan else f"RUTAS A LA LAN: {rutas_lan}")
    if DETALLE:
        for linea in (out_iso or err_iso or '').splitlines():
            print(f"        | {linea}")

    fallos = [n for n, ok, _ in CHECKS if not ok]
    print("\n== RESUMEN ==")
    print(f"  {len(CHECKS) - len(fallos)}/{len(CHECKS)} comprobaciones OK")
    if fallos:
        print("\n[X] FALLAN: " + ', '.join(fallos))
        return 1
    print("\n[OK] Topologia verificada. Puede ejecutar la prueba T5:\n"
          "       setx MIKROTIK_PROFILE lab\n"
          "       setx IDS_IPS_AUTONOMO 1\n"
          "       python t5_routeros_ips.py")
    return 0


if __name__ == '__main__':
    sys.exit(main())
