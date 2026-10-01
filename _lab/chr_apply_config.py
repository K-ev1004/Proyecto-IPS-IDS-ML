# =============================================================================
# chr_apply_config.py - Laboratorio IDS/IPS (UNIPAZ)
# -----------------------------------------------------------------------------
# Aplica por SSH la configuracion de CUALQUIER nodo RouterOS CHR del lab.
#
#   router    CHR-IDS-LAB        enruta entre wan y lan + reglas de drop
#   atacante  CHR-ATACANTE-LAB   origen del trafico que atraviesa el router
#   victima   CHR-VICTIMA-LAB    destino del trafico
#
# Los tres nodos clonan la MISMA gold image (un CHR ya configurado), asi que
# arrancan con la config del router: 10.10.0.2 en ether1 y 10.10.1.2 en ether2.
# Reasignar eso sin cortar la sesion SSH que lo hace exige dos fases:
#
#   Fase A  se entra por la IP de bootstrap y se anade la IP final + ruta por
#           defecto + identidad; se limpian las direcciones que NO sostienen la
#           sesion actual y se apaga el cliente DHCP (la red del lab es estatica).
#   Fase B  se entra por la IP final y se retira la IP de bootstrap (y se
#           deshabilita la interfaz que ya no debe usarse).
#
# La interfaz destino NO SE HARDCODEA: se detecta en runtime buscando la que ya
# tiene una direccion de la subred objetivo, porque el nombre que RouterOS asigna
# (ether1/ether2/...) depende de cuantas NICs tenga la VM.
#
# MACS - por que los clones comparten las del router. RouterOS identifica las
# interfaces 'ether' por MAC, no por posicion: un clon cuyas NICs tengan MACs
# desconocidas NO reconoce ether1/ether2, sus direcciones heredadas quedan en
# interfaces que el host no ve y el nodo es inalcanzable (no hay consola que lo
# arregle). Por eso provision_chr.ps1 da a los clones las MISMAS MACs que el router
# y el bootstrap por SSH es posible.
# El duplicado no se puede corregir despues: RouterOS 7 rechaza
# '/interface set <iface> mac-address=...' con 'bad parameter' porque la MAC la
# impone el hardware, y la unica ventana para fijarla es antes del primer
# arranque, que es justo cuando el clon aun no tiene ether1/ether2. Que el
# duplicado no rompa la conmutacion se MIDIO, no se supudio: con las tres VMs
# encendidas, 30 pings host -> atacante y 30 atacante -> router dieron 0% perdida.
#
# Uso (maquina objetivo):
#   python chr_apply_config.py                  # router (comportamiento previo)
#   python chr_apply_config.py --nodo atacante
#   python chr_apply_config.py --nodo victima
#   python chr_apply_config.py --nodo atacante --ip 10.10.0.2   # forzar entrada
#   python chr_apply_config.py --listar
# =============================================================================
import argparse
import os
import re
import socket
import sys
import time

_LAB = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_LAB)
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

import mikrotik_api  # noqa: E402  (lee config/mikrotik_lab.json o env MIKROTIK_*)

try:
    import paramiko
except ImportError:
    sys.exit("[X] Falta 'paramiko'. Instale:  pip install paramiko")

_MAS = '/24'
WAN_IP = os.environ.get('CHR_WAN_IP', '10.10.0.2')
LAN_IP = os.environ.get('CHR_LAB_IP', os.environ.get('CHR_LAN_IP', '10.10.1.2'))

NODOS = {
    'router': {
        'vm': 'CHR-IDS-LAB',
        'identity': 'CHR-IDS-LAB',
        # El router ya esta verificado con ether1=wan / ether2=lan, y es la
        # MAC origen de la gold image, asi que sus MACs no se tocan.
        'iface': None,
        'detectar_prefijo': None,
        'ip': f'{WAN_IP}{_MAS}',
        'gw': None,
        'firewall': True,
        'deshabilitar_b': [],
        'limpiar_a': [],
        'limpiar_b': [],
        # El router es la MAC origen de la gold image; sus NICs no se tocan.
        'macs': {'ether1': '08:00:27:49:7F:9C', 'ether2': '08:00:27:D2:A1:09'},
        'ip_admin': WAN_IP,
        'ip_bootstrap': WAN_IP,
    },
    'atacante': {
        'vm': 'CHR-ATACANTE-LAB',
        'identity': 'CHR-ATACANTE-LAB',
        # Solo tiene una NIC real (nic1 -> wan); nic2 queda en 'none', asi que
        # no existe ether2 y el atacante no puede saltarse el router.
        'iface': 'ether1',
        'detectar_prefijo': '10.10.0.',
        'ip': '10.10.0.3/24',
        'gw': WAN_IP,
        'firewall': False,
        'deshabilitar_b': [],
        'limpiar_a': [f'/ip address remove [find address="{LAN_IP}{_MAS}"]'],
        'limpiar_b': [f'/ip address remove [find address="{WAN_IP}{_MAS}"]'],
        # MACs REALES (compartidas con el router a proposito): son las de la gold
        # image y RouterOS 7 no permite cambiarlas despues del primer arranque.
        'macs': {'ether1': '08:00:27:49:7F:9C'},
        'ip_admin': '10.10.0.3',
        'ip_bootstrap': WAN_IP,
    },
    'victima': {
        'vm': 'CHR-VICTIMA-LAB',
        'identity': 'CHR-VICTIMA-LAB',
        # ether1 (wan) queda solo como via de bootstrap y se deshabilita al
        # final; la IP del lab vive en ether2 (lan).
        'iface': 'ether2',
        'detectar_prefijo': '10.10.1.',
        'ip': '10.10.1.3/24',
        'gw': LAN_IP,
        'firewall': False,
        'deshabilitar_b': ['ether1'],
        'limpiar_a': [f'/ip address remove [find address="{LAN_IP}{_MAS}"]'],
        'limpiar_b': [f'/ip address remove [find address="{WAN_IP}{_MAS}"]'],
        # MACs REALES (compartidas con el router a proposito): ver la cabecera.
        'macs': {'ether1': '08:00:27:49:7F:9C', 'ether2': '08:00:27:D2:A1:09'},
        'ip_admin': '10.10.1.3',
        # El clon entra por la WAN porque el host esta en 10.10.0.1; de ahi
        # conserva 10.10.0.2 y 10.10.1.2, y solo se retira la primera.
        'ip_bootstrap': WAN_IP,
    },
}

# El cliente DHCP del clon queda 'bound' a la gold image y pediria una direccion
# del rango 10.10.0.100-200 del servidor DHCP de VirtualBox: es la MISMA que ya
# usa el router, y dos nodos peleandose por ella rompen el ping del laboratorio.
# La red del lab es 100 % estatica, asi que el cliente se apaga y su direccion
# dinamica se retira (las dinamicas se marcan con 'D' en 'print').
DESHABILITAR_DHCP = ['/ip dhcp-client disable [find]',
                     '/ip address remove [find dynamic]']

COMANDOS_FIREWALL = [
    '/system identity set name=CHR-IDS-LAB',
    '/ip firewall address-list remove [find list="IDS_BLACKLIST"]',
    '/ip firewall filter remove [find comment="IDS_BLACKLIST_DROP_FORWARD"]',
    '/ip firewall filter remove [find comment="IDS_BLACKLIST_DROP_INPUT"]',
    '/ip firewall filter add chain=forward action=drop src-address-list="IDS_BLACKLIST" '
    'comment="IDS_BLACKLIST_DROP_FORWARD" place-before=0',
    '/ip firewall filter add chain=input action=drop src-address-list="IDS_BLACKLIST" '
    'comment="IDS_BLACKLIST_DROP_INPUT" place-before=0',
]

# Errores que equivalen a "ya estaba aplicado": el script es idempotente.
_YA_ESTA = ('already have such address', 'already have such route',
            'already have such item', 'no such item', 'nothing to remove')

# '/ip address print terse' emite UNA LINEA por direccion y la iface NO va pegada
# al '/24' (interviene 'network='):
#   0 address=10.10.0.3/24 network=10.10.0.0 interface=ether1 actual-interface=...
# Un patron que exija 'address=IP/LONG\spatterns+interface=' no encuentra NADA y
# hacia fallar los gates de IP de todos los nodos.
RE_DIRECCION = re.compile(r'address=([0-9.]+)/(\d+)[^\n]*?interface=(\S+)')
# '/system resource print' no contiene la palabra 'RouterOS' en modo no interactivo.
RE_VERSION = re.compile(r'version:\s*\S+|board-name:\s*\S+', re.I)


def ejecutar(host, user, pwd, port, cmd, timeout=10.0):
    """Ejecuta un comando y devuelve (rc, salida, error).

    RouterOS escribe sus errores en el STDOUT del canal SSH (no en stderr) y
    devuelve rc != 0, asi que hay que mirar ambos flujos + el codigo de salida.
    Leer antes de recv_exit_status: al reves un stdout grande llena el buffer y
    exec_command se queda esperando el codigo de salida.
    """
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, port=port, username=user, password=pwd, timeout=timeout)
    _, out, err = cli.exec_command(cmd, timeout=timeout)
    salida = out.read().decode(errors='replace') or ''
    error = err.read().decode(errors='replace') or ''
    rc = out.channel.recv_exit_status()
    cli.close()
    return rc, salida.replace('\r\n', '\n').strip(), error.replace('\r\n', '\n').strip()


def _aplanar(texto):
    """RouterOS en SSH no interactivo envuelve las tablas en varias lineas
    ('name: C' / 'H' / 'R' ...), lo que rompe cualquier busqueda por substring.
    """
    return ''.join((texto or '').split())


def listar_direcciones(host, user, pwd, port):
    """Devuelve [(ip, iface), ...] del nodo."""
    _, salida, _ = ejecutar(host, user, pwd, port, '/ip address print terse')
    return [(m.group(1), m.group(3)) for m in RE_DIRECCION.finditer(salida or '')]


def puerto_abierto(host, puerto=22, espera=1.5):
    """Comprueba que el puerto SSH responde sin depender de paramiko."""
    try:
        with socket.create_connection((host, puerto), timeout=espera):
            return True
    except OSError:
        return False


def _esperar_puerto(host, puerto=22, intentos=30, espera=4):
    """Espera a que el puerto abra (RouterOS tarda ~15-25 s en arrancar)."""
    for _ in range(intentos):
        if puerto_abierto(host, puerto):
            return True
        time.sleep(espera)
    return False


def _ejecutar_lote(host, user, pwd, port, cmds, verbose=True):
    """Ejecuta una lista de comandos tolerando 'ya aplicado'. Devuelve fallos."""
    fallos = []
    for cmd in cmds:
        rc, salida, error = ejecutar(host, user, pwd, port, cmd)
        detalle = (salida or error).strip()

        # RouterOS 7 rechaza 'place-before=0' cuando la cadena aun no tiene
        # reglas ("no such item"): en ese caso la regla se agrega al final, que
        # para una cadena vacia equivale a ir primera.
        if rc != 0 and 'place-before=0' in cmd:
            cmd_retry = cmd.replace(' place-before=0', '')
            rc2, salida2, error2 = ejecutar(host, user, pwd, port, cmd_retry)
            if rc2 == 0:
                if verbose:
                    print(f"    [OK] {cmd_retry[:74]}  (cadena vacia: sin place-before)")
                continue
            rc, salida, error = rc2, salida2, error2
            detalle = (salida or error).strip()

        if rc == 0:
            if verbose:
                print(f"    [OK] {cmd[:74]}")
        elif any(m in detalle.lower() for m in _YA_ESTA):
            if verbose:
                print(f"    [OK] {cmd[:74]}  (ya aplicada)")
        else:
            if verbose:
                print(f"    [FALLO] {cmd[:74]}\n        -> {detalle[:150]}")
            fallos.append(cmd)
    return fallos


def _esperar_ssh(host, user, pwd, port, intentos=24, espera=5):
    """Espera a que el nodo acepte SSH. RouterOS tarda ~10-20 s en arrancar."""
    for i in range(1, intentos + 1):
        if puerto_abierto(host, port):
            try:
                rc, salida, _ = ejecutar(host, user, pwd, port,
                                         '/system resource print', timeout=8.0)
                if rc == 0:
                    return True, i
            except Exception:
                pass
        time.sleep(espera)
    return False, intentos


def _detectar_iface(host, user, pwd, port, cfg):
    """Devuelve la interfaz que ya tiene una direccion de la subred objetivo."""
    prefijo = cfg['detectar_prefijo']
    if not prefijo:
        return None
    actual = listar_direcciones(host, user, pwd, port)
    for ip, iface in actual:
        if ip.startswith(prefijo):
            print(f"[*] Interfaz de la subred {prefijo}0/24 detectada: {iface} (tiene {ip})")
            return iface
    print(f"[!] Ninguna interfaz tiene una IP de {prefijo}0/24. Se usara "
          f"{cfg['iface']} (lo define el registro del nodo).")
    for ip, iface in actual:
        print(f"      direccion actual: {ip} en {iface}")
    return cfg['iface']


def _fase_a(cfg, iface, host, user, pwd, port):
    """Sesion de bootstrap: deja el nodo alcanzable en su IP final."""
    # Primero se abre el enlace y se apaga el DHCP (no sostiene la sesion: la IP
    # de bootstrap es estatica), y despues se limpian direcciones, identidad, IP
    # y ruta. El orden importa: anadir la IP final antes de limpiar evita quedar
    # sin ninguna direccion valida si un comando intermedio falla.
    cmds = ['/interface set ether1 disabled=no', '/interface set ether2 disabled=no']
    cmds += DESHABILITAR_DHCP
    if cfg['firewall']:
        cmds += [f'/ip address add address={WAN_IP}{_MAS} interface=ether1',
                 f'/ip address add address={LAN_IP}{_MAS} interface=ether2']
        cmds += COMANDOS_FIREWALL
    else:
        cmds += [f"/system identity set name={cfg['identity']}",
                 f'/ip address add address={cfg["ip"]} interface={iface}']
        if cfg['gw']:
            cmds += ['/ip route remove [find dst-address="0.0.0.0/0"]',
                 f'/ip route add dst-address=0.0.0.0/0 gateway={cfg["gw"]}']
    cmds += list(cfg['limpiar_a'])
    donde = f"{iface}" if iface else "ether1/ether2 (router)"
    print(f"[*] Fase A sobre {host}: sin DHCP, identidad {cfg['identity']}, "
          f"IP {cfg['ip']} en {donde}, ruta por defecto")
    return _ejecutar_lote(host, user, pwd, port, cmds)


def _fase_b(cfg, host, user, pwd, port):
    """Retira la IP de bootstrap y deshabilita las interfaces que ya no se usan."""
    cmds = list(cfg['limpiar_b']) + [f'/interface set {i} disabled=yes'
                                     for i in cfg['deshabilitar_b']]
    if not cmds:
        return []
    extra = f" y deshabilita {', '.join(cfg['deshabilitar_b'])}" if cfg['deshabilitar_b'] else ''
    print(f"[*] Fase B sobre {host}: retira la IP de bootstrap{extra}")
    return _ejecutar_lote(host, user, pwd, port, cmds)


def _fase_mac(cfg, host, user, pwd, port):
    """Comprueba las MACs reales del nodo contra las de la gold image. NO intenta
    cambiarlas.

    RouterOS 7 no permite escribirlas por CLI: '/interface set <iface>
    mac-address=...' responde 'bad parameter' porque la MAC de una interfaz
    'ether' la impone el hardware. Solo se fija desde VirtualBox antes del primer
    arranque, y ese es justo el momento en que el clon todavia no tiene las
    interfaces 'ether1/ether2' que le impone la configuracion heredada del router:
    si naciera con MACs distintas, la IP 10.10.0.2 heredada quedaria en una
    interfaz que el host no ve.

    Que unas MACs duplicadas no contaminen la conmutacion se midio, no se suppio:
    30 pings host -> atacante y 30 atacante -> router con las tres VMs encendidas
    dieron 0% de perdida. Asi que el duplicado es una decision consciente. Si
    aun asi el hardware cambiara, el desajuste se ve aqui como MAC distinta, sin
    dejar el nodo marcado como roto.
    """
    _, plano, _ = ejecutar(host, user, pwd, port, '/interface print terse')
    reales = {}
    # Se parsean las lineas CRUDAS, no '_aplanar()': esa funcion borra los espacios
    # ('name=ether1default-name=ether1'), y sin el espacio el \b despues de 'ether1'
    # ya no casa y la interfaz parecia no existir.
    patron = re.compile(r'\bname=(ether\d)\b.*?\bmac-address=([0-9A-Fa-f:]+)')
    for linea in (plano or '').splitlines():
        m = patron.search(linea)
        if m:
            reales[m.group(1)] = m.group(2)
    print("[*] MACs: no son escribibles por CLI en RouterOS 7; el clon conserva a "
          "proposito las de la gold image para que su configuracion heredada sea "
          "alcanzable durante el bootstrap (0% de perdida medida con 60 pings).")
    fallos = []
    for iface, esperado_mac in cfg['macs'].items():
        real = reales.get(iface)
        if real is None:
            print(f"      - {iface}: no aparece en /interface print (esperada {esperado_mac})")
            fallos.append(f'mac_{iface}_ausente')
        elif real.upper() != esperado_mac.upper():
            print(f"      - {iface}: real={real} esperada={esperado_mac} "
                  f"(distinta de la gold image)")
            fallos.append(f'mac_{iface}_distinta')
        else:
            print(f"      - {iface}: {real} (gold image) OK")
    return fallos


def _verificar_router(host, user, pwd, port):
    fallos = []
    _, salida, _ = ejecutar(host, user, pwd, port, '/ip address print terse')
    print(f"\n    $ /ip address print terse\n    {salida or '(vacio)'}")
    if not (WAN_IP in salida and LAN_IP in salida):
        fallos.append('direcciones')

    _, salida, _ = ejecutar(host, user, pwd, port, '/system identity print')
    identidad = _aplanar(salida)
    print(f"\n    $ /system identity print\n    {identidad or '(vacio)'}")
    if 'CHR-IDS-LAB' not in identidad:
        fallos.append('identity')

    _, terse, _ = ejecutar(host, user, pwd, port, '/ip firewall filter print terse')
    print(f"\n    $ /ip firewall filter print terse\n    {terse or '(vacio)'}")
    ok_drop = ('IDS_BLACKLIST_DROP_FORWARD' in terse and 'IDS_BLACKLIST_DROP_INPUT' in terse)
    if not ok_drop:
        fallos.append('reglas_drop')
    print(f"\n[{'OK' if ok_drop else 'X'}] Reglas de drop IDS_BLACKLIST presentes: {ok_drop}")
    return fallos


def _flag_deshabilitada(texto, iface):
    """Devuelve True/False si la interfaz aparece deshabilitada, o None si no sale.

    RouterOS 7.23.7 NO permite leer el estado por '/interface get <iface> disabled':
    devuelve cadena vacia tanto si esta habilitada como deshabilitada (probado en
    las dos). El unico indicador fiable es el flag 'X' que '/interface print'
    antepone a la fila ('0 X ether1 ...'). Ojo: 'default-name=ether1' tambien
    contiene 'name=ether1', asi que la fila se ancla al principio de la linea.
    """
    patron = re.compile(r'\s*\d+\s+([A-Z]*)\s+name=' + re.escape(iface) + r'\b')
    for linea in (texto or '').splitlines():
        m = patron.match(linea)
        if m:
            return 'X' in m.group(1)
    return None


def _verificar_nodo(cfg, iface, host, user, pwd, port):
    fallos = []
    _, salida, _ = ejecutar(host, user, pwd, port, '/ip address print terse')
    print(f"\n    $ /ip address print terse\n    {salida or '(vacio)'}")
    # Se parsea la MISMA salida que se acaba de imprimir: repetir la llamada SSH
    # hacia una segunda consulta de la misma cosa y depender de ella hacia que
    # esa segunda vez no falle (si se pierde, las dos comprobaciones de IP salian
    # 'direcciones' y 'direcciones_extra' con la configuracion ya correcta).
    direcciones = [(m.group(1), m.group(3)) for m in RE_DIRECCION.finditer(salida or '')]
    print(f"    direcciones detectadas: {direcciones or '(ninguna)'}")
    ip_final = cfg['ip'].split('/')[0]
    if not any(ip == ip_final and ifc == iface for ip, ifc in direcciones):
        fallos.append('direcciones')
    # Ninguna direccion de la otra subred debe sobrevivir a la fase B.
    if len(direcciones) != 1:
        fallos.append('direcciones_extra')

    _, salida, _ = ejecutar(host, user, pwd, port,
                            '/ip route print terse where dst-address=0.0.0.0/0')
    print(f"\n    $ /ip route print terse where dst-address=0.0.0.0/0\n    {salida or '(vacio)'}")
    if cfg['gw'] and cfg['gw'] not in _aplanar(salida):
        fallos.append('ruta_por_defecto')

    _, salida, _ = ejecutar(host, user, pwd, port, '/interface print terse')
    print(f"\n    $ /interface print terse\n    {salida or '(vacio)'}")
    for i in cfg['deshabilitar_b']:
        # El estado se lee del flag 'X' de 'print': '/interface get <i> disabled'
        # devuelve vacio siempre, aunque la interfaz este de verdad deshabilitada.
        _, filas, _ = ejecutar(host, user, pwd, port, '/interface print terse')
        estado = _flag_deshabilitada(filas, i)
        print(f"    $ /interface print terse -> {i} deshabilitada={estado}")
        if estado is not True:
            fallos.append(f'{i}_sigue_habilitada')

    # Las MACs ya se imprimen en _fase_mac(), que es el punto unico que explica
    # por que el clon comparte las del router. Aqui solo se muestra la tabla
    # legible; NO se juzga 'mac objetivo' porque en RouterOS 7 no es escribible
    # por CLI y una comparacion contra ese objetivo solo produciria un FAIL
    # permanente que no depende de la configuracion del nodo.
    if cfg['macs']:
        _, plano, _ = ejecutar(host, user, pwd, port, '/interface ethernet print')
        print(f"\n    $ /interface ethernet print\n    {plano or '(vacio)'}")

    _, salida, _ = ejecutar(host, user, pwd, port, '/system identity print')
    identidad = _aplanar(salida)
    print(f"\n    $ /system identity print\n    {identidad or '(vacio)'}")
    if cfg['identity'] not in identidad:
        fallos.append('identity')

    _, salida, error = ejecutar(host, user, pwd, port, '/system resource print')
    if not RE_VERSION.search(salida or error):
        fallos.append('version')
    return fallos


def main():
    ap = argparse.ArgumentParser(
        description='Configura por SSH un nodo CHR del laboratorio IDS/IPS.')
    ap.add_argument('--nodo', default='router', choices=sorted(NODOS),
                    help='perfil de nodo a configurar (por defecto: router)')
    ap.add_argument('--ip', default=None,
                    help='IP por la que entrar; por defecto se elige sola')
    ap.add_argument('--listar', action='store_true', help='muestra el registro y sale')
    args = ap.parse_args()

    if args.listar:
        for nombre, cfg in NODOS.items():
            print(f"{nombre:10s} vm={cfg['vm']:<18s} ip={cfg['ip']:<14s} "
                  f"admin={cfg['ip_admin']:<10s} bootstrap={cfg['ip_bootstrap']}")
        return 0

    if mikrotik_api.ROUTER_PASS == 'LAB_PENDIENTE_CONFIG':
        print("""[!] Sin credenciales MikroTik. Configure config/mikrotik_lab.json
    (o variables MIKROTIK_IP/USER/PASS) antes de continuar.
    Plantilla: config/mikrotik.example.json  ->  config/mikrotik_lab.json""")
        return 2

    cfg = NODOS[args.nodo]
    user, pwd = mikrotik_api.ROUTER_USER, mikrotik_api.ROUTER_PASS
    port = int(mikrotik_api.ROUTER_PORT)
    admin, bootstrap = cfg['ip_admin'], cfg['ip_bootstrap']

    # Punto de entrada. La IP final es la que se busca primero: es el estado en el
    # que queda el nodo, asi que en una reejecucion es la unica que va a
    # contestar. Se le da margen (RouterOS acaba de arrancar) antes de rendirse y
    # caer a la IP de bootstrap, que solo existe mientras el clon no se ha
    # reconfigurado nunca: sin ese margen, un nodo ya configurado que acaba de
    # arrancar caia al bootstrap inexistente y el script moria por timeout.
    entrada = args.ip
    if entrada is None:
        if admin == bootstrap:
            entrada = admin
        elif _esperar_puerto(admin, port, intentos=30, espera=4):
            entrada = admin
        else:
            print(f"[*] {admin}:22 no responde todavia; se entra por el bootstrap {bootstrap}.")
            entrada = bootstrap

    print(f"[*] Nodo '{args.nodo}' (VM {cfg['vm']}) · entrada={entrada} · admin={admin}")
    ok, n = _esperar_ssh(entrada, user, pwd, port, intentos=45, espera=4)
    if not ok:
        print(f"[X] {entrada}:22 no respondio tras {n} intentos (~{n*4}s).")
        print(f"    Compruebe que la VM '{cfg['vm']}' esta encendida, que ether1 esta en")
        print(f"    la red host-only wan (10.10.0.1) y que CHR-IDS-LAB esta APAGADA")
        print(f"    mientras se reconfigura (si no, ambas responden por 10.10.0.2).")
        return 1
    print(f"[+] SSH OK en {entrada} (intento {n})")

    iface = _detectar_iface(entrada, user, pwd, port, cfg) or cfg['iface']
    fallos = _fase_a(cfg, iface, entrada, user, pwd, port)

    # Fase B: se ejecuta siempre que haya algo que limpiar, en cuanto la IP final
    # responda. Es idempotente, asi que tambien vale para reejecuciones.
    if cfg['limpiar_b'] or cfg['deshabilitar_b']:
        if admin == entrada:
            fallos += _fase_b(cfg, admin, user, pwd, port)
        else:
            print(f"[*] Esperando que {admin} responda antes de limpiar el bootstrap ...")
            ok_admin, n_admin = _esperar_ssh(admin, user, pwd, port, intentos=30, espera=4)
            if not ok_admin:
                print(f"[X] {admin}:22 no respondio: la fase A no completo. NO se limpia la IP")
                print(f"    de bootstrap para no dejar el nodo inaccesible.")
                fallos.append('ip_admin_no_alcanzable')
            else:
                print(f"[+] {admin} responde (intento {n_admin})")
                fallos += _fase_b(cfg, admin, user, pwd, port)
                entrada = admin
                iface = cfg['iface']

    # Informe de MACs: va DESPUES de B porque el nodo solo es alcanzable de forma
    # estable por su IP final cuando ya se le quito la IP de bootstrap. A partir de
    # aqui 'entrada' es siempre la IP final.
    if entrada != admin and not fallos:
        print("[*] La IP final no respondio tras la fase A: no se informan las MACs.")
    elif cfg['macs'] and entrada == admin:
        fallos += _fase_mac(cfg, admin, user, pwd, port)

    print("\n[*] Verificacion:")
    if cfg['firewall']:
        fallos += _verificar_router(entrada, user, pwd, port)
    else:
        fallos += _verificar_nodo(cfg, iface, entrada, user, pwd, port)

    if fallos:
        print(f"[X] {len(fallos)} paso(s) fallaron: {', '.join(fallos)}")
        return 1
    print(f"\nListo: nodo '{args.nodo}' ({cfg['vm']}) operativo en {cfg['ip_admin']}.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
