# =============================================================================
# chr_apply_config.py - Laboratorio IDS/IPS (UNIPAZ)
# -----------------------------------------------------------------------------
# Aplica la configuracion del CHR por SSH (una vez desbloqueado con SSH en el
# bootstrap manual): IPs ether1/ether2, identity y reglas de firewall drop
# para IDS_BLACKLIST (forward + input). Es REUTILIZABLE y comparte la
# maquinaria de credenciales por perfil de row ROUTER (config/mikrotik_*.json).
#
# Uso (maquina objetivo):  python chr_apply_config.py
# =============================================================================
import os
import sys

_LAB = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_LAB)
sys.path.insert(0, _PROJ)

import mikrotik_api  # noqa: E402  (lee config/mikrotik_lab.json o env MIKROTIK_*)

try:
    import paramiko
except ImportError:
    sys.exit("[X] Falta 'paramiko'. Instale:  pip install paramiko")

# --- Config esperada del CHR del laboratorio ---
CHR_LAB_IP = os.environ.get('CHR_LAB_IP', '10.10.0.2')
WAN_IP = os.environ.get('CHR_WAN_IP', '10.10.0.2')
LAN_IP = os.environ.get('CHR_LAN_IP', '10.10.1.2')
WAN_NET = os.environ.get('CHR_WAN_NET', '10.10.0.0/24')
LAN_NET = os.environ.get('CHR_LAN_NET', '10.10.1.0/24')

COMANDOS = [
    f'/ip address add address={WAN_IP}/{int(WAN_NET.split("/")[1])} interface=ether1',
    f'/ip address add address={LAN_IP}/{int(LAN_NET.split("/")[1])} interface=ether2',
    '/system identity set name=CHR-IDS-LAB',
    '/ip firewall address-list remove [find list="IDS_BLACKLIST"]',
    '/ip firewall filter remove [find comment="IDS_BLACKLIST_DROP_FORWARD"]',
    '/ip firewall filter remove [find comment="IDS_BLACKLIST_DROP_INPUT"]',
    '/ip firewall filter add chain=forward action=drop src-address-list="IDS_BLACKLIST" comment="IDS_BLACKLIST_DROP_FORWARD" place-before=0',
    '/ip firewall filter add chain=input action=drop src-address-list="IDS_BLACKLIST" comment="IDS_BLACKLIST_DROP_INPUT" place-before=0',
]

VERIFICAR = [
    '/ip address print',
    '/ip firewall filter print terse',
    '/system identity print',
]


def ejecutar(host, user, pwd, port, cmd):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, port=port, username=user, password=pwd, timeout=8.0)
    _, out, err = cli.exec_command(cmd)
    salida = out.read().decode(errors='replace').strip()
    error = err.read().decode(errors='replace').strip()
    cli.close()
    return salida, error


def main():
    if mikrotik_api.ROUTER_PASS == 'LAB_PENDIENTE_CONFIG':
        print("""[!] Sin credenciales MikroTik. Configure config/mikrotik_lab.json
    (o variables MIKROTIK_IP/USER/PASS) antes de continuar.
    Plantilla: config/mikrotik.example.json  ->  config/mikrotik_lab.json""")
        sys.exit(2)

    host = os.environ.get('MIKROTIK_IP', mikrotik_api.ROUTER_IP)
    print(f"[*] Aplicando config a {host} ...")
    for cmd in COMANDOS:
        salida, error = ejecutar(host, mikrotik_api.ROUTER_USER,
                                 mikrotik_api.ROUTER_PASS,
                                 int(mikrotik_api.ROUTER_PORT), cmd)
        if error and 'already' not in error:
            print(f"    [!] {cmd}\n        -> {error}")
        else:
            print(f"    [OK] {cmd[:70]}")

    print("\n[*] Verificacion:")
    todo_ok = True
    for cmd in VERIFICAR:
        salida, error = ejecutar(host, mikrotik_api.ROUTER_USER,
                                 mikrotik_api.ROUTER_PASS,
                                 int(mikrotik_api.ROUTER_PORT), cmd)
        print(f"\n    $ {cmd}\n    {salida or error or '(vacío)'}")
        if WAN_IP not in salida or LAN_IP not in salida:
            todo_ok = todo_ok and False

    ok_drop = 'IDS_BLACKLIST_DROP_FORWARD' in (ejecutar(
        host, mikrotik_api.ROUTER_USER, mikrotik_api.ROUTER_PASS,
        int(mikrotik_api.ROUTER_PORT),
        '/ip firewall filter print terse')[0] or '')
    print(f"\n[{'OK' if ok_drop else 'X'}] Reglas de drop IDS_BLACKLIST presentes: {ok_drop}")
    print("Listo. Siga con t5_routeros_ips.py" if ok_drop else
          "Revise la config aplicada.")


if __name__ == '__main__':
    main()