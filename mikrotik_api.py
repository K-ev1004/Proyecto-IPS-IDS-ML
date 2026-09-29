# mikrotik_api.py — Módulo de Interacción con RouterOS (MikroTik CCR2004)
# Universidad UNIPAZ
# =============================================================================
# Propósito: Ejecuta comandos remotos vía SSH para bloquear dinámicamente
# las direcciones IP atacantes en el Firewall Perimetral de la institución.
#
# NOTA (verificado): añadir una IP a un address-list NO bloquea nada por sí
# solo en RouterOS; debe existir una regla de firewall (/ip firewall filter,
# chains forward + input) que haga drop para list="IDS_BLACKLIST".
# La confirmación real (readback) verifica que la regla EXISTE en el equipo.
# =============================================================================

import logging
import datetime

# Nota: En producción, instalar 'paramiko' (pip install paramiko)
try:
    import paramiko
    PARAMIKO_DISPONIBLE = True
except ImportError:
    PARAMIKO_DISPONIBLE = False

# ============================================================
# CONFIGURACIÓN DEL ROUTER (por entorno / perfil, NUNCA credenciales en el fuente)
# ============================================================
# Orden de resolución para REDES/integracion:
#   1) Variables de entorno: MIKROTIK_PROFILE | MIKROTIK_IP | MIKROTIK_USER
#      MIKROTIK_PASS | MIKROTIK_PORT | MIKROTIK_ADDRESS_LIST
#   2) Archivo de perfil: config/mikrotik_<perfil>.json (lab / prod).
#   3) Valores por defecto (solo referencia; se advierte si no hay config).

import os
import json as _json

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config')

_DEFAULTS_LAB = {
    'ip': '192.168.1.1',
    'user': 'admin_ids',
    'pass': 'LAB_PENDIENTE_CONFIG',
    'port': 22,
    'address_list': 'IDS_BLACKLIST',
}


def _cargar_config_mikrotik():
    cfg = {}
    perfil = os.environ.get('MIKROTIK_PROFILE', 'lab')
    ruta_perfil = os.path.join(CONFIG_DIR, f'mikrotik_{perfil}.json')
    if os.path.exists(ruta_perfil):
        try:
            with open(ruta_perfil, encoding='utf-8') as f:
                cfg.update(_json.load(f))
            print(f"[CFG] Perfil MikroTik '{perfil}' cargado: {ruta_perfil}")
        except Exception as e:
            print(f"[!] No se pudo leer {ruta_perfil}: {e}")
    else:
        print(f"[CFG] Sin perfil MikroTik '{perfil}' ({ruta_perfil}). "
              f"Usar config/mikrotik_lab.json o variables MIKROTIK_*.")

    for var, key in [('MIKROTIK_IP', 'ip'), ('MIKROTIK_USER', 'user'),
                     ('MIKROTIK_PASS', 'pass'), ('MIKROTIK_PORT', 'port'),
                     ('MIKROTIK_ADDRESS_LIST', 'address_list')]:
        valor = os.environ.get(var)
        if valor is not None:
            cfg[key] = valor

    v = dict(_DEFAULTS_LAB)
    v.update({k: cfg[k] for k in cfg if k in v})
    if v['pass'] == 'LAB_PENDIENTE_CONFIG':
        print("[CFG] ADVERTENCIA: credenciales MikroTik sin configurar. "
              "El bloqueo REAL no funcionará hasta definir MIKROTIK_PASS.")
    return v


_CFG = _cargar_config_mikrotik()

ROUTER_IP = _CFG['ip']                       # IP de gestión del MikroTik Core
ROUTER_USER = _CFG['user']                   # Usuario con permisos de firewall
ROUTER_PASS = _CFG['pass']
ROUTER_PORT = int(_CFG['port'])              # Puerto SSH estándar (o custom)

LISTA_BLOQUEO = _CFG['address_list']         # Nombre del Address-List en MikroTik


def _resultado(ok, modo, confirmado, comando, respuesta, error=""):
    """Devuelve la estructura estándar de resultado del bloqueo."""
    return {
        'ok': bool(ok),
        'modo': modo,            # 'real' | 'mock' | 'error'
        'confirmado': bool(confirmado),
        'comando': comando,
        'respuesta': respuesta,
        'error': error,
    }


def bloquear_ip_mikrotik(ip_atacante, duracion_horas=24):
    """
    Se conecta al MikroTik, añade la IP a la lista de bloqueo del firewall
    y CONFIRMA por readback que la regla quedó registrada en IDS_BLACKLIST.
    Devuelve un dict: {ok, modo, confirmado, comando, respuesta, error}
    """
    print(f"\n[IPS MIKROTIK] Iniciando bloqueo activo para {ip_atacante}")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    comando = (
        f'/ip firewall address-list add '
        f'list="{LISTA_BLOQUEO}" '
        f'address={ip_atacante} '
        f'timeout={duracion_horas}h '
        f'comment="Bloqueado automáticamente por NIPS CatBoost - {timestamp}"'
    )

    if not PARAMIKO_DISPONIBLE:
        print("[!] Paramiko no está instalado. Bloqueo simulado (Mock).")
        print(f"[!] MOCK COMMAND: {comando}")
        return _resultado(True, 'mock', False, comando,
                          'MOCK: SIN CONEXION SSH, REGLA NO APLICADA')

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print(f"[*] Conectando a MikroTik ({ROUTER_IP})...")
        ssh.connect(ROUTER_IP, port=ROUTER_PORT, username=ROUTER_USER, password=ROUTER_PASS, timeout=5.0)

        print(f"[*] Ejecutando: {comando}")
        stdin, stdout, stderr = ssh.exec_command(comando)

        error = stderr.read().decode().strip()
        salida = stdout.read().decode().strip()

        if error and not ("already have" in error or "already exists" in error):
            ssh.close()
            print(f"[X] Error desde MikroTik: {error}")
            return _resultado(False, 'error', False, comando, salida, error)
        if error:
            print(f"[OK] La IP {ip_atacante} ya estaba bloqueada en el MikroTik.")

        # --- VERIFICACIÓN REAL (READBACK): la regla debe EXISTIR en el equipo ---
        readback_cmd = (
            f'/ip firewall address-list print terse '
            f'where list="{LISTA_BLOQUEO}" and address={ip_atacante}'
        )
        stdin2, stdout2, stderr2 = ssh.exec_command(readback_cmd)
        rb_salida = stdout2.read().decode().strip()
        rb_error = stderr2.read().decode().strip()
        ssh.close()

        confirmado = ip_atacante in rb_salida
        print(f"[{'OK' if confirmado else 'X'}] Readback IDS_BLACKLIST: "
              f"regla presente = {confirmado}")
        print(f"      Respuesta equipo: {rb_salida or rb_error or '(vacio)'}")
        if confirmado:
            print(f"[OK] IP {ip_atacante} bloqueada exitosamente por {duracion_horas} horas (CONFIRMADA en MikroTik).")
        return _resultado(True, 'real', confirmado, comando, rb_salida, rb_error)

    except Exception as e:
        print(f"[X] Falla crítica al conectar con MikroTik: {e}")
        return _resultado(False, 'error', False, comando, '', str(e))


def desbloquear_ip_mikrotik(ip_atacante):
    """
    Se conecta al MikroTik, elimina la IP de la lista de bloqueo y CONFIRMA
    por readback que ya no existe la regla. Devuelve el mismo dict estándar.
    """
    print(f"\n[IPS MIKROTIK] Iniciando desbloqueo activo para {ip_atacante}")

    comando = f'/ip firewall address-list remove [find list="{LISTA_BLOQUEO}" address="{ip_atacante}"]'

    if not PARAMIKO_DISPONIBLE:
        print("[!] Paramiko no está instalado. Desbloqueo simulado (Mock).")
        print(f"[!] MOCK COMMAND: {comando}")
        return _resultado(True, 'mock', False, comando,
                          'MOCK: SIN CONEXION SSH, DESBLOQUEO NO APLICADO')

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print(f"[*] Conectando a MikroTik ({ROUTER_IP})...")
        ssh.connect(ROUTER_IP, port=ROUTER_PORT, username=ROUTER_USER, password=ROUTER_PASS, timeout=5.0)

        print(f"[*] Ejecutando: {comando}")
        stdin, stdout, stderr = ssh.exec_command(comando)

        error = stderr.read().decode().strip()
        salida = stdout.read().decode().strip()

        if error:
            ssh.close()
            print(f"[X] Error desde MikroTik: {error}")
            return _resultado(False, 'error', False, comando, salida, error)

        # --- VERIFICACIÓN REAL (READBACK): la regla ya no debe existir ---
        readback_cmd = (
            f'/ip firewall address-list print terse '
            f'where list="{LISTA_BLOQUEO}" and address={ip_atacante}'
        )
        stdin2, stdout2, stderr2 = ssh.exec_command(readback_cmd)
        rb_salida = stdout2.read().decode().strip()
        ssh.close()

        desbloqueado = ip_atacante not in rb_salida
        print(f"[{'OK' if desbloqueado else 'X'}] Readback: regla eliminada = {desbloqueado}")
        print(f"      Respuesta equipo: {rb_salida or '(vacio)'}")
        if desbloqueado:
            print(f"[OK] IP {ip_atacante} desbloqueada exitosamente.")
        return _resultado(True, 'real', desbloqueado, comando, rb_salida)

    except Exception as e:
        print(f"[X] Falla crítica al conectar con MikroTik: {e}")
        return _resultado(False, 'error', False, comando, '', str(e))