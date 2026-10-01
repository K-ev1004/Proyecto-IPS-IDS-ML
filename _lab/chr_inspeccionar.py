#!/usr/bin/env python3
"""Inspecciona el CHR del laboratorio por SSH y muestra el estado real.

Sirve para dos cosas:

  * no depender de teclear en la consola del CHR (nadie la tiene abierta);
  * dejar constancia de como quedo la configuracion antes/despues de T5
    (el informe de la tesis lo usa como evidencia).

    python _lab/chr_inspeccionar.py
    python _lab/chr_inspeccionar.py --guardar docs/lab/chr_estado_antes.json
    python _lab/chr_inspeccionar.py --limpiar     # borra el placeholder de pruebas

Notas de RouterOS que costaron tiempo (ver _lab/chr_apply_config.py):
  * los errores salen por stdout con codigo de salida distinto de 0;
  * 'print' envuelve las columnas segun el ancho de la consola no interactiva;
  * 'print terse' no existe en 'identity' y se ignora en 'firewall filter';
  * las reglas son numeradas por posicion: 'move number=0' es la primera.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import paramiko

LAB = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(LAB)
CONFIG = os.path.join(RAIZ, 'config', 'mikrotik_lab.json')

CONSULTAS = [
    # (nombre, comando, como aplanar)  ->  'todo' quita TODOS los espacios.
    # RouterOS ajusta las columnas al ancho de la consola; sin terminal real
    # eso parte hasta el nombre de la identidad letra por letra, asi que para
    # ese caso hay que compararlo sin espacios.
    ('identidad', '/system identity print', 'todo'),
    ('version', '/system resource print', 'espacios'),
    ('interfaces', '/ip address print terse', 'espacios'),
    ('filtro', '/ip firewall filter print terse', 'espacios'),
    ('listas', '/ip firewall address-list print', 'espacios'),
    ('servicio_ssh', '/ip service print', 'espacios'),
]

PLACEHOLDER = 'LAB_PLACEHOLDER'


def _conectar():
    with open(CONFIG, encoding='utf-8') as f:
        cfg = json.load(f)
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(cfg['ip'], port=cfg.get('port', 22),
                username=cfg['user'], password=cfg['pass'],
                timeout=15, banner_timeout=20, auth_timeout=20)
    return cli, cfg


def _ejecutar(cli, cmd: str) -> tuple[int, str, str]:
    """(rc, stdout, stderr) leyendo antes de recv_exit_status (ver notas)."""
    _, out, err = cli.exec_command(cmd, timeout=30)
    salida = out.read().decode('utf-8', 'replace')
    error = err.read().decode('utf-8', 'replace')
    rc = out.channel.recv_exit_status()
    return rc, salida.replace('\r\n', '\n'), error.replace('\r\n', '\n')


def _aplanar(texto: str, como: str = 'espacios') -> str:
    """Quita saltos de linea: 'print' envuelve segun el ancho de la consola.

    'espacios' deja los tokens separados por un espacio (util para columnas);
    'todo' elimina cualquier espacio (identidad, que sale partida en letras).
    """
    if como == 'todo':
        return ''.join(texto.split())
    return ' '.join(texto.split())


def main() -> int:
    p = argparse.ArgumentParser(description='Estado del CHR del laboratorio.')
    p.add_argument('--guardar', metavar='ARCHIVO',
                   help='volcar el estado a un JSON de evidencia')
    p.add_argument('--limpiar', action='store_true',
                   help=f'borrar la entrada {PLACEHOLDER} de las listas '
                        '(residuo de pruebas manuales)')
    args = p.parse_args()

    if not os.path.isfile(CONFIG):
        sys.exit(f'[X] Falta {CONFIG} (creelo con las credenciales del CHR).')

    try:
        cli, cfg = _conectar()
    except Exception as exc:                       # noqa: BLE001
        sys.exit(f'[X] No se pudo conectar a {cfg.get("ip", "?") if "cfg" in dir() else "el CHR"}: {exc}')

    print(f'[OK] Conectado a {cfg["ip"]} como {cfg["user"]}')

    if args.limpiar:
        rc, salida, error = _ejecutar(
            cli, f'/ip firewall address-list remove [find list="{PLACEHOLDER}"]')
        if rc == 0:
            print(f'[OK] Placeholder {PLACEHOLDER} eliminado.')
        else:
            print(f'[!!] No se elimino {PLACEHOLDER} (rc={rc}): '
                  f'{_aplanar(salida + error)}')

    estado: dict[str, str] = {}
    for nombre, cmd, como in CONSULTAS:
        rc, salida, error = _ejecutar(cli, cmd)
        if rc == 0:
            texto = _aplanar(salida, como)
        else:
            texto = f'ERROR rc={rc}: ' + _aplanar(salida + error, como)
        estado[nombre] = texto
        marca = '   ' if rc == 0 else '[!]'
        print(f'  {marca} {nombre}: {texto}')

    cli.close()

    if args.guardar:
        os.makedirs(os.path.dirname(os.path.abspath(args.guardar)), exist_ok=True)
        with open(args.guardar, 'w', encoding='utf-8') as f:
            json.dump({'host': cfg['ip'], 'salidas': estado}, f,
                      indent=2, ensure_ascii=False)
        print(f'[OK] Evidencia guardada en {args.guardar}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
