#!/usr/bin/env python3
"""Verifica _lab/alpine-tools.iso sin montarla.

El instalador de Alpine viaja en esa ISO porque las VMs todavia no tienen Guest
Additions (no hay forma de copiar archivos). Si la ISO quedara mal-formed, la
VM arrancaria, no encontraria /mnt/INSTALL.SH y el fallo seria dificil de leer.
Este script la abre como lo haria Linux: lee el PVD, la raiz y extrae el
archivo, y lo compara byte a byte con el origen.

    python _lab/verify_lab_iso.py [ruta.iso]

Devuelve 0 si todo esta bien, 1 si algo falla (util en un `&&`).
"""
from __future__ import annotations

import hashlib
import os
import sys

LAB = os.path.dirname(os.path.abspath(__file__))
ORIGEN = os.path.join(LAB, 'install_alpine_vm.sh')
ISO_POR_DEFECTO = os.path.join(LAB, 'alpine-tools.iso')
SECTOR = 2048

# Marcadores que el instalador necesita para no quedarse esperando teclado y
# para no fallar en silencio: repo local (no hay internet), instalacion NO
# interactiva (setup-disk y no setup-alpine), login de root por password, IP
# fija en el sistema instalado y apagado limpio.
MARCADORES = (
    b'setup-disk -m sys -s 0',
    b'dl-cdn.alpinelinux.org',
    b'apk add --quiet syslinux linux-lts',
    b'PermitRootLogin yes',
    b'iface eth0 inet static',
    b'poweroff',
)


def _le(buf: bytes, i: int, n: int) -> int:
    """Entero 'little endian' (los campos ISO son 'both endian': LE primero,
    pero Linux y el resto de lectores toman la mitad LE)."""
    return int.from_bytes(buf[i:i + n], 'little')


def _primer_archivo(d: bytes, sector: int):
    """Primer archivo (no directorio) de un sector de directorio.

    Ojo con el flag: los directorios se marcan con el bit 1 (0x02) del byte 25
    del registro, NO con el bit alto del nombre (offset 2 es el sector). Los
    nombres de '.' y '..' valen un unico byte 0x00 y 0x01 respectivamente.
    """
    base, fin = sector * SECTOR, (sector + 1) * SECTOR
    p = base
    while p < fin:
        largo = d[p]
        if largo == 0:                       # salto al siguiente sector
            p = base + ((p - base) // SECTOR + 1) * SECTOR
            continue
        cuerpo = d[p:p + largo]
        if cuerpo[25] & 0x02:                # es un directorio: saltar
            p += largo
            continue
        n = cuerpo[32]
        nombre = cuerpo[33:33 + n]
        return nombre, _le(cuerpo, 2, 4), _le(cuerpo, 10, 4)
    raise ValueError('el directorio no contiene archivos')


def main() -> int:
    ruta_iso = sys.argv[1] if len(sys.argv) > 1 else ISO_POR_DEFECTO
    fallos: list[str] = []

    def check(ok: bool, msg: str) -> None:
        print(('  [OK] ' if ok else '  [!!] ') + msg)
        if not ok:
            fallos.append(msg)

    if not os.path.isfile(ruta_iso):
        print(f"No existe: {ruta_iso}")
        return 1

    d = open(ruta_iso, 'rb').read()
    print(f"ISO: {ruta_iso} ({len(d)} bytes, {len(d) // SECTOR} sectores)")

    pvd = d[16 * SECTOR:17 * SECTOR]
    check(pvd[1:6] == b'CD001', 'PVD con identificador CD001')
    check(_le(pvd, 128, 2) == SECTOR, f'logical block size = {_le(pvd, 128, 2)}')

    raiz_rec = pvd[156:156 + 34]
    raiz = _le(raiz_rec, 2, 4)
    try:
        nombre, sector, largo = _primer_archivo(d, raiz)
        print(f"  raiz LBA {raiz} -> archivo {nombre.decode('latin-1')!r} "
              f"(LBA {sector}, {largo} bytes)")
        check(nombre.upper().startswith(b'INSTALL.SH') or nombre.upper() == b'GO;1',
              f'el archivo de la raiz es INSTALL.SH o GO ({nombre.decode()})')
        cuerpo = d[sector * SECTOR:sector * SECTOR + largo]
    except ValueError as exc:
        check(False, f'no se pudo leer la raiz: {exc}')
        return 1

    origen = open(ORIGEN, 'rb').read()

    # Dos variantes de carga: el instalador tal cual, o el instalador con un
    # 'set -- <host> <ip> <gw>' pegado delante (las ISO por VM, para que en la
    # consola haya que teclear solo 'sh /m/GO').
    prefijo = b''
    if cuerpo.startswith(b'set -- '):
        linea = cuerpo[:cuerpo.index(b'\n')].decode('ascii')
        prefijo = (linea + '\n').encode('ascii')
        argumentos = linea.split()[2:]
        print(f"  argumentos ya puestos: {' '.join(argumentos)}")
        check(len(argumentos) == 3,
              f'tiene los 3 argumentos que espera el instalador (hay {len(argumentos)})')
    cuerpo_limpio = cuerpo[len(prefijo):]

    check(len(cuerpo_limpio) == len(origen),
          f'largo igual al origen ({len(origen)} bytes)')
    check(cuerpo_limpio == origen,
          'contenido identico a install_alpine_vm.sh')
    check(b'\r\n' not in cuerpo,
          'sin CRLF (el shebang no funcionaria con \\r)')
    for marcador in MARCADORES:
        check(marcador in cuerpo, f'contiene {marcador.decode()}')

    print("  sha256 del archivo dentro de la ISO: "
          + hashlib.sha256(cuerpo).hexdigest())
    print("  sha256 de _lab/install_alpine_vm.sh: "
          + hashlib.sha256(origen).hexdigest())

    print('[OK] ISO utilizable.' if not fallos else f'[FALLA] {len(fallos)}')
    return 1 if fallos else 0


if __name__ == '__main__':
    sys.exit(main())
