# -*- coding: utf-8 -*-
# =============================================================================
# mk_lab_iso.py - Genera la ISO de herramientas del laboratorio IDS/IPS.
# -----------------------------------------------------------------------------
# Por que existe: las VMs Alpine todavia no tienen Guest Additions, asi que no
# se les puede copiar archivos con 'VBoxManage guestcontrol', y tampoco hay
# carpetas compartidas para guests Linux. La solucion es meter el instalador en
# una ISO de datos (segundo DVD) y montarla desde la ISO live.
#
# Se escribe el formato ISO9660 a mano: la API de Windows (IMAPI2FS) no esta
# disponible en este equipo y el toolkit de Windows (oscdimg) tampoco.
#
# Uso:
#   python _lab/mk_lab_iso.py
#   -> _lab/alpine-tools.iso  (contiene INSTALL.SH, sin argumentos: hay que
#      teclear 'sh /mnt/INSTALL.SH <host> <ip> <gw>')
#
#   python _lab/mk_lab_iso.py --por-vm
#   -> ademas _lab/alpine-tools-atacante.iso y _lab/alpine-tools-victima.iso,
#      cada una con un archivo 'GO' que ya trae los argumentos puestos
#      ('set -- ...' pegado delante del instalador). Sirve para que en la
#      consola de la VM haya que teclear solo 'sh /m/GO': una linea corta, sin
#      numeros que teclear mal. La consola emulada se come teclas en lineas
#      largas y ya rompio la instalacion una vez.
#
# Verificacion (desde Windows):
#   Mount-DiskImage .\_lab\alpine-tools.iso
#   (Get-FileHash <letra>:\INSTALL.SH).Hash -eq
#       (Get-FileHash .\_lab\install_alpine_vm.sh).Hash
# o, mejor:  python _lab/verify_lab_iso.py
# =============================================================================
import hashlib
import os
import struct
import sys

_LAB = os.path.dirname(os.path.abspath(__file__))
ORIGEN = os.path.join(_LAB, 'install_alpine_vm.sh')
DESTINO = os.path.join(_LAB, 'alpine-tools.iso')
NOMBRE_ISO = b'INSTALL.SH;1'      # ISO9660: 8.3 en mayusculas + version ';1'

# Host, IP y gateway de cada VM del lab (ver docs/lab/topologia-lab.md).
VMS = {
    'atacante': dict(host='atq', ip='10.10.0.50', gw='10.10.0.2'),
    'victima': dict(host='vic', ip='10.10.1.50', gw='10.10.1.2'),
}
SECTOR = 2048


def _ambos_extremos(valor, bytes_totales):
    """Un valor 'double endian' de la ISO: LE seguido de BE.

    bytes_totales es el tamaño TOTAL del campo: 8 para un entero de 32 bits
    (4 bytes en cada endianness) y 4 para uno de 16 bits.
    """
    fmt = {4: 'H', 8: 'I'}[bytes_totales]
    return struct.pack('<' + fmt, valor) + struct.pack('>' + fmt, valor)


def _campo(pvd, inicio, largo, valor, etiqueta):
    """Escribe un campo de tamaño fijo y verifica que no desborde el sector."""
    if len(valor) != largo:
        raise ValueError(
            f"campo '{etiqueta}': se esperaban {largo} bytes, se generaron "
            f"{len(valor)}")
    pvd[inicio:inicio + largo] = valor


def _fecha_iso():
    """Fecha de un registro de directorio: 7 bytes (año desde 1900, mes, día,
    hora, minuto, segundo, offset GMT)."""
    import time
    t = time.localtime()
    return bytes([t.tm_year - 1900, t.tm_mon, t.tm_mday,
                  t.tm_hour, t.tm_min, t.tm_sec, 0])


def _fecha_pvd():
    """Fecha del PVD: 17 bytes. Los 9 primeros son año (u16 LE), mes, día,
    hora, minuto, segundo, centésimas y offset GMT; el resto es relleno."""
    import time
    t = time.localtime()
    return (struct.pack('<H', t.tm_year - 1900)
            + bytes([t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, 0, 0])
            + b'\x00' * 8)


def _registro(nombre, sector, largo, es_dir):
    """Registro de directorio ISO9660 (offsets fijos de ECMA-119 §9.1)."""
    cuerpo = bytearray(SECTOR * 0)          # se rellena al final
    cuerpo = bytearray()
    cuerpo.append(0)                                   # [0]  largo del registro
    cuerpo.append(0)                                   # [1]  atributos extendidos
    _campo(cuerpo, 2, 8, _ambos_extremos(sector, 8), 'extent')
    _campo(cuerpo, 10, 8, _ambos_extremos(largo, 8), 'data length')
    _campo(cuerpo, 18, 7, _fecha_iso(), 'fecha')
    cuerpo += bytes([0x02 if es_dir else 0x00])        # [25] banderas
    cuerpo += bytes([0, 0])                            # [26-27] unidad/brecha
    _campo(cuerpo, 28, 4, _ambos_extremos(1, 4), 'volume sequence')
    cuerpo.append(len(nombre))                         # [32] largo del nombre
    cuerpo += nombre                                   # [33..] nombre
    if len(cuerpo) % 2:                                # los registros son pares
        cuerpo.append(0)
    cuerpo[0] = len(cuerpo)
    if len(cuerpo) > 255:
        raise ValueError(f"registro de {len(nombre)} bytes: excede 255")
    return bytes(cuerpo)


def _tabla_rutas(sector_raiz, big_endian=False):
    """Tabla de rutas con una sola entrada: la raiz.

    Entrada: [0] largo del identificador, [1] atributos, [2..5] sector de la
    raiz, [6..7] numero del directorio padre (siempre 1 = la propia raiz).
    """
    fmt = '>H' if big_endian else '<H'
    entrada = bytes([1, 0]) \
        + struct.pack('>I' if big_endian else '<I', sector_raiz) \
        + struct.pack(fmt, 1)
    return entrada


def construir(origen, destino, nombre_iso=NOMBRE_ISO, prefijo=b''):
    with open(origen, 'rb') as f:
        contenido = f.read()

    # El prefijo va delante del instalador para 'set -- <args>': el guion '-'
    # descarta lo que hubiera en la linea de comandos y el instalador lee
    # $1 $2 $3 como siempre.
    if prefijo:
        contenido = prefijo + contenido

    # El sector donde vive el archivo se rellena con ceros, pero el 'data
    # length' del registro debe ser el tamaño REAL: si se pone el tamaño ya
    # rellenado, al leer el archivo aparecen NULs al final.
    largo_real = len(contenido)
    sectores_datos = (largo_real + SECTOR - 1) // SECTOR
    if largo_real % SECTOR:
        contenido += b'\x00' * (sectores_datos * SECTOR - largo_real)

    # Disposicion de la imagen (el sector 0 es el arranque, reservado):
    #   0-15 area de sistema | 16 PVD | 17 terminador
    #   18 tabla L | 19 tabla M | 20 directorio raiz | 21.. datos
    SECTOR_PVD = 16
    SECTOR_TABLA_L = 18
    SECTOR_TABLA_M = 19
    SECTOR_RAIZ = 20
    SECTOR_ARCHIVO = 21
    total = SECTOR_ARCHIVO + sectores_datos

    # --- directorio raiz: '.', '..' y el archivo ---
    raiz = bytearray()
    raiz += _registro(b'\x00', SECTOR_RAIZ, SECTOR, es_dir=True)
    raiz += _registro(b'\x01', SECTOR_RAIZ, SECTOR, es_dir=True)
    raiz += _registro(nombre_iso, SECTOR_ARCHIVO, largo_real, es_dir=False)
    raiz += b'\x00' * (SECTOR - len(raiz))

    # --- Primary Volume Descriptor ---
    pvd = bytearray(b'\x00' * SECTOR)
    pvd[0] = 1
    pvd[1:6] = b'CD001'
    pvd[6] = 1
    _campo(pvd, 8, 32, b'LINUX'.ljust(32, b' '), 'system id')
    _campo(pvd, 40, 32, b'LABTOOLS'.ljust(32, b' '), 'volume id')
    _campo(pvd, 80, 8, _ambos_extremos(total, 8), 'volume space size')
    _campo(pvd, 120, 4, _ambos_extremos(1, 4), 'volume set size')
    _campo(pvd, 124, 4, _ambos_extremos(1, 4), 'volume sequence number')
    _campo(pvd, 128, 4, _ambos_extremos(SECTOR, 4), 'logical block size')
    _campo(pvd, 132, 8, _ambos_extremos(len(_tabla_rutas(SECTOR_RAIZ)), 8),
           'path table size')
    _campo(pvd, 140, 4, struct.pack('<I', SECTOR_TABLA_L), 'L path table')
    _campo(pvd, 144, 4, struct.pack('<I', 0), 'L opt path table')
    _campo(pvd, 148, 4, struct.pack('>I', SECTOR_TABLA_M), 'M path table')
    _campo(pvd, 152, 4, struct.pack('>I', 0), 'M opt path table')
    _campo(pvd, 156, 34,
           _registro(b'\x00', SECTOR_RAIZ, SECTOR, es_dir=True), 'root record')
    _campo(pvd, 190, 128, b'UNIPAZ'.ljust(128, b' '), 'volume set id')
    _campo(pvd, 318, 128, b'IDS-IPS-LAB'.ljust(128, b' '), 'publisher')
    _campo(pvd, 446, 128, b'UNIPAZ-LAB'.ljust(128, b' '), 'preparer')
    _campo(pvd, 574, 128, b'LAB'.ljust(128, b' '), 'application')
    _campo(pvd, 813, 17, _fecha_pvd(), 'creacion')
    _campo(pvd, 830, 17, _fecha_pvd(), 'modificacion')
    _campo(pvd, 847, 17, _fecha_pvd(), 'expiracion')
    _campo(pvd, 864, 17, _fecha_pvd(), 'vigencia')
    pvd[881] = 1                                     # version de estructura
    if len(pvd) != SECTOR:
        raise ValueError(f'PVD de {len(pvd)} bytes, deberia ser {SECTOR}')

    terminador = bytearray(b'\x00' * SECTOR)
    terminador[0] = 255
    terminador[1:6] = b'CD001'
    terminador[6] = 1

    imagen = bytearray(b'\x00' * (total * SECTOR))
    imagen[SECTOR_PVD * SECTOR:SECTOR_PVD * SECTOR + SECTOR] = pvd
    imagen[17 * SECTOR:17 * SECTOR + SECTOR] = terminador
    tabla_l = _tabla_rutas(SECTOR_RAIZ, big_endian=False)
    tabla_m = _tabla_rutas(SECTOR_RAIZ, big_endian=True)
    imagen[SECTOR_TABLA_L * SECTOR:SECTOR_TABLA_L * SECTOR + len(tabla_l)] = tabla_l
    imagen[SECTOR_TABLA_M * SECTOR:SECTOR_TABLA_M * SECTOR + len(tabla_m)] = tabla_m
    imagen[SECTOR_RAIZ * SECTOR:SECTOR_RAIZ * SECTOR + SECTOR] = raiz
    imagen[SECTOR_ARCHIVO * SECTOR:SECTOR_ARCHIVO * SECTOR + len(contenido)] \
        = contenido

    with open(destino, 'wb') as f:
        f.write(imagen)

    return {
        'iso': destino,
        'bytes': len(imagen),
        'sectores': total,
        'archivo': nombre_iso.decode().rstrip(';1'),
        'sha256_origen': hashlib.sha256(open(origen, 'rb').read()).hexdigest(),
        'sha256_carga': hashlib.sha256(contenido).hexdigest(),
    }


def _informe(info: dict) -> None:
    print("[ISO] {iso}".format(**info))
    print("     {bytes} bytes, {sectores} sectores de {s} bytes".format(
        s=SECTOR, **info))
    print("     contiene {archivo} (carga sha256 {sha256_carga})".format(**info))


if __name__ == '__main__':
    por_vm = '--por-vm' in sys.argv[1:]
    if not os.path.exists(ORIGEN):
        sys.exit(f"[X] No existe {ORIGEN}")

    info = construir(ORIGEN, DESTINO)
    _informe(info)
    print("[OK] ISO generica: el instalador pide argumentos al teclear.")

    if por_vm:
        for clave, vm in VMS.items():
            destino = os.path.join(_LAB, f'alpine-tools-{clave}.iso')
            prefijo = ('set -- {host} {ip} {gw}\n'.format(**vm)).encode('ascii')
            info = construir(ORIGEN, destino, nombre_iso=b'GO;1', prefijo=prefijo)
            _informe(info)
        print('[OK] En la consola de cada VM basta:  sh /m/GO')

