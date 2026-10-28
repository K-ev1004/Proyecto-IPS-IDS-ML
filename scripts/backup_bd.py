# -*- coding: utf-8 -*-
"""
backup_bd.py — Copia diaria de la base de datos de producción v5.

Uso:
    python scripts/backup_bd.py [--retencion 90]

Lección del incidente (la BD de producción se perdió): una copia de seguridad
automática con hash verificable es obligatoria antes de abrir alertas.

Usa la API de backup de SQLite (segura con el sniffer en marcha) y deja el
resultado comprimido en backups/ junto a su SHA-256.
"""
import argparse
import gzip
import hashlib
import os
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256(ruta, bloque=1024 * 1024):
    h = hashlib.sha256()
    with open(ruta, 'rb') as f:
        for chunk in iter(lambda: f.read(bloque), b''):
            h.update(chunk)
    return h.hexdigest()


def backup_seguro(ruta_bd, ruta_tmp):
    """Copia consistente aunque haya escrituras concurrentes."""
    origen = sqlite3.connect(f"file:{ruta_bd}?mode=ro", uri=True)
    destino = sqlite3.connect(ruta_tmp)
    with destino:
        origen.backup(destino)
    destino.close()
    origen.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bd', default=os.path.join(BASE_DIR, 'intrusiones_v5.db'))
    ap.add_argument('--retencion', type=int, default=90, help='días a conservar')
    args = ap.parse_args()

    if not os.path.exists(args.bd):
        print(f"[X] No existe {args.bd}. ¿Es la primera ejecución de la v5?")
        sys.exit(1)

    dir_salida = os.path.join(BASE_DIR, 'backups')
    os.makedirs(dir_salida, exist_ok=True)

    marca = datetime.now(timezone.utc).strftime('%Y%m%d')
    destino_gz = os.path.join(dir_salida, f"backup_{os.path.basename(args.bd)}_{marca}.db.gz")
    ruta_tmp = destino_gz + '.tmp'

    backup_seguro(args.bd, ruta_tmp)
    with open(ruta_tmp, 'rb') as f_in, gzip.open(destino_gz, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.remove(ruta_tmp)

    h = sha256(destino_gz)
    with open(destino_gz + '.sha256', 'w', encoding='utf-8') as f:
        f.write(f"{h}  {os.path.basename(destino_gz)}\n")

    # Retención
    corte = time.time() - args.retencion * 86400
    eliminados = 0
    for nombre in os.listdir(dir_salida):
        ruta = os.path.join(dir_salida, nombre)
        if os.path.getmtime(ruta) < corte:
            os.remove(ruta)
            eliminados += 1

    tam = os.path.getsize(destino_gz) / (1024 * 1024)
    print(f"[OK] Backup: {destino_gz} ({tam:.1f} MB)")
    print(f"     SHA-256: {h}")
    if eliminados:
        print(f"     Limpieza: {eliminados} copias anteriores a {args.retencion} días eliminadas")


if __name__ == '__main__':
    main()
