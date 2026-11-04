# -*- coding: utf-8 -*-
"""
corrida_observacion.py — Motor IDS/IPS en modo observación, para servidores.

Diseñado para correr 24/7 sin GUI (tarea programada / consola):

    set IDS_RUN_ID=obs-c3-20261028
    python scripts/corrida_observacion.py

- Usa la interfaz de `IDS_IFACE` (o la por defecto de Scapy).
- Termina solo tras `IDS_DURACION_H` horas (0 o vacío = hasta Ctrl+C).
- Escribe una línea de estado cada hora (prueba de vida): pps, ventanas
  activas y eventos en BD. SQLite confirma cada inserción: un corte de luz
  no corrompe nada.
- Al salir imprime un resumen de la corrida por tipo de evento.
"""
import os
import sys
import time
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import ids  # noqa: E402

ESTADO_CADA_S = 3600  # estado horario


def _fecha_utc():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def _estado(conn_ids):
    try:
        cur = conn_ids.cursor()
        total, con_evid, con_feat = cur.execute(
            "SELECT COUNT(*), "
            "       SUM(evidencia_json IS NOT NULL), "
            "       SUM(features_json IS NOT NULL) "
            "FROM ataques").fetchone()
        try:
            muestras = cur.execute(
                "SELECT COUNT(*) FROM metricas_escaneo").fetchone()[0]
        except Exception:
            muestras = -1
        print(f"[{_fecha_utc()}] ESTADO pps~{ids.ewma_pps:.0f} | "
              f"ventanas={len(ids.ventana_scan)} | horizontales={len(ids.barrido_horizontal)} | "
              f"eventos_bd={total} (con_evidencia: {con_evid or 0}, "
              f"con_features: {con_feat or 0}) | muestras_scan={muestras}", flush=True)
    except Exception as e:
        print(f"[!] Estado no disponible: {e}", flush=True)


def _resumen_final(conn_ids, run_id):
    try:
        cur = conn_ids.cursor()
        print("\n===== RESUMEN DE CORRIDA =====", flush=True)
        for origen, tipo, n, modo in cur.execute(
                "SELECT origen, tipo_ataque, COUNT(*), MIN(modo) FROM ataques "
                "WHERE run_id=? GROUP BY origen, tipo_ataque "
                "ORDER BY COUNT(*) DESC", (run_id,)):
            print(f"  {n:>7}  [{modo}]  {origen:<10}  {tipo}", flush=True)
        try:
            muestras = cur.execute(
                "SELECT COUNT(*) FROM metricas_escaneo WHERE run_id=?",
                (run_id,)).fetchone()[0]
            print(f"  {muestras:>7}  muestras de escaneo bajo umbral (metricas_escaneo)",
                  flush=True)
        except Exception:
            pass
        print("==============================", flush=True)
    except Exception as e:
        print(f"[!] Resumen no disponible: {e}", flush=True)


def main():
    iface = os.environ.get('IDS_IFACE', '').strip() or None
    duracion_h = float(os.environ.get('IDS_DURACION_H', '0') or 0)

    print(f"[*] {ids.VERSION_MOTOR} | run_id={ids.RUN_ID} | "
          f"modo_observacion={ids.IDS_MODO_OBSERVACION} | ips_autonomo={ids.modo_ips_autonomo} | "
          f"ml_alertas={ids.ML_ALERTAS} | mi_ip={ids.MI_IP} | "
          f"iface={iface or '(por defecto)'}", flush=True)
    print(f"[*] Umbrales escaneo: externo={ids.PORT_SCAN_THRESHOLD} "
          f"interno={ids.PORT_SCAN_THRESHOLD_INTERNAL} "
          f"horizontal={ids.PORT_SCAN_MIN_DESTINOS} ventana={ids.PORT_SCAN_WINDOW_S}s",
          flush=True)
    print(f"[*] Duración: {'hasta Ctrl+C' if duracion_h <= 0 else f'{duracion_h} h'}", flush=True)

    ids.iniciar_monitoreo(iface=iface)

    fin = (time.time() + duracion_h * 3600) if duracion_h > 0 else None
    proximo_estado = time.time() + 30  # primer estado a los 30 s (verificar captura)

    try:
        while fin is None or time.time() < fin:
            if time.time() >= proximo_estado:
                _estado(ids.conn)
                proximo_estado += ESTADO_CADA_S
            time.sleep(5)
        print(f"\n[*] Duración de {duracion_h} h cumplida.", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Detenido por el operador.", flush=True)
    finally:
        ids.detener_monitoreo()
        _estado(ids.conn)
        _resumen_final(ids.conn, ids.RUN_ID)
        try:
            ids.conn.close()
        except Exception:
            pass


if __name__ == '__main__':
    main()
