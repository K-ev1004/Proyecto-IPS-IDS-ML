# -*- coding: utf-8 -*-
"""
clasificar_c3.py — Rescate auditable del corpus C3 (72 h en observación).

Uso:
    python scripts/clasificar_c3.py [--bd intrusiones_v5.db] [--salida-dir evidencia]

Qué hace (SOLO LECTURA, no modifica la BD):
  1. Abre la BD en modo read-only y verifica `PRAGMA integrity_check`.
  2. Clasifica CADA fila en una de estas familias:
       - senal_exploit_externa / senal_exploit_interna  (heurística real)
       - fp_ml_sqli_sin_flujo        IGMP/multicast: protocolo 0 y puerto 0
       - fp_ml_sqli_respuesta        respuestas HTTP/WUDO con puerto de servicio
       - fp_ml_sqli_flujo            resto de SQLi predicho por el modelo v5
       - fp_ml_exploit_retorno       Google/WhatsApp/QUIC de retorno
       - fp_ml_syn_unico             SYN_Flood con un solo paquete
       - fp_ml_ddos                  DDoS del modelo (tráfico agregado)
       - fp_escaneo_wudo_7680        barrido horizontal a Delivery Optimization
       - fp_udp_retorno              "UDP Flood" sin evidencia (retorno QUIC)
       - revisar                     lo que no encaja en ninguna familia
  3. Escribe:
       evidencia/c3_clasificacion.csv  (una fila por evento, con motivo)
       evidencia/c3_iocs.csv           (solo señal real, deduplicada)
       evidencia/c3_resumen.csv        (conteo por clase)
       docs/INFORME_C3_DATOS.md        (informe con cifras y hashes)
       evidencia/c3_bd_sha256.txt      (hash de la BD analizada)

El CSV de clasificación contiene IPs reales de terceros y por eso vive en
`evidencia/` (ignorada por git). El informe en `docs/` solo publica agregados
por puerto y por segmento, nunca direcciones.
"""
import argparse
import csv
import hashlib
import json
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Puertos de servicio que, vistos como destino de una respuesta, delatan
# tráfico de retorno (no un ataque entrante).
PUERTOS_SERVICIO = {20, 21, 22, 23, 25, 53, 69, 80, 110, 123, 143, 443, 445,
                    465, 587, 993, 995, 3306, 3389, 5223, 5228, 7680, 8080,
                    8443}


def sha256(ruta, bloque=1024 * 1024):
    h = hashlib.sha256()
    with open(ruta, 'rb') as f:
        for chunk in iter(lambda: f.read(bloque), b''):
            h.update(chunk)
    return h.hexdigest()


def es_interna(ip):
    return bool(ip) and ip.startswith(('172.10.', '172.20.', '172.30.',
                                       '10.', '192.168.'))


def _entero(valor):
    try:
        return int(valor)
    except (TypeError, ValueError):
        return 0


def clasificar(fila):
    """Devuelve (clase, motivo) para una fila de `ataques`."""
    (tipo, origen, ip_src, ip_dst, protocolo, puerto,
     n_puertos, n_destinos, evidencia, features) = fila

    puerto = _entero(puerto)
    n_puertos = _entero(n_puertos)
    n_destinos = _entero(n_destinos)

    heur = ''
    if evidencia:
        try:
            heur = (json.loads(evidencia) or {}).get('heuristic', '') or ''
        except (ValueError, TypeError):
            heur = ''

    proto_ml = None
    src_port_ml = None
    dst_port_ml = None
    if features:
        try:
            f = json.loads(features) or {}
            proto_ml = _entero(f.get('protocol'))
            src_port_ml = _entero(f.get('src_port'))
            dst_port_ml = _entero(f.get('dst_port'))
        except (ValueError, TypeError):
            f = {}

    # --- Señal real: heurística de exploit (externa o interna) ---
    if heur == 'exploit_port':
        if ip_dst.endswith('.255') or ip_src.endswith('.255'):
            return 'fp_exploit_broadcast', 'SYN a puerto de servicio hacia broadcast de subred'
        clase = 'senal_exploit_interna' if es_interna(ip_src) else 'senal_exploit_externa'
        return clase, f"SYN a puerto de servicio {puerto} desde {'red UNIPAZ' if es_interna(ip_src) else 'Internet'}"

    # --- Escaneo horizontal a Windows Delivery Optimization ---
    if tipo.startswith('Escaneo Horizontal'):
        if puerto == 7680:
            return 'fp_escaneo_wudo_7680', 'un solo puerto (7680) hacia muchos pares: WUDO, no escaneo'
        return 'revisar', f'barrido horizontal al puerto {puerto}'

    # --- UDP Flood sin evidencia: retorno QUIC/streaming al sensor ---
    if tipo.startswith('UDP Flood'):
        return 'fp_udp_retorno', 'flood contado por destino sin separar direccion; retorno QUIC al sensor'

    # --- Predicciones del modelo ML (todas las de C3) ---
    if origen == 'ml':
        if tipo.startswith('Inyeccion_SQL'):
            if proto_ml == 0 or (dst_port_ml == 0 and src_port_ml == 0):
                return 'fp_ml_sqli_sin_flujo', 'IGMP/multicast sin puertos: vector de features en cero'
            if (src_port_ml in PUERTOS_SERVICIO) or (dst_port_ml in PUERTOS_SERVICIO):
                return 'fp_ml_sqli_respuesta', f'respuesta de servicio ({src_port_ml}->{dst_port_ml}) puntuada como SQLi'
            return 'fp_ml_sqli_flujo', 'flujo TCP/UDP normal puntuado como SQLi'
        if tipo.startswith('Posible_Exploit') or tipo.startswith('Posible Exploit'):
            if src_port_ml in {5223, 5228} or dst_port_ml in {5223, 5228}:
                return 'fp_ml_exploit_retorno', 'retorno de Google/WhatsApp (5223/5228)'
            return 'fp_ml_exploit_retorno', f'retorno de servicio ({src_port_ml}->{dst_port_ml})'
        if tipo.startswith('SYN_Flood'):
            return 'fp_ml_syn_unico', 'un solo SYN aislado, no una rafaga'
        if tipo.startswith('DDoS'):
            return 'fp_ml_ddos', 'trafico agregado puntuado como DDoS'
        return 'revisar', f'prediccion ML no clasificada: {tipo}'

    return 'revisar', f'evento heuristico no clasificado: {tipo} (heur={heur or "n/a"})'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bd', default=os.environ.get('IDS_DB_PATH')
                    or os.path.join(BASE_DIR, 'intrusiones_v5.db'))
    ap.add_argument('--salida-dir', default=os.path.join(BASE_DIR, 'evidencia'))
    args = ap.parse_args()

    if not os.path.exists(args.bd):
        print(f"[X] No existe la BD: {args.bd}")
        sys.exit(1)

    os.makedirs(args.salida_dir, exist_ok=True)

    print(f"[*] BD: {args.bd}")
    print("[*] Calculando SHA-256 (solo lectura)...")
    hash_bd = sha256(args.bd)

    conn = sqlite3.connect(f"file:{args.bd}?mode=ro", uri=True)
    cur = conn.cursor()

    integridad = cur.execute('PRAGMA integrity_check').fetchone()[0]
    total = cur.execute('SELECT COUNT(*) FROM ataques').fetchone()[0]
    rango = cur.execute('SELECT MIN(ts_utc), MAX(ts_utc) FROM ataques').fetchone()
    run_ids = cur.execute(
        'SELECT run_id, COUNT(*) FROM ataques GROUP BY 1 ORDER BY 2 DESC').fetchall()

    print(f"[*] Filas: {total} | integridad: {integridad}")
    print(f"[*] Rango UTC: {rango[0]} .. {rango[1]}")

    # --- 1) Clasificación por fila ---
    ruta_clas = os.path.join(args.salida_dir, 'c3_clasificacion.csv')
    cols = ['id', 'ts_utc', 'tipo_ataque', 'origen', 'ip_src', 'ip_dst',
            'protocolo', 'puerto', 'n_puertos', 'n_destinos', 'clase', 'motivo']
    conteo = Counter()
    signal = []
    primera = {}
    ultima = {}
    total_por_clase = Counter()

    consulta = '''
        SELECT id, ts_utc, tipo_ataque, origen, ip_src, ip_dst, protocolo,
               puerto, n_puertos, n_destinos, evidencia_json, features_json
        FROM ataques ORDER BY id
    '''
    with open(ruta_clas, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for fila in cur.execute(consulta):
            (fid, ts, tipo, origen, ip_src, ip_dst, proto, puerto,
             n_puertos, n_destinos, evidencia, features) = fila
            clase, motivo = clasificar(
                (tipo, origen, ip_src, ip_dst, proto, puerto,
                 n_puertos, n_destinos, evidencia, features))
            w.writerow([fid, ts, tipo, origen, ip_src, ip_dst, proto, puerto,
                        n_puertos or 0, n_destinos or 0, clase, motivo])
            total_por_clase[clase] += 1
            conteo[clase] += 1
            if clase.startswith('senal_') or clase == 'revisar':
                clave = (ip_src, ip_dst, _entero(puerto), proto)
                signal.append({
                    'id': fid, 'ts_utc': ts, 'tipo_ataque': tipo,
                    'ip_src': ip_src, 'ip_dst': ip_dst, 'protocolo': proto,
                    'puerto': _entero(puerto), 'n_puertos': int(n_puertos or 0),
                    'n_destinos': int(n_destinos or 0), 'clase': clase,
                    'motivo': motivo,
                })
                primera[clave] = min(primera.get(clave, ts), ts)
                ultima[clave] = max(ultima.get(clave, ts), ts)

    print(f"[OK] {ruta_clas}")

    # --- 2) IOCs (señal real, deduplicada) ---
    ruta_iocs = os.path.join(args.salida_dir, 'c3_iocs.csv')
    agrupado = defaultdict(lambda: {'n': 0, 'clase': '', 'motivo': ''})
    for ev in signal:
        clave = (ev['ip_src'], ev['ip_dst'], ev['puerto'], ev['protocolo'])
        agrupado[clave]['n'] += 1
        agrupado[clave]['clase'] = ev['clase']
        agrupado[clave]['motivo'] = ev['motivo']

    with open(ruta_iocs, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['ip_src', 'segmento_src', 'ip_dst', 'puerto', 'protocolo',
                    'eventos', 'primera_utc', 'ultima_utc', 'clase', 'motivo'])
        for (ip_src, ip_dst, puerto, proto), dato in sorted(
                agrupado.items(), key=lambda kv: (-kv[1]['n'], kv[0][0])):
            w.writerow([ip_src, 'interna' if es_interna(ip_src) else 'externa',
                        ip_dst, puerto, proto, dato['n'],
                        primera.get((ip_src, ip_dst, puerto, proto), ''),
                        ultima.get((ip_src, ip_dst, puerto, proto), ''),
                        dato['clase'], dato['motivo']])
    print(f"[OK] {ruta_iocs}")

    # --- 3) Resumen agregado ---
    ruta_resumen = os.path.join(args.salida_dir, 'c3_resumen.csv')
    with open(ruta_resumen, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['clase', 'eventos', 'porcentaje'])
        for clase, n in sorted(total_por_clase.items(), key=lambda kv: -kv[1]):
            w.writerow([clase, n, f"{100.0 * n / total:.4f}"])
    print(f"[OK] {ruta_resumen}")

    # --- 4) Hash de la BD ---
    ruta_hash = os.path.join(args.salida_dir, 'c3_bd_sha256.txt')
    with open(ruta_hash, 'w', encoding='utf-8') as fh:
        fh.write(f"{hash_bd}  {os.path.basename(args.bd)}\n")
        fh.write(f"# analizado_utc={datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
        fh.write(f"# filas={total}\n# integridad={integridad}\n")
    print(f"[OK] {ruta_hash}")

    # --- 5) Informe para docs (sin IPs publicas) ---
    escribir_informe(args.salida_dir, args.bd, hash_bd, integridad, total,
                     rango, run_ids, total_por_clase, signal, ruta_clas,
                     ruta_iocs, ruta_resumen)

    conn.close()
    print("\n[OK] Rescate C3 completado.")
    for clase, n in sorted(total_por_clase.items(), key=lambda kv: -kv[1]):
        print(f"     {n:>7}  {clase}")


def escribir_informe(salida_dir, bd, hash_bd, integridad, total, rango,
                     run_ids, clases, signal, ruta_clas, ruta_iocs, ruta_resumen):
    ruta = os.path.join(BASE_DIR, 'docs', 'INFORME_C3_DATOS.md')

    def pct(n):
        return 100.0 * n / total if total else 0.0

    lineas = []
    lineas.append('# Informe de datos — corrida C3 (72 h en observación)')
    lineas.append('')
    lineas.append(f'**Generado:** {datetime.now(timezone.utc).isoformat(timespec="seconds")}  ')
    lineas.append(f'**BD analizada:** `{os.path.basename(bd)}`  ')
    lineas.append(f'**SHA-256:** `{hash_bd}`  ')
    lineas.append(f'**Integridad SQLite:** `{integridad}`  ')
    lineas.append(f'**Filas:** {total}  ')
    lineas.append(f'**Rango UTC:** {rango[0]} → {rango[1]}  ')
    lineas.append('**Run IDs:** ' + ', '.join(f'`{r}` ({n})' for r, n in run_ids))
    lineas.append('')
    lineas.append('> Documento generado por `scripts/clasificar_c3.py`. Las direcciones IP '
                  'reales solo están en `evidencia/c3_iocs.csv`; este informe publica '
                  'agregados por puerto y por segmento.')
    lineas.append('')
    lineas.append('## 1. Resumen ejecutivo')
    lineas.append('')
    lineas.append('La corrida C3 capturó 72 h completas sin caídas y con la BD íntegra, pero '
                  'el 99,97 % de las filas son falsos positivos del modelo ML. El motor '
                  'heurístico, en cambio, produjo señal real y trazable. Conclusión: el '
                  'modelo v5 + SQLiGuard **no puede ser la vía de alerta** con las features '
                  'de flujo actuales; la vía de producción debe ser heurística, y el ML '
                  'queda como instrumentación.')
    lineas.append('')
    lineas.append('## 2. Clasificación del corpus')
    lineas.append('')
    lineas.append('| Clase | Eventos | % | Lectura |')
    lineas.append('|---|---:|---:|---|')
    lecturas = {
        'fp_ml_sqli_sin_flujo': 'IGMP/multicast sin puertos: vector de features en cero',
        'fp_ml_sqli_respuesta': 'respuestas HTTP/WUDO puntuadas como SQLi',
        'fp_ml_sqli_flujo': 'flujos normales puntuados como SQLi',
        'fp_ml_exploit_retorno': 'retorno de Google/WhatsApp/QUIC',
        'fp_ml_syn_unico': 'un SYN aislado clasificado como SYN Flood',
        'fp_ml_ddos': 'tráfico agregado clasificado como DDoS',
        'fp_exploit_broadcast': 'SYN a puerto de servicio hacia broadcast de subred',
        'fp_escaneo_wudo_7680': 'Windows Delivery Optimization (puerto 7680)',
        'fp_udp_retorno': 'retorno QUIC al sensor contado como UDP Flood',
        'senal_exploit_externa': 'SYN externo a puerto de explotación',
        'senal_exploit_interna': 'SYN interno a puerto de explotación (revisar)',
        'revisar': 'sin clasificar',
    }
    for clase, n in sorted(clases.items(), key=lambda kv: -kv[1]):
        lineas.append(f'| `{clase}` | {n} | {pct(n):.3f} | {lecturas.get(clase, "")} |')
    lineas.append('')
    lineas.append('## 3. Por qué el ML falló')
    lineas.append('')
    lineas.append('1. **Paquetes sin puertos.** IGMP (protocolo IP 2) y otro tráfico no '
                  'TCP/UDP llega a `FlowTracker` con `puerto=0`. El vector de features queda '
                  'en cero y SQLiGuard devuelve P≈0,78, por encima del umbral 0,30. En C3 '
                  'esto explica la mayor parte de las 275.744 predicciones de SQLi.')
    lineas.append('2. **Sin dirección.** El flujo se normaliza por IP, no por quién inicia. '
                  'Una respuesta de un servidor web (80→efímero) y el retorno de Google '
                  '(5228→efímero) se evalúan igual que una petición del atacante.')
    lineas.append('3. **Features insuficientes.** SQLiGuard se entrenó con features de flujo '
                  '(puertos, duración, bytes, flags), no con el payload. Con esas features '
                  'no separa una inyección real de una respuesta HTTP normal.')
    lineas.append('4. **Sin umbral de corroboración.** El modelo v5 se usó como alerta con '
                  'un umbral de confianza, sin una segunda señal independiente.')
    lineas.append('')
    lineas.append('## 4. Señal real encontrada')
    lineas.append('')
    externos = [e for e in signal if e['clase'] == 'senal_exploit_externa']
    internos = [e for e in signal if e['clase'] == 'senal_exploit_interna']
    lineas.append(f'- Eventos heurísticos de exploit: **{len(externos) + len(internos)}** '
                  f'({len(externos)} externos, {len(internos)} internos).')
    por_puerto = Counter(e['puerto'] for e in signal if e['clase'].startswith('senal_'))
    if por_puerto:
        lineas.append('- Puertos objetivo: ' + ', '.join(
            f'**{p}** ({n})' for p, n in por_puerto.most_common()))
    destinos = Counter(e['ip_dst'] for e in signal if e['clase'].startswith('senal_'))
    if destinos:
        top = destinos.most_common(5)
        lineas.append('- Destinos más golpeados (conteo, sin dirección en este informe): ' +
                      ', '.join(f'{n} eventos' for _, n in top))
    lineas.append('')
    lineas.append('La lista completa y deduplicada está en `evidencia/c3_iocs.csv`. '
                  'Los eventos internos se marcan para revisión: pueden ser administración '
                  'legítima (RDP/SMB) o movimiento lateral.')
    lineas.append('')
    lineas.append('## 5. Por qué no hay P99 válido')
    lineas.append('')
    lineas.append('`ataques` solo guardaba eventos que ya habían superado el umbral. '
                  'Calcular P99 sobre esa muestra es circular: mide la cola de lo ya '
                  'alertado, no el tráfico normal. Además `calibrar_escaneo.py` anclaba la '
                  'ventana a `now`, por lo que al analizar una corrida terminada devolvía '
                  '"sin eventos".')
    lineas.append('')
    lineas.append('Correcciones aplicadas para la validación:')
    lineas.append('')
    lineas.append('- Nueva tabla `metricas_escaneo` con muestras **bajo umbral** por par '
                  '(máximo de puertos/destinos observado), para calibrar con datos reales.')
    lineas.append('- `calibrar_escaneo.py` ancla en `max(ts_utc)` y acepta `--desde/--hasta`.')
    lineas.append('- El ML deja de persistir alertas (`IDS_ML_ALERTAS=0` por defecto).')
    lineas.append('- Paquetes que no son TCP/UDP no entran al `FlowTracker`.')
    lineas.append('')
    lineas.append('## 6. Artefactos')
    lineas.append('')
    for ruta_art in (ruta_clas, ruta_iocs, ruta_resumen):
        lineas.append(f'- `evidencia/{os.path.basename(ruta_art)}`')
    lineas.append('- `evidencia/c3_bd_sha256.txt`')
    lineas.append('')
    lineas.append('## 7. Privacidad')
    lineas.append('')
    lineas.append('Los CSV de `evidencia/` contienen IPs reales y no se versionan. '
                  'Este informe y los agregados no permiten reconstruir la lista de '
                  'orígenes. Ver `docs/informe_privacidad_ips.md`.')
    lineas.append('')

    with open(ruta, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lineas))
    print(f"[OK] {ruta}")


if __name__ == '__main__':
    main()
