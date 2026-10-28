# Plan de lanzamiento — IDS/IPS-ML v5 (nueva producción)

**Proyecto:** IDS/IPS-ML UNIPAZ
**Documento de origen:** `heuristica.md` (post-mortem de la v1)
**Estado:** plan aprobado, en ejecución (C1 → C2 → C3 → C4)
**Fecha:** 2026-10-28

---

## 1. Contexto

La instalación anterior (v1) generó **18.244 alertas de "Escaneo de Puertos" en 191 h**, sin
evidencia asociada y sin respaldo del modelo ML. Esa instalación **ya no existe**: no hay
producción viva ni histórico que migrar. La base `intrusiones.db` que queda en el repositorio
proviene del **servidor de prueba** y se conserva únicamente como rastro.

Por tanto, este plan no es una corrección incremental: es el **diseño y lanzamiento de una
nueva producción**, con la métrica correcta desde el primer paquete capturado.

### Decisiones de lanzamiento

| # | Decisión | Implicación |
|---|---|---|
| 1 | Misma red, mismo equipo y mismo sensor (UNIPAZ: 172.10/172.20/172.30) | Los umbrales internos y la lista de exenciones siguen siendo válidos; la comparación v1↔v2 es limpia |
| 2 | Base de datos nueva (`intrusiones_v5.db`); la antigua se archiva | Esquema limpio, sin `ALTER TABLE` heredados; la BD de prueba se archiva con hash para auditoría |
| 3 | 72 h de observación y 1 semana antes de activar el IPS | El umbral se fija con percentiles medidos, no a ojo |

---

## 2. Post-mortem de la v1 (medido, no estimado)

Fuente: `alertas_sospechosas_falso_positivo.csv` (18.288 filas, 2026-08-21 → 2026-10-28).

| Métrica | Valor |
|---|---:|
| Alertas de escaneo | 18.244 |
| IPs origen distintas | 168 |
| IPs que concentran el 80 % del ruido | **23** |
| Origen interno (172.x) | 3.755 (**20,6 %**) |
| Origen externo | 14.489 (79,4 %) |
| Alertas con `confianza_ml > 0` | **0** |
| Pico diario (27-oct) | 4.468 |
| Mediana entre alertas de `34.117.41.85` | **30,0 s** (es el throttle, no un escaneo) |
| Filas con `puerto` textual (`Múltiples`) | 18.264 (100 % de los escaneos) |

### Efecto medido de una lista de exenciones

| Exención | Alertas eliminadas | % |
|---|---:|---:|
| DNS públicos (8.8.8.8, 1.1.1.1…) | 922 | 5,1 % |
| `34.117.0.0/16` (Google LB) | 6.310 | 34,6 % |
| `149.154.0.0/16` (Telegram) | 2.055 | 11,3 % |
| `57.144.0.0/16` (Meta) | 1.711 | 9,4 % |
| **Total CDN/DNS** | **~11.000** | **~60 %** |

### Causas raíz (cuatro defectos independientes)

1. **Conteo global por IP origen**, no por `(origen, destino)`.
2. **Sin ventana temporal**: el conjunto de puertos nunca caduca, así que cualquier host activo
   acaba superando el umbral.
3. **La evidencia se destruye al alertar**: se persiste la cadena `"Múltiples"` en lugar de
   `n_puertos`, la lista de puertos y la ventana usada.
4. **Sin lista blanca**: `8.8.8.8`, declarado en `IPS_CONFIABLES`, generó 709 alertas porque el
   detector nunca consultaba esa lista.

### Hallazgos adicionales (no recogidos en `heuristica.md`)

| # | Hallazgo | Efecto |
|---|---|---|
| A | `RANGOS_CONFIABLES` incluye `172.16.0.0/12`, que contiene 172.20 y 172.30 | Aplicar la whitelist "ingenua" cegaría el **20,6 %** del tráfico interno (escaneo lateral) |
| B | `flags != 'A'` cuenta respuestas `RST`/`SA` de servidores | Un servidor que rechaza conexiones parece un escáner |
| C | El throttle es por IP y compartido entre todos los detectores | Un escaneo silencia 30 s un SQLi/DDoS de la misma IP; además se marca antes del INSERT y se pierde la alerta si el INSERT falla |
| D | `paquetes_por_ip` se indexa por `src` en SYN flood y por `dst` en DDoS/UDP flood | Contaminación cruzada de contadores |
| E | El export diario sale de `deque(maxlen=10000)` | Truncamiento silencioso: todos los CSV de `evidencia/` tienen exactamente 10.000 filas |
| F | Dos variantes de `tipo_ataque` por encoding (`Heuristica` / `Heur�stica`) | 521 filas históricas mal clasificadas |

---

## 3. Diseño de la v5

### 3.1 Esquema `ataques`

```sql
CREATE TABLE ataques (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_utc         TEXT    NOT NULL,
  timestamp      TEXT,
  tipo_ataque    TEXT    NOT NULL,
  origen         TEXT    NOT NULL,            -- 'heuristica' | 'ml' | 'ml+sqliguard'
  ip_src         TEXT    NOT NULL,
  ip_dst         TEXT    NOT NULL,
  protocolo      TEXT,
  puerto         INTEGER DEFAULT 0,           -- 0 = evento agregado
  n_puertos      INTEGER DEFAULT 0,
  n_destinos     INTEGER DEFAULT 0,
  ventana_s      INTEGER DEFAULT 0,
  umbral         INTEGER DEFAULT 0,
  confianza_ml   REAL    DEFAULT 0.0,
  features_json  TEXT,
  evidencia_json TEXT,
  modo           TEXT    DEFAULT 'observacion',
  version_motor  TEXT,
  run_id         TEXT,
  vlan_id        INTEGER DEFAULT 0,
  ttl            INTEGER DEFAULT 0,
  packet_size    INTEGER DEFAULT 0
);
```

Índices: `(ts_utc)`, `(tipo_ataque, ts_utc)`, `(ip_src, ts_utc)`, `(run_id)`.

Los campos `umbral`, `ventana_s`, `version_motor` y `run_id` permiten **reproducir la decisión**
que produjo cada alerta.

### 3.2 Parámetros (configurables por entorno)

| Constante | Env | Defecto | Significado |
|---|---|---:|---|
| `PORT_SCAN_WINDOW_S` | `IDS_SCAN_WINDOW` | 60 | Ventana corta de detección |
| `PORT_SCAN_THRESHOLD` | `IDS_SCAN_THRESHOLD` | 50 | Puertos distintos a un destino externo |
| `PORT_SCAN_THRESHOLD_INTERNAL` | `IDS_SCAN_THRESHOLD_INT` | 25 | Puertos distintos a un destino interno |
| `PORT_SCAN_MIN_DESTINOS` | `IDS_SCAN_MIN_DST` | 20 | Barrido horizontal |
| `PORT_SCAN_WINDOW_LENTA_S` | `IDS_SCAN_WINDOW_SLOW` | 300 | Ventana para escaneos `-T1/-T2` |
| `PORT_SCAN_THRESHOLD_LENTA` | `IDS_SCAN_THRESHOLD_SLOW` | 80 | Umbral de la ventana lenta |
| `IDS_MODO_OBSERVACION` | `IDS_MODO_OBSERVACION` | `1` | Persiste sin alertar ni bloquear |
| `PORT_SCAN_COOLDOWN_PAR` | `IDS_SCAN_COOLDOWN` | 120 | Enfriamiento por par tras alertar (un barrido largo cruza el umbral varias veces al vaciarse la ventana) |
| `THROTTLE_PERSISTENCIA_FLOOD` | — | 10 s | Persistencia mínima entre eventos flood (un `nmap -sS` también dispara SYN Flood) |

### 3.3 Reglas que la v2 no puede violar

| Regla | Defecto que corrige |
|---|---|
| Contar por `(src, dst)` en ventana deslizante | Acumulación histórica |
| Exenciones **explícitas** de CDN/DNS, nunca rangos internos | Cegar el 20,6 % interno |
| Aceptar iniciación (`'A' not in flags and 'R' not in flags`) | Respuestas contadas como escaneo; pérdida de `-sF/-sN/-sX` |
| Throttle por `(ip, tipo)` y posterior al INSERT | Pérdida de alertas y bloqueo cruzado entre detectores |
| Contadores separados SYN flood / flood por destino | Contaminación cruzada |
| EWMA desactivado en escaneo | Umbral a 200 en hora punta |
| Persistir siempre; limitar solo la notificación | Evidencia destruida |
| Export desde SQLite | Truncamiento a 10.000 filas |

### 3.4 Evidencia persistida por alerta

```json
{
  "heuristic": "port_scan_vertical",
  "n_distinct_ports": 137,
  "threshold": 50,
  "window_s": 60,
  "ports_sample": [21, 22, 23, 80, 443, 445, 3389],
  "tcp_init_packets": 220,
  "ignored_ack_or_rst": 0,
  "policy": "v5"
}
```

---

## 4. Fases y puertas de salida

### C1 — Esquema v5, persistencia y archivo de la BD anterior

* `intrusiones_v5.db` con el esquema de §3.1.
* `guardar_ataque()` ampliada: `n_puertos`, `n_destinos`, `ventana_s`, `umbral`,
  `meta_heuristica`, `modo`, `forzar`.
* Throttle por `(ip, tipo)`, aplicado a la notificación y al bloqueo, **no** a la persistencia.
* `ts_utc` ISO-8601; se conserva `timestamp` legible para la interfaz.
* Export diario desde SQLite (`interfasc.py`), no desde memoria.
* `scripts/archivar_bd.py` + `scripts/backup_bd.py`.

**Puerta:** 10 min de captura en observación con
`SELECT COUNT(*) FROM ataques WHERE origen='heuristica' AND evidencia_json IS NULL` = 0.

### C2 — Detector de escaneo rediseñado

* Ventana deslizante por `(src, dst)`; ventana rápida y lenta.
* Detección horizontal por `(src, puerto) → destinos`.
* Exenciones explícitas CDN/DNS; umbral interno/externo; EWMA desactivado.
* Purga por tiempo y tope de claves (sin fugas de memoria).
* Separación de contadores de SYN flood y DDoS.
* `tests/test_portscan.py` con paquetes sintéticos.

**Puerta:** 6/6 tests + pruebas `nmap` (vertical, stealth, horizontal) + negativos
(`curl`, RST masivos, tráfico lento).

### C3 — Observación real (72 h) y calibración

* `IDS_MODO_OBSERVACION=1`, Telegram silenciado, IPS off.
* `scripts/calibrar_escaneo.py`: P50/P90/P95/P99 por segmento y hora.
* `scripts/analizar_produccion.py`: reproduce el post-mortem y el efecto de cada política.

**Puerta:** informe con percentiles y umbral propuesto = P99 + margen.

### C4 — Apertura de alertas y activación del IPS

* Umbral aprobado → alertas ON, IPS OFF durante 24 h.
* Revisión manual de 100 alertas (FP < 5 %).
* IPS ON con *readback* de MikroTik.

---

## 5. Pruebas de aceptación

```bash
nmap -sS -p 1-1000 172.10.x.x     # 1 alerta vertical
nmap -sF -p 1-100           # 1 alerta (stealth, no solo SYN)
nmap -p 445 172.10.0.0/24    # 1 alerta horizontal
nmap -sS -p 1-100 172.20.x.x # 1 alerta (interno: NO exento)
curl https://google.com      # 0 alertas
# 50 RST/SA desde un servidor # 0 alertas
# 45 puertos en 10 minutos     # 0 alertas
```

---

## 6. Red de seguridad

| Síntoma en las primeras 24 h | Acción |
|---|---|
| > 50 alertas/día | `IDS_MODO_OBSERVACION=1` + reinicio |
| Bloqueo a CDN/DNS | `IDS_IPS_AUTONOMO=0` inmediato |
| BD lenta o bloqueada | `backup_bd.py` + reinicio |
| Duda sobre un dato histórico | La BD archivada sigue íntegra con hash verificado |

---

## 7. Criterios de éxito

| Métrica | v1 | v5 (objetivo) |
|---|---:|---:|
| Alertas de escaneo/día | 4.468 (pico) | **< 20** |
| Alertas sin evidencia | 100 % | **0 %** |
| Alertas sin respaldo ML | 99,8 % | < 70 % |
| Detección `nmap` vertical/horizontal | parcial | **100 %** |
| Tiempo de triaje por alerta | imposible | **< 1 min** |

---

## 8. Anexo — Privacidad

`alertas_sospechosas_falso_positivo.csv` contiene direcciones internas reales. Para publicación o
versionado se usa una copia **anonimizada** (`IN-001`, `EX-001`…) y se conserva el SHA-256 del
original, conforme a `docs/informe_privacidad_ips.md`.
