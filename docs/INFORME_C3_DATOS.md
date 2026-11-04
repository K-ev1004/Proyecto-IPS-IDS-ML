# Informe de datos — corrida C3 (72 h en observación)

**Generado:** 2026-11-04T16:17:33+00:00  
**BD analizada:** `intrusiones_v5.db`  
**SHA-256:** `387bffd88cc16666a0643fd603f2732e057d2e10fe9a9b3ce8260a7476064bb2`  
**Integridad SQLite:** `ok`  
**Filas:** 276098  
**Rango UTC:** 2026-10-28T17:18:15+00:00 → 2026-10-31T17:18:09+00:00  
**Run IDs:** `obs-c3-20261028` (276098)

> Documento generado por `scripts/clasificar_c3.py`. Las direcciones IP reales solo están en `evidencia/c3_iocs.csv`; este informe publica agregados por puerto y por segmento.

## 1. Resumen ejecutivo

La corrida C3 capturó 72 h completas sin caídas y con la BD íntegra, pero el 99,97 % de las filas son falsos positivos del modelo ML. El motor heurístico, en cambio, produjo señal real y trazable. Conclusión: el modelo v5 + SQLiGuard **no puede ser la vía de alerta** con las features de flujo actuales; la vía de producción debe ser heurística, y el ML queda como instrumentación.

## 2. Clasificación del corpus

| Clase | Eventos | % | Lectura |
|---|---:|---:|---|
| `fp_ml_sqli_sin_flujo` | 275102 | 99.639 | IGMP/multicast sin puertos: vector de features en cero |
| `fp_ml_sqli_respuesta` | 641 | 0.232 | respuestas HTTP/WUDO puntuadas como SQLi |
| `fp_ml_exploit_retorno` | 257 | 0.093 | retorno de Google/WhatsApp/QUIC |
| `senal_exploit_externa` | 65 | 0.024 | SYN externo a puerto de explotación |
| `fp_udp_retorno` | 12 | 0.004 | retorno QUIC al sensor contado como UDP Flood |
| `fp_escaneo_wudo_7680` | 9 | 0.003 | Windows Delivery Optimization (puerto 7680) |
| `fp_ml_syn_unico` | 5 | 0.002 | un SYN aislado clasificado como SYN Flood |
| `senal_exploit_interna` | 4 | 0.001 | SYN interno a puerto de explotación (revisar) |
| `fp_ml_sqli_flujo` | 1 | 0.000 | flujos normales puntuados como SQLi |
| `fp_ml_ddos` | 1 | 0.000 | tráfico agregado clasificado como DDoS |
| `fp_exploit_broadcast` | 1 | 0.000 | SYN a puerto de servicio hacia broadcast de subred |

## 3. Por qué el ML falló

1. **Paquetes sin puertos.** IGMP (protocolo IP 2) y otro tráfico no TCP/UDP llega a `FlowTracker` con `puerto=0`. El vector de features queda en cero y SQLiGuard devuelve P≈0,78, por encima del umbral 0,30. En C3 esto explica la mayor parte de las 275.744 predicciones de SQLi.
2. **Sin dirección.** El flujo se normaliza por IP, no por quién inicia. Una respuesta de un servidor web (80→efímero) y el retorno de Google (5228→efímero) se evalúan igual que una petición del atacante.
3. **Features insuficientes.** SQLiGuard se entrenó con features de flujo (puertos, duración, bytes, flags), no con el payload. Con esas features no separa una inyección real de una respuesta HTTP normal.
4. **Sin umbral de corroboración.** El modelo v5 se usó como alerta con un umbral de confianza, sin una segunda señal independiente.

## 4. Señal real encontrada

- Eventos heurísticos de exploit: **69** (65 externos, 4 internos).
- Puertos objetivo: **23** (30), **3389** (24), **135** (7), **22** (4), **445** (2), **21** (1), **5900** (1)
- Destinos más golpeados (conteo, sin dirección en este informe): 55 eventos, 10 eventos, 2 eventos, 2 eventos

La lista completa y deduplicada está en `evidencia/c3_iocs.csv`. Los eventos internos se marcan para revisión: pueden ser administración legítima (RDP/SMB) o movimiento lateral.

## 5. Por qué no hay P99 válido

`ataques` solo guardaba eventos que ya habían superado el umbral. Calcular P99 sobre esa muestra es circular: mide la cola de lo ya alertado, no el tráfico normal. Además `calibrar_escaneo.py` anclaba la ventana a `now`, por lo que al analizar una corrida terminada devolvía "sin eventos".

Correcciones aplicadas para la validación:

- Nueva tabla `metricas_escaneo` con muestras **bajo umbral** por par (máximo de puertos/destinos observado), para calibrar con datos reales.
- `calibrar_escaneo.py` ancla en `max(ts_utc)` y acepta `--desde/--hasta`.
- El ML deja de persistir alertas (`IDS_ML_ALERTAS=0` por defecto).
- Paquetes que no son TCP/UDP no entran al `FlowTracker`.

## 6. Artefactos

- `evidencia/c3_clasificacion.csv`
- `evidencia/c3_iocs.csv`
- `evidencia/c3_resumen.csv`
- `evidencia/c3_bd_sha256.txt`

## 7. Privacidad

Los CSV de `evidencia/` contienen IPs reales y no se versionan. Este informe y los agregados no permiten reconstruir la lista de orígenes. Ver `docs/informe_privacidad_ips.md`.
