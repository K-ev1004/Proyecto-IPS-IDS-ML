# Análisis de falsos positivos en la heurística de Escaneo de Puertos

**Proyecto:** IDS/IPS-ML UNIPAZ — `ids.py` v3
**Base de datos analizada:** `intrusiones.db` (18.550 alertas, ~191 h de captura continua)
**Alcance de este documento:** diagnóstico y propuesta de cambios. **No se ha aplicado ningún cambio al código.**

---

## 1. Resumen ejecutivo

Durante 191 h el motor generó **18.550 alertas**, de las cuales **18.244 (98,35 %) son "Escaneo de Puertos"**. El 99,8 % de todas las alertas no tienen confianza ML (`confianza_ml == 0.0`), es decir, provienen de las heurísticas y no del modelo.

El problema no es solo que el umbral sea bajo: **la heurística está mal diseñada en cuatro puntos independientes** que se refuerzan entre sí:

1. **Cuenta puertos a nivel global por IP origen**, no por destino.
2. **El conjunto de puertos nunca caduca** (no hay ventana temporal), así que cualquier host normal acaba superando el umbral tarde o temprano.
3. **Cuando salta, destruye la evidencia**: guarda literalmente `"Múltiples"` en la columna `puerto`, sin el conteo real ni la lista de puertos, lo que hace imposible auditar o recalibrar a posteriori.
4. **No aplica ninguna lista blanca** (DNS, CDN, proveedores cloud) que el resto de detectores sí aplica.

**Conclusión:** subir el número del umbral por sí solo, manteniendo el conteo global y sin ventana temporal, **no resuelve nada**: solo retrasa el momento en que cada IP vuelve a disparar. Es imprescindible cambiar *cómo se cuenta* antes de decidir *cuánto vale el umbral*.

---

## 2. Situación actual medida

### 2.1 Distribución por tipo de alerta

| Tipo | Alertas | % | Confianza ML |
|---|---:|---:|---|
| Escaneo de Puertos | 18.244 | 98,35 % | 0,0 (heurística) |
| DDoS Distribuido | 217 | 1,17 % | 0,0 (heurística) |
| Posible Exploit | 56 | 0,30 % | 0,0 (heurística) |
| Inyeccion_SQL | 30 | 0,16 % | mixta (ML + SQLiGuard) |
| SYN Flood | 3 | 0,02 % | 0,0 (heurística) |
| **Total** | **18.550** | 100 % | — |

### 2.2 Distribución por confianza ML

| Rango `confianza_ml` | Alertas | Interpretación |
|---|---:|---|
| `== 0.0` | 18.520 | Heurísticas puras (sin score del modelo) |
| `0.0 < c < 0.70` | 1 | Residual |
| `0.70 ≤ c < 0.85` | 1 | Residual (por debajo del umbral de bloqueo) |
| `≥ 0.85` | 28 | **Únicas alertas con respaldo estadístico fuerte** |

### 2.3 Top IPs origen de alertas

| IP | Alertas | Naturaleza |
|---|---:|---|
| `34.117.41.85` | 6.297 | Google (infraestructura) |
| `149.154.166.110` | 2.080 | Telegram |
| `172.10.15.162` | 822 | UNIPAZ (interna) |
| `8.8.8.8` | 715 | DNS Google — **está en `IPS_CONFIABLES`** |
| `172.10.0.79` | 626 | UNIPAZ (interna) |
| `172.10.6.62` | 618 | UNIPAZ (interna) |
| `57.144.60.3` | 505 | Meta / Facebook |
| `57.144.114.3` | 323 | Meta / Facebook |
| `72.153.5.138` | 220 | Cloud (AWS) |
| `172.10.0.154` | 217 | UNIPAZ (interna) |

**Dato clave:** `8.8.8.8` está declarado en `IPS_CONFIABLES` (línea 163) y **aun así generó 715 alertas** de escaneo, porque `detectar_escaneo_puertos()` nunca consulta esa lista. Es la prueba directa de que falta el filtro de confianza.

### 2.4 Otras heurísticas (contexto)

| Heurística | Alertas | Observación |
|---|---:|---|
| DDoS Distribuido | 217 | Concentradas en `172.10.12.216` (106), `172.10.3.99` (32), `172.10.7.170` (30). Orígenes incluyen `149.154.166.110`, `8.8.8.8`, `1.1.1.1`. Sospecha de falso positivo por tráfico CDN/DNS. |
| SYN Flood | 3 | Las tres hacia **puerto 7680** (WUDO de Windows Update). Tráfico legítimo de actualizaciones, no flood. |
| UDP Flood | 0 | Sin casos. |
| Posible Exploit | 56 | `172.10.0.57` (14) y `172.10.0.59` (11) concentran el 45 %. Todas heurísticas. Revisar si son equipos de gestión/monitorización. |
| Inyeccion_SQL | 30 | Dispersas en `172.20.x.x` (subred de docentes). 27 de 30 con `confianza_ml ≥ 0.85`; el pipeline SQLiGuard está funcionando como segunda etapa. |

---

## 3. Problemática 1 — Dónde se pierde la información del escaneo

### 3.1 El síntoma

Cualquier consulta a la BD devuelve esto para todas las alertas de escaneo:

```text
id | tipo_ataque                       | ip_src       | ip_dst       | puerto
27 | 'Escaneo de Puertos (Heurística)' | 172.20.0.1   | DESCONOCIDA  | 'Múltiples'
```

La columna `puerto` es de tipo `INTEGER` en el esquema, pero contiene la cadena `'Múltiples'`. SQLite lo acepta por tipado dinámico, pero **el dato numérico es irrecuperable**.

### 3.2 La causa exacta en el código

**Origen (línea ~723, `detectar_escaneo_puertos`):**

```python
umbral_scan = calcular_umbral_dinamico(BASE_PORT_SCAN_THRESHOLD)
if len(puertos_por_ip[ip_src]) > umbral_scan:
    guardar_ataque(ip_src, "Escaneo de Puertos", "TCP/UDP", "Múltiples", ip_dst)
    if len(puertos_por_ip[ip_src]) > umbral_scan + 20:
         puertos_por_ip[ip_src].clear()
```

En el momento de la alerta **se conoce perfectamente** `len(puertos_por_ip[ip_src])` (el número de puertos distintos) y el propio `set` con la lista completa. Sin embargo:

- se pasa la constante `"Múltiples"` como `puerto`,
- **no se pasa** el conteo,
- **no se pasa** la lista de puertos,
- **no se pasa** la ventana temporal usada,
- **no se pasa** el umbral vigente en ese instante.

**Destino (`guardar_ataque`, líneas ~503-508):**

```python
cursor.execute('''
    INSERT INTO ataques (timestamp, tipo_ataque, ip_src, ip_dst, protocolo, puerto,
                         confianza_ml, features_json, vlan_id, ttl, packet_size)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', (timestamp, tipo_final, ip_src, ip_dst, protocolo, puerto,
      confianza_ml, features_json, vlan_id, ttl, packet_size))
```

`guardar_ataque` no tiene ningún parámetro para recibir metadatos adicionales de la heurística. El único campo libre es `features_json`, y en las alertas heurísticas se envía `None` (el valor por defecto), porque solo el flujo ML lo rellena.

### 3.3 Consecuencia práctica

Sin el conteo real y la lista de puertos:

- **No se puede recalibrar el umbral con datos históricos.** Es la razón por la que el análisis de percentiles sobre la BD no es viable: no hay distribución que calcular, solo un texto constante.
- **No se puede distinguir un escaneo vertical (muchos puertos a un host) de uno horizontal (un puerto a muchos hosts).** Ambos producen el mismo registro.
- **No se puede hacer triaje.** No hay forma de separar una alerta de 41 puertos de una de 500.
- **No se puede auditar una decisión del IPS** en un informe o tesis.

### 3.4 Cambio propuesto (P1)

**Objetivo:** que cada alerta de escaneo sea autosuficiente y auditable, sin romper el esquema existente.

**a) Ampliar `guardar_ataque` con un parámetro opcional de metadatos heurísticos:**

```python
def guardar_ataque(ip_src, tipo_ataque, protocolo, puerto, ip_dst="DESCONOCIDA",
                   flag="N/A", es_ml_puro=False, confianza_ml=0.0, features_json=None,
                   vlan_id=0, ttl=0, packet_size=0, meta_heuristica=None):
    ...
    if features_json is None and meta_heuristica:
        features_json = json.dumps(meta_heuristica)
```

**b) En `detectar_escaneo_puertos`, persistir la evidencia en el momento de la alerta:**

```python
n_puertos = len(puertos_por_ip[ip_src])
if n_puertos > umbral_scan:
    meta = {
        "heuristic": "port_scan",
        "n_distinct_ports": n_puertos,
        "threshold": int(umbral_scan),
        "window_seconds": None,          # None = acumulado histórico (ver Problemática 2)
        "ports_sample": sorted(puertos_por_ip[ip_src])[:50],
        "n_destinations": len(destinos_por_ip[ip_src]) if 'destinos_por_ip' in globals() else None,
        "tcp_syn": ..., "tcp_rst": ..., "tcp_ack_only_ignored": ...,
    }
    guardar_ataque(ip_src, "Escaneo de Puertos", "TCP/UDP", n_puertos, ip_dst,
                   meta_heuristica=meta)
```

**c) Corregir el tipo de la columna (opcional, requiere migración):**

| Opción | Ventaja | Inconveniente |
|---|---|---|
| Guardar el conteo como entero en `puerto` y la lista en `features_json` | Cero cambios de esquema, retrocompatible | `puerto` deja de significar "puerto destino" para esta fila (documentar) |
| Añadir columna `puerto_txt TEXT` para el caso `"Múltiples"` y usar `puerto` solo numérico | Semántica limpia | Requiere `ALTER TABLE` y tocar la interfaz que lee `puerto` |
| Añadir columnas dedicadas `n_puertos INTEGER`, `ventana_s INTEGER`, `destinos INTEGER` | Consultable con SQL directo, ideal para recalibrar | Más columnas que mantener |

**Recomendación:** opción 3 (columnas dedicadas) + `features_json` para el detalle (lista de puertos). Es la única que permite hacer `SELECT n_puertos FROM ataques WHERE ...` para recalibrar umbrales en el futuro.

**d) No aplicar el throttle antes de persistir.** `guardar_ataque` descarta la alerta si la misma IP alertó en los últimos 30 s (`TIEMPO_ENTRE_ALERTAS`, línea 479). Eso significa que **se están perdiendo también eventos legítimos**. Para el modo observación conviene un `guardar_ataque(..., forzar=True)` o una tabla de diagnóstico separada.

---

## 4. Problemática 2 — El umbral y por qué subirlo no basta

### 4.1 Cómo está configurado hoy

```python
BASE_PORT_SCAN_THRESHOLD = 40        # línea 91
BASE_THRESHOLD_DDOS      = 500
BASE_THRESHOLD_UDP_FLOOD = 500
BASE_THRESHOLD_SYN_FLOOD = 50
TIEMPO_ENTRE_ALERTAS     = 30        # throttle por IP
DISCOVERY_PORTS = {5353, 5355, 1900, 137, 138}
```

Y el umbral se escala con EWMA (`calcular_umbral_dinamico`, líneas 100-108):

```python
def calcular_umbral_dinamico(base, max_mult=10.0):
    baseline_esperado = 200.0
    if ewma_pps <= baseline_esperado:
        return base
    factor = min(ewma_pps / baseline_esperado, max_mult)
    return int(base * factor)
```

### 4.2 Los tres defectos del umbral

**Defecto A — El conjunto nunca caduca.**

```python
puertos_por_ip[ip_src].add(f"TCP:{puerto}")
```

No hay `deque` con timestamps ni limpieza periódica. La única limpieza es:

```python
if len(puertos_por_ip[ip_src]) > umbral_scan + 20:
     puertos_por_ip[ip_src].clear()
```

Es decir, el contador se resetea **solo cuando ya ha disparado**, no por tiempo. Consecuencia matemática: **cualquier host que a lo largo de su vida hable con más de 40 puertos distintos —aunque sea uno por día— acaba alertando.** Un puesto de trabajo normal (web 80/443, DNS 53, NTP 123, SMB 445, actualizaciones 7680/8080, telemetría, VPN, impresión 9100, RDP 3389…) supera los 40 puertos distintos en cuestión de días sin hacer nada remotamente parecido a un escaneo.

Esto explica el patrón sostenido: `34.117.41.85` con **6.297 alertas en 191 h** = una alerta cada ~1,8 min durante 8 días seguidos. Es el ciclo `acumula 20 puertos → alerta → limpia → acumula otros 20 → alerta` repitiéndose indefinidamente.

**Defecto B — El conteo es global, no por destino.**

```python
puertos_por_ip[ip_src].add(f"TCP:{puerto}")
```

El `set` no distingue a quién se conecta. Visitar 40 sitios web distintos por el puerto 443 cuenta como **un solo elemento** (`TCP:443`), pero visitar 40 *servicios distintos* de un mismo proveedor (443, 8443, 5228, 5223, 5222, 123, 53, 853…) cuenta como 8. El problema aparece al mezclar destinos: 20 CDNs × 2 puertos cada uno = 40 elementos = alerta, aunque ningún destino individual recibió más de 2 puertos.

**Un escaneo real es vertical**: **un** origen, **un** destino, **muchos** puertos en **pocos segundos**. La implementación actual no modela ninguna de esas tres dimensiones (destino, tiempo, tasa).

**Defecto C — El escalado por EWMA actúa en la dirección equivocada para este detector.**

`calcular_umbral_dinamico` sube el umbral cuando hay mucho tráfico global (`ewma_pps`). Para flood tiene sentido (evitar alertar en hora punta). Pero para escaneo de puertos es discutible: en una red con 5.000 pps el umbral de escaneo pasa de 40 a 200, lo que **oculta escaneos reales** justo cuando hay más tráfico. Además `ewma_pps` es una métrica global de la interfaz, no por host.

### 4.3 Qué hacer con el umbral: procedimiento, no un número

La pregunta "¿cuánto subirlo?" **no tiene respuesta válida mientras no exista la ventana temporal y el conteo por destino**, porque el número correcto depende de la unidad de medida. Con ventanas de distinta duración, "40 puertos" significa cosas completamente distintas.

**Procedimiento recomendado (en este orden):**

| Paso | Acción | Resultado |
|---|---|---|
| 1 | Implementar P1 (persistir `n_puertos`, `n_destinos`, `ventana_s`) | Datos reales de distribución |
| 2 | Añadir ventana temporal (P2) y conteo por destino (P3) | La métrica pasa a significar "puertos distintos a UN destino en N segundos" |
| 3 | Desplegar en **modo observación**: registrar sin alertar ni bloquear durante 24-72 h | Histograma real de la red UNIPAZ |
| 4 | Calcular percentiles por segmento (internos vs externos) | P50, P90, P95, P99 por par (src,dst) |
| 5 | Fijar el umbral por encima del P99 de tráfico normal y por debajo del mínimo de un escaneo real | Umbral justificado con datos, no a ojo |

**Valores de partida razonables** (a validar con el paso 4):

| Parámetro | Valor propuesto | Justificación |
|---|---|---|
| `PORT_SCAN_WINDOW_S` | `60` | Nmap por defecto completa un barrido de 1.000 puertos en segundos; 60 s captura también escaneos lentos tipo `-T2`. |
| `PORT_SCAN_THRESHOLD` | `50` puertos distintos **al mismo destino** en 60 s | Muy por encima del uso normal de un host contra un único servidor (rara vez > 10-15), muy por debajo de un barrido típico (> 100). |
| `PORT_SCAN_THRESHOLD_INTERNAL` | `25` | Tráfico interno legítimo contra un solo host es aún más acotado; permite bajar el umbral sin ruido. |
| `PORT_SCAN_MIN_DESTINOS` (barrido horizontal) | `20` destinos con el **mismo** puerto en 60 s | Detecta `nmap -p 445 172.10.0.0/24`, que el conteo actual no ve. |
| Escalado EWMA para escaneo | **Desactivar** (`calcular_umbral_dinamico` sin uso aquí) | Evita enmascarar escaneos en horas de alto tráfico. |
| `TIEMPO_ENTRE_ALERTAS` para escaneo | Mantener 30 s, pero **persistir siempre** el evento | Evita spam sin perder evidencia. |

> **Nota importante:** el umbral de 40 actual, con conteo global y sin ventana, **no es comparable** con ninguno de los valores de esta tabla. No se debe "subir el 40 a 100" y ya; hay que cambiar la métrica y luego fijar el número.

---

## 5. Problemática 3 — Cómo mejorar la heurística (rediseño)

### 5.1 Limitaciones adicionales detectadas

| # | Limitación | Efecto |
|---|---|---|
| 1 | No consulta `IPS_CONFIABLES` ni `RANGOS_CONFIABLES` (a diferencia de `detectar_exploit` y `detectar_sql_injection`) | `8.8.8.8`, `1.1.1.1`, Google, Meta, Telegram generan miles de alertas |
| 2 | `flags != 'A'` cuenta cualquier paquete no-ACK, incluido `RST` y `SA` | Un servidor que rechaza conexiones (RST masivo) se ve como escáner; un `SA` es respuesta, no intento |
| 3 | No hay ventana temporal | Acumulación histórica permanente |
| 4 | No distingue TCP de UDP en el umbral | UDP tiene dinámica distinta (p. ej. DNS, QUIC); mezclar ambos sets infla el conteo |
| 5 | No detecta barrido horizontal | `nmap -p 22 10.0.0.0/24` es invisible |
| 6 | No pondera por `SYN` recibidos vs `RST` de vuelta | Un escaneo contra puertos cerrados devuelve RST; contra filtrados, silencio. Sin señal de retorno no se distingue éxito de fallo |
| 7 | No hay exclusión de puertos de servicio muy habituales hacia el mismo destino | Menor, pero ayuda |
| 8 | Sin `flow_tracker` para corroborar | La información de flujos ya calculada no se usa en la heurística |

### 5.2 Diseño propuesto

**Modelo de datos (en memoria):**

```python
from collections import defaultdict, deque

# Ventana deslizante por par (src, dst) -> deque de (timestamp, puerto, proto)
PORT_SCAN_WINDOW_S = 60
ventana_scan = defaultdict(deque)

# Barrido horizontal: (src, puerto) -> set de destinos en ventana
barrido_horizontal = defaultdict(lambda: defaultdict(float))  # src -> {dst: ts}
```

**Algoritmo para escaneo vertical (muchos puertos, un destino):**

```python
def detectar_escaneo_puertos(packet):
    if not packet.haslayer(scapy.IP):
        return

    ip_src = packet[scapy.IP].src
    ip_dst = packet[scapy.IP].dst

    # 1) Lista blanca (imprescindible)
    if ip_src in IPS_CONFIABLES or ip_en_rangos(ip_src):
        return
    # Ignorar respuestas del propio host y tráfico de retorno
    if ip_dst == MI_IP and ip_src in IPS_CONFIABLES:
        return

    proto = None
    puerto = 0

    if packet.haslayer(scapy.TCP):
        flags = str(packet[scapy.TCP].flags)
        puerto = packet[scapy.TCP].dport
        # 2) Solo paquetes de INICIO de conexión: SYN puro
        #    (excluye A, SA, RST, F, PA...) — un escaneo emite SYN
        if flags != 'S':
            return
        proto = 'TCP'
    elif packet.haslayer(scapy.UDP):
        puerto = packet[scapy.UDP].dport
        if puerto in DISCOVERY_PORTS:
            return
        proto = 'UDP'
    else:
        return

    if puerto == 0 or puerto > 65535:
        return

    ahora = time.time()

    # 3) Ventana deslizante por par (src, dst)
    clave = (ip_src, ip_dst)
    dq = ventana_scan[clave]
    dq.append((ahora, puerto, proto))
    while dq and ahora - dq[0][0] > PORT_SCAN_WINDOW_S:
        dq.popleft()

    # 4) Contar puertos DISTINTOS dentro de la ventana
    puertos = {p for (_, p, _) in dq}
    n = len(puertos)

    umbral = PORT_SCAN_THRESHOLD_INTERNAL if ip_dst.startswith(UNIPAZ_PREF) else PORT_SCAN_THRESHOLD

    if n > umbral:
        meta = {
            "heuristic": "port_scan_vertical",
            "n_distinct_ports": n,
            "threshold": umbral,
            "window_s": PORT_SCAN_WINDOW_S,
            "ip_dst": ip_dst,
            "ports_sample": sorted(puertos)[:50],
        }
        guardar_ataque(ip_src, "Escaneo de Puertos", proto, n, ip_dst, meta_heuristica=meta)
        ventana_scan[clave].clear()   # evitar repetición inmediata

    # 5) Limpieza oportunista (evita fugas de memoria)
    if len(ventana_scan) > 20_000:
        for k in [k for k, v in ventana_scan.items() if not v]:
            del ventana_scan[k]
```

**Algoritmo complementario para barrido horizontal (un puerto, muchos destinos):**

```python
def detectar_barrido_horizontal(ip_src, ip_dst, puerto, ahora):
    """Detecta nmap -p <puerto> <subred>: mismo puerto a muchos hosts."""
    destinos = barrido_horizontal[(ip_src, puerto)]
    destinos[ip_dst] = ahora
    # purgar por ventana
    for d, ts in list(destinos.items()):
        if ahora - ts > PORT_SCAN_WINDOW_S:
            del destinos[d]
    if len(destinos) > PORT_SCAN_MIN_DESTINOS:
        meta = {
            "heuristic": "port_scan_horizontal",
            "n_destinations": len(destinos),
            "threshold": PORT_SCAN_MIN_DESTINOS,
            "window_s": PORT_SCAN_WINDOW_S,
            "port": puerto,
        }
        guardar_ataque(ip_src, "Barrido Horizontal", "TCP/UDP", puerto,
                       f"{len(destinos)} destinos", meta_heuristica=meta)
        barrido_horizontal[(ip_src, puerto)].clear()
```

### 5.3 Mejoras complementarias (priorizadas)

| Prioridad | Mejora | Impacto esperado | Riesgo |
|---|---|---|---|
| **P0** | Lista blanca (`IPS_CONFIABLES` + `ip_en_rangos`) al inicio de la función | Elimina inmediatamente DNS/CDN/Google/Meta/Telegram | Nulo |
| **P0** | Ventana temporal de 60 s | Elimina el 90 %+ del ruido acumulativo | Bajo |
| **P0** | Contar por `(ip_src, ip_dst)` | Alinea la métrica con el concepto real de escaneo | Bajo |
| **P0** | Persistir `n_puertos`, `ventana`, `destino` (Problemática 1) | Habilita recalibración y auditoría | Bajo |
| P1 | Exigir `SYN` puro (no `A`/`SA`/`RST`) | Evita confundir respuestas y rechazos con intentos | Bajo |
| P1 | Umbral diferenciado interno / externo / hacia interno | Menos FP entre segmentos UNIPAZ | Bajo |
| P2 | Detección de barrido horizontal | Cubre un hueco real de detección | Medio (código nuevo) |
| P2 | Desactivar EWMA para este detector | Evita enmascarar escaneos en hora punta | Bajo |
| P3 | Correlación con `flow_tracker` (nº de flujos por destino) | Segunda señal de confirmación | Medio |
| P3 | Ponderar con `RST` de retorno (puertos cerrados) | Distingue escaneo efectivo de intento fallido | Medio |

---

## 6. Cambios concretos propuestos (NO aplicados)

### 6.1 Constantes nuevas (línea ~88-93)

```python
BASE_THRESHOLD_SYN_FLOOD  = 50
BASE_THRESHOLD_DDOS       = 500
BASE_THRESHOLD_UDP_FLOOD  = 500
TIEMPO_ENTRE_ALERTAS      = 30

# --- Escaneo de puertos (rediseño) ---
PORT_SCAN_WINDOW_S              = 60
PORT_SCAN_THRESHOLD             = 50    # puertos distintos a UN destino externo en 60 s
PORT_SCAN_THRESHOLD_INTERNAL    = 25    # idem hacia destino interno UNIPAZ
PORT_SCAN_MIN_DESTINOS          = 20    # barrido horizontal: mismo puerto a N hosts
# BASE_PORT_SCAN_THRESHOLD queda obsoleto -> eliminar tras migrar
```

### 6.2 Esquema de BD (migración aditiva, no destructiva)

```sql
ALTER TABLE ataques ADD COLUMN n_puertos    INTEGER DEFAULT 0;
ALTER TABLE ataques ADD COLUMN n_destinos   INTEGER DEFAULT 0;
ALTER TABLE ataques ADD COLUMN ventana_s    INTEGER DEFAULT 0;
ALTER TABLE ataques ADD COLUMN puerto_txt   TEXT;
```

Detalle de la lista de puertos (hasta 50) dentro de `features_json` para no fragmentar el esquema.

### 6.3 Resumen del diff conceptual

| Archivo | Zona | Cambio |
|---|---|---|
| `ids.py` | líneas 88-93 | Constantes nuevas de ventana/umbral; retirar `BASE_PORT_SCAN_THRESHOLD` |
| `ids.py` | líneas 122-127 | Añadir `ventana_scan`, `barrido_horizontal`; retirar `puertos_por_ip` |
| `ids.py` | líneas 462-508 | `guardar_ataque(..., meta_heuristica=None)` → serializa en `features_json` |
| `ids.py` | líneas 703-726 | Reescribir `detectar_escaneo_puertos` con ventana + por destino + whitelist |
| `ids.py` | nuevas | `detectar_barrido_horizontal()` |
| `ids.py` | líneas 853-859 | Invocar el nuevo detector en `procesar_paquete` |
| `intrusiones.db` | — | `ALTER TABLE` aditivo de 4 columnas |
| `intrasc.py` | vistas de alertas | Mostrar `n_puertos` en lugar de `"Múltiples"` |

---

## 7. Plan de validación antes de tocar producción

**No aplicar nada con el sniffer en marcha.** Secuencia recomendada:

1. **Parar el IDS** (`detener_monitoreo`).
2. Implementar P0 (whitelist + ventana + por destino + persistencia).
3. **Modo observación**: activar el detector pero escribir en una tabla `diagnostico_escaneo` en lugar de `ataques`, y sin alertas Telegram ni bloqueo IPS.
4. Dejar correr **24-72 h** (idealmente cubriendo un día laboral completo y un fin de semana).
5. Calcular percentiles:

```sql
SELECT
  CASE WHEN ip_dst LIKE '172.10.%' OR ip_dst LIKE '172.20.%' OR ip_dst LIKE '172.30.%'
       THEN 'interno' ELSE 'externo' END AS destino,
  COUNT(*)                          AS pares,
  MIN(n_puertos), MAX(n_puertos),
  AVG(n_puertos)
FROM diagnostico_escaneo
GROUP BY destino;
```

6. Ajustar el umbral al **P99 + margen** del tráfico normal.
7. Activar alertas, mantener IPS **desactivado** otras 24 h.
8. Activar IPS solo si el volumen es sostenible y revisable manualmente.

---

## 8. Criterios de éxito

| Métrica | Hoy | Objetivo |
|---|---:|---:|
| Alertas/día de "Escaneo de Puertos" | ~2.285 | < 20 |
| % alertas sin `confianza_ml` | 99,8 % | < 70 % |
| Escaneos reales detectados (prueba controlada con `nmap`) | a determinar | 100 % |
| Alertas con evidencia (`n_puertos`, `ventana`, `destino`) | 0 % | 100 % |
| Tiempo de triaje manual por alerta | imposible | < 1 min |

**Prueba de aceptación:** ejecutar contra un host de laboratorio:

```bash
nmap -sS -p 1-1000 172.10.x.x     # debe alertar (vertical)
nmap -sS -p 445 172.10.0.0/24     # debe alertar (horizontal)
curl https://google.com           # NO debe alertar
```

---

## 9. Riesgos y advertencias

| Riesgo | Mitigación |
|---|---|
| Al cambiar la métrica se pueden dejar de detectar escaneos lentos (`-T1`/`-T2`) | Añadir ventana secundaria larga (p. ej. 50 puertos en 300 s) con severidad menor |
| El `ALTER TABLE` sobre una BD en uso puede bloquear escrituras | Parar el IDS antes; `ALTER TABLE ADD COLUMN` es rápido y no reescribe datos |
| `features_json` crece con la lista de puertos | Limitar a 50 puertos de muestra |
| El throttle de 30 s sigue ocultando eventos | Persistir siempre; aplicar throttle solo al envío de alertas y al bloqueo |
| Cambios en `intrasc.py` si se modifica el significado de `puerto` | Usar `puerto_txt` y mantener `puerto` numérico |

---

## 10. Anexo — Otras heurísticas a revisar después

Una vez estabilizado el escaneo, el mismo patrón de análisis aplica al resto:

| Heurística | Hallazgo | Acción sugerida |
|---|---|---|
| `detectar_syn_flood` | 3 alertas, todas al puerto **7680** (Windows Update / Delivery Optimization) | Añadir 7680 a una lista de puertos de servicio excluidos, o exigir destino interno |
| `detectar_ddos` | 217 alertas; 106 hacia `172.10.12.216`; orígenes CDN/DNS | Aplicar la misma whitelist de origen; revisar si `172.10.12.216` es un servidor con mucho tráfico legítimo |
| `detectar_exploit` | 56 alertas; `172.10.0.57` y `172.10.0.59` concentran el 45 % | Verificar si son equipos de gestión/monitorización; considerar whitelist de hosts internos críticos |
| `detectar_sql_injection` (heurística) | El regex es muy laxa (`\bselect\b...--`) y podría marcar formularios legítimos; hoy queda contenida por SQLiGuard | Mantener SQLiGuard como árbitro; documentar que la heurística por sí sola no debe alertar |
| `RANGOS_CONFIABLES` | Contiene rangos muy amplios (`52.0.0.0/8`, `40.0.0.0/8`) que podrían cegar la detección de atacantes alojados en AWS/Azure | Revisar caso por caso; preferir rangos /24 específicos de CDN sobre /8 completos |

---

## 11. Conclusión

Las 18.244 alertas de "Escaneo de Puertos" **no son un problema de umbral: son un problema de definición de la métrica**. Un umbral de 40 sobre un contador global que nunca caduca equivale, en la práctica, a alertar a cualquier host activo de la red tarde o temprano.

El orden de trabajo correcto es:

1. **Persistir la evidencia** (hoy se destruye: `"Múltiples"`).
2. **Cambiar la métrica** a "puertos distintos a un mismo destino en 60 s", con lista blanca.
3. **Solo entonces**, fijar el umbral con percentiles medidos en modo observación.

Invertir ese orden —subir el 40 a 100 y seguir— solo retrasa el mismo resultado unas horas.