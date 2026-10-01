# Informe de Verificación — Código y Datos (Fases II y III)

> Documento de trabajo de tesis (UNIPAZ, IDS/IPS con ML).
> Todas las afirmaciones fueron verificadas directamente en código fuente, archivos de datos, base de datos y registros (logs). **No se usó documentación como fuente**; la documentación solo se cita en la tabla comparativa para validar o descartar afirmaciones.

---

## 1. Resumen ejecutivo

- La Fase II entregó un **IDS solo-detección**: seis detectores heurísticos, un modelo de ML ensamblado (RF+MLP+XGB+SMOTE), dashboard PyQt5, alertas Telegram y persistencia (28,519 eventos).
- La Fase III convirtió el sistema en un **IDS/IPS**: CatBoost v5 (7 clases), detector dedicado SQLiGuard, flujos bidireccionales, bloqueo automatizado vía MikroTik (SSH) y exportador de logs con integridad.
- **Brecha de la Fase II (verificada en datos):** 96.7 % de los eventos en producción quedaron clasificados como "Desconocido"; no existía ningún mecanismo de bloqueo.
- **Estado de la Fase III (verificado):** el modelo v5 logra accuracy 0.86 (informe de entrenamiento y prueba T1). El SQLiGuard logra precisión >0.998 con el dataset externo. La prueba de **cadena completa (T3)** quedó corregida en P0: ahora **persiste 2,343 de 3,000 ataques SQL** (precision_cadena 0.9983, recall_cadena 0.7797); antes persistía 0 de 3,000 por un bug de esquema de base de datos.
- **Bloqueo:** existen 2,553 registros de bloqueo en BD y 4 líneas en el log de producción, todos simulados o de prueba. **P2 aportó además evidencia en un equipo MikroTik real** (RouterOS CHR): regla confirmada por readback y corte de conectividad, ver T5 en §P2.
- **P1 aplicado (verificado):** credenciales fuera del código (env + perfiles JSON), unidad de log corregida a horas, decisión SQL endurecida (SQLi solo con confirmación SQLiGuard), y gates de aprobación T1–T4 con logs aislados en carpeta temporal.
- **P2 ejecutado y aprobado (T5 9/9):** el laboratorio se montó sobre tres nodos RouterOS CHR 7.23.7 (router 10.10.0.2/10.10.1.2, atacante 10.10.0.3, víctima 10.10.1.3). `verificar_lab.py` dio 13/13 y T5 dio 9/9 gates PASS con `exit 0`: detección D2 por la ruta de producción, bloqueo en `IDS_BLACKLIST` confirmado por readback, 3 paquetes contados en la regla `forward`, atacante a 0/3 paquetes y conectividad restaurada a 3/3 tras el desbloqueo. Evidencias en `docs/lab/`.
- **Decisión de validación:** toda prueba de funcionamiento y efectividad se ejecutará en un **entorno virtual replicando la red**, sin tocar la red real de la universidad.

---

## 2. Pregunta 1 — ¿Cuál era el resultado exacto de las Fases I y II?

**Entregables verificados:**

| Entregable | Verificación |
|---|---|
| IDS heurístico funcional de 6 detectores | Código: SYN Flood, DDoS Distribuido, Escaneo de Puertos, Posible Exploit, Inyección SQL (regex), UDP Flood; captura en tiempo real, advertencias previas, IPs confiables |
| Modelo ML ensamblado (RF + MLP + XGB + SMOTE) | Entrenado sobre dataset propio; 6 características numéricas (IPs, puerto, protocolo, bandera, hora) |
| Dataset procesado y de entrenamiento | `escanerpuertos.csv`: **25,753 filas** (no 20,000 como dice la documentación) |
| Dashboard SOC | Interfaz PyQt5 con eventos en vivo |
| Alertas Telegram | Módulo de alertas |
| Persistencia y evidencia | BD: **28,519 eventos** (tabla simple: fecha, tipo, IP origen, protocolo, puerto); exportación CSV |
| Módulos auxiliares | Reputación de IPs (AbuseIPDB), guardado de eventos para reentrenamiento |

**Código y estructura de datos:**
- Salida real del modelo en producción: **3 clases codificadas (1, 4, 9)** — no distinguía los tipos de ataque del problema.
- BD de la Fase II: únicamente tabla `ataques`; **no existe tabla de bloqueos**.
- **No existía:** bloqueo/IPS, flujos bidireccionales, confirmación ML de SQLi, geolocalización, trazabilidad de características, logs con hash.

**Conclusión:** la Fase II entregó un IDS que *detecta y alerta*, con IA débil en la práctica (96.7 % "Desconocido" en operación) y **sin capacidad de respuesta**.

---

## 3. Pregunta 2 — ¿Qué deficiencia concreta persistía antes de la Fase III?

Verificado en código, BD y dataset de la Fase II:

1. **Ausencia total de bloqueo (IPS).** Ninguna función de bloqueo, sin integración MikroTik ni firewall local; el "bloqueo" de AbuseIPDB era solo un conjunto de IPs *en memoria*. La BD no tiene tabla de bloqueos.
2. **Clasificación ML incompleta/no operativa en vivo.** De 28,519 ataques registrados, **27,577 (96.7 %)** quedaron como "Desconocido". El codificador del modelo solo contenía 3 clases internas (1, 4, 9).
3. **Falsos positivos estructurales.** El propio dataset de entrenamiento contiene etiquetas contradictorias ("SYN Flood (Tráfico Normal)", "DDoS Distribuido (Tráfico Normal)", "Escaneo de Puertos (Tráfico Normal)"). Umbrales fijos extremos; "Escaneo de Puertos" = 96.7 % de todo lo registrado.
4. **Detección de SQLi de un solo vector.** Solo regex sobre carga útil legible; solo 50 eventos de SQL en la BD; sin segunda etapa de confirmación ML.
5. **Falta de integración extremo a extremo.** Clasificación por paquete suelto (sin flujos), sin confianza ni características guardadas, sin geolocalización, sin auditoría con integridad.

### ¿La documentación de la Fase II es validable con el código?

| Afirmación documental | Validable |
|---|---|
| "IDS heurístico con 6 detectores" | **Sí** (6 detectores en código) |
| "Modelo con 91.9 % de precisión" | **No reproducible en operación** (96.7 % "Desconocido" en vivo) |
| "Clasifica 6 tipos de ataque" | **No** (salida real: 3 clases codificadas 1/4/9) |
| "Dataset de 20,000 registros" | **No** (archivo real: 25,753 filas) |
| "Bloqueo automático en IPS" | **No** (no existe función ni tabla) |

---

## 4. Pregunta 3 — ¿Qué fuentes de tráfico/ataques usa cada prueba?

| Prueba | Fuente | Qué mide |
|---|---|---|
| **T1** | Dataset global propio v5 (muestra de 150,000 flujos) | Accuracy del modelo v5, F1-macro, matriz de confusión, métricas por las 7 clases; referencia SQLi del v5 |
| **T2** | Dataset externo independiente D2 (Zenodo, SQLi, 57,229 flujos NetFlow) — convertido al formato CIC de producción | SQLiGuard por la **ruta exacta de producción**: precision, recall, F1 y falsos positivos sobre benigno |
| **T3** | D2 balanceado (3,000 benignos + 3,000 SQLi) por la **cadena completa** `on_flow_ready`, BD temporal, sin alertas ni bloqueo | Cuántos ataques SQL quedan realmente registrados como `Inyeccion_SQL` con trazabilidad. **P0:** corregido el bug de esquema (persistía 0 por tabla sin columnas); ahora **2,343/3,000** |
| **T4** | Sin dataset; IP de documentación | El exportador de logs escribe y verifica la línea de bloqueo con integridad |

**Limitaciones de diseño (verificadas):** ninguna prueba usa captura en vivo por Npcap; T3 alimenta la cadena desde CSV; ninguna verifica el bloqueo real en el MikroTik.

---

## 5. Pregunta 4 — Entorno de despliegue y prueba

- **Red objetivo:** la red real de la universidad — MikroTik CCR2004 en el núcleo institucional (estructura segmentada documentada).
- **Estrategia de validación (decisión):** toda prueba de funcionamiento y efectividad se realizará en un **entorno virtual que replica la red** (atacante simulado → segmento replicado → equipo IDS/IPS → enrutador virtual con RouterOS real, p. ej. CHR), para no arriesgar la producción.
- **Lo que el código confirma:** el módulo de integración habla por SSH con RouterOS (IP 192.168.1.1, puerto 22) y crea la regla en la lista `IDS_BLACKLIST` con expiración de 24 h; contiene respaldo simulado (mock) si el SSH no está disponible.
- **Implicaciones para el laboratorio:** el laboratorio virtual debe incluir un RouterOS auténtico para validar la misma ruta de código de producción; las credenciales del laboratorio deben ser distintas a las de producción.

---

## 6. Pregunta 5 — Las siete clases definitivas de CatBoost v5

Confirmado en el codificador cargado por producción y en el dataset v5 (3,738,678 flujos):

| # | Clase | Flujos en dataset v5 | % |
|---|---|---|---|
| 1 | DDoS_Distribuido | 1,000,000 | 26.7 |
| 2 | Inyeccion_SQL | 3,108 | 0.08 |
| 3 | Normal | 1,500,000 | 40.1 |
| 4 | Port_Scanner | 158,930 | 4.3 |
| 5 | Posible_Exploit | 556,765 | 14.9 |
| 6 | SYN_Flood | 500,000 | 13.4 |
| 7 | UDP_Flood | 19,875 | 0.5 |

**Observación clave:** `Inyeccion_SQL` es residual (0.08 %, ~3,100 muestras); justifica la existencia del SQLiGuard como detector independiente entrenado con el dataset externo D2.

---

## 7. Pregunta 6 — Evidencia que existe sobre el bloqueo (código y logs)

**Flujo existente en código:**
1. Si un ataque crítico cumple criterios y el modo es **autónomo**, se llama al bloqueo vía SSH MikroTik; si es semi-autónomo, solo alerta.
2. El comando enviado al equipo:
   `/ip firewall address-list add list="IDS_BLACKLIST" address=<IP> timeout=24h comment="Bloqueado automáticamente por NIPS CatBoost - <fecha>"`
3. La función retorna `True` con bloqueo exitoso, **también con el respaldo simulado (mock)** y **también si el equipo responde "ya existe"**; retorna `False` solo ante error real.
4. Con ese retorno, la BD registra el bloqueo con estado `ACTIVO` (si `True`) o `SIMULADO/SEMI` (si `False` o semi-autónomo).
5. El exportador escribe la línea en el log de bloqueos con hash de integridad.

**Evidencia cruda existente:**
- **BD, tabla `bloqueos`:** 2,553 filas — 2,499 `ACTIVO`, 54 `SIMULADO`/`SIMULADO/SEMI`. Registros recientes son de prueba (192.168.20.13) y de Google del 28-may.
- **Log de bloqueos:** 4 líneas — 2 de prueba LAN (192.168.20.13, escaneo, 06-sep) y 2 del test masivo con IP de documentación (203.0.113.199, 16-sep).

**Interpretación estricta:**
- La única prueba registrada es "se intentó bloquear" (fila BD + línea log).
- El estado `ACTIVO` **no garantiza** bloqueo real: deriva del retorno de la función, que también es `True` en el modo simulado y en "ya existía".
- **No se guarda** el comando enviado, la respuesta del equipo ni confirmación de la regla en la lista. **No existe** medición de conectividad post-bloqueo.
- Existe la función inversa de desbloqueo (remover de la lista), sin invocación evidenciada en el flujo principal.
- **Nota P0:** la descripción anterior corresponde al estado *histórico*. Tras la mejora P0, la función de bloqueo hace readback en el equipo, devuelve `{ok, modo, confirmado, comando, respuesta, error}` y la BD guarda comando/respuesta/confirmado con estados `CONFIRMADO`/`SIMULADO`/`ERROR` (el mock ya no produce `ACTIVO`).

---

## 8. Pregunta 7 — Resultados cuantitativos existentes (archivos de resultados y logs)

### Modelo v5 (archivo de métricas, 747,736 flujos)
- Accuracy **0.8641** | F1-Macro **0.7442** | Kappa **0.8138**

| Clase | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| DDoS_Distribuido | 0.92 | 0.83 | 0.87 | 200,000 |
| Inyeccion_SQL | 0.07 | 0.93 | 0.12 | 622 |
| Normal | 0.93 | 0.94 | 0.93 | 300,000 |
| Port_Scanner | 0.87 | 1.00 | 0.93 | 31,786 |
| Posible_Exploit | 0.87 | 0.76 | 0.81 | 111,353 |
| SYN_Flood | 0.68 | 0.77 | 0.72 | 100,000 |
| UDP_Flood | 0.69 | 1.00 | 0.82 | 3,975 |

### Batería de pruebas (archivo del informe)

| Prueba | Resultados existentes |
|---|---|
| **T1** — v5 sobre 150,000 flujos | Accuracy **0.8629**, F1-macro **0.7423**, 1.13 s. Per-clase: UDP recall 1.0; Port_Scanner recall 0.9964; Normal F1 0.93; SQL F1 0.1237 (support 124). Referencia SQLi v5: precision 0.0662 / recall 0.9355 |
| **T2** — SQLiGuard sobre 57,229 flujos D2 | Precision **0.9985**, recall **0.7534**, F1 **0.8588**; TN 28,582 / FP 33 / FN 7,055 / TP 21,559; tasa FP benigno 0.115 %; 0.03 s; umbral **0.3** |
| **T3** — cadena completa (6,000 flujos) | **SQLi persistidos 2,343 / 3,000** (0 antes del fix P0); precision_cadena **0.9983** (tp 2,339 / fp 4); recall_cadena **0.7797** (fn 661); filas en BD temporal 2,390; SQLiGuard confirmados 6,000; 40.25 s |
| **T4** — exportador de logs | 7 logs semanales + log de bloqueos presentes; línea de prueba escrita: **true** |

### SQLiGuard (umbral canónico 0.30 — resuelto en P0)
- Accuracy **0.8761** | Precision **0.9985** | Recall **0.7534** | F1 **0.8588**
- TN 28,582 / FP 33 / FN 7,055 / TP 21,559 — tasa FP sobre benigno **0.115 %**
- El umbral canónico del proyecto pasó a ser **0.30** (antes existía un archivo de métricas con 0.5 → recall 0.6783 / FP 32). La metadata del modelo (`sql_guard_features.pkl`) ya guarda **0.3**, que es el valor real de ejecución. **Conflicto resuelto:** el archivo de métricas fue reescrito y el informe ya no mezcla fuentes.

### Curva Precision-Recall de SQLiGuard (justificación académica del umbral)
Generada sobre los 57,229 flujos externos (D2/Zenodo) por la **ruta de producción**, con barrido de umbrales 0.05→0.95 (+ malla fina 0.10–0.50). Artefactos: `docs/ml/curva_sqli_guard.csv` y `docs/ml/curva_sqli_guard.png`.

| Umbral | Precision | Recall | F1 | FP | FP/benigno |
|---|---|---|---|---|---|
| 0.10 | 0.9982 | 0.8336 | 0.9085 | 44 | 0.154 % |
| 0.20 | 0.9985 | 0.7957 | 0.8856 | 34 | 0.119 % |
| 0.25 | 0.9985 | 0.7762 | 0.8734 | 34 | 0.119 % |
| **0.30 (canónico)** | **0.9985** | **0.7534** | **0.8588** | **33** | **0.115 %** |
| 0.35 | 0.9984 | 0.7336 | 0.8458 | 33 | 0.115 % |
| 0.40 | 0.9984 | 0.7122 | 0.8314 | 33 | 0.115 % |
| 0.50 (histórico) | 0.9984 | 0.6783 | 0.8078 | 32 | 0.112 % |

**Interpretación:** la precisión se mantiene prácticamente plana (>0.998) en todo el rango — los falsos positivos sobre trafico benigno pasan de 32 a 44 a lo sumo. Lo que gobierna la elección del umbral es el **recall**. El umbral **0.30 es el punto de operación canónico** porque:
1. Coincide con la corrida de producción del informe (T2) — números 100 % reproducibles.
2. Equilibra recall 0.75 (≈21,600 de 28,614 ataques detectados) con solo 33 falsos positivos.
3. Deja margen de seguridad operativa: bajar a 0.10 subiría el recall a 0.83 (F1 0.91) agregando apenas ~11 FP más, decisión futura opcional ya anotada en el CHANGELOG.
4. Subir a 0.50 (histórico) **no** compensa: pierde ~7.5 pp de recall (9,204 SQLi no detectados) a cambio de 0 FP menos.

### Registros operativos
- 2,553 bloqueos registrados en BD; 4 líneas en el log de bloqueos (pruebas LAN y test masivo con IP de documentación).
- **No existe ninguna corrida con bloqueo confirmado en equipo real.**
- **P0 aplicado:** la tabla `bloqueos` ahora guarda `comando`, `respuesta` y `confirmado`, y el estado distingue `CONFIRMADO` (readback real en el MikroTik), `SIMULADO` (mock/omisión) y `ERROR`. El mock ya no registra `ACTIVO`.

---

## 9. Mejoras aplicadas (P0) y pendientes verificados

### P0 — Cambios aplicados y verificados
1. **Bug T3 corregido:** la prueba creaba una tabla reducida (8 columnas) y el `INSERT` usaba 11 → cada registro fallaba en silencio. Ahora producción y T3 comparten un esquema único (`ESQUEMA_ATAQUES` / `crear_tabla_ataques`), y el guardado registra el error si falla. **Resultado verificado:** T3 persiste **2,343/3,000 SQLi** (antes 0), precision_cadena 0.9983, recall_cadena 0.7797, 2,390 filas con trazabilidad.
2. **Bloqueo con confirmación real:** `bloquear_ip_mikrotik` ahora devuelve `{ok, modo, confirmado, comando, respuesta, error}` y hace **readback** `/ip firewall address-list print terse where list=IDS_BLACKLIST` para confirmar la regla. El mock distingue `confirmado=False` y registra estado `SIMULADO`, no `ACTIVO`. Tabla `bloqueos` migrada con nuevas columnas.
3. **Umbral SQLiGuard canónico = 0.30:** archivo de métricas reescrito con las métricas de producción (precisión 0.9985, recall 0.7534, FP 33); la metadata ya guardaba 0.3. Conflicto de fuentes resuelto.
4. **Curva Precision-Recall de SQLiGuard** (`graficar_curva_sqli_guard.py`): barrido 0.05–0.95 (59 umbrales) sobre D2 por la ruta de producción. Verifica que 0.30 (P 0.9985 / R 0.7534) y 0.50 (R 0.6783) coinciden con T2 y el reporte histórico; el recall decide el punto de operación. Artefactos en `docs/ml/`.

### P1 — Cambios aplicados y verificados
1. **Credenciales fuera del código:** `mikrotik_api.py` resuelve la configuración en cascada `env vars → config/mikrotik_<lab|prod>.json → placeholders`. Solo se versiona `config/mikrotik.example.json`; `.gitignore` cubre los perfiles reales. **Verificado:** sin perfil presente, el sistema carga en modo lab y advierte que el bloqueo real requiere `MIKROTIK_PASS`; la contraseña ya no está en el fuente.
2. **Unidad de log corregida:** `registrar_bloqueo_log` escribe `Duración: N h` (los llamadores pasan horas). Históricos («24 min») no se modifican.
3. **Decisión SQL endurecida:** si v5 predice `Inyeccion_SQL` pero SQLiGuard **no** confirma, la predicción ya no se persiste como SQLi: se re-mapea a la siguiente clase más probable de v5 (flag `REMAP-SQLi`) o a `Normal` según `UMBRAL_ML`, y se contabiliza en la métrica nueva `sql_no_confirmados`. `Inyeccion_SQL` solo se persiste con confirmación de SQLiGuard.
4. **Gates de aprobación T1–T4 + logs aislados:** `test_masivo.py` marca `PASS`/`FAIL` por prueba (T1: acc≥0.80 y F1≥0.70; T2: prec≥0.99 y FP≤0.2 %; T3: ≥1,500 persistidos y prec_cadena≥0.95; T4: línea de bloqueo escrita), los incorpora al informe JSON y termina con `sys.exit(1)` si alguno falla. Además define `LOG_FOLDER` a una carpeta temporal antes de importar `ids`, y T4 usa `obtener_carpeta_logs()`, con lo cual la batería **ya no escribe en `logs_ciberseguridad/`**.
5. **Verificación de cierre (batería P1, 4/4 PASS, exit 0):** T1 acc 0.8629 / F1-macro 0.7423; T2 P 0.9985, R 0.7534, FP 33 (0.115 % sobre benigno); T3 2,343/3,000 persistidos y prec_cadena 0.9983; T4 `linea_bloqueo_escrita=True` en la carpeta temporal. El log de producción quedó intacto (su última línea sigue siendo la corrida P0, formato previo «24 min»). Resultados en `informe_test_masivo.json` (campo `gates`).

### Pendientes verificados (no cubiertos en P0)
1. Ninguna prueba usa tráfico capturado en vivo por Npcap.
2. T5 quedó cerrada en P2: el laboratorio virtual se ejecutó y pasó 9/9 (ver §P2). Queda como mejora futura escalar el laboratorio a más nodos o añadir captura en vivo.

### P2 — Laboratorio virtual (ejecutado y aprobado; T5 9/9)
- **Montaje real sobre tres CHR.** La variante Alpine del diseño inicial se descartó por bloqueo en la instalación (sin `linux-lts`, repositorio local no firmable y `confirm_erase` interactivo), así que atacante y víctima son clones del disco del router (gold image). Topología: host 10.10.0.1 / 10.10.1.1, router `CHR-IDS-LAB` (`ether1` 10.10.0.2, `ether2` 10.10.1.2), atacante `CHR-ATACANTE-LAB` 10.10.0.3 con una sola NIC, víctima `CHR-VICTIMA-LAB` 10.10.1.3 en `ether2` con `ether1` deshabilitada. Redes host-only con DHCP de VirtualBox apagado (direccionamiento 100 % estático).
- **Kit:** `provision_chr.ps1` (redes host-only, gold image, discos independientes por clon, configuración en serie con el router apagado), `chr_apply_config.py` (config por SSH en dos fases: entrada por la IP de bootstrap → IP final → retirada del bootstrap, con la interfaz destino detectada en runtime), `verificar_lab.py`, `t5_routeros_ips.py`, `nodos_lab.py`/`nodos.json`, `LEEME_LAB.md`.
- **MACs de los clones.** Deben ser las del router (`08:00:27:49:7F:9C`, `08:00:27:D2:A1:09`): con MACs desconocidas RouterOS no reconoce `ether1`/`ether2` y los clones quedan inalcanzables sin consola. RouterOS 7 rechaza escribirlas por CLI (`bad parameter`), de modo que el duplicado es inevitable. Se **midió** en lugar de suponer: 30 pings host→atacante y 30 atacante→router con las tres VMs encendidas dieron 0 % de pérdida.
- **T5 ejecutado (9/9, `exit 0`).** Secuencia reproducida el 2026-10-01: SSH y versión del CHR OK → reglas `IDS_BLACKLIST_DROP_FORWARD/INPUT` presentes → atacante→víctima 3/3 → detección SQLi por la ruta de producción (`ids.on_flow_ready`) → `address-list add` con readback `CONFIRMADO` → atacante→víctima 0/3 → 3 paquetes contados en la regla `forward` → entrada presente en `IDS_BLACKLIST` → desbloqueo con readback vacío → atacante→víctima 3/3 restaurado. `verificar_lab.py`: 13/13.
- **Resultado:** la afirmación de que el bloqueo estaba "solo en mock" queda superada por evidencia en equipo real. Evidencias: `docs/lab/t5_*.txt`, `docs/lab/t5_consola.txt` e `docs/lab/informe_t5.json`. Registrado en `CHANGELOG` [18].

---

## 10. Conclusión

- Antes de la Fase III: el sistema **detectaba mucho, clasificaba casi nada en vivo y no bloqueaba nada**.
- La Fase III aporta: 7 clases, precisión alta en tráfico normal y escaneo, un detector SQL dedicado con falsos positivos mínimos, flujos bidireccionales y trazabilidad.
- La **cadena completa quedó verificada** (T3: 2,343/3,000 SQLi persistidos con 4 falsos positivos).
- **La respuesta activa quedó verificada contra un equipo real:** T5 pasó 9/9 sobre RouterOS CHR, con bloqueo confirmado por readback, corte real de la conectividad en `forward` y restauración tras el desbloqueo.
- **P1 cerró los pendientes de seguridad y calidad:** las credenciales ya no están en el código, la decisión SQL nunca persiste `Inyeccion_SQL` sin confirmación de SQLiGuard, la unidad del log es correcta, y la batería de pruebas queda automatizada con umbrales de aprobación (PASS/FAIL) sin contaminar los logs de producción.
- El bloqueo está implementado y registrado con confirmación por readback, y **quedó probado contra un RouterOS real** en T5 (9/9): la regla se confirmó en el equipo, el atacante dejó de alcanzar a la víctima y recuperó la conectividad tras el desbloqueo.
