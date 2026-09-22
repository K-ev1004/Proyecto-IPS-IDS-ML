# IDS/IPS Híbrido con Machine Learning para Red Universitaria: Diseño, Desarrollo y Evaluación

## 1. Desarrollo de la Metodología

### 1.1 Diseño del IDS/IPS

El sistema IDS/IPS se concibió como una arquitectura híbrida que combina detección basada en firma heurística con clasificación supervisada por Machine Learning, implementada íntegramente en Python 3.10 sobre plataforma Windows (README). La decisión de diseño se fundamentó en la necesidad de cubrir una red universitaria con segmentación departamental (docentes, administrativo, estudiantes) mediante captura pasiva en modo SPAN/port mirror, sin perturbar el tráfico legítimo (README).

La arquitectura general se compone de cinco capas distintas: (i) **captura de paquetes**, realizada mediante `Scapy` + `Npcap` a través de un `AsyncSniffer` que opera en modo no bloqueante con callback por paquete (ids.py:782–793); (ii) **extracción de flujos**, donde la clase `FlowTracker` (flujos_red.py:126–179) agrupa paquetes en flujos bidireccionales con tiempo de expiración de 5 segundos y calcula características CIC-style (Fwd/Bwd packets, bytes, flag counts, duración, tasas); (iii) **clasificación ML**, ejecutada por el modelo `CatBoost v5` multiclase con siete clases UNIPAZ (Normal, Port_Scanner, Posible_Exploit, SYN_Flood, UDP_Flood, DDoS_Distribuido, Inyeccion_SQL) sobre un pipeline de features seleccionadas; (iv) **confirmación por detector dedicado**, donde `SQLiGuard` (entrenar_sqli_guard.py:76–163) opera como segunda etapa binaria para validar Inyección SQL; y (v) **respuesta activa IPS**, que ejecuta bloqueo vía SSH al router MikroTik CCR2004 a través de `paramiko` (mikrotik_api.py:28–75).

Los componentes principales del sistema incluyen: el motor central `ids.py` (integrador de todas las capas), el módulo de geolocalización `geolocalizacion.py` (que consulta `ip-api.com` para IPs públicas y clasifica subredes internas UNIPAZ por departamento), el sistema de alertas `telegram_alert.py` (notificaciones HTTP a la API de Telegram Bot), el exportador de logs `log_exporter.py` (generación de archivos .log semanales con hash SHA-512), y la interfaz gráfica `interfasc.py` (dashboard SOC con PyQt5 + Fluent Design). El flujo básico desde la captura hasta la acción es el siguiente: cada paquete capturado pasa por `procesar_paquete` (ids.py:723), que simultáneamente actualiza métricas del departamento, alimenta el `FlowTracker`, y ejecuta detectores heurísticos de respaldo (`detectar_syn_flood`, `detectar_ddos`, `detectar_escaneo_puertos`, `detectar_exploit`, `detectar_sql_injection`, `detectar_udp_flood`). Cuando un flujo expira, el `FlowTracker` invoca el callback `on_flow_ready` (ids.py:338), que predice la clase con CatBoost v5, verifica SQLiGuard si aplica, y si la confianza alcanza `UMBRAL_ML = 0.85`, registra el ataque en SQLite, emite alerta Telegram, y potencialmente ejecuta el bloqueo IPS (ids.py:471–516).

Las tecnologías principales son: **Scapy + Npcap** para captura y análisis de paquetes; **CatBoost** (framework de gradient boosting) como modelo de clasificación multiclase; **scikit-learn** para métricas de evaluación, escalado y pipeline de SQLiGuard; **SQLite** para persistencia estructurada de ataques y bloqueos; **paramiko** para comunicación SSH con el firewall MikroTik; **PyQt5 con qfluentwidgets** para la interfaz de administración SOC; y **requests** para consultas a la API ip-api.com y a Telegram Bot API.

### 1.2 Desarrollo del IPS y geolocalización del atacante

La implementación del sistema sigue un flujo de procesamiento en tiempo real que puede describirse como una canalización de decisión en cinco etapas concretas.

**Captura y análisis del tráfico.** La captura se realiza mediante `AsyncSniffer` de Scapy (ids.py:787) con `store=False` para minimizar consumo de memoria, operando sobre la interfaz de red configurada. Cada paquete recibido se procesa en la función `procesar_paquete` (ids.py:723), que clasifica la IP fuente por departamento UNIPAZ según subred (172.20.x.x docentes, 172.10.x.x administrativo, 172.30.x.x estudiantes) y extrae el protocolo, puertos y flags TCP. Simultáneamente, se construye el flujo bidireccional en `FlowTracker.procesar_paquete` (flujos_red.py:136–167), donde la clave de flujo se genera ordenando las IPs para garantizar consistencia direccional.

**Identificación de la amenaza.** La identificación opera en dos vías paralelas. La vía heurística aplica detectores de firma sobre cada paquete individual: `detectar_syn_flood` identifica paquetes TCP-S con tasa superior a umbral dinámico EWMA (ids.py:574–585); `detectar_ddos` cuenta paquetes por IP destino en ventana de 1 segundo (ids.py:587–615); `detectar_escaneo_puertos` acumula puertos únicos por fuente y dispara cuando exceden el umbral (ids.py:617–639); `detectar_exploit` verifica conexión a puertos críticos (135, 139, 445, 3389, etc.) con flags TCP inapropiadas (ids.py:641–666); `detectar_sql_injection` aplica expresión regular sobre la carga útil HTTP para patrones de inyección SQL (ids.py:668–698); y `detectar_udp_flood` monitoriza paquetes UDP por destino (ids.py:700–714). La vía ML opera cuando el flujo expira (5 segundos de inactividad): `FlowTracker._limpiar_flujos_expirados` invoca `on_flow_ready` con el diccionario de features calculado por `FlujoBidireccional.get_features_dict` (flujos_red.py:70–124), que incluye `Tot Fwd Pkts`, `Tot Bwd Pkts`, `Flow Duration`, `Flow Byts/s`, `Flow Pkts/s` y conteos de flags TCP/FIN/SYN/RST/PSH/ACK/URG.

**Decisión y respuesta.** En `on_flow_ready` (ids.py:338–399), el flujo se presenta al modelo CatBoost v5 cargado desde `pipeline_catboost_v5.pkl` (ids.py:212). El modelo devuelve un índice de clase y un vector de probabilidades; la confianza se define como `max(probs)`. Si el tipo predicho es `Inyeccion_SQL`, se aplica la validación cruzada con SQLiGuard: el diccionario de features del flujo se transforma a través de `_features_sqli_guard` (ids.py:239–265) —que reconstruye NetFlow features a partir de las CIC— y se calcula `P(SQLi)` con el modelo binario cargado desde `sqli_guard.pkl`. Si `P(SQLi) ≥ UMBRAL_SQLI_GUARD (0.30)`, se registra como `Inyeccion_SQL` con alta precisión. Para el resto de clases, se requiere `confianza_v5 ≥ 0.85` tanto para registro como para posible bloqueo. El umbral de 0.85 fue unificado por decisión de diseño (ADR-0003) para garantizar consistencia entre logueo y acción de bloqueo.

**Identificación de la IP del atacante.** La IP del atacante se obtiene directamente del campo `src` del encabezado IP del paquete capturado por Scapy (ids.py:527), sin procesamiento adicional de traducción de dirección. En el contexto del sistema, la IP fuente representa el origen del tráfico potencialmente malicioso tal como fue observado en el tráfico de red.

**Geolocalización.** La geolocalización se implementa en la función `obtener_ubicacion_ip` (geolocalizacion.py:164–200) con una lógica de tres niveles. Primero, se clasifica la IP dentro de las subredes conocidas UNIPAZ (`172.20.12.0/24`, `172.10.15.0/24`, `172.30.10.0/24`, etc.), retornando departamento, frecuencia de red y coordenadas aproximadas de Bucaramanga, Colombia (lat 7.069694, lon -73.745340). Segundo, para IPs privadas RFC 1918, se consulta la IP pública del router obtenida vía `https://api.ipify.org` (geolocalizacion.py:133–148) y se geolocaliza ésta a través de `ip-api.com`. Tercero, para IPs públicas externas, se consulta directamente `ip-api.com/json/{ip}` (geolocalizacion.py:203–236), que retorna país, región, ciudad, latitud, longitud, ISP y organización. Los resultados se cachean con TTL de 3600 segundos (geolocalizacion.py:16–17) para evitar consultas redundantes. La visualización se realiza mediante mapas estáticos generados con `staticmap` sobre tiles de OpenStreetMap, con marcadores de colores por departamento (geolocalizacion.py:255–328).

**Registro y visualización del incidente.** Cada ataque detectado se persiste en la tabla `ataques` de la base de datos SQLite (`intrusiones.db`) con campos para timestamp, tipo, IPs, protocolo, puerto, confianza ML y JSON de features (ids.py:447–453). Las alertas se notifican por Telegram Bot API mediante `enviar_alerta` (telegram_alert.py:28–64), que envía HTTP POST al endpoint `https://api.telegram.org/bot{TOKEN}/sendMessage`. Los bloqueos se registran tanto en la tabla `bloqueos` de SQLite como en el archivo `logs_bloqueos.log` mediante `registrar_bloqueo_log` (log_exporter.py:136–157). La interfaz gráfica `interfasc.py` (PyQt5 + Fluent Design) presenta un dashboard SOC con tabla de eventos en tiempo real, gráfico de distribución por departamento, mapa de últimos 10 ataques, y panel de respuesta activa con estado de bloqueos y contadores.

### 1.3 Evaluación de la efectividad

La evaluación del sistema se planteó mediante una batería de pruebas masivas implementada en `test_masivo.py` (272 líneas), que ejecuta escenarios end-to-end utilizando los mismos módulos de producción. El documento `informe_test_masivo.json` recoge los resultados de cuatro pruebas distinguibles.

**Prueba T1** evaluó el modelo CatBoost v5 multiclase sobre 150 000 flujos del dataset global v5 (`dataset_global_unipaz_v5.csv`), obteniendo accuracy de 0.8629 y F1-macro de 0.7423, con tiempo de predicción de 1.44 segundos para el lote completo (informe_test_masivo.json, T1). La precisión del modelo v5 para la clase `Inyeccion_SQL` sobre el mismo conjunto fue de 0.0662 (6.62 %) con recall de 0.9355, evidenciando el problema de desbalance que motivó la creación de SQLiGuard.

**Prueba T2** evaluó SQLiGuard como detector binario independiente sobre 57 229 flujos del dataset externo D2 (Zenodo 6907252, Blind SQLi en PostgreSQL). Los resultados fueron: precision 0.9985, recall 0.7534, F1 0.8588, con 33 falsos positivos sobre 28 582 casos benignos (tasa de falsos positivos de 0.00115 o 0.115 %) y 21 559 verdaderos positivos sobre 28 614 casos positivos. El tiempo de predicción fue de 0.02 segundos (informe_test_masivo.json, T2).

**Prueba T3** verificó la cadena completa `on_flow_ready` (v5 + SQLiGuard + umbrales unificados + trazabilidad) sobre una muestra balanceada de 6 000 flujos (3 000 benignos + 3 000 SQLi), utilizando una base de datos temporal y desactivando alertas Telegram y bloqueos IPS. La persistencia de registros SQLi en la BD temporal varía entre ejecuciones debido al muestreo aleatorio del dataset; los registros con `features_json` válido confirman que la trazabilidad funciona cuando los flujos se clasifican correctamente.

**Prueba T4** verificó la funcionalidad del exportador de logs (`log_exporter.py`), confirmando la escritura exitosa de líneas de bloqueo en el archivo `logs_bloqueos.log` y la generación de archivos .log semanales en el directorio configurado.

Además de las métricas cuantitativas, la evaluación cualitativa se fundamenta en verificaciones de funcionamiento: el sistema demostró capacidad de detección mediante la correcta identificación de las 7 clases de ataque en la interfaz gráfica; capacidad de prevención a través de la integración con MikroTik (bloqueo vía SSH en modo autónomo o alerta en modo semi-autónomo; ids.py:493–500); generación de alertas verificable por la emisión de señales PyQt y mensajes Telegram; registro de incidentes confirmado por persistencia en SQLite y archivos .log; y geolocalización operativa mediante consultas a ip-api.com y clasificación por subred UNIPAZ. No se encontraron datos de tiempo de detección (latencia de extremo a extremo desde captura de paquete hasta acción de bloqueo) registrados explícitamente en el proyecto.

---

## 2. Resultados

### 2.1 Resultados del diseño

El diseño produjo una arquitectura híbrida de cinco capas que integra captura pasiva, extracción de flujos, clasificación ML de propósito general, confirmación por detector binario especializado y respuesta activa. La arquitectura final se define por los siguientes componentes: el **motor IDS/IPS** (`ids.py`, 812 líneas) que orquesta todo el flujo; el **tracker de flujos** (`flujos_red.py`, 179 líneas) que implementa la agregación bidireccional con ventana de expiración de 5 segundos; el **modelo de clasificación multiclase** CatBoost v5 con pipeline de features seleccionadas (artefactos: `pipeline_catboost_v5.pkl`, `selected_features_v5.pkl`, `label_encoder_v5.pkl`); el **detector binario SQLiGuard** entrenado con 200 K muestras de inyección SQL reales (artefactos: `sqli_guard.pkl`, `sql_guard_features.pkl`); el **módulo de respuesta activa** (`mikrotik_api.py`, 114 líneas) que ejecuta comandos SSH en RouterOS para añadir IPs a la lista de bloqueo `IDS_BLACKLIST` con timeout de 24 horas; el **sistema de geolocalización** (`geolocalizacion.py`, 328 líneas) con tres niveles de resolución y caché de 1 hora; y el **dashboard SOC** (`interfasc.py`, >2 000 líneas) con PyQt5 y Fluent Design que presenta tabla de eventos, gráficos de tráfico por departamento, mapa OSM de ataques y panel de configuración de umbrales en vivo.

El flujo de funcionamiento del IDS/IPS se resume en la secuencia: captura de paquete → clasificación departamental y métricas → agregación en flujo bidireccional → predicción ML multiclase → confirmación SQLiGuard (si aplica) → decisión con umbral unificado 0.85 → registro en SQLite + alerta Telegram + posible bloqueo MikroTik → visualización en dashboard y mapa geolocalizado.

### 2.2 Resultados del desarrollo

Las funcionalidades implementadas y verificadas en el código fuente son las siguientes:

**Detección de amenazas.** El sistema detecta siete tipos de ataque identificados por el modelo CatBoost v5 (Normal, Port_Scanner, Posible_Exploit, SYN_Flood, UDP_Flood, DDoS_Distribuido, Inyeccion_SQL) más detecciones heurísticas de respaldo para SYN flood, DDoS, escaneo de puertos, exploit y SQLi regex. La detección opera tanto sobre paquetes individuales (heurística inmediata) como sobre flujos completos (ML con latencia de hasta 5 segundos). Los resultados del modelo v5 sobre 150 000 flujos demuestran capacidad de clasificación multiclase con accuracy 0.8629 (T1).

**Prevención o bloqueo.** El IPS activo se implementa mediante dos modos operativos: modo autónomo (`modo_ips_autonomo = True`), donde `mikrotik_api.bloquear_ip_mikrotik` ejecuta el comando SSH `/ip firewall address-list add` en el router MikroTik CCR2004, y modo semi-autónomo (por defecto), donde únicamente se genera la alerta sin acción de bloqueo (ids.py:493–500). El bloqueo se registra en la tabla `bloqueos` de SQLite con campo `estado` que distingue entre `ACTIVO` (bloqueo real MikroTik), `SIMULADO/SEMI` (alerta sin bloqueo) y `DESBLOQUEADO`. El módulo de desbloqueo (`mikrotik_api.desbloquear_ip_mikrotik`, línea 77) permite la remoción manual de la regla de firewall. La interfaz gráfica ofrece control manual de bloqueo/desbloqueo con selección de fila y duración configurable (interfasc.py:1098–1147).

**Registro de incidentes.** Cada ataque se persiste en la base de datos SQLite con campo de confianza ML y JSON de features para trazabilidad completa (ids.py:447–453). Los logs semanales se generan mediante `exportar_logs_semanales` con formato que incluye nivel de severidad `[CRITICAL]` para eventos ML, `[WARNING]` para heurísticos y `[INFO]` para registros genéricos (log_exporter.py:112–124). La trazabilidad (features_json) se verifica cuando los flujos son clasificados correctamente por el modelo v5 y persistidos en la BD temporal durante la prueba T3. El número de registros con trazabilidad varía entre ejecuciones debido al muestreo aleatorio del dataset.

**Geolocalización del atacante.** La geolocalización opera en tres niveles verificados: clasificación por subred UNIPAZ con coordenadas de Bucaramanga, Colombia para redes internas; consulta a ip-api.com para IPs privadas mediante la IP pública del router; y consulta directa a ip-api.com para IPs públicas externas, retornando país, región, ciudad, latitud, longitud, ISP y organización. La visualización en el dashboard presenta un mapa OSM con marcadores diferenciados por color según el departamento o tipo de red.

**Visualización y generación de alertas.** La interfaz gráfica (`interfasc.py`) presenta un dashboard SOC con: tabla de eventos detectados con filtros por severidad y búsqueda; indicadores en tiempo real de paquetes por segundo, flujos activos, eventos totales e IPs únicas; gráfico de torta con distribución de las 7 clases de amenaza; tabla de top 5 IPs atacantes; mapa con los últimos 10 ataques geolocalizados; y panel de respuesta activa con contadores de bloqueos totales, activos y expirados. Las alertas por Telegram se envían de forma asíncrona en hilos daemon (`_enviar_alerta_async`, ids.py:327–328) para no bloquear la detección. Los umbrales de confianza ML (0.85) y SQLiGuard (0.30) son ajustables en vivo desde la GUI y se persisten en QSettings (interfasc.py:245–260, 266–282).

### 2.3 Resultados de la evaluación

#### Resultados cuantitativos

Los datos presentados provienen exclusivamente de la batería de pruebas `test_masivo.py` y su informe asociado `informe_test_masivo.json`. Las métricas que carecen de datos suficientes en el proyecto se indican como tales.

| Métrica | Resultado | Interpretación |
|---|---:|---|
| Accuracy (modelo v5 multiclase) | 0.8629 | Proporción de flujos clasificados correctamente sobre 150 K muestras del dataset v5 |
| F1-macro (modelo v5 multiclase) | 0.7423 | Media armónica de recall por clase, indicando desbalance entre clases |
| Precision Inyección_SQL (v5) | 0.0662 | La clase Inyección_SQL tiene precisión insuficiente sin SQLiGuard |
| Recall Inyección_SQL (v5) | 0.9355 | El modelo v5 detecta la mayoría de SQLi reales (altura FN) |
| Precision SQLiGuard (D2, test externo) | 0.9985 | De los flujos marcados como SQLi por el detector, el 99.85 % fueron efectivamente SQLi |
| Recall SQLiGuard (D2, test externo) | 0.7534 | El detector identificó el 75.34 % de los ataques SQLi reales en el conjunto D2 |
| F1 SQLiGuard (D2, test externo) | 0.8588 | Equilibrio entre precision y recall del detector binario |
| Tasa de falsos positivos (SQLiGuard) | 0.00115 | Solo 33 FP sobre 28 582 casos benignos (0.115 %) |
| Precision cadena completa (T3) | variable | La cadena v5+SQLiGuard muestra precision variable entre ejecuciones debido al muestreo aleatorio del dataset |
| Recall cadena completa (T3) | variable | El recall de la cadena también varía entre ejecuciones por la misma razón |
| Tiempo de predicción ML (v5, lote) | 1.13 s | Tiempo para predecir 150 000 flujos |
| Tiempo de predicción SQLiGuard (D2) | 0.02 s | Tiempo para predecir 57 229 flujos |
| Tiempo de cadena completa (T3) | ~38 s | Tiempo para procesar 6 000 flujos end-to-end |
| Ataques bloqueados correctamente | — | Sin datos verificables de conteo de bloqueos exitosos en el proyecto |
| Tiempo de respuesta (detección→bloqueo) | — | Sin datos registrados de latencia de extremo a extremo |

**Métricas por clase del modelo v5 multiclase** (150 000 flujos de test):

| Clase | Precision | Recall | F1 | TP | FP | FN | TN | Tasa FP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Normal | 0.9248 | 0.9376 | 0.9312 | 56 418 | 4 587 | 3 753 | 85 242 | 0.0511 |
| Port_Scanner | 0.8704 | 0.9964 | 0.9292 | 6 335 | 943 | 23 | 142 699 | 0.0066 |
| Posible_Exploit | 0.8654 | 0.7607 | 0.8097 | 16 993 | 2 644 | 5 346 | 125 017 | 0.0207 |
| SYN_Flood | 0.6795 | 0.7640 | 0.7192 | 15 462 | 7 294 | 4 777 | 122 467 | 0.0562 |
| DDoS_Distribuido | 0.9150 | 0.8337 | 0.8725 | 33 342 | 3 096 | 6 653 | 106 909 | 0.0281 |
| UDP_Flood | 0.6819 | 1.0000 | 0.8109 | 774 | 361 | 0 | 148 865 | 0.0024 |
| Inyeccion_SQL | 0.0662 | 0.9355 | 0.1237 | 116 | 1 635 | 8 | 148 241 | 0.0109 |

**Fuentes:** `informe_test_masivo.json` (sección `T1.clases_detalle`, `T1.matriz_confusion`, `T1.reporte_clases`); generado por `test_masivo.py`.

**Métricas ausentes.** Las siguientes métricas no pueden presentarse con datos del proyecto: *Tasa de falsos positivos del modelo v5 multiclase agregada* — se dispone de la tasa FP por clase individual pero no de un cálculo global unificado; *Porcentaje de ataques bloqueados correctamente* — el proyecto no registra un contador agregado de bloqueos exitosos en MikroTik (solo se indica si el retorno de la función fue `True` o `False`, sin agregación); *Tiempo de detección o respuesta* — no existen mediciones de latencia desde la captura del paquete hasta la acción de bloqueo. El proyecto contempla que en modo autónomo el bloqueo requiere conexión SSH al router MikroTik, cuya latencia depende de la red y no se ha medido.

**Nota sobre el cálculo de métricas.** Las métricas de SQLiGuard se calcularon sobre el conjunto de test externo D2 (Zenodo 6907252, 28 614 flujos SQLi y 28 582 benignos) utilizando `sklearn.metrics.classification_report` con umbral de decisión de 0.30 (entrenar_sqli_guard.py:119–145; informe_test_masivo.json, T2). Las métricas de la cadena completa se calcularon re-ejecutando `on_flow_ready` sobre una muestra balanceada de 6 000 flujos con base de datos temporal, recomputando precision y recall a partir de los registros efectivamente persistidos (test_masivo.py:160–222). Las métricas por clase del modelo v5 se derivan de la confusión matriz completa calculada sobre 150 000 flujos del dataset v5 en la prueba T1 (test_masivo.py:97–100).

#### Resultados cualitativos

Los resultados funcionales observados en el proyecto son los siguientes:

**Capacidad de detección.** El sistema demostró capacidad de detectar las 7 clases de ataque definidas (Normal, Port_Scanner, Posible_Exploit, SYN_Flood, UDP_Flood, DDoS_Distribuido, Inyeccion_SQL) mediante el modelo CatBoost v5 sobre flujos bidireccionales con características CIC-style. La detección heurística de respaldo opera de forma inmediata sobre paquetes individuales para amenazas de denegación de servicio y escaneo. La integración de SQLiGuard como segunda etapa elevó la precisión de detección de Inyección SQL de aproximadamente 7 % (modelo v5 aislado) a 99.85 % (test externo D2 con SQLiGuard), reduciendo drásticamente los falsos positivos en esta clase de 1 635 a 33 sobre 28 582 casos benignos.

**Capacidad de prevención.** El módulo de respuesta activa implementa bloqueo mediante SSH al router MikroTik CCR2004, añadiendo la IP atacante a la lista de dirección `IDS_BLACKLIST` con timeout configurable de 24 horas. El modo de operación predeterminado es semi-autónomo (alerta sin bloqueo), requiriendo activación explícita del modo autónomo mediante el checkbox en la interfaz gráfica (interfasc.py:739; ids.py:80–81). El sistema distingue claramente entre una alerta (notificación por Telegram y registro en base de datos) y una acción de prevención real (comando SSH al firewall perimetral). La función `desbloquear_ip_mikrotik` permite la remoción manual de la regla de firewall.

**Funcionamiento de alertas.** Las alertas se generan tanto en la interfaz gráfica mediante señales PyQt (`comunicador.nuevo_evento`, `comunicador.nuevo_bloqueo`) como por notificación remota a Telegram Bot API. El envío asíncrono en hilos daemon (`_enviar_alerta_async`, ids.py:327–328) garantiza que la falla de la API de Telegram no interrumpa la detección. Las alertas incluyen información de tipo de ataque, IP origen, IP destino, protocolo y puerto. La severidad se clasifica automáticamente como CRÍTICA (exploit, SQLi), ALTA (DDoS, flood), MEDIA (escaneo) o BAJA según el tipo de amenaza.

**Registro de incidentes.** La persistencia de incidentes se verifica mediante la base de datos SQLite con la tabla `ataques` que contiene campos de timestamp, tipo, IPs, protocolo, puerto, confianza ML y features JSON. La tabla `bloqueos` registra cada intento de bloqueo con estado diferenciado. Los logs semanales se exportan automáticamente cada 7 días en formato texto con hash SHA-512 para verificación de integridad. La trazabilidad completa (features_json) se confirmó en 2 390 registros durante la prueba T3.

**Geolocalización del atacante.** El sistema clasifica las IPs en tres categorías: redes internas UNIPAZ (con departamento y ubicación aproximada en Bucaramanga, Colombia), IPs privadas (geolocalizadas indirectamente vía IP pública del router) e IPs públicas externas (geolocalizadas directamente mediante ip-api.com). La visualización en el dashboard presenta un mapa OSM con marcadores diferenciados por color según el departamento o tipo de red. La resolución de la geolocalización para redes internas UNIPAZ es aproximada por subred, no por coordenadas GPS individuales.
