# Respuestas a la solicitud de información (institucional, técnica y experimental)

> Documento de apoyo para el informe de tesis. Recoge las 20 respuestas solicitadas,
> con la fuente verificable de cada dato (`archivo:línea`) cuando corresponde.
> Última verificación: batería `test_masivo.py` ejecutada dos veces con resultados
> idénticos (T1–T4, `exit 0`).

---

## 1. Información institucional

**1. Dependencia o área beneficiada.**
Proyecto adscrito a la carrera de **Ingeniería Informática**, Escuela de Ciencias,
Instituto Universitario de la Paz (UNIPAZ). Desarrollado en el marco del **Grupo de
Investigación en Ciencias e Ingenierías (CIPAZ)** y del **Semillero de Investigación en
Soluciones Informáticas (SISINFO)**, ambos de la Escuela de Ciencias de UNIPAZ. El
desarrollo es individual (autoría de un solo investigador/estudiante).

**2. Servicios y activos de red incluidos.**
Servicios presentes: correo institucional, plataformas académicas, bases de datos,
cámaras de videovigilancia, impresoras y televisores. Infraestructura de red: firewall
perimetral Sophos XGS 3300, routers MikroTik CCR2004-1G-12S+2XS y CCR1009-7G-1C-1S+
(core y DHCP), switch troncal Raisecom ISCOM S3600 (fibra), switches de acceso
TP-Link Omada SG2428P / TL-SG1428PE (PoE+), puntos de acceso Ubiquiti UniFi 6 LR y
Ruckus. Segmentación 802.1Q en perfiles Estudiantes / Docentes / Administrativos.

Usuarios aproximados: se cuenta con información de la población estudiantil
(**~2,915 estudiantes matriculados**, con una concurrencia estimada de **1,100–1,750
dispositivos simultáneos** en hora pico). **No se dispone del número de docentes ni de
administrativos**; ese dato no es reportado en este documento.

Equipo que hospeda el IDS/IPS: estación Windows proporcional por el investigador
(Intel i9-14900KF, 64 GB RAM, RTX 4070 SUPER 12 GB, 1 TB), sin costo para la
institución.

**3. Descripción general de la topología.**
Topología jerárquica de tres capas (Core / Distribución / Acceso):

```
ISP → equipo de borde del ISP → Sophos XGS 3300 (firewall perimetral)
    → Raisecom ISCOM S3600 (switch troncal de fibra)
    → MikroTik CCR2004 / CCR1009 (core, DHCP, políticas)
    → nodos SR1 (Aulas), SR2 (Biblioteca), SR3 (Salones Externos)
    → switches TP-Link Omada → APs UniFi/Ruckus → clientes por VLAN
```

El IDS opera en **modo pasivo SPAN/port-mirror** sobre un puerto del switch central y
el IPS actúa de forma **reactiva fuera de línea** (SSH / API de RouterOS hacia el
MikroTik core).

Estado real del punto de captura: **existe conexión física a un puerto del switch
principal de la red, pero sin la configuración de port-mirroring y con alcance
limitado de acción** (el equipo está conectado sin permisos de configuración ni de
realizar peticiones al switch). Por lo tanto, el SPAN está **diseñado pero no
habilitado**; ningún experimento del proyecto depende de él.

**4. Estado de la autorización para laboratorio.**
Existe **autorización verbal** del ingeniero encargado de redes de UNIPAZ para realizar
**análisis de la red sin interferir en ella**. De esa restricción se deriva directamente
la decisión de montar un laboratorio virtual en lugar de operar sobre la red productiva.

> Redacción propuesta para el informe de tesis:
>
> *«Nunca se ejecutan pruebas de ataque o de bloqueo directamente sobre la red de
> producción de UNIPAZ. Con autorización verbal del responsable de redes de la
> institución —otorgada para análisis sin interferencia—, toda la validación
> experimental (inyección de ataques y bloqueo) se realiza sobre una réplica
> controlada en máquinas virtuales (RouterOS CHR y máquinas de prueba), con el fin de
> demostrar la efectividad del sistema, detectar fallos y dejarlo listo para una
> futura puesta en marcha. La red productiva queda fuera del alcance experimental.»*

Esto se documenta como criterio ético y de seguridad experimental del proyecto.

---

## 2. Información técnica del sistema

**5. Sistema operativo del IDS/IPS.**
Windows, de forma obligatoria e ininterrumpida (24/7). La restricción de plataforma es
del propio entorno institucional: no se cambia el sistema operativo del equipo de
seguridad. Todo el laboratorio (incluido RouterOS CHR bajo VirtualBox) se ejecutó
también en Windows.

**6. Python y librerías principales.**
Python **3.10+ (64 bits)** como mínimo documentado (`README.md`, `docs/guias/instalacion.md`);
la corrida del laboratorio se ejecutó con Python 3.13. Librerías: `catboost`,
`scikit-learn`, `imbalanced-learn`, `pandas`, `numpy`, `joblib`, `tqdm`, `scapy` + Npcap,
`paramiko`, `requests`, `PyQt5` + `PyQt-Fluent-Widgets`, `matplotlib`, `staticmap`.

**7. Motor de base de datos.**
**SQLite** (archivo `intrusiones.db`), sin servidor ni configuración adicional. Tablas:

- `ataques(id, timestamp, tipo_ataque, ip_src, protocolo, puerto, ip_dst, confianza_ml, features_json, vlan_id, ttl, packet_size)` — esquema único `ESQUEMA_ATAQUES` (`ids.py:279`), compartido con la prueba T3.
- `bloqueos(id, timestamp, ip_src, tipo_ataque, duracion, estado, comando, respuesta, confirmado)` (`ids.py:336`).

**8. RouterOS / CHR y versión.**
**RouterOS CHR 7.23.7 (long-term)**, x86_64 sobre VirtualBox, tres nodos: router
10.10.0.2, atacante 10.10.0.3, víctima 10.10.1.3 (evidencia
`docs/lab/t5_chr_version.txt`). Objetivo de despliegue futuro: MikroTik CCR2004 / CCR1009
de la red institucional (hoy sin intervención).

**9. Características de entrada de CatBoost.**
23 features CIC-style calculadas en tiempo real por `flujos_red.py` y almacenadas en
`selected_features_v5.pkl`:

```
Dst Port, Protocol, Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts,
TotLen Fwd Pkts, TotLen Bwd Pkts, Fwd Pkt Len Max, Fwd Pkt Len Min,
Fwd Pkt Len Mean, Fwd Pkt Len Std, Bwd Pkt Len Max, Bwd Pkt Len Min,
Bwd Pkt Len Mean, Bwd Pkt Len Std, Flow Byts/s, Flow Pkts/s,
FIN Flag Cnt, SYN Flag Cnt, RST Flag Cnt, PSH Flag Cnt, ACK Flag Cnt,
URG Flag Cnt
```

SQLiGuard (segunda capa, binaria) recibe 9 features NetFlow, guardadas en
`sql_guard_features.pkl`:

```
src_port, dst_port, protocol, flow_duration_ms, total_packets,
total_bytes, flow_byts_s, flow_pkts_s, tcp_flags
```

**10. Umbral CatBoost definitivo: 0.85.**
`UMBRAL_ML = 0.85` (`ids.py:371`). Es el umbral **único** para loguear **y** para
bloquear, decisión registrada en `docs/adr/0003-umbral-unificado-ml.md`:
anteriormente se logueaba con ≥ 0.85 y se bloqueaba con ≥ 0.70, lo que producía
bloqueos sin registro ML; unificarlos elimina esa inconsistencia. Ambos umbrales son
ajustables en vivo desde la GUI (sección «Umbrales del Motor ML») y se persisten en
QSettings; 0.85 es el valor por defecto documentado.

**11. Umbral SQLiGuard definitivo: 0.30.**
`UMBRAL_SQLI_GUARD = 0.30` (`ids.py:212`); es el valor almacenado en la metadata del
artefacto `sql_guard_features.pkl`, o sea, el que **producección realmente opera**.
A 0.30, sobre el dataset externo D2 (57,229 flujos): precision **0.9985**, recall
**0.7534**, F1 0.8588, 33 falsos positivos sobre 28,582 benignos (**0.115 %**).

Aclaración de las tres cifras que parecen contradictorias:

- **0.30** = umbral de decisión (probabilidad de SQLiGuard para confirmar el SQLi).
- **0.50** = umbral **histórico**, reemplazado: con él el recall era 0.6783 frente a
  0.7534 del 0.30, con falsos positivos prácticamente iguales (verificado con la
  curva precision-recall 0.05–0.95 en `docs/ml/`). No debe citarse como configuración
  vigente.
- **0.99 (0.9985)** = **precisión resultante**, no un umbral. Es el error más frecuente
  al leer el informe: 0.99 es el *resultado* obtenido *con* el umbral 0.30.

Único umbral experimental por escenario: **CatBoost 0.85 / SQLiGuard 0.30**. No se
mezclan métricas de configuraciones distintas.

**12. Ataques que activan bloqueo autónomo.**
Con el IPS activo y en modo autónomo (`IDS_IPS_AUTONOMO=1`), la IP de origen se bloquea
cuando la clase es crítica **y** la confianza alcanza el umbral (`ids.py:525–542`):

| Clase | ¿Bloquea? |
|---|---|
| Inyeccion_SQL | Sí (severidad CRÍTICA) |
| Posible_Exploit | Sí (severidad CRÍTICA) |
| SYN_Flood, UDP_Flood, DDoS_Distribuido | Sí (severidad ALTA) |
| Port_Scanner | Sí (severidad ALTA) |
| Normal | Nunca |
| Detecciones heurísticas de respaldo | Sí, si el IPS está activo |

Condiciones acumulativas: `ips_activo` activado desde la GUI, modo autónomo, clase
crítica y `confianza_ml ≥ 0.85` en la vía ML (los heurísticos no exigen umbral ML).
Además hay un límite de **1 evento cada 30 s por IP** (`TIEMPO_ENTRE_ALERTAS`,
`ids.py:93`) para evitar spam de alertas y bloqueos repetidos.
En **modo semi-autónomo** no se bloquea: sólo se genera alerta.

**13. Duración y retiro de reglas.**
**24 horas**: `timeout=24h` en el comando de MikroTik y `duracion=24` en la tabla
`bloqueos` (`ids.py:545`). Retiro por tres vías: (a) expiración automática del timeout
en RouterOS; (b) desbloqueo manual desde el panel del dashboard; (c) ejecución de
`/ip firewall address-list remove [find list="IDS_BLACKLIST" address=...]`, verificado
en T5 con lectura de retorno (readback) vacío. Cada bloqueo queda registrado en BD con
estado `CONFIRMADO` cuando el equipo confirma la regla por lectura.

---

## 3. Información experimental

**14. Diseño definitivo de T1.**
Dataset propio global v5 (`Dataset_Limpio/dataset_global_unipaz_v5.csv`), lote fijo de
**150,000 flujos** (primeras filas del CSV, que se generó barajado con semilla;
`test_masivo.py:81`). Reporta: accuracy, F1-macro, matriz de confusión y métricas por
clase (precision/recall/F1/TP/FP/FN/TN/tasa FP), más tiempo de predicción. Gates de
aprobación: accuracy ≥ 0.80 y F1-macro ≥ 0.70.
**Resultado:** accuracy **0.8629**, F1-macro **0.7423**, 1.13 s → **PASS**.

**15. Diseño definitivo de T2.**
Dataset externo e independiente **D2** (Zenodo 6907252, SQLi ciego en PostgreSQL),
**57,229 flujos NetFlow** convertidos al formato CIC de producción y evaluados por la
**ruta exacta de producción**. Reporta precision, recall, F1 y falsos positivos sobre
benigno. Gates: precision ≥ 0.99 y tasa FP ≤ 0.2 %.
**Resultado:** precision **0.9985**, recall **0.7534**, F1 0.8588, 33 FP / 28,582
benignos (**0.115 %**), umbral 0.30 → **PASS**.

**16. Corrección aplicada a T3.**
La prueba re-ejecuta la cadena completa `on_flow_ready` (v5 + SQLiGuard + umbrales +
trazabilidad) sobre **6,000 flujos** (3,000 benignos + 3,000 SQLi) con base de datos
temporal y con Telegram y bloqueo IPS desactivados. El defecto original (la prueba
creaba una tabla `ataques` de 8 columnas mientras el `INSERT` usaba 11, con fallo
silencioso → 0 registros) quedó corregido con un esquema único compartido con
producción (`ESQUEMA_ATAQUES` / `crear_tabla_ataques`).

**Sobre la reproducibilidad:** la muestra se toma con semilla fija
(`random_state=1`, `test_masivo.py:210–212`), por lo que el resultado es
**determinista**. Se ejecutó la batería completa dos veces consecutivas y **ambas
corridas arrojaron valores idénticos** (T1–T4, `exit 0` en ambas). Por tanto la
documentación que decía que T3 era «variable entre ejecuciones» fue corregida.
Gates: ≥ 1,500 ataques SQLi persistidos y precisión de cadena ≥ 0.95.
**Resultado:** persistidos **2,343 / 3,000**, precisión **0.9983**, recall **0.7797**,
2,390 filas con trazabilidad → **PASS**.

**17. Diseño de T4.**
Sin dataset; usa una IP de documentación (203.0.113.199). Verifica que el exportador
`log_exporter.py` escribe la línea de bloqueo en `logs_bloqueos.log` y genera los
archivos `.log` semanales, todo sobre una carpeta temporal para no contaminar los logs
de producción. Gate: línea de bloqueo escrita = `true`.
**Resultado:** `linea_bloqueo_escrita=true` → **PASS**.

**18. Diseño de T5 (ejecutado, 9/9 gates, `exit 0`).**
Laboratorio de tres nodos RouterOS CHR 7.23.7 (router 10.10.0.2, atacante 10.10.0.3,
víctima 10.10.1.3), verificado con `verificar_lab.py` (13/13) antes de arrancar. La
prueba encadena:

1. SSH al CHR y versión RouterOS (gate `chr_ssh`).
2. Reglas `IDS_BLACKLIST_DROP_FORWARD/INPUT` presentes (`reglas_drop`).
3. Línea base: atacante → víctima responde **3/3** (`pre_ping`).
4. Detección SQLi por la **ruta de producción** (`ids.on_flow_ready`) → `address-list add`
   con **readback** `CONFIRMADO` (`bloqueo_confirmado`).
5. Atacante → víctima **0/3** (`post_ping_denegado`).
6. Contador `packets>0` en la regla `forward` (`drop_forward_stats`): **3 paquetes**,
   168 bytes.
7. Entrada presente en `IDS_BLACKLIST` con timeout de 24 h (`address_list_presente`).
8. `address-list remove` con readback vacío (`desbloqueado`).
9. Conectividad **restaurada 3/3** (`tras_ping_restaurado`).

El ping se **parsea** (no se lee el código de salida), porque RouterOS devuelve 0
siempre. Evidencia: `docs/lab/informe_t5.json`, ocho archivos `t5_*.txt`,
`t5_consola.txt` y una segunda corrida independiente en `docs/lab/corridas/corrida2/`.

*Medición de latencia extremo a extremo:* **no se realiza**; queda fuera del alcance
declarado de T5.

---

## 4. Evidencia y delimitación

**19. Evidencias o archivos con los que se cuenta.**

- `Tesis_Fase1.md` — documento de la Fase I (raíz del repositorio).
- `docs/lab/` — `informe_t5.json`, 8 × `t5_*.txt`, `t5_consola.txt`, `topologia-lab.{md,svg,png}`,
  `fig_secuencia_demo.png`, `fig_bloqueo_timeline.png`, `demo_bloqueo.gif`,
  `demo_timeline.csv`, `intrusiones_resumen.json`, `bloqueos_resumen.json`,
  `chr_estado_inicial.json` y `corridas/corrida2/` (corrida independiente).
- `informe_test_masivo.json` — gates y resultados T1–T4.
- `Modelos_Entrenados/metricas_v5.txt` y `metricas_sqli_guard.txt` — métricas de ambos modelos.
- `docs/red/arquitectura-red-unipaz.md` — topología institucional y plan de despliegue.
- `docs/tesis/informe_verificacion_codigo_datos.md`, `docs/CHANGELOG.md` (entradas [17]–[20]),
  `docs/adr/0001–0003`, `docs/guias/`, `README.md` (diagrama de arquitectura).
- `docs/diagramas/architecture-ids-ips.html` — diagrama de arquitectura Fase III.

*No se incluyen en el repositorio:* capturas del dashboard y documentos de la Fase II
(informe final, actas, manuales), que se entregan por fuera.

**20. Limitaciones declaradas.**

1. El proyecto **no** pretende construir un SOC institucional completo.
2. **No** realiza pentesting no autorizado ni ataques sobre la red de producción: toda
   la validación es en máquinas virtuales (réplica controlada), para probar efectividad
   y detectar fallos antes de una futura puesta en marcha.
3. **No** pretende detectar todas las familias de amenazas: son 7 clases definidas.
4. El enfoque es **exclusivamente cuantitativo**: no evalúa comportamiento humano,
   percepción del personal ni entrevistas.
5. Los resultados se limitan a las clases, datasets, umbrales (0.85 / 0.30), equipos y
   condiciones experimentales definidos.
6. Geolocalización y Telegram son complementos de visualización y alerta; **no**
   constituyen evidencia primaria de detección ni de bloqueo.
7. Verificadas en el código: ninguna prueba T1–T4 usa captura en vivo por Npcap (se
   alimentan desde CSV); T5 se ejecuta sobre CHR virtual, con un solo tipo de ataque
   (SQLi), sin medición de latencia y sin verificar la regla `INPUT`.
