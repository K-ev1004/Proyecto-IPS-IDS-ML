# CHANGELOG · IDS/IPS UNIPAZ

> Historial verificado del sistema. Documentación relacionada:
> [README](../README.md) · [Guias](./guias/) · [ADRs](./adr/)

## Última entrada

TAREAS IDS/IPS - ESTADO

[19] DEMO EN VIVO DEL BLOQUEO: 5/5 VEREDICTOS + FIGURA Y GIF
    - _lab/demo_bloqueo.py convierte el T5 de gates en algo grutable: dos pings
      continuos a 1 Hz más el muestreo del contador del router, en seis etapas
      (libre -> deteccion -> bloqueado -> desbloqueo -> restaurado -> cierre).
      Correr completo: 5/5 veredictos, exit 0.
    - Las tres señales en pantalla: atacante->victima (el tráfico que se corta),
      victima->ROUTER como control, y el contador IDS_BLACKLIST_DROP_FORWARD.
      Un corte por caída de red no haría subir ese contador: es lo que convierte
      la demo en evidencia y no en un anecdote de consola.
    - El control NO puede salir del atacante: bloquear_ip_mikrotik crea también
      una regla chain=input, así que al bloquear se le corta contra el router.
      Documentado para que nadie 'arregle' el ping de control en esa dirección.
    - _lab/graficar_bloqueo.py genera fig_bloqueo_timeline.png y
      demo_bloqueo.gif desde el CSV. Sin ffmpeg ni OBS en la máquina, el MP4 se
      graba con la Xbox Game Bar (Win+Alt+R); para el GIF basta PillowWriter.
      El PNG y el GIF salen solo del CSV: si la figura contradijera al CSV, el
      bug es del graficador, no del laboratorio.
    - Bugs reales encontrados grabando, que ninguna prueba de gates detecta:
      (1) deadlock: _fase() tomaba el candado y llamaba a _registrar() dentro,
      que lo vuelve a tomar; un Lock no es reentrante y colgaba en la etapa 1.
      Se cambió a RLock.
      (2) El ping de RouterOS tiene dos formatos y el de timeout OMITE size y
      TTL ('    1 10.10.1.3                    timeout'). El regex los exigía, así
      que ninguna línea de timeout casaba, los paquetes se perdían en silencio y
      BLOQUEADO salía 0/0 con el bloqueo funcionando. Verificado contra las
      líneas reales capturadas con el bloqueo puesto.
      (3) pd.read_csv de 7.8 MB + iterrows() en vivo mantienen el GIL ocupado y
      congelaba los hilos de ping justo en la etapa clave: el lote D2 se carga
      ahora antes de arrancar los medidores.
      (4) twinx() por fotograma acumulaba cientos de ejes vivos en el GIF y lo
      hacía tardar minutos; el eje secundario se crea una vez.
      (5) Salida de dos hilos entrecortada: colorama parte la escritura al
      quitar ANSI. Cada línea se imprime bajo candado y con flush=True.
      (6) Los paquetes ya en vuelo al aplicar la regla podían responder y hacer
      fallar la etapa BLOQUEADO; se cuentan aparte como '(en vuelo)'.
    - Docs: docs/lab/demo-bloqueo.md (guía, tabla de veredictos y las notas
      técnicas anteriores, para que el próximo no vuelva a tropezar).

[18] O P2-LABORATORIO VIRTUAL + T5: EJECUTADO Y APROBADO 9/9
    - La instalación del laboratorio se rehízo sobre TRES nodos RouterOS CHR
      7.23.7 en lugar de Alpine (no superable aquí: falta linux-lts, el repo
      local no es firmable y confirm_erase es interactivo). Topología final:
      host 10.10.0.1 / 10.10.1.1; router CHR-IDS-LAB ether1 10.10.0.2 y
      ether2 10.10.1.2; atacante CHR-ATACANTE-LAB 10.10.0.3 (una sola NIC);
      víctima CHR-VICTIMA-LAB 10.10.1.3 en ether2 con ether1 deshabilitada.
    - _lab/provision_chr.ps1 crea gold image y discos independientes por clon,
      apaga el DHCP de VirtualBox en ambas redes host-only (topología 100 %
      estática) y configura los clones en serie con el router apagado.
    - _lab/chr_apply_config.py aplica la config por SSH en dos fases sobre cada
      clon (entrada por la IP de bootstrap -> IP final -> retirada del
      bootstrap) e identifica la interfaz destino en runtime, porque RouterOS
      nombra ether1/ether2 según cuántas NICs vea.
    - MACs: los clones NECESITAN las MACs del router (08:00:27:49:7F:9C y
      08:00:27:D2:A1:09) o RouterOS no reconoce ether1/ether2 y quedan
      inalcanzables sin consola. RouterOS 7 rechaza 'bad parameter' al
      escribirlas por CLI, así que el duplicado es definitivo. Se midió en vez
      de suponer: 30 pings host->atacante y 30 atacante->router con las tres
      VMs encendidas dieron 0 % de pérdida.
    - _lab/verificar_lab.py: 13/13 comprobaciones OK (SSH, IPs, reglas de drop,
      camino atacante->router->víctima y atacante sin ruta a la LAN).
    - T5: 9/9 gates PASS, exit 0. Detección D2 por la ruta de producción ->
      address-list IDS_BLACKLIST confirmado por readback -> 3 paquetes contados
      en la regla forward -> atacante a 0/3 -> desbloqueo confirmado y
      conectividad restaurada a 3/3. Evidencias y consola en docs/lab/.
    - Cumplido el requisito previo: paramiko instalado en esta máquina.

[17] O P2-LABORATORIO VIRTUAL + T5: KIT DISEÑADO, SIN EJECUTAR (SUPERADO POR [18])
    - Ver [18]: el laboratorio se acabó montando y ejecutando sobre tres CHR, y
      la variante Alpine se descartó por bloqueo durante la instalación.
    - Kit portable en _lab/: provision_chr.ps1, provision_alpine.ps1,
      chr_bootstrap_console.txt, chr_apply_config.py, t5_routeros_ips.py,
      LEEME_LAB.md. Incluye la prueba T5 (detección D2 por la ruta de
      producción -> bloqueo autónomo real -> readback CONFIRMADO -> drop
      forward -> desbloqueo) con gates PASS/FAIL y evidencias en docs/lab/.
    - Código: ids.py ahora expone modo_ips_autonomo por entorno
      (IDS_IPS_AUTONOMO=1; default False). config/mikrotik_lab.json.example
      (gitignored el archivo real).
    - DECISIÓN DEL USUARIO (vigente al redactar [17], luego superada por la
      ejecución real de [18]): no se ejecutaba en esta máquina; requisito
      previo allí, `pip install paramiko`.

[13] ✔ P1-CREDENCIALES FUERA DEL CÓDIGO (mikrotik_api.py + config/)
    - Resolución en cascada: env vars (MIKROTIK_IP/USER/PASS/PORT/
      ADDRESS_LIST, perfil vía MIKROTIK_PROFILE) -> config/mikrotik_lab.json
      o mikrotik_prod.json -> placeholders (se advierte sin credenciales).
    - Solo se versiona config/mikrotik.example.json (plantilla). .gitignore
      cubre los perfiles reales. Sin dependencias nuevas.
    - La contraseña real ya NO aparece en el fuente.

[14] ✔ P1-UNIDAD DE LOG CORREGIDA (log_exporter.py)
    - registrar_bloqueo_log escribía "Duración: 24 min" pero los llamadores
      pasan horas. Ahora escribe "Duración: 24 h". Históricos sin modificar.

[15] ✔ P1-DECISIÓN SQL ENDURECIDA (ids.py on_flow_ready)
    - Si v5 predice Inyeccion_SQL pero SQLiGuard NO confirma, ya NO se
      persiste como SQLi: se re-mapea a la siguiente clase más probable de v5
      (flag "REMAP-SQLi") o a Normal si no supera UMBRAL_ML.
    - Nueva métrica sql_no_confirmados para auditar los descartes.
      Inyeccion_SQL solo se persiste con confirmación de SQLiGuard.

[16] ✔ P1-GATES PASS/FAIL + LOGS AISLADOS (test_masivo.py)
    - T1-T4 con gates de aprobación (T1 acc>=0.80/F1>=0.70; T2 prec>=0.99
      y FP<=0.2%; T3 persistidos>=1500 y prec_cadena>=0.95; T4 línea escrita).
      PASS/FAIL en consola + informe JSON + sys.exit(1) si falla.
    - LOG_FOLDER apunta a carpeta temporal antes de importar ids: el test
      ya NO contamina logs_ciberseguridad/. T4 usa obtener_carpeta_logs().
    - Verificado (batería P1): T1 0.8629 / T2 0.9985 (FP 0.115%) / T3 2343 de
      3000 / T4 True con carpeta temporal. 4/4 PASS, exit 0, logs reales
      intactos (última línea de producción sigue en formato previo "24 min").

[12] ✔ CURVA PR SQLIGUARD - JUSTIFICACIÓN DEL UMBRAL (graficar_curva_sqli_guard.py)
    - Evalúa la ruta de producción (ids._features_sqli_guard + ids.sqli_guard)
      sobre D2 (Zenodo, 57,229 flujos), barrido 0.05-0.95 + malla fina 0.10-0.50.
    - Artefactos: docs/ml/curva_sqli_guard.csv (59 umbrales) y
      docs/ml/curva_sqli_guard.png (PR + F1 + tasa FP, puntos 0.30/0.50 marcados).
    - Verificado: 0.30 -> P 0.9985 / R 0.7534 / FP 33 (== T2 del informe);
      0.50 -> R 0.6783 / FP 32 (== reporte histórico). Conflicto cerrado.
    - Elección 0.30: precisión plana >0.998 en todo el rango; el recall decide.
      Deja margen opcional documentado (0.10 => recall 0.83, F1 0.91, +11 FP).

[9] ✔ P0-CORRECCION CADENA COMPLETA (ids.py + test_masivo.py)
    - BUG T3 RESUELTO: la prueba creaba una tabla `ataques` reducida (8 cols)
      mientras guardar_ataque insertaba 11 columnas (ip_dst/vlan_id/ttl/
      packet_size). Cada INSERT fallaba en silencio (except: pass) -> la cadena
      persistía 0/3000 aunque detectara. Ahora existe ESQUEMA_ATAQUES único
      (constante + crear_tabla_ataques()) compartido por producción y T3.
    - Verificado: T3 persiste 2343/3000 SQLi (antes 0), precision_cadena 0.9983,
      recall_cadena 0.7797, 2390 filas con trazabilidad, SQLiGuard confirmó 6000.
    - Se elimina el except:pass en la persistencia: ahora el error se imprime.

[10] ✔ P0-BLOQUEO CON CONFIRMACION REAL (mikrotik_api.py + ids.py)
    - bloquear_ip_mikrotik() ahora devuelve {ok, modo, confirmado, comando,
      respuesta, error} y tras ejecutar el comando hace READBACK por SSH
      (/ip firewall address-list print terse where list=... address=<ip>)
      para confirmar que la regla existe en el equipo.
    - El respaldo simulado (mock) ya NO devuelve confirmado: estado SIMULADO,
      ya no ACTIVE. Estados nuevos: CONFIRMADO / SIMULADO / ACTIVO / ERROR.
    - Tabla bloqueos migrada: columnas comando, respuesta, confirmado.
    - Nota RouterOS: address-list NO bloquea por sí sola; se requiere regla
      /ip firewall filter (chains forward + input) -> drop para IDS_BLACKLIST.

[11] ✔ P0-UMBRAL SQLIGUARD CANÓNICO = 0.30 (metricas_sqli_guard.txt)
    - Archivo de métricas reescrito con las métricas de producción a umbral
      0.30 (precision 0.9985, recall 0.7534, F1 0.8588, FP 33/28615).
    - Reemplaza el reporte histórico de umbral 0.5 (recall 0.6783). La metadata
      (sql_guard_features.pkl) ya guardaba 0.3; producción NO cambió de valor.

[1] ✔ LOGS .LOG SEMANALES (log_exporter.py)
    - Exportacion automatica cada semana a carpeta externa (logs_ciberseguridad).
    - Nombres: logsciberseguridad_<fecha>.log
    - Logs de bloqueo en formato .log.
    - Corregido bug de filtro de fechas (_ts_en_rango parsea time.ctime()).

[2] ✔ PIPELINE DE DATOS REPARADO (generador_dataset_global.py)
    - Bug de encoding U+FFFD en CIC-IDS2017: labels corruptos como
      'Web Attack � Sql Injection' no mapeaban (se perdian ~2180 ataques web).
      Ahora _normalizar_label normaliza U+FFFD y guiones antes del MAPEO_CLASES.
    - Dataset v5 (dataset_global_unipaz_v5.csv): Inyeccion_SQL pasa de 928 a 3108.
    - Barras de progreso tqdm añadidas (archivos, chunks y balanceo).

[3] ✔ MODELO V5 (CEREBRO_V5.py)
    - Re-entrenado sobre dataset v5 con SMOTE focalizado en Inyeccion_SQL y
      auto_class_weights Balanced. GPU.
    - Metricas: acc 0.8641, F1-macro 0.7442, Kappa 0.8138
      (v4: 0.8551 / 0.7165 / 0.8014). Precision SQLi 1% -> 7%.
    - Artefactos: pipeline_catboost_v5.pkl, label_encoder_v5.pkl,
      selected_features_v5.pkl, metricas_v5.txt.

[4] ✔ SQLIGUARD - DETECTOR BINARIO DEDICADO (entrenar_sqli_guard.py)
    - Dataset externo: "SQL Injection Attack Netflow" (Zenodo 6907252),
      D1 (200K SQLi Union) entrenamiento + D2 (28K SQLi Blind) test externo.
    - Metricas en test externo independiente (D2): Precision SQLi 99.8%,
      Recall 75% (umbral 0.30), F1 0.86. Solo ~35 falsos positivos en 28K benignos.
    - Artefactos: sqli_guard.pkl, sql_guard_features.pkl, metricas_sqli_guard.txt.

[5] ✔ INTEGRACION PRODUCCION (ids.py + flujos_red.py)
    - Migrado a artefactos v5 (pipeline_catboost_v5.pkl).
    - SQLiGuard como capa de confirmacion de 2a etapa:
        * Si SQLiGuard confirma (P>=0.30) -> Inyeccion_SQL (precision ~99.8%).
        * v5 Inyeccion_SQL bajo umbral -> no se loguea (menos falsos positivos).
    - Umbrales unificados a UMBRAL_ML=0.85 para logueo Y bloqueo ML
      (antes log 0.85 / block 0.70: habia bloqueos sin registro).
    - flujos_red.py: añadido 'Src Port' a features y Src Port al flujo.

[6] ✔ TRAZABILIDAD (intrusiones.db)
    - Nuevas columnas en tabla ataques: confianza_ml REAL, features_json TEXT
      (ALTER para BD existentes). Permite auditar cada decision ML.
    - Verificado end-to-end: SQLi real se confirma y persiste con confianza y
      features; trafico benigno no genera falsos positivos.

[7] O PENDIENTE (opcional): si se desea mayor recall de SQLi, bajar
    UMBRAL_SQLI_GUARD en ids.py (e.g., 0.10 => recall 83%, precision sigue 99.8%).

[8] ✔ FRONTEND ACTUALIZADO (interfasc.py)
    - Pestaña Configuracion: nueva seccion "Umbrales del Motor ML (Confianza)"
      con DoubleSpinBox para UMBRAL_ML (def 0.85) y UMBRAL_SQLI_GUARD (def 0.30),
      persistidos en QSettings y aplicados en vivo a ids.py.
    - Boton "Abrir Carpeta de Logs" en Acciones Globales (abre logs_ciberseguridad).
    - Mapeo de clases del pie de "Distribucion de Amenazas" actualizado a las
      7 clases reales del modelo v5 (Normal, Port_Scanner, Posible_Exploit,
      SYN_Flood, UDP_Flood, DDoS_Distribuido, Inyeccion_SQL).
    - log_exporter.py: nueva funcion obtener_carpeta_logs() reutilizable.
    - Verificado: modulo importa, GUI instancia offscreen sin errores,
      spin_umbral_ml=0.85, spin_umbral_sqli=0.3, boton_logs presente.
    - Contrato senales intacto (eventos 7-tupla, nuevo_bloqueo, dashboard).

