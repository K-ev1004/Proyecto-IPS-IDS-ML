# CHANGELOG · IDS/IPS UNIPAZ

> Historial verificado del sistema. Documentación relacionada:
> [README](../README.md) · [Guias](./guias/) · [ADRs](./adr/)

## Última entrada

TAREAS IDS/IPS - ESTADO

[17] O P2-LABORATORIO VIRTUAL + T5: KIT DISEÑADO, SIN EJECUTAR
    - Se diseñó el laboratorio que replica la red de la universidad (aislado):
      VirtualBox -> 2 redes host-only (idslab_wan 10.10.0.0/24, idslab_lan
      10.10.1.0/24) + RouterOS CHR 7.23.7 (ether1 10.10.0.2 / ether2 10.10.1.2)
      + Alpine atacante 10.10.0.50 + víctima 10.10.1.50.
    - Kit portable en _lab/: provision_chr.ps1, provision_alpine.ps1,
      chr_bootstrap_console.txt, chr_apply_config.py, t5_routeros_ips.py,
      LEEME_LAB.md. Incluye la prueba T5 (detección D2 por la ruta de
      producción -> bloqueo autónomo real -> readback CONFIRMADO -> drop
      forward -> desbloqueo) con gates PASS/FAIL y evidencias en docs/lab/.
    - Código: ids.py ahora expone modo_ips_autonomo por entorno
      (IDS_IPS_AUTONOMO=1; default False). config/mikrotik_lab.json.example
      (gitignored el archivo real).
    - DECISIÓN DEL USUARIO: NO se ejecuta en esta máquina (sin capacidad 3 VMs);
      se ejecutará en la máquina objetivo siguiendo LEEME_LAB.md. Requisito
      previo en dicha máquina: pip install paramiko.

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

