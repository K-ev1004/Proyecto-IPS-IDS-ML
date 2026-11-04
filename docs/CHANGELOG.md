# CHANGELOG · IDS/IPS UNIPAZ

> Historial verificado del sistema. Documentación relacionada:
> [README](../README.md) · [Guias](./guias/) · [ADRs](./adr/)

## Última entrada

[33] M4 ARBITRAJE Y MODO SOMBRA: MATRIZ DE POLÍTICA, ML_CANDIDATOS, T7 (PUERTA M4 CUMPLIDA)
     - Diseño elegido con el usuario: matriz de decisión por COMBINACIÓN DE
       FUENTE (mejor que el arbitraje fijo de la guía §5.3) + severidad que
       escala el tiempo de bloqueo + etiqueta de origen en cada aviso:
         ml+heuristica -> BLOQUEAR 24 h (CRITICA, doble firma)
         ml            -> ALERTAR   1 h (MEDIA; se autorevierte si es FP)
         heuristica    -> ALERTAR  24 h (NORMAL, comportamiento v5)
       Rollback de una variable: IDS_POLITICA=heuristica = producción v5.
     - Nuevo módulo politica_bloqueo.py (decisión pura, sin scapy/BD):
       defaults en código + config/politica_bloqueo.json (overrides por
       clase para el reingreso M6; arranca SIN overrides: sombra
       conservadora) + IDS_POLITICA={heuristica,sombra} para operaciones.
       8 tests unitarios (combinaciones, overrides, modos, config inválida).
     - ids.py v6 (solo con IDS_ML_V6=1):
       * Carga pipeline_catboost_v6 + features_v6 + umbrales_v6 +
         sqli_payload (M2/M3).
       * Tabla ml_candidatos (BD propia, NUNCA reemplaza a ataques): toda
         predicción queda con features completas, umbral de clase,
         corrobora_heuristica y decisión — el corpus para reentrenar en M5
         existe desde el día 1 (corrección del pecado original de C3).
       * Cadena de decisión: predicción multiclase -> umbral POR CLASE ->
         señales de arbitraje independientes (SYN de inicio v6 a
         PUERTOS_EXPLOIT, contador de puertos/2, contadores flood/2) ->
         política -> sombra graba / activo ejecuta.
       * detectar_payload_v6 a nivel paquete: TF-IDF+LogReg puntúa la
         petición HTTP; el regex fuerte v5 queda como árbitro barato.
       * guardar_ataque acepta severidad y duracion_horas: la política fija
         cuánto dura el bloqueo (proporcional a la confianza).
     - T7 (nuevo, en test_masivo.py): replay de la capa de decisión sobre el
       corpus C3 bajo los 3 modos. Resultados (276.098 filas / 3 días):
         sombra:     FP/día ML = 0.0, señales reales 69/69
         heurística: FP/día ML = 0.0, señales reales 69/69
         default:    FP/día ML = 301,7 (905 alertas) — el coste transparente
                     de "ml->alertar" activo; por eso M4 corre en sombra.
       Los 275.102 vectores en cero quedan filtrados a la entrada (M1).
       Batería completa: 6/6 gates PASS (T1-T4, T6, T7).
     - Pendiente de M4: contador "ML v6 (sombra)" en la GUI (lectura de
       ml_candidatos; se deja para no tocar el Qt sin probarlo).
     - NO se toca produccion (main): todo el trabajo en rama ml-v6.

[32] M3 CATBOOST V6: MODELO FINAL ENTRENADO, UMBRALES POR CLASE (PUERTA M3 CUMPLIDA)
     - CatBoost v6: 1000 iteraciones (learn 1,53 -> 0,103) sobre
       dataset_global_unipaz_v6.csv (3.720.533 filas x 33 features), con
       class_weights recalculados y SIN SMOTE (descartado por escala y
       riesgo de calibracion; el punto de operacion lo fija el umbral por
       clase).
     - Holdout 85/15: accuracy 0,9441, macro-F1 0,8713. La vara real sigue
       siendo replay C3/fase sombra (M4/M5): el holdout aleatorio y el
       cruzado por fuente (ablacion) delimitan el rango de honestidad.
     - Umbrales por clase (curvas PR, precision objetivo 0,995):
       Normal 0,885, DDoS_Distribuido 0,085, Posible_Exploit 0,975,
       SYN_Flood 0,755, Port_Scanner 0,5, Inyeccion_SQL 0,5, UDP_Flood 0,5.
     - Artefactos versionados (15,8 MB): pipeline_catboost_v6.pkl,
       features_v6.pkl, label_encoder_v6.pkl, umbrales_v6.pkl +
       entrenar/resultados/metricas_v6.txt (formato comparable a v5).
     - Nota de operacion: la primera corrida del modo final murio sin
       rastro (exit 1, salida vacia, 53 GB libres — descartada memoria);
       el reintento con stdout line-buffered y CatBoost verbose=50 completo
       normal. Si reincide, checkpointing por partes.
     - NO se toca produccion (main): todo el trabajo en rama ml-v6.

[31] M2 DETECTOR DE PAYLOAD SQLI: ENTRENADO, PUERTA CUMPLIDA (P 0,9977)
     - Motivo: SQLiGuard v5 adivina SQLi por features de flujo (91.924 FP/dia
       medidos en M0); el payload SI contiene la senal. Nivel 2a de la
       arquitectura v6: TF-IDF + modelo lineal sobre la peticion HTTP cruda.
     - Script: entrenar/train_sqli_payload.py. Pipeline: URL-decode ->
       lowercase -> TF-IDF char 1-3 grams (50K) + word 1-2 grams (30K,
       FeatureUnion 65.558 features) -> Regresion Logistica.
     - Umbral calibrado en VALIDACION con margen de seguridad (P>=0,998 en
       val para aguantar la deriva a test; leccion de C3: el umbral lo fija
       el benigno). v1 sin margen dio P test=0,9941 (0,9 puntos corto).
     - TEST (29.001 peticiones, umbral fijo 0,475):
       precision=0,9977 (objetivo >=0,995 CUMPLIDA), recall=0,9422,
       FP sobre benigno 16/21.645 = 0,074% (por debajo del 0,1%),
       F1=0,9692, latencia 0,006-0,10 ms/prediccion (<10 ms).
     - CAMBIO DE MODELO por runtime: LightGBM (v1/v2) disparaba access
       violation dentro de LGBM_BoosterPredictForCSR cuando convive con
       CatBoost en el mismo proceso (bateria T1->T6 reproducible, aislado
       no ocurre): conflicto de runtimes OpenMP. En M4 el motor carga
       CatBoost + este detector JUNTOS, asi que se paso a LogReg (sklearn,
       que ya convive con CatBoost en produccion via SQLiGuard). Bonus:
       entrenamiento 134 s -> 10,5 s y latencia 1,86 -> 0,10 ms.
     - T6 agregado a test_masivo.py con gate (P>=0,995, lat<10 ms);
       T1 ahora usa el dataset v6 (el v5 solo existe en produccion).
       Bateria completa: 5/5 gates PASS (T1 acc 0,8655 sobre el dataset v6;
       nota: precision de Inyeccion_SQL en el v5 multiclase = 0,0603, mas
       evidencia del diagnostico C3).
     - Artefactos versionados: Modelos_Entrenados/sqli_payload.pkl (7,4 MB,
       excepcion de gitignore igual que sqli_guard),
       entrenar/resultados/metricas_sqli_payload.txt + curva_pr (agregados).
     - La puerta "FP <= 0,1 % en replay C3" corre en M4/M5 (el corpus C3 no
       guarda payloads; ml_candidatos si).
     - NO se toca produccion (main): todo el trabajo en rama ml-v6.

[30] M2 DECISION DE FUENTE DE PAYLOAD: SOLO CSIC 2010, GRABBER DESCARTADO
     - Motivo: medir antes de construir (regla del laboratorio). El trafico
       UNIPAZ resulto 99,998 % no-HTTP-plano (C3: 5 de 276.007 filas con
       puerto web; prueba en vivo del grabber: 0 peticiones en 30 s de
       SPAN). Alcanzar 500K peticiones HTTP reales tomaria semanas: el
       grabber no aporta y se descarta.
     - Tarea programada Grabber-HTTP-v6 detenida y desinstalada; BD de
       captura (0 filas) eliminada. El codigo queda versionado con sus 8
       tests (persistencia incremental, reanudacion, auto-arranque) por si
       UNIPAZ suma servicios HTTP planos: activarlo es solo re-crear la
       tarea (comando en ML_V6_DESARROLLO.md §3.1).
     - Fuente unica de payload para M2: CSIC 2010, dos copias complementarias
       verificadas fila a fila: csic_database.csv de Kaggle (61.066 filas,
       columnas parseadas, aportacion manual del usuario) y b1nch3f/csic-
       dataset de HF (96.668 peticiones crudas con split train/validation/
       test: 72.000 Normal / 24.668 Anomalous). El texto crudo es lo que
       come el TF-IDF char 1-3 grams.
     - Salvedad detectada por verificacion de contenido: el espejo HF
       ittailup/csic NO es CSIC 2010 (es prosa literaria en espanol); se
       descargo, se inspecciono y se descarto. En el manifiesto queda la
       URL correcta.
     - Limitacion documentada para la tesis: benigno de payload
       representativo (CSIC), no nativo UNIPAZ. Mitigaciones del plan: M4
       arbitraje, M5 fase sombra contra trafico real, SQLiGuard v5 como
       corroborador.
     - NO se toca produccion (main): todo el trabajo en rama ml-v6.

[29] M1 FEATURES DIRECCIONALES: FLOWTRACKER V6 + DATASET V6 (PUERTA M1 CUMPLIDA)
     - Motivo: el defecto nº 1 del diagnostico C3 (flujo sin direccion: el
       primer paquete visto se asume atacante) se corrige en la raiz, en el
       extractor de flujos.
     - flujos_red.py -> v6: dir_init (1=inicio con SYN puro, 0=respondio,
       -1=desconocida; si el primer paquete no es SYN NO se inventa),
       init_win_bytes (window del SYN), dst_port_svc / src_port_svc (servicio
       vs efimero, misma lista de clasificar_c3.py), unipaz_src / unipaz_dst
       (segmentos 172.10/20/30, replica de ids._es_ip_interna porque
       flujos_red no puede importar ids), fwd_bwd_ratio, bytes_per_pkt,
       flow_iat_mean / flow_iat_std, pkt_dir_changes.
     - Compatibilidad v5: las 24 features quedan intactas y con sus nombres;
       CatBoost v5 y SQLiGuard siguen cargando leyendo solo sus
       features_seleccionadas. ids.py solo anade pasar la window TCP.
     - Tests: tests/test_flujos_v6.py (8 casos: SYN puro, SYN-ACK primero,
       retorno de servicio, IAT/ping-pong, flujo de 1 paquete, compat v5,
       callback completo, JSON serializable). Suite completa: 42/42.
     - generador_dataset_global.py -> v6: dataset pasa de 23 a 33 features
       (Flow IAT Mean/Std, Active/Idle Mean/Std de CIC + init_win_bytes
       unificado 2017/2018 + 3 derivadas con paridad verificada en vivo:
       dst_port_svc, fwd_bwd_ratio, bytes_per_pkt). Corregido en v2 del
       generador: coaccionar a numerico ANTES de derivar (las cabeceras
       repetidas de los CSV dejaban la columna object y tumbaban 3 archivos:
       02-16/02-28/03-01; recuperadas 1.242.745 filas de
       SlowHTTPTest/Hulk/Infiltration/benignos).
     - dataset_global_unipaz_v6.csv generado: 3.720.533 filas x 33 features
       (+fuente). Distribucion: Normal 1.500.000, DDoS_Distribuido 1.000.000,
       Posible_Exploit 556.765, SYN_Flood 500.000, Port_Scanner 158.930,
       Inyeccion_SQL 3.108, UDP_Flood 1.730 (este ultimo sigue corto: entra
       mas con CIC-DDoS2019 si M3 lo pide).
     - Sello del dataset: entrenar/resultados/dataset_v6_sha256.txt
       (93f18d524f8774a838ff4ac5ff3faf61affc21e293d7e8d590bc9060bf1582e5,
       regenerado en M3 con la columna 'fuente' para el holdout por origen).
     - dir_init real y unipaz_src/dst NO van en el dataset (no existen en
       CIC): llegan del trafico real en la fase sombra M5, como dice la guia.
     - NO se toca produccion (main): todo el trabajo en rama ml-v6.

[28] M0 LINEA BASE: REPLAY SQLIGUARD V5 CONTRA EL CORPUS C3 (PUERTA M0 CUMPLIDA)
     - Motivo: el plan ML v6 (docs/PLAN_ML_V6.md) exige antes de tocar codigo
       un numero formal del "antes": FP/dia del modelo v5 sobre el corpus C3
       etiquetado (276.098 filas, 72 h).
     - Script nuevo: entrenar/evaluar_ml_c3.py. Repasa el corpus archivado
       (evidencia/db_archive/intrusiones_v5_c3-72h_20261104_161736.db, modo
       read-only, sin capturar red) y aplica la logica de clasificacion
       auditada de scripts/clasificar_c3.py como etiqueta de verdad.
     - Determinismo 100 %: el replay reproduce 275.744/275.744 decisiones SQLi
       vivas de la corrida C3 (mismo modelo, mismo umbral 0,30, mismas 9
       features de features_json). Latencia 0,003 ms/prediccion.
     - Numeros del "antes": canal ML v5 en C3 = 276.007 alertas/72 h =
       92.004,5 FP/dia; SQLiGuard replay = 275.835 alertas (91.924 FP/dia),
       precision 0,00025 y recall 1,0 (las 69 senales reales tambien las
       dispara, con P identica 0,7842: mismo vector degenerado).
     - Evidencia del diagnostico: 275.102 filas (99,64 %) son vectores en cero
       (sin puertos/trafico) y TODAS se alertan (P media 0,68) -> defecto nº 1
       confirmado con numeros versionables.
     - Salidas versionadas (agregados, sin IPs): entrenar/resultados/
       M0_linea_base.md y metricas_v6_M0.txt. Nota de entorno: .pkl v5
       serializados con scikit-learn 1.8.0, venv con 1.9.0; el determinismo
       100 % valida que la inferencia no cambio.
     - Script de datasets: scripts/descargar_datasets_v6.py (reanudacion,
       verificacion, reporte). Decision de descarga documentada en
       docs/ML_V6_DESARROLLO.md §3.2: 2018+2017+D1 necesarios, 2019 diferido
       (30 GB; subconjunto si M3 lo pide), 2020 no necesario.
     - Pendiente de M0: NADA — el estudio de fuga Dst Port quedo hecho
       (M0_fuga_puertos.md): un arbol con SOLO Dst Port alcanza 83,7 % de
       accuracy en holdout IDS2018 (fuga directa), y quitar el puerto al
       modelo completo cuesta solo 0,9 puntos (94,4 -> 93,5). M3 decide
       con/sin puertos usando replay C3, no accuracy de holdout.
     - NO se toca produccion (main): todo el trabajo en rama ml-v6.

TAREAS IDS/IPS - ESTADO

[22] SELLOS DE LOGS: .sha256 -> .sha512 (EXTENSION = ALGORITMO) Y FORMATO sha512sum
     - Motivo: los sellos semanales se producian con SHA-512 (hashlib.sha512(),
       log_exporter.py:173) pero se guardaban como ".sha256". La extension
       contradecia el algoritmo; estaba documentado como salvedad conocida en
       varios .md y en .gitignore, pero seguia siendo una etiqueta errónea.
     - Se renombran los 9 sellos versionados: git mv de
       logs_ciberseguridad/*.log.sha256 -> *.log.sha512. El valor del hash no
       cambia: solo la extension.
     - Cambio de formato: el contenido pasa de hex pelado a la forma estándar de
       sha512sum ("<hash>  <nombre>\n", dos espacios), de modo que ahora se
       verifican con 'sha512sum -c' en lugar de comparar a mano. log_exporter.py
       escribe el nuevo sufijo y formato (newline='\n'); los 9 sellos históricos
       se reformatearon con su hex ya calculado, sin necesitar el .log.
     - Config: .gitattributes (regla -text pasa a *.sha512) y .gitignore
       (comentario actualizado).
     - Docs actualizados: docs/informe_privacidad_ips.md, docs/lab/demo-bloqueo.md,
       docs/lab/README.md, docs/lab/bloqueos_resumen.json, articulo_cientifico_
       metodologia_y_resultados.md y cambios.txt.
     - NO se toca el SHA-256 del laboratorio (_lab/mk_lab_iso.py,
       _lab/verify_lab_iso.py): ahi extension y algoritmo ya coincidian.

[21] T3 REPRODUCIBLE: DOS CORRIDAS IDENTICAS Y DOCS CORREGIDAS
     - Motivo: la documentacion afirmaba que precision/recall de T3 eran
       "variable entre ejecuciones" por muestreo aleatorio, lo que obligaria a
       reportar un rango en la tesis en lugar de un valor unico.
     - Verificacion: test_masivo.py ejecutado DOS veces seguidas. Resultados
       IDENTICOS en T1-T4 (exit 0 en ambas): T1 acc 0.8629 / F1 0.7423; T2
       P 0.9985 / R 0.7534 / FP 33; T3 2343/3000 persistidos, prec 0.9983,
       recall 0.7797, 2390 filas con trazabilidad; T4 linea_bloqueo_escrita=true.
       Se comparo el JSON completo descartando campos de tiempo/ruta: sin
       diferencias.
     - La causa: la muestra de T3 YA estaba sembrada (random_state=1 en
       test_masivo.py:210-212) y las features salen del CSV (sin datetime.now);
       el texto "variable" era residuo de una version anterior de la prueba.
     - T1 tampoco es un muestreo aleatorio: usa nrows=150000 (primeras filas
       de un CSV barajado con semilla al generarse). Redaccion corregida.
     - Docs actualizados: articulo_cientifico_fase3.md (tabla T3 y textos de
       trazabilidad), docs/tesis/articulo_cientifico_metodologia_y_resultados.md
       (tabla de metricas T3 y "lote aleatorio" -> "lote fijo"). La afirmacion
       ya no aparece en ningun .md del repo.
     - Nuevo: docs/tesis/respuestas-solicitud-informacion.md con las 20
       respuestas institucionales/tecnicas/experimentales solicitadas, incluida
       la declaracion de que NADA se prueba en produccion: toda la validacion
       es sobre maquinas virtuales (CHR) para demostrar efectividad y detectar
       fallos antes de una futura puesta en marcha.
     - Autorizacion registrada: verbal, del ingeniero encargado de redes de
       UNIPAZ, para analizar la red SIN interferir en ella (de ahi el lab).
       Punto de captura: puerto del switch principal CONECTADO pero sin
       port-mirror habilitado ni permisos de configuracion.

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

[20] EVIDENCIA VERSIONADA: CSV TIMELINE, DATASET D2 Y RESUMENES AGREGADOS
     - Motivo: la evidencia que sostiene el resultado de [18] y [19] estaba en
       gran parte fuera de Git. El PNG y el GIF se publicaban sin su CSV fuente,
       y el dataset que alimenta la deteccion no estaba en el repo, de modo que
       ni la figura ni las metricas eran reproducibles desde un clon.
     - Se versionan (7 archivos, 57.494 lineas):
         docs/lab/demo_timeline.csv                    3,9 KB   fuente de verdad
         docs/lab/intrusiones_resumen.json             2,8 KB   nuevo
         docs/lab/bloqueos_resumen.json                4,8 KB   nuevo
         datasets/SQLi_Zenodo/D2_test.csv              7,5 MB   57.229 flujos
         Captura_Linea_Base/captura_volumen_0911.csv   7,7 KB   150 muestras
     - Reproducibilidad comprobada: al reejecutar graficar_bloqueo.py sobre el CSV
       versionado, el PNG y el GIF salen byte-identicos (SHA-256 CA580D24... y
       B2FC0018...). La figura es evidencia auditable, no una captura.
     - DECISION DE PRIVACIDAD, y una casi se nos escapa: logs_bloqueos.log se
       iba a publicar como evidencia de bloqueos, pero al revisarlo resulto ser
       el MISMO dato que intrusiones.db en texto plano: 113 bloqueos, 13 IPs de
       origen, con 149.154.166.110 (Telegram) x18 y 8.8.8.8 (Google DNS) x14.
       Subirlo habria annulado por la puerta de atras la razon por la que el .db
       queda fuera. Los 3 logs semanales con contenido tenian el mismo problema.
       Se sustituyen por bloqueos_resumen.json, que publica los conteos
       (103/7/3 por familia, 76 privadas vs 37 publicas) sin escribir ninguna IP.
     - NO se publica intrusiones.db: tiene IPs publicas de terceros. En su lugar,
       intrusiones_resumen.json agrega 585 ataques y 113 bloqueos sin ninguna
       IP, e incluye el SHA-512 del .db para que la transformacion sea auditable.
       Los dos resúmenes coinciden exactamente entre si (mismos 113 bloqueos,
       13 IPs, 76/37), lo que confirma que el .db y el .log son la misma fuente.
     - Los 113 bloqueos estan todos en estado SIMULADO/SEMI con confirmado=0:
       documentan el modo semi-autonomo, NO el bloqueo autonomo validado. La
       evidencia del bloqueo real es t5_routeros_ips.txt y demo_timeline.csv.
     - Los .sha256 de logs_cibersegui/ siguen versionados pero, al no publicar
       los .log, NINGUNO de los 9 puede verificarse tras un git clone. Queda
       escrito en vez de insinuar una integridad que ya no puede comprobarse.
       Localmente verifican los de 2026-09-04, 2026-09-15 y 2026-09-24 (con
       sha512sum); el de 2026-08-25 no, porque el .log cambio tras ser sellado.
     - BUG DE INTEGRIDAD detectado y corregido: core.autocrlf=true hacia que Git
       normalizara LF<->CRLF en los .log y los sellos dejarian de verificar tras
       un clon. Se reprodujo (2 de 3 sellos FALLABAN contra el blob del indice) y
       se corrigio con -text en .gitattributes y git add --renormalize. Sin
       .gitattributes, la tabla de integridad habria sido falsa en GitHub.
     - Hallazgo preexistente: evidencia/eventos_ids_*.csv ya publicados contienen
       IPs de terceros (AWS, Akamai, Google). Se detectaron al aplicar el
       criterio de privacidad; se decidió no reescribirlos para no alterar el
       historial de un archivo ya publicado. Registrado en
       docs/informe_privacidad_ips.md.
     - Advertencia registrada: informe_test_masivo.json (bloque T4) declara como
       prueba un logs_bloqueos.log en Temp\ids_logs_test_* que ya no existe.
       Ninguna copia disponible de ese log es ese archivo.
     - .gitignore: las reglas globales *.csv y *.log eran demasiado amplias y
       ocultaban evidencia que si debe publicarse. Se anaden excepciones
       explicitas, cada una con su motivo. datasets/ exige reabrir la cadena de
       directorios: Git no re-incluye un archivo si su carpeta padre esta
       excluida.
      - Docs: seccion 'Trazabilidad de la evidencia' en docs/lab/demo-bloqueo.md,
        indice de artefactos en docs/lab/README.md y nuevo
        docs/informe_privacidad_ips.md.


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


[23] LANZAMIENTO V5 - C1+C2: ESQUEMA Y PERSISTENCIA + DETECTOR DE ESCANEO REDISEÑADO
    - Motivo: post-mortem en heuristica.md (18.244 alertas de escaneo en 191 h,
      0 % con evidencia). La produccion v1 ya no existe; se lanza una nueva.
      Plan completo: docs/PLAN_LANZAMIENTO_V5.md.
    - Esquema v5 (intrusiones_v5.db): columnas de evidencia de primera clase
      (n_puertos, n_destinos, ventana_s, umbral, evidencia_json, modo,
      version_motor, run_id, ts_utc ISO-8601) + 4 indices. Adios a la cadena
      "Multiples" en la columna puerto (era INTEGER con texto dentro).
    - guardar_ataque v5: la persistencia NUNCA pasa por throttle (la evidencia
      no se descarta); el throttle (30 s) solo limita Telegram/bloqueo y su
      clave es (ip, tipo) para que un detector no silencie a otro. Antes se
      marcaba ANTES del INSERT y perdia la alerta si el INSERT fallaba.
    - Modo observacion (IDS_MODO_OBSERVACION=1, defecto): persiste y muestra,
      no alerta ni bloquea. Puerta de entrada del plan de calibracion.
    - Detector de escaneo v5: ventana deslizante por par (src,dst), conteo de
      puertos DISTINTOS, exenciones explicitas CDN/DNS (IPS_SCAN_EXENTAS,
      ~60 % del ruido v1), umbral interno/externo (25/50), EWMA desactivado,
      purga por tiempo con tope de claves (la v1 nunca limpiaba).
    - Solo cuenta paquetes de INICIACION (sin ACK/RST): las respuestas SA/RST
      de un servidor ya no parecen escaneo, y -sF/-sN/-sX siguen detectandose.
    - Cooldown por par (120 s): un barrido largo cruza el umbral repetidas
      veces al vaciarse la ventana; antes disparaba 4+ alertas por nmap.
    - Barrido horizontal nuevo (nmap -p 445 subred/24): invisible para la v1.
    - Contadores separados SYN flood (por src) y DDoS/UDP (por dst): antes
      compartian dict con semanticas opuestas (contaminacion cruzada).
    - Throttle de persistencia flood (10 s): nmap -sS dispara tambien SYN
      Flood (119 SYN en <0,5 s); se persiste 1 en vez de cientos.
    - interfasc.py: spin de escaneo ligado a PORT_SCAN_THRESHOLD; export
      diario desde SQLite (antes deque(maxlen=10000): todos los CSV quedaban
      truncados en exactamente 10.000 filas).
    - Scripts: archivar_bd.py (mueve la BD con SHA-256 y ficha), backup_bd.py
      (copia diaria comprimida, retencion 90 d), analizar_produccion.py
      (post-mortem + --anonimizar para publicar sin IPs reales).
    - Pruebas: tests/test_portscan.py 10/10 (paquetes sinteticos de scapy,
      sin red): exenciones, iniciacion vs respuesta, vertical, stealth FIN,
      trabajo normal (45 puertos/10 min = 0 alertas), umbral interno, escaneo
      lateral interno NO exento, horizontal, persistencia con evidencia.
    - Smoke end-to-end: 119 SYN -> 1 alerta de escaneo (26 puertos, ventana 60,
      umbral 25) + 1 SYN Flood + 4 exploit (21/22/23/69); CDN exenta: 0.
    - Evidencia: alertas_produccion_v1_anon.csv (18.288 filas anonimizadas)
      y sha256_corpus_v1.txt. La BD de pruebas se archiva con hash.

[24] C1+C2 AMPLIACION: EXENCIONES FLOOD, SQLI CANDIDATA, HOSTS DE GESTION Y UI V5
    - Senal Qt de 10 a 13 elementos (n_puertos, n_destinos, modo). La celda
      Puerto muestra la evidencia: "26 puertos -> 1 destino" / "1 puerto ->
      N destinos" en vez de un 0 sin sentido. Fallback lst[:13] retrocompatible.
    - QSettings: clave nueva thresh_scan_v5; la vieja thresh_scan podia pisar
      el umbral nuevo con el 40 de la v1 en el primer arranque.
    - detectar_ddos: cuenta SOLO SYN sin ACK. Contar data/ACK convertia el
      trafico legitimo de un servidor popular en DDoS (FP hacia 172.10.12.216).
      Con 300 paquetes PA de una CDN: 0 alertas; con 501 SYN: 1 alerta.
    - detectar_syn_flood y detectar_udp_flood: exencion de origen (CDN/DNS).
    - detectar_exploit: HOSTS_GESTION (env IDS_HOSTS_GESTION, defecto
      172.10.0.57/.59, concentraban el 45 % en la v1) + evidencia JSON
      (heuristic/port/flag). VERIFICAR la lista con redes.
    - SQLi regex degradada a candidata: modo_forzado='observacion' en
      guardar_ataque; solo ML+SQLiGuard alerta. Muestra de payload truncada a
      80 chars y omitida si contiene posibles credenciales.
    - BUG que las pruebas destaparon: un evento forzado a observacion igual
      enviaba Telegram (se miraba el modo global y no el del evento). Corregido:
      el modo del evento manda.
    - Throttle de persistencia ampliado a Posible Exploit (10 s): un host que
      habla SMB todo el dia no genera miles de filas identicas.
    - tests/test_respuesta.py (10 nuevos): modo alerta (Telegram, sin bloqueo),
      bloqueo semi-autonomo (fila en bloqueos, estado SIMULADO/SEMI), ML bajo
      umbral no bloquea, SQLi solo observacion, muestra saneada, CDN exenta en
      SYN/DDoS/UDP, DDoS cuenta solo SYN, throttle de persistencia. 20/20.

[25] LOG SEMANAL CON EVIDENCIA, RETENCION DE BD, PANEL V5 Y README
    - log_exporter.py: SELECT ampliado con origen, modo, n_puertos, n_destinos,
      umbral y ventana_s (detecta columnas via PRAGMA, compatible con BD v3).
      La linea de log ahora incluye ORIGEN y MODO, y para eventos agregados:
      'PUERTO: agregado (26 puertos, umbral 25, ventana 60s)'. BD apuntada:
      IDS_DB_PATH o intrusiones_v5.db (antes intrusiones.db fijo).
    - backup_bd.py: --purgar-dias 90 borra de la BD viva los eventos con
      ts_utc anterior (SOLO tras backup exitoso). bloqueos.timestamp es
      time.ctime() y no se purga por fecha. backups/ anadido a .gitignore.
    - interfasc.py: tarjeta de escaneo con 4 controles (umbral externo, umbral
      interno UNIPAZ, ventana, enfriamiento por pareja), persistidos en
      QSettings con claves *_v5 y aplicados en vivo.
    - README.md: caracteristicas v5 (evidencia, modo observacion, candidatas
      SQLi), variables de entorno IDS_*, comandos de scripts y tests,
      estructura (tests/, scripts/, evidencia/), estado del proyecto.
    - Verificado: 20/20 pruebas, export semanal contra BD de humo muestra la
      evidencia completa, backup con purga funciona, artefactos de prueba
      limpiados.

[26] DECISION HOSTS DE GESTION + RUNBOOK C3: SERVIDOR EN OBSERVACION 24/7
    - Decision operativa (2026-10-28): 172.10.0.57 y 172.10.0.59 quedan en
      LISTA BLANCA del detector de exploit (defecto de IDS_HOSTS_GESTION, ya
      aplicado en [24]). Evidencia de la v1: su trafico era TFTP broadcast
      (255.255.255.255:69), 25 alertas = 45 % del ruido de exploit. Se
      descarto la alternativa de vigilancia etiquetada. Si la decision
      cambia: IDS_HOSTS_GESTION="" sin tocar codigo.
    - Fijado en pruebas: hosts de gestion exentos, host interno normal sigue
      detectado (movimiento lateral). 23/23.
    - scripts/corrida_observacion.py: motor headless para servidores (sin
      GUI). Estado horario (pps, ventanas, eventos trazables), duracion por
      IDS_DURACION_H o hasta Ctrl+C, resumen de corrida al salir. Verificado
      en corrida real: 35/35 eventos trazables.
    - scripts/lanzar_observacion.bat: env vars de la corrida (RUN_ID,
      observacion=1, hosts gestion, IDS_IFACE para el SPAN) + log a archivo.
    - scripts/configurar_tareas_c3.ps1 (como ADMIN): desactiva
      suspension/hibernacion, crea tarea IDS-Observacion-C3 (al arranque,
      reinicio 3x1min, limite 7 dias - el default de 72 h mataria la corrida)
      y tarea IDS-Backup diaria 06:00 con purga >90 dias.
    - docs/RUNBOOK_C3.md: runbook completo (preparacion, arranque,
      comprobacion de captura, revision diaria, cierre, calibracion y paso a
      C4) + decision de hosts de gestion documentada.
    - README: enlace al runbook y defecto de IDS_HOSTS_GESTION.


[27] RESCATE C3 + ML FUERA DE ALERTAS + VALIDACION HEURISTICA
    - Motivo: C3 (72 h, 276.098 filas) cerro con 276.007 falsos positivos del
      ML y 70 eventos reales de exploit. El analisis completo esta en
      docs/INFORME_C3_DATOS.md, generado desde la BD con scripts/clasificar_c3.py
      (solo lectura; CSVs en evidencia/ con IPs, informe en docs con agregados).
      Hallazgos: 275.102 SQLi son IGMP/sin puertos (vector en cero), 642 son
      respuestas HTTP/WUDO, 257 "Posible_Exploit" son retorno 5223/5228,
      9 barridos son WUDO:7680 y 12 "UDP Flood" son retorno QUIC.
    - IDS_ML_ALERTAS=0 por defecto: on_flow_ready cuenta el flujo pero no
      predice, no persiste y no notifica. El modelo queda como instrumentacion.
    - flujos_red.py: solo acepta TCP/UDP con puertos validos. IGMP/ICMP ya no
      llega al ML con un vector en cero (causa raiz de los 275k FP).
    - MI_IP se deriva de IDS_IFACE (o IDS_MI_IP), no de conf.iface.
    - deteccion de exploit con direccion: solo SYN de inicio (sin SA/RST),
      destino unicast (excluye broadcast .255) y metadatos de direccion.
    - 7680 (Delivery Optimization) excluido de escaneo vertical y horizontal;
      UDP de retorno (puerto servicio -> efimero) no cuenta como flood; DDoS
      exige >=10 fuentes distintas (una sola IP es SYN Flood).
    - SYN/DDoS/UDP Flood guardan evidencia (ventana, pps, umbral, fuentes).
    - SQLi: firma fuerte dentro de una peticion HTTP -> alerta; el resto queda
      como candidato en observacion. Se quitaron exclusiones "host" y
      "user-agent" que hacian que casi ninguna peticion HTTP se analizara.
    - Nueva tabla metricas_escaneo (muestras bajo umbral, 1 por par/30 s) y
      calibrar_escaneo.py reescrito: ancla en max(ts_utc), acepta --desde/--hasta
      y usa metricas_escaneo para que el P99 no sea circular.
    - corrida_observacion.py: estado separa con_evidencia y con_features (antes
      un OR ocultaba las 12 filas sin evidencia) y cuenta muestras_scan.
    - scripts/lanzar_validacion.bat (12 h) y RUNBOOK §7 con el procedimiento.
    - Tests: 34/34 (nuevos: WUDO 7680, broadcast, IGMP fuera del tracker, UDP
      de retorno, DDoS multi-fuente, ML sin alertas, SQLi fuerte/candidata y
      muestras bajo umbral).
