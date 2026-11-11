# ML v6 — Avance completo (M0 → M6) y estado del sistema

**Fecha:** 2026-11-11 · **Rama:** `ml-v6` (laboratorio) · **Producción:** `main` intacta
**Resumen ejecutable:** el ML volvió a ser detector con evidencia medida en cada paso. Hoy corre en **fase sombra con reingreso por clase iniciado**, con GUI visible, a prueba de apagones, y con política de bloqueo configurable desde la propia GUI.

---

## 1. Lo que se hizo, fase por fase

### M0 — Línea base (el "antes" formal)
- `entrenar/evaluar_ml_c3.py`: replay de las 276.098 filas del corpus C3 contra SQLiGuard v5.
- **Determinismo 100 %** (275.744/275.744 decisiones reproducidas) — el corpus es un banco de pruebas fiable.
- El "antes": **92.004,5 FP/día** del canal ML v5; SQLiGuard replay: 91.924 FP/día (precisión 0,00025).
- Fuga de características probada: un árbol con SOLO `Dst Port` acierta **83,7 %** en holdout IDS2018 → el puerto cuasi-etiqueta la clase.
- Artefactos: `M0_linea_base.md`, `metricas_v6_M0.txt`, `M0_fuga_puertos.md`.

### M1 — Features direccionales (FlowTracker v6)
- `flujos_red.py` v6: **dirección real** (SYN puro de inicio → `dir_init` 1/0/-1, no se inventa), `init_win_bytes`, `dst/src_port_svc`, `unipaz_src/dst`, `fwd_bwd_ratio`, `bytes_per_pkt`, `flow_iat_mean/std`, `pkt_dir_changes`.
- Las 24 features v5 intactas → compatibilidad total con los modelos viejos.
- Tests: 8 nuevos; suite completa 42/42.

### M2 — Detector de SQLi por payload
- `entrenar/train_sqli_payload.py`: TF-IDF char 1-3 + word 1-2 (65.558 features) → **Regresión Logística**.
- Datos: solo CSIC 2010 (verificado fila a fila; el espejo "ittailup/csic" de HF era prosa literaria y se descartó; el verdadero: `b1nch3f/csic-dataset` + el CSV de Kaggle).
- **Test (29.001 peticiones): P=0,9977 · R=0,9422 · FP benigno 0,074 % · 0,006 ms** — puerta (P≥0,995) **cumplida**.
- Decisión de arquitectura: LightGBM descartado — conflicto de runtimes OpenMP con CatBoost en el mismo proceso (access violation reproducible en la batería).
- Umbral calibrado contra el benigno con margen de deriva (lección C3).

### M3 — CatBoost v6
- Dataset v6: **3.720.533 filas × 33 features** (IAT/Window/Active/Idle + derivadas con paridad en vivo), columna `fuente` para holdout por origen, sellado con SHA-256.
- **Ablación por fuente** (2017↔2018 × con/sin puerto): hallazgo mayor — la generalización cruzada colapsa (acc 0,30–0,55) → **el 0,86 del v5 estaba inflado por fuga de fuente**. La vara real: replay + fase sombra.
- Modelo final (1000 iter): acc 0,9441, macro-F1 0,8713, **umbrales por clase** calibrados con curvas PR.
- Artefactos: `pipeline_catboost_v6.pkl`, `features_v6.pkl`, `label_encoder_v6.pkl`, `umbrales_v6.pkl`, `metricas_v6.txt`.

### M4 — Arbitraje y modo sombra
- **Matriz de política por fuente** (mejor que el arbitraje fijo): `ml+heuristica → bloquear 24 h (CRÍTICA)` · `ml → alertar 1 h (MEDIA)` · `heurística → alertar 24 h (NORMAL)` — severidad escala el tiempo de bloqueo.
- `politica_bloqueo.py` (decisión pura, 10 tests) + `config/politica_bloqueo.json` (única fuente de verdad, versionable).
- Tabla **`ml_candidatos`**: toda predicción queda con features completas y decisión — el corpus para reentrenar existe desde el día 1.
- `detectar_payload_v6` por paquete; señales de arbitraje independientes por clase (SYN de inicio v6, contadores/2, regex fuerte).
- **T7** (replay de la capa de decisión sobre C3): sombra y heurística con **FP/día = 0** y las 69 señales reales conservadas. Batería: 6/6 gates PASS.

### M5 — Fase sombra (corriendo en tráfico real)
- Tarea programada **`IDS-Lab-M5-V6`** (al iniciar sesión): abre la GUI del laboratorio con `IDS_ML_V6=1` + sombra + `run_id=lab-m5-shadow`; la captura se relanza sola tras cada reinicio del servidor.
- **Puerta CUMPLIDA** (`M5_informe_sombra.md`): FP reales **0/día** (0 de 2.516 candidatos); los 2 únicos 'alerta' fueron **verdaderos con doble firma** (ML + heurística del mismo origen, ±9 s: SYN externo a puertos 21/22).
- Grabber de HTTP benigno: construido, medido y **descartado** (UNIPAZ es 99,998 % no-HTTP-plano, riesgo R6); el código queda versionado con sus tests por si la red cambia. Fuente de payload: solo CSIC.

### M6 — Reingreso por clase (iniciado)
- Mecanismo: salida de sombra **por clase** vía override en `config/politica_bloqueo.json` (el override es el pase de reingreso, auditable en git).
- **Primera clase activada: Inyeccion_SQL** (la más precisa: 0,9977; 0 FP en sombra; casi no se dispara por R6 = riesgo mínimo): ML solo → alertar 1 h; doble firma → bloquear 24 h.
- Fila de reingreso: `Posible_Exploit` (2.514 candidatos, 2 verdaderos) → luego las volumétricas. Revisión semanal: FP < 5 %; si una clase falla, se quita su override y vuelve a sombra.

### GUI — Configuración de la v6
- **Botón de bloqueo de valores calibrados** (default BLOQUEADO, persistido): los 9 umbrales calibrados deshabilitados con su evidencia en tooltips; desbloquear exige doble confirmación y queda en el log.
- Sección **"ML v6"**: estado en vivo (30 s: CatBoost cargado, SOMBRA/ACTIVO, candidatos/descartados/alertas), **toggle sombra ↔ activo efectivo al instante**, **matriz por clase** (acción ML-solo / doble-firma + duración → guarda el JSON, aplica al instante), "Restaurar sombra (M6 off)".
- Umbrales v6 mostrados **solo lectura** (artefactos de entrenamiento).

---

## 2. ⚠️ PENDIENTE PRIORITARIO: arreglar lo responsive de la GUI

**Al agregar las secciones nuevas se DAÑÓ el responsive de la página de Configuración.** La página es un `QVBoxLayout` fijo sin scroll: con el botón de bloqueo + la sección ML v6 (6 filas de matriz con 5 widgets c/u + labels + botones), el contenido **ya no cabe** y las secciones de abajo ("Acciones Globales", parte de la matriz) quedan cortadas o comprimidas según la resolución. Además se eliminó un `addStretch()` intermedio que absorbía el espacio sobrante.

**Arreglo pendiente (próxima sesión de GUI):**
1. Envolver el contenido de `page_settings` en un `ScrollArea` (qfluentwidgets) con ancho fijo interno — la página completa debe hacer scroll vertical.
2. Reorganizar la matriz por clase a una cuadrícula compacta (2 columnas de 3 clases, o una tabla) para que no ocurra desbordamiento horizontal en pantallas pequeñas.
3. Revisar los `addStretch()` y márgenes para que "Acciones Globales" vuelva a su lugar.
4. Repetir la prueba de arranque en la resolución problemática del servidor.

*Mientras tanto: la ventana maximizada (o en pantalla grande) muestra todo; el problema es de acomodo, no de funcionalidad — la política y los contadores funcionan.*

---

## 3. Estado del pipeline completo

```
paquete (SPAN) ──► procesar_paquete (ids.py)
    ├─ heurísticas v5 ────────────► ALERTA (nivel 1, siempre activa)
    ├─ payload HTTP ──► TF-IDF+LogReg (M2) ─┐
    └─ FlowTracker v6 ─► CatBoost v6 (M3) ──┤
                                            ▼
                            MATRIZ DE POLÍTICA (M4/M6)
              ml+heuristica=🔴 bloquear 24h · ml=🟠 alertar 1h · heur=🟡 24h
                                            │
                     sombra: todo → ml_candidatos (nada notifica salvo clase reingresada)
```

**Operación actual:** `IDS_ML_V6=1` + sombra + Inyeccion_SQL reingresada; heurísticas alertando; bloqueo OFF en laboratorio.

---

## 4. Commits de la construcción (orden)

| Commit | Contenido |
|---|---|
| `095058e` | M0 línea base + script de descargas |
| `be38a8d` | CHANGELOG [28] + decisión de datasets |
| `75c12f5` | Corrección descargas (espejo HF oficial, ZIP exacto) |
| `a7c5e9e` | M0 CERRADO (fuga 83,7 % solo-puerto) |
| `a571a21` | M1 FlowTracker v6 + tests |
| `6e6c170` | M1 CERRADO (dataset v6 sellado) |
| `f4619c5` | Grabber a prueba de apagones + R6 medido |
| `7414f27` | [30] Solo CSIC, grabber descartado |
| `9ec51cc` | CSIC verificado (espejo falso descartado) |
| `d76a141` | M2 CERRADO (P=0,9977, LightGBM→LogReg) |
| `bc8cd29` | M3 ablación por fuente (fuga de fuente > fuga de puertos) |
| `2ccb4cd` | M3 CERRADO (CatBoost v6 + umbrales) |
| `f3aa23e` | M4 CERRADO (matriz + ml_candidatos + T7) |
| `c5adbc1` | M5 LANZADA (tarea al iniciar sesión) |
| `da5c51a` | M6 INICIADA (M5 cerrado + Inyeccion_SQL activa) |
| `94d6d07` | GUI: bloqueo calibrados + sección ML v6 |
| *(este)* | Avance M0→M6 documentado + pendiente responsive GUI |

## 5. Comandos de operación rápida

```powershell
# Estado de la fase sombra
schtasks /query /tn "IDS-Lab-M5-V6"
Get-Content logs_ciberseguridad\gui_v6_m5.log -Tail 20

# Candidatos por clase/decisión (revisión semanal M6)
venv\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect('intrusiones_v5.db'); [print(r) for r in c.execute(\"SELECT clase_predicha, decision, COUNT(*) FROM ml_candidatos WHERE ts_utc > '2026-11-11' GROUP BY 1,2\")]"

# Reingresar/quitar una clase: editar config/politica_bloqueo.json (por_clase)
# Rollback total a producción v5: IDS_POLITICA=heuristica (o cerrar y usar main)
```
