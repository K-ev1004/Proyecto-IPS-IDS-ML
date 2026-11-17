# ML v6 — Avance completo (M0 → M6) y estado del sistema

**Fecha:** 2026-11-11 · **Actualizado:** 2026-11-17 · **Rama:** `ml-v6` (laboratorio) · **Producción:** `main` intacta
**Resumen ejecutable:** el ML volvió a ser detector con evidencia medida en cada paso. El laboratorio queda **configurado para arrancar solo con el canal v6 activo** (6 clases fuera de sombra, bloqueo OFF y medición pasiva conservada en `ml_candidatos`), con GUI visible, a prueba de apagones y con política de bloqueo configurable desde la propia GUI. **Producción (`main`) sigue en v5 y no se ha tocado.**

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

### M6 — Reingreso por clase → reingreso total en laboratorio
- Mecanismo: salida de sombra **por clase** vía override en `config/politica_bloqueo.json` (el override es el pase de reingreso, auditable en git).
- **Primera clase activada: Inyeccion_SQL** (la más precisa: 0,9977; 0 FP en sombra; casi no se dispara por R6 = riesgo mínimo): ML solo → alertar 1 h; doble firma → bloquear 24 h.
- **Laboratorio (2026-11-17): las 6 clases activas de golpe** mediante `IDS_ML_V6=1` + `IDS_ML_SOMBRA=0` en `scripts\lanzar_v6_lab.bat`. Con sombra 0, `politica_bloqueo.decidir()` usa los defaults activos (`ml → alertar 60 min`, doble firma → `bloquear 1440 min`, heurística → `alertar 1440 min`) sin editar el JSON.
- La **medición pasiva no se pierde**: `_registrar_candidato_v6()` se ejecuta antes de los filtros de sombra/decisión, así que toda predicción sigue en `ml_candidatos` con clase, confianza, umbral, arbitraje, features y `decision`. Al activar una clase solo cambia `descartado → alerta`; los descartados siguen contando para la revisión FP < 5 %.
- Freno global intacto: toggle **"Modo SOMBRA"** en la GUI, `IDS_POLITICA=sombra` o quitar overrides del JSON. Revisión semanal FP < 5 % por clase (antes `Posible_Exploit`, luego volumétricas) aunque el laboratorio ya corra activo.

### GUI — Configuración de la v6
- **Botón de bloqueo de valores calibrados** (default BLOQUEADO, persistido): los 9 umbrales calibrados deshabilitados con su evidencia en tooltips; desbloquear exige doble confirmación y queda en el log.
- Sección **"ML v6"**: estado en vivo (30 s: CatBoost cargado, SOMBRA/ACTIVO, candidatos/descartados/alertas), **toggle sombra ↔ activo efectivo al instante**, **matriz por clase** (acción ML-solo / doble-firma + duración → guarda el JSON, aplica al instante), "Restaurar sombra (M6 off)".
- Umbrales v6 mostrados **solo lectura** (artefactos de entrenamiento).

---

## 2. ✅ RESUELTO: responsive de la GUI de Configuración

El desbordamiento documentado quedó corregido en el commit `c3546d5`:

1. `page_settings` envuelto en `ScrollArea` (qfluentwidgets con fallback Qt) → scroll vertical completo.
2. Contenido reorganizado en **5 cards**, con "Acciones Globales" al inicio y botones en `FlowLayout`.
3. Umbrales en grids 2x2; matriz M6 como `QGridLayout` de 5 columnas con cabecera, sin desbordamiento horizontal.
4. SpinBox de duración ampliado a **150 px** (con 95 px el `lineEdit` quedaba en 3 px y el valor no se veía); `10080` mide 40 px.
5. Ancho mínimo del contenedor **984 → 726 px**; tooltips en acciones y celdas.

Verificación: `python -m py_compile interfasc.py` OK, 14 checks funcionales PASS. La batería de 60 tests no se ejecutó aquí (`pytest` no está instalado en este intérprete).

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

**Operación actual (laboratorio, configurado pero NO lanzado en esta sesión):** `IDS_ML_V6=1` + `IDS_ML_SOMBRA=0` + `IDS_RUN_ID=lab-v6-activo` + bloqueo OFF; heurísticas alertando; ML v5 en instrumentación (`IDS_ML_ALERTAS=0`). El arranque automático al iniciar sesión lo registra la tarea **`IDS-Lab-V6-Activo`** a través de `scripts\instalar_tarea_v6_lab.bat` (requiere ejecutarse como Administrador). `[ONLOGON]` y no `[ONSTART]` porque la GUI es el motor y necesita sesión interactiva; si la sesión entra sola al encender el PC, equivale a arranque automático.

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
| `c3546d5` | GUI: configuracion responsive con scroll y matriz v6 compacta (termina el pendiente) |
| *(este)* | Arranque automático del laboratorio con v6 activo + documentación |

## 5. Comandos de operación rápida

```powershell
# Estado del arranque automático (requiere haber ejecutado el instalador como Admin)
schtasks /query /tn "IDS-Lab-V6-Activo" /fo LIST /v

# Log del run activo (el lanzador NO se ejecutó al preparar esto)
Get-Content logs_ciberseguridad\gui_lab-v6-activo.log -Tail 20
# Debe aparecer: [OK] Modelos v6 cargados (sombra=NO): CatBoost v6 (7 umbrales por clase) + detector de payload

# Candidatos por clase/decisión — la medición pasiva se conserva con clases activas
python -c "import sqlite3; c=sqlite3.connect('intrusiones_v5.db'); [print(r) for r in c.execute(\"SELECT clase_predicha, decision, COUNT(*) FROM ml_candidatos WHERE run_id='lab-v6-activo' GROUP BY 1,2\")]"

# Instalar / desinstalar el arranque automático
scripts\instalar_tarea_v6_lab.bat        # clic derecho -> Ejecutar como administrador
schtasks /delete /tn "IDS-Lab-V6-Activo" /f

# Freno inmediato sin tocar código: toggle "Modo SOMBRA" en la GUI o IDS_POLITICA=sombra
# Rollback total a producción v5: IDS_POLITICA=heuristica (o cerrar y usar main)
```
