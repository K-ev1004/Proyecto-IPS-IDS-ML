# Matriz de evidencias — extensión ML v6 (T1v6 … T5v6)

**Rama:** `ml-v6` · **Estado:** batería v6 preparada y configurada, **no ejecutada** en esta entrega · **Actualizado:** 2026-11-17

Esta matriz deja constancia de **qué se mide, con qué modelo, sobre qué datos, con qué banderas de ejecución y en qué informe** se registrará cada prueba de la extensión v6. Las corridas históricas v5 **no se sobrescriben**: `informe_test_masivo.json` y `docs/lab/informe_t5.json` se conservan tal cual. La evidencia v6 se escribe en archivos nuevos y separados.

## 1. Evidencias históricas preservadas (v5)

| Prueba | Modelo / componente | Fuente | Informe (intacto) | Cifra de referencia |
|---|---|---|---|---|
| T1 | CatBoost v5 (`pipeline_catboost_v5.pkl`) | `dataset_global_unipaz_v5.csv`, 150 000 flujos | `informe_test_masivo.json` → `T1` | accuracy 0.8629, F1-macro 0.7423 |
| T2 | SQLiGuard (`sqli_guard.pkl`, umbral 0.30) | D2 / Zenodo 6907252, 57 229 flujos | `informe_test_masivo.json` → `T2` | precision 0.9985, recall 0.7534, 33 FP |
| T3 | Cadena v5 + SQLiGuard (`on_flow_ready`) | D2 balanceado, 6 000 flujos, BD temporal | `informe_test_masivo.json` → `T3` | 2 343/3 000 SQLi persistidos, precision_cadena 0.9983 |
| T4 | `log_exporter.py` | IP de documentación | `informe_test_masivo.json` → `T4` | `linea_bloqueo_escrita=true` |
| T5 | Bloqueo real sobre RouterOS CHR | 3 CHR 7.23.7, topología UNIPAZ | `docs/lab/informe_t5.json` | 9/9 gates, readback `CONFIRMADO`, corte y restauración verificados |

> El histórico T3 ponía `ML_ALERTAS=True`, por lo que **no ejercitaba el canal v6**: `ids.on_flow_ready` solo llama a `procesar_candidato_v6` dentro de `if not ML_ALERTAS`. Por eso T3v6 se ejecuta con `ML_ALERTAS=0`.

## 2. Matriz de la extensión v6

| Prueba | Qué mide | Modelo / componente | Dataset o fuente | Flags del proceso | Informe de salida | Cifra clave | Estado |
|---|---|---|---|---|---|---|---|
| **T1v6** | Calidad multiclase y por umbral | `pipeline_catboost_v6.pkl`, 33 features, 7 umbrales por clase | `Dataset_Limpio/dataset_global_unipaz_v6.csv` (150 000 filas, **ya generado; no se regenera**) | `IDS_ML_V6=1`, `SOMBRA=0`, `ALERTAS=0`, `IPS_AUTONOMO=0`, `run_id=test-v6` | `informe_test_masivo_v6.json` → `T1v6` | accuracy, F1-macro, matriz de confusión, precisión/recall argmax y por umbral | **Preparada** |
| **T2v6** (= **T6**) | Detector de SQLi por payload | `sqli_payload.pkl` (M2: LogReg sobre TF-IDF de payload decodificado) | CSIC 2010 (`datasets/CSIC2010/b1_test-00000-of-00001.parquet`) | Igual que T1v6; umbral del propio bundle | `informe_test_masivo_v6.json` → `T2v6` y `T6` (alias) | precision, recall, F1, FP/benigno, ms por predicción (referencia M2: P=0.9977) | **Preparada** |
| **T3v6** | Cadena v6 real: candidatos, decisiones, persistencia y trazabilidad | `ids.on_flow_ready` → `procesar_candidato_v6` → `ml_candidatos` + tabla `ataques` | Filas **reales** del dataset v6 (3 000 `Inyeccion_SQL` + 3 000 `Normal`), BD temporal | `ML_V6=1`, `SOMBRA=0`, **`ML_ALERTAS=0`**, `IPS_AUTONOMO=0`, sin Telegram, sin bloqueo | `informe_test_masivo_v6.json` → `T3v6` | candidatos, descartados, alertas, `sql_persistidos`, precision/recall de cadena, `features_json` | **Preparada** |
| **T4v6** | Exportador de logs (independiente de la versión del modelo) | `registrar_bloqueo_log` / `obtener_carpeta_logs` | IP de documentación, carpeta de logs aislada | `LOG_FOLDER` temporal | `informe_test_masivo_v6.json` → `T4v6` | `linea_bloqueo_escrita=true` | **Preparada** |
| **T5v6** | Respuesta activa del IPS v6 sobre equipo real | CatBoost v6 + política M4/M6 + `bloquear_ip_mikrotik` | 3 CHR + una fila real de `Inyeccion_SQL` del dataset v6 (33 features) | `IDS_ML_V6=1`, `SOMBRA=0`, `ALERTAS=0`, `MIKROTIK_PROFILE=lab`, **`IDS_IPS_AUTONOMO=1` solo en el laboratorio** | `docs/lab/corridas/v6/informe_t5_v6.json` | 9 gates: SSH, reglas, ping base, detección, readback `CONFIRMADO`, corte `forward`, desbloqueo, restauración | **Pendiente de CHR** (no ejecutada) |

## 3. Condiciones de ejecución y gates

- **Preflight:** `scripts\ejecutar_t_v6.bat` exige `.venv`, modelos, `dataset_global_unipaz_v6.csv`, el corpus CSIC y los dos scripts v6. **No lanza el sensor, no registra tareas y no restaura ni regenera el dataset v6.**
- **Informe:** si falla el preflight, se escribe igualmente `informe_test_masivo_v6.json` con el campo `PREFLIGHT.error` para dejar rastro.
- **Gates v6:** T1v6 (`accuracy ≥ 0.80`, `f1_macro ≥ 0.70`), T2v6 (`precision ≥ 0.995`, `< 10 ms/predicción`), T3v6 (`≥ 1 500` persistidos, `precision_cadena ≥ 0.95`), T4v6 (línea escrita). T5v6 queda marcado como `PENDIENTE_CHR`.
- **Aislamiento:** los procesos fijan las variables de entorno **antes** de importar `ids` (porque `ids.py` lee `ML_V6`/`ML_SOMBRA` al importar) y usan una base SQLite y un `LOG_FOLDER` temporales. No escriben en la BD ni en los logs de producción.

## 4. Consideración metodológica de T5v6

Con la matriz versionada (`config/politica_bloqueo.json`), un SQLi detectado solo por ML se decide como `alertar`, de modo que no llegaría al actuador. Para probar **el bloqueo real** sin cambiar la configuración versionada ni la política de producción, `docs/lab/t5_routeros_v6.py` inyecta **solo en memoria de ese proceso** un override de `politica_bloqueo._cargar_config` que fuerza `Inyeccion_SQL` → `bloquear` durante 1440 minutos, tanto para `ml` como para `ml+heuristica`. El archivo de configuración en disco no se modifica y el override desaparece al terminar el proceso. La detección usa filas reales del dataset v6 (33 features), no el D2 convertido a CIC de la T5 histórica.

## 5. Cómo reproducir

```powershell
# T1v6 / T2v6(=T6) / T3v6 / T4v6
scripts\ejecutar_t_v6.bat

# T5v6 — solo con las 3 CHR encendidas y accesibles
setx MIKROTIK_PROFILE lab
setx IDS_IPS_AUTONOMO 1
.venv\Scripts\python.exe docs\lab\t5_routeros_v6.py --evidencia-dir docs\lab\corridas\v6
```

Las cifras concretas de la extensión v6 se incorporarán a esta matriz **después** de ejecutar cada prueba, sin alterar las cifras históricas de la sección 1.
