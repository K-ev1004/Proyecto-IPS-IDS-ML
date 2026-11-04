# ML v6 — Guía completa de desarrollo (qué, cómo, con qué)

**Rama:** `ml-v6` · **Carpeta:** `Proyecto-IPS-IDBS-ML-v6` (worktree) · **Producción:** `main`, intacta.
**Complementos:** roadmap resumido en `docs/PLAN_ML_V6.md` · diagnóstico medido en `docs/INFORME_C3_DATOS.md`.

Este documento es el manual de construcción de la v6: arquitectura, datasets
(exactamente cuáles descargar y de dónde), cambios de código archivo por
archivo, cómo se reestructura cada modelo, protocolo de evaluación y
despliegue gradual.

---

## 1. Objetivo y principio de diseño

**Objetivo:** que el ML vuelva a ser el detector primario, con evidencia y
precisión demostrada, sin sacrificar la producción que hoy funciona.

**Principio de diseño (arquitectura de dos niveles + arbitraje):**

```
                        ┌─────────────────────────────────────────────┐
  paquete (SPAN) ──────►│ procesar_paquete (ids.py)                   │
                        │   ├─ heurísticas v5  ──────────────► ALERTA │  ← nivel 1 (hoy funciona)
                        │   ├─ payload HTTP ──► DETECTOR PAYLOAD v6   │  ← nivel 2a (nuevo)
                        │   │        (SQLi/XSS, TF-IDF+LightGBM)      │
                        │   └─ FlowTracker v6 ─► CatBoost v6 (candid.)│  ← nivel 2b (rehabilitado)
                        │                ▲                            │
                        │   ARBITRAJE: un candidato ML solo alerta    │
                        │   si una señal independiente lo confirma    │
                        │   (payload / puerto de servicio / dirección │
                        │    / contador heurístico)                   │
                        └─────────────────────────────────────────────┘
                                     │
                     modo sombra: todo candidato a ml_candidatos (BD aparte),
                     nada notifica hasta pasar las puertas de M5.
```

Reglas fijas:
- Las heurísticas v5 **nunca se apagan**: son el nivel 1 y la red de seguridad.
- El ML se re-activa **por clase y con puerta cumplida**, nunca todo a la vez.
- Toda evaluación es contra el **corpus C3 etiquetado** (276.098 filas con
  clase verdadera) y holdouts de datasets: nada "a ojo".

---

## 2. Diagnóstico que la v6 corrige (medido, no estimado)

| # | Defecto del modelo v5 | Cómo lo corrige la v6 |
|---|---|---|
| 1 | Flujo sin dirección: el primer paquete se asume atacante | `FlowTracker v6`: dirección real por SYN de inicio + flags in/out/lateral UNIPAZ |
| 2 | Vector en cero (IGMP, flujos de 1 paquete) | Ya filtrado en la entrada (fix 27); además features que no colapsan a 0 |
| 3 | Fuga de características: `Dst Port` casi etiqueta la clase en los datasets CIC | Ablation obligatoria: entrenar con y sin puerto, comparar, elegir con evidencia |
| 4 | SQLi evaluada sin payload | Detector de payload nuevo (TF-IDF + LightGBM) sobre el contenido HTTP |
| 5 | Umbral global único 0.85 | Umbral por clase fijado con curvas precisión-recall y objetivo de FP/día |
| 6 | Dataset sintético ≠ UNIPAZ | Validación final siempre en replay C3 + fase sombra en tráfico real |

---

## 3. Datasets: qué descargar, de dónde y para qué

Estado actual del laboratorio: solo `datasets/SQLi_Zenodo/D2_test.csv` (7,8 MB).
Todo lo demás hay que traerlo (los CSV pesados viven fuera de git).

| # | Dataset | Fuente | Tamaño aprox. | Para qué | Destino local |
|---|---|---|---|---|---|
| 1 | **CSE-CIC-IDS2018** (MachineLearningCSV) | UNB: `https://www.unb.ca/cic/datasets/ids-2018.html` — copia pública en AWS S3 (`s3://cse-cic-ids2018/MachineLearningCSV/`) | ~1,7 GB (10 CSV por día de captura) | Clases volumétricas y de explotación del multiclase | `datasets/CSE-CIC-IDS2018/` |
| 2 | **CIC-IDS2017** (MachineLearningCSV) | UNB: `https://www.unb.ca/cic/datasets/ids-2017.html` | ~230 MB | Refuerzo de Friday-* (Bruteforce, XSS, SQLi web) | `datasets/CIC-IDS2017/` |
| 3 | **CIC-DDoS2019** (opcional) | UNB: `https://www.unb.ca/cic/datasets/ddos-2019.html` | 500 MB–17 GB | Solo si se quiere ampliar DDoS; hoy lo cubre la heurística | `datasets/CIC-DDoS2019/` |
| 4 | **SQLi Zenodo 6907252** — `D1_train.csv` (Union SQLi, ~200K) y `D2_test.csv` (Blind SQLi PostgreSQL) | `https://zenodo.org/record/6907252` | D1 ~250 MB, D2 7,8 MB (ya está) | Entrenamiento/test del detector SQLi | `datasets/SQLi_Zenodo/D1_train.csv` |
| 5 | **CSIC 2010 HTTP** (opcional, recomendado) | `https://www.isi.csic.es/dataset/` (espejos en Kaggle) | ~30 MB | Tráfico HTTP normal + ataques web adicionales para el modelo de payload | `datasets/CSIC2010/` |
| 6 | **HTTP benigno UNIPAZ** (NUEVO, crítico) | Captura propia 3-7 días | objetivo ≥ 500K peticiones | **Es el dataset que evita repetir C3**: sin benignos reales, todo modelo sobre-aprende a atacar | `datasets/unipaz_http/` (solo local, sanitizado) |
| 7 | **Corpus C3 etiquetado** | Ya copiado al laboratorio | 160 MB | Banco de pruebas y replay (FP/día) | `evidencia/db_archive/intrusiones_v5_c3-72h_*.db` |

Notas de descarga:
- Los CSV de CIC traen columnas con espacios (p. ej. `Flow Duration`); el
  generador ya las normaliza (`generador_dataset_global.py`).
- Regla de privacidad: los datasets 5 y 6 contienen posibles datos personales →
  `datasets/` está en `.gitignore`; sanitizar con `_sanear_muestra_sqli`
  (sin credenciales) y publicar solo agregados en docs.

### 3.2 Decisión de descarga (2026-11-04, M0)

Evaluada la necesidad real de cada dataset contra el plan y `MAPEO_CLASES`
del generador:

| Dataset | Veredicto | Justificación |
|---|---|---|
| CSE-CIC-IDS2018 | **Descargar** (~6,4 GB) | Clases volumétricas/explotación + ablation de fuga M0/M3. OJO: el plan estimaba 1,7 GB; el análisis de viabilidad mide 6,4 GB (02-20-2018 pesa 3,9 GB). El bucket S3 oficial sirve los CICFlowMeter por día (`Processed Traffic Data for ML Algorithms/`), no el reempaquetado MachineLearningCSV; mismo contenido. |
| CIC-IDS2017 | **Descargar** (~230 MB) | Única fuente de `Port_Scanner` (viabilidad §5) + ataques web del viernes. |
| CIC-DDoS2019 | **Diferido** | Opcional según plan ("hoy lo cubre la heurística"). El set completo pesa ~30 GB (TFTP solo 9,3 GB). Si M3 muestra debilidad en DDoS/UDP, descargar subconjunto: UDPLag (158 MB) + Syn (637 MB) + DrDoS_LDAP (917 MB). |
| CIC-IDS2020 | **No necesario** | No está en el plan ni en `MAPEO_CLASES`; sus clases solapan 2018/2019 y no aporta cobertura nueva. Alcance de tesis innecesario. |
| SQLi Zenodo D1 | **Descargar** (~250 MB) | Entrenamiento del detector de payload M2. |
| CSIC 2010 | Opcional (si hay espejo) | Benigno HTTP adicional para M2; la fuente original suele estar caída. |

La descarga usa `scripts/descargar_datasets_v6.py` (reanudación + verificación
de tamaño + reporte en `entrenar/resultados/descargas_v6.txt`).

### 3.1 Corpus HTTP benigno de UNIPAZ (paso nuevo, crítico)

Es la pieza que faltó siempre: sin benignos reales, cualquier modelo aprende a
marcar todo. Plan de captura:

1. Activar en el laboratorio un *grabber* de payloads HTTP: solo peticiones
   hacia puertos web (80/443 decodificado si TLS no permite, 8080/8000...),
   puerto de servicio → efímero, `dport in PUERTOS_WEB`.
2. Guardar por fila: `ts_utc`, `ip_src` (truncada/anonimizada), `puerto`,
   `metodo`, `ruta` (sin query si trae `session=`), `payload` sanitizado
   (sin `password=`, `authorization`, `token`).
3. Objetivo: ≥ 500K peticiones en 3-7 días (el tráfico del SPAN a ~250 pps lo
   permite; la mayoría es HTTPS — ver riesgo R6).
4. Etiquetar todo como `Label=0` (benigno). **Nunca se versiona**; su hash
   queda en la ficha del experimento.

---

## 4. Cambios de código, archivo por archivo

### 4.1 `flujos_red.py` → FlowTracker v6 (features direccionales)

Cambios en `FlujoBidireccional` y `FlowTracker`:

1. **Dirección real:** al crear el flujo, si el primer paquete es SYN sin ACK
   (`tcp_flags` empieza con 'S' y no trae 'A'), ese origen es el *iniciador*.
   Si el primer paquete no es SYN, marcar `dir_desconocida=1` (no inventar).
2. **Nuevas features** (se agregan a `get_features_dict()`):

```python
'dir_init':        1 si src_ip inició, 0 si respondió, -1 desconocido,
'dst_port_svc':    1 si Dst Port < 1024 o puerto de servicio conocido,
'src_port_svc':    1 ídem para Src Port,
'unipaz_src':      1 si src ∈ 172.10/20/30 (ya existe _es_ip_interna),
'unipaz_dst':      1 ídem para dst,
'fwd_bwd_ratio':   Tot Fwd Pkts / max(1, Tot Bwd Pkts),
'bytes_per_pkt':   total_bytes / max(1, total_pkts),
'flow_iat_mean':   media de intervalos entre paquetes (ms),
'flow_iat_std':    desviación estándar de IAT (ms),
'init_win_bytes':  window del primer SYN (TCP window),
'pkt_dir_changes': número de cambios de dirección (ping-pong cliente/servidor),
```

3. **Ablation**: el dict completo se guarda; el entrenamiento decide si
   `Dst Port` entra o no (ver §6.2). `get_features_dict()` devuelve TODO.
4. Compatibilidad: `on_flow_ready` recibe el dict completo; los modelos viejos
   siguen funcionando leyendo solo sus features (`features_seleccionadas`).

### 4.2 `ids.py` — motor v6

1. **Carga doble de modelos** (v5 mientras v6 no apruebe su puerta):
   `modelo_v6 = None`; si existe `Modelos_Entrenados/pipeline_catboost_v6.pkl`
   y `features_v6.pkl`, cargar y usar; si no, quedarse en instrumentación.
2. **Umbral por clase:**

```python
UMBRAL_ML_POR_CLASE = {
    'Inyeccion_SQL':   float(os.environ.get('IDS_UMBRAL_SQLI',   0.97)),
    'Posible_Exploit': float(os.environ.get('IDS_UMBRAL_EXPLOIT',0.95)),
    'Port_Scanner':    float(os.environ.get('IDS_UMBRAL_SCAN',   0.95)),
    'SYN_Flood':       float(os.environ.get('IDS_UMBRAL_SYN',    0.97)),
    'DDoS_Distribuido':float(os.environ.get('IDS_UMBRAL_DDOS',   0.98)),
    'UDP_Flood':       float(os.environ.get('IDS_UMBRAL_UDP',    0.98)),
}
```
   (Valores iniciales de la calibración M3; se ajustan con las curvas PR.)

3. **Modo sombra** (`IDS_ML_SOMBRA=1`, el defecto de la v6 hasta M5): cada
   predicción del modelo, alerte o no, va a una tabla propia:

```sql
CREATE TABLE IF NOT EXISTS ml_candidatos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    run_id TEXT,
    ip_src TEXT, ip_dst TEXT,
    clase_predicha TEXT, confianza REAL,
    umbral_clase REAL, alertaria INTEGER,
    corrobora_heuristica INTEGER,   -- 1 si una señal independiente coincide
    features_json TEXT,             -- features v6 COMPLETAS (para replay futuro)
    decision TEXT                   -- 'alerta'|'candidato'|'descartado'
);
```
   **Esto resuelve para siempre el problema de C3**: desde el día 1 queda un
   corpus de flujos reales con features completas y etiqueta de lo que decidió
   el sistema.

4. **Detector de payload (nivel 2a):** donde hoy está `detectar_sql_injection`,
   además del regex, si hay payload HTTP y el modelo de payload está cargado:
   `prob = sqli_payload.predict_proba(payload)`; si supera su umbral → candidato
   con `origen='ml_payload'`. El regex queda como señal barata de arbitraje.
5. **Arbitraje (nivel de decisión):** un candidato ML solo se convierte en
   alerta si su señal independiente confirma (tabla §7). Si no, queda en
   `ml_candidatos` con `decision='descartado'` — nunca se pierde evidencia.
6. Nuevas env: `IDS_ML_SOMBRA`, `IDS_ML_V6=1`, `IDS_UMBRAL_<CLASE>`,
   `IDS_SQLI_PAYLOAD=1`.

### 4.3 Scripts de entrenamiento (carpeta `entrenar/`, nueva)

| Script | Qué hace |
|---|---|
| `entrenar/evaluar_ml_c3.py` | **M0**: carga `sqli_guard.pkl` + `pipeline_catboost_v5.pkl`, repasa el corpus C3 (las 276K features guardadas en `features_json` son exactamente las 9 de SQLiGuard) y produce matriz de confusión, FP/día y curvas. Además el estudio de fuga: multiclase sobre IDS2018 holdout con y sin `Dst Port` |
| `entrenar/train_sqli_payload.py` | **M2**: TF-IDF char 1-3 grams (max 50K) + LightGBM/LogReg sobre D1/D2 + CSIC + benigno UNIPAZ; exporta `sqli_payload.pkl` (vectorizador+modelo) y `metricas_sqli_payload.txt` con PR curves |
| `entrenar/train_catboost_v6.py` | **M3**: CatBoost v6 sobre `Dataset_Limpio/dataset_global_unipaz_v6.csv` (features nuevas) + features de flujo UNIPAZ reales de `ml_candidatos`; calibración por clase; exporta `pipeline_catboost_v6.pkl`, `features_v6.pkl`, `label_encoder_v6.pkl` |
| `entrenar/replay_c3.py` | Re-evalúa cualquier versión de modelo contra el corpus C3: FP/día, precisión por clase — la misma vara para todas las versiones |
| `entrenar/ablate_port.py` | Estudio de fuga de puertos (con/sin `Dst Port`, con/sin `Src Port`) |
| `entrenar/calibrar_umbral.py` | Curvas PR por clase y propuesta de umbral con objetivo de FP/día |

### 4.4 `generador_dataset_global.py` → v6

- Añadir las columnas nuevas de features a `FEATURES_V4` (las que existan en
  los CSV de CIC: IAT, Window, Active/Idle) y producir
  `dataset_global_unipaz_v6.csv`.
- Las features que CIC no trae (dirección real, unipaz_src/dst) **no se
  inventan**: se estiman del puerto/servicio y se marcan como derivadas; su
  valor real llega del tráfico de sombra (M5) para el fine-tuning.

### 4.5 `test_masivo.py` — experimentos nuevos

| Test | Qué mide |
|---|---|
| **T6** | Detector de payload: precisión/recall en D2 holdout + benigno UNIPAZ (objetivo P≥99,5 %) |
| **T7** | Arbitraje: replay C3 con el pipeline v6 completo → FP/día ≈ 0 |
| **T8** | Latencia: ms por predicción payload y por flujo (objetivo < 10 ms) |

### 4.6 GUI (`interfasc.py`) — mínimo

- Pestaña/etiqueta "ML v6 (sombra)": contador de candidatos/descartados del día
  (lee `ml_candidatos`). No toca el motor.

---

## 5. Cómo se reestructura cada modelo

### 5.1 CatBoost v6 (multiclase de flujo)

- **Entrada:** `dataset_global_unipaz_v6.csv` (CIC 2017+2018 [+2019]) con
  features v4/v5 + direccionales §4.1, y (fase M5+) flujos reales de
  `ml_candidatos` etiquetados por la decisión final del sistema.
- **Clases:** mantener las 7, pero con `class_weights` recalculados y sin SMOTE
  si el balance empeora la calibración (probar ambos, documentar).
- **Fuga de puertos:** dos modelos (con y sin `Dst Port`/`Src Port`). El que
  produzca menor FP en replay C3 gana. Hipótesis: sin puertos generaliza mejor
  aunque baje accuracy en el holdout sintético — esa tensión ES el resultado
  interesante de la tesis.
- **Calibración:** curvas PR por clase en holdout por fuente (entrenar con 2018,
  validar con 2017 y viceversa) → umbral por clase (§4.2).
- **Salida:** `pipeline_catboost_v6.pkl` + `features_v6.pkl` + `label_encoder_v6.pkl`
  + `metricas_v6.txt` (igual formato que v5 para comparación directa).

### 5.2 Detector de payload SQLi (nuevo)

- **Pipeline:** `URL-decode → lowercase → TF-IDF(char 1-3 grams, max 50K) →
  LightGBM` (fallback LogReg). Entrenamiento: D1 (Union) + 25 % de D2 como
  dev + CSIC normal + benigno UNIPAZ; test final: D2 completo (externo, como
  hace hoy SQLiGuard) + replay de peticiones reales.
- **Umbral:** el que dé precisión ≥ 99,5 % en el holdout benigno (la lección de
  C3: el umbral lo fija el benigno real, no el balance del dataset).
- **Ventaja estructural sobre SQLiGuard:** el payload SÍ contiene la señal; no
  se adivina por puertos y tamaños.
- **Relación con SQLiGuard v5:** se conserva como corroborador barato durante la
  fase sombra; al confirmarse el payload model, SQLiGuard pasa a histórico.

### 5.3 Arbitraje (quién decide qué)

| Candidato ML | Señal independiente que debe confirmar |
|---|---|
| Inyeccion_SQL (payload) | URL/payload decodificado contiene patrón fuerte (`_RE_SQLI_FUERTE`) o puerto web con dirección entrante |
| Posible_Exploit | SYN de inicio hacia `PUERTOS_EXPLOIT` con destino unicast (misma lógica del detector heurístico) |
| Port_Scanner | Contador v5: ≥ umbral/2 puertos distintos hacia el destino en la ventana |
| SYN_Flood / DDoS / UDP_Flood | Contador heurístico de la ventana ≥ umbral/2 (las heurísticas ya son confiables aquí) |

Si no hay confirmación → `ml_candidatos` con `decision='descartado'` (evidencia
conservada, sin alerta). Si la hay → alerta con `origen='ml+heuristica'`.

---

## 6. Protocolo de evaluación (la vara única)

1. **M0 (antes de tocar nada):** SQLiGuard v5 contra las 276.098 features
   guardadas del corpus C3 → FP/día formal. Éste es el número "antes".
2. **Holdout por fuente:** entrenar 2018→validar 2017 y viceversa; nunca
   mezclar train/test del mismo origen.
3. **Replay C3** (`entrenar/replay_c3.py`): toda versión de modelo pasa por el
   corpus completo; se publica FP/día y precisión por clase.
4. **T6/T7/T8** en `test_masivo.py` como pruebas automatizadas (exit 0).
5. **Fase sombra:** 3-7 días; comparación diaria ML vs heurísticas sobre
   `ml_candidatos`; informe con FP reales.
6. Todo resultado se versiona: `metricas_v6.txt`, `metricas_sqli_payload.txt`,
   commits con el dataset hash usado.

---

## 7. Despliegue gradual y rollback

| Etapa | Env | Efecto |
|---|---|---|
| Sombra | `IDS_ML_SOMBRA=1` (default v6) | Solo graba candidatos; alerta lo heurístico |
| Reingreso por clase | `IDS_ML_ALERTAS=1` + `IDS_UMBRAL_<CLASE>=x` | Primero la clase más precisa (payload SQLi), una a la vez |
| Pleno | Las 6 clases aprobadas | Heurísticas quedan como respaldo y arbitraje |
| **Rollback total** | `IDS_ML_ALERTAS=0` | Vuelve a producción heurística actual, sin tocar código |

---

## 8. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Sobreajuste a D2 (train/test del mismo origen) | Holdout por fuente + replay UNIPAZ como prueba final |
| HTTPS cifra el payload → poco benigno HTTP real | Capturar en puertos web internos sin TLS (80/8080), proxies, y usar CSIC como benigno adicional; documentar la limitación |
| Fuga de puertos no detectada a tiempo | M0 la mide primero; ablation obligatoria en M3 |
| El arbitraje reduce recall del ML | Medir recall en cada fase; las señales de arbitraje son baratas y específicas |
| Cambios rompen producción | Producción está en otra carpeta/rama y su GUI no lee este código; nada se mergea a `main` sin la puerta M6 |
| Tiempo de tesis | Cada fase deja resultado publicable por sí solo; M0+M2 ya son contribución |

---

## 9. Checklist de arranque (orden de ejecución)

- [x] Descargar IDS2018 MachineLearningCSV → `datasets/CSE-CIC-IDS2018/` (2026-11-04, vía S3 CICFlowMeter, 10/10 archivos)
- [x] Descargar IDS2017 MachineLearningCSV → `datasets/CIC-IDS2017/` (2026-11-04, espejo del ZIP oficial en HF, 8 CSV)
- [x] Descargar D1_train.csv (Zenodo 6907252) → `datasets/SQLi_Zenodo/` (2026-11-04, nombre real "SLQ Injection Attack for training (D1).csv")
- [ ] (Opcional) CSIC 2010 → `datasets/CSIC2010/`; CIC-DDoS2019 (diferido: 30 GB; subconjunto si M3 lo pide)
- [x] M0: `entrenar/evaluar_ml_c3.py` → informe línea base (FP/día "antes": 92.004,5) + fuga documentada (`M0_fuga_puertos.md`)
- [x] M1: features direccionales en `flujos_red.py` + dataset v6 (`dataset_global_unipaz_v6.csv`, 2,72 M filas × 33 features)
- [ ] Grabber de HTTP benigno UNIPAZ corriendo en el laboratorio (3-7 días)
- [ ] M2 → M3 → M4 → M5 → M6 según puertas de §6

## 10. Definition of Done (v6 lista)

- [ ] Replay C3: FP/día del pipeline v6 ≈ 0 y ≥ 1 señal real detectada por clase habilitada
- [ ] T6/T7/T8 en verde dentro de `test_masivo.py`
- [ ] Fase sombra ≥ 3 días con informe de FP reales ≤ 5/día
- [ ] Métricas versionadas y comparables v5 vs v6 (`metricas_v5.txt` vs `metricas_v6.txt`)
- [ ] Merge a `main` con la puerta M6 cumplida y documentación actualizada
