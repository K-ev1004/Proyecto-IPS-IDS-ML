# M3 — Ablation de puertos con holdout por fuente (CIC 2017 ↔ 2018)

**Generado:** 2026-11-04 · semilla 42 · CatBoost 400 iter · class_weights (sin SMOTE)
**Datos:** `dataset_global_unipaz_v6.csv` (3.720.533 filas × 33 features + fuente)

## 1. Tabla de generalización cruzada

| Entrenamiento → Validación | Features | Accuracy | Macro-F1 | FP sobre Normal |
|---|---|---:|---:|---:|
| 2017 → 2018 | con puerto (33) | 0,5526 | 0,2915 | 8,791 % |
| 2017 → 2018 | sin puerto (32) | 0,5038 | 0,2162 | 7,199 % |
| 2018 → 2017 | con puerto (33) | 0,3828 | 0,1612 | 6,912 % |
| 2018 → 2017 | sin puerto (32) | 0,2965 | 0,0777 | 16,795 % |

## 2. El hallazgo principal: la fuga de FUENTE, mayor que la de puertos

El v5 reportaba accuracy 0,8655 (T1, split aleatorio del dataset mezclado).
Al separar por fuente, la generalización colapsa a **0,30–0,55**: el split
aleatorio mezclaba tráfico del mismo día/origen en train y test — la métrica
estaba inflada por fuga de fuente. **Esta es la evidencia cuantitativa de que
"accuracy de dataset CIC" nunca midió capacidad de detección real**, y de por
qué la v6 exige replay C3 + fase sombra como vara final.

## 3. Veredicto de puertos (matiz)

- Dirección 2017→2018: sin puerto reduce FP (7,2 % vs 8,8 %) — consistente
  con la hipótesis de fuga de M0.
- Dirección 2018→2017: con puerto reduce FP de forma drástica (6,9 % vs
  16,8 %) — los puertos, combinados con las features direccionales v6
  (dst_port_svc, init_win_bytes), ayudan a separar servicio de efímero.
- Señales opuestas con n=2 fuentes: el promedio favorece con_puerto
  (FP 7,85 % vs 12,0 %) y la dirección más difícil (2018→2017) lo hace de
  forma contundente.

**Decisión:** modelo final CON puerto, y el veredicto definitivo con/sin
puerto se toma en M5 con `ml_candidatos` (tráfico real UNIPAZ), como el plan
contempla. El JSON `M3_ablacion_puertos.json` queda como insumo de la tesis:
la tensión holdout-sintético vs generalización real ES el resultado.

## 4. Implicación para los umbrales por clase

Los umbrales calibrados en holdout aleatorio (85/15) son optimistas frente a
la deriva de fuente (acaban de medirse: 7–17 % FP cruzado). Por eso la v6 NO
activa alertas ML por esto solo: M4 (arbitraje) y M5 (sombra, FP reales
≤ 5/día) son la red de seguridad antes de reingresar clase por clase (M6).
