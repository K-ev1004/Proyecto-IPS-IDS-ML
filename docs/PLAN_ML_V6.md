# Plan ML v6 — Rehabilitación del modelo como detector primario

**Rama:** `ml-v6` (sale de `main`) · **Carpeta de trabajo:** `Proyecto-IPS-IDBS-ML-v6` (git worktree)
**Producción:** queda en `main` / carpeta original, con la GUI corriendo y heurísticas alertando. Esta rama NO la toca.
**Base del diagnóstico:** `docs/INFORME_C3_DATOS.md` — el modelo actual produce 276.007 FP / 72 h y 0 verdaderos.

## Entorno del laboratorio (ya montado)

| Elemento | Dónde |
|---|---|
| Código rama `ml-v6` | `C:\Users\Ciber-UNIPAZ\Desktop\Version 4 Ultra\Proyecto-IPS-IDBS-ML-v6` |
| Venv propio (mismas versiones) | `...\Proyecto-IPS-IDBS-ML-v6\venv` (congelado desde producción en `requirements-v6.txt`) |
| Corpus C3 etiquetado (banco de pruebas) | `...\Proyecto-IPS-IDBS-ML-v6\evidencia\db_archive\intrusiones_v5_c3-72h_20261104_161736.db` |
| Modelos actuales (línea base) | `Modelos_Entrenados\pipeline_catboost_v5.pkl`, `sqli_guard.pkl` |
| BD del laboratorio | `...\Proyecto-IPS-IDBS-ML-v6\intrusiones_v5.db` (propia, nunca la de producción) |

Regla: cada experimento usa `IDS_DB_PATH` propio y NO captura en `Ethernet`
mientras producción corre (el replay del corpus C3 no necesita red).

## Diagnóstico a corregir (medido en C3)

1. Sin dirección: el primer paquete visto se asume atacante → los retornos (Google/WhatsApp/QUIC) parecen ataques.
2. Flujo degenerado: IGMP/1-paquete → vector en cero → SQLiGuard P≈0,78.
3. Fuga de características: `Dst Port` casi etiqueta la clase en IDS2018 → reglas de puertos que no generalizan.
4. SQLi es de payload, pero SQLiGuard puntúa 9 features de flujo.
5. Umbral global único (0.85) para 7 clases, sin calibración.
6. Dataset (IDS2018) con distribución distinta a UNIPAZ.

## Fases y puertas de salida

| Fase | Entregable | Puerta para avanzar |
|---|---|---|
| **M0 — Línea base** | `scripts/evaluar_ml_c3.py`: replay del corpus C3 contra el modelo actual; matriz de confusión; FP/día; análisis con/sin `Dst Port` (fuga) | Informe con el "antes": FP/día formal del modelo actual |
| **M1 — Features direccionales** | `flujos_red.py` v6: bit de dirección real (SYN de inicio), contexto de servicio (puerto servicio vs efímero), IAT stats; dataset v6 regenerado | Misma clase con/sin puerto cambia → fuga documentada |
| **M2 — SQLi por payload** | Modelo TF-IDF char 1-3 grams + LightGBM/LogReg sobre D2 + HTTP benigno UNIPAZ (captura sanitizada local) | Precisión ≥ 99,5 % en holdout y FP ≤ 0,1 % en replay C3 |
| **M3 — CatBoost v6** | Reentrenamiento multiclase con features nuevas + umbral por clase (curvas PR) | Recall volumétricas ≥ heurísticas; FP < heurísticas en replay |
| **M4 — Arbitraje** | ML candidato + confirmación independiente (payload/puerto/dirección/contador heurístico) | FP/día ≈ 0 en replay completo con recall aceptable |
| **M5 — Fase sombra** | Tabla `ml_candidatos` (propia, nunca `ataques`), 3-7 días de tráfico real comparando vs heurísticas | FP reales ≤ 5/día; sin contradicciones sin explicar |
| **M6 — Reingreso por clase** | `IDS_ML_ALERTAS=1` clase por clase (primero la más precisa), heurísticas de respaldo | Revisión semanal FP < 5 % |

## Reglas del laboratorio

- Cada experimento: semillas fijas, métricas versionadas (`metricas_v6.txt`),
  commit propio. Nada de resultados "a ojo".
- Corpus benigno/payloads de UNIPAZ: solo en `datasets/` local (gitignored),
  sanitizado (ver `_sanear_muestra_sqli`), conforme a `docs/informe_privacidad_ips.md`.
- Producción (`main`) no recibe merges hasta M6 con su puerta cumplida.
- La GUI de producción no se detiene para trabajar aquí; el replay usa la BD
  archivada, no la red.
