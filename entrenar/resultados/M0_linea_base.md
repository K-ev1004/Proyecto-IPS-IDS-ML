# M0 — Línea base del ML v5 contra el corpus C3

**Generado:** 2026-11-04T17:43:38+00:00 · semilla 42 · corpus 72 h read-only · sin captura de red

## 1. El "antes" (números formales)

| Métrica | Valor |
|---|---|
| Filas del corpus | 276,098 |
| Duración | 72.0 h |
| Alertas del canal ML (vivas) | 276,007 |
| **FP/día del canal ML v5** | **92,004.5** |
| Predicciones SQLi (vivas) | 275,744 |
| SQLiGuard replay: alertas | 275,835 |
| SQLiGuard replay: FP/día | 91,924.1 |
| SQLiGuard replay: precisión | 0.00025 |
| SQLiGuard replay: recall | 1.0 |
| Determinismo replay vs vivo | 275744/275744 |
| Latencia por predicción | 0.003 ms |

> Puerta M2 usa "FP ≤ 0,1 % en replay" y M4 "FP/día ≈ 0": comparar SIEMPRE contra esta tabla.

## 2. Descomposición del FP (familias clasificar_c3)

| Familia | Eventos | Alerta replay | Tasa | P. media | P. máx |
|---|---:|---:|---:|---:|---:|
| `fp_ml_sqli_sin_flujo` | 275,102 | 275,102 | 1.0 | 0.6765 | 0.9796 |
| `fp_ml_sqli_respuesta` | 641 | 641 | 1.0 | 0.8117 | 1.0 |
| `fp_ml_exploit_retorno` | 257 | 0 | 0.0 | 0.0 | 0.0016 |
| `senal_exploit_externa` | 65 | 65 | 1.0 | 0.7842 | 0.7842 |
| `fp_udp_retorno` | 12 | 12 | 1.0 | 0.7842 | 0.7842 |
| `fp_escaneo_wudo_7680` | 9 | 9 | 1.0 | 0.7842 | 0.7842 |
| `fp_ml_syn_unico` | 5 | 0 | 0.0 | 0.0 | 0.0001 |
| `senal_exploit_interna` | 4 | 4 | 1.0 | 0.7842 | 0.7842 |
| `fp_ml_sqli_flujo` | 1 | 1 | 1.0 | 0.3838 | 0.3838 |
| `fp_ml_ddos` | 1 | 0 | 0.0 | 0.0 | 0.0 |
| `fp_exploit_broadcast` | 1 | 1 | 1.0 | 0.7842 | 0.7842 |

## 3. Vectores en cero (defecto nº 1 del diagnóstico)

275,102 filas sin puertos/tráfico (99.64 %); SQLiGuard alertó 275,102. Esto confirma que la ausencia de dirección/puertos colapsa el vector y produce el 99,6 % de los FP.

## 4. FP por hora (picos)

- 2026-10-29T15:00 → 9,149 FP
- 2026-10-30T14:00 → 9,114 FP
- 2026-10-29T14:00 → 9,049 FP
- 2026-10-30T15:00 → 9,045 FP
- 2026-10-30T16:00 → 8,483 FP

## 5. Fuga de características (Dst Port)

Pendiente: requiere CSE-CIC-IDS2018 descargado (`--fuga` cuando datasets/CSE-CIC-IDS2018/ esté completo).
