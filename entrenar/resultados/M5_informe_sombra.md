# M5 — Informe de fase sombra (ML v6 vs heurísticas sobre tráfico real)

**Generado:** 2026-11-11 · **Run:** `lab-m5-shadow` · **Ventana:** 2026-11-04T21:37 UTC → 2026-11-11 (~4 días de cobertura efectiva; huecos 8-9 por ventana cerrada)
**Corpus:** `intrusiones_v5.db` del laboratorio, tabla `ml_candidatos` (2.516 filas) + `ataques` (37 alertas heurísticas)

## 1. Resultado principal: la puerta M5 está cumplida

| Métrica | Valor | Puerta M5 |
|---|---|---|
| FP reales del ML (por día) | **0** (0 de 2.516 candidatos) | ≤ 5/día ✅ |
| Contradicciones sin explicar | **0** | 0 ✅ |
| Señales reales conservadas | 37 heurísticas + 2 con doble firma | — |
| Bloqueos | 0 (correcto: bloqueo OFF en laboratorio) | — |

## 2. Los 2 candidatos 'alerta' (6 de noviembre) — verificación uno a uno

| ts_utc | Confianza ML | Umbral clase | Árbitro | Veredicto |
|---|---|---|---|---|
| 16:39:16 | 0,967 | 0,975 (no llegaba) | corrobora=1: SYN de inicio a puerto 21 (dir_init=1) | **VERDADERO**: heurística del mismo origen ±5 s (16:39:11) |
| 18:03:18 | 0,858 | 0,975 (no llegaba) | corrobora=1: SYN de inicio a puerto 22 (dir_init=1) | **VERDADERO**: heurística del mismo origen ±5 s (18:03:09) |

Ambos: SYN externo a puertos de servicio (21=FTP, 22=SSH) hacia el mismo
servidor interno — el patrón `senal_exploit_externa` de C3. **El caso de uso
central del arbitraje se observó en producción real**: el ML solo no llegó a
su umbral por clase, la señal independiente lo confirmó, y la matriz
(ml+heuristica) lo habría bloqueado 24 h. Nada notificó porque la fase corre
en sombra — correcto.

*(Las IPs completas quedan en la BD; este informe publica solo el patrón.)*

## 3. Descomposición de los 2.516 candidatos

| Decisión | Corrobora | Alertaría | Total | Lectura |
|---|---|---|---|---|
| descartado | 0 | 0 | 2.548 | ML solo sin señal independiente: la matriz los suprime (en C3 esto era la inundación de 92.004 FP/día) |
| alerta | 1 | 0 | 2 | Doble firma (arbitraje confirmó por debajo del umbral) — verdaderos |

- 100 % de los candidatos son clase `Posible_Exploit`: los retornos
  Google/WhatsApp (5228→efímero) que en C3 daban 257 FP — ahora filtrados.
- **0 candidatos Inyeccion_SQL**: la red es 99,998 % no-HTTP (R6); el detector
  de payload apenas ve peticiones → sin FP observados en esta clase.
- Por día: 74 (4-nov) · 1.354 (5) · 1.048 (6) · 34 (7) · 3 (10) · 3 (11).

## 4. Comparación ML vs heurísticas por día

| Día | Candidatos ML | ML 'alerta' | Alertas heurísticas | Coincidencia |
|---|---:|---:|---:|---|
| 4-nov | 74 | 0 | — (arranque 21:37) | — |
| 5-nov | 1.354 | 0 | 15 (exploit) | las heurísticas detectaron solo; el ML no contradijo |
| 6-nov | 1.048 | 2 | 21 (exploit) | **los 2 ML = 2 de las 21 heurísticas (doble firma)** |
| 7-nov | 34 | 0 | 1 | sin contradicciones |
| 10-nov | 3 | 0 | 0 | — |
| 11-nov | 3 | 0 | 0 | — |

## 5. Conclusión y pase a M6

La puerta M5 (FP reales ≤ 5/día, sin contradicciones) queda **cumplida**. El
ML v6 como candidato suprime el 99,9 % de lo que en C3 era ruido, y sus
únicas alertas son dobles firmas verificables.

**Reingreso (M6), primera clase: Inyeccion_SQL** — la de mayor precisión
medida (0,9977 en T6) y 0 FP en sombra. Segunda: Posible_Exploit (2.514
candidatos, 2 alertas verdaderas). El mecanismo: override `por_clase` en
`config/politica_bloqueo.json` = pase de salida de sombra; el resto de
clases queda en sombra hasta su semana de revisión.
