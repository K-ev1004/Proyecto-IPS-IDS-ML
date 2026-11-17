# Próximos pasos — operación v6 (handoff)

> **Leer este archivo al retomar el proyecto.** Fecha: 2026-11-17 · Rama: `ml-v6` · Último commit: `e440288` (pusheado a `origin/ml-v6`).

## Regla de oro

**No ejecutar nada todavía salvo instrucción explícita del usuario.** No lanzar el motor, no registrar tareas programadas, no tocar `main`, no regenerar ni restaurar `Dataset_Limpio\dataset_global_unipaz_v6.csv`.

## Estado actual

- Producción v6 configurada **dentro de `ml-v6`** con lanzador y tarea propios; `main` queda como línea base v5 (no se mergeó).
- Flags previstos: `IDS_ML_V6=1`, `IDS_ML_SOMBRA=0`, `IDS_ML_ALERTAS=0`, `IDS_IPS_AUTONOMO=0`, `IDS_MODO_OBSERVACION=0`, `IDS_AUTO_INICIAR=1`, `IDS_RUN_ID=prod-v6-activo`.
- Batería `T*v6` preparada, **no ejecutada**. T5v6 preparada, **no ejecutada**.
- Evidencias históricas preservadas: `informe_test_masivo.json` y `docs/lab/informe_t5.json` (no sobrescribir).
- Validaciones ya pasadas: `py_compile` → 0; `scripts\verificar_windows.bat /NOPAUSE` → 0.
- Árbol de trabajo limpio salvo un `.sha512` de logs sin seguimiento, preexistente: **no incluirlo en commits**.
- En esta copia no hay `.venv`; los lanzadores caen al `python` del PATH, que pasó el chequeo. Si el usuario quiere el kit portable completo, ejecutar `scripts\instalar_windows.bat` como Administrador.

## 1. Cuando el usuario diga «comencemos con las T»

1. Comprobar **solo la existencia** de `Dataset_Limpio\dataset_global_unipaz_v6.csv`. Si falta, avisar y parar: **no regenerarlo**.
2. Ejecutar:

   ```powershell
   scripts\ejecutar_t_v6.bat
   ```

   Hace preflight y corre T1v6, T2v6 (=T6), T3v6 y T4v6. No lanza el sensor ni toca el dataset.
3. Leer `informe_test_masivo_v6.json`: revisar campo `PREFLIGHT` (si falló), `gates` y las cifras de `T1v6`, `T2v6`, `T3v6`, `T4v6`.
4. Si algún gate falla, **no parchear a ciegas**: leer el detalle del informe y el `error` de la prueba correspondiente, corregir solo eso y repetir.
5. Con cifras reales, actualizar `docs\tesis\matriz_evidencias_v6.md` (sección 2 y nota final) y, si aplica, `docs\ML_V6_AVANCE.md`.
6. Reportar al usuario los números y si T5v6 sigue pendiente.

Gates esperados: T1v6 `accuracy ≥ 0.80` y `f1_macro ≥ 0.70`; T2v6 `precision ≥ 0.995` y `< 10 ms/predicción`; T3v6 `≥ 1500` SQLi persistidos y `precision_cadena ≥ 0.95`; T4v6 línea de bloqueo escrita.

## 2. Cuando las 3 CHR estén disponibles (T5v6)

1. Verificar topología primero:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\_lab\provision_chr.ps1 -Configurar
   python .\_lab\verificar_lab.py        # debe dar 13/13
   ```

2. Ejecutar T5v6:

   ```powershell
   setx MIKROTIK_PROFILE lab
   setx IDS_IPS_AUTONOMO 1
   .venv\Scripts\python.exe docs\lab\t5_routeros_v6.py --evidencia-dir docs\lab\corridas\v6
   ```

   Si no hay `.venv`, usar `python.exe` del PATH.

3. Revisar los 9 gates en `docs\lab\corridas\v6\informe_t5_v6.json`. No tocar `docs\lab\informe_t5.json` (histórico v5, 9/9).
4. **Restaurar el entorno al terminar**, porque `setx` es persistente:

   ```powershell
   setx IDS_IPS_AUTONOMO 0
   ```

5. Actualizar `docs\tesis\matriz_evidencias_v6.md` y `docs\lab\README.md` con el resultado real de T5v6.

## 3. Cuando el usuario pida activar la producción v6

1. Ejecutar **como Administrador** `scripts\instalar_tarea_v6_produccion.bat` (o el instalador completo `scripts\instalar_windows.bat`, que ya registra `IDS-Prod-V6-Activo`). Solo registra la tarea: el motor arranca en el próximo inicio de sesión.
2. Cerrar sesión y volver a entrar; verificar:

   ```powershell
   schtasks /query /tn "IDS-Prod-V6-Activo" /fo LIST /v
   Get-Content logs_ciberseguridad\gui_prod-v6-activo.log -Tail 20
   ```

3. La línea de confirmación esperada: `[OK] Modelos v6 cargados (sombra=NO): CatBoost v6 (7 umbrales por clase) + detector de payload`.
4. Frenos / rollback sin tocar código: `IDS_POLITICA=sombra`, `IDS_POLITICA=heuristica`, toggle «Modo SOMBRA» en la GUI, o cerrar y usar `scripts\lanzar_gui.bat` desde `main`.

## Trampas ya conocidas (no repetir)

- `ids.py` lee `ML_V6` / `ML_SOMBRA` **al importar**: fijar variables de entorno antes de `import ids` (ya lo hacen los scripts v6).
- T3 histórico ponía `ML_ALERTAS=True` y por eso **no ejercitaba el canal v6**; T3v6 usa `ML_ALERTAS=0`.
- `ids.py` no carga `label_encoder_v6.pkl`; las clases v6 salen de `ids.modelo_v6.classes_`.
- En `.bat`, un paréntesis literal dentro de un `echo` dentro de un bloque `if (...)` rompe cmd (ya corregido en `verificar_windows.bat`).
- El override de política en T5v6 es **solo en memoria**; `config\politica_bloqueo.json` no se modifica.
- `docs\lab\t5_routeros_v6.py` usa filas reales del dataset v6 (33 features), **no** D2 convertido como la T5 histórica.
- Si `git lfs pull` no se ha hecho, los `.pkl` pueden ser punteros: el verificador lo delata.

## Archivos clave

| Archivo | Para qué |
|---|---|
| `scripts\ejecutar_t_v6.bat` | Preflight + T1v6…T4v6 |
| `test_masivo_v6.py` | Batería v6 → `informe_test_masivo_v6.json` |
| `docs\lab\t5_routeros_v6.py` | T5v6 → `docs\lab\corridas\v6\informe_t5_v6.json` |
| `scripts\lanzar_v6_produccion.bat` | GUI de producción v6 en `ml-v6` |
| `scripts\instalar_tarea_v6_produccion.bat` | Registra `IDS-Prod-V6-Activo` |
| `docs\tesis\matriz_evidencias_v6.md` | Matriz prueba/modelo/dataset/flags/informe/cifra/estado |
| `docs\ML_V6_AVANCE.md` §5 | Comandos de operación rápida |
| `docs\PORTABILIDAD.md` | Kit Windows y despliegue |
| `PROXIMOS_PASOS.md` | Este archivo |
