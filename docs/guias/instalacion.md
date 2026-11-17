# Guía de instalación (Windows)

Guía paso a paso para poner en marcha el sistema IDS/IPS en **Windows**
(entorno objetivo, rama `ml-v6` del laboratorio).

> **Guía principal:** [docs/PORTABILIDAD.md](../PORTABILIDAD.md) contiene el
> procedimiento completo (preparación del ZIP, actualización, mover la carpeta,
> desinstalación y solución de problemas). Esta página es el resumen operativo.

---

## 1. Requisitos del sistema

| Componente | Mínimo recomendado |
|---|---|
| SO | Windows 10/11 (64 bits) |
| Python | 3.12 de 64 bits (mínimo 3.10), detectable con `py` o en `PATH` |
| Npcap | Última versión estable, instalada como Administrador |
| Git + Git LFS | Solo si la carpeta conserva `.git/` (para `git lfs pull`) |
| Permisos | Administrador, para registrar la tarea programada |
| GPU | Opcional: NVIDIA + drivers CUDA para entrenar con `task_type='GPU'` |
| Disco | ~1,5 GB libres (modelos); los datasets van aparte |

---

## 2. Instalación con el kit portable (recomendada)

### Paso 1 — Copiar la carpeta

Copiar el proyecto a la PC destino, por ejemplo `C:\IDS-IPS\Proyecto-IPS-IDBS-ML`.
No copiar `.venv/`, bases de datos, logs, `datasets/` ni `Dataset_Limpio/`.

### Paso 2 — Ejecutar el instalador como Administrador

Clic derecho en `scripts\instalar_windows.bat` → **Ejecutar como administrador**.

El instalador crea `.venv`, instala `requirements-windows.txt`, ejecuta
`git lfs pull` (si hay `.git`), detecta Npcap, crea `logs_ciberseguridad/` y
`.env`, registra la tarea `IDS-Lab-V6-Activo` (`ONLOGON`) y verifica todo.
**No lanza el motor.**

Si se abre una ventana pidiendo permisos o aparece `Acceso denegado`, el
motivo es la falta de elevación: repetir con clic derecho.

### Paso 3 — Npcap

Si el instalador avisó que falta:

1. Descargar desde https://npcap.com/.
2. Instalar como Administrador.
3. Verificar con `sc query npcap`.

El kit **no instala Npcap**: es un driver de kernel cuya redistribución
requiere licencia OEM. Sin él no hay captura de tráfico real.

### Paso 4 — Iniciar sesión

Cerrar sesión y volver a entrar. La tarea lanza `scripts\lanzar_v6_lab.bat`
y abre la GUI con el v6 activo. Esa ventana es el motor: no cerrarla.

### Paso 5 — Verificar

```powershell
scripts\verificar_windows.bat
schtasks /query /tn "IDS-Lab-V6-Activo" /fo LIST /v
Get-Content logs_ciberseguridad\gui_lab-v6-activo.log -Tail 20
```

Resultado esperado en el log:

```text
[OK] Modelos v6 cargados (sombra=NO): CatBoost v6 (7 umbrales por clase) + detector de payload
```

`scripts\verificar_windows.bat` no inicia el sensor; comprueba dependencias,
modelos (detecta punteros LFS), Npcap, la tarea y el log.

---

## 3. Configuración

Copiar la plantilla si no existe (el instalador ya lo hace):

```powershell
copy .env.example .env
```

Editar `.env` con un editor de texto. Formato: `CLAVE=VALOR`, sin comillas,
sin `export`; las líneas que empiezan con `#` se ignoran. Variables principales:

| Variable | Uso |
|---|---|
| `IDS_IFACE` | Nombre exacto de la NIC del SPAN; vacío = autodetección |
| `IDS_DB_PATH` | Base SQLite (def. `intrusiones_v5.db`) |
| `LOG_FOLDER` | Carpeta de logs (def. local si no existe la unidad `D:`) |
| `IDS_TELEGRAM_TOKEN` / `IDS_TELEGRAM_CHAT_IDS` | Alertas de Telegram |
| `MIKROTIK_*` | Router para bloqueo IPS |

El lanzador del laboratorio fija siempre `IDS_ML_V6=1`, `IDS_ML_SOMBRA=0`,
`IDS_ML_ALERTAS=0`, `IDS_IPS_AUTONOMO=0`, `IDS_RUN_ID=lab-v6-activo` y
`IDS_AUTO_INICIAR=1`.

---

## 4. Comprobar los modelos

El motor espera estos artefactos en `Modelos_Entrenados/`:

- **v5:** `pipeline_catboost_v5.pkl`, `selected_features_v5.pkl`, `label_encoder_v5.pkl`,
  `sqli_guard.pkl`, `sql_guard_features.pkl`
- **v6:** `pipeline_catboost_v6.pkl`, `features_v6.pkl`, `umbrales_v6.pkl`,
  `sqli_payload.pkl` (y `label_encoder_v6.pkl` como complemento)

Todos los `.pkl` van por Git LFS. Si clonaste el repo y no bajaron:

```powershell
git lfs install --local
git lfs pull
```

Un puntero LFS mide ~130 bytes y empieza por
`version https://git-lfs.github.com/spec/v1`; no es un modelo. El verificador
lo detecta automáticamente.

> [!NOTE]
> Si faltan modelos, el IDS sigue funcionando con **detección heurística**,
> pero el canal v6 no carga. No es aceptable para el laboratorio.

---

## 5. Instalación manual (alternativa)

Para desarrollo, sin kit ni tarea programada:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-windows.txt
git lfs install --local
git lfs pull
sc query npcap

# Arrancar la GUI del laboratorio con v6 activo
scripts\lanzar_v6_lab.bat

# Arrancar la GUI sin flags del laboratorio
.\.venv\Scripts\python.exe interfasc.py
```

`requirements-windows.txt` incluye CatBoost, pandas, numpy, scikit-learn,
imbalanced-learn, joblib, tqdm, PyQt5, PyQt-Fluent-Widgets, matplotlib, Scapy,
paramiko, requests, pyarrow y LightGBM (entre otros, todos con versión fija).

> [!TIP]
> Si el entrenamiento no dispone de GPU, cambiar `task_type='GPU'` por `'CPU'`
> en `CEREBRO_V5.py` / `entrenar_sqli_guard.py`.

---

## 6. Actualizar, mover y desinstalar

```powershell
# Actualizar código, modelos y dependencias (no lanza el motor)
scripts\actualizar_windows.bat

# Detener el proceso actual sin borrar la tarea
schtasks /end /tn "IDS-Lab-V6-Activo"

# Desinstalar arranque automático y entorno
schtasks /delete /tn "IDS-Lab-V6-Activo" /f
rmdir /s /q .venv
del .env
```

Si la carpeta se mueve a otra ruta, `schtasks` sigue apuntando a la anterior:
volver a ejecutar `scripts\instalar_windows.bat` como Administrador.

---

## 7. Solución de problemas

| Síntoma | Causa probable | Acción |
|---|---|---|
| `Acceso denegado` al registrar la tarea | Sin elevación | Ejecutar como Administrador |
| No se captura tráfico | Npcap ausente / interfaz incorrecta | `sc query npcap`; fijar `IDS_IFACE` en `.env` |
| `[!] No se pudieron cargar los modelos v6` | `.pkl` son punteros LFS | `git lfs install --local && git lfs pull` |
| `ImportError: qfluentwidgets` | Falta PyQt-Fluent-Widgets | `.\.venv\Scripts\python.exe -m pip install PyQt-Fluent-Widgets` |
| `pip install` falla | Sin red o proxy | Repetir; configurar `PIP_INDEX_URL` si aplica |
| La GUI abre pero no arranca la captura | `IDS_AUTO_INICIAR` no llegó | Revisar `.env` y usar `scripts\lanzar_v6_lab.bat` |
| La tarea apunta a ruta inexistente | Carpeta movida | Re-registrar con el instalador |
| Bloqueos siempre "simulado" | Sin acceso SSH al MikroTik | Configurar `MIKROTIK_*` o dejar `IDS_IPS_AUTONOMO=0` |

Para el detalle completo, ver [docs/PORTABILIDAD.md](../PORTABILIDAD.md).
