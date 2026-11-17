# Portabilidad en Windows — kit de un clic

**Rama:** `ml-v6` · **Estado:** laboratorio configurado con v6 activo · **Producción `main`: intacta**

Este documento explica cómo llevar el proyecto a otra PC de Windows y dejarlo
funcionando sin Docker, sin Python embebido y sin rutas absolutas.

---

## 1. Decisión tomada y por qué

Se descartó Docker para esta fase. Un contenedor Windows no soporta GUI ni
drivers de captura (Npcap es un driver de kernel), y un contenedor Linux en
Docker Desktop no ve la NIC de Windows donde llega el SPAN. Docker daría un
Python reproducible, pero **no daría un sensor funcionando en Windows**.

La opción elegida es un **kit portable en carpeta**:

```
copiar carpeta → scripts\instalar_windows.bat (Administrador) → cerrar/iniciar sesión → GUI con v6 activo
```

El instalador **no lanza el motor**. El arranque lo hace la tarea programada
`IDS-Lab-V6-Activo` con disparador `ONLOGON` en el próximo inicio de sesión.

> `ONLOGON` y no `ONSTART`: la GUI es el motor y necesita una sesión
> interactiva. Si la sesión entra sola al encender el PC (configurado con
> `netplwiz`), equivale a "arrancar al encender".

---

## 2. Qué se lleva y qué no

### Se incluye en la carpeta / ZIP

| Elemento | Por qué |
|---|---|
| Código `*.py`, `config/`, `scripts/`, `docs/` | Es portable: usa `__file__` y variables de entorno |
| `Modelos_Entrenados/*.pkl` **reales** (v5 + v6, ~160 MB útiles) | Sin ellos el motor degrada a heurística; van por Git LFS |
| `requirements-windows.txt` | Versiones congeladas, idénticas a `requirements-v6.txt` |
| `.env.example`, `.gitattributes`, `.gitignore` | Plantilla limpia y reglas LFS |

### NO se incluye

| Elemento | Motivo |
|---|---|
| `.venv/` | No es reubicable; se crea en cada PC |
| `*.db`, `backups/` | Estado con IPs de terceros; se crean vacíos en destino |
| `logs_ciberseguridad/*.log` | Contienen IPs reales; la carpeta se crea vacía |
| `datasets/` (7,5 GB), `Dataset_Limpio/` (807 MB) | Solo para reentrenar; se descargan aparte |
| Modelos v3/v4/rf_individual (~250 MB) | No los carga el motor |
| `.env` | Copia local con secretos; se genera desde la plantilla |
| `.git/` (opcional) | Si se omite, no hay `git pull`; ver §5 |

---

## 3. Requisitos en la PC destino

| Requisito | Detalle |
|---|---|
| SO | Windows 10/11 de 64 bits |
| Python | 3.12 de 64 bits recomendado (mínimo 3.10). El instalador prueba `py -3.12` → `py -3` → `python` |
| Npcap | Última versión estable, instalada como Administrador. **El instalador solo la detecta y avisa** |
| Git + Git LFS | Solo si la carpeta conserva `.git/`; necesario para bajar los `.pkl` |
| Red | NIC conectada al puerto SPAN / port mirror del switch |
| Permisos | Ejecutar el instalador como Administrador (para `schtasks`) |

> Npcap no se instala automáticamente: es un driver de kernel y redistribuirlo
> requiere licencia OEM. Descargarlo desde **https://npcap.com/** e instalarlo
> con el instalador normal, como Administrador.

---

## 4. Instalación paso a paso

### Paso 1 — Copiar el proyecto

Copiar la carpeta completa a la PC nueva, por ejemplo a `C:\IDS-IPS\Proyecto-IPS-IDBS-ML`.

- Si se copia desde un clon con `.git/`, conservar la carpeta `.git` para poder
  usar `git pull` y `git lfs pull` después.
- Si se entrega un ZIP sin `.git`, **verificar antes** que los `.pkl` son archivos
  reales y no punteros de texto (§7, problema 2).

### Paso 2 — Ejecutar el instalador como Administrador

Clic derecho en `scripts\instalar_windows.bat` → **Ejecutar como administrador**.

El instalador hace, en este orden:

| # | Acción | Resultado |
|---|---|---|
| 1 | Comprobar elevación | Falla con mensaje claro si no es Admin |
| 2 | Resolver Python | `py -3.12` → `py -3` → `python` |
| 3 | Crear `.venv` | `.venv\Scripts\python.exe` (se reutiliza si ya existe) |
| 4 | Instalar dependencias | `pip install -r requirements-windows.txt` |
| 5 | Bajar modelos | `git lfs install --local` + `git lfs pull` si hay `.git` |
| 6 | Detectar Npcap | Aviso con enlace si falta; **no lo instala** |
| 7 | Preparar carpetas | `logs_ciberseguridad/`, `backups/` y `.env` desde la plantilla |
| 8 | Registrar tarea | `IDS-Prod-V6-Activo`, disparador `ONLOGON`, con `schtasks /f` (idempotente) |
| 9 | Verificar | Llama a `scripts\verificar_windows.bat` |

Al terminar, **no se ha lanzado nada**.

### Paso 3 — Instalar Npcap si hizo falta

Si el instalador mostró el aviso de Npcap:

1. Descargar el instalador desde https://npcap.com/.
2. Ejecutarlo como Administrador (opción "WinPcap API compatible" si el switch
   exige compatibilidad; el laboratorio usa Npcap nativo).
3. Reiniciar si el instalador lo pide.
4. Comprobar: `sc query npcap`.

### Paso 4 — Cerrar sesión y volver a iniciarla

No hace falta reiniciar el PC: con cerrar sesión y entrar de nuevo, la tarea
`ONLOGON` dispara `scripts\lanzar_v6_produccion.bat` (producción v6 en `ml-v6`).

Si se quiere forzar manualmente **sin** registrar la tarea:

```powershell
scripts\lanzar_v6_produccion.bat
```

Esa ventana es el motor: **no cerrarla** (minimizar sí es seguro).
`main` permanece como línea base v5 y no recibe este lanzador.

### Paso 5 — Verificar que arrancó con v6 activo

```powershell
# Chequeo completo (no inicia el sensor)
scripts\verificar_windows.bat

# Log del run
Get-Content logs_ciberseguridad\gui_prod-v6-activo.log -Tail 20
```

La línea esperada en el log es:

```
[OK] Modelos v6 cargados (sombra=NO): CatBoost v6 (7 umbrales por clase) + detector de payload
```

Comprobación adicional de arranque automático:

```powershell
schtasks /query /tn "IDS-Prod-V6-Activo" /fo LIST /v
```

Debe mostrar `Estado: Listo` y `Iniciar: Al iniciar sesión`.

### Paso 6 — Confirmar la medición pasiva

Con las clases activas, toda predicción se guarda en `ml_candidatos`
(incluso las descartadas), así que la medición no se pierde:

```powershell
.venv\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect('intrusiones_v5.db'); [print(r) for r in c.execute(\"SELECT clase_predicha, decision, COUNT(*) FROM ml_candidatos WHERE run_id='prod-v6-activo' GROUP BY 1,2\")]"
```

### Paso 7 — Repetir las pruebas T sobre v6

```powershell
scripts\ejecutar_t_v6.bat
```

Hace el preflight y corre T1v6, T2v6 (=T6) , T3v6 y T4v6. **No lanza el sensor
y no regenera el dataset v6**: el CSV debe estar ya en
`Dataset_Limpio\dataset_global_unipaz_v6.csv`. El informe nuevo es
`informe_test_masivo_v6.json`; el histórico `informe_test_masivo.json` no se toca.

T5v6 se ejecuta aparte con las 3 CHR encendidas:

```powershell
setx MIKROTIK_PROFILE lab
setx IDS_IPS_AUTONOMO 1
.venv\Scripts\python.exe docs\lab\t5_routeros_v6.py --evidencia-dir docs\lab\corridas\v6
```

---

## 5. Configuración (`.env`)

El lanzador lee `.env` de la raíz **antes** de fijar los flags de producción.
Formato: una línea `CLAVE=VALOR`, sin `export`, sin comillas y sin espacios
alrededor de `=`. Las líneas que empiezan con `#` se ignoran. Los flags del
lanzador tienen prioridad sobre `.env`.

Flags que el lanzador fija siempre (no se pueden cambiar desde `.env`):

```
IDS_ML_V6=1          IDS_ML_SOMBRA=0      IDS_ML_ALERTAS=0
IDS_IPS_AUTONOMO=0   IDS_RUN_ID=prod-v6-activo
IDS_MODO_OBSERVACION=0
```

Variables útiles que sí se leen de `.env`:

| Variable | Uso |
|---|---|
| `IDS_IFACE` | Nombre exacto de la NIC del SPAN; vacío = autodetección |
| `IDS_DB_PATH` | Ruta de la base SQLite (def. `intrusiones_v5.db`) |
| `LOG_FOLDER` | Carpeta de logs (def. `logs_ciberseguridad`) |
| `IDS_TELEGRAM_TOKEN` / `IDS_TELEGRAM_CHAT_IDS` | Credenciales de Telegram |
| `MIKROTIK_*` | Credenciales del router (solo si se activa IPS) |

---

## 6. Actualizar y desinstalar

### Actualizar a una versión nueva

Clic derecho en `scripts\actualizar_windows.bat` → Ejecutar como administrador.
Hace `git pull` + `git lfs pull` + reinstall en el mismo `.venv` y después
verifica. No lanza el motor.

### Mover la carpeta a otra ubicación

`schtasks` guarda la ruta **absoluta** del `.bat` en el momento de registrar.
Si se mueve la carpeta después de instalar, la tarea apuntará a la ruta vieja.
Solución: volver a ejecutar `scripts\instalar_windows.bat` como Administrador
(el `schtasks /f` sobrescribe la tarea) o directamente
`scripts\instalar_tarea_v6_produccion.bat`.

### Desinstalar

```powershell
schtasks /delete /tn "IDS-Prod-V6-Activo" /f
rmdir /s /q .venv
del .env
```

Quedan intactos: código, modelos, BD y logs. Para borrar el estado del run v6,
eliminar `intrusiones_v5.db` y `logs_ciberseguridad\`.

### Freno de emergencia sin tocar código

- Toggle **"Modo SOMBRA"** en la GUI (efecto inmediato).
- Variable de entorno `IDS_POLITICA=sombra`.
- `schtasks /end /tn "IDS-Prod-V6-Activo"` detiene el proceso actual sin borrar la tarea.

---

## 7. Solución de problemas

| Síntoma | Causa | Acción |
|---|---|---|
| `Acceso denegado` al registrar la tarea | Falta elevación | Clic derecho → Ejecutar como administrador |
| `No se pudo crear .venv` | Python no está en PATH o es de 32 bits | Instalar Python 3.12 de 64 bits marcando "Add Python to PATH" |
| `[!] No se pudieron cargar los modelos v6` | Los `.pkl` son punteros LFS | `git lfs install --local && git lfs pull` |
| `pip install` falla | Sin internet o proxy | Repetir; si hay proxy, configurar `PIP_INDEX_URL` |
| No se captura tráfico | Npcap ausente o interfaz incorrecta | `sc query npcap`; fijar `IDS_IFACE` en `.env` con el nombre exacto |
| `ImportError: qfluentwidgets` | Dependencia incompleta | `.\.venv\Scripts\python.exe -m pip install PyQt-Fluent-Widgets` |
| Se abre la GUI pero no arranca la captura | `IDS_AUTO_INICIAR` no llegó al proceso | Revisar `.env` y usar `scripts\lanzar_v6_produccion.bat` |
| La tarea apunta a una ruta que ya no existe | Carpeta movida tras instalar | Reejecutar el instalador (§6) |

### Cómo detectar un puntero LFS a ojo

Un modelo real pesa MB; un puntero mide ~130 bytes y su primera línea es:

```
version https://git-lfs.github.com/spec/v1
```

`scripts\verificar_windows.bat` detecta este caso automáticamente.

---

## 8. Fase Linux y Docker

Linux se hará en una segunda fase con el mismo patrón:
`scripts\instalar_linux.sh` + `requirements-linux.txt` (idéntico sin `pywin32`) +
`systemd --user` o `@reboot`. En Linux no hay Npcap: Scapy usa `AF_PACKET` y
necesita `CAP_NET_RAW` o root.

Docker queda aparcado como opción C opcional: la imagen Linux `full` tiene
sentido para CI o para un host con SPAN real en Linux, pero no es la vía fácil
para Windows y no resuelve el driver de captura.

---

*Instituto Universitario de la Paz (UNIPAZ) · Ingeniería de Sistemas · rama `ml-v6`*
