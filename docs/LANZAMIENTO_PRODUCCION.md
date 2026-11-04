# Guía de lanzamiento — IDS/IPS v5 en producción (UNIPAZ)

**Estado actual (2026-11-04):** el motor corre en este servidor en modo
**producción con alertas**, bloqueo desactivado. Umbrales calibrados con las
72 h de la corrida C3 (`docs/INFORME_C3_DATOS.md`). Esta guía explica cómo
lanzarlo, verificarlo, detenerlo y cambiar su configuración sin tocar código.

---

## 1. Configuración actual (resumen)

| Parámetro | Valor | Efecto |
|---|---|---|
| `IDS_MODO_OBSERVACION` | `0` | Persiste y **alerta por Telegram** |
| `IDS_IPS_AUTONOMO` | `0` | **Ningún bloqueo** automático (MikroTik intacto) |
| `IDS_ML_ALERTAS` | `0` | El ML solo cuenta flujos; la detección es heurística |
| `IDS_RUN_ID` | `prod-v5` | Trazabilidad de cada alerta en la BD |
| `IDS_DURACION_H` | `0` | Corre 24/7 hasta apagado o cierre de sesión |
| `IDS_HOSTS_GESTION` | `172.10.0.57,172.10.0.59` | Lista blanca de gestión (decisión 2026-10-28) |
| `IDS_IFACE` | `Ethernet` | Realtek 2.5GbE donde entra el SPAN (IP por DHCP, hoy `172.10.12.77`) |
| Umbrales de escaneo | 50 ext / 25 int / 20 horiz | Validados: en 72 h el tráfico normal nunca los alcanzó |

Estos valores viven en `scripts\lanzar_gui.bat`. **No hay que tocar
`ids.py`** para cambiar ninguno.

**Cómo corre desde 2026-11-04:** la producción es la **GUI visible**
(`interfasc.py`), que es a la vez el motor: la ventana muestra dashboard,
eventos, bloqueos y mapa, y **arranca la captura sola** al abrirse
(`IDS_AUTO_INICIAR=1`). `scripts\lanzar_observacion.bat` (el que llama la
tarea programada) delega en `lanzar_gui.bat`.

> **Importante:** la ventana es el motor. **Minimizar no afecta**; **cerrarla
> detiene la captura** (al cerrarse apaga el sniffer limpiamente). La tarea
> programada la vuelve a lanzar en el próximo inicio de sesión.

---

## 2. Cómo lanzarlo

### Opción A — Automática (la normal en producción)

Existe la tarea programada **`IDS-Observacion-C3`** que lanza el `.bat`
**al iniciar sesión** en el servidor. Es decir:

> Encender el servidor → iniciar sesión → se abre la GUI y la captura
> arranca sola (sin clicks).

Comprobar que quedó vivo (después de ~40 s):

```powershell
Get-Content logs_ciberseguridad\gui_prod-v5.log -Tail 5
```

Debe verse `[OK] AsyncSniffer arrancado correctamente.` Y en la ventana: la
insignia de estado `Interfaz: LAN | ● Running` y el contador de paquetes
subiendo.

### Opción B — A mano (consola oculta, igual que la tarea)

```powershell
cd "C:\Users\Ciber-UNIPAZ\Desktop\Version 4 Ultra\Proyecto-IPS-IDBS-ML"
Start-Process -FilePath "cmd.exe" -ArgumentList '/c', 'scripts\lanzar_observacion.bat' -WindowStyle Hidden
```

### Opción C — Headless, sin GUI (servidor sin sesión interactiva)

Mismo motor sin ventana ni dashboard, con línea de estado horaria:

```powershell
cd "C:\Users\Ciber-UNIPAZ\Desktop\Version 4 Ultra\Proyecto-IPS-IDBS-ML"
$env:IDS_MODO_OBSERVACION=0; $env:IDS_ML_ALERTAS=0; $env:IDS_RUN_ID="prod-headless"
$env:IDS_IFACE="Ethernet"; $env:IDS_DURACION_H=0
.\venv\Scripts\python.exe scripts\corrida_observacion.py
```

> **Regla de oro:** un solo proceso escribiendo la BD. Si lanzas a mano,
> verifica antes que no haya otro `python` corriendo
> (`Get-Process python`). No abrir una segunda instancia de la GUI.

---

## 3. Verificar que funciona

### 3.1 Que captura

- **En la ventana**: insignia `● Running`, "Paquetes por segundo" subiendo y
  gráfica de tráfico moviéndose (el dashboard se actualiza cada ~1 s).
- **En el log** (`logs_ciberseguridad\gui_prod-v5.log`): debe estar
  `[OK] AsyncSniffer arrancado correctamente.` y cada alerta que se emite.

Conexión de oro: los eventos crecen **solo** cuando pasa algo real.

### 3.2 Que detecta (prueba con nmap, desde OTRO equipo)

```powershell
nmap -sS -p 1-1000 172.10.x.x     # -> 1 alerta "Escaneo de Puertos"
nmap -p 445 172.10.0.0/24         # -> 1 alerta "Escaneo Horizontal"
curl https://google.com           # -> 0 alertas
```

Y debe llegar el mensaje a Telegram. Ver la alerta en la BD:

```powershell
& venv\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect('intrusiones_v5.db'); [print(r) for r in c.execute('select ts_utc, tipo_ataque, modo, evidencia_json is not null from ataques order by id desc limit 5')]"
```

---

## 4. Detenerlo

```powershell
# Cerrar la ventana de la GUI, o:
Stop-Process -Name python -Force        # detiene el motor

# La BD queda íntegra: cada inserción se confirma al momento.
# Al cerrar la GUI, el sniffer se apaga limpio (closeEvent).
# Tras un reinicio del servidor, la tarea la vuelve a lanzar sola.
```

Para que NO arranque al iniciar sesión (p. ej. mantenimiento largo):
deshabilitar la tarea como administrador:
`Disable-ScheduledTask -TaskName "IDS-Observacion-C3"`.

---

## 5. Cambiar el modo de operación (sin tocar código)

Editar `scripts\lanzar_observacion.bat`, guardar y relanzar (detener antes):

| Quiero... | Cambio |
|---|---|
| Silenciar alertas (solo observar/auditar) | `set IDS_MODO_OBSERVACION=1` |
| **Rollback rápido ante falsos positivos** | El cambio anterior + reiniciar |
| Activar bloqueo automático MikroTik | `set IDS_IPS_AUTONOMO=1` (solo tras días de alertas revisadas) |
| Afinar umbral de escaneo externo | `set IDS_SCAN_THRESHOLD=<n>` |
| Afinar umbral de escaneo interno | `set IDS_SCAN_THRESHOLD_INT=<n>` |
| Afinar barrido horizontal | `set IDS_SCAN_MIN_DST=<n>` |
| Añadir/eximir hosts de gestión | `set IDS_HOSTS_GESTION=ip1,ip2` (vacío = desactiva la exención) |
| Forzar la IP del sensor | `set IDS_MI_IP=172.10.12.77` |

Criterio usado para los umbrales (P99 + 20 %): ver `docs/RUNBOOK_C3.md` §7.

---

## 6. Problemas conocidos

| Síntoma | Causa | Solución |
|---|---|---|
| Tarea con `LastTaskResult: 101` | El venv usa Python de la Microsoft Store (por usuario); no corre como SYSTEM | Las tareas corren **al iniciar sesión** como tu usuario: dejar sesión iniciada |
| Tras reiniciar no se abre la GUI | Nadie inició sesión (el disparador es "al iniciar sesión") | Iniciar sesión; para no teclear contraseña, `netplwiz` → desmarcar la casilla |
| Cerré la ventana y ya no hay captura | La GUI es el motor: cerrarla detiene el sniffer | Relanzar (`scripts\lanzar_observacion.bat`); mejor minimizar que cerrar |
| La GUI abre pero dice `○ Stopped` | El auto-inicio no encontró la interfaz | Verificar que `IDS_IFACE=Ethernet` en `lanzar_gui.bat` y pulsar "Iniciar monitoreo" |
| `eventos_bd=0` con `pps > 0` | Normal: el tráfico propio del sensor se excluye (`MI_IP`) | No es error; la señal viva es `pps > 0` |
| `Acceso denegado` al consultar la tarea | Shell sin privilegios de administrador | Abrir PowerShell como administrador |
| No llega Telegram pero hay alertas en BD | Sin internet o token vencido | La alerta ya está en la BD con evidencia; revisar salida del log |
| Horas sin `ESTADO` en el log | El servidor se apagó o cerró sesión | Revisar energía/UPS; verificar que la sesión quedó iniciada |

---

## 7. Mantenimiento mínimo

| Frecuencia | Qué |
|---|---|
| Diaria (1 min) | Un vistazo al log o a Telegram |
| Diaria (auto) | Backup de la BD a las 06:00 (tarea `IDS-Backup`, purga >90 días) |
| Semanal | Revisar las alertas acumuladas en la BD (el SQL del punto 3.2) |
| Mensual | Verificar un backup: comparar SHA-256 con `Get-FileHash` |

**Dónde queda la evidencia:** `intrusiones_v5.db` (alertas con
`evidencia_json`), `metricas_escaneo` (muestras de calibración bajo umbral),
`logs_ciberseguridad\gui_prod-v5.log` (arranque del motor y alertas) y
`backups\` (copias diarias). El corpus C3 de 72 h está archivado con su hash
en `evidencia\db_archive\`.
