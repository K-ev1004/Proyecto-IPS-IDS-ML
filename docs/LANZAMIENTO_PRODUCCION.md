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

Estos valores viven en `scripts\lanzar_observacion.bat`. **No hay que tocar
`ids.py`** para cambiar ninguno.

---

## 2. Cómo lanzarlo

### Opción A — Automática (la normal en producción)

Existe la tarea programada **`IDS-Observacion-C3`** que lanza el `.bat`
**al iniciar sesión** en el servidor. Es decir:

> Encender el servidor → iniciar sesión → el IDS arranca solo.

Comprobar que quedó vivo (después de ~40 s):

```powershell
Get-Content logs_ciberseguridad\corrida_prod-v5.log -Tail 5
```

Debe verse `AsyncSniffer arrancado` y una línea `ESTADO` con `pps` mayor que 0.

### Opción B — A mano (ventana oculta, igual que la tarea)

```powershell
cd "C:\Users\Ciber-UNIPAZ\Desktop\Version 4 Ultra\Proyecto-IPS-IDBS-ML"
Start-Process -FilePath "cmd.exe" -ArgumentList '/c', 'scripts\lanzar_observacion.bat' -WindowStyle Hidden
```

### Opción C — A mano con consola visible (para pruebas)

Muestra el motor en vivo y se detiene con `Ctrl+C`:

```powershell
cd "C:\Users\Ciber-UNIPAZ\Desktop\Version 4 Ultra\Proyecto-IPS-IDBS-ML"
.\scripts\lanzar_observacion.bat
```

> **Regla de oro:** un solo proceso escribiendo la BD. Si lanzas a mano,
> verifica antes que no haya otro `python` corriendo
> (`Get-Process python`). No abrir la GUI en el servidor mientras el motor
> corre: la GUI abre la misma BD.

---

## 3. Verificar que funciona

### 3.1 Que captura

```powershell
Get-Content logs_ciberseguridad\corrida_prod-v5.log -Tail 5 -Wait
```

Línea esperada cada hora (y a los 30 s del arranque):

```
[2026-11-04 16:44:42] ESTADO pps~237 | ventanas=2 | horizontales=2 |
eventos_bd=0 (con_evidencia: 0, con_features: 0) | muestras_scan=0
```

- `pps` > 0 → el SPAN está entrando. Si es `0` estable, revisar el cable/espejo.
- `eventos_bd=0` es **bueno**: significa cero falsos positivos de fondo.
- Conexión de oro: los eventos crecen **solo** cuando pasa algo real.

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
# Si lo lanzó la tarea programada (sesión iniciada):
Stop-Process -Name python -Force        # detiene el motor

# La BD queda íntegra: cada inserción se confirma al momento.
# Tras un reinicio del servidor, la tarea lo vuelve a lanzar sola.
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
| Tras reiniciar no hay captura | Nadie inició sesión (el disparador es "al iniciar sesión") | Iniciar sesión; para no teclear contraseña, `netplwiz` → desmarcar la casilla |
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
`logs_ciberseguridad\corrida_prod-v5.log` (pulso horario) y
`backups\` (copias diarias). El corpus C3 de 72 h está archivado con su hash
en `evidencia\db_archive\`.
