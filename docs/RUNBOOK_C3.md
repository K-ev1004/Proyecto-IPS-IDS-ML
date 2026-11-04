# Runbook — Fase C3: 72 h de observación en el servidor

**Objetivo:** dejar el IDS v5 corriendo en modo observación (persistir candidatos,
sin alertar ni bloquear) durante 72 h, con backup diario, y calibrar los umbrales
de escaneo con percentiles reales.

**Decisiones registradas (2026-10-28):**
- `172.10.0.57` y `172.10.0.59` van en la **lista blanca de hosts de gestión**
  (`IDS_HOSTS_GESTION`): su tráfico en la v1 era TFTP broadcast
  (`255.255.255.255:69`, 25 alertas = 45 % del ruido de exploit). Cualquier
  conexión suya a un puerto de explotación contra un servidor concreto deja de
  alertar — si esto cambia, quitarlas con `IDS_HOSTS_GESTION=""`.

---

## 1. Preparación (una sola vez, como ADMINISTRADOR)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\configurar_tareas_c3.ps1
```

Esto hace: desactivar suspensión/hibernación, crear la tarea
**IDS-Observacion-C3** (al **iniciar sesión**, reinicia si falla, límite de 7 días) y la
tarea **IDS-Backup** (diaria 06:00 con purga >90 días).

Antes de arrancar, fijar la interfaz donde entra el SPAN en
`scripts\lanzar_observacion.bat` (ya viene fijada con `set IDS_IFACE=Ethernet`,
la Realtek; su IP es DHCP y en la última corrida era `172.10.12.77`).

### ⚠️ Hallazgo: Python de la Microsoft Store no corre como SYSTEM

El `venv` se creó con el Python de la Store, que se instala **por usuario**
(`AppData\...\WindowsApps`). Una tarea programada como **SYSTEM** no puede
ejecutarlo → la tarea falla con `LastTaskResult: 101` y en el log:
`"Unable to create process ... El sistema no tiene acceso al archivo"`.

Por eso las tareas corren **como tu usuario y al iniciar sesión**. Consecuencias:

- El servidor debe **quedar con la sesión iniciada** (pantalla bloqueada está bien).
- Para sobrevivir reinicios sin teclear contraseña: `netplwiz` → desmarcar
  *"Los usuarios deben escribir su nombre y contraseña"*.
- Alternativa robusta 24/7 (post-C3): instalar Python de python.org "para todos
  los usuarios" y recrear el `venv`; entonces sí puede correr como SYSTEM.

## 2. Arrancar y comprobar (día 0)

```powershell
Start-ScheduledTask -TaskName "IDS-Observacion-C3"

# a los ~40 s, verificar que captura (debe haber líneas ESTADO con pps > 0):
Get-Content logs_ciberseguridad\corrida_obs-c3-20261028.log -Tail 5 -Wait
```

Alternativa inmediata sin tarea programada (misma corrida, ventana a la vista):

```powershell
.\scripts\lanzar_observacion.bat
```

Verificación de la tarea: `Get-ScheduledTaskInfo IDS-Observacion-C3` →
`LastTaskResult` **267009 (0x41301)** significa "en ejecución"; un **101** significa
que el proceso no arrancó (revisar el log de corrida).

La línea de estado se escribe cada hora y a los 30 s del arranque:

```
[2026-10-28 14:05:02] ESTADO pps~180 | ventanas=312 | horizontales=45 | eventos_bd=57 (con evidencia: 57)
```

Comprobación de oro: `eventos_bd` crece y **todos los eventos llevan evidencia**.

## 3. Durante las 72 h

- **No abrir la GUI** en el mismo servidor: un solo proceso contra la BD.
  (Si se necesita ver el dashboard, es mejor consultar la BD desde otro equipo.)
- Backup automático a las 06:00 (`Get-ScheduledTask IDS-Backup`).
- Revisión rápida diaria recomendada:

```powershell
& venv\Scripts\python.exe -c "import sqlite3;c=sqlite3.connect('intrusiones_v5.db');\
print(c.execute(\"select tipo_ataque, count(*) from ataques group by 1 order by 2 desc\").fetchall())"
```

Si algo oliera mal (cientos de eventos/minuto), detener con
`Stop-ScheduledTask -TaskName 'IDS-Observacion-C3'` — la BD queda íntegra y el
backup del día anterior existe.

## 4. Cierre y calibración (día 3)

```powershell
Stop-ScheduledTask -TaskName "IDS-Observacion-C3"

# Percentiles por segmento interno/externo:
& venv\Scripts\python.exe scripts\calibrar_escaneo.py --horas 72

# Pruebas controladas con nmap (IDS detenido o en otro RUN_ID):
#   nmap -sS -p 1-1000 <host-lab>      -> 1 alerta vertical
#   nmap -sF -p 1-100 <host-lab>       -> 1 alerta (stealth)
#   nmap -p 445 172.10.0.0/24          -> 1 alerta horizontal
#   curl https://google.com            -> 0 alertas
```

Con el P99 + margen de cada segmento, fijar umbrales (UI: "Escaneo externo /
interno") y pasar a **C4**: `IDS_MODO_OBSERVACION=0` en
`scripts\lanzar_observacion.bat` (o el entorno), 24 h con IPS off, revisión
manual de 100 alertas (FP < 5 %) y solo entonces `IDS_IPS_AUTONOMO=1`.

## 5. Criterios de éxito (recordatorio)

| Métrica | Objetivo |
|---|---|
| Eventos sin evidencia | 0 |
| Alertas escaneo/día tras calibrar | < 20 |
| Detección nmap vertical/stealth/horizontal | 100 % |
| Falsos positivos en revisión manual | < 5 % |

---

## 6. Problemas conocidos y ya resueltos

| Síntoma | Causa | Solución aplicada |
|---|---|---|
| Tarea con `LastTaskResult: 101`, log: `"Unable to create process ... El sistema no tiene acceso al archivo"` | El venv usa el Python de la **Microsoft Store** (instalación por usuario); una tarea como SYSTEM no puede ejecutarlo | Las tareas corren como el usuario actual con disparador **al iniciar sesión** (`configurar_tareas_c3.ps1` v2) |
| El evento de estado no coincide con la corrida al pararlo con Ctrl+C sin `.bat` | `IDS_RUN_ID` solo lo fija el `.bat`; corriendo `corrida_observacion.py` a mano se genera `run-<fecha>-<hora>` | Arrancar siempre vía `lanzar_observacion.bat` (o exportar `IDS_RUN_ID` antes) |
| `eventos_bd=0` con `pps > 0` | El guard `ip_src == MI_IP` descarta el tráfico propio del sensor (172.10.12.216), que es el que más habla en horas tranquilas | No es un error: la señal de captura viva es `pps > 0` y las líneas `ESTADO` |

---

## 7. Validación tras C3 (ML apagado, solo heurística)

La corrida C3 cerró con 276.098 eventos: **276.007 eran falsos positivos del ML**
y solo 70 eran señal real de exploit. El detalle y las cifras están en
`docs/INFORME_C3_DATOS.md`. Decisión: el ML queda como instrumentación y la vía
de alerta es la heurística.

### 7.1 Qué cambió en el motor

| Cambio | Motivo |
|---|---|
| `IDS_ML_ALERTAS=0` (defecto) | El modelo v5 + SQLiGuard no separa ataque de tráfico normal con features de flujo |
| IGMP/ICMP y puertos 0 no entran al `FlowTracker` | Vector de features en cero puntuaba como SQLi (275.102 FP) |
| `MI_IP` se deriva de `IDS_IFACE` | Antes usaba `conf.iface` y podía ser otra tarjeta |
| Exploit solo con SYN de inicio y destino unicast | `SA`/broadcast generaban eventos falsos |
| 7680 excluido de escaneo y floods | Windows Delivery Optimization (9 FP) |
| UDP de retorno (443→efímero) no cuenta como flood | 12 FP de QUIC hacia el sensor |
| DDoS exige ≥10 fuentes distintas | 501 SYN de una IP es SYN Flood, no DDoS |
| Evidencia en SYN/DDoS/UDP flood | Antes 12 filas no tenían `evidencia_json` |
| `metricas_escaneo` (bajo umbral) | Sin ella, calibrar el P99 era circular |
| SQLi: firma fuerte en petición HTTP sí alerta; el resto queda candidato | SQLiGuard ya no arbitra |

### 7.2 Corrida corta (12–24 h)

```powershell
# 1) Archivar el corpus C3 (deja hash + ficha y libera intrusiones_v5.db)
& venv\Scripts\python.exe scripts\clasificar_c3.py --bd intrusiones_v5.db
& venv\Scripts\python.exe scripts\archivar_bd.py --origen intrusiones_v5.db --etiqueta c3-72h

# 2) Validación instrumentada (12 h por defecto)
.\scripts\lanzar_validacion.bat

# 3) Pruebas controladas mientras corre (desde otro equipo de la misma red)
#    nmap -sS -p 1-1000 172.10.x.x   -> 1 alerta vertical
#    nmap -sF -p 1-100 172.10.x.x    -> 1 alerta stealth
#    nmap -p 445 172.10.0.0/24       -> 1 alerta horizontal
#    curl https://google.com         -> 0 alertas

# 4) Al terminar: percentiles reales y revisión
& venv\Scripts\python.exe scripts\calibrar_escaneo.py --horas 12
```

Criterio de salida: **0 alertas de fondo** (solo las de las pruebas nmap), todas
con `evidencia_json`, y `metricas_escaneo` con muestras suficientes para fijar
el P99. Si aparece una alerta inesperada, se documenta como FP y se corrige
antes de abrir C4.

La BD de la validación se crea nueva en `intrusiones_v5.db`; el corpus C3 queda
en `evidencia/db_archive/` con su `.ficha.json` y su SHA-256.
