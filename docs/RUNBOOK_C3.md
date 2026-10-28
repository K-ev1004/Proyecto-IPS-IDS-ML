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
**IDS-Observacion-C3** (al arranque, reinicia si falla, límite de 7 días) y la
tarea **IDS-Backup** (diaria 06:00 con purga >90 días).

Antes de arrancar, fijar la interfaz donde entra el SPAN en
`scripts\lanzar_observacion.bat`:

```bat
set IDS_IFACE=Ethernet   # nombre exacto de Get-NetAdapter
```

## 2. Arrancar y comprobar (día 0)

```powershell
Start-ScheduledTask -TaskName "IDS-Observacion-C3"

# a los ~40 s, verificar que captura (debe haber líneas ESTADO con pps > 0):
Get-Content logs_ciberseguridad\corrida_obs-c3-20261028.log -Tail 5 -Wait
```

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
