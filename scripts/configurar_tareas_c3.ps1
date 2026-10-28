# ============================================================================
# configurar_tareas_c3.ps1 - Prepara el servidor para la fase C3 (72 h).
# EJECUTAR COMO ADMINISTRADOR:
#     powershell -ExecutionPolicy Bypass -File scripts\configurar_tareas_c3.ps1
# Crea dos tareas programadas y aplica los ajustes de energía.
#
# HALLAZGO 2026-10-28: el venv usa el Python de la MICROSOFT STORE, que se
# instala POR USUARIO (...\AppData\...\WindowsApps\...). Una tarea como
# SYSTEM no puede ejecutarlo (LastTaskResult 101, "El sistema no tiene
# acceso al archivo"). Por eso las tareas corren como EL USUARIO ACTUAL con
# disparador AL INICIAR SESION: la sesion debe quedar iniciada (o auto-login
# con netplwiz) para que sobrevivan reinicios.
# ============================================================================

# Verificar elevación antes de tocar nada
$identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
$esAdmin = ([Security.Principal.WindowsPrincipal]$identidad).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $esAdmin) {
    Write-Host "[X] Ejecutalo como ADMINISTRADOR (clic derecho en PowerShell -> Ejecutar como administrador)." -ForegroundColor Red
    exit 1
}

$raiz = Split-Path -Parent $PSScriptRoot

Write-Host "[1/4] Evitando que el servidor se duerma..."
powercfg /change standby-timeout-ac 0 | Out-Null
powercfg /change hibernate-timeout-ac 0 | Out-Null

Write-Host "[2/4] Tarea 'IDS-Observacion-C3' (al iniciar sesion, reinicia si falla)..."
$accion = New-ScheduledTaskAction -Execute "$raiz\scripts\lanzar_observacion.bat" `
    -WorkingDirectory $raiz
$disparador = New-ScheduledTaskTrigger -AtLogOn -User $identidad.Name
$ajustes = New-ScheduledTaskSettingsSet -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Days 7)
Register-ScheduledTask -TaskName "IDS-Observacion-C3" -Action $accion `
    -Trigger $disparador -Settings $ajustes -RunLevel Highest -Force | Out-Null

Write-Host "[3/4] Tarea 'IDS-Backup' (diaria 06:00, con purga >90 dias)..."
$accionBk = New-ScheduledTaskAction -Execute "$raiz\venv\Scripts\python.exe" `
    -Argument "scripts\backup_bd.py" -WorkingDirectory $raiz
$disparadorBk = New-ScheduledTaskTrigger -Daily -At 06:00
$ajustesBk = New-ScheduledTaskSettingsSet -StartWhenAvailable
Register-ScheduledTask -TaskName "IDS-Backup" -Action $accionBk `
    -Trigger $disparadorBk -Settings $ajustesBk -RunLevel Highest -Force | Out-Null

Write-Host "[4/4] Verificando..."
Get-ScheduledTask IDS-* | Select-Object TaskName, State | Format-Table -AutoSize

Write-Host "[OK] Listo."
Write-Host "   Arrancar ya:     Start-ScheduledTask -TaskName 'IDS-Observacion-C3'"
Write-Host "   O a mano:        .\scripts\lanzar_observacion.bat"
Write-Host "   Estado en vivo:  Get-Content logs_ciberseguridad\corrida_obs-c3-*.log -Tail 5 -Wait"
Write-Host ""
Write-Host "[!] IMPORTANTE: la tarea corre AL INICIAR SESION (venv con Python de la"
Write-Host "    Microsoft Store, por usuario). Para que sobreviva reinicios, deja la"
Write-Host "    sesion iniciada o configura auto-login: netplwiz -> desmarcar"
Write-Host "    'Los usuarios deben escribir su nombre y contraseña'."
