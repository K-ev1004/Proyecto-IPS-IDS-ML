# =============================================================================
# provision_alpine.ps1 - Laboratorio IDS/IPS (UNIPAZ) - VMs Atacante y Victima
# -----------------------------------------------------------------------------
# EJECUTAR EN LA MAQUINA OBJETIVO (3 VMs ~1 GB). Crea la VM ATACANTE
# (10.10.0.50, red wan) y la VM VICTIMA (10.10.1.50, red lan), ambas Alpine
# Linux (128 MB), con la ISO de instalacion adjunta.
#
# INSTALACION DE ALPINE (manual, una vez por VM, ~15 min): boot de la ISO,
# login root, `setup-alpine` (modo sys, disco /dev/sda o /dev/sdb, hostname,
# IP estatica, gw, DNS 1.1.1.1, contrasena de root, habilitar servidor OpenSSH).
# Final: /reboot, retirar la ISO, y verificar `ping 10.10.<0|1>.2`.
# =============================================================================
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Get-VBoxManage {
    $cmd = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
                     "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe")) {
        if (Test-Path $p) { return $p }
    }
    throw "VBoxManage no encontrado. Instale Oracle VirtualBox + Extension Pack."
}
$vb = Get-VBoxManage

# --- 1) ISO de Alpine Linux (latest-stable; si 404, descarga manual) ---
$iso = "$dir\alpine-virt-latest-stable-x86_64.iso"
if (-not (Test-Path $iso)) {
    Write-Host "[*] Descargando Alpine virt ..."
    $url = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-virt-3.21.3-x86_64.iso"
    try { Invoke-WebRequest -Uri $url -OutFile $iso -UseBasicParsing }
    catch {
        throw "No se pudo descargar Alpine. Descargue 'alpine-virt-*.iso' x86_64 desde https://alpinelinux.org/downloads/ y coloquelo en: $dir"
    }
}
Write-Host "[+] ISO Alpine: $iso"

# --- 2) Redes host-only (deben existir tras provision_chr.ps1) ---
function Get-HostOnlyIface {
    param([string]$Ip, [object]$Vb)
    $lines = & $Vb list hostonlyifs
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -like 'IPAddress:*') {
            $curIp = ($lines[$i] -replace 'IPAddress:\s*', '').Trim()
            if ($curIp -eq $Ip) { return ($lines[$i - 1] -replace 'Name:\s*', '').Trim() }
        }
    }
    return $null
}
$wanEth = Get-HostOnlyIface -Ip '10.10.0.1' -Vb $vb
$lanEth = Get-HostOnlyIface -Ip '10.10.1.1' -Vb $vb
if (-not $wanEth -or -not $lanEth) {
    throw "Faltan las redes host-only. Ejecute primero provision_chr.ps1"
}

# --- 3) VMs ---
function New-AlpineVm {
    param([string]$Name, [string]$Iface, [object]$Vb, [string]$Iso)
    if (& $Vb showvminfo $Name 2>$null) {
        Write-Host "[!] La VM '$Name' ya existe."
        return
    }
    & $Vb createvm --name $Name --basefolder "$dir\vms" --register | Out-Null
    & $Vb modifyvm $Name --memory 128 --cpus 1 --ioapic on --ostype Linux_64 `
        --nic1 hostonly --hostonlyadapter1 $Iface | Out-Null
    & $Vb storagectl $Name --name SATA --add sata --controller IntelAhci | Out-Null
    & $Vb storagectl $Name --name IDE --add ide | Out-Null
    & $Vb storageattach $Name --storagectl SATA --port 0 --device 0 --type hdd `
        --medium emptydrive | Out-Null
    & $Vb storageattach $Name --storagectl IDE --port 0 --device 0 --type dvddrive --medium $Iso | Out-Null
    Write-Host "[+] VM '$Name' creada (nic1=$Iface, ISO Alpine adjunta)."
}

New-AlpineVm -Name 'ATACANTE-IDS' -Iface $wanEth -Vb $vb -Iso $iso
New-AlpineVm -Name 'VICTIMA-IDS'  -Iface $lanEth -Vb $vb -Iso $iso

Write-Host ""
Write-Host "== SIGUIENTES PASOS =="
Write-Host " 1) VBoxManage startvm ATACANTE-IDS   (script tiene el setup-alpine manual)"
Write-Host " 2) VBoxManage startvm VICTIMA-IDS"
Write-Host " 3) Detalle de instalacion de Alpine en LEEME_LAB.md (seccion VMs)."
Write-Host " 4) Tras instalar, llenar _lab/alpine.json con las credenciales root y"
Write-Host "    ejecutar T5:  python .\t5_routeros_ips.py"