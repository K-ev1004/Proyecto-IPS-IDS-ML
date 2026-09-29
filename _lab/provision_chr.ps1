# =============================================================================
# provision_chr.ps1 - Laboratorio IDS/IPS (UNIPAZ) - RouterOS CHR 7.23.7
# -----------------------------------------------------------------------------
# EJECUTAR EN LA MAQUINA OBJETIVO (con capacidad para 3 VMs ~1 GB), NO aqui.
# Crea las 2 redes host-only (idslab_wan / idslab_lan), descarga el disco CHR
# 7.23.7 y registra la VM CHR-IDS-LAB con ether1 (wan) y ether2 (lan).
#
# Pre-requisitos: Oracle VirtualBox + Extension Pack instalados (elevado).
#
# IP PLAN
#   wan  10.10.0.0/24  -> host adapter 10.10.0.1 | CHR ether1 10.10.0.2  | atacante 10.10.0.50
#   lan  10.10.1.0/24  -> host adapter 10.10.1.1 | CHR ether2 10.10.1.2  | victima  10.10.1.50
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
    throw "VBoxManage no encontrado. Instale Oracle VirtualBox + Extension Pack e intente de nuevo."
}

$vb = Get-VBoxManage
$req = '7.23.7'

# --- 1) Disco de RouterOS CHR (descarga diferida; si falla, descarga manual) ---
$disk = "$dir\chr-$req.vmdk"
if (-not (Test-Path $disk)) {
    Write-Host "[*] Descargando CHR $req (VMDK)..."
    try {
        Invoke-WebRequest -Uri "https://download.mikrotik.com/routeros/$req/chr-$req.vmdk" `
            -OutFile $disk -UseBasicParsing
    } catch {
        $diskVdi = "$dir\chr-$req.vdi"
        try {
            Write-Host "[*] VMDK no disponible, intentando VDI..."
            Invoke-WebRequest -Uri "https://download.mikrotik.com/routeros/$req/chr-$req.vdi" `
                -OutFile $diskVdi -UseBasicParsing
            $disk = $diskVdi
        } catch {
            throw "No se pudo descargar CHR automaticamente. Descargue 'chr-$req.vmdk' (o .vdi) desde https://mikrotik.com/download/chr (seccion CHR) y coloquelo en: $dir"
        }
    }
}
Write-Host "[+] Disco CHR: $disk"

# --- 2) Redes host-only (idempotente) ---
function New-HostOnlyNet {
    param([string]$Name, [string]$Ip, [string]$Mask, [object]$Vb)
    $iface = $null
    $lines = & $Vb list hostonlyifs
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -like 'Name:*') {
            $candidate = ($lines[$i] -replace 'Name:\s*', '').Trim()
            # buscar si ya tiene la IP objetivo
            for ($j = $i; $j -lt $lines.Count; $j++) {
                if ($lines[$j] -like 'IPAddress:*') {
                    $curIp = ($lines[$j] -replace 'IPAddress:\s*', '').Trim()
                    if ($curIp -eq $Ip) { return $candidate }
                }
                if ($lines[$j] -like 'Name:*') { break }
            }
        }
    }
    $out = & $Vb hostonlyif create | Out-String
    if ($LASTEXITCODE -ne 0) { throw "No se pudo crear red host-only: $out" }
    $match = $out | Select-String -Pattern 'VirtualBox Host-Only Ethernet Adapter #[0-9]+' | Select-Object -First 1
    if (-not $match) { throw "No se pudo detectar el adaptador host-only. Ejecute manualmente: hostonlyif create" }
    $iface = $match.Matches[0].Value
    & $Vb hostonlyif ipconfig $iface --ip $Ip --netmask $Mask | Out-Null
    & $Vb dhcpserver modify --ifname $iface --disable | Out-Null
    Write-Host "[+] Red host-only '$Name' -> $Ip/$Mask en $iface"
    return $iface
}

$wanEth = New-HostOnlyNet -Name 'idslab_wan' -Ip '10.10.0.1' -Mask '255.255.255.0' -Vb $vb
$lanEth = New-HostOnlyNet -Name 'idslab_lan' -Ip '10.10.1.1' -Mask '255.255.255.0' -Vb $vb

# --- 3) VM CHR-IDS-LAB ---
$vm = 'CHR-IDS-LAB'
if (& $Vb showvminfo $vm 2>$null) {
    Write-Host "[!] La VM '$vm' ya existe. Se omiten los pasos de creacion."
} else {
    & $Vb createvm --name $vm --basefolder "$dir\vms" --register | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Fallo al crear la VM $vm" }
    & $Vb modifyvm $vm --memory 512 --cpus 1 --ioapic on --ostype Linux_64 `
        --nic1 hostonly --hostonlyadapter1 $wanEth `
        --nic2 hostonly --hostonlyadapter2 $lanEth | Out-Null
    & $Vb storagectl $vm --name SATA --add sata --controller IntelAhci | Out-Null
    & $Vb storageattach $vm --storagectl SATA --port 0 --device 0 --type hdd --medium $disk | Out-Null
    Write-Host "[+] VM '$vm' creada (CHR ether1=$wanEth / ether2=$lanEth)."
}

Write-Host ""
Write-Host "== SIGUIENTES PASOS =="
Write-Host " 1) Iniciar:  VBoxManage startvm $vm"
Write-Host "    (o abrir VirtualBox y arrancar CHR-IDS-LAB)"
Write-Host " 2) Primera consola: siga 'chr_bootstrap_console.txt' (password admin + usuario ids + ssh)."
Write-Host " 3) Configurar IPs y firewall:  python .\chr_apply_config.py"
Write-Host " 4) Crear atacante/victima:      .\provision_alpine.ps1"