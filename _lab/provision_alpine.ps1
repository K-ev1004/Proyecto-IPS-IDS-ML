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

# --- 0) Utilidad ---
# 'showvminfo' escribe "Could not find a registered machine" cuando la VM no
# existe y, con $ErrorActionPreference='Stop', aborta el script. 'list vms'
# responde por stdout sin errores.
function Test-VmExiste {
    param([string]$Nombre, [object]$Vb)
    $coincide = & $Vb list vms 2>&1 | Where-Object { $_ -match ('"' + [regex]::Escape($Nombre) + '"') }
    return [bool]$coincide
}

# --- 1) ISO de Alpine Linux (version vigente de latest-stable) ---
# VERIFICADO 2026-10-01: la version fijada antes (3.21.3) ya no existe en
# latest-stable (hoy 3.24.2) -> 404. Ahora la version se descubre en
# latest-releases.yaml, asi el kit no caduca al cambiar latest-stable.
$base = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64"
$iso = "$dir\alpine-virt-latest-stable-x86_64.iso"
if (-not (Test-Path $iso)) {
    $url = $null
    try {
        $yaml = (Invoke-WebRequest -Uri "$base/latest-releases.yaml" -UseBasicParsing).Content
        if ($yaml -is [byte[]]) { $yaml = [Text.Encoding]::UTF8.GetString($yaml) }
        $m = [regex]::Match($yaml, 'file:\s*(alpine-virt-[0-9\.]+-x86_64\.iso)')
        if ($m.Success) { $url = "$base/$($m.Groups[1].Value)" }
    } catch {
        Write-Host "    [!] no se pudo leer latest-releases.yaml: $($_.Exception.Message)"
    }
    if (-not $url) {
        throw "No se pudo determinar la ISO de Alpine vigente. Descargue 'alpine-virt-*-x86_64.iso' (la de alpine-virt, ~66 MB) desde https://alpinelinux.org/downloads/ y coloquelo en: $dir"
    }
    Write-Host "[*] Descargando Alpine virt: $url"
    try { Invoke-WebRequest -Uri $url -OutFile $iso -UseBasicParsing }
    catch {
        Remove-Item $iso -ErrorAction SilentlyContinue
        throw "No se pudo descargar Alpine desde $url. Descargue 'alpine-virt-*-x86_64.iso' desde https://alpinelinux.org/downloads/ y coloquelo en: $dir"
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
            if ($curIp -eq $Ip) {
                # El bloque de cada interfaz es  Name / GUID / DHCP / IPAddress / ...
                # Asi que $lines[$i-1] es la linea DHCP, NO el nombre. Se busca
                # hacia atras el ultimo 'Name:' del bloque.
                for ($j = $i - 1; $j -ge 0; $j--) {
                    if ($lines[$j] -like 'Name:*') {
                        return ($lines[$j] -replace 'Name:\s*', '').Trim()
                    }
                }
            }
        }
    }
    return $null
}
$wanEth = Get-HostOnlyIface -Ip '10.10.0.1' -Vb $vb
$lanEth = Get-HostOnlyIface -Ip '10.10.1.1' -Vb $vb
if (-not $wanEth -or -not $lanEth) {
    throw "Faltan las redes host-only. Ejecute primero provision_chr.ps1"
}

# DHCP en las redes del lab. NO es para las VMs instaladas (esas usan IP fija):
# es para que el Alpine live, mientras se instala, tenga una IP y se pueda
# observar/verificar desde Windows. El rango excluye a proposito las fijas
# (.1 host, .2 CHR, .50 atacante/victima) para que el pool nunca choque con
# ellas. Sin esto el live queda sin red y no hay forma de diagnosticarlo.
foreach ($red in @(@{ Net = "HostInterfaceNetworking-$wanEth"; Ip = '10.10.0.1'; Lo = '10.10.0.100'; Hi = '10.10.0.200' },
                   @{ Net = "HostInterfaceNetworking-$lanEth"; Ip = '10.10.1.1'; Lo = '10.10.1.100'; Hi = '10.10.1.200' })) {
    $existe = (& $Vb list dhcpservers | Select-String -SimpleMatch $red.Net)
    if ($existe) {
        $cmd = @('dhcpserver', 'modify', '--network', "`"$($red.Net)`"", '--ip', $red.Ip,
                 '--netmask', '255.255.255.0', '--lower-ip', $red.Lo, '--upper-ip', $red.Hi, '--enable')
    } else {
        $cmd = @('dhcpserver', 'add', '--network', "`"$($red.Net)`"", '--ip', $red.Ip,
                 '--netmask', '255.255.255.0', '--lower-ip', $red.Lo, '--upper-ip', $red.Hi, '--enable')
    }
    Start-Process -FilePath $Vb -ArgumentList ($cmd -join ' ') -Wait -NoNewWindow | Out-Null
    Write-Host "[+] DHCP en $($red.Net): $($red.Lo)-$($red.Hi)"
}

# --- 3) VMs ---
function New-AlpineVm {
    param([string]$Name, [string]$Iface, [object]$Vb, [string]$Iso, [string]$IsoLab)    $existe = Test-VmExiste -Nombre $Name -Vb $Vb
    if ($existe) {
        Write-Host "[!] La VM '$Name' ya existe. Se reasignan disco y adaptador (idempotente)."
    } else {
        & $Vb createvm --name $Name --basefolder "$dir\vms" --register | Out-Null
        & $Vb modifyvm $Name --memory 128 --cpus 1 --ioapic on --ostype Linux_64 | Out-Null
        & $Vb storagectl $Name --name SATA --add sata --controller IntelAhci | Out-Null
        & $Vb storagectl $Name --name IDE --add ide | Out-Null
        & $Vb storageattach $Name --storagectl IDE --port 0 --device 0 --type dvddrive --medium $Iso | Out-Null
        Write-Host "[+] VM '$Name' creada (ISO Alpine adjunta)."
    }

    # Disco de 2 GB. OJO: '--medium emptydrive' ya no existe en VirtualBox 7 y
    # NO da error: lo ignora en silencio y deja la VM sin disco, que es como
    # fallaba la instalacion (setup-disk no encontraba nada que particionar).
    # La unica forma fiable es crear el VDI y adjuntarlo por su ruta.
    $vdi = "$dir\vms\$Name\$Name.vdi"
    if (-not (Test-Path $vdi)) {
        if (Test-Path "$dir\vms\$Name") {
            & $Vb createhd --filename $vdi --size 2048 --format VDI | Out-Null
        } else {
            New-Item -ItemType Directory -Force -Path "$dir\vms\$Name" | Out-Null
            & $Vb createhd --filename $vdi --size 2048 --format VDI | Out-Null
        }
        Write-Host "[+] Disco creado: $vdi (2 GB, dinamico)"
    }
    & $Vb storageattach $Name --storagectl SATA --port 0 --device 0 --type hdd `
        --medium $vdi | Out-Null

    # ISO de herramientas (instalador desatendido), segundo puerto IDE.
    if ($IsoLab -and (Test-Path $IsoLab)) {
        & $Vb storageattach $Name --storagectl IDE --port 1 --device 0 --type dvddrive `
            --medium $IsoLab | Out-Null
        Write-Host "[+] ISO de herramientas adjunta: $IsoLab"
    }

    # Verificacion: sin disco el instalar Alpine falla mas tarde y sin pistas.
    # La clave machine-readable del medio es '"SATA-0-0"="<ruta>"'.
    $mr = & $Vb showvminfo $Name --machinereadable
    $disco = ($mr | Select-String -Pattern '^"SATA-0-0"=').Line
    if (-not $disco -or $disco -match '"none"' -or $disco -notmatch '\.vdi"') {
        throw "La VM '$Name' quedo SIN disco en SATA 0 ( revise '$vdi' )."
    }
    Write-Host "[OK] $Name con disco en SATA 0: $disco"

    # Orden de arranque para la FASE DE INSTALACION: DVD primero. Con el disco
    # vacio primero, SeaBIOS se queda en "no bootable device" y la ISO live
    # nunca arranca (asi se perdia la instalacion sin ningun error visible).
    # Despues de instalar hay que invertirlo a disco primero; ese paso esta
    # documentado en PASO-INSTALAR-ALPINE.txt.
    & $Vb modifyvm $Name --boot1 dvd --boot2 disk --boot3 none --boot4 none | Out-Null
    Write-Host "[+] $Name arranca desde la ISO mientras se instala"

    # El adaptador se asigna siempre (tambien al recrear): es el paso que fallo
    # cuando la busqueda devolvio en vez del nombre la linea 'DHCP:'.
& $Vb modifyvm $Name --nic1 hostonly --hostonlyadapter1 $Iface | Out-Null
Write-Host "[+] $Name nic1=$Iface"

# NIC 2 en NAT, SOLO para la fase de instalacion. Las ISO de Alpine 3.24 (virt
# y standard) no traen ni el kernel (linux-lts) ni el bootloader (syslinux), asi
# que setup-disk no puede dejar el disco arrancable sin descargarlos del CDN.
# Al terminar de instalar hay que quitar esta NIC para que el lab quede aislado:
#   VBoxManage modifyvm <VM> --nic2 none
& $Vb modifyvm $Name --nic2 nat --nictype2 82540EM | Out-Null
Write-Host "[+] $Name nic2=nat (temporal: se quita al terminar de instalar)"
}

# La ISO de herramientas es distinta por VM: cada una trae un 'GO' con la IP y
# el gateway ya escritos dentro, para que en la consola haya que teclear solo
# 'sh /m/GO' (una linea corta: la consola emulada pierde teclas en las largas).
foreach ($falta in @("$dir\alpine-tools-atacante.iso", "$dir\alpine-tools-victima.iso")) {
    if (-not (Test-Path $falta)) {
        throw "Falta $falta. Genere las ISO con:  python .\mk_lab_iso.py --por-vm"
    }
}

New-AlpineVm -Name 'ATACANTE-IDS' -Iface $wanEth -Vb $vb -Iso $iso -IsoLab "$dir\alpine-tools-atacante.iso"
New-AlpineVm -Name 'VICTIMA-IDS'  -Iface $lanEth -Vb $vb -Iso $iso -IsoLab "$dir\alpine-tools-victima.iso"

Write-Host ""
Write-Host "== SIGUIENTES PASOS =="
Write-Host " 1) Doble clic en ATACANTE-IDS en el VirtualBox Manager"
Write-Host " 2) login root -> teclee:  mkdir /m;mount /dev/sr1 /m   (18 caracteres)"
Write-Host " 3) luego:                sh /m/GO                       (9 caracteres)"
Write-Host " 4) espere el reinicio (1-3 min) y repita en VICTIMA-IDS."
Write-Host " 5) Detalle y Troubleshooting en PASO-INSTALAR-ALPINE.txt"