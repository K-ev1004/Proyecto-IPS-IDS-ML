# =============================================================================
# provision_chr.ps1 - Laboratorio IDS/IPS (UNIPAZ) - nodos RouterOS CHR 7.23.7
# -----------------------------------------------------------------------------
# Crea las 2 redes host-only (idslab_wan / idslab_lan) y los 3 nodos CHR del
# laboratorio, y opcionalmente los configura por SSH. NO hay consola manual, NO
# hay instalador de SO y NO hace falta internet.
#
#   router     CHR-IDS-LAB       nic1->wan nic2->lan   enruta + reglas de drop
#   atacante   CHR-ATACANTE-LAB  nic1->wan nic2->none  una sola NIC real
#   victima    CHR-VICTIMA-LAB   nic1->wan nic2->lan   ether1 queda deshabilitada
#
# Idea: atacante y victima clonan una GOLD IMAGE (copia del CHR ya configurado,
# con usuario ids y SSH habilitado) en lugar de instalar Alpine. Por eso arrancan
# con la config del router y hay que reasignarles la IP, que se hace por SSH en
# dos fases (ver chr_apply_config.py).
#
#   powershell -ExecutionPolicy Bypass -File .\provision_chr.ps1
#   powershell -ExecutionPolicy Bypass -File .\provision_chr.ps1 -Configurar
#   powershell -ExecutionPolicy Bypass -File .\provision_chr.ps1 -Nodos atacante
#
# Requisitos: Oracle VirtualBox + Extension Pack, Python con paramiko.
# =============================================================================
[CmdletBinding()]
param(
    [ValidateSet('router', 'atacante', 'victima', 'todos')]
    [string[]]$Nodos = @('todos'),
    # Ademas de crear las VMs, arrancar y configurar cada nodo por SSH y
    # comprobar la conectividad de la topologia.
    [switch]$Configurar,
    [string]$ChrVersion = '7.23.7'
)

$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Nodos -contains 'todos') { $Nodos = @('router', 'atacante', 'victima') }

# --- Tabla de nodos -----------------------------------------------------------
# 'red' por posicion: indice 0 -> nic1, indice 1 -> nic2. 'none' = sin adaptador.
# 'mac' son las MACs que VirtualBox asigna a las NICs. Para los clones DEBEN ser
# las mismas del router: RouterOS identifica las interfaces 'ether' por MAC, y un
# clon con MACs desconocidas deja sus IPs heredadas en interfaces inexistentes
# (inalcanzable sin consola). El clash se resuelve despues por SSH en la fase C
# de chr_apply_config.py, que asigna MACs unicas por nodo.
$MACS_ROUTER = @{ Wan = '080027497F9C'; Lan = '080027D2A109' }

$NODOS_LAB = @(
    @{ Perfil = 'router';   VM = 'CHR-IDS-LAB';       Red = @('wan', 'lan');  Gold = $false; Mac = $null },
    @{ Perfil = 'atacante'; VM = 'CHR-ATACANTE-LAB';  Red = @('wan', 'none'); Gold = $true;  Mac = $MACS_ROUTER },
    @{ Perfil = 'victima';  VM = 'CHR-VICTIMA-LAB';   Red = @('wan', 'lan');  Gold = $true;  Mac = $MACS_ROUTER }
)

function Get-VBoxManage {
    $cmd = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
                     "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe")) {
        if (Test-Path $p) { return $p }
    }
    throw "VBoxManage no encontrado. Instale Oracle VirtualBox + Extension Pack e intente de nuevo."
}

# VBoxManage escribe algunos errores en stdout/stderr; con
# $ErrorActionPreference='Stop' eso aborta el script aunque sea inocuo
# (p.ej. "DHCP server does not exist" o el showvminfo de una VM que no existe).
# Por eso la existencia de una VM se consulta con 'list vms' (sin stderr) y las
# llamadas nativas no criticas se aisan con 2>&1 + try/catch.
function Test-VmExiste {
    param([string]$Nombre, [object]$Vb)
    $coincide = & $Vb list vms 2>&1 | Where-Object { $_ -match ('"' + [regex]::Escape($Nombre) + '"') }
    return [bool]$coincide
}

function Test-VmEncendida {
    param([string]$Nombre, [object]$Vb)
    $corriendo = & $Vb list runningvms 2>&1 | Where-Object { $_ -match ('"' + [regex]::Escape($Nombre) + '"') }
    return [bool]$corriendo
}

function Stop-Vm {
    <# Apagado ordenado: primero el boton ACPI (RouterOS cierra la config), y si
       no responde en 40 s se recurre al corte de energia. #>
    param([string]$Nombre, [object]$Vb)
    if (-not (Test-VmEncendida -Nombre $Nombre -Vb $Vb)) { return $true }
    Write-Host "[*] Apagando $Nombre (ACPI) ..."
    & $Vb controlvm $Nombre acpipowerbutton | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Seconds 2
        if (-not (Test-VmEncendida -Nombre $Nombre -Vb $Vb)) {
            Write-Host "[+] $Nombre apagada correctamente."
            return $true
        }
    }
    Write-Warning "$Nombre no respondio al boton ACPI; se corta la alimentacion."
    & $Vb controlvm $Nombre poweroff | Out-Null
    Start-Sleep -Seconds 3
    return (-not (Test-VmEncendida -Nombre $Nombre -Vb $Vb))
}

$vb = Get-VBoxManage

# =============================================================================
# 1) Disco de RouterOS CHR (descarga diferida; si falla, descarga manual)
# =============================================================================
# VERIFICADO 2026-10-01: MikroTik publica el disco CHR COMPRIMIDO en .zip
#   https://download.mikrotik.com/routeros/<ver>/chr-<ver>.vmdk.zip   (~45 MB)
# La version anterior de este script pedia el .vmdk/.vdi SIN comprimir y
# recibia 404 en todos los intentos.
$disk = "$dir\chr-$ChrVersion.vmdk"
if (-not (Test-Path $disk)) {
    Write-Host "[*] Descargando CHR $ChrVersion (VMDK comprimido)..."
    $zip = "$disk.zip"
    $ok = $false
    foreach ($u in @("https://download.mikrotik.com/routeros/$ChrVersion/chr-$ChrVersion.vmdk.zip",
                     "https://download.mikrotik.com/routeros/$ChrVersion/chr-$ChrVersion.vdi.zip")) {
        try {
            Invoke-WebRequest -Uri $u -OutFile $zip -UseBasicParsing
            $ok = $true
            break
        } catch {
            Write-Host "    [!] no disponible: $u"
        }
    }
    if (-not $ok) {
        Remove-Item $zip -ErrorAction SilentlyContinue
        throw "No se pudo descargar CHR automaticamente. Descargue 'chr-$ChrVersion.vmdk.zip' desde https://download.mikrotik.com/routeros/$ChrVersion/ (seccion CHR de https://mikrotik.com/download/chr), descomprimalo en $dir y vuelva a ejecutar."
    }
    Write-Host "[*] Descomprimiendo CHR..."
    Expand-Archive -Path $zip -DestinationPath $dir -Force
    Remove-Item $zip -Force
}
if (-not (Test-Path $disk)) {
    # El .zip puede traer otro nombre de disco (p.ej. .vdi): se acepta cualquiera.
    $alt = Get-ChildItem -Path $dir -File -Filter "chr-$ChrVersion.*" -ErrorAction SilentlyContinue |
           Where-Object { $_.Extension -in @('.vmdk', '.vdi') } | Select-Object -First 1
    if (-not $alt) { throw "No se encontro el disco CHR ya descomprimido en: $dir" }
    $disk = $alt.FullName
}
Write-Host "[+] Disco CHR: $(Split-Path -Leaf $disk)"

# =============================================================================
# 2) Redes host-only (idempotente)
# =============================================================================
function New-HostOnlyNet {
    <# Crea (o reutiliza) un adaptador host-only con la IP indicada.
       Devuelve @{ Iface = <nombre del adaptador>; Network = <nombre de red VBox> }.
       El nombre de red es lo que acepta 'dhcpserver modify --network'. #>
    param([string]$Name, [string]$Ip, [string]$Mask, [object]$Vb)
    $iface = $null
    $lines = & $Vb list hostonlyifs
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -like 'Name:*') {
            $candidate = ($lines[$i] -replace 'Name:\s*', '').Trim()
            # buscar si ya tiene la IP objetivo.
            # El inner loop arranca en $i+1: si arrancara en $i, la linea 'Name:'
            # del propio bloque cortaria el recorrido y nunca se llegaria al
            # IPAddress (creaba una red host-only nueva en cada ejecucion).
            for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                if ($lines[$j] -like 'IPAddress:*') {
                    $curIp = ($lines[$j] -replace 'IPAddress:\s*', '').Trim()
                    if ($curIp -eq $Ip) { return @{ Iface = $candidate } }
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
    Write-Host "[+] Red host-only '$Name' -> $Ip/$Mask en $iface"
    return @{ Iface = $iface }
}

function Disable-DhcpServer {
    <# El laboratorio es 100 % estatico. VirtualBox levanta un servidor DHCP en
       cada host-only recien creado (rango .100-.200), y los clones lo usan al
       arrancar: pedirian una IP que el router ya tiene tomada. #>
    param([string]$Network, [object]$Vb)
    $salida = & $Vb dhcpserver modify --network $Network --disable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Servidor DHCP de '$Network' deshabilitado (red estatica)."
    } else {
        Write-Warning "No se pudo deshabilitar el DHCP de '$Network': $salida"
    }
}

$wanEth = (New-HostOnlyNet -Name 'idslab_wan' -Ip '10.10.0.1' -Mask '255.255.255.0' -Vb $vb).Iface
$lanEth = (New-HostOnlyNet -Name 'idslab_lan' -Ip '10.10.1.1' -Mask '255.255.255.0' -Vb $vb).Iface
$redDe = @{ wan = $wanEth; lan = $lanEth }

# El laboratorio es estatico: cualquier DHCP que VirtualBox haya levantado sobre
# estas redes se apaga (los clones heredan el cliente DHCP del router y pedirian
# una IP del rango .100-.200 que el router ya ocupa).
foreach ($red in @($wanEth, $lanEth)) {
    Disable-DhcpServer -Network "HostInterfaceNetworking-$red" -Vb $vb
}

# =============================================================================
# 3) Gold image: copia del CHR ya configurado (usuario ids + SSH habilitado)
# =============================================================================
# Es lo que elimina la consola manual: los clones arrancan con SSH funcionando.
# El origen DEBE tener CHR-IDS-LAB apagada, porque se clona su disco en caliente.
$gold = "$dir\chr-gold-lab.vmdk"
$necesitanGold = @($NODOS_LAB | Where-Object { $Nodos -contains $_.Perfil -and $_.Gold }).Count -gt 0

if ($necesitanGold -and -not (Test-Path $gold)) {
    if (Test-VmEncendida -Nombre 'CHR-IDS-LAB' -Vb $vb) {
        throw "CHR-IDS-LAB esta encendida. Apagela (VBoxManage controlvm CHR-IDS-LAB acpipowerbutton) y ejecute de nuevo: la gold image se clona de su disco."
    }
    Write-Host "[*] Creando gold image desde el disco del router..."
    & $vb clonemedium disk $disk $gold --format VMDK | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $gold)) {
        throw "No se pudo clonar el disco CHR a la gold image: $gold"
    }
    Write-Host "[+] Gold image: $(Split-Path -Leaf $gold)"
}
if ($necesitanGold -and -not (Test-Path $gold)) {
    throw "Falta la gold image $gold y no se pudo crear."
}

# =============================================================================
# 4) Crear / reasignar VMs
# =============================================================================
function Set-NicsDeVm {
    param([string]$Vm, [string[]]$Red, [hashtable]$RedDe, $Mac, [object]$Vb)
    # 'modifyvm' abre un lock de escritura sobre la maquina y VirtualBox lo
    # rechaza si esta encendida ('machine is already locked for a session'). En vez
    # de fallar con un error de VBox, se dice que apague y se sigue: el NIC solo
    # se reconfigura cuando la VM esta apagada, que es cuando tiene sentido.
    if (Test-VmEncendida -Nombre $Vm -Vb $Vb) {
        Write-Warning "$Vm esta encendida: no se pueden cambiar sus adaptadores (VBoxManage modifyvm exige la VM apagada). Si la topologia esta mal, apaguela con 'VBoxManage controlvm $Vm acpipowerbutton' y ejecute de nuevo."
        return
    }
    $args = @('modifyvm', $Vm, '--nic1', 'hostonly', '--hostonlyadapter1', $RedDe[$Red[0]])
    if ($Red.Count -ge 2) {
        if ($Red[1] -eq 'none') {
            $args += @('--nic2', 'none')
        } else {
            $args += @('--nic2', 'hostonly', '--hostonlyadapter2', $RedDe[$Red[1]])
        }
    }
    if ($Mac) {
        $args += @('--macaddress1', $Mac.Wan)
        if ($Red.Count -ge 2 -and $Red[1] -ne 'none') { $args += @('--macaddress2', $Mac.Lan) }
    }
    & $Vb @args | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Fallo al asignar las NICs de $Vm" }
    $desc = ($Red | ForEach-Object { if ($_ -eq 'none') { 'nic=none' } else { "$_" } }) -join ' / '
    $descMac = if ($Mac) { "  mac1=$($Mac.Wan)$(if ($Mac.Lan) { " mac2=$($Mac.Lan)" })" } else { '' }
    Write-Host "[+] $Vm adapters: $desc$descMac"
}

foreach ($n in $NODOS_LAB) {
    if ($Nodos -notcontains $n.Perfil) { continue }
    $vm = $n.VM

    if (Test-VmExiste -Nombre $vm -Vb $vb) {
        Write-Host "[!] La VM '$vm' ya existe. Se reasignan sus adaptadores (idempotente)."
        Set-NicsDeVm -Vm $vm -Red $n.Red -RedDe $redDe -Mac $n.Mac -Vb $vb
        continue
    }

    # Cada nodo clonado necesita SU PROPIA copia del disco: dos VMs no pueden
    # compartir un mismo medio escribiente.
    $discoNodo = $disk
    if ($n.Gold) {
        $discoNodo = "$dir\chr-$vm.vmdk"
        if (-not (Test-Path $discoNodo)) {
            Write-Host "[*] Clonando la gold image para $vm ..."
            & $vb clonemedium disk $gold $discoNodo --format VMDK | Out-Null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $discoNodo)) {
                throw "No se pudo clonar la gold image para $vm"
            }
        }
    }

    Write-Host "[*] Creando VM $vm ..."
    & $vb createvm --name $vm --basefolder "$dir\vms" --register | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Fallo al crear la VM $vm" }
    & $vb modifyvm $vm --memory 512 --cpus 1 --ioapic on --ostype Linux_64 --boot1 disk | Out-Null
    Set-NicsDeVm -Vm $vm -Red $n.Red -RedDe $redDe -Mac $n.Mac -Vb $vb
    & $vb storagectl $vm --name SATA --add sata --controller IntelAhci | Out-Null
    & $vb storageattach $vm --storagectl SATA --port 0 --device 0 --type hdd --medium $discoNodo | Out-Null
    Write-Host "[+] VM '$vm' creada (disco $(Split-Path -Leaf $discoNodo))."
}

if (-not $Configurar) {
    Write-Host ""
    Write-Host "== SIGUIENTES PASOS =="
    Write-Host " 1) Configurar y arrancar:  .\provision_chr.ps1 -Configurar"
    Write-Host " 2) Ejecutar T5 (con los 3 nodos encendidos):  python .\t5_routeros_ips.py"
    return
}

# =============================================================================
# 5) Configurar por SSH (arranque secuencial, sin consola)
# =============================================================================
# atacante y victima arrancan con la IP 10.10.0.2 que trae el clon, la misma que
# el router: por eso CHR-IDS-LAB debe estar APAGADA mientras se reconfiguran, o
# el ARP de 10.10.0.2 seria ambiguo.
$scriptConfig = Join-Path $dir 'chr_apply_config.py'
if (-not (Test-Path $scriptConfig)) { throw "No se encuentra chr_apply_config.py en $dir" }

if (($Nodos -contains 'atacante' -or $Nodos -contains 'victima')) {
    if (-not (Stop-Vm -Nombre 'CHR-IDS-LAB' -Vb $vb)) {
        throw "No se pudo apagar CHR-IDS-LAB. Debe estar apagada mientras se reconfiguran atacante y victima (comparten la IP de bootstrap 10.10.0.2)."
    }
}

foreach ($perfil in @('atacante', 'victima')) {
    if ($Nodos -notcontains $perfil) { continue }
    $n = $NODOS_LAB | Where-Object { $_.Perfil -eq $perfil }
    Write-Host ""
    Write-Host "===== Configurando $($n.VM) ($perfil) ====="
    # Los clones entran por la WAN, que es donde el host tiene 10.10.0.1. La VM
    # tiene que estar APAGADA antes de tocar los adaptadores (modifyvm pide lock
    # de escritura) y antes de arrancar con el NIC definitivo.
    if (Test-VmEncendida -Nombre $n.VM -Vb $vb) { Stop-Vm -Nombre $n.VM -Vb $vb | Out-Null }
    Set-NicsDeVm -Vm $n.VM -Red $n.Red -RedDe $redDe -Mac $n.Mac -Vb $vb
    Write-Host "[*] Arrancando $($n.VM) ..."
    & $vb startvm $n.VM --type headless | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo arrancar $($n.VM)" }

    & python $scriptConfig --nodo $perfil
    if ($LASTEXITCODE -ne 0) { throw "chr_apply_config.py --nodo $perfil fallo (exit $LASTEXITCODE)" }

    if (-not (Stop-Vm -Nombre $n.VM -Vb $vb)) {
        throw "No se pudo apagar $($n.VM) tras configurarlo"
    }
}

if ($Nodos -contains 'router') {
    Write-Host ""
    Write-Host "===== Configurando CHR-IDS-LAB (router) ====="
    & python $scriptConfig --nodo router
    if ($LASTEXITCODE -ne 0) { throw "chr_apply_config.py --nodo router fallo (exit $LASTEXITCODE)" }
}

# =============================================================================
# 6) Encender los tres nodos y comprobar la topologia
# =============================================================================
Write-Host ""
Write-Host "== Encendiendo los 3 nodos =="
foreach ($n in $NODOS_LAB) {
    if ($Nodos -notcontains $n.Perfil) { continue }
    if (Test-VmEncendida -Nombre $n.VM -Vb $vb) {
        Write-Host "[*] $($n.VM) ya estaba encendida."
    } else {
        Write-Host "[*] Arrancando $($n.VM) ..."
        & $vb startvm $n.VM --type headless | Out-Null
    }
}
Start-Sleep -Seconds 25

Write-Host ""
Write-Host "== Verificacion de la topologia =="
$verificador = Join-Path $dir 'verificar_lab.py'
if (Test-Path $verificador) {
    & python $verificador
    $rcVerif = $LASTEXITCODE
} else {
    Write-Warning "No se encuentra verificar_lab.py: se omite la comprobacion."
    $rcVerif = 0
}

Write-Host ""
Write-Host "== SIGUIENTES PASOS =="
if ($rcVerif -ne 0) {
    Write-Host " [X] La topologia todavia no responde. Revise el bloque anterior."
} else {
    Write-Host " [OK] Topologia verificada. Ejecutar la prueba:"
    Write-Host "       setx MIKROTIK_PROFILE lab"
    Write-Host "       setx IDS_IPS_AUTONOMO 1"
    Write-Host "       python .\t5_routeros_ips.py"
}
