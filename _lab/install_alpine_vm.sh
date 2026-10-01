#!/bin/sh
# =============================================================================
# install_alpine_vm.sh - Instalacion desatendida de Alpine para el lab IDS/IPS
# Universidad UNIPAZ - Proyecto IDS/IPS (Fase III).
# -----------------------------------------------------------------------------
# Se ejecuta DENTRO de la ISO live (como root), antes de instalar nada:
#
#   sh install_alpine_vm.sh <hostname> <ip> <gateway>
#
# Ejemplos:
#   sh install_alpine_vm.sh atq  10.10.0.50 10.10.0.2
#   sh install_alpine_vm.sh vic  10.10.1.50 10.10.1.2
#
# REQUISO INETNET EN ESTA FASI (una sola vez, mientras instala):
# las ISO de Alpine 3.24 (virt y standard) traen solo 95 paquetes de base: NO
# incluyen ni el kernel (linux-lts) ni el bootloader (syslinux). Sin ellos no
# hay sistema instalable al disco. La VM lleva una NIC NAT solo para esta fase;
# despues se quita y el lab queda aislado, como debe ser.
#
# Password de root: lab   (credencial de laboratorio, ver _lab/alpine.json)
# Al terminar APAGA la VM (no reinicia: con la ISO live como primer disco de
# arranque, un reboot devolveria la VM a la ISO en vez de al disco instalado).
#
# -----------------------------------------------------------------------------
# POR QUE NO SE USA setup-alpine
#
# setup-alpine es INTERACTIVO. Aunque se le pase un archivo de respuestas, para
# la password de root termina llamando a 'passwd' sin argumentos, y busybox
# 'passwd' con la entrada estandar cerrada no falla: se queda imprimiendo
# 'new password:' para siempre. Asi que aqui no se usa:
#
#   1. setup-disk -m sys -s 0 <disco>  -> particiona, instala alpine-base +
#      kernel + bootloader, escribe fstab y extlinux, sin preguntar NADA.
#   2. Se monta la particion raiz y se configura a mano lo que setup-alpine
#      habria hecho: hostname, password de root, openssh e IP fija.
#
# Cada paso se verifica con un mensaje claro, porque el fallo silencioso clasico
# de este lab es que el puerto 22 abre pero nadie puede entrar.
# =============================================================================

set -e

HOST="${1:?falta el hostname (1er argumento)}"
IP="${2:?falta la IP (2do argumento)}"
GW="${3:?falta el gateway (3er argumento)}"
DISK="${ALPINE_DISK:-/dev/sda}"
ROOT_PASS="${ALPINE_ROOT_PASS:-lab}"
NETMASK="255.255.255.0"

# Tope para cualquier comando: un prompt inesperado se convierte en un error
# visible en un minuto, no en una consola colgada toda la tarde.
CORTE="${ALPINE_CMD_TIMEOUT:-120}"

paso() {
	echo
	echo "======== $* ========"
}

paso "1/6 Contexto"
echo "hostname : $HOST"
echo "ip       : $IP/$NETMASK  gateway: $GW"
echo "disco    : $DISK"
echo "alpine   : $(cat /etc/alpine-release 2>/dev/null || echo '?')"
echo "cpu      : $(uname -m)"

# ---------------------------------------------------------------------------
# Repositorio de paquetes. El repo local de la ISO tiene lo basico, pero el
# kernel y el bootloader hay que bajarlos del CDN: por eso se exige internet.
# La version sale de /etc/alpine-release ('3.24.2' -> rama 'v3.24').
# ---------------------------------------------------------------------------
paso "2/6 Repositorio de paquetes"
APK_REPO_LOCAL=$(find /media -maxdepth 4 -type d -name apks 2>/dev/null | head -1)
if [ -n "$APK_REPO_LOCAL" ]; then
	echo "repo local de la ISO: $APK_REPO_LOCAL"
else
	echo "[!] No se encontro el repo local de la ISO; se usara solo el CDN."
fi

VER=$(cat /etc/alpine-release 2>/dev/null || echo '')
RAMO="v$(echo "$VER" | cut -d. -f1,2)"
[ -n "$VER" ] || { echo "[X] No se pudo leer la version de Alpine."; exit 1; }
echo "rama del CDN: $RAMO"

cat > /etc/apk/repositories <<EOF
https://dl-cdn.alpinelinux.org/alpine/$RAMO/main
https://dl-cdn.alpinelinux.org/alpine/$RAMO/community
EOF
cat /etc/apk/repositories

if ! timeout 90 apk update; then
	echo ""
	echo "[X] Sin internet no se puede instalar: la ISO de Alpine 3.24 no trae"
	echo "    ni el kernel (linux-lts) ni el bootloader (syslinux), y setup-disk"
	echo "    los necesita para dejar el disco arrancable."
	echo "    Que hacer: apagar la VM, adjuntarle una NIC NAT (VBoxManage"
	echo "    modifyvm <VM> --nic2 nat) y volver a correr este instalador."
	exit 1
fi

# syslinux y el kernel se instalan aqui y no dentro de setup-disk para que un
# fallo de red se reporte en este punto, con un mensaje claro, y no al final.
paso "2b/6 Descargando kernel y bootloader"
if ! timeout 600 apk add --quiet syslinux linux-lts; then
	echo "[X] No se pudieron descargar syslinux/linux-lts (falta internet?)."
	exit 1
fi
SETUP_DISK=$(command -v setup-disk || true)
[ -n "$SETUP_DISK" ] \
	|| { echo "[X] setup-disk no esta instalado ni en PATH."; exit 1; }
echo "setup-disk: $SETUP_DISK"

# ---------------------------------------------------------------------------
# 3/6 - Instalacion real. setup-disk no pregunta nada. Se le manda 'yes |' por
# si alguna version pide confirmar el borrado del disco.
# ---------------------------------------------------------------------------
paso "3/6 Instalando Alpine en $DISK (esto tarda 3-5 minutos)"
yes | timeout 1200 "$SETUP_DISK" -m sys -s 0 "$DISK" \
	|| { echo "[X] setup-disk fallo. Lea el mensaje de error de arriba."; exit 1; }
echo "setup-disk: OK"

# ---------------------------------------------------------------------------
# 4/6 - Configuracion del sistema ya instalado. El layout de particiones puede
# cambiar entre versiones, asi que se busca la particion que tenga
# /etc/alpine-release en vez de asumir 'sda3'.
# ---------------------------------------------------------------------------
paso "4/6 Configurando el sistema instalado"
mkdir -p /mnt
# El operador pudo montar la ISO de herramientas en /mnt antes de correr esto.
umount /mnt 2>/dev/null || true
ROOTPART=""
for p in ${DISK}[0-9]*; do
	[ -b "$p" ] || continue
	mount "$p" /mnt 2>/dev/null || continue
	if [ -f /mnt/etc/alpine-release ]; then
		ROOTPART="$p"
		break
	fi
	umount /mnt
done
if [ -z "$ROOTPART" ]; then
	echo "[X] No se encontro la particion raiz instalada en $DISK."
	exit 1
fi
echo "raiz instalada en $ROOTPART"

echo "$HOST" > /mnt/etc/hostname

# SSH: setup-disk instala alpine-base pero no necesariamente openssh.
if [ ! -x /mnt/usr/sbin/sshd ]; then
	echo "instalando openssh en el sistema instalado..."
	timeout 600 chroot /mnt apk add --quiet openssh \
		|| { echo "[X] No se pudo instalar openssh en el sistema instalado."; exit 1; }
fi
if [ ! -x /mnt/usr/sbin/sshd ]; then
	echo "[X] El sistema instalado quedo sin sshd (openssh)."
	exit 1
fi
echo "openssh instalado: OK"

# Password de root. Se prueban varias vias porque segun la version el chpasswd
# puede no existir en el destino, o no aceptar '-c SHA512'. Al final se
# VERIFICA contra /etc/shadow: si root queda sin password, el puerto 22 abriria
# pero nadie podria entrar, y eso no se ve hasta tarde.
fijar_password() {
	printf 'root:%s\n' "$ROOT_PASS" | timeout 30 chroot /mnt "$@" >/dev/null 2>&1 || true
	awk -F: '$1 == "root" { print $2 }' /mnt/etc/shadow
}
SHADOW_PW=$(fijar_password /usr/sbin/chpasswd -c SHA512)
case "$SHADOW_PW" in
	'' | '!' | '*' | 'x' | '!!' | '!*') SHADOW_PW=$(fijar_password /usr/sbin/chpasswd) ;;
esac
case "$SHADOW_PW" in
	'' | '!' | '*' | 'x' | '!!' | '!*') SHADOW_PW=$(fijar_password /bin/busybox chpasswd) ;;
esac
case "$SHADOW_PW" in
	'' | '!' | '*' | 'x' | '!!' | '!*')
		echo "[X] No se pudo fijar la password de root en el sistema instalado."
		echo "    Revise que el destino tenga chpasswd:"
		echo "      chroot $ROOTPART apk add shadow"
		echo "    y luego fijela a mano:  chroot $ROOTPART passwd root"
		exit 1
		;;
esac
echo "password de root: OK"

# SSH con password para root. Alpine deja PermitRootLogin en
# 'prohibit-password', que deja FUERA el login por clave de T5: hay que
# reemplazar la linea, no anadirla al final (OpenSSH gana el primer valor que
# encuentra y el archivo generado ya trae el suyo).
if [ ! -f /mnt/etc/ssh/sshd_config ]; then
	echo "[X] No existe /etc/ssh/sshd_config en el sistema instalado."
	exit 1
fi
sed -i -e 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' \
	-e 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication yes/' \
	/mnt/etc/ssh/sshd_config
grep -q '^PermitRootLogin yes' /mnt/etc/ssh/sshd_config \
	|| echo 'PermitRootLogin yes' >> /mnt/etc/ssh/sshd_config
grep -q '^PasswordAuthentication yes' /mnt/etc/ssh/sshd_config \
	|| echo 'PasswordAuthentication yes' >> /mnt/etc/ssh/sshd_config

# Claves de host: sin esto sshd no arranca.
timeout 60 chroot /mnt ssh-keygen -A >/dev/null 2>&1 || true
chroot /mnt rc-update add sshd default >/dev/null 2>&1 || true
chroot /mnt rc-update add networking boot >/dev/null 2>&1 || true
chroot /mnt rc-update add hostname boot >/dev/null 2>&1 || true
echo "servicios habilitados: sshd, networking, hostname"

# IP estatica en el sistema instalado (obligatoria: el CHR tiene que poder
# bloquear al atacante por IP, y DHCP no sirve para eso).
cat > /mnt/etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address $IP
    netmask $NETMASK
    gateway $GW
    hostname $HOST
EOF
echo "--- /etc/network/interfaces instalado ---"
cat /mnt/etc/network/interfaces

# El arranque desde disco depende de esto: si setup-disk no escribio el
# bootloader, la VM vuelve a la ISO live y el lab parece trabado sin explicacion.
if [ -f /mnt/boot/extlinux.conf ] || [ -f /mnt/boot/grub/grub.cfg ] \
	|| [ -f /mnt/boot/syslinux/syslinux.cfg ]; then
	echo "bootloader: OK"
else
	echo "[!] No se encontro bootloader en /mnt/boot. Si al encender no arranca"
	echo "    del disco, revisar la salida de setup-disk de arriba."
fi

sync
umount /mnt

paso "5/6 Resumen"
echo "VM       : $HOST"
echo "IP       : $IP/$NETMASK   gateway: $GW"
echo "SSH      : root / $ROOT_PASS  (PermitRootLogin yes)"
echo "ISO      : se puede desconectar; el disco ya es arrancable"

paso "6/6 Apagando (no reinicia: volveria a la ISO live)"
sleep 2
sync
echo ""
echo "================================================================"
echo " INSTALACION TERMINADA.  VM: $HOST   IP: $IP   gateway: $GW"
echo " Esta VM se apaga sola en unos segundos."
echo " En esta maquina hay que quitar la NIC NAT, poner el disco primero"
echo " y sacar la ISO antes de volver a encenderla."
echo "================================================================"
echo ""

# poweroff y no reboot a proposito: con la ISO live puesta como primer
# dispositivo de arranque, un reboot devolveria la VM a la ISO en vez de al
# disco recien instalado. Apagando, el operador ve desde Windows que termino
# (VBoxManage showvminfo -> poweroff) y ordena el arranque una sola vez.
poweroff
