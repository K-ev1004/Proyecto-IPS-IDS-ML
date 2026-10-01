# Laboratorio virtual para la prueba T5 (IPS + RouterOS CHR)

> **Ejecutar en:** una maquina con capacidad para las 3 VMs (~1,5 GB de RAM de
> invitados + VirtualBox). Topologia **aislada** por redes host-only: las VMs no
> se conectan a la red real de la universidad.
>
> **Los tres nodos son RouterOS CHR 7.23.7.** Atacante y víctima son clones del
> disco del router, así que el montaje **no necesita consola, ni ISO de sistema,
> ni internet**: se clona el disco y se reconfigura por SSH.

## Proposito
Verificar la integracion IPS de produccion contra un **RouterOS real** (CHR
7.23.7) en un entorno aislado que replica la red de la universidad:
deteccion D2 (ruta de produccion) -> bloqueo autonomo por SSH -> **readback**
`CONFIRMADO` -> **drop real** en el forward del firewall (el atacante deja de
llegar a la victima) -> desbloqueo -> restauracion.

## Plan de IP (fijo, no cambiarlo sin tocar el kit)
| Nodo | Red wan 10.10.0.0/24 | Red lan 10.10.1.0/24 |
|------|----------------------|----------------------|
| Host (Windows: IDS/IPS + SSH de gestion) | 10.10.0.1 | 10.10.1.1 |
| `CHR-IDS-LAB` ether1 (wan) / ether2 (lan) | 10.10.0.2 | 10.10.1.2 |
| `CHR-ATACANTE-LAB` ether1 (gw 10.10.0.2)  | 10.10.0.3 | - |
| `CHR-VICTIMA-LAB` ether2 (gw 10.10.1.2)   | - | 10.10.1.3 |

El atacante tiene **una sola NIC**: todo su trafico hacia la victima pasa por el
router, que es lo que el IPS necesita para cortarlo. La victima conserva su
`ether1` (wan) pero **deshabilitada** por software: ver la nota de
`docs/lab/topologia-lab.md`.

## Pre-requisitos (maquina objetivo)
- Windows (cualquier edicion con VirtualBox) con **Oracle VirtualBox + Extension Pack** instalados.
- Python 3.13 + dependencias del proyecto (pandas, joblib, numpy, scapy, PyQt5) y:
  `pip install paramiko`
- Copiar todo el proyecto (o al menos: `ids.py`, `mikrotik_api.py`, `log_exporter.py`,
  `flujos_red.py`, `telegram_alert.py`, `Modelos_Entrenados/*v5*`, `sqli_guard.pkl`,
  `sql_guard_features.pkl`, `datasets/SQLi_Zenodo/D2_test.csv`, `_lab/`).

## Pasos

### 1. Montar el laboratorio (un solo comando)
```
powershell -ExecutionPolicy Bypass -File .\provision_chr.ps1 -Configurar
```
`provision_chr.ps1` hace, en este orden:

1. descarga el disco CHR 7.23.7 si falta (`chr-7.23.7.vmdk`; enlace oficial
   `https://download.mikrotik.com/routeros/7.23.7/chr-7.23.7.vmdk.zip`);
2. crea las redes host-only `idslab_wan` (10.10.0.1/24) e `idslab_lan` (10.10.1.1/24);
3. crea la **gold image** `_lab/chr-gold-lab.vmdk` clonando el disco del router
   (exige `CHR-IDS-LAB` apagada: es un clon en caliente de su disco);
4. crea `CHR-ATACANTE-LAB` y `CHR-VICTIMA-LAB`, cada una con **su propia copia**
   de la gold image (dos VMs no pueden compartir un medio escribiente);
5. rearranca atacante y victima **por turnos** y ejecuta
   `chr_apply_config.py --nodo <rol>` sobre cada una;
6. enciende los tres nodos y lanza `verificar_lab.py`.

> [!IMPORTANT]
> El paso 5 es secuencial y con `CHR-IDS-LAB` **apagada** a propósito: los clones
> heredan `10.10.0.2`, la misma IP del router, y con dos equipos definiendo esa
> IP el ARP de la red queda ambiguo. El script apaga el router antes de arrancar
> los clones y lo vuelve a encender al final.

Subconjuntos utiles (idempotentes):
```
.\provision_chr.ps1                       # solo crear redes y VMs
.\provision_chr.ps1 -Nodos atacante       # un solo nodo
.\provision_chr.ps1 -ChrVersion 7.23.7    # otra version de CHR
```

### 2. Configurar el router (solo la primera vez, o para reajustar reglas)
La **primera** configuracion del CHR es la unica que necesita consola, porque no
hay de donde clonar. Es una unica sesion:
```
VBoxManage startvm CHR-IDS-LAB
```
y siga `_lab/chr_bootstrap_console.txt` (password de admin + crear usuario `ids`
+ habilitar SSH para 10.10.0.0/24). A partir de ahi, el disco **ya sirve de gold
image** y atacante/victima nunca mas necesitan consola.

Con el usuario `ids` disponible, las IPs y el firewall se aplican sin consola:
```
python .\chr_apply_config.py --listar            # ver los 3 perfiles
python .\chr_apply_config.py --nodo router       # IPs + reglas IDS_BLACKLIST_*
python .\chr_apply_config.py --nodo atacante --ip 10.10.0.3/24
```
El perfil se puede reejecutar cuantas veces haga falta: es idempotente.

### 3. Comprobar la topologia antes de T5
```
python .\verificar_lab.py
python .\verificar_lab.py --detalle     # imprime /ip address print, /interface, rutas
```
Verifica SSH en los 3 nodos, que cada uno tenga **exactamente** las IPs
previstas (ni una de mas ni una de menos), que las dos reglas de drop existan,
que la victima tenga `ether1` deshabilitada, que el atacante no tenga ruta a la
LAN, y que `atacante -> victima` responda. Codigo de salida 0 = listo para T5.

### 4. Credenciales del lab (NUNCA versionar)
`config/mikrotik_lab.json` (gitignored) con las credenciales del CHR:
```json
{ "ip": "10.10.0.2", "user": "ids", "pass": "CLAVE_CHR", "port": 22,
  "address_list": "IDS_BLACKLIST" }
```
Atacante y victima son el mismo equipo clonado, asi que **usan esas mismas
credenciales**. Para separarlas basta `_lab/nodos.json` (gitignored):
```json
{ "atacante": { "host": "10.10.0.3", "user": "ids", "port": 22 },
  "victima":  { "host": "10.10.1.3", "user": "ids", "port": 22 } }
```
o las variables `LAB_ATACANTE_IP` / `LAB_ATACANTE_PASS` / `LAB_VICTIMA_IP` /
`LAB_VICTIMA_PASS` / `LAB_*_USER` / `LAB_*_PUERTO`. La resolucion completa esta
en `nodos_lab.cargar_nodos()`.

### 5. Ejecutar T5 (con los tres nodos encendidos)
```
setx MIKROTIK_PROFILE lab
setx IDS_IPS_AUTONOMO 1
python .\t5_routeros_ips.py
```
El motor usa `ids.on_flow_ready` con features reales de D2 y la **IP del
atacante del lab** (10.10.0.3) para que el bloqueo cayga sobre esa maquina.
La victima **no necesita ningun servidor web**: el trafico es sintetico, el
deteccion y el bloqueo son los de produccion.

### 6. Resultado esperado: 9/9 gates PASS y exit 0
`chr_ssh`, `reglas_drop`, `pre_ping`, `bloqueo_confirmado`,
`post_ping_denegado`, `drop_forward_stats`, `address_list_presente`,
`desbloqueado`, `tras_ping_restaurado`.
Evidencias en `docs/lab/` (`informe_t5.json`, `print terse`, pings, stats).

### 7. Demo en vivo, figura y GIF (para grabar en MP4)
```
setx MIKROTIK_PROFILE lab
setx IDS_IPS_AUTONOMO 1
python .\demo_bloqueo.py          # ~50 s: pings a 1 Hz + contador del router
python .\graficar_bloqueo.py      # fig_bloqueo_timeline.png + demo_bloqueo.gif
```
T5 es la prueba de gates; esto es lo mismo pero **gr adaptable**: se ve pasar el
ping de `OK` a `TIMEOUT` y volver a `OK`. Para grabar, `Win+Alt+R` (Xbox Game Bar)
antes de arrancar y otra vez al terminar; el MP4 cae en `Videos\Captures`.

Opciones: `--sin-pausas` (humo, 1 s por etapa), `--libre/--bloqueado/--restaurado`
(segundos por etapa), `--intervalo N`, `--sin-deteccion` (solo medidores).

Detalle, tabla de veredictos y notas tecnicas en
[`docs/lab/demo-bloqueo.md`](../docs/lab/demo-bloqueo.md).

### 8. Registrar
Anotar en `docs/CHANGELOG.md` y en el informe de la tesis (apartado T5) los
numeros reales obtenidos.

## Notas
- Licencia CHR gratuita: 1 Mbps / 1 core — suficiente para las pruebas.
- `IDS_IPS_AUTONOMO=1` solo en el lab; en la red real se mantiene el modo
  semi-autonomo (alerta) hasta una validacion formal aparte.
- **El ping de T5 se parsea, no se mira el codigo de salida.** En RouterOS
  `/ping <ip> count=3` devuelve `rc=0` aun con cero paquetes recibidos; el
  veredicto sale de `sent=… received=…` (`nodos_lab.ping_nodo()`). Con el
  criterio antiguo (`rc`) el gate `post_ping_denegado` no distinguiria un ataque
  bloqueado de uno sin bloqueo.

## Material heredado de la version Alpine (fuera del flujo activo)
Estos archivos se conservan por trazabilidad, pero **la opcion 3 no los usa** y
no son necesarios para montar el laboratorio:
`provision_alpine.ps1`, `install_alpine_vm.sh`, `alpine.json`, `mk_lab_iso.py`,
`verify_lab_iso.py`, `PASO-INSTALAR-ALPINE.txt`, las ISOs de `_lab/` y las VMs
`ATACANTE-IDS` / `VICTIMA-IDS`.

Motivo del descarte (verificado): la ISO de Alpine no trae `linux-lts` ni
`syslinux`, asi que la instalacion al disco exige red; `setup-disk` no acepta el
repo local sin firma (`--allow-untrusted` no existe en esa version) y ademas
pide confirmacion interactiva (`confirm_erase`), y la consola de Alpine perdia
caracteres de forma intermitente. Clonar el CHR resuelve las tres cosas.
