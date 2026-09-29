# Laboratorio virtual para la prueba T5 (IPS + RouterOS CHR)

> **Disenado en:** maquina actual (solo-lectura: no se crearon VMs ni se descargo nada).
> **Ejecutar en:** la maquina con capacidad para las 3 VMs (~1 GB en total de
> RAM de invitados + VirtualBox). NO ejecutar en la red real de la universidad.

## Proposito
Verificar la integracion IPS de produccion contra un **RouterOS real** (CHR
7.23.7) en un entorno aislado que replica la red de la universidad:
deteccion D2 (ruta de produccion) -> bloqueo autonomo por SSH -> **readback**
`CONFIRMADO` -> **drop real** en el forward del firewall (el atacante deja de
llegar a la victima) -> desbloqueo -> restauracion.

## Plan de IP (fijo, no cambiarlo sin tocar el kit)
| Nodo        | Red wan 10.10.0.0/24   | Red lan 10.10.1.0/24   |
|-------------|------------------------|------------------------|
| Host (Windows, IDS/IPS + SSH de gestion) | 10.10.0.1 | 10.10.1.1 |
| CHR ether1 (wan) / ether2 (lan)          | 10.10.0.2 | 10.10.1.2 |
| Atacante (Alpine, gw 10.10.0.2)          | 10.10.0.50 | - |
| Victima (Alpine, gw 10.10.1.2)           | - | 10.10.1.50 |

## Pre-requisitos (maquina objetivo)
- Windows (cualquier edicion con VirtualBox) con **Oracle VirtualBox + Extension Pack** instalados.
- Python 3.13 + dependencias del proyecto (pandas, joblib, numpy, scapy, PyQt5) y:
  `pip install paramiko`
- Copiar todo el proyecto (o al menos: `ids.py`, `mikrotik_api.py`, `log_exporter.py`,
  `flujos_red.py`, `telegram_alert.py`, `Modelos_Entrenados/*v5*`, `sqli_guard.pkl`,
  `sql_guard_features.pkl`, `datasets/SQLi_Zenodo/D2_test.csv`, `_lab/`).

## Pasos
1. **VirtualBox:** `provision_chr.ps1` crea las redes host-only y la VM `CHR-IDS-LAB`
   (descarga el disco CHR 7.23.7; si el enlace cambia, descargue el VMDK/VDI a mano
   desde https://mikrotik.com/download/chr y coloquelo en `_lab/`).
   ```
   powershell -ExecutionPolicy Bypass -File .\provision_chr.ps1
   ```
2. **Primera consola del CHR** (una sola vez): `VBoxManage startvm CHR-IDS-LAB` y siga
   `chr_bootstrap_console.txt` (password de admin + crear usuario `ids` + habilitar SSH
   para 10.10.0.0/24).
3. **Config automatica** (IPs + firewall drop): `python .\chr_apply_config.py`.
   Verifique que imprime las reglas `IDS_BLACKLIST_DROP_FORWARD/INPUT`.
4. **VMs atacante/victima:** `.\provision_alpine.ps1` crea `ATACANTE-IDS` y `VICTIMA-IDS`.
   Instale Alpine en cada una (ISO adjunta):
   - boot de la ISO, login `root` (sin password al inicio)
   - `setup-alpine` -> modo **sys**, disco por defecto, hostname (atq/vic),
     red manual con IP estatica segun el plan, gw, DNS 1.1.1.1, password de root,
     **activar servidor OpenSSH**
   - `/reboot`, retirar la ISO, verificar: `ping 10.10.0.2` (atacante) y `ping 10.10.1.2` (victima).
5. **Credenciales del lab (NUNCA versionar):** cree `_lab/alpine.json`
   (gitignored):
   ```json
   {
     "atacante": { "user": "root", "pass": "CLAVE_ROOT_ATACANTE" },
     "victima":  { "user": "root", "pass": "CLAVE_ROOT_VICTIMA" }
   }
   ```
   y `config/mikrotik_lab.json` (gitignored) con las credenciales del CHR:
   ```json
   { "ip": "10.10.0.2", "user": "ids", "pass": "CLAVE_CHR", "port": 22,
     "address_list": "IDS_BLACKLIST" }
   ```
6. **Ejecutar T5** (con los tres nodos encendidos):
   ```
   setx MIKROTIK_PROFILE lab
   setx IDS_IPS_AUTONOMO 1
   python .\t5_routeros_ips.py
   ```
   El motor usa `ids.on_flow_ready` con features reales de D2 y la **IP del
   atacante del lab** (10.10.0.50) para que el bloqueo cayga sobre esa maquina.
7. **Resultado esperado:** 8/8 gates PASS y exit 0:
   `chr_ssh`, `reglas_drop`, `pre_ping`, `bloqueo_confirmado`,
   `post_ping_denegado`, `drop_forward_stats`, `address_list_presente`,
   `desbloqueado`, `tras_ping_restaurado`.
   Evidencias en `docs/lab/` (`informe_t5.json`, `print terse`, pings, stats).
8. **Registrar** en `docs/CHANGELOG.md` (entrada [17]) y en el informe de la tesis
   (apartado T5) con los numeros reales obtenidos.

## Notas
- Licencia CHR gratuita: 1 Mbps / 1 core — suficiente para las pruebas.
- `IDS_IPS_AUTONOMO=1` solo en el lab; en la red real se mantiene el modo
  semi-autonomo (alerta) hasta una validacion formal aparte.
- Si alguna regla falla de la lista prevista, revise `chr_apply_config.py` (los
  comandos RouterOS pueden variar ligeramente entre versiones).