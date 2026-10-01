# Evidencias del laboratorio virtual (T5 · IPS sobre RouterOS real)

> **Estado: EJECUTADO Y APROBADO (9/9, `exit 0`).** La topología se verificó antes
> con `verificar_lab.py` (13/13) y T5 pasó los nueve gates contra el CHR real.
> Quedan aquí las nueve salidas de comando y el `informe_t5.json` que las resume.
>
> Secuencia reproducida el `2026-10-01`:
> `verificar_lab.py` 13/13 → `t5_routeros_ips.py` 9/9 → `informe_t5.json`.
>
> Los tres nodos son CHR 7.23.7; atacante y víctima son clones del disco del
> router (gold image), por lo que el montaje no requiere consola, ISO de sistema
> ni internet.

## Propósito

Validar la **respuesta activa del IPS contra un RouterOS real** (CHR) replicando la
topología de la universidad, sin tocar la red de producción:

```
deteccion D2 (ruta de produccion) -> bloqueo autonomo por SSH -> readback CONFIRMADO
-> drop real en la cadena forward (el atacante deja de llegar a la victima)
-> desbloqueo -> restauracion de conectividad
```

## Componentes

| Pieza | Ubicación |
|---|---|
| Runbook de construcción y ejecución | [`_lab/LEEME_LAB.md`](../../_lab/LEEME_LAB.md) |
| Topología, IPs y reglas del CHR | [topologia-lab.md](./topologia-lab.md) |
| Provisionador de los 3 nodos CHR | [`_lab/provision_chr.ps1`](../../_lab/provision_chr.ps1) |
| Configuración por SSH de cada nodo | [`_lab/chr_apply_config.py`](../../_lab/chr_apply_config.py) |
| Verificación previa de la topología | [`_lab/verificar_lab.py`](../../_lab/verificar_lab.py) |
| Script de la prueba T5 | [`_lab/t5_routeros_ips.py`](../../_lab/t5_routeros_ips.py) |
| Perfil de nodos y parser de ping | [`_lab/nodos_lab.py`](../../_lab/nodos_lab.py) |
| Esquema esperado del informe | [plantilla_informe_t5.json](./plantilla_informe_t5.json) |
| Evidencias generadas por T5 | esta carpeta (`t5_*.txt`, `informe_t5.json`) |
| **Demo en vivo + figura + GIF** | [demo-bloqueo.md](./demo-bloqueo.md) |

## Topología (resumen)

| Nodo | Red wan `10.10.0.0/24` | Red lan `10.10.1.0/24` |
|---|---|---|
| Host Windows (IDS/IPS + SSH de gestión) | `10.10.0.1` | `10.10.1.1` |
| RouterOS CHR (`ether1` / `ether2`) | `10.10.0.2` | `10.10.1.2` |
| Atacante (`CHR-ATACANTE-LAB`, 1 NIC) | `10.10.0.3` | — |
| Víctima (`CHR-VICTIMA-LAB`) | `ether1` deshabilitada | `10.10.1.3` |

## Gates de aprobación (9) y evidencia asociada

T5 termina con `exit 0` solo si **los 9** pasan. Cada gate deja su evidencia aquí:

| # | Gate | Qué demuestra | Archivo de evidencia |
|---|---|---|---|
| 1 | `chr_ssh` | CHR alcanzable por SSH + versión RouterOS | `t5_chr_version.txt` |
| 2 | `reglas_drop` | reglas `IDS_BLACKLIST_DROP_FORWARD/INPUT` creadas | `t5_chr_firewall_terse.txt` |
| 3 | `pre_ping` | línea base: atacante → víctima **responde** | `t5_pre_ping_atacante.txt` |
| 4 | `bloqueo_confirmado` | estado `CONFIRMADO` + `confirmado=1` (readback) | `t5_bloqueo_readback.txt` |
| 5 | `post_ping_denegado` | atacante → víctima **ya no responde** | `t5_post_ping_atacante.txt` |
| 6 | `drop_forward_stats` | contador `packets>0` en la regla de `forward` | `t5_chr_drop_stats_forward.txt` |
| 7 | `address_list_presente` | IP del atacante en `IDS_BLACKLIST` | `t5_chr_address_list.txt` |
| 8 | `desbloqueado` | `address-list remove` con readback vacío | solo en `informe_t5.json` (`gates[].detalle`) |
| 9 | `tras_ping_restaurado` | conectividad **restaurada** tras el desbloqueo | `t5_tras_desbloqueo_ping.txt` |

> [!IMPORTANT]
> El gate 8 no genera archivo propio: su evidencia es la línea de detalle en
> `informe_t5.json`. Al archivar la tesis hay que incluir también ese JSON.

## Cómo se ejecuta

1. Montar los 3 nodos y comprobar la topología:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\_lab\provision_chr.ps1 -Configurar
   python .\_lab\verificar_lab.py          # exit 0 = listo para T5
   ```
2. Credenciales (**nunca versionar**): `config/mikrotik_lab.json` y, si
   atacante y víctima usan claves distintas, `_lab/nodos.json` (ambos en
   `.gitignore`; plantillas en `config/mikrotik_lab.json.example` y
   `_lab/nodos.json.example`). Por defecto los clones usan las credenciales del
   router.
3. Con los tres nodos encendidos y las reglas del CHR aplicadas:
   ```powershell
   $env:MIKROTIK_PROFILE = 'lab'
   $env:IDS_IPS_AUTONOMO = '1'
   python .\_lab\t5_routeros_ips.py
   echo "exit=$LASTEXITCODE"     # 0 = 9/9 PASS
   ```
4. Guardar la salida de consola completa (el bloque `== GATES T5 ==`) en
   `t5_consola.txt` junto a las evidencias.

## Al terminar la corrida

- [x] `informe_t5.json` presente con los 9 gates en `true`
- [x] Los 8 `t5_*.txt` guardados en esta carpeta
- [x] `t5_consola.txt` con el bloque de gates y el código de salida
- [x] Resultados reales copiados en `docs/CHANGELOG.md` (entrada [18]) y en
      [`docs/tesis/informe_verificacion_codigo_datos.md`](../tesis/informe_verificacion_codigo_datos.md) §P2
- [x] Sustituido el estado «PENDIENTE» de este README por los números obtenidos

## Notas

- Los logs de T5 van a una carpeta temporal (`LOG_FOLDER`): no contamina
  `logs_ciberseguridad/`.
- `IDS_IPS_AUTONOMO=1` solo en el laboratorio; en la red real el modo autónomo
  permanece desactivado hasta una validación formal.
- El bloqueo se prueba contra el `forward` (tráfico entre nodos), no contra el
  `input`; la regla de `input` queda aplicada y visible como control.
- El ping de los gates 3, 5 y 9 se hace con `/ping <ip> count=3` de RouterOS y
  el veredicto sale de `sent=… received=…`, **no del código de salida**: RouterOS
  devuelve `rc=0` aun con cero paquetes recibidos, así que mirar solo `rc`
  haría pasar `post_ping_denegado` con y sin ataque.