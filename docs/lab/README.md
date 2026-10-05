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
| Trazabilidad de la evidencia (qué es fuente de verdad) | [demo-bloqueo.md § Trazabilidad](./demo-bloqueo.md#trazabilidad-de-la-evidencia) |
| Datos no publicados y motivo | [`docs/informe_privacidad_ips.md`](../informe_privacidad_ips.md) |

## Evidencia versionada en el commit `[20]`

Además de las nueve salidas de T5, el repositorio incluye:

| Archivo | Qué aporta |
|---|---|
| `demo_timeline.csv` | línea de tiempo cruda de la demo; fuente de verdad de la figura |
| `intrusiones_resumen.json` | agregado de `intrusiones.db` (585 ataques, 113 bloqueos) sin IPs |
| `bloqueos_resumen.json` | agregado de `logs_bloqueos.log` y los logs semanales, sin IPs |
| `fig_bloqueo_timeline.png` y `demo_bloqueo.gif` | derivados, reproducibles al byte desde el CSV |
| `../../datasets/SQLi_Zenodo/D2_test.csv` | dataset externo (7,5 MB) que alimenta la detección |
| `../../Captura_Linea_Base/captura_volumen_0911.csv` | línea base de tráfico, 150 muestras |

Tres artefactos **no** se publican, y el motivo está en
[`demo-bloqueo.md § Trazabilidad`](./demo-bloqueo.md#trazabilidad-de-la-evidencia)
y en el informe de privacidad: `intrusiones.db` y los `.log` de
`logs_ciberseguridad/` (contienen IPs públicas de terceros) y las credenciales del
laboratorio. Los `.sha256` sí se publican, pero sin su `.log` adjunto ninguno
puede verificarse tras un clon.


## Corridas repetidas (`corridas/`)

La corrida de la tabla anterior es la que está en la raíz de `docs/lab/`. Para no
pisarla, las siguientes se escriben en su propia carpeta con `--evidencia-dir`:

```powershell
python .\_lab\t5_routeros_ips.py   --evidencia-dir docs\lab\corridas\corrida2
python .\_lab\demo_bloqueo.py      --evidencia-dir docs\lab\corridas\corrida2
python .\_lab\graficar_bloqueo.py  --csv docs\lab\corridas\corrida2\demo_timeline.csv `
                                    --salida-dir docs\lab\corridas\corrida2
```

Sin ese flag los scripts siguen escribiendo en `docs/lab/`, igual que antes.
Cada corrida deja su CSV, sus figuras y la consola completa de T5 y de la demo.

### Corrida 2

Repetición independiente de la corrida 1, con las tres VMs encendidas en ventana
visible para poder grabarla. Resultado: **T5 9/9** y **demo 5/5**, coherente con
la corrida 1. Durante la etapa bloqueada hubo **0 paquetes aceptados y 16
descartados** hacia la víctima, mientras el control `víctima→router` quedó en
**18/18**: el corte es del atacante, no de la red.

Esta repetición no fue un trámite: sirve de replicación, y además destapó un
defecto de medición que la corrida 1 no había mostrado (ver abajo).


### Defecto corregido: la hora anotada no era la de envío

La primera corrida 2 dio **4/5**. El veredicto «dejó de llegar mientras estaba
bloqueado» falló porque un paquete que había salido **antes** del bloqueo se
anotaba **después**, y ya dentro de la etapa `BLOQUEADO`.

La causa no estaba en el IPS sino en el instrumento: `PingContinuo` retiene la
última línea de cada trozo para no emitir un paquete a medias (necesario, porque
las líneas llegan troceadas), pero tomaba la hora **al emitir**, no al llegar. Con
`interval=1` eso retrasaba **todos** los sellos ~1 s. Medido sobre el CSV de la
corrida 2, el desfase era de `+1,00 s` en cada paquete, con picos de `+2,00 s`
cuando entraban dos trozos juntos.

Un paquete enviado en `t=16,02` se anotaba en `t=18,06`: 1,7 s tarde, ya con la
regla puesta, y por tanto contado como fuga. Al reconstruir el envío real desde
la cadencia conocida del ping, ese paquete salió **antes** del bloqueo confirmado
en `t=16,37`: estaba en vuelo de verdad. En las dos corridas **ningún** timeout
se había enviado antes del bloqueo, que es justo la firma de un bloqueo que
funciona.

La corrección (`PingContinuo._t_de_posicion`) fecha cada línea con el instante de
**llegada** de su trozo, con lo que el retardo del retenido deja de desplazar los
sellos. Verificado en aislamiento: el error por paquete pasa de `+1,00 s` a
`+0,00 s`. La categoría `EN_VUELO` se conserva, pero el margen ya no es una
holgura inventada: se mide y se anota en el CSV como `margen_envio`.

Que la instrumentación se auto-verifique quedó documentado porque el caso es
ilustrativo: una primera versión de la corrección falló con
`'PingContinuo' object has no attribute '_cursor_limpio'` y dejó la demo en
`0/0`. La causa era una errata en el nombre del método recién añadido, no la
lógica del arreglo; los dos hilos de ping murieron en el primer trozo y por eso
no se registró ningún paquete. Se detectó ejecutando el parser directamente, sin
VMs, y quedó una comprobación que fija el comportamiento esperado.


## Figuras del laboratorio

Tres figuras para explicar el laboratorio, generadas por
[`_lab/graficar_lab.py`](../../_lab/graficar_lab.py):

| Figura | Para qué sirve |
|---|---|
| [`fig_topologia_lab.png`](fig_topologia_lab.png) | **Cómo está construido**: el host, las dos redes host-only, las tres VMs y por dónde pasa el tráfico |
| [`fig_secuencia_demo.png`](fig_secuencia_demo.png) | **Cómo funciona** en una imagen: las cuatro fases sobre el tiempo real y los nueve gates de T5 debajo |
| [`lab_secuencia.gif`](lab_secuencia.gif) | Lo mismo en movimiento, para proyectar o defender en vivo |

```powershell
python .\_lab\graficar_lab.py                        # las tres, desde la corrida de la raiz
python .\_lab\graficar_lab.py --solo-png             # sin el GIF, que es lo que tarda
python .\_lab\graficar_lab.py --csv docs\lab\corridas\corrida2\demo_timeline.csv `
                                 --t5  docs\lab\corridas\corrida2\informe_t5.json
```

Las direcciones IP de `fig_topologia_lab.png` no están todas escritas a mano: las
de atacante y víctima se leen de `nodos_lab.py`, y la del router de
`config/mikrotik_lab.json`, así que si esas cambian la figura cambia con ellas.
Las dos del host y la del LAN del router sí están fijas en el graficador, porque
no están en ninguna configuración; se pueden sobrescribir con `MIKROTIK_IP` y
`MIKROTIK_LAN_IP` si algún día se renumera la red.

**De dónde salen los datos, y qué significan.** Las tres figuras se derivan de la
evidencia ya registrada —el CSV de la demo y el `informe_t5.json`—, no de una
corrida en vivo. Es justo lo que las hace defendibles: se regeneran cuando se
quiera y están obligadas a coincidir con el CSV, así que si una figura
contradicta a la evidencia sería un bug del graficador y no del laboratorio. En
cambio **no son capturas del laboratorio funcionando**, y no deben presentarse
como tal.

`fig_bloqueo_timeline.png` y `demo_bloqueo.gif`, que ya estaban antes, se
mantienen: las primeras miden los paquetes uno por uno, estas muestran la
topología y la secuencia. Son complementarias.

## Topología (resumen)

La misma topología en [diagrama dibujado](topologia-lab.png) y en código
[mermaid](topologia-lab.md), que se renderiza con
`npx @mermaid-js/mermaid-cli -i lab.mmd -o topologia-lab.svg`.

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