# Demostración en vivo del bloqueo (IDS/IPS sobre RouterOS CHR)

> **Estado: FUNCIONAL Y VERIFICADA (5/5 veredictos, `exit 0`).**
> La corrida completa con detección real, bloqueo confirmado por readback,
> diferencial de conectividad y desbloqueo pasa los cinco veredictos.
>
> Secuencia reproducida el `2026-10-01` con los tres CHR 7.23.7 encendidos.

## Qué demuestra

La demo convierte T5 (script de gates, pensado para CI) en algo **gr adaptable**:
una línea de tiempo con dos pings en vivo y el contador del router, de modo que se
ve pasar el tráfico de `OK` a `TIMEOUT` y volver a `OK`, mientras el equipo cuenta
cada paquete que descarta.

```
atacante 10.10.0.3 ──▶ router 10.10.0.2 ──▶ victima 10.10.1.3
        ▲                      │
        └── ping objeto        └── ping de CONTROL (lo hace la victima)
```

## Las tres señales en pantalla

| Señal | Qué es | Por qué importa |
|---|---|---|
| `atacante->victima` | el tráfico objeto del bloqueo | se muere al activarse: es la prueba principal |
| `victima->ROUTER` | ping de control | si sigue respondiendo, los timeouts son por el bloqueo y no por una caída del laboratorio |
| contador `IDS_BLACKLIST_DROP_FORWARD` | paquetes contados por el router | una caída de red no haría subir este número; es lo que convierte la demo en evidencia |

> [!IMPORTANT]
> El control **no** sale del atacante a propósito. `bloquear_ip_mikrotik` crea
> además de la regla de `forward` una de `input`
> (`chain=input action=drop src-address-list=IDS_BLACKLIST`), así que al bloquear
> también se le corta al atacante contra el router. Eso es correcto como
> aislamiento de un host comprometido, pero invalida un ping `atacante->router`
> como prueba de que la red sigue viva.

## Cómo se ejecuta

```powershell
$env:MIKROTIK_PROFILE = 'lab'
$env:IDS_IPS_AUTONOMO = '1'

python .\_lab\demo_bloqueo.py      # duraciones por defecto: 14 + 18 + 9 s
python .\_lab\graficar_bloqueo.py  # figura PNG + GIF, desde el CSV
```

Opciones útiles de `demo_bloqueo.py`:

| Opción | Para qué |
|---|---|
| `--sin-pausas` | prueba de humo: cada etapa dura 1 s |
| `--libre / --bloqueado / --restaurado` | ajustar cada etapa en segundos |
| `--intervalo N` | intervalo del ping continuo (por defecto 1 s) |
| `--sin-deteccion` | solo pings y contador, sin ejecutar el motor |

## Grabación con Game Bar

No hay `ffmpeg` ni OBS en la máquina, así que el MP4 sale de la Xbox Game Bar:

1. `Win+Alt+R` para empezar a grabar (o `Win+G` → *Capturar*).
2. Correr la demo.
3. `Win+Alt+R` otra vez para detener.

Se guarda en `C:\Users\<usuario>\Videos\Captures`.

## Salidas

| Archivo | Contenido |
|---|---|
| `demo_timeline.csv` | línea de tiempo cruda: `t_rel, t_fmt, fase, evento, ok, detalle` |
| `fig_bloqueo_timeline.png` | figura estática para la memoria |
| `demo_bloqueo.gif` | animación para proyectar o insertar en un PPT |

Los tres están versionados en el repositorio (commit `[20]`).

El PNG y el GIF se generan **solo** desde el CSV. Si la figura contradijera al
CSV, el bug estaría en `graficar_bloqueo.py`, no en el laboratorio.

### Comprobación de reproducibilidad

Como el CSV está versionado (commit `[20]`), la figura es verificable. Reejecutar
`graficar_bloqueo.py` sobre el CSV del repositorio reproduce los archivos
**byte a byte**:

| Archivo | SHA-256 (prefijo) |
|---|---|
| `fig_bloqueo_timeline.png` | `CA580D24CC84BDCB54C7BA5F…` |
| `demo_bloqueo.gif` | `B2FC0018A58B846E3C2F86EC…` |

Si alguien clona el repo y corre el script, obtiene los mismos bytes. Eso
convierte la figura en evidencia auditable y no en una captura de pantalla.

## Trazabilidad de la evidencia

Qué es fuente de verdad y qué es regenerable:

| Artefacto | Papel | Versionado |
|---|---|---|
| `docs/lab/demo_timeline.csv` | **fuente de verdad** de la línea de tiempo | sí |
| `docs/lab/fig_bloqueo_timeline.png` | derivado, reproducible al byte | sí |
| `docs/lab/demo_bloqueo.gif` | derivado, reproducible al byte | sí |
| `docs/lab/t5_routeros_ips.txt` | evidencia del gate de T5 (9/9) | sí |
| `docs/lab/informe_t5.json` | los 9 gates con veredicto y detalle | sí |
| `docs/lab/intrusiones_resumen.json` | agregado de `intrusiones.db`, sin IPs | sí |
| `docs/lab/bloqueos_resumen.json` | agregado de los `.log`, sin IPs | sí |
| `datasets/SQLi_Zenodo/D2_test.csv` | dataset externo que alimenta la detección | sí (7,5 MB) |
| `Captura_Linea_Base/captura_volumen_0911.csv` | línea base de tráfico, 150 muestras | sí |
| `logs_ciberseguridad/*.sha256` | sellos semanales, sin el `.log` adjunto | sí (9) |
| `intrusiones.db` | base local con IPs de terceros | **no** |
| `logs_ciberseguridad/*.log` | mismos datos que el `.db`, en texto plano | **no** |

Tres salvedades que conviene no ocultar al leer la tabla:

1. **Los `.sha256` contienen SHA-512**, no SHA-256, pese al nombre de la
   extensión: así lo produce `log_exporter.py:173`. Verifican con `sha512sum`.
   Como los `.log` no se publican, **ninguno de los 9 sellos puede verificarse
   tras un `git clone`**: quedan como constancia del sellado, no como prueba
   verificable por un tercero. Localmente, los de las semanas `2026-09-04`,
   `2026-09-15` y `2026-09-24` sí verifican; el de `2026-08-25` no, porque el
   `.log` cambió después de ser sellado; los otros 5 corresponden a `.log` que ya
   no existen en la máquina.
2. **No se publica `logs_bloqueos.log` aunque sea la evidencia más legible.**
   Contiene las mismas 13 IPs de origen y los mismos 113 bloqueos que
   `intrusiones.db`, en texto plano: `149.154.166.110` (Telegram) ×18 y
   `8.8.8.8` (Google DNS) ×14 entre otras. Publicarlo por la vía del `.log`
   anularía la razón por la que el `.db` queda fuera. Los conteos están en
   `bloqueos_resumen.json`.
3. **`informe_test_masivo.json` (bloque `T4`) declara como prueba un
   `logs_bloqueos.log` en `C:\Users\rojas\AppData\Local\Temp\ids_logs_test_*`,
   carpeta que ya no existe.** Ninguna de las copias de `logs_bloqueos.log`
   disponible es ese archivo. La evidencia del bloqueo autónomo real es
   `t5_routeros_ips.txt` y `demo_timeline.csv`, no ese log.

Los CSV de evidencia llevan `-text` en `.gitattributes`. Con
`core.autocrlf=true`, Git normalizaría los saltos de línea y los hashes dejarían
de coincidir.

Sobre qué datos no se publican y por qué, ver
[`docs/informe_privacidad_ips.md`](../informe_privacidad_ips.md).


## Veredictos de la corrida

| Veredicto | Qué comprueba |
|---|---|
| el atacante llegaba a la víctima antes | línea base |
| dejó de llegar mientras estaba bloqueado | eficacia del corte |
| volvió a llegar tras desbloquear | reversibilidad |
| la red seguía viva (control víctima→router) | descarta caída del laboratorio |
| el router contó los descartes | evidencia en el equipo, no solo en el cliente |

## Notas técnicas

- **Tráfico real:** el ping sí lo es. La detección SQLi se inyecta como features
  NetFlow D2 por `ids.on_flow_ready`, igual que en T5; no se sniffa un payload
  HTTP real porque el motor no inspecciona payloads.
- **Formato del ping de RouterOS.** Los dos formatos de línea **no** tienen los
  mismos campos. Capturado de un CHR 7 real con el bloqueo puesto:

  ```
  con respuesta:  '    0 10.10.1.3     56  63 465us     '
  con timeout:    '    1 10.10.1.3                    timeout     '
  ```

  En la línea de timeout RouterOS **omite SIZE y TTL**. Por eso el regex los
  trata como grupo opcional: si los exigiera, ninguna línea de timeout casaría,
  los paquetes se perderían en silencio y la etapa `BLOQUEADO` saldría `0/0`
  aunque el bloqueo funcionase.
- **Paquetes en vuelo.** Un paquete ya salido cuando se aplica la regla puede
  responder igual. Se cuentan aparte como `(en vuelo)` en vez de colarlos en
  `BLOQUEADO`, que haría fallar la demo por un artefacto de temporización y no
  por un fallo del IPS.
- **El lote D2 se carga antes de arrancar los medidores.** Leer 7.8 MB con pandas
  y recorrerlos con `iterrows()` mantiene el GIL ocupado; con los pings corriendo
  en paralelo, sus hilos se quedaban sin leer el canal y se perdían justo los
  paquetes de la etapa interesante. Pagando el coste fuera de plano, en vivo solo
  queda la evaluación del motor.
- **Rendimiento del GIF.** El eje secundario se crea **una sola vez** y su
  altura se fija para todo el metraje. Crear un `twinx()` por fotograma
  acumulaba cientos de ejes vivos y el `figure` acababa dibujándolos todos en
  cada frame.
- **Salida atómica.** Hay dos hilos escribiendo a la vez, así que cada línea se
  imprime bajo un candado y con `flush=True`: sin eso, colorama parte la
  escritura al quitar los códigos ANSI y las líneas salen pegadas y entrecortadas.
- Los logs de la demo van a una carpeta temporal: no contamina
  `logs_ciberseguridad/`.
