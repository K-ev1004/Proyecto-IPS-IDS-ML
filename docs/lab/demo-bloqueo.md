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

El PNG y el GIF se generan **solo** desde el CSV. Si la figura contradijera al
CSV, el bug estaría en `graficar_bloqueo.py`, no en el laboratorio.

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
