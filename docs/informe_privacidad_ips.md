# Informe de privacidad de la evidencia publicada

> Documento de trazabilidad del repositorio. Registra qué datos personales o
> de terceros quedan expuestos por el versionado de la evidencia y por qué se
> tomó cada decisión.
>
> Fecha del análisis: `2026-10-01`. Alcance: commit `[20]`.

## Principio aplicado

La evidencia de la tesis se publica **completa** salvo cuando contenga datos de
terceros que el proyecto no controla. No se aplica un criterio distinto según el
archivo: un mismo criterio para base de datos, logs y CSV.

## 1. `intrusiones.db` — NO se publica

Razón: contiene direcciones IP públicas de terceros, muchas de ellas
pertenecientes a servicios que no son parte del laboratorio.

Contenido real del archivo:

| Elemento | Valor |
|---|---|
| Registros en `ataques` | 585 |
| Registros en `bloqueos` | 113 |
| IPs de origen únicas en `bloqueos` | 13 |
| IPs públicas de origen (37 de 113 registros) | `8.8.8.8`, `149.154.166.110`, `150.171.29.11`, `23.39.24.44`, `2.21.75.54`, `2.21.133.158`, `2.22.20.219` |
| IPs privadas `172.20.x` (76 de 113 registros) | red de la universidad |

Decisión: se publica `docs/lab/intrusiones_resumen.json`, un agregado con los
mismos conteos, la distribución por familia de ataque, el rango temporal y la
clasificación de IPs (pública / privada) **sin escribir ninguna dirección**. El
resumen incluye el SHA-512 del `.db` local, de modo que la transformación es
auditable: cualquiera puede regenerar el resumen y comparar el hash.

## 1 bis. `logs_bloqueos.log` y los logs semanales — NO se publican

Este caso es el que más fácil se escapa, así que se documenta aparte.

`logs_bloqueos.log` **es el mismo dato que `intrusiones.db` en texto plano**:

| Indicador | `intrusiones.db` (tabla `bloqueos`) | `logs_bloqueos.log` |
|---|---|---|
| Registros | 113 | 113 |
| IPs de origen únicas | 13 | 13 |
| Registros con IP privada / pública | 76 / 37 | 76 / 37 |
| Familias de ataque | 103 / 7 / 3 | 103 / 7 / 3 |

Publicar el `.log` por la vía del archivo de texto habría anulado por la puerta
de atrás la razón por la que el `.db` queda fuera: mismas IPs de terceros
(`149.154.166.110` Telegram ×18, `8.8.8.8` Google DNS ×14, rangos Akamai/AWS),
mismo conjunto, solo que legible.

Decisión: se publica `docs/lab/bloqueos_resumen.json`, con los conteos por
acción, el rango temporal, la clasificación de IPs y el SHA-512 de cada
archivo local, sin ninguna dirección.

Los 3 logs semanales con contenido tienen el mismo problema: su primera línea ya
registra `IP_SRC: 172.20.4.151` junto a `150.171.109.66`. Se resumen en el mismo
archivo.

> [!NOTE]
> Los dos resúmenes (`intrusiones_resumen.json` y `bloqueos_resumen.json`)
> coinciden exactamente en sus conteos. Esa coincidencia es la comprobación de
> que la agregación no perdió ni deformó registros: es evidencia de que el
> criterio se aplicó de forma consistente a las dos fuentes.


> [!CAUTION]
> Los 113 registros de `bloqueos` están en estado `SIMULADO/SEMI` con
> `confirmado=0`. Esa tabla documenta el **modo semi-autónomo**, no el bloqueo
> autónomo validado. La evidencia del bloqueo autónomo real está en
> [`docs/lab/t5_routeros_ips.txt`](lab/t5_routeros_ips.txt) (gate
> `bloqueo_confirmado`, readback `CONFIRMADO`) y en
> `docs/lab/demo_timeline.csv`.

## 2. Logs y CSV de `evidencia/` — hallazgo preexistente, NO se modifica

Al revisar los CSV ya versionados en `evidencia/` se detectaron direcciones IP
públicas de terceros:

| Archivo | IPs públicas detectadas |
|---|---|
| `evidencia/eventos_ids_20260407_093455.csv` | `57.144.114.192` (Amazon AWS) |
| `evidencia/eventos_ids_20260408_093455.csv` | `57.144.115.33` (Amazon AWS), `2.19.172.154` (Akamai) |
| `evidencia/eventos_ids_20260409_093455.csv` | `2.19.172.154` (Akamai), `172.217.30.170` (Google) |

Estas IPs provienen del tráfico real capturado en el punto de espejo de la red
universitaria. Son destinos de servicios legítimos observados durante la
captura, no víctimas ni atacantes, y no hay ningún atributo que las vincule a una
persona concreta.

**Decisión: se dejan como están.** Estos archivos están publicados desde
commits anteriores, y el criterio que se aplica a `intrusiones.db` (no publicar
IPs de terceros) se adoptó **después**. Reescribir archivos ya publicados deja
constancia en el historial de Git de que la información estuvo expuesta, y un
historial alterado es peor evidencia que un dato público ya publicado.

Este párrafo es el registro de que el hallazgo se detectó, se evaluó y se
resolvió conscientemente.

## 3. Credenciales — NO se publican

| Archivo | Contenido |
|---|---|
| `config/mikrotik_lab.json` | usuario y contraseña reales del CHR del laboratorio |
| `_lab/nodos.json` | posibles contraseñas propias por nodo |
| `_lab/alpine.json` | parámetros de aprovisionamiento de las VMs Alpine |

Plantillas publicables en su lugar: `config/mikrotik_lab.json.example` y
`_lab/nodos.json.example`.

## 4. Integrity de los sellos

Los archivos `*.sha256` de `logs_ciberseguridad/` **contienen sumas SHA-512**, no
SHA-256, pese a la extensión: lo produce `log_exporter.py:173`
(`hashlib.sha512()`). Verifican con `sha512sum`.

Estado tras el commit `[20]`:

| Sello | `.log` en el repo | Verificable tras `git clone` |
|---|---|---|
| semana `2026-09-04 al 2026-09-11` | no | **no** |
| semana `2026-09-15 al 2026-09-22` | no | **no** |
| semana `2026-09-24 al 2026-10-01` | no | **no** |
| semana `2026-08-25 al 2026-09-01` | no | no, y además su sello no coincide con el `.log` local |
| semanas `2026-08-24`, `2026-08-26`, `2026-08-28`, `2026-08-30`, `2026-09-01` | no | no, el `.log` ya no existe en la máquina |

Los 9 `.sha256` siguen versionados, así que se conserva la constancia de qué
semana fue sellada y con qué valor. Pero al no publicar los `.log`, **ninguno de
los 9 puede verificarse por un tercero**: la cadena de custodia queda
incompleta. Es preferible a publicar los `.log` con sus IPs, y a que la tabla
de integridad aparente no se correspondiera con la realidad.

Verificación local, contra la copia de trabajo (no contra el repositorio):

| Semana | Sello SHA-512 | Resultado |
|---|---|---|
| `2026-09-04 al 2026-09-11` | declarado en el `.sha256` | **verifica** |
| `2026-09-15 al 2026-09-22` | declarado en el `.sha256` | **verifica** |
| `2026-09-24 al 2026-10-01` | declarado en el `.sha256` | **verifica** |
| `2026-08-25 al 2026-09-01` | declarado en el `.sha256` | **no verifica**: el `.log` cambió después de ser sellado |

> [!IMPORTANT]
> Durante la preparación de este commit se detectó y corrigió un fallo que
> habría hecho falsa esta tabla en GitHub. `core.autocrlf=true` hacía que Git
> normalizara LF↔CRLF en los `.log`, y el resultado fue que **2 de 3 sellos
> fallaban al calcularse contra el blob del índice**, es decir, contra lo que
> habría recibido un `git clone`. Se reprodujo, se añadió `-text` en
> `.gitattributes` para la evidencia y se aplicó `git add --renormalize`.
> Verificado contra los blobs, los 3 pasaron. Al no publicarse finalmente los
> `.log`, el efecto directo de la corrección es que la evidencia que sí se
> publica (los CSV) conserva sus bytes exactos, pero la investigación queda
> registrada porque el fallo es real y afectaría a cualquier archivo sellado que
> se añadiera en el futuro.


## 5. Evidencia citada que ya no existe

`informe_test_masivo.json` (bloque `T4`) declara como prueba un archivo en
`C:\Users\rojas\AppData\Local\Temp\ids_logs_test_lngqwc9x\logs_bloqueos.log`.
Esa carpeta temporal ya no está en la máquina. Ninguna copia disponible de
`logs_bloqueos.log` —tampoco la que está resumida en
`bloqueos_resumen.json`— es ese archivo: provienen de otra ejecución. Queda
anotado para que no se citen como respaldo del mismo resultado.

## 6. Resumen de lo publicado

| Sí se publica | No se publica | Motivo |
|---|---|---|
| `docs/lab/demo_timeline.csv` | `intrusiones.db` | IPs de terceros |
| `docs/lab/intrusiones_resumen.json` | `logs_bloqueos.log` | mismos datos que el `.db`, en texto plano |
| `docs/lab/bloqueos_resumen.json` | `logs_ciberseguridad/*.log` | IPs de terceros |
| `datasets/SQLi_Zenodo/D2_test.csv` | `config/mikrotik_lab.json` | credenciales |
| `Captura_Linea_Base/captura_volumen_0911.csv` | `_lab/nodos.json` | credenciales |
| `logs_ciberseguridad/*.sha256` (9) | `_lab/alpine.json` | parámetros de VM |
| `evidencia/*.csv` y `*.png` (preexistentes) | discos `.vmdk`, `.iso`, `_lab/vms/` | ~822 MB, regenerables |

Sobre `D2_test.csv`: contiene IPs públicas, pero son **direcciones del propio
dataset académico publicado** (Zenodo 6907252), no datos de terceros del autor.
El criterio no las excluye: son el objeto de estudio y sin ellas no hay
reproducibilidad de las métricas de SQLiGuard.

