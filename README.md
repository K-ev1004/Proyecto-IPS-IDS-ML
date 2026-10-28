# IPS-IDBS-ML · Sistema IDS/IPS con Machine Learning (UNIPAZ)

Sistema **híbrido de Detección y Prevención de Intrusiones (IDS/IPS)** basado en Machine
Learning para la red del Instituto Universitario de la Paz (UNIPAZ). Combina **captura en
tiempo real** (Scapy + Npcap), **detección heurística**, **clasificación por CatBoost v5**,
una **capa dedicada de confirmación de Inyección SQL (SQLiGuard)** y **respuesta activa IPS**
(bloqueo en MikroTik), con dashboard SOC en PyQt5 y alertas por Telegram.

> Entorno objetivo: **Windows** (24/7), presupuesto **cero**, 100% software libre.

---

## ⚡ Características

- 🕵️ Captura pasiva de paquetes en tiempo real (modo SPAN / port mirror) con `Scapy` + `Npcap`.
- 🧠 **CatBoost v5** (multiclase, 7 clases UNIPAZ) sobre flujos bidireccionales CIC-style.
- 💉 **SQLiGuard**: detector binario dedicado de Inyección SQL entrenado con ~230 K SQLi reales
  (Zenodo 6907252) → precisión **~99.8 %** sobre test externo independiente.
- ⚖️ Heurística de respaldo con **evidencia auditable** (`n_puertos`, `n_destinos`, `ventana_s`,
  `umbral` en cada fila): escaneo de puertos por ventana deslizante `(origen, destino)`,
  barrido horizontal, SYN/UDP flood (solo SYN sin ACK), exploit y SQLi regex (solo candidatos:
  SQLiGuard es el árbitro).
- 🕯️ **Modo observación por defecto**: registra candidatos sin alertar ni bloquear (calibración
  por percentiles antes de abrir alertas).
- 🛡️ IPS activo: bloqueo automático o semi-autónomo vía SSH a MikroTik (RouterOS).
- 📊 Dashboard SOC (PyQt5 + Fluent) con eventos, tráfico, gráficos y umbrales ajustables en vivo.
- 🔔 Alertas por Telegram + logs semanales + trazabilidad SQLite (`confianza_ml`, `features_json`,
  `evidencia_json`, `run_id`, `version_motor`).

## 📦 Requisitos previos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Windows 10/11 (objetivo de despliegue; Linux compatible en gran parte) |
| Python | 3.10+ (64 bits) |
| Npcap | Driver de captura (instalado con permisos de administrador) |
| GPU (opcional) | NVIDIA + CUDA para entrenamiento con `task_type='GPU'` |
| Acceso red | Puerto espejo/SPAN en el switch para capturar tráfico clonado |

## 🚀 Instalación rápida

```powershell
# 1. Clonar (incluye modelos subidos con Git LFS)
git clone https://github.com/K-ev1004/Proyecto-IPS-IDBS-ML.git
cd Proyecto-IPS-IDBS-ML

# 2. (Recomendado) Entorno virtual
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Verificar que el driver de captura esté disponible
Get-Process -Name npcap* -ErrorAction SilentlyContinue   # o: sc query npcap
```

> [!NOTE]
> Si el modelo `.pkl` no se descargó con el clon, ejecutar `git lfs pull` (los artefactos
> `v5` y `SQLiGuard` están en `Modelos_Entrenados/` via Git LFS).

## ⚙️ Configuración (variables de entorno)

| Variable | Uso | Obligatoria |
|---|---|---|
| `LOG_FOLDER` | Carpeta donde se escriben los logs semanales y de bloqueo (def. `D:\logs_ciberseguridad` o `logs_ciberseguridad/`) | No |
| `TELEGRAM_BOT_TOKEN` | Token del bot de Telegram (ver `telegram_alert.py`) | Solo si se usan alertas |
| `TELEGRAM_CHAT_IDS` | IDs de chat destino (separados por coma) | Solo si se usan alertas |
| `MIKROTIK_IP` / `MIKROTIK_USER` / `MIKROTIK_PASS` | Credenciales del router para bloqueo IPS | Solo modo autónomo |
| `IDS_MODO_OBSERVACION` | `1` (defecto): persiste candidatos sin alertar ni bloquear. `0`: alerta (y bloquea si aplica) | No |
| `IDS_DB_PATH` | Ruta de la base SQLite (def. `intrusiones_v5.db`) | No |
| `IDS_RUN_ID` | Etiqueta de la corrida (def. `run-<fecha>-<hora>`) | No |
| `IDS_SCAN_THRESHOLD` / `IDS_SCAN_THRESHOLD_INT` | Umbral de escaneo externo/interno (puertos distintos a un destino) | No |
| `IDS_SCAN_WINDOW` / `IDS_SCAN_COOLDOWN` / `IDS_SCAN_MIN_DST` | Ventana (s), enfriamiento por pareja (s) y destinos mínimos del barrido horizontal | No |
| `IDS_HOSTS_GESTION` | IPs de gestión/monitorización exentas del detector de exploit | No |
| `IDS_IPS_AUTONOMO` | `1`: bloqueo autónomo vía MikroTik; `0` (defecto): semi-autónomo | No |

> [!CAUTION]
> Las credenciales están **hardcodeadas** en `telegram_alert.py` y `mikrotik_api.py`
> (¡no commitear tokens reales!). Está previsto migrarlas a variables de entorno.

## 🧭 Comandos principales

```powershell
# GUI (recomendado)
python interfasc.py

# Motor IDS/IPS standalone (10 s de captura de prueba)
python ids.py

# Reconstruir dataset global v5 (CIC-IDS2017 + 2018 + DDoS2019)
python generador_dataset_global.py

# Entrenar modelo multiclase v5 (GPU) → Modelos_Entrenados/*v5*
python CEREBRO_V5.py

# Entrenar SQLiGuard (detector binario SQLi)
python entrenar_sqli_guard.py

# Batería de pruebas masivas (datasets sintéticos + trazabilidad)
python test_masivo.py

# Pruebas unitarias del motor (paquetes sintéticos, sin red)
.\venv\Scripts\python.exe -m pytest tests/ -v

# Backup diario comprimido + purga de eventos > 90 días
python scripts/backup_bd.py

# Calibrar umbrales de escaneo tras la ventana de observación
python scripts/calibrar_escaneo.py --horas 72

# Analizar el post-mortem de la v1 (y generar copia anonimizada)
python scripts/analizar_produccion.py --anonimizar evidencia/corpus_anon.csv

# Exportar logs semanales
python log_exporter.py
```

## 🏗️ Arquitectura

```mermaid
flowchart TD
    subgraph Captura["Captura en tiempo real (Scapy + Npcap)"]
        P[Paquete de red] --> M[procesar_metricas<br/>VLAN 802.1Q / EWMA]
    end

    P --> H[Heurística de respaldo<br/>SYN/UDP flood · DDoS · port scan<br/>exploit · SQLi regex]
    P --> F[FlowTracker<br/>flujos bidireccionales 5s]

    F --> V5[CatBoost v5 multiclase<br/>7 clases UNIPAZ]
    V5 --> G[SQLiGuard<br/>detector binario SQLi<br/>umbral 0.30]
    V5 --> D[Decisión ML<br/>confianza ≥ 0.85]

    H --> A[guardar_ataque v5<br/>persiste SIEMPRE<br/>throttle solo notifica]
    G --> A
    D --> A

    A --> DB[(SQLite v5<br/>ataques + bloqueos<br/>evidencia_json · modo · run_id)]
    A --> TG[Telegram alert]
    A --> IPS{IPS activo}
    IPS -->|modo autónomo| MK[Bloqueo MikroTik<br/>SSH RouterOS]
    IPS -->|semi-autónomo| AL[Alerta solamente]
    MK --> LG[(Logs semanales<br/>log_exporter)]
    DB --> GUI[Dashboard SOC<br/>interfasc.py · PyQt5 Fluent]
    TG --> GUI
```

### Flujo de decisión ML (v5 + SQLiGuard)

1. El flujo completo genera features CIC-style → `pipeline_catboost_v5.pkl` predice la clase.
2. **SQLiGuard** (features NetFlow) confirma o descarta `Inyeccion_SQL`:
   - Si `P(SQLi) ≥ UMBRAL_SQLI_GUARD (0.30)` → se registra como `Inyeccion_SQL` (alta precisión).
   - Si v5 decía SQLi pero SQLiGuard no confirma → no se loguea (reduce falsos positivos).
3. Para el resto de clases se exige `confianza_ml ≥ UMBRAL_ML (0.85)` para loguear y bloquear.

## 📁 Estructura del repositorio

```
.
├── interfasc.py                 # GUI (dashboard SOC PyQt5 Fluent)
├── ids.py                       # Motor principal IDS/IPS (captura, ML, respuesta activa)
├── flujos_red.py                # FlowTracker: flujos bidireccionales y features
├── mikrotik_api.py              # Bloqueo IPS vía SSH a RouterOS
├── telegram_alert.py            # Alertas Telegram
├── log_exporter.py              # Logs semanales y registro de bloqueos
├── generador_dataset_global.py  # Pipeline de datos (CIC 2017+2018+2019) → v5
├── CEREBRO_V5.py                # Entrenamiento CatBoost v5
├── entrenar_sqli_guard.py       # Entrenamiento SQLiGuard
├── test_masivo.py               # Batería de pruebas end-to-end
├── tests/                       # Pruebas unitarias del motor (scapy sintético)
├── scripts/                     # backup_bd, archivar_bd, calibrar, post-mortem
├── evidencia/                   # Exportaciones, corpus anonimizado y hashes
├── requirements.txt
├── .gitattributes               # Git LFS para *.pkl
├── scripts/legacy/              # Scripts históricos v2/v3 (conservados como evidencia)
├── Modelos_Entrenados/          # Artefactos v5 + SQLiGuard (Git LFS)
├── datasets/                    # Datasets crudos (ignorados en git)
├── Dataset_Limpio/              # Dataset global v5 (ignorado)
├── docs/                        # → Documentación (este proyecto)
│   ├── academico/               # Tesis, anteproyecto e imágenes (docx/pdf/xlsx/tex)
│   ├── adr/                     # Registros de decisiones (ADRs)
│   ├── guias/                   # Guías de instalación, uso y entrenamiento
│   ├── ml/                      # Análisis ML (algunos históricos)
│   ├── lab/                     # Laboratorio virtual: evidencia T5 (CHR real)
│   ├── red/                     # Arquitectura de red UNIPAZ
│   ├── tesis/                   # Capítulos y anteproyecto (académico)
│   └── CHANGELOG.md             # Historial de cambios del sistema
└── (LICENSE)                    # Pendiente de definir licencia
```

## 📚 Documentación

| Sección | Contenido |
|---|---|
| [Guias](./docs/guias/) | Instalación, uso de la GUI y entrenamiento de modelos |
| [ADRs](./docs/adr/) | Decisiones de arquitectura (v5, SQLiGuard, Git LFS) |
| [ML](./docs/ml/) | Análisis técnico y viabilidad de datasets |
| [Laboratorio](./docs/lab/) | Laboratorio virtual (RouterOS CHR), T5 y [demo en vivo](./docs/lab/demo-bloqueo.md) |
| [Plan de lanzamiento v5](./docs/PLAN_LANZAMIENTO_V5.md) | Post-mortem de la v1, esquema v5, fases y criterios de aceptación |
| [Red UNIPAZ](./docs/red/) | Topología de red y plan de despliegue |
| [Tesis](./docs/tesis/) | Anteproyecto y capítulos académicos |
| [CHANGELOG](./docs/CHANGELOG.md) | Historial de cambios verificados |

## ✅ Estado del proyecto

- Modelo **v5** en producción: acc 0.8641 · F1-macro 0.7442 · Kappa 0.8138.
- **SQLiGuard**: precisión 99.85 % · recall 75 % (umbral 0.30) en test externo (D2).
- Umbrales unificados: logueo y bloqueo ML con `UMBRAL_ML = 0.85`.
- **Motor v5 (2026-10)**: esquema con evidencia completa, detector de escaneo por ventana
  `(origen, destino)`, modo observación por defecto; lanzamiento de nueva producción en curso
  (ver [plan de lanzamiento](./docs/PLAN_LANZAMIENTO_V5.md)).
- Ver `docs/CHANGELOG.md` para el detalle completo.

---

*Proyecto académico · Instituto Universitario de la Paz (UNIPAZ) · Ingeniería de Sistemas*
