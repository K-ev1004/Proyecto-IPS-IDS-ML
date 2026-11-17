# -*- coding: utf-8 -*-
"""
verificar_entorno.py — Chequeo de salud del kit portable de Windows.

NO lanza el motor, NO abre la GUI y NO inicia la captura. Solo lee archivos
y comprueba que los imports y los modelos esten disponibles. Lo invoca
`scripts/verificar_windows.bat`, y tambien se puede ejecutar a mano:

    .venv\\Scripts\\python.exe scripts\\verificar_entorno.py

Sale con codigo 0 si todo esta bien, 1 si falta algo critico.
"""

import importlib
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELOS = os.path.join(BASE_DIR, "Modelos_Entrenados")

# Artefactos que ids.py carga en el arranque (v5 + v6). Si falta uno, el motor
# degrada a heuristicas o a v5; por eso se marcan como criticos.
CRITICOS = [
    ("pipeline_catboost_v5.pkl", "CatBoost v5 (motor de produccion)"),
    ("selected_features_v5.pkl", "features del modelo v5"),
    ("label_encoder_v5.pkl", "etiquetas del modelo v5"),
    ("sqli_guard.pkl", "SQLiGuard (confirmacion de SQLi)"),
    ("sql_guard_features.pkl", "features de SQLiGuard"),
    ("pipeline_catboost_v6.pkl", "CatBoost v6 (laboratorio)"),
    ("features_v6.pkl", "features del modelo v6"),
    ("umbrales_v6.pkl", "umbrales por clase del v6"),
    ("sqli_payload.pkl", "detector de payload v6"),
]
OPCIONALES = [
    ("label_encoder_v6.pkl", "etiquetas del modelo v6"),
]
IMPORTACIONES = [
    "scapy", "catboost", "pandas", "numpy", "sklearn", "joblib",
    "requests", "paramiko", "PyQt5", "qfluentwidgets",
]
PUNTERO_LFS = b"version https://git-lfs.github.com/spec/v1"


def titulo(texto):
    print("\n" + "=" * 72)
    print(texto)
    print("=" * 72)


def verificar_python():
    titulo("1) Python")
    version = sys.version.split()[0]
    bits = 64 if sys.maxsize > (2 ** 32) else 32
    print(f"[INFO] {sys.executable}")
    print(f"[INFO] Python {version} ({bits} bits)")
    fallos = 0
    if sys.version_info < (3, 10):
        print("[X] Se requiere Python 3.10 o superior (recomendado 3.12).")
        fallos += 1
    else:
        print("[OK] Version compatible.")
    if bits != 64:
        print("[X] Se requiere Python de 64 bits (CatBoost/pandas no tienen "
              "wheels de 32 bits).")
        fallos += 1
    else:
        print("[OK] Arquitectura de 64 bits.")
    return fallos


def verificar_archivos():
    titulo("2) Archivos del proyecto")
    fallos = 0
    for nombre, descripcion in [
        ("ids.py", "motor IDS/IPS"),
        ("interfasc.py", "GUI"),
        ("config/politica_bloqueo.json", "matriz de decision M4/M6"),
        ("requirements-windows.txt", "dependencias del kit Windows"),
    ]:
        ruta = os.path.join(BASE_DIR, nombre)
        if os.path.isfile(ruta):
            print(f"[OK] {nombre} ({descripcion})")
        else:
            print(f"[X] Falta {nombre} ({descripcion})")
            fallos += 1
    return fallos


def verificar_modelos():
    titulo("3) Modelos (Git LFS)")
    fallos = 0
    if not os.path.isdir(MODELOS):
        print(f"[X] No existe {MODELOS}")
        return 1
    for nombre, descripcion in CRITICOS + OPCIONALES:
        ruta = os.path.join(MODELOS, nombre)
        critico = (nombre, descripcion) in CRITICOS
        if not os.path.isfile(ruta):
            print(f"[X] {nombre}: FALTA ({descripcion})")
            fallos += 1 if critico else 0
            continue
        tamano = os.path.getsize(ruta)
        with open(ruta, "rb") as archivo:
            cabecera = archivo.read(len(PUNTERO_LFS))
        if cabecera == PUNTERO_LFS:
            print(f"[X] {nombre}: es un PUNTERO LFS, no el modelo real.")
            print(f"    Solucion: git lfs install --local && git lfs pull")
            fallos += 1 if critico else 0
            continue
        print(f"[OK] {nombre}: {tamano / (1024 * 1024):.1f} MB "
              f"({descripcion})")
    return fallos


def verificar_imports():
    titulo("4) Dependencias Python")
    fallos = 0
    for modulo in IMPORTACIONES:
        try:
            objeto = importlib.import_module(modulo)
            detalle = getattr(objeto, "__version__", "")
            sufijo = f" {detalle}" if detalle else ""
            print(f"[OK] {modulo}{sufijo}")
        except Exception as error:
            print(f"[X] {modulo}: {error}")
            fallos += 1
    return fallos


def main():
    print("Chequeo de salud del kit portable (no inicia el sensor)")
    fallos = (verificar_python()
              + verificar_archivos()
              + verificar_modelos()
              + verificar_imports())
    titulo("RESULTADO")
    if fallos:
        print(f"[X] {fallos} problema(s) detectado(s). No arranques el sensor "
              "hasta corregirlos.")
        return 1
    print("[OK] Entorno listo: dependencias y modelos presentes.")
    print("[OK] El sensor NO ha sido lanzado por esta verificacion.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
