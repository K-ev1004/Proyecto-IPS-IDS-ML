"""
generador_dataset_global.py — Pipeline unificado de datasets (CIC 2017 + 2018 + 2019)
Objetivo: Producir un dataset de alta calidad, balanceado (downsampling masivos),
conteniendo las 23 características del modelo v4.
Para el IDS/IPS de la Universidad UNIPAZ
"""
import pandas as pd
import numpy as np
import os
import gc
from tqdm import tqdm

# ============================================================
# CONFIGURACIÓN
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
DIR_2017 = os.path.join(DATASETS_DIR, "CIC-IDS2017")
DIR_2018 = os.path.join(DATASETS_DIR, "CSE-CIC-IDS2018")
DIR_2019 = os.path.join(DATASETS_DIR, "CIC-DDoS2019")
OUTPUT_DIR = os.path.join(BASE_DIR, "Dataset_Limpio")
os.makedirs(OUTPUT_DIR, exist_ok=True)

RANDOM_STATE = 42

# ---- V6 (M1): features nuevas que SÍ existen en los CSV de CIC -------------
# - flow_iat_mean/std, init_win_bytes: mismas magnitudes que FlowTracker v6
#   (flujos_red.py) para paridad entrena-en-vivo.
# - Active/Idle: solo existen en CIC (FlowTracker v6 no las calcula en vivo);
#   quedan en el dataset para el ablation, marcadas CIC-only.
# - NO se inventan: dir_init real, unipaz_src/dst y src_port_svc NO existen en
#   los CSV (solo traen puerto destino); llegan con el tráfico real de la fase
#   sombra (M5) para el fine-tuning. docs/ML_V6_DESARROLLO.md §4.4.
FEATURES_V6_EXTRA = ['Flow IAT Mean', 'Flow IAT Std', 'Active Mean',
                     'Active Std', 'Idle Mean', 'Idle Std']

# Columnas de window: nombre distinto por fuente; ambas son la window TCP del
# flujo forward (el que inicia), equivalente a init_win_bytes del tracker v6.
RENOMBRES_WINDOW = ['Init Fwd Win Byts', 'Init_Win_bytes_forward']

# Puertos de servicio (igual que flujos_red.py/ clasificar_c3.py): base de la
# feature DERIVADA dst_port_svc, determinista desde Dst Port.
PUERTOS_SERVICIO = {20, 21, 22, 23, 25, 53, 69, 80, 110, 123, 143, 443, 445,
                    465, 587, 993, 995, 3306, 3389, 5223, 5228, 7680, 8080,
                    8443}

FEATURES_V4 = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 
    'ACK Flag Cnt', 'URG Flag Cnt'
]

MAPEO_CLASES = {
    'BENIGN': 'Normal',
    'Benign': 'Normal',
    'PortScan': 'Port_Scanner',
    'DoS slowloris': 'SYN_Flood',
    'DoS attacks-Slowloris': 'SYN_Flood',
    'DoS Slowhttptest': 'SYN_Flood',
    'DoS attacks-SlowHTTPTest': 'SYN_Flood',
    'DoS Hulk': 'SYN_Flood',
    'DoS attacks-Hulk': 'SYN_Flood',
    'DoS GoldenEye': 'SYN_Flood',
    'DoS attacks-GoldenEye': 'SYN_Flood',
    'DoS': 'UDP_Flood',
    'DDOS attack-LOIC-UDP': 'UDP_Flood',
    'DDoS': 'DDoS_Distribuido',
    'DDOS attack-HOIC': 'DDoS_Distribuido',
    'DDoS attacks-LOIC-HTTP': 'DDoS_Distribuido',
    'Bot': 'DDoS_Distribuido',
    'LDAP': 'DDoS_Distribuido',
    'MSSQL': 'DDoS_Distribuido',
    'NetBIOS': 'DDoS_Distribuido',
    'Portmap': 'DDoS_Distribuido',
    'Syn': 'SYN_Flood',
    'UDP': 'UDP_Flood',
    'UDPLag': 'UDP_Flood',
    'Brute Force': 'Posible_Exploit',
    'FTP-Patator': 'Posible_Exploit',
    'SSH-Patator': 'Posible_Exploit',
    'FTP-BruteForce': 'Posible_Exploit',
    'SSH-Bruteforce': 'Posible_Exploit',
    'Infiltration': 'Posible_Exploit',
    'Infilteration': 'Posible_Exploit',
    'Heartbleed': 'Posible_Exploit',
    'Web Attack - Sql Injection': 'Inyeccion_SQL',
    'SQL Injection': 'Inyeccion_SQL',
    'Web Attack - XSS': 'Inyeccion_SQL',
    'Brute Force -XSS': 'Inyeccion_SQL',
    'Web Attack - Brute Force': 'Inyeccion_SQL',
    'Brute Force -Web': 'Inyeccion_SQL',
    'Web Attack \u2013 Brute Force': 'Inyeccion_SQL',
    'Web Attack \u2013 XSS': 'Inyeccion_SQL',
    'Web Attack \u2013 Sql Injection': 'Inyeccion_SQL',
}

LIMITES_CLASE = {
    'Normal': 1_500_000,
    'DDoS_Distribuido': 1_000_000,
    'SYN_Flood': 500_000,
    'UDP_Flood': 500_000,
    'Port_Scanner': None,
    'Posible_Exploit': None,
    'Inyeccion_SQL': None
}

def normalizar_columnas(df):
    df.columns = df.columns.str.strip()
    return df

# Carácter de reemplazo (U+FFFD) que aparece corrupto en algunos CSVs de 2017
# y que impide mapear correctamente los ataques web (Web Attack � XSS, etc.)
_replace_caracter = {'\ufffd': '-', '\u2013': '-', '\u2014': '-'}

def _normalizar_label(valor):
    if not isinstance(valor, str):
        return valor
    for origen, destino in _replace_caracter.items():
        if origen in valor:
            valor = valor.replace(origen, destino)
    return valor

def procesar_chunk(chunk):
    chunk = normalizar_columnas(chunk)
    if 'Destination Port' in chunk.columns:
        chunk = chunk.rename(columns={'Destination Port': 'Dst Port'})
    # V6: unificar el nombre de la window TCP forward entre 2017 y 2018
    for col_win in RENOMBRES_WINDOW:
        if col_win in chunk.columns:
            chunk = chunk.rename(columns={col_win: 'init_win_bytes'})
    
    if 'Label' in chunk.columns:
        chunk = chunk[chunk['Label'] != 'Label']
        # Normalizar caracteres corruptos (U+FFFD, guiones) antes del mapeo
        chunk['Label'] = chunk['Label'].map(_normalizar_label)
        chunk['Label_UNIPAZ'] = chunk['Label'].map(MAPEO_CLASES)
        chunk = chunk.dropna(subset=['Label_UNIPAZ'])
        
        for f in FEATURES_V4 + FEATURES_V6_EXTRA + ['init_win_bytes']:
            if f not in chunk.columns:
                chunk[f] = 0

        chunk = chunk[FEATURES_V4 + FEATURES_V6_EXTRA
                      + ['init_win_bytes', 'Label_UNIPAZ']]
        # Coaccionar ANTES de las derivadas: los CSV de CIC traen filas de
        # cabecera repetida que dejan la columna object y un '<' entre str
        # e int revienta el chunk entero (02-16/02-28/03-01 en la v1 de M1).
        for col in FEATURES_V4 + FEATURES_V6_EXTRA + ['init_win_bytes']:
            chunk[col] = pd.to_numeric(chunk[col], errors='coerce')

        # ---- V6: features DERIVADAS (deterministas, paridad con el tracker) ----
        # dst_port_svc: puerto de servicio visto como destino (NaN -> False -> 0)
        chunk['dst_port_svc'] = (
            (chunk['Dst Port'] < 1024)
            | chunk['Dst Port'].isin(PUERTOS_SERVICIO)).astype('float64')
        # fwd_bwd_ratio: dirección de paquetes (el defecto nº 1 era no tenerla)
        chunk['fwd_bwd_ratio'] = (
            chunk['Tot Fwd Pkts'] / chunk['Tot Bwd Pkts'].clip(lower=1))
        # bytes_per_pkt: tamaño medio por paquete del flujo
        chunk['bytes_per_pkt'] = (
            (chunk['TotLen Fwd Pkts'] + chunk['TotLen Bwd Pkts'])
            / (chunk['Tot Fwd Pkts'] + chunk['Tot Bwd Pkts']).clip(lower=1))

        return chunk
    return pd.DataFrame()

def procesar_carpeta(carpeta_path, origen_nombre):
    print(f"\n[*] Procesando dataset: {origen_nombre} ({carpeta_path})")

    if not os.path.exists(carpeta_path):
        print(f"  [!] La carpeta {carpeta_path} no existe. Saltando...")
        return pd.DataFrame()
        
    archivos = [f for f in os.listdir(carpeta_path) if f.endswith('.csv') or f.endswith('.parquet')]
    chunks_procesados = []
    
    posibles_features = (FEATURES_V4 + FEATURES_V6_EXTRA + ['init_win_bytes']
                         + RENOMBRES_WINDOW + ['Label', 'Destination Port'])
    
    for archivo in tqdm(archivos, desc=f"Procesando {origen_nombre}", unit="archivo", ncols=100):
        ruta = os.path.join(carpeta_path, archivo)
        print(f"    -> Leyendo: {archivo}")
        
        try:
            if archivo.endswith('.parquet'):
                # Los parquets se pueden cargar enteros porque son comprimidos y más pequeños
                chunk = pd.read_parquet(ruta)
                chunk_proc = procesar_chunk(chunk)
                if not chunk_proc.empty:
                    chunks_procesados.append(chunk_proc)
            else:
                # CSV
                header = pd.read_csv(ruta, nrows=0)
                # Seleccionar columnas que tras hacer strip() sean válidas
                cols_a_leer = [c for c in header.columns if c.strip() in posibles_features]
                
                for chunk in tqdm(pd.read_csv(ruta, usecols=cols_a_leer, chunksize=250000, low_memory=False),
                                  desc=f"    chunk {archivo}", unit="chunk", ncols=100, leave=False):
                    chunk_proc = procesar_chunk(chunk)
                    if not chunk_proc.empty:
                        chunks_procesados.append(chunk_proc)
                
        except Exception as e:
            print(f"      [ERROR] Falló procesamiento de {archivo}: {e}")
            
    if not chunks_procesados:
        return pd.DataFrame()
        
    df_consolidado = pd.concat(chunks_procesados, ignore_index=True)
    # V6: columna 'fuente' para el holdout por origen del protocolo de
    # evaluacion (entrenar 2018->validar 2017 y viceversa, docs §6.2).
    df_consolidado['fuente'] = origen_nombre
    del chunks_procesados
    gc.collect()
    
    print(f"  Total {origen_nombre} procesado: {len(df_consolidado):,} registros.")
    return df_consolidado

def aplicar_downsampling(df):
    print("\n[*] Aplicando Downsampling Inteligente...")
    df_final_chunks = []
    
    clases = sorted(df['Label_UNIPAZ'].unique())
    
    for clase in tqdm(clases, desc="Balanceando clases", unit="clase", ncols=100):
        subset = df[df['Label_UNIPAZ'] == clase]
        limite = LIMITES_CLASE.get(clase)
        
        if limite is not None and len(subset) > limite:
            print(f"    - {clase}: Reduciendo de {len(subset):,} a {limite:,}")
            subset = subset.sample(n=limite, random_state=RANDOM_STATE)
        else:
            print(f"    - {clase}: Preservando {len(subset):,} registros (sin recorte)")
            
        df_final_chunks.append(subset)
        
    return pd.concat(df_final_chunks, ignore_index=True)

if __name__ == "__main__":
    print("======================================================")
    print(" GENERADOR DE DATASET GLOBAL v6 (CIC 2017+2018+2019)")
    print("  24 features v4 + IAT/Window/Active/Idle + 3 derivadas v6")
    print("  (dir_init real y unipaz_src/dst NO van: no existen en CIC;")
    print("   llegan del trafico real en la fase sombra M5)")
    print("======================================================")
    
    df_2017 = procesar_carpeta(DIR_2017, "CIC-IDS2017")
    df_2018 = procesar_carpeta(DIR_2018, "CSE-CIC-IDS2018")
    df_2019 = procesar_carpeta(DIR_2019, "CIC-DDoS2019")
    
    print("\n[*] Fusionando datasets...")
    df_total = pd.concat([df_2017, df_2018, df_2019], ignore_index=True)
    
    del df_2017, df_2018, df_2019
    gc.collect()
    
    print(f"    Total bruto fusionado: {len(df_total):,} registros.")
    
    df_total.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_total = df_total.fillna(0)
    
    df_total = aplicar_downsampling(df_total)
    df_total = df_total.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    
    ruta_csv = os.path.join(OUTPUT_DIR, "dataset_global_unipaz_v6.csv")
    print(f"\n[*] Guardando dataset definitivo en: {ruta_csv}")
    df_total.to_csv(ruta_csv, index=False)
    
    print("\n======================================================")
    print(" RESUMEN FINAL DEL DATASET v6")
    print("======================================================")
    resumen = df_total['Label_UNIPAZ'].value_counts()
    print(resumen)
    sql = resumen.get('Inyeccion_SQL', 0)
    print(f"\n  [!] Inyeccion_SQL en v6: {sql:,}")
    print(f"\n  Features del dataset v6: {len(df_total.columns) - 1}")
    print("\n  [OK] Dataset global v6 generado. Listo para el entrenamiento M3.")
