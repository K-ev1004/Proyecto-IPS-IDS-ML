# flujos_red.py — Motor de Extracción de Flujos en Tiempo Real (V6)
# Universidad UNIPAZ
# =============================================================================
# Propósito: Agrupa paquetes individuales de Scapy en "Flujos Bidireccionales"
# y calcula en vivo las características estadísticas que necesita el modelo
# entrenado con CSE-CIC-IDS2018 (NetFlow-like features).
#
# V6 (M1 de docs/PLAN_ML_V6.md) — features direccionales que corrigen el
# defecto nº 1 del diagnóstico C3 (flujo sin dirección):
#   - dir_init: dirección real por SYN de inicio (1=iniciador, 0=respondió,
#     -1=desconocida). Si el primer paquete no es SYN puro, NO se inventa.
#   - init_win_bytes: TCP window del SYN de inicio (huella del sistema/stack).
#   - dst_port_svc / src_port_svc: contexto de servicio vs puerto efímero.
#   - unipaz_src / unipaz_dst: segmento de origen/destino (172.10/20/30).
#   - fwd_bwd_ratio, bytes_per_pkt, flow_iat_mean/std, pkt_dir_changes.
# Las 24 features v5 quedan INTACTAS (mismos nombres): los modelos v5 siguen
# cargando leyendo solo sus features_seleccionadas (compatibilidad hacia atrás).
# =============================================================================

import time
import ipaddress
from collections import defaultdict
import numpy as np

# Tiempo máximo de inactividad antes de considerar un flujo como "Terminado" y predecirlo
FLOW_TIMEOUT = 5.0 # Segundos

# Puertos de servicio conocidos (los mismos que usa el rescate C3 en
# scripts/clasificar_c3.py): un puerto < 1024 o de esta lista visto como
# DELTA delata tráfico de retorno, no un ataque entrante.
PUERTOS_SERVICIO = {20, 21, 22, 23, 25, 53, 69, 80, 110, 123, 143, 443, 445,
                    465, 587, 993, 995, 3306, 3389, 5223, 5228, 7680, 8080,
                    8443}

# Segmentos UNIPAZ (igual que REDES_UNIPAZ en ids.py: se duplica aquí porque
# flujos_red no puede importar ids — ids importa flujos_red).
REDES_UNIPAZ = [
    ipaddress.ip_network('172.10.0.0/16'),
    ipaddress.ip_network('172.20.0.0/16'),
    ipaddress.ip_network('172.30.0.0/16'),
]


def _es_ip_interna(ip):
    """True si la IP pertenece a la red UNIPAZ o a un rango privado
    (misma lógica que ids._es_ip_interna)."""
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return a.is_private or any(a in red for red in REDES_UNIPAZ)


class FlujoBidireccional:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocolo, timestamp,
                 tcp_flags=None, tcp_window=None):
        # 5-Tuple (La clave de dirección Forward = PRIMER paquete visto)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocolo = protocolo

        # Tiempos
        self.start_time = timestamp
        self.last_time = timestamp

        # Paquetes y Bytes (Forward)
        self.fwd_pkts = 0
        self.fwd_bytes = 0
        self.fwd_pkt_lens = []

        # Paquetes y Bytes (Backward)
        self.bwd_pkts = 0
        self.bwd_bytes = 0
        self.bwd_pkt_lens = []

        # Flags (combinados o específicos si es TCP)
        self.fin_flag_cnt = 0
        self.syn_flag_cnt = 0
        self.rst_flag_cnt = 0
        self.psh_flag_cnt = 0
        self.ack_flag_cnt = 0
        self.urg_flag_cnt = 0

        # ---- V6: dirección real y contexto --------------------------------
        # Dirección del iniciador, solo si el primer paquete es SYN puro
        # (SYN sin ACK). Si no, se marca desconocida: no se inventa.
        self.iniciador_ip = None
        self.dir_desconocida = True
        if tcp_flags and 'S' in tcp_flags and 'A' not in tcp_flags:
            self.iniciador_ip = src_ip
            self.dir_desconocida = False
        # TCP window del SYN de inicio (0 si no hay SYN o es UDP)
        self.init_win_bytes = 0
        if not self.dir_desconocida and tcp_window:
            self.init_win_bytes = int(tcp_window)

        # V6: estadísticas por paquete
        self.iats_ms = []          # intervalos entre paquetes (ms, ambas dir.)
        self.ultima_direccion = None
        self.dir_changes = 0       # cambios de dirección (ping-pong)

    def add_packet(self, packet_len, timestamp, is_forward, tcp_flags=None,
                   tcp_window=None):
        # V6: IAT antes de actualizar last_time. El primer paquete no tiene
        # intervalo (no hay paquete previo).
        if (self.fwd_pkts + self.bwd_pkts) > 0:
            delta_ms = (float(timestamp) - float(self.last_time)) * 1000.0
            if delta_ms >= 0:
                self.iats_ms.append(delta_ms)
            # V6: ping-pong cliente/servidor
            if self.ultima_direccion is not None and self.ultima_direccion != is_forward:
                self.dir_changes += 1
        self.ultima_direccion = is_forward

        self.last_time = timestamp

        if is_forward:
            self.fwd_pkts += 1
            self.fwd_bytes += packet_len
            self.fwd_pkt_lens.append(packet_len)
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += packet_len
            self.bwd_pkt_lens.append(packet_len)

        if tcp_flags:
            if 'F' in tcp_flags: self.fin_flag_cnt += 1
            if 'S' in tcp_flags: self.syn_flag_cnt += 1
            if 'R' in tcp_flags: self.rst_flag_cnt += 1
            if 'P' in tcp_flags: self.psh_flag_cnt += 1
            if 'A' in tcp_flags: self.ack_flag_cnt += 1
            if 'U' in tcp_flags: self.urg_flag_cnt += 1
            # V6: window del SYN de inicio, por si el flujo arrancó antes de
            # que existiera este campo (compatibilidad con llamadas viejas).
            if (self.init_win_bytes == 0 and tcp_window
                    and 'S' in tcp_flags and 'A' not in tcp_flags
                    and not self.dir_desconocida):
                self.init_win_bytes = int(tcp_window)

    def is_expired(self, current_time):
        return (current_time - self.last_time) > FLOW_TIMEOUT

    def get_features_dict(self):
        """
        Calcula y retorna un diccionario con las características del flujo.
        Estos nombres DEBEN coincidir exactamente con los que use CEREBRO al entrenar.
        V6: devuelve las 24 features v5 + las 11 nuevas direccionales (ablation:
        el entrenamiento decide cuáles entran; nada se filtra aquí).
        """
        # Calcular duraciones
        flow_duration_sec = self.last_time - self.start_time
        # Convertir a microsegundos para coincidir con CIC-IDS2018
        flow_duration = max(1.0, flow_duration_sec * 1e6)

        total_pkts = self.fwd_pkts + self.bwd_pkts
        total_bytes = self.fwd_bytes + self.bwd_bytes

        flow_byts_s = (total_bytes / flow_duration_sec) if flow_duration_sec > 0 else 0
        flow_pkts_s = (total_pkts / flow_duration_sec) if flow_duration_sec > 0 else 0

        # Estadísticas Fwd
        fwd_pkt_len_max = max(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0
        fwd_pkt_len_min = min(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0
        fwd_pkt_len_mean = np.mean(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0
        fwd_pkt_len_std = np.std(self.fwd_pkt_lens) if len(self.fwd_pkt_lens) > 1 else 0

        # Estadísticas Bwd
        bwd_pkt_len_max = max(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0
        bwd_pkt_len_min = min(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0
        bwd_pkt_len_mean = np.mean(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0
        bwd_pkt_len_std = np.std(self.bwd_pkt_lens) if len(self.bwd_pkt_lens) > 1 else 0

        # V6: dirección real — 1 si el src del primer paquete inició, 0 si
        # respondió, -1 si se desconoce (el primer paquete no fue SYN puro).
        if self.dir_desconocida:
            dir_init = -1
        elif self.iniciador_ip == self.src_ip:
            dir_init = 1
        else:
            dir_init = 0

        # V6: IAT del flujo (ms)
        if self.iats_ms:
            iat_mean = float(np.mean(self.iats_ms))
            iat_std = float(np.std(self.iats_ms)) if len(self.iats_ms) > 1 else 0
        else:
            iat_mean = 0
            iat_std = 0

        features = {
            # ---- 24 features v5 (intactas, mismos nombres) ----
            'Src Port': self.src_port,
            'Dst Port': self.dst_port,
            'Protocol': 6 if self.protocolo == 'TCP' else (17 if self.protocolo == 'UDP' else 0),
            'Flow Duration': flow_duration,
            'Tot Fwd Pkts': self.fwd_pkts,
            'Tot Bwd Pkts': self.bwd_pkts,
            'TotLen Fwd Pkts': self.fwd_bytes,
            'TotLen Bwd Pkts': self.bwd_bytes,
            'Fwd Pkt Len Max': fwd_pkt_len_max,
            'Fwd Pkt Len Min': fwd_pkt_len_min,
            'Fwd Pkt Len Mean': fwd_pkt_len_mean,
            'Fwd Pkt Len Std': fwd_pkt_len_std,
            'Bwd Pkt Len Max': bwd_pkt_len_max,
            'Bwd Pkt Len Min': bwd_pkt_len_min,
            'Bwd Pkt Len Mean': bwd_pkt_len_mean,
            'Bwd Pkt Len Std': bwd_pkt_len_std,
            'Flow Byts/s': flow_byts_s,
            'Flow Pkts/s': flow_pkts_s,
            'FIN Flag Cnt': self.fin_flag_cnt,
            'SYN Flag Cnt': self.syn_flag_cnt,
            'RST Flag Cnt': self.rst_flag_cnt,
            'PSH Flag Cnt': self.psh_flag_cnt,
            'ACK Flag Cnt': self.ack_flag_cnt,
            'URG Flag Cnt': self.urg_flag_cnt,
            # ---- 11 features v6 (M1: direccionales y de contexto) ----
            'dir_init': dir_init,
            'dst_port_svc': 1 if (self.dst_port < 1024
                                  or self.dst_port in PUERTOS_SERVICIO) else 0,
            'src_port_svc': 1 if (self.src_port < 1024
                                  or self.src_port in PUERTOS_SERVICIO) else 0,
            'unipaz_src': 1 if _es_ip_interna(self.src_ip) else 0,
            'unipaz_dst': 1 if _es_ip_interna(self.dst_ip) else 0,
            'fwd_bwd_ratio': self.fwd_pkts / max(1, self.bwd_pkts),
            'bytes_per_pkt': total_bytes / max(1, total_pkts),
            'flow_iat_mean': iat_mean,
            'flow_iat_std': iat_std,
            'init_win_bytes': self.init_win_bytes,
            'pkt_dir_changes': self.dir_changes,
        }
        return features

class FlowTracker:
    def __init__(self, callback_prediccion):
        """
        callback_prediccion: Función a la que se le pasará el diccionario de features
        cuando un flujo esté listo para ser analizado.
        """
        self.flujos = {}
        self.callback_prediccion = callback_prediccion
        self.ultimo_chequeo = time.time()

    def procesar_paquete(self, ip_src, ip_dst, puerto_src, puerto_dst, protocolo,
                         packet_len, tcp_flags, timestamp, tcp_window=None):
        # Solo TCP/UDP con puertos válidos. ICMP/IGMP y otros protocolos no
        # tienen puertos y producían un vector de features en cero que el ML
        # clasificaba como SQLi.
        if protocolo not in ('TCP', 'UDP'):
            return
        if not (0 < puerto_src <= 65535 and 0 < puerto_dst <= 65535):
            return
        # Para identificar el flujo ignoramos la dirección inicial.
        # Ordenamos las IPs y Puertos de manera predecible para crear la clave
        if ip_src < ip_dst:
            flow_key = (ip_src, ip_dst, puerto_src, puerto_dst, protocolo)
            is_forward = True
        else:
            flow_key = (ip_dst, ip_src, puerto_dst, puerto_src, protocolo)
            is_forward = False

        if flow_key not in self.flujos:
            # Si is_forward es False en el primer paquete, la lógica técnica de CIC
            # asume que el primer paquete visto es el Fwd. Para simplificar y mantener
            # consistencia, usamos src/dst literales del primer paquete.
            # V6: se pasan tcp_flags/tcp_window para fijar la dirección REAL
            # del iniciador (solo si el primer paquete es SYN puro).
            self.flujos[flow_key] = FlujoBidireccional(
                ip_src, ip_dst, puerto_src, puerto_dst, protocolo, timestamp,
                tcp_flags=tcp_flags, tcp_window=tcp_window)

        flujo = self.flujos[flow_key]

        # Corregir is_forward relativo al flujo instanciado
        if flujo.src_ip == ip_src:
            is_forward = True
        else:
            is_forward = False

        flujo.add_packet(packet_len, timestamp, is_forward, tcp_flags, tcp_window)

        # Chequear flujos expirados cada 2 segundos aprox
        if timestamp - self.ultimo_chequeo > 2.0:
            self._limpiar_flujos_expirados(timestamp)
            self.ultimo_chequeo = timestamp

    def _limpiar_flujos_expirados(self, current_time):
        keys_to_delete = []
        for key, flujo in self.flujos.items():
            if flujo.is_expired(current_time):
                features = flujo.get_features_dict()
                # Llamar a la función de ML (CEREBRO / ids.py)
                self.callback_prediccion(flujo.src_ip, flujo.dst_ip, features)
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self.flujos[key]
