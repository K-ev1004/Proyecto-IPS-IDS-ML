# =============================================================================
# telegram_alert.py — Módulo de notificaciones en tiempo real via Telegram
# Envía alertas del IDS a uno o varios usuarios mediante la API de Telegram Bot
# =============================================================================

# requests: Librería HTTP de terceros para realizar peticiones REST a la API de Telegram
import os

import requests


def _valor_entorno(*nombres, defecto=""):
    """Devuelve el primer valor de entorno no vacío, o `defecto`.

    Se aceptan dos nombres por compatibilidad: los nuevos `IDS_TELEGRAM_*`
    (documentados en `.env.example`) y los antiguos `TELEGRAM_*` que ya aparecían
    en el README. El lanzador `lanzar_v6_lab.bat` carga `.env` antes de arrancar.
    """
    for nombre in nombres:
        valor = os.environ.get(nombre)
        if valor and valor.strip():
            return valor.strip()
    return defecto


# BOT_TOKEN: Credencial única que identifica el bot ante la API de Telegram
# Formato: "<id_numérico>:<hash_alfanumérico>", obtenido con @BotFather.
# [!] SEGURIDAD: por entorno. El valor literal de abajo es SOLO un valor de
# desarrollo heredado para no romper la máquina actual; en una PC nueva hay que
# definir IDS_TELEGRAM_TOKEN en .env (y rotar el token antes de distribuir).
BOT_TOKEN = _valor_entorno(
    "IDS_TELEGRAM_TOKEN", "TELEGRAM_BOT_TOKEN",
    defecto="8954487099:AAEb4Y50c1_mE0i0V6q7QXOspImkRg649Zw",
)


def _parsear_chats(texto):
    """Convierte "123,456" en [123, 456]; tolera IDs no numéricos."""
    resultado = []
    for parte in texto.split(","):
        parte = parte.strip()
        if not parte:
            continue
        try:
            resultado.append(int(parte))
        except ValueError:
            resultado.append(parte)
    return resultado


# CHAT_IDS: destinatarios separados por coma (administradores, SOC, etc.).
# Mismo criterio de fallback que el token: valor de desarrollo heredado.
CHAT_IDS = _parsear_chats(_valor_entorno(
    "IDS_TELEGRAM_CHAT_IDS", "TELEGRAM_CHAT_IDS", defecto="6750700630",
)) or [6750700630]


# =============================================================================
# FUNCIÓN: enviar_alerta
# Propósito: Envía un mensaje de texto a todos los chat_ids configurados
# Parámetros:
#   mensaje — String con el contenido de la alerta a enviar
# Retorna: None (opera por efectos secundarios — HTTP POST y logs en consola)
# =============================================================================
def enviar_alerta(mensaje):
    if not BOT_TOKEN:
        print("[!] Telegram sin configurar (IDS_TELEGRAM_TOKEN vacío): "
              "alerta no enviada.")
        return

    # Construye la URL del endpoint sendMessage de la API de Telegram Bot
    # f-string embebe el BOT_TOKEN dinámicamente en la URL
    # Formato oficial: https://api.telegram.org/bot{TOKEN}/METHOD
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    # Itera sobre cada destinatario configurado en la lista
    # Permite notificación masiva: el mismo mensaje llega a todos los admins
    for chat_id in CHAT_IDS:

        # Construye el cuerpo de la petición como diccionario Python
        # chat_id: identifica al destinatario en Telegram
        # text: contenido del mensaje (soporta emojis y texto plano)
        data = {
            "chat_id": chat_id,
            "text": mensaje
        }

        try:
            # requests.post(): Envía una petición HTTP POST al endpoint de Telegram
            # La API de Telegram espera los datos como form-data (parámetro data=)
            # No se usa json= porque la API acepta application/x-www-form-urlencoded
            response = requests.post(url, data=data)

            # Verifica el código de estado HTTP de la respuesta
            # 200 OK indica que el mensaje fue recibido y encolado por Telegram
            if response.status_code == 200:
                print(f"📨 Alerta enviada a Telegram (chat_id {chat_id}) con éxito.")
            else:
                # Cualquier código diferente a 200 indica error de la API
                # response.text contiene el JSON de error de Telegram con detalles
                print(f"[X] Error al enviar alerta a {chat_id}: {response.text}")

        except Exception as e:
            # Captura errores de red: timeout, sin conexión, DNS fallido, etc.
            # Manejo defensivo para no interrumpir la detección de ataques si Telegram falla
            print(f"[X] Excepción al enviar alerta a {chat_id}: {e}")


# =============================================================================
# BLOQUE DE PRUEBA — Se ejecuta solo cuando se invoca el archivo directamente
# if __name__ == "__main__": evita que esta prueba se ejecute al importar el módulo
# =============================================================================
if __name__ == "__main__":
    # Envía un mensaje de prueba para verificar que el bot y el token funcionan
    enviar_alerta("[ALERT] Prueba de alerta desde mi bot!")

# =============================================================================
# FIN DEL SCRIPT — telegram_alert.py
# =============================================================================
