import re
import os
import time
import base64
import json
import logging
import requests
import urllib.parse
import zlib
from bs4 import BeautifulSoup
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

CHANNEL_URL = "https://t.me/s/freewireguard"
OUTPUT_FILE_WG = 'sub/wireguard6th'
OUTPUT_FILE_NEKO = 'sub/nekobox6th'

def wireguard_to_neko(wg_url):
    try:
        parsed = urllib.parse.urlparse(wg_url)
        query = dict(urllib.parse.parse_qs(parsed.query))

        private_key = urllib.parse.unquote(parsed.username)
        reserved_str = query.get('reserved', ['0'])[0]
        reserved_parts = reserved_str.split(',')
        if len(reserved_parts) == 3:
            reserved_bytes = bytes(map(int, reserved_parts))
            reserved_base64 = base64.b64encode(reserved_bytes).decode()
        else:
            reserved_base64 = reserved_str

        config = {
            "type": "wireguard",
            "name": "WireGuard",
            "server": parsed.hostname,
            "port": parsed.port,
            "private_key": private_key,
            "peerPublicKey": query.get('publickey', [''])[0],
            "peerPreSharedKey": "",
            "mtu": int(query.get('mtu', ['1280'])[0]),
            "reserved": reserved_base64,
            "localAddress": query.get('address', [''])[0].split(',')[0],
        }

        config_json = json.dumps(config)
        compressed_data = zlib.compress(config_json.encode(), 9)
        encoded = base64.urlsafe_b64encode(compressed_data).decode().rstrip('=')
        
        neko_url = f"sn://wg?{encoded}"
        logger.debug(f"Config before encoding: {config_json}")
        logger.debug(f"Encoded config: {encoded}")
        return neko_url
    except Exception as e:
        logger.error(f"Error converting to nekobox format: {str(e)}")
        return None

def fetch_wireguard_configs():
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(CHANNEL_URL, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        messages = soup.find_all('div', class_='tgme_widget_message_text')

        wg_configs = []
        neko_configs = []

        for message in messages:
            if not message.text:
                continue

            matches = re.finditer(r'wireguard://[^\s]+', message.text)
            for match in matches:
                config = match.group(0)
                base_config = config.split('#')[0]
                wg_configs.append(base_config)

                neko_config = wireguard_to_neko(base_config)
                if neko_config:
                    neko_configs.append(neko_config)

            if len(wg_configs) >= 25:
                break

        wg_configs = wg_configs[:25]
        neko_configs = neko_configs[:25]

        if not wg_configs:
            logger.error("No configs found!")
            return

        final_wg_configs = [
            f"{config}#NiREvil{i+1}"
            for i, config in enumerate(wg_configs)
        ]

        os.makedirs(os.path.dirname(OUTPUT_FILE_WG), exist_ok=True)
        with open(OUTPUT_FILE_WG, 'w', encoding='utf-8') as f:
            f.write('\n\n'.join(final_wg_configs))

        final_neko_configs = [
            f"{config}#NiREvil{i+1}"
            for i, config in enumerate(neko_configs)
        ]

        os.makedirs(os.path.dirname(OUTPUT_FILE_NEKO), exist_ok=True)
        with open(OUTPUT_FILE_NEKO, 'w', encoding='utf-8') as f:
            f.write('\n\n'.join(final_neko_configs))

        logger.info(f"YES {datetime.now()}")

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")

if __name__ == '__main__':
    fetch_wireguard_configs()
