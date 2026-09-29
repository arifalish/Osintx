import json
import logging
import os
import urllib.request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Osintx.Bot")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

def send_msg(text: str):
    if not BOT_TOKEN or not CHAT_ID:
        logger.warning("Telegram credentials not configured in environment.")
        return False
    domain = "api.telegram.org"
    url = f"https://{domain}/bot{BOT_TOKEN}/sendMessage"
    payload = json.dumps({"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.getcode() == 200
    except Exception as e:
        logger.error("Telegram delivery failed: %s", e)
        return False

def main():
    logger.info("Osintx Bot engine starting up...")
    send_msg("🚀 *Osintx Engine Worker is online and active.*")

if __name__ == "__main__":
    main()
