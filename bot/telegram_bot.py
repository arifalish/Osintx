import json
import logging
import os
import sys
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

# Add parent directory to path so config and engines can be imported cleanly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import get_config
import engines.osint_engine as osint_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Osintx.Bot")

cfg = get_config()
BOT_TOKEN = cfg.notifications.telegram_bot_token
CHAT_ID = cfg.notifications.telegram_chat_id


def delete_webhook() -> bool:
    """Clear active webhook if present so getUpdates long-polling works without HTTP 409 Conflict."""
    if not BOT_TOKEN:
        return False
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/deleteWebhook"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OsintxBot/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("ok", False)
    except Exception as e:
        logger.warning("Failed to delete webhook: %s", e)
        return False


def send_msg(chat_id: str, text: str, parse_mode: str = "Markdown") -> bool:
    """Send message to a Telegram chat."""
    if not BOT_TOKEN:
        logger.warning("Telegram BOT_TOKEN is not configured.")
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.getcode() == 200
    except Exception as e:
        logger.error("Failed to send message to chat %s: %s", chat_id, e)
        return False


def process_command(chat_id: str, text: str) -> None:
    """Process incoming command or query and send response back."""
    text = text.strip()
    if not text:
        return

    parts = text.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    if cmd in ["/start", "/help"]:
        help_msg = (
            "🔍 *Osintx Intelligence Bot*\n"
            "High-concurrency OSINT Reconnaissance Framework\n\n"
            "*Available Commands:*\n"
            "• `/scan <target>` - Perform comprehensive OSINT scan\n"
            "• `/dns <domain>` - Query DNS A, AAAA, MX, TXT, NS records\n"
            "• `/ip <target>` - IP Geolocation, Reverse DNS, ASN info\n"
            "• `/whois <domain>` - Domain WHOIS / RDAP lookup\n"
            "• `/headers <url>` - HTTP security headers inspection\n"
            "• `/help` - Show this usage guide\n\n"
            "_Tip: You can also send a raw domain or IP directly (e.g., `example.com`)._"
        )
        send_msg(chat_id, help_msg)
        return

    if cmd == "/dns":
        if not arg:
            send_msg(chat_id, "⚠️ *Usage:* `/dns <domain>`")
            return
        send_msg(chat_id, f"🔎 *Resolving DNS for* `{arg}`...")
        res = osint_engine.dns_lookup(arg)
        send_msg(chat_id, osint_engine.format_dns_report(res))
        return

    if cmd == "/ip":
        if not arg:
            send_msg(chat_id, "⚠️ *Usage:* `/ip <ip_or_domain>`")
            return
        send_msg(chat_id, f"🔎 *Fetching IP details for* `{arg}`...")
        res = osint_engine.ip_lookup(arg)
        send_msg(chat_id, osint_engine.format_ip_report(res))
        return

    if cmd == "/whois":
        if not arg:
            send_msg(chat_id, "⚠️ *Usage:* `/whois <domain>`")
            return
        send_msg(chat_id, f"🔎 *Fetching WHOIS for* `{arg}`...")
        res = osint_engine.whois_lookup(arg)
        send_msg(chat_id, osint_engine.format_whois_report(res))
        return

    if cmd == "/headers":
        if not arg:
            send_msg(chat_id, "⚠️ *Usage:* `/headers <url>`")
            return
        send_msg(chat_id, f"🔎 *Analyzing HTTP Headers for* `{arg}`...")
        res = osint_engine.headers_lookup(arg)
        send_msg(chat_id, osint_engine.format_headers_report(res))
        return

    if cmd == "/scan":
        if not arg:
            send_msg(chat_id, "⚠️ *Usage:* `/scan <domain_or_ip>`")
            return
        send_msg(chat_id, f"🚀 *Initiating full OSINT scan for* `{arg}`...")
        res = osint_engine.full_scan(arg)
        send_msg(chat_id, osint_engine.format_scan_report(res))
        return

    # Handle direct text target lookup
    target = text.lstrip("/")
    send_msg(chat_id, f"🚀 *Initiating full OSINT scan for* `{target}`...")
    res = osint_engine.full_scan(target)
    send_msg(chat_id, osint_engine.format_scan_report(res))


def get_updates(offset: Optional[int] = None, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """Poll Telegram getUpdates API."""
    if not BOT_TOKEN:
        return None

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?timeout={timeout}"
    if offset is not None:
        url += f"&offset={offset}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OsintxBot/1.0"})
        with urllib.request.urlopen(req, timeout=timeout + 5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.error("getUpdates failed: %s", e)
        return None


def run_polling():
    """Continuous polling loop for Telegram Updates."""
    logger.info("Clearing active webhook for long polling...")
    delete_webhook()
    logger.info("Starting Osintx Bot Telegram continuous long-polling loop...")
    if CHAT_ID:
        send_msg(CHAT_ID, "🚀 *Osintx Engine Worker is online and active.*")

    offset = None
    while True:
        try:
            updates = get_updates(offset=offset, timeout=10)
            if updates and updates.get("ok"):
                for result in updates.get("result", []):
                    update_id = result.get("update_id")
                    offset = update_id + 1 if update_id is not None else offset

                    message = result.get("message", {})
                    chat = message.get("chat", {})
                    chat_id = str(chat.get("id", ""))
                    text = message.get("text", "")

                    if chat_id and text:
                        logger.info("Processing update %s from chat %s: %s", update_id, chat_id, text)
                        process_command(chat_id, text)
        except Exception as e:
            logger.error("Unexpected error in polling loop: %s", e)

        time.sleep(1)


def main():
    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not configured. Exiting.")
        sys.exit(1)

    run_polling()


if __name__ == "__main__":
    main()
