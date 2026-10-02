from http.server import BaseHTTPRequestHandler
import json
import logging
import os
import sys

# Add parent directory to path so bot, config and engines can be imported cleanly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bot.telegram_bot import process_command
from config import get_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Osintx.Webhook")


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {
            "status": "online",
            "service": "Osintx Telegram Intelligence Webhook",
        }
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            update = json.loads(post_data.decode("utf-8"))
            logger.info("Received Webhook update: %s", update)

            message = update.get("message", {})
            chat = message.get("chat", {})
            chat_id = str(chat.get("id", ""))
            text = message.get("text", "")

            if chat_id and text:
                process_command(chat_id, text)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
        except Exception as e:
            logger.error("Error processing Webhook update: %s", e)
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
