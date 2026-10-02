import json
import os
from io import BytesIO
import unittest
from unittest.mock import MagicMock, patch

from api.index import handler
from bot.telegram_bot import process_command
from config import get_config


class TestBotAndAPI(unittest.TestCase):

    @patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "test_token_123", "TELEGRAM_CHAT_ID": "98765"})
    def test_config_defaults(self):
        cfg = get_config()
        self.assertEqual(cfg.notifications.telegram_bot_token, "test_token_123")
        self.assertEqual(cfg.notifications.telegram_chat_id, "98765")

    @patch("bot.telegram_bot.send_msg")
    def test_process_command_help(self, mock_send_msg):
        process_command("12345", "/help")
        mock_send_msg.assert_called_once()
        args, _ = mock_send_msg.call_args
        self.assertEqual(args[0], "12345")
        self.assertIn("Osintx Intelligence Bot", args[1])

    @patch("bot.telegram_bot.send_msg")
    @patch("engines.osint_engine.dns_lookup")
    def test_process_command_dns(self, mock_dns_lookup, mock_send_msg):
        mock_dns_lookup.return_value = {"domain": "example.com", "records": {"A": ["1.2.3.4"]}}
        process_command("12345", "/dns example.com")
        self.assertGreaterEqual(mock_send_msg.call_count, 2)

    @patch("bot.telegram_bot.send_msg")
    @patch("engines.osint_engine.full_scan")
    def test_process_command_scan(self, mock_full_scan, mock_send_msg):
        mock_full_scan.return_value = {"target": "example.com"}
        process_command("12345", "/scan example.com")
        self.assertGreaterEqual(mock_send_msg.call_count, 2)

    @patch("api.index.process_command")
    def test_api_webhook_post(self, mock_process_command):
        # Test HTTP Handler POST request
        payload = json.dumps({
            "update_id": 1,
            "message": {
                "chat": {"id": 12345},
                "text": "/start"
            }
        }).encode("utf-8")

        # Mock server request handling
        h = MagicMock(spec=handler)
        h.headers = {"Content-Length": str(len(payload))}
        h.rfile = BytesIO(payload)
        h.wfile = BytesIO()

        # Call do_POST on handler instance
        handler.do_POST(h)
        mock_process_command.assert_called_once_with("12345", "/start")


if __name__ == "__main__":
    unittest.main()
