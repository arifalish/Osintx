from http.server import BaseHTTPRequestHandler
import json
import os
import socket
import urllib.request

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8035189228:AAHOKY887AREFP9uTsok_FzW_HlZY8aaHfQ")
