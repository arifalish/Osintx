from http.server import BaseHTTPRequestHandler
import json
import os
import socket
import urllib.request

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8035189228:AAFXhcmPhMHhHq0JHxJidNhImVKVhYCX77g")
ALLOWED_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "8035189228")

def send_telegram(chat_id: str, text: str):
    if not BOT_TOKEN: return False
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.getcode() == 200
    except Exception:
        return False

def run_recon(target: str) -> str:
    subdomains = ["www", "mail", "api", "dev", "vpn", "admin", "auth"]
    resolved_ips = []
    found_subs = []
    try:
        resolved_ips.append(socket.gethostbyname(target))
    except: pass
    for sub in subdomains:
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            found_subs.append(fqdn)
            if ip not in resolved_ips: resolved_ips.append(ip)
        except: continue
    subs_list = "\n".join([f"- `{s}`" for s in found_subs]) if found_subs else "None discovered"
    ips_list = "\n".join([f"- `{ip}`" for ip in resolved_ips]) if resolved_ips else "None resolved"
    return f"🎯 *Osintx Recon Report: {target}*\n\n🌐 *Subdomains:*\n{subs_list}\n\n🖥 *IP Addresses:*\n{ips_list}"

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "online", "service": "Osintx Serverless Bot"}).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_response(200)
            self.end_headers()
            return
        body_raw = self.rfile.read(content_length).decode("utf-8")
        try:
            update = json.loads(body_raw)
        except: update = {}
        
        message = update.get("message", {})
        text = message.get("text", "").strip()
        chat_id = str(message.get("chat", {}).get("id", ""))
        
        if chat_id and chat_id == ALLOWED_CHAT_ID:
            if text.startswith("/start"):
                send_telegram(chat_id, "🚀 *Osintx Recon Bot is Active*\n\nUse `/scan <domain>` to run passive network reconnaissance.")
            elif text.startswith("/scan"):
                parts = text.split()
                if len(parts) > 1:
                    target = parts[1].replace("https://", "").replace("http://", "").split("/")[0]
                    send_telegram(chat_id, f"🔍 Scanning target `{target}`...")
                    send_telegram(chat_id, run_recon(target))
                else:
                    send_telegram(chat_id, "⚠️ Usage: `/scan example.com`")
        
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
