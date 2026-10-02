import ipaddress
import json
import logging
import re
import socket
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

import dns.resolver

logger = logging.getLogger("Osintx.Engine")


def sanitize_target(target: str) -> str:
    """Clean domain or IP input string."""
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urllib.parse.urlparse(target)
        target = parsed.netloc or parsed.path
    target = target.split("/")[0].split(":")[0]
    return target.strip()


def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def dns_lookup(domain: str) -> Dict[str, Any]:
    """Perform DNS lookup for A, AAAA, MX, TXT, NS, and CNAME records."""
    clean_domain = sanitize_target(domain)
    if not clean_domain:
        return {"error": "Invalid target domain"}

    results: Dict[str, Any] = {"domain": clean_domain, "records": {}}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    for r_type in record_types:
        try:
            answers = resolver.resolve(clean_domain, r_type)
            records = [str(rdata).strip('"') for rdata in answers]
            if records:
                results["records"][r_type] = records
        except Exception:
            continue

    if not results["records"] and not is_valid_ip(clean_domain):
        # Fallback to standard socket A record lookup
        try:
            _, _, ips = socket.gethostbyname_ex(clean_domain)
            if ips:
                results["records"]["A"] = ips
        except Exception as e:
            logger.debug("Socket resolution failed for %s: %s", clean_domain, e)

    return results


def ip_lookup(target: str) -> Dict[str, Any]:
    """Lookup IP details, reverse DNS, and geolocation info."""
    clean_target = sanitize_target(target)
    if not clean_target:
        return {"error": "Invalid IP or target"}

    ip_address = clean_target
    if not is_valid_ip(clean_target):
        try:
            ip_address = socket.gethostbyname(clean_target)
        except Exception:
            return {"error": f"Could not resolve domain '{clean_target}' to IP address."}

    info: Dict[str, Any] = {"query": target, "ip": ip_address}

    # Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        info["reverse_dns"] = hostname
    except Exception:
        info["reverse_dns"] = "N/A"

    # GeoIP / ASN lookup via free RDAP or ip-api API
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OsintxBot/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                info["country"] = data.get("country", "N/A")
                info["region"] = data.get("regionName", "N/A")
                info["city"] = data.get("city", "N/A")
                info["isp"] = data.get("isp", "N/A")
                info["org"] = data.get("org", "N/A")
                info["asn"] = data.get("as", "N/A")
            else:
                info["error_detail"] = data.get("message", "IP lookup unsuccessful")
    except Exception as e:
        info["error_detail"] = f"GeoIP API request failed: {e}"

    return info


def whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform RDAP / WHOIS lookup for domain registration information."""
    clean_domain = sanitize_target(domain)
    if not clean_domain or is_valid_ip(clean_domain):
        return {"error": "Invalid domain for WHOIS lookup"}

    url = f"https://rdap.org/domain/{clean_domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "OsintxBot/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))

            registrar = "N/A"
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry[0] == "fn":
                                registrar = entry[3]
                                break

            events = {ev.get("eventAction"): ev.get("eventDate") for ev in data.get("events", [])}
            nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]

            return {
                "domain": clean_domain,
                "handle": data.get("handle", "N/A"),
                "registrar": registrar,
                "created": events.get("registration", events.get("created", "N/A")),
                "updated": events.get("last changed", events.get("last updated", "N/A")),
                "expires": events.get("expiration", "N/A"),
                "nameservers": nameservers or ["N/A"],
                "status": [st for st in data.get("status", [])] or ["N/A"],
            }
    except Exception as e:
        logger.debug("RDAP lookup failed for %s: %s", clean_domain, e)
        return {
            "domain": clean_domain,
            "registrar": "N/A",
            "created": "N/A",
            "expires": "N/A",
            "nameservers": ["N/A"],
            "note": f"RDAP data unavailable or rate-limited: {e}"
        }


def headers_lookup(url_target: str) -> Dict[str, Any]:
    """Check HTTP response headers and security posture."""
    if not url_target.startswith("http://") and not url_target.startswith("https://"):
        url_target = "https://" + url_target

    req = urllib.request.Request(url_target, headers={"User-Agent": "OsintxBot/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            headers = dict(resp.headers)
            status_code = resp.getcode()
            final_url = resp.geturl()

            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
                "Referrer-Policy": headers.get("Referrer-Policy", "Missing"),
                "Permissions-Policy": headers.get("Permissions-Policy", "Missing"),
            }

            return {
                "url": url_target,
                "final_url": final_url,
                "status_code": status_code,
                "server": headers.get("Server", "Hidden/Unspecified"),
                "content_type": headers.get("Content-Type", "N/A"),
                "security_headers": security_headers,
                "raw_headers": headers,
            }
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if e.headers else {}
        return {
            "url": url_target,
            "status_code": e.code,
            "server": headers.get("Server", "Hidden/Unspecified"),
            "security_headers": {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            },
            "error": f"HTTP Error {e.code}"
        }
    except Exception as e:
        return {"url": url_target, "error": f"HTTP Request failed: {e}"}


def full_scan(target: str) -> Dict[str, Any]:
    """Comprehensive OSINT target analysis."""
    clean_target = sanitize_target(target)
    results: Dict[str, Any] = {"target": clean_target}

    results["ip_info"] = ip_lookup(clean_target)
    results["dns_info"] = dns_lookup(clean_target)

    if not is_valid_ip(clean_target):
        results["whois_info"] = whois_lookup(clean_target)
        results["headers_info"] = headers_lookup(clean_target)

    return results


# Formatting Utilities for Telegram Messages

def format_dns_report(dns_data: Dict[str, Any]) -> str:
    if "error" in dns_data:
        return f"⚠️ *DNS Error:* {dns_data['error']}"

    domain = dns_data.get("domain", "Unknown")
    records = dns_data.get("records", {})
    if not records:
        return f"🌐 *DNS Records for `{domain}`*\n\nNo records found or domain resolution failed."

    msg = [f"🌐 *DNS Records for `{domain}`*\n"]
    for r_type, vals in records.items():
        msg.append(f"• *{r_type}:*")
        for val in vals[:5]:  # limit top 5
            msg.append(f"   `{val}`")
        if len(vals) > 5:
            msg.append(f"   _...and {len(vals)-5} more_")
    return "\n".join(msg)


def format_ip_report(ip_data: Dict[str, Any]) -> str:
    if "error" in ip_data:
        return f"⚠️ *IP Lookup Error:* {ip_data['error']}"

    ip = ip_data.get("ip", "N/A")
    query = ip_data.get("query", ip)
    reverse = ip_data.get("reverse_dns", "N/A")
    country = ip_data.get("country", "N/A")
    region = ip_data.get("region", "N/A")
    city = ip_data.get("city", "N/A")
    isp = ip_data.get("isp", "N/A")
    asn = ip_data.get("asn", "N/A")

    return (
        f"📍 *IP Intelligence Report*\n"
        f"• *Target:* `{query}`\n"
        f"• *IP:* `{ip}`\n"
        f"• *Reverse DNS:* `{reverse}`\n"
        f"• *Location:* {city}, {region}, {country}\n"
        f"• *ISP:* `{isp}`\n"
        f"• *ASN:* `{asn}`"
    )


def format_whois_report(whois_data: Dict[str, Any]) -> str:
    if "error" in whois_data:
        return f"⚠️ *WHOIS Error:* {whois_data['error']}"

    domain = whois_data.get("domain", "N/A")
    registrar = whois_data.get("registrar", "N/A")
    created = whois_data.get("created", "N/A")
    expires = whois_data.get("expires", "N/A")
    nameservers = whois_data.get("nameservers", ["N/A"])

    ns_str = ", ".join(nameservers[:4]) if nameservers else "N/A"

    return (
        f"📋 *WHOIS Intelligence for `{domain}`*\n"
        f"• *Registrar:* `{registrar}`\n"
        f"• *Created:* `{created}`\n"
        f"• *Expires:* `{expires}`\n"
        f"• *Name Servers:* `{ns_str}`"
    )


def format_headers_report(headers_data: Dict[str, Any]) -> str:
    if "error" in headers_data and "security_headers" not in headers_data:
        return f"⚠️ *HTTP Headers Error:* {headers_data['error']}"

    url = headers_data.get("url", "N/A")
    status = headers_data.get("status_code", "N/A")
    server = headers_data.get("server", "N/A")

    sec_headers = headers_data.get("security_headers", {})
    sec_str = []
    for h, val in sec_headers.items():
        icon = "✅" if val != "Missing" else "❌"
        sec_str.append(f"{icon} *{h}:* `{val[:30]}`")

    return (
        f"🛡️ *HTTP Security Analysis for `{url}`*\n"
        f"• *Status Code:* `{status}`\n"
        f"• *Server:* `{server}`\n\n"
        f"*Security Headers:*\n" + "\n".join(sec_str)
    )


def format_scan_report(scan_data: Dict[str, Any]) -> str:
    target = scan_data.get("target", "Target")
    parts = [f"🚀 *Full OSINT Scan Report for `{target}`*\n"]

    if "ip_info" in scan_data:
        parts.append(format_ip_report(scan_data["ip_info"]))
        parts.append("\n" + "—"*20 + "\n")

    if "dns_info" in scan_data:
        parts.append(format_dns_report(scan_data["dns_info"]))
        parts.append("\n" + "—"*20 + "\n")

    if "whois_info" in scan_data:
        parts.append(format_whois_report(scan_data["whois_info"]))
        parts.append("\n" + "—"*20 + "\n")

    if "headers_info" in scan_data:
        parts.append(format_headers_report(scan_data["headers_info"]))

    return "\n".join(parts)
