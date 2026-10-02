import unittest
from unittest.mock import MagicMock, patch

from engines.osint_engine import (
    dns_lookup,
    format_dns_report,
    format_headers_report,
    format_ip_report,
    format_scan_report,
    format_whois_report,
    full_scan,
    headers_lookup,
    ip_lookup,
    is_valid_ip,
    sanitize_target,
    whois_lookup,
)


class TestOSINTEngine(unittest.TestCase):

    def test_sanitize_target(self):
        self.assertEqual(sanitize_target("https://example.com/path/to/page"), "example.com")
        self.assertEqual(sanitize_target("http://1.1.1.1:8080/"), "1.1.1.1")
        self.assertEqual(sanitize_target("  domain.com  "), "domain.com")

    def test_is_valid_ip(self):
        self.assertTrue(is_valid_ip("8.8.8.8"))
        self.assertTrue(is_valid_ip("2001:4860:4860::8888"))
        self.assertFalse(is_valid_ip("example.com"))
        self.assertFalse(is_valid_ip("999.999.999.999"))

    def test_dns_lookup_invalid(self):
        res = dns_lookup("")
        self.assertIn("error", res)

    @patch("dns.resolver.Resolver")
    def test_dns_lookup_mock(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_answer = [MagicMock(__str__=lambda self: "93.184.216.34")]
        mock_resolver.resolve.return_value = mock_answer

        res = dns_lookup("example.com")
        self.assertEqual(res["domain"], "example.com")
        self.assertIn("A", res["records"])

    @patch("urllib.request.urlopen")
    def test_ip_lookup_mock(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status": "success", "country": "United States", "regionName": "California", "city": "Los Angeles", "isp": "Test ISP", "as": "AS12345 Test"}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        res = ip_lookup("8.8.8.8")
        self.assertEqual(res["ip"], "8.8.8.8")
        self.assertEqual(res["country"], "United States")
        self.assertEqual(res["city"], "Los Angeles")

    @patch("urllib.request.urlopen")
    def test_whois_lookup_mock(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"handle": "123", "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}], "events": [{"eventAction": "registration", "eventDate": "2020-01-01"}], "nameservers": [{"ldhName": "ns1.example.com"}]}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        res = whois_lookup("example.com")
        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["registrar"], "Example Registrar")

    @patch("urllib.request.urlopen")
    def test_headers_lookup_mock(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.getcode.return_value = 200
        mock_response.geturl.return_value = "https://example.com"
        mock_response.headers = {
            "Server": "nginx",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Type": "text/html",
        }
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        res = headers_lookup("https://example.com")
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["server"], "nginx")
        self.assertEqual(res["security_headers"]["Strict-Transport-Security"], "max-age=31536000")

    def test_formatting_reports(self):
        dns_data = {"domain": "test.com", "records": {"A": ["1.2.3.4"]}}
        ip_data = {"query": "1.2.3.4", "ip": "1.2.3.4", "country": "US", "city": "NYC", "isp": "ISP", "asn": "AS1"}
        whois_data = {"domain": "test.com", "registrar": "Reg", "created": "2020", "expires": "2025", "nameservers": ["ns1.com"]}
        headers_data = {"url": "https://test.com", "status_code": 200, "server": "nginx", "security_headers": {"X-Frame-Options": "DENY"}}

        self.assertIn("test.com", format_dns_report(dns_data))
        self.assertIn("1.2.3.4", format_ip_report(ip_data))
        self.assertIn("Reg", format_whois_report(whois_data))
        self.assertIn("nginx", format_headers_report(headers_data))

        scan_data = {
            "target": "test.com",
            "ip_info": ip_data,
            "dns_info": dns_data,
            "whois_info": whois_data,
            "headers_info": headers_data,
        }
        formatted_scan = format_scan_report(scan_data)
        self.assertIn("Full OSINT Scan Report", formatted_scan)


if __name__ == "__main__":
    unittest.main()
