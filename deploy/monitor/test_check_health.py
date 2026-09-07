import unittest
from check_health import check


class HealthChecks(unittest.TestCase):
    def responses(self, readiness=(200, "application/json", b'{"status":"ready"}'), scans=401):
        return lambda url: readiness if url.endswith("/api/ready") else (
            (scans, "application/json", b"{}") if url.endswith("/api/scans")
            else (200, "text/html", b"<html>Login</html>"))

    def test_healthy_service(self):
        self.assertTrue(all(r["ok"] for r in check("https://example.com", self.responses())))

    def test_not_ready_is_failure(self):
        result = check("https://example.com", self.responses((503, "application/json", b'{"status":"not_ready"}')))
        self.assertFalse(result[0]["ok"])

    def test_anonymous_scan_access_is_failure(self):
        self.assertFalse(check("https://example.com", self.responses(scans=200))[2]["ok"])

    def test_bad_readiness_json_is_failure(self):
        for body in (b"not json", b"[]", b'{"status":"offline"}'):
            with self.subTest(body=body):
                self.assertFalse(check("https://example.com", self.responses((200, "application/json", body)))[0]["ok"])

    def test_connection_failure_is_recorded_without_detail(self):
        def failure(url):
            raise OSError("private diagnostic text")
        result = check("https://example.com", failure)
        self.assertTrue(all(not r["ok"] for r in result))
        self.assertNotIn("private diagnostic text", str(result))

    def test_rejects_credentials_and_non_https_origins(self):
        for url in ("http://example.com", "https://user:secret@example.com", "https://example.com/path"):
            with self.assertRaises(ValueError):
                check(url, self.responses())


if __name__ == "__main__":
    unittest.main()
