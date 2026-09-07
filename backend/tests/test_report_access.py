"""
CyberShield AI — Report Download Access Tests
==============================================
Task 07: Verify that the /api/reports/download endpoint rejects path
traversal, absolute paths, non-PDF filenames, and symlinks that escape
the reports directory, while still serving legitimately registered PDFs.

All tests run entirely offline using temporary files.
"""

import os
import sys
import tempfile
import shutil

import pytest

# Make project root importable regardless of where pytest is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client_with_tmpdir(monkeypatch, tmp_path):
    """
    Return a TestClient whose REPORTS_DIR is a fresh temp directory.
    Monkeypatches server.REPORTS_DIR so the real reports/ folder is not used.
    Uses the lifespan context manager to initialize app.state.scan_store.
    """
    import server as srv

    monkeypatch.setattr(srv, "REPORTS_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERSHIELD_API_TOKEN", "test-report-token")
    with TestClient(srv.app, raise_server_exceptions=False) as client:
        client.headers["Authorization"] = "Bearer test-report-token"
        yield client, tmp_path


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestReportDownload:
    """Verify access-control behaviour of GET /api/reports/download."""

    def test_valid_pdf_returns_200(self, client_with_tmpdir):
        """A legitimate PDF registered inside REPORTS_DIR is served."""
        client, tmpdir = client_with_tmpdir
        pdf_file = tmpdir / "scan_report_abc123.pdf"
        pdf_file.write_bytes(b"%PDF-1.4 fake pdf content")

        store = client.app.state.scan_store
        scan = store.create_scan({"domain": "example.com"}, owner="operator@cybershield.ai")
        store.update_scan(scan["id"], "running")
        store.update_scan(scan["id"], "completed", result={"pdf_path": "scan_report_abc123.pdf"})

        resp = client.get("/api/reports/download", params={"filename": "scan_report_abc123.pdf"})
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"

    def test_traversal_dotdot_rejected(self, client_with_tmpdir):
        """../../etc/passwd style traversal must be rejected."""
        client, _ = client_with_tmpdir
        resp = client.get("/api/reports/download", params={"filename": "../../etc/passwd"})
        assert resp.status_code in (400, 404)

    def test_absolute_path_rejected(self, client_with_tmpdir):
        """An absolute path in the filename param must be rejected."""
        client, _ = client_with_tmpdir
        resp = client.get("/api/reports/download", params={"filename": "/etc/passwd"})
        assert resp.status_code in (400, 404)

    def test_non_pdf_extension_rejected(self, client_with_tmpdir):
        """Files without a .pdf extension must be rejected."""
        client, tmpdir = client_with_tmpdir
        # Create the file so the rejection is purely extension-based, not missing-file.
        (tmpdir / "secret.txt").write_text("sensitive")
        resp = client.get("/api/reports/download", params={"filename": "secret.txt"})
        assert resp.status_code in (400, 404)

    def test_filename_with_embedded_slash_rejected(self, client_with_tmpdir):
        """A filename containing a forward slash must be rejected."""
        client, _ = client_with_tmpdir
        resp = client.get("/api/reports/download", params={"filename": "subdir/report.pdf"})
        assert resp.status_code in (400, 404)

    def test_symlink_escape_rejected(self, client_with_tmpdir):
        """A symlink inside REPORTS_DIR that points outside must be rejected."""
        client, tmpdir = client_with_tmpdir
        # Create a file outside REPORTS_DIR to be the symlink target.
        outside = tmpdir.parent / "outside_secret.pdf"
        outside.write_bytes(b"%PDF-1.4 secret content")
        link = tmpdir / "escape.pdf"
        link.symlink_to(outside)

        resp = client.get("/api/reports/download", params={"filename": "escape.pdf"})
        assert resp.status_code in (400, 404)

    def test_nonexistent_pdf_returns_404(self, client_with_tmpdir):
        """A valid filename that simply does not exist returns 404."""
        client, _ = client_with_tmpdir
        resp = client.get("/api/reports/download", params={"filename": "ghost_report.pdf"})
        assert resp.status_code == 404

    def test_leading_dot_filename_rejected(self, client_with_tmpdir):
        """A filename beginning with '.' (hidden file) must be rejected."""
        client, _ = client_with_tmpdir
        resp = client.get("/api/reports/download", params={"filename": ".hidden.pdf"})
        assert resp.status_code in (400, 404)
