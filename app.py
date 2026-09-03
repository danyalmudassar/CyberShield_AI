"""
CyberShield AI — Gradio Web Interface
========================================
Professional security scanning interface built with Gradio 4.x.

Features:
  - Domain input with authorization checkbox
  - Scope selection (passive/full pentest)
  - Real-time progress indicator
  - Security Posture Score (0-100, color-coded)
  - PISF 2026 Compliance Matrix (12-row table)
  - Critical Findings list with framework mappings
  - PDF Report download

Usage:
    python app.py
    # Opens at http://localhost:7860
"""

import sys
import os

# Fix import path when running from project root or agents/ directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gradio as gr
from agents.orchestrator import run_full_scan


# ---------------------------------------------------------------------------
# Theme: Dark Cybersecurity
# ---------------------------------------------------------------------------

THEME = gr.themes.Soft(
    primary_hue="blue",
    secondary_hue="cyan",
    neutral_hue="slate",
    font=gr.themes.GoogleFont("JetBrains Mono"),
    font_mono=gr.themes.GoogleFont("Fira Code"),
).set(
    body_background_fill="#0a0e17",
    body_background_fill_dark="#0a0e17",
    background_fill_primary="#0d1321",
    background_fill_primary_dark="#0d1321",
    background_fill_secondary="#131a2e",
    background_fill_secondary_dark="#131a2e",
    border_color_primary="#1e2d4a",
    border_color_primary_dark="#1e2d4a",
    color_accent="#00d4ff",
    color_accent_soft="#00d4ff22",
    button_primary_background_fill="linear-gradient(135deg, #0055ff, #00d4ff)",
    button_primary_background_fill_dark="linear-gradient(135deg, #0055ff, #00d4ff)",
    button_primary_text_color="#ffffff",
    button_secondary_background_fill="#1a2540",
    button_secondary_background_fill_dark="#1a2540",
    button_secondary_text_color="#8899bb",
    input_background_fill="#0f1729",
    input_background_fill_dark="#0f1729",
    input_border_color="#1e2d4a",
    input_border_color_dark="#1e2d4a",
    block_title_text_color="#c8d6e5",
    block_title_text_color_dark="#c8d6e5",
    block_label_text_color="#6b7fa3",
    block_label_text_color_dark="#6b7fa3",
    body_text_color="#c8d6e5",
    body_text_color_dark="#c8d6e5",
    body_text_color_subdued="#5a6d8a",
    body_text_color_subdued_dark="#5a6d8a",
    link_text_color="#00d4ff",
    link_text_color_dark="#00d4ff",
)

CUSTOM_CSS = """
/* ── Glassmorphism panels ────────────────────────────────────────── */
.gradio-container .form,
.gradio-container .block {
    background: rgba(13, 19, 33, 0.7) !important;
    backdrop-filter: blur(12px);
    border: 1px solid rgba(30, 45, 74, 0.6) !important;
    border-radius: 12px !important;
}

/* ── Tabs styling ────────────────────────────────────────────────── */
.tab-nav button {
    color: #5a6d8a !important;
    font-weight: 600 !important;
    border-bottom: 2px solid transparent !important;
    transition: all 0.3s ease !important;
}
.tab-nav button.selected {
    color: #00d4ff !important;
    border-bottom: 2px solid #00d4ff !important;
}

/* ── Dataframe styling ───────────────────────────────────────────── */
.gradio-dataframe table {
    font-family: 'Fira Code', monospace !important;
    font-size: 12px !important;
}
.gradio-dataframe th {
    background: #131a2e !important;
    color: #00d4ff !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
    font-size: 11px !important;
}
.gradio-dataframe td {
    color: #c8d6e5 !important;
    border-color: #1e2d4a !important;
}
.gradio-dataframe tr:hover td {
    background: rgba(0, 212, 255, 0.05) !important;
}

/* ── Button hover effects ────────────────────────────────────────── */
#scan-btn:hover {
    box-shadow: 0 0 30px rgba(0, 85, 255, 0.4) !important;
    transform: translateY(-1px);
    transition: all 0.2s ease;
}
#mock-btn:hover {
    box-shadow: 0 0 20px rgba(0, 212, 255, 0.2) !important;
    transform: translateY(-1px);
    transition: all 0.2s ease;
}

/* ── Header glow ─────────────────────────────────────────────────── */
.cyber-header h1 {
    background: linear-gradient(90deg, #0055ff, #00d4ff, #00ffaa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: none;
}

/* ── Score container glow ────────────────────────────────────────── */
.score-glow {
    animation: scoreGlow 3s ease-in-out infinite alternate;
}
@keyframes scoreGlow {
    from { box-shadow: 0 0 10px rgba(0, 212, 255, 0.1); }
    to   { box-shadow: 0 0 25px rgba(0, 212, 255, 0.2); }
}

/* ── Scrollbar styling ───────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0a0e17; }
::-webkit-scrollbar-thumb { background: #1e2d4a; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #2a3f66; }

/* ── Checkbox accent ─────────────────────────────────────────────── */
input[type="checkbox"]:checked {
    accent-color: #00d4ff !important;
}
"""


# ---------------------------------------------------------------------------
# Helper: Score HTML
# ---------------------------------------------------------------------------

def _make_score_html(score: float, status: str) -> str:
    """Return styled HTML for the security posture score gauge."""
    if status == "DENIED":
        return f"""
        <div class="score-glow" style="text-align:center;padding:24px;border-radius:12px;
                    background:rgba(26,10,10,0.8);backdrop-filter:blur(8px);
                    border:1px solid rgba(255,68,68,0.3);font-family:'JetBrains Mono',monospace;">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:3px;
                        color:#ff6666;margin-bottom:8px;font-weight:600;">Authorization</div>
            <div style="font-size:42px;font-weight:900;color:#ff4444;
                        text-shadow:0 0 20px rgba(255,68,68,0.5);">DENIED</div>
            <div style="font-size:11px;color:#666;margin-top:6px;">
                Scan cannot proceed without authorization
            </div>
        </div>"""

    score = max(0, min(100, score))

    if score < 40:
        color, glow = "#ff4444", "rgba(255,68,68,0.15)"
        label = "CRITICAL RISK"
    elif score < 60:
        color, glow = "#ff8c00", "rgba(255,140,0,0.15)"
        label = "HIGH RISK"
    elif score < 80:
        color, glow = "#ffd700", "rgba(255,215,0,0.15)"
        label = "MEDIUM RISK"
    else:
        color, glow = "#00ff88", "rgba(0,255,136,0.15)"
        label = "LOW RISK"

    return f"""
    <div class="score-glow" style="text-align:center;padding:28px;border-radius:12px;
                background:rgba(10,14,23,0.9);backdrop-filter:blur(8px);
                border:1px solid {color}33;font-family:'JetBrains Mono',monospace;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:4px;
                    color:#5a6d8a;margin-bottom:12px;font-weight:600;">Security Posture Score</div>
        <div style="font-size:68px;font-weight:900;color:{color};
                    line-height:1;text-shadow:0 0 40px {glow};">{score:.0f}</div>
        <div style="font-size:10px;color:#5a6d8a;margin-top:4px;font-weight:600;">/ 100</div>
        <div style="margin-top:14px;display:inline-block;padding:5px 18px;
                    border-radius:20px;background:{color}15;border:1px solid {color}44;
                    color:{color};font-size:11px;font-weight:700;letter-spacing:2px;">
            {label}
        </div>
    </div>"""


# ---------------------------------------------------------------------------
# Helper: Findings Summary HTML
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "Critical": "#ff4444",
    "High": "#ff8c00",
    "Medium": "#ffd700",
    "Low": "#4fc3f7",
    "Info": "#5a6d8a",
}

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _make_findings_summary_html(findings) -> str:
    """Return HTML with severity badge counts and a CSS bar chart."""
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = f.severity if f.severity in counts else "Info"
        counts[sev] += 1

    total = len(findings)
    max_count = max(counts.values()) if counts else 1
    if max_count == 0:
        max_count = 1

    badges = ""
    bars = ""
    for sev in _SEVERITY_ORDER:
        c = counts[sev]
        col = _SEVERITY_COLORS[sev]
        badges += (
            f'<span style="display:inline-block;margin:4px 6px;padding:5px 14px;'
            f'border-radius:20px;background:{col}15;border:1px solid {col}44;'
            f'color:{col};font-size:12px;font-weight:700;'
            f'font-family:\'JetBrains Mono\',monospace;">{sev}: {c}</span>'
        )
        pct = (c / max_count) * 100
        bars += f"""
        <div style="display:flex;align-items:center;margin:8px 0;">
            <div style="width:70px;font-size:11px;color:#5a6d8a;text-align:right;
                        padding-right:12px;font-family:'JetBrains Mono',monospace;
                        font-weight:600;text-transform:uppercase;">{sev}</div>
            <div style="flex:1;background:#0f1729;border-radius:4px;height:20px;
                        overflow:hidden;border:1px solid #1e2d4a33;">
                <div style="width:{pct}%;height:100%;
                            background:linear-gradient(90deg,{col}88,{col});
                            border-radius:4px;transition:width 0.6s ease;"></div>
            </div>
            <div style="width:35px;font-size:12px;color:{col};text-align:center;
                        padding-left:10px;font-family:'JetBrains Mono',monospace;
                        font-weight:700;">{c}</div>
        </div>"""

    return f"""
    <div style="font-family:'JetBrains Mono',monospace;padding:16px;">
        <div style="font-size:13px;color:#5a6d8a;margin-bottom:10px;font-weight:600;">
            Total Findings: <strong style="color:#00d4ff;">{total}</strong>
        </div>
        <div style="margin-bottom:18px;">{badges}</div>
        {bars}
    </div>"""


# ---------------------------------------------------------------------------
# Helper: PISF Table
# ---------------------------------------------------------------------------

def _make_pisf_table(pisf_result) -> list:
    """Return list-of-lists for the PISF 2026 compliance Dataframe."""
    if not pisf_result or not pisf_result.controls:
        return []

    rows = []
    for c in pisf_result.controls:
        iso = c.international_mapping.get("iso_27001", "")
        nist = c.international_mapping.get("nist_csf", "")
        rows.append([
            f"Control {c.control_id}",
            c.domain,
            c.status,
            c.evidence[:120] if c.evidence else "",
            iso,
            nist,
        ])
    return rows


# ---------------------------------------------------------------------------
# Helper: Findings Table
# ---------------------------------------------------------------------------

def _make_findings_table(findings) -> list:
    """Return list-of-lists for the findings Dataframe, sorted by severity."""
    if not findings:
        return []

    order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    sorted_findings = sorted(findings, key=lambda f: order.get(f.severity, 99))

    rows = []
    for f in sorted_findings:
        rows.append([
            f.finding_id or f.check_id,
            f.severity,
            f.title,
            f.cvss_score,
            f.owasp_top10,
            f.wstg_id,
            f.cwe_id,
            f.pisf_control,
        ])
    return rows


# ---------------------------------------------------------------------------
# Helper: Visual Analysis HTML Card
# ---------------------------------------------------------------------------

def _make_visual_html(visual) -> str:
    """Return HTML card displaying V-001 to V-008 visual security audit results."""
    if not visual:
        return "<div style='color:#5a6d8a;padding:16px;'>Visual analysis data unavailable.</div>"

    def _badge(label, status, ok_text="SAFE / YES", fail_text="RISK / NO", is_good_when_true=True):
        is_ok = (status == is_good_when_true)
        col = "#00e676" if is_ok else "#ff4444"
        bg = f"{col}15"
        border = f"{col}44"
        text = ok_text if is_ok else fail_text
        return f"""
        <div style="background:{bg};border:1px solid {border};border-radius:8px;padding:12px;margin:6px 0;">
            <div style="font-size:11px;color:#5a6d8a;font-family:'JetBrains Mono',monospace;font-weight:600;">{label}</div>
            <div style="font-size:14px;color:{col};font-family:'JetBrains Mono',monospace;font-weight:700;margin-top:4px;">{text}</div>
        </div>"""

    b_admin = _badge("V-001: Admin Panel Exposed", visual.admin_panel_detected, ok_text="NOT DETECTED", fail_text="EXPOSED / DETECTED", is_good_when_true=False)
    b_https = _badge("V-002: HTTPS / HSTS Enforced", visual.https_padlock, ok_text="ENFORCED & ACTIVE", fail_text="NOT ENFORCED / MISSING", is_good_when_true=True)
    b_captcha = _badge("V-003: CAPTCHA Protection", visual.captcha_present, ok_text="PRESENT", fail_text="NOT FOUND", is_good_when_true=True)
    b_cookie = _badge("V-007: Cookie Consent Banner", visual.cookie_consent, ok_text="COMPLIANT", fail_text="NOT DETECTED", is_good_when_true=True)
    b_mixed = _badge("V-008: Mixed Content (HTTP on HTTPS)", visual.mixed_content, ok_text="CLEAN", fail_text="MIXED CONTENT DETECTED", is_good_when_true=False)

    scripts_html = "".join(f"<li style='color:#c8d6e5;font-size:11px;'>{s}</li>" for s in visual.third_party_scripts[:10]) or "<li style='color:#5a6d8a;font-size:11px;'>None detected</li>"
    susp_html = "".join(f"<li style='color:#ff8c00;font-size:11px;'>{s}</li>" for s in visual.suspicious_elements) or "<li style='color:#5a6d8a;font-size:11px;'>None detected</li>"
    sens_html = "".join(f"<li style='color:#ff4444;font-size:11px;'>{s}</li>" for s in visual.sensitive_info_exposed) or "<li style='color:#5a6d8a;font-size:11px;'>None exposed</li>"

    return f"""
    <div style="font-family:'JetBrains Mono',monospace;padding:16px;">
        <h4 style="color:#00d4ff;margin-bottom:12px;">👁️ Browser-Level Visual Security Audit (V-001 to V-008)</h4>
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:10px;margin-bottom:16px;">
            {b_admin}
            {b_https}
            {b_captcha}
            {b_cookie}
            {b_mixed}
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:14px;margin-top:16px;">
            <div style="background:#0f1729;border:1px solid #1e2d4a;border-radius:8px;padding:12px;">
                <div style="font-size:12px;color:#00d4ff;font-weight:700;margin-bottom:6px;">V-004: Third-Party Scripts ({len(visual.third_party_scripts)})</div>
                <ul style="padding-left:16px;margin:0;">{scripts_html}</ul>
            </div>
            <div style="background:#0f1729;border:1px solid #1e2d4a;border-radius:8px;padding:12px;">
                <div style="font-size:12px;color:#ff8c00;font-weight:700;margin-bottom:6px;">V-005: Suspicious UI Elements</div>
                <ul style="padding-left:16px;margin:0;">{susp_html}</ul>
            </div>
            <div style="background:#0f1729;border:1px solid #1e2d4a;border-radius:8px;padding:12px;">
                <div style="font-size:12px;color:#ff4444;font-weight:700;margin-bottom:6px;">V-006: Sensitive Info In Source</div>
                <ul style="padding-left:16px;margin:0;">{sens_html}</ul>
            </div>
        </div>
    </div>"""


# ---------------------------------------------------------------------------
# Core scan function
# ---------------------------------------------------------------------------

def run_scan(domain, authorized, scope_type, contact_email, use_mock=False):
    """Run the full security scan and return all UI component values."""

    # Validate inputs
    if not domain or not domain.strip():
        return (
            _make_score_html(0, "DENIED"),
            "[ERROR] No domain provided",
            "<h3 style='color:#ff4444;font-family:JetBrains Mono,monospace;'>⚠ No domain entered</h3>",
            [],
            [],
            "Please enter a target domain.",
            "<div style='color:#ff4444;'>No scan performed.</div>",
            None,
        )

    domain = domain.strip()

    # Collect progress messages
    progress_log = []

    def progress_cb(stage, msg):
        progress_log.append(f"[{stage.upper()}] {msg}")

    # Run the orchestrator
    state = run_full_scan(
        domain=domain,
        authorized=authorized,
        scope_type=scope_type,
        contact_email=contact_email or "",
        use_mock=use_mock,
        progress_callback=progress_cb,
    )

    # Check if denied
    if state.scan_progress.get("status") == "DENIED":
        return (
            _make_score_html(0, "DENIED"),
            "\n".join(progress_log),
            "<h3 style='color:#ff4444;font-family:JetBrains Mono,monospace;'>⛔ Authorization Denied</h3>"
            "<p style='color:#5a6d8a;'>Security scan cannot proceed without authorization. "
            "Please check the authorization checkbox and try again.</p>",
            [],
            [],
            "Authorization denied. No scan performed.",
            "<div style='color:#ff4444;'>Scan denied.</div>",
            None,
        )

    # Check if error
    if state.scan_progress.get("status") == "ERROR":
        return (
            _make_score_html(0, "DENIED"),
            "\n".join(progress_log),
            "<h3 style='color:#ff4444;font-family:JetBrains Mono,monospace;'>⚠ Scan Error</h3>"
            "<p style='color:#5a6d8a;'>An error occurred during the scan. See progress log for details.</p>",
            [],
            [],
            "Scan error. See progress log.",
            "<div style='color:#ff4444;'>Scan error.</div>",
            None,
        )

    # Build score HTML
    score = state.report.security_posture_score if state.report else 0
    score_html = _make_score_html(score, "SCANNED")

    # Build findings summary HTML
    summary_html = _make_findings_summary_html(state.all_findings)

    # Build PISF table
    pisf_rows = _make_pisf_table(state.pisf)

    # Build findings table
    findings_rows = _make_findings_table(state.all_findings)

    # Build visual HTML
    visual_html = _make_visual_html(state.visual)

    # Report text
    exec_summary = state.report.executive_summary if state.report else "No report generated."

    # PDF file
    pdf_path = state.report.pdf_path if state.report else None
    if pdf_path and not os.path.isfile(pdf_path):
        pdf_path = None

    return (
        score_html,
        "\n".join(progress_log),
        summary_html,
        pisf_rows,
        findings_rows,
        visual_html,
        exec_summary,
        pdf_path,
    )


# ---------------------------------------------------------------------------
# Gradio UI
# ---------------------------------------------------------------------------

with gr.Blocks(
    title="CyberShield AI — Security Assessment",
) as app:

    # Header
    gr.Markdown(
        '<div class="cyber-header">\n'
        "# 🛡️ CyberShield AI — Automated Security Assessment\n"
        "</div>",
    )
    gr.Markdown(
        "*PISF 2026 Compliant &nbsp;|&nbsp; PTES Methodology &nbsp;|&nbsp; CVSSv3.1 Scoring*"
    )

    with gr.Row():
        with gr.Column(scale=2):
            # Input Section
            domain_input = gr.Textbox(
                label="Target Domain",
                placeholder="example.com",
                info="Enter domain without http://",
            )
            with gr.Row():
                authorized_checkbox = gr.Checkbox(
                    label="I confirm I am authorized to test this domain",
                    value=False,
                )
            scope_selector = gr.Radio(
                ["passive_only", "full_pentest"],
                label="Scan Scope",
                value="passive_only",
                info="Passive: reconnaissance only. Full: includes active vulnerability checks",
            )
            contact_email = gr.Textbox(
                label="Contact Email (optional)",
                placeholder="admin@example.com",
            )

            with gr.Row():
                scan_button = gr.Button(
                    "🔍 Start Security Scan",
                    variant="primary",
                    size="lg",
                    elem_id="scan-btn",
                )
                mock_button = gr.Button(
                    "📋 Demo Mode (Mock Data)",
                    variant="secondary",
                    elem_id="mock-btn",
                )

        with gr.Column(scale=1):
            # Score Display
            score_display = gr.HTML(label="Security Score")
            progress_text = gr.Textbox(
                label="Scan Progress",
                lines=8,
                interactive=False,
            )

    # Results Section
    with gr.Tabs():
        with gr.TabItem("📊 Overview"):
            findings_summary_html = gr.HTML(label="Findings Summary")

        with gr.TabItem("🇵🇰 PISF 2026 Compliance"):
            pisf_table = gr.Dataframe(
                headers=["Control", "Domain", "Status", "Evidence", "ISO 27001", "NIST CSF"],
                label="PISF 2026 Compliance Matrix",
                wrap=True,
            )

        with gr.TabItem("🔴 Critical Findings"):
            findings_table = gr.Dataframe(
                headers=["ID", "Severity", "Title", "CVSS", "OWASP", "WSTG", "CWE", "PISF"],
                label="Security Findings",
                wrap=True,
            )

        with gr.TabItem("👁️ Visual Analysis"):
            visual_html_display = gr.HTML(label="Visual Security Audit")

        with gr.TabItem("📄 Report"):
            report_text = gr.Textbox(
                label="Executive Summary",
                lines=10,
                interactive=False,
            )
            pdf_download = gr.File(label="📥 Download PDF Report")

    # Footer
    gr.Markdown("---")
    gr.Markdown(
        "*CyberShield AI — Alibaba Cloud AI Hackathon Pakistan 2026 &nbsp;|&nbsp; Powered by Qwen-Max*"
    )

    # ── Button bindings ────────────────────────────────────────────────────

    scan_outputs = [
        score_display,
        progress_text,
        findings_summary_html,
        pisf_table,
        findings_table,
        visual_html_display,
        report_text,
        pdf_download,
    ]
    scan_inputs = [domain_input, authorized_checkbox, scope_selector, contact_email]

    scan_button.click(
        fn=lambda d, a, s, e: run_scan(d, a, s, e, use_mock=False),
        inputs=scan_inputs,
        outputs=scan_outputs,
    )

    mock_button.click(
        fn=lambda d, a, s, e: run_scan(
            d if d else "testphp.vulnweb.com", True, s, e, use_mock=True
        ),
        inputs=scan_inputs,
        outputs=scan_outputs,
    )


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        theme=THEME,
        css=CUSTOM_CSS,
    )
