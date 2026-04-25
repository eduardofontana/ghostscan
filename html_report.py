"""HTML dashboard report generator for GhostScan."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path


def generate_html_report(payload: Dict[str, Any], output_path: Path) -> Path:
    """Generate an interactive HTML dashboard from scan results."""
    scan = payload.get("scan", {})
    summary = payload.get("summary", {})
    results = payload.get("results", [])
    services = summary.get("services_detected", {})
    firewall = summary.get("firewall_assessment", {})
    waf = summary.get("waf_assessment", {})

    open_count = scan.get("open_ports_count", 0)
    ports_scanned = scan.get("ports_scanned", 0)

    services_html = ""
    if services:
        for service, count in sorted(services.items(), key=lambda x: (-x[1], x[0])):
            services_html += f'<div class="service-item"><span class="service-name">{service}</span><span class="service-count">{count}</span></div>'
    else:
        services_html = '<div class="no-data">No services detected</div>'

    results_html = ""
    for row in results:
        version = row.get("version", "")
        version_str = f" <span class='version'>{version}</span>" if version else ""
        confidence = row.get("confidence", 0)
        conf_class = "high" if confidence >= 0.7 else "medium" if confidence >= 0.4 else "low"
        results_html += f"""
        <tr>
            <td class="port">{row.get("port", "")}</td>
            <td>{row.get("service", "Unknown")}{version_str}</td>
            <td><span class="transport {row.get('transport', 'tcp')}">{row.get('transport', 'tcp')}</span></td>
            <td><span class="confidence {conf_class}">{confidence:.0%}</span></td>
        </tr>"""

    if not results_html:
        results_html = '<tr><td colspan="4" class="no-data">No open ports detected</td></tr>'

    firewall_enabled = firewall.get("enabled", False)
    firewall_behind = firewall.get("behind_firewall", False)
    firewall_html = ""
    if firewall_enabled:
        firewall_html = f"""
        <div class="card firewall-card">
            <h3>Firewall Assessment</h3>
            <div class="firewall-status {'active' if firewall_behind else 'inactive'}">
                {'Detected' if firewall_behind else 'Not Detected'}
            </div>
            <div class="firewall-details">
                <p><strong>Type:</strong> {firewall.get('firewall_type', 'N/A')}</p>
                <p><strong>Score:</strong> {firewall.get('score', 0)}/99</p>
                <p><strong>Confidence:</strong> {firewall.get('confidence', 0):.0%}</p>
            </div>
        </div>"""

    waf_detected = waf.get("detected", False)
    waf_html = ""
    if waf.get("enabled"):
        waf_signals = ""
        for signal in waf.get("signals", [])[:5]:
            waf_signals += f"<li>{signal}</li>"
        waf_html = f"""
        <div class="card waf-card">
            <h3>WAF Fingerprint</h3>
            <div class="waf-status {'detected' if waf_detected else 'not-detected'}">
                {'Detected' if waf_detected else 'Not Detected'}
            </div>
            <p><strong>Confidence:</strong> {waf.get('confidence', 0):.0%}</p>
            <div class="waf-signals">
                <strong>Signals:</strong>
                <ul>{waf_signals}</ul>
            </div>
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostScan Report - {scan.get('resolved_target', 'N/A')}</title>
    <style>
        :root {{
            --bg-primary: #0a0a0a;
            --bg-secondary: #111111;
            --bg-tertiary: #1a1a1a;
            --text-primary: #e0e0e0;
            --text-secondary: #888888;
            --accent-green: #00ff41;
            --accent-cyan: #00d9ff;
            --accent-red: #ff3333;
            --accent-yellow: #ffcc00;
            --accent-blue: #3399ff;
            --border-color: #222222;
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', 'Roboto', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            padding: 30px;
            border-bottom: 2px solid var(--accent-green);
            margin-bottom: 30px;
        }}
        h1 {{
            font-size: 2rem;
            color: var(--accent-green);
            font-family: monospace;
            letter-spacing: 2px;
        }}
        .meta {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 10px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
        }}
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent-cyan);
        }}
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-card.danger .stat-value {{
            color: var(--accent-red);
        }}
        .stat-card.success .stat-value {{
            color: var(--accent-green);
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--bg-secondary);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            padding: 20px;
        }}
        .card h3 {{
            color: var(--accent-cyan);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 15px;
            font-size: 1.1rem;
        }}
        .service-item {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }}
        .service-name {{
            color: var(--text-primary);
        }}
        .service-count {{
            color: var(--accent-green);
            font-weight: bold;
        }}
        .no-data {{
            color: var(--text-secondary);
            font-style: italic;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            padding: 12px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.8rem;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        .port {{
            color: var(--accent-cyan);
            font-weight: bold;
            font-family: monospace;
        }}
        .version {{
            color: var(--text-secondary);
            font-size: 0.85em;
        }}
        .transport {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
        }}
        .transport.tcp {{
            background: rgba(51, 153, 255, 0.2);
            color: var(--accent-blue);
        }}
        .transport.tls {{
            background: rgba(0, 255, 65, 0.2);
            color: var(--accent-green);
        }}
        .transport.udp {{
            background: rgba(255, 204, 0, 0.2);
            color: var(--accent-yellow);
        }}
        .confidence {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
        }}
        .confidence.high {{
            background: rgba(0, 255, 65, 0.2);
            color: var(--accent-green);
        }}
        .confidence.medium {{
            background: rgba(255, 204, 0, 0.2);
            color: var(--accent-yellow);
        }}
        .confidence.low {{
            background: rgba(255, 51, 51, 0.2);
            color: var(--accent-red);
        }}
        .firewall-status, .waf-status {{
            padding: 10px 20px;
            border-radius: 4px;
            font-weight: bold;
            text-align: center;
            margin: 10px 0;
        }}
        .firewall-status.active, .waf-status.detected {{
            background: rgba(255, 51, 51, 0.2);
            color: var(--accent-red);
        }}
        .firewall-status.inactive, .waf-status.not-detected {{
            background: rgba(0, 255, 65, 0.2);
            color: var(--accent-green);
        }}
        .firewall-details p, .waf-signals {{
            color: var(--text-secondary);
            margin: 5px 0;
        }}
        .waf-signals ul {{
            list-style: none;
            padding-left: 10px;
        }}
        .waf-signals li {{
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
        .high-risk {{
            background: rgba(255, 51, 51, 0.1);
            border: 1px solid var(--accent-red);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .high-risk h3 {{
            color: var(--accent-red);
        }}
        footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 30px;
        }}
        .timestamp {{
            color: var(--accent-cyan);
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>GHOSTSCAN // REPORT</h1>
            <div class="meta">
                Target: <strong>{scan.get('resolved_target', 'N/A')}</strong> |
                Scan Date: <span class="timestamp">{scan.get('started_at', '')}</span>
            </div>
        </div>
    </header>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card {'danger' if open_count > 0 else 'success'}">
                <div class="stat-value">{open_count}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{ports_scanned}</div>
                <div class="stat-label">Ports Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{scan.get('scan_duration_seconds', 0):.2f}s</div>
                <div class="stat-label">Scan Time</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{scan.get('total_duration_seconds', 0):.2f}s</div>
                <div class="stat-label">Total Time</div>
            </div>
        </div>"""

    risks = summary.get("high_risk_exposures", [])
    if risks:
        html_content += f"""
        <div class="high-risk">
            <h3>⚠ High Risk Exposures</h3>
            <p>{', '.join(risks)}</p>
        </div>"""

    html_content += f"""
        <div class="grid-2">
            <div class="card">
                <h3>Services Detected</h3>
                {services_html}
            </div>
            {firewall_html}
            {waf_html}
        </div>

        <div class="card">
            <h3>Open Port Details</h3>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Transport</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {results_html}
                </tbody>
            </table>
        </div>
    </div>

    <footer>
        <div class="container">
            Generated by GhostScan v1.2.0 |
            <span class="timestamp">{datetime.now().isoformat()}</span>
        </div>
    </footer>
</body>
</html>"""

    output_path.write_text(html_content, encoding="utf-8")
    return output_path


def get_available_profiles() -> Dict[str, str]:
    """Return available scan profiles and their descriptions."""
    from scanner import PortScanner
    return {name: profile.description for name, profile in PortScanner.PROFILES.items()}