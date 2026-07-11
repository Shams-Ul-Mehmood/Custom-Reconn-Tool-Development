import argparse
import json
import logging
import os
import socket
from datetime import datetime

logger = logging.getLogger("recon_tool")

# order the sections will appear in the report
SECTIONS = ["whois", "dns", "subdomains", "ports", "techdetect"]


def calculate_risk_score(results):
    """
    Looks at data from all modules and gives a simple risk score.
    This is not a replacement for real security testing, just a
    quick summary to highlight things worth looking into.
    """
    score = 0
    reasons = []

    tech = results.get("techdetect") or {}
    missing_headers = tech.get("security_headers_missing", [])
    if missing_headers:
        score += min(len(missing_headers) * 2, 6)
        reasons.append(f"{len(missing_headers)} security header(s) missing")

    dns_summary = (results.get("dns") or {}).get("summary", {})
    if dns_summary.get("has_spf") is False:
        score += 2
        reasons.append("SPF record not configured")
    if dns_summary.get("has_dmarc") is False:
        score += 2
        reasons.append("DMARC record not configured")

    ports_data = (results.get("ports") or {}).get("data", {})
    open_ports = ports_data.get("open_ports", [])
    if open_ports:
        score += len(open_ports)
        reasons.append(f"{len(open_ports)} open port(s) found")

    if score >= 8:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    return {"score": score, "level": level, "reasons": reasons}


def get_ip(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def format_value_text(value, indent=1):
    # recursively formats nested dicts/lists so nothing prints as raw python repr
    pad = "  " * indent
    if isinstance(value, dict):
        lines = []
        for k, v in value.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines.append(format_value_text(v, indent + 1))
            else:
                lines.append(f"{pad}{k}: {v}")
        return "\n".join(lines)
    elif isinstance(value, list):
        if not value:
            return f"{pad}(none)"
        lines = []
        for item in value:
            if isinstance(item, dict):
                item_lines = format_value_text(item, indent + 1).splitlines()
                if item_lines:
                    lines.append(f"{pad}-")
                    lines.extend(item_lines)
            elif isinstance(item, list):
                lines.append(format_value_text(item, indent))
            else:
                lines.append(f"{pad}- {item}")
        return "\n".join(lines)
    else:
        return f"{pad}{value}"


def format_section_text(name, data):
    # some modules might not have run yet, so handle missing data gracefully
    if not data:
        return f"[{name.upper()}]\n  Not available yet.\n"

    return f"[{name.upper()}]\n" + format_value_text(data) + "\n"


def generate_txt_report(results, target):
    ip = get_ip(target)
    risk = calculate_risk_score(results)

    header = (
        "=" * 50 + "\n"
        f"Recon Report for: {target}\n"
        f"Generated on: {datetime.now().isoformat()}\n"
        f"Resolved IP: {ip or 'could not resolve'}\n"
        + "=" * 50 + "\n\n"
        + "SECURITY POSTURE SUMMARY\n"
        + ("-" * 25) + "\n"
        + f"Risk Score : {risk['score']} ({risk['level']} Risk)\n"
    )

    if risk["reasons"]:
        for reason in risk["reasons"]:
            header += f"  - {reason}\n"
    else:
        header += "  - No obvious issues found\n"

    header += "\n"

    body = ""
    for section in SECTIONS:
        body += format_section_text(section, results.get(section)) + "\n"

    return header + body


def format_value_html(value):
    # recursively formats nested dicts/lists into tables/lists instead of raw python repr
    if isinstance(value, dict):
        rows = "".join(f"<tr><td>{k}</td><td>{format_value_html(v)}</td></tr>" for k, v in value.items())
        return f"<table>{rows}</table>"
    elif isinstance(value, list):
        if not value:
            return "<i>none</i>"
        items = "".join(f"<li>{format_value_html(item)}</li>" for item in value)
        return f"<ul>{items}</ul>"
    else:
        return str(value)


def format_section_html(name, data):
    if not data:
        return f"<h2>{name.title()}</h2><p>Not available yet.</p>"

    return f"<h2>{name.title()}</h2>{format_value_html(data)}"


def generate_html_report(results, target):
    ip = get_ip(target)
    risk = calculate_risk_score(results)
    sections_html = "".join(format_section_html(s, results.get(s)) for s in SECTIONS)

    reasons_html = "".join(f"<li>{r}</li>" for r in risk["reasons"]) or "<li>No obvious issues found</li>"

    return f"""<html>
<head>
<title>Recon Report - {target}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 2rem; }}
  h1 {{ color: #333; }}
  h2 {{ color: #555; border-bottom: 1px solid #ccc; }}
  table {{ border-collapse: collapse; }}
  td {{ padding: 5px 10px; }}
  td:first-child {{ font-weight: bold; }}
  .risk-box {{ border: 1px solid #ccc; padding: 1rem; margin: 1rem 0; background: #f9f9f9; }}
  .risk-high {{ color: #c0392b; }}
  .risk-medium {{ color: #d68910; }}
  .risk-low {{ color: #27ae60; }}
</style>
</head>
<body>
  <h1>Reconnaissance Report</h1>
  <p><b>Target:</b> {target}</p>
  <p><b>Resolved IP:</b> {ip or 'could not resolve'}</p>
  <p><b>Generated on:</b> {datetime.now().isoformat()}</p>

  <div class="risk-box">
    <h2>Security Posture Summary</h2>
    <p>Risk Score: <b class="risk-{risk['level'].lower()}">{risk['score']} ({risk['level']} Risk)</b></p>
    <ul>{reasons_html}</ul>
  </div>

  {sections_html}
</body>
</html>"""


def generate_json_report(results, target, output_dir="reports"):
    # useful for automation or feeding the data into another tool
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"{target}_report.json")

    export = {
        "target": target,
        "generated_on": datetime.now().isoformat(),
        "resolved_ip": get_ip(target),
        "risk_score": calculate_risk_score(results),
        "results": results,
    }

    with open(json_path, "w") as f:
        json.dump(export, f, indent=2, default=str)

    logger.info(f"JSON report saved to {json_path}")
    return json_path


def generate_report(results, target, output_dir="reports"):
    # this is the function main.py calls, always, at the end of every run
    os.makedirs(output_dir, exist_ok=True)

    txt_path = os.path.join(output_dir, f"{target}_report.txt")
    html_path = os.path.join(output_dir, f"{target}_report.html")

    with open(txt_path, "w") as f:
        f.write(generate_txt_report(results, target))

    with open(html_path, "w") as f:
        f.write(generate_html_report(results, target))

    logger.info(f"Reports saved to {txt_path} and {html_path}")
    return txt_path, html_path


# lets this file be tested on its own, without running the full tool
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a recon report from a results JSON file")
    parser.add_argument("--input", required=True, help="path to a JSON file with combined results")
    parser.add_argument("--target", required=True, help="target the results belong to")
    parser.add_argument("--format", choices=["txt", "html", "json", "all"], default="all",
                         help="which report format to generate")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity level")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    with open(args.input) as f:
        results = json.load(f)

    if args.format in ("txt", "html", "all"):
        generate_report(results, args.target)
    if args.format in ("json", "all"):
        generate_json_report(results, args.target)
