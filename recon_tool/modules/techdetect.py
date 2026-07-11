import argparse
import json
import logging
import re
import socket

import requests

logger = logging.getLogger("recon_tool")

# signatures used to guess which CMS a site is running
CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes"],
    "Joomla": ["/media/jui/", "Joomla!"],
    "Drupal": ["sites/all/themes", "Drupal.settings"],
    "Shopify": ["cdn.shopify.com"],
    "Wix": ["wix.com", "_wixCIDX"],
}

# signatures used to guess which JS libraries a site is using
JS_SIGNATURES = {
    "jQuery": ["jquery.js", "jquery.min.js"],
    "Bootstrap": ["bootstrap.css", "bootstrap.min.css"],
    "React": ["react.js", "data-reactroot"],
    "Vue.js": ["vue.js", "__vue__"],
    "Angular": ["ng-app", "ng-version"],
}

# security headers a well configured site should have
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def get_ip(target):
    # remove http/https in case a full url was passed instead of just a domain
    hostname = re.sub(r"^https?://", "", target).split("/")[0]
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def find_matches(page_source, signature_dict):
    found = []
    for tech_name, keywords in signature_dict.items():
        for keyword in keywords:
            if keyword.lower() in page_source.lower():
                found.append(tech_name)
                break
    return found


def run_techdetect(target):
    # this is the function main.py calls
    url = target if target.startswith("http") else "http://" + target

    result = {
        "resolved_ip": get_ip(target),
        "status_code": None,
        "server": None,
        "cms": [],
        "js_libraries": [],
        "security_headers_missing": [],
        "error": None,
    }

    try:
        response = requests.get(url, timeout=8, headers={"User-Agent": "ReconTool/1.0"})
        page = response.text

        result["status_code"] = response.status_code
        result["server"] = response.headers.get("Server", "Unknown")
        result["cms"] = find_matches(page, CMS_SIGNATURES)
        result["js_libraries"] = find_matches(page, JS_SIGNATURES)
        result["security_headers_missing"] = [
            h for h in SECURITY_HEADERS if h not in response.headers
        ]

        logger.info(f"Tech detection completed for {target}")

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        logger.error(f"Tech detection failed for {target}: {e}")

    return result


# lets this file be tested on its own, without running the full tool
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect technologies used by a website")
    parser.add_argument("--target", required=True, help="domain or URL to scan")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity level")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    print(json.dumps(run_techdetect(args.target), indent=2))
