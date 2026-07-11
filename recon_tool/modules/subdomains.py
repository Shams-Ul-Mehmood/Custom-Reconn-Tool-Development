import json
import logging
import socket
import time
import concurrent.futures

logger = logging.getLogger("recon_tool")


REQUEST_TIMEOUT      = 15        # default timeout for OTX / HackerTarget
CRTSH_TIMEOUT        = 25        # crt.sh is a free public service and is often slow
MAX_RETRIES          = 3         # transient-failure retries per source
RETRY_BACKOFF_BASE   = 1.5       # seconds, doubles/1.5x's each retry
BRUTE_FORCE_TIMEOUT  = 2         # per-name DNS timeout for the offline fallback
BRUTE_FORCE_WORKERS  = 20

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# A small, common wordlist used ONLY as a last-resort, fully-offline fallback
# (plain DNS resolution, no external API) so the module always has a chance
# to return *something* useful even if crt.sh / OTX / HackerTarget are all
# unreachable (blocked network, rate limited, down, etc.).
COMMON_SUBDOMAIN_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
    "ns1", "ns2", "ns3", "dns", "mx", "autodiscover", "autoconfig",
    "vpn", "remote", "portal", "secure", "login", "sso", "auth",
    "api", "api1", "api2", "dev", "development", "staging", "stage",
    "test", "testing", "qa", "uat", "demo", "sandbox",
    "admin", "administrator", "cpanel", "whm", "webdisk",
    "blog", "shop", "store", "support", "help", "helpdesk",
    "cdn", "static", "assets", "img", "images", "media",
    "m", "mobile", "app", "apps",
    "git", "gitlab", "github", "jenkins", "jira", "confluence",
    "status", "monitor", "grafana", "kibana",
    "cloud", "cluster", "docs", "wiki", "forum",
    "beta", "old", "new", "internal", "intranet", "extranet",
]


_EMPTY_RESULT = {
    "domain":      None,
    "subdomains":  [],
    "count":       0,
    "sources":     {"crtsh": 0, "otx": 0, "hackertarget": 0, "bruteforce": 0},
}


def run_subdomains(target: str) -> dict:
    """
    Enumerate subdomains for a target domain using three independent,
    fail-soft external sources -- crt.sh (Certificate Transparency logs),
    AlienVault OTX (passive DNS), and HackerTarget (hostsearch) -- plus an
    offline DNS brute-force fallback so the module never hard-fails just
    because one or two public APIs happen to be down, slow, or rate
    limiting the caller.

    Parameters:
        target (str): Domain e.g. "hackthissite.org"

    Returns:
        dict with keys:
            domain, subdomains, count, sources
        "subdomains" is always a clean, deduplicated,
        sorted list of strings.
        "sources" reports how many results came from
        each method, for transparency in the report.
    """
    logger.debug(f"[SUBDOMAINS] Starting enumeration for: {target}")

    # Step 1 -- check requests is available
    try:
        import requests
    except ImportError:
        msg = "requests not installed. Run: pip3 install requests"
        logger.error(f"[SUBDOMAINS] {msg}")
        return {**_EMPTY_RESULT, "domain": target, "error": msg}

    session = _build_session(requests)

    # Step 2 -- query each source independently (fail-soft)
    crtsh_subs, crtsh_err = _query_crtsh(target, session, requests)
    otx_subs, otx_err = _query_otx(target, session, requests)
    ht_subs, ht_err = _query_hackertarget(target, session, requests)

    all_api_subs = crtsh_subs + otx_subs + ht_subs

    # Step 3 -- offline brute-force fallback, ONLY if the APIs came back
    # empty. This guarantees the module can still surface real, resolvable
    # subdomains even with no working internet access to the APIs above
    # (corporate proxy, blocked outbound, rate limiting, API downtime, etc).
    brute_subs = []
    if not all_api_subs:
        logger.warning(
            "[SUBDOMAINS] All external APIs returned nothing usable -- "
            "falling back to offline DNS brute force."
        )
        brute_subs = _bruteforce_dns(target)

    # Step 4 -- merge, clean, dedupe
    merged = _merge_and_clean(all_api_subs + brute_subs, target)

    result = {
        "domain":     target,
        "subdomains": merged,
        "count":      len(merged),
        "sources": {
            "crtsh":        len(crtsh_subs),
            "otx":          len(otx_subs),
            "hackertarget": len(ht_subs),
            "bruteforce":   len(brute_subs),
        },
    }

    # Surface *why* a source failed (if it did) -- helps a lot when
    # debugging in the field instead of just seeing "0" with no context.
    source_errors = {}
    if crtsh_err:
        source_errors["crtsh"] = crtsh_err
    if otx_err:
        source_errors["otx"] = otx_err
    if ht_err:
        source_errors["hackertarget"] = ht_err
    if source_errors:
        result["source_errors"] = source_errors

    if result["count"] == 0:
        result["error"] = (
            "No subdomains found via crt.sh, AlienVault OTX, HackerTarget, "
            "or offline DNS brute force. The domain may genuinely have no "
            "publicly-logged subdomains, or all sources are unreachable "
            "from this network -- see 'source_errors' for details."
        )

    logger.info(
        f"[SUBDOMAINS] Done for {target} | "
        f"total={result['count']} "
        f"(crt.sh={result['sources']['crtsh']}, "
        f"otx={result['sources']['otx']}, "
        f"hackertarget={result['sources']['hackertarget']}, "
        f"bruteforce={result['sources']['bruteforce']})"
    )
    return result


# ---------------------------------------------------
# Shared HTTP session w/ retry-with-backoff
# ---------------------------------------------------

def _build_session(requests):
    """
    Builds a requests.Session with a real browser-like User-Agent
    (several of these APIs are picky about default python-requests UA
    strings) and an automatic retry policy for the transient failures
    that are extremely common on free public recon APIs (429 rate
    limits, 502/503/504 from overloaded backends).
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
    })

    try:
        from requests.adapters import HTTPAdapter
        try:
            from urllib3.util.retry import Retry
        except ImportError:
            from requests.packages.urllib3.util.retry import Retry

        retry = Retry(
            total=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF_BASE,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
    except Exception as e:
        # If urllib3's Retry isn't available for some reason, we still
        # fall back gracefully to manual per-call retries below.
        logger.debug(f"[SUBDOMAINS] Could not attach urllib3 Retry adapter: {e}")

    return session


def _manual_retry_get(session, url, timeout, requests):
    """
    A small manual retry loop layered on top of the session's own retry
    adapter. This catches things the adapter can't (connection resets,
    read timeouts) and is what actually saves runs against crt.sh, which
    times out or resets connections under load far more often than it
    returns a clean 5xx.
    """
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return session.get(url, timeout=timeout), None
        except requests.exceptions.Timeout as e:
            last_exc = f"timeout on attempt {attempt}/{MAX_RETRIES}"
        except requests.exceptions.ConnectionError as e:
            last_exc = f"connection error on attempt {attempt}/{MAX_RETRIES}: {e}"
        except requests.exceptions.RequestException as e:
            last_exc = f"request error on attempt {attempt}/{MAX_RETRIES}: {e}"

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_BACKOFF_BASE * attempt)

    return None, last_exc


# ---------------------------------------------------
# Private: query crt.sh
# ---------------------------------------------------

def _query_crtsh(target: str, session, requests) -> tuple:
    """
    Query crt.sh certificate transparency logs.
    Returns (list_of_raw_subdomains, error_message_or_None).
    Never raises.
    """
    url = f"https://crt.sh/?q=%25.{target}&output=json"

    logger.debug(f"[SUBDOMAINS] Querying crt.sh for {target} ...")
    resp, err = _manual_retry_get(session, url, CRTSH_TIMEOUT, requests)

    if resp is None:
        logger.warning(f"[SUBDOMAINS] crt.sh failed after retries: {err}")
        return [], err

    if resp.status_code != 200:
        msg = f"crt.sh returned status {resp.status_code}"
        logger.warning(f"[SUBDOMAINS] {msg}")
        return [], msg

    if not resp.text or not resp.text.strip():
        msg = "crt.sh returned an empty body"
        logger.warning(f"[SUBDOMAINS] {msg}")
        return [], msg

    data = _parse_crtsh_json(resp.text)
    if data is None:
        msg = "crt.sh returned malformed/non-JSON output that could not be parsed"
        logger.warning(f"[SUBDOMAINS] {msg}")
        return [], msg

    found = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        # name_value can contain multiple names separated by newlines
        for name in name_value.split("\n"):
            found.add(name.strip())

    results = list(found)
    logger.debug(f"[SUBDOMAINS] crt.sh returned {len(results)} entries")
    return results, None


def _parse_crtsh_json(text: str):
    """
    crt.sh's JSON endpoint is notoriously unreliable about producing a
    single valid JSON array: under load it sometimes streams back
    multiple JSON objects concatenated directly against each other
    (e.g. "...}{ ..."), which breaks a plain json.loads() call and used
    to cause this module to silently treat a large domain (with lots of
    certs, e.g. tesla.com) as a total failure. This tries a normal parse
    first, then falls back to repairing the concatenated-object case.
    """
    try:
        return json.loads(text)
    except ValueError:
        pass

    try:
        repaired = "[{}]".format(text.strip().replace("}{", "},{"))
        return json.loads(repaired)
    except ValueError:
        pass

    # last resort: parse one JSON object at a time via a raw decoder
    try:
        decoder = json.JSONDecoder()
        idx = 0
        text = text.strip()
        objects = []
        while idx < len(text):
            # skip separators/whitespace between objects
            while idx < len(text) and text[idx] in " \t\n\r,[]":
                idx += 1
            if idx >= len(text):
                break
            obj, end = decoder.raw_decode(text, idx)
            objects.append(obj)
            idx = end
        return objects if objects else None
    except ValueError:
        return None


# ---------------------------------------------------
# Private: query AlienVault OTX
# ---------------------------------------------------

def _query_otx(target: str, session, requests) -> tuple:
    """
    Query AlienVault OTX passive DNS API.
    Returns (list_of_raw_subdomains, error_message_or_None).
    Never raises.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"

    logger.debug(f"[SUBDOMAINS] Querying AlienVault OTX for {target} ...")
    resp, err = _manual_retry_get(session, url, REQUEST_TIMEOUT, requests)

    if resp is None:
        logger.warning(f"[SUBDOMAINS] OTX failed after retries: {err}")
        return [], err

    if resp.status_code != 200:
        msg = f"OTX returned status {resp.status_code}"
        logger.warning(f"[SUBDOMAINS] {msg}")
        return [], msg

    try:
        data = resp.json()
    except ValueError as e:
        msg = f"OTX returned invalid JSON: {e}"
        logger.warning(f"[SUBDOMAINS] {msg}")
        return [], msg

    entries = data.get("passive_dns", [])

    found = set()
    for entry in entries:
        hostname = entry.get("hostname", "")
        if hostname:
            found.add(hostname.strip())

    results = list(found)
    logger.debug(f"[SUBDOMAINS] OTX returned {len(results)} entries")
    return results, None


# ---------------------------------------------------
# Private: query HackerTarget (third, independent source)
# ---------------------------------------------------

def _query_hackertarget(target: str, session, requests) -> tuple:
    """
    Query the free HackerTarget hostsearch API. No key required.
    This exists as a third, independent data source so the module isn't
    solely dependent on crt.sh and OTX both being healthy at the same
    time -- in practice at least one of the three tends to work.
    Returns (list_of_raw_subdomains, error_message_or_None).
    Never raises.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={target}"

    logger.debug(f"[SUBDOMAINS] Querying HackerTarget for {target} ...")
    resp, err = _manual_retry_get(session, url, REQUEST_TIMEOUT, requests)

    if resp is None:
        logger.warning(f"[SUBDOMAINS] HackerTarget failed after retries: {err}")
        return [], err

    if resp.status_code != 200:
        msg = f"HackerTarget returned status {resp.status_code}"
        logger.warning(f"[SUBDOMAINS] {msg}")
        return [], msg

    text = (resp.text or "").strip()

    # HackerTarget returns plain-text error strings instead of an HTTP
    # error code (e.g. rate limit hit, invalid domain, no records).
    if not text or "error" in text.lower() or "api count exceeded" in text.lower():
        msg = f"HackerTarget returned no usable data: {text[:120]!r}"
        logger.warning(f"[SUBDOMAINS] {msg}")
        return [], msg

    found = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # format is "subdomain,ip"
        hostname = line.split(",")[0].strip()
        if hostname:
            found.add(hostname)

    results = list(found)
    logger.debug(f"[SUBDOMAINS] HackerTarget returned {len(results)} entries")
    return results, None


# ---------------------------------------------------
# Private: offline DNS brute-force (final, no-API fallback)
# ---------------------------------------------------

def _bruteforce_dns(target: str) -> list:
    """
    Pure-DNS, no-external-API fallback. Tries a small list of very common
    subdomain names and keeps whichever ones actually resolve. This is
    what guarantees the module can still do *something* useful even if
    crt.sh, OTX, and HackerTarget are all blocked, down, or rate-limited
    on the machine running the tool.
    """
    found = []

    def _try_resolve(name):
        host = f"{name}.{target}"
        try:
            socket.setdefaulttimeout(BRUTE_FORCE_TIMEOUT)
            socket.gethostbyname(host)
            return host
        except (socket.gaierror, socket.timeout, OSError):
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=BRUTE_FORCE_WORKERS) as pool:
        for host in pool.map(_try_resolve, COMMON_SUBDOMAIN_WORDLIST):
            if host:
                found.append(host)

    logger.debug(f"[SUBDOMAINS] Offline brute force resolved {len(found)} entries")
    return found


# ---------------------------------------------------
# Private: merge, clean, dedupe, sort
# ---------------------------------------------------

def _merge_and_clean(raw_list: list, target: str) -> list:
    """
    Takes raw subdomain strings from all sources and:
      - lowercases + strips them
      - drops empty / malformed entries
      - drops wildcard entries (e.g. "*.example.com")
      - keeps only names that actually belong to the target domain
      - deduplicates
      - returns a sorted list
    """
    target_clean = target.strip().lower()
    cleaned = set()

    for item in raw_list:
        if not item:
            continue

        name = item.strip().lower()

        # Skip wildcard certificate entries
        if name.startswith("*."):
            name = name[2:]

        # Skip anything that isn't actually a subdomain of the target
        # (protects against unrelated data slipping in from either API)
        if name != target_clean and not name.endswith("." + target_clean):
            continue

        if name:
            cleaned.add(name)

    return sorted(cleaned)


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # Change this to test any domain you want, or pass it as an argv.
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    print()
    print("=" * 55)
    print(f"  SUBDOMAIN ENUMERATION TEST")
    print(f"  Target: {target}")
    print("=" * 55)

    result = run_subdomains(target)

    print()
    print("FULL RESULT:")
    print(json.dumps(result, indent=2, default=str))

    print()
    print("PLAIN ENGLISH SUMMARY:")
    print(f"  Total Subdomains   : {result.get('count', 0)}")
    print(f"  crt.sh Results     : {result.get('sources', {}).get('crtsh', 0)}")
    print(f"  OTX Results        : {result.get('sources', {}).get('otx', 0)}")
    print(f"  HackerTarget Results: {result.get('sources', {}).get('hackertarget', 0)}")
    print(f"  Brute-force Results : {result.get('sources', {}).get('bruteforce', 0)}")
    for sub in result.get("subdomains", []):
        print(f"    -> {sub}")

    if "source_errors" in result:
        print()
        print("SOURCE ERRORS:")
        for src, msg in result["source_errors"].items():
            print(f"  {src}: {msg}")

    if "error" in result:
        print(f"  ERROR: {result['error']}")

    print()
    print("KEY CHECK (confirms integration format):")
    required = ["domain", "subdomains", "count", "sources"]
    for key in required:
        status = "OK" if key in result else "MISSING"
        print(f"  [{status}] {key}")
