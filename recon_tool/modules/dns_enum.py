import logging

logger = logging.getLogger("recon_tool")


RECORD_TYPES = ["A", "MX", "TXT", "NS"]


DNS_TIMEOUT = 5


def run_dns(target: str) -> dict:
    """
    Query A, MX, TXT, NS DNS records for a domain.

    Parameters:
        target (str): Domain e.g. "hackthissite.org"

    Returns:
        dict with keys: A, MX, TXT, NS, summary
        Each record value is always a list of strings.
        summary contains plain English analysis.
    """
    logger.debug(f"[DNS] Starting enumeration for: {target}")

    # Check library is available
    try:
        import dns.resolver
    except ImportError:
        msg = "dnspython not installed. Run: pip3 install dnspython"
        logger.error(f"[DNS] {msg}")
        return {
            "A":   [], "MX":  [],
            "TXT": [], "NS":  [],
            "summary": {},
            "error": msg
        }

    # Start with all keys present and empty
    result = {
        "A":   [],
        "MX":  [],
        "TXT": [],
        "NS":  [],
    }

    # Query each record type one by one
    for rtype in RECORD_TYPES:
        result[rtype] = _query(target, rtype)

    # Build plain English summary
    result["summary"] = _build_summary(result)

    logger.info(
        f"[DNS] Done for {target} | "
        f"A={len(result['A'])} "
        f"MX={len(result['MX'])} "
        f"TXT={len(result['TXT'])} "
        f"NS={len(result['NS'])}"
    )
    return result


# ---------------------------------------------------
# Private: query one record type
# ---------------------------------------------------

def _query(target: str, rtype: str) -> list:
    """
    Query one DNS record type.
    Returns list of strings.
    Returns empty list on ANY error.
    Never raises exceptions.
    """
    import dns.resolver
    import dns.exception

    try:
        logger.debug(f"[DNS] Querying {rtype} for {target} ...")
        answers = dns.resolver.resolve(
            target,
            rtype,
            lifetime=DNS_TIMEOUT
        )
        records = [str(r).strip() for r in answers]
        logger.debug(f"[DNS] {rtype} found: {records}")
        return records

    except dns.resolver.NoAnswer:
        # Domain exists but no records of this type
        # This is completely normal
        logger.debug(f"[DNS] No {rtype} records for {target}")
        return []

    except dns.resolver.NXDOMAIN:
        # Domain does not exist at all
        logger.warning(f"[DNS] Domain does not exist: {target}")
        return []

    except dns.resolver.Timeout:
        logger.warning(f"[DNS] Timeout querying {rtype} for {target}")
        return []

    except dns.resolver.NoNameservers:
        logger.warning(f"[DNS] No nameservers available for {target}")
        return []

    except dns.exception.DNSException as e:
        logger.warning(f"[DNS] DNS error ({rtype}): {e}")
        return []

    except Exception as e:
        logger.error(f"[DNS] Unexpected error ({rtype}): {e}")
        return []


# ---------------------------------------------------
# Private: build plain English summary
# ---------------------------------------------------

def _build_summary(results: dict) -> dict:
    """
    Reads the raw DNS records and produces a plain
    English analysis. This is what makes the report
    useful for non-experts.
    """
    summary = {}

    # ── A Records analysis ──────────────────────────
    a_records = results.get("A", [])
    summary["total_a_records"] = len(a_records)

    if len(a_records) > 1:
        summary["load_balanced"] = True
        summary["load_balance_note"] = (
            f"{len(a_records)} A records found -- "
            f"suggests load balancing or CDN"
        )
    else:
        summary["load_balanced"] = False

    # ── MX Records analysis (mail provider) ─────────
    mx_records = results.get("MX", [])
    summary["has_mx"] = len(mx_records) > 0

    if mx_records:
        mx_str = " ".join(mx_records).lower()
        if "google" in mx_str or "gmail" in mx_str:
            summary["mail_provider"] = "Google (Gmail / Workspace)"
        elif "outlook" in mx_str or "microsoft" in mx_str:
            summary["mail_provider"] = "Microsoft (Office 365)"
        elif "mimecast" in mx_str:
            summary["mail_provider"] = "Mimecast"
        elif "proofpoint" in mx_str:
            summary["mail_provider"] = "Proofpoint"
        elif "amazonses" in mx_str or "amazonaws" in mx_str:
            summary["mail_provider"] = "Amazon SES"
        else:
            summary["mail_provider"] = "Unknown / Self-hosted"
    else:
        summary["mail_provider"] = "No MX records found"

    # ── TXT Records analysis ────────────────────────
    txt_records = results.get("TXT", [])
    txt_str = " ".join(txt_records).lower()

    summary["has_spf"]   = "v=spf1" in txt_str
    summary["has_dmarc"] = "v=dmarc" in txt_str

    # Find domain verification tokens
    verification = []
    for record in txt_records:
        r = record.lower()
        if "google-site-verification" in r:
            verification.append("Google Site Verification")
        if "facebook-domain-verification" in r:
            verification.append("Facebook Domain Verification")
        if "ms=" in r:
            verification.append("Microsoft Domain Verification")
        if "t-verify=" in r:
            verification.append("HackThisSite Verification Token")
        if "harica" in r:
            verification.append("Harica Certificate Verification")
    if verification:
        summary["verification_tokens"] = verification

    # ── NS Records analysis (DNS provider) ──────────
    ns_records = results.get("NS", [])
    summary["nameserver_count"] = len(ns_records)

    if ns_records:
        ns_str = " ".join(ns_records).lower()
        if "buddyns" in ns_str:
            summary["dns_provider"] = "BuddyNS"
        elif "cloudflare" in ns_str:
            summary["dns_provider"] = "Cloudflare"
        elif "awsdns" in ns_str:
            summary["dns_provider"] = "Amazon Route 53"
        elif "google" in ns_str:
            summary["dns_provider"] = "Google Cloud DNS"
        elif "azure-dns" in ns_str:
            summary["dns_provider"] = "Microsoft Azure DNS"
        else:
            summary["dns_provider"] = "Unknown / Custom"
    else:
        summary["dns_provider"] = "No NS records found"

    return summary




if __name__ == "__main__":
    import json

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # Change this to test any domain you want
    target = "hackthissite.org"

    print()
    print("=" * 55)
    print(f"  DNS ENUMERATION TEST")
    print(f"  Target: {target}")
    print("=" * 55)

    result = run_dns(target)

    print()
    print("FULL RESULT:")
    print(json.dumps(result, indent=2, default=str))

    print()
    print("PLAIN ENGLISH SUMMARY:")
    s = result.get("summary", {})
    a = result.get("A", [])
    print(f"  IP Addresses   : {len(a)} found")
    for ip in a:
        print(f"    -> {ip}")
    print(f"  Load Balanced  : {s.get('load_balanced', False)}")
    print(f"  Mail Provider  : {s.get('mail_provider', 'N/A')}")
    print(f"  DNS Provider   : {s.get('dns_provider', 'N/A')}")
    print(f"  SPF Configured : {s.get('has_spf', False)}")
    print(f"  DMARC Present  : {s.get('has_dmarc', False)}")
    if s.get("verification_tokens"):
        print(f"  Verifications  :")
        for v in s["verification_tokens"]:
            print(f"    -> {v}")

    print()
    print("KEY CHECK (confirms integration format):")
    for key in ["A", "MX", "TXT", "NS", "summary"]:
        count = len(result.get(key, []))
        if key == "summary":
            status = "OK" if "summary" in result else "MISSING"
            print(f"  [{status}] summary: {len(result.get('summary', {}))} fields")
        else:
            print(f"  [OK] {key}: {count} record(s) found")