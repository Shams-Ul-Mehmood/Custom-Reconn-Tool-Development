import logging


logger = logging.getLogger("recon_tool")


_EMPTY_RESULT = {
    "registrar":        None,
    "creation_date":    None,
    "expiration_date":  None,
    "name_servers":     [],
    "emails":           [],
    "org":              None,
    "country":          None,
}


def run_whois(target: str) -> dict:
    """
    Perform WHOIS lookup on a domain.

    Parameters:
        target (str): Domain or IP e.g. "hackthissite.org"

    Returns:
        dict with keys:
            registrar, creation_date, expiration_date,
            name_servers, emails, org, country
    """
    logger.debug(f"[WHOIS] Starting lookup for: {target}")

    # Step 1 -- import the library
    try:
        import whois as whois_lib
    except ImportError:
        msg = "python-whois not installed. Run: pip3 install python-whois"
        logger.error(f"[WHOIS] {msg}")
        return {**_EMPTY_RESULT, "error": msg}

    # Step 2 -- query the WHOIS registry
    try:
        logger.info(f"[WHOIS] Querying registry for: {target}")
        data = whois_lib.whois(target)
    except Exception as e:
        logger.error(f"[WHOIS] Query failed for {target}: {e}")
        return {**_EMPTY_RESULT, "error": str(e)}

    # Step 3 -- build clean result with all fixed keys
    result = {
        "registrar":       _clean_str(data.registrar),
        "creation_date":   _clean_date(data.creation_date),
        "expiration_date": _clean_date(data.expiration_date),
        "name_servers":    _clean_list(data.name_servers),
        "emails":          _clean_list(data.emails),
        "org":             _clean_str(data.get("org")),
        "country":         _clean_str(data.get("country")),
    }

    logger.info(f"[WHOIS] Done. Registrar: {result['registrar']}")
    logger.debug(f"[WHOIS] Created  : {result['creation_date']}")
    logger.debug(f"[WHOIS] Expires  : {result['expiration_date']}")
    logger.debug(f"[WHOIS] NS count : {len(result['name_servers'])}")
    return result

# Helper functions

def _clean_str(value):
    """
    python-whois sometimes returns a list even for
    single-value fields. Always returns plain string or None.
    """
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            if item:
                return str(item).strip()
        return None
    return str(value).strip()


def _clean_date(value):
    """
    Dates come back as datetime objects or lists of datetimes.
    Always converts to a readable string.
    """
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0]
    return str(value).strip() if value else None


def _clean_list(value):
    """
    Fields like name_servers and emails can be None,
    a string, or a list. Always returns a clean
    deduplicated list of lowercase strings.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip().lower()]
    if isinstance(value, list):
        seen = set()
        clean = []
        for item in value:
            if item:
                item_clean = str(item).strip().lower()
                if item_clean not in seen:
                    seen.add(item_clean)
                    clean.append(item_clean)
        return clean
    return []




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
    print(f"  WHOIS LOOKUP TEST")
    print(f"  Target: {target}")
    print("=" * 55)

    result = run_whois(target)

    print()
    print("FULL RESULT:")
    print(json.dumps(result, indent=2, default=str))

    print()
    print("PLAIN ENGLISH SUMMARY:")
    print(f"  Registrar    : {result.get('registrar', 'N/A')}")
    print(f"  Organisation : {result.get('org', 'N/A')}")
    print(f"  Country      : {result.get('country', 'N/A')}")
    print(f"  Created      : {result.get('creation_date', 'N/A')}")
    print(f"  Expires      : {result.get('expiration_date', 'N/A')}")
    print(f"  Name Servers : {len(result.get('name_servers', []))} found")
    for ns in result.get("name_servers", []):
        print(f"    -> {ns}")
    print(f"  Emails       : {len(result.get('emails', []))} found")
    for email in result.get("emails", []):
        print(f"    -> {email}")

    print()
    print("KEY CHECK (confirms integration format):")
    required = [
        "registrar", "creation_date",
        "expiration_date", "name_servers",
        "emails", "org", "country"
    ]
    for key in required:
        status = "OK" if key in result else "MISSING"
        print(f"  [{status}] {key}")