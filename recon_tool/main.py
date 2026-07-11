
from utils.logger import setup_logger

# Member 2 - WHOIS and DNS (UNCOMMENTED AND READY)
from modules.whois_lookup import run_whois
from modules.dns_enum     import run_dns

# Member 3 - Subdomain Enumeration (UNCOMMENTED AND READY)
from modules.subdomains import run_subdomains

# Member 4 - Ports Scanning
from modules.portscan   import *

# Other Members
from modules.techdetect import run_techdetect
from modules.report import generate_report





def main():
    args   = parse_arguments()
    logger = setup_logger(args.verbose)

    logger.info(f"Starting recon on target: {args.target}")

    results = {}

    # ── WHOIS (Member 2) ─────────────────────────────────
    if args.whois:
        logger.info("Running WHOIS lookup...")
        results['whois'] = run_whois(args.target)

        w = results['whois']
        print()
        print("=" * 55)
        print("  WHOIS RESULTS")
        print("=" * 55)
        print(f"  Registrar    : {w.get('registrar',        'N/A')}")
        print(f"  Organisation : {w.get('org',              'N/A')}")
        print(f"  Country      : {w.get('country',          'N/A')}")
        print(f"  Created      : {w.get('creation_date',    'N/A')}")
        print(f"  Expires      : {w.get('expiration_date',  'N/A')}")

        print(f"  Name Servers : {len(w.get('name_servers', []))} found")
        for ns in w.get('name_servers', []):
            print(f"    -> {ns}")

        print(f"  Emails       : {len(w.get('emails', []))} found")
        for email in w.get('emails', []):
            print(f"    -> {email}")

        if 'error' in w:
            print(f"  ERROR        : {w['error']}")
        print()

    # ── DNS (Member 2) ───────────────────────────────────
    if args.dns:
        logger.info("Running DNS enumeration...")
        results['dns'] = run_dns(args.target)

        d = results['dns']
        s = d.get('summary', {})

        print()
        print("=" * 55)
        print("  DNS RESULTS")
        print("=" * 55)

        print(f"  A Records ({len(d.get('A', []))} found -- IP Addresses):")
        for r in d.get('A', []):
            print(f"    -> {r}")

        print(f"  MX Records ({len(d.get('MX', []))} found -- Mail Servers):")
        for r in d.get('MX', []):
            print(f"    -> {r}")

        print(f"  TXT Records ({len(d.get('TXT', []))} found):")
        for r in d.get('TXT', []):
            print(f"    -> {r}")

        print(f"  NS Records ({len(d.get('NS', []))} found -- Name Servers):")
        for r in d.get('NS', []):
            print(f"    -> {r}")

        # Print the summary analysis
        print()
        print("  ANALYSIS:")
        print(f"    Load Balanced  : {s.get('load_balanced',    'N/A')}")
        print(f"    Mail Provider  : {s.get('mail_provider',    'N/A')}")
        print(f"    DNS Provider   : {s.get('dns_provider',     'N/A')}")
        print(f"    SPF Configured : {s.get('has_spf',          'N/A')}")
        print(f"    DMARC Present  : {s.get('has_dmarc',        'N/A')}")

        if s.get('verification_tokens'):
            print(f"    Verifications  :")
            for v in s['verification_tokens']:
                print(f"      -> {v}")

        if 'error' in d:
            print(f"  ERROR: {d['error']}")
        print()

    # ── Subdomains (Member 3) ────────────────────────────
    if args.subdomains:
        logger.info("Running Subdomain enumeration...")
        results['subdomains'] = run_subdomains(args.target)

        sd = results['subdomains']
        print()
        print("=" * 55)
        print("  SUBDOMAIN ENUMERATION RESULTS")
        print("=" * 55)
        print(f"  Target        : {sd.get('domain', args.target)}")
        print(f"  Total Found   : {sd.get('count', 0)}")
        print(f"  crt.sh        : {sd.get('sources', {}).get('crtsh', 0)} raw hits")
        print(f"  AlienVault OTX: {sd.get('sources', {}).get('otx', 0)} raw hits")
        print()
        for sub in sd.get('subdomains', []):
            print(f"    -> {sub}")

        if 'error' in sd:
            print(f"  ERROR        : {sd['error']}")
        print()

    # ── Port Scan (Member 4) ─────────────────────────────
    if args.ports:
        logger.info("Running Port scanning...")
        results['ports'] = run_portscan(
            args.target,
            args.ports,
            use_nmap=args.nmap,
            nmap_args=args.nmap_args,
            timeout=args.timeout,
            threads=args.threads,
            banners=args.banners,
        )
        ps = results["ports"]
 
        print()
        print("=" * 55)
        print("  PORTS SCANNING RESULTS")
        print("=" * 55)
 
        if not ps.get("success"):
            print(f"  ERROR        : {ps.get('error', 'Unknown error')}")
        else:
            data = ps.get("data", {})
            open_ports = data.get("open_ports", [])
            print(f"  Target       : {ps.get('target', args.target)}")
            print(f"  Resolved IP  : {data.get('resolved_ip', 'N/A')}")
            print(f"  Backend      : {data.get('backend', 'N/A')}")
            print(f"  Scanned      : {data.get('scanned_port_count', 0)} port(s)")
            print(f"  Duration     : {data.get('duration_sec', 'N/A')}s")
            print(f"  Open Ports   : {len(open_ports)} found")
            print()
            for port in open_ports:
                line = f"    -> {port.get('port')}/tcp"
                if port.get('service'):
                    line += f"  {port.get('service')}"
                if port.get('banner'):
                    line += f"  — {port.get('banner')}"
                print(line)
        print()
    
    """
    if args.ports:
        logger.info("Running Port scanning...")
        results['ports'] = run_portscan(args.target, args.ports)
        ps = results["ports"]
        print()
        print("=" * 55)
        print("  PORTS SCANNING RESULTS")
        print("=" * 55)
        print(f"  Target : {ps.get('target', args.target)}")
        print(f"  Success : {ps.get('success', ps['success'])}")
        print(f"  Open Ports : {ps.get('data', {}).get('open_ports', {})}")
        print()
        for port in ps.get('ports', []):
            print(f"    -> {port}")

        if 'error' in ps:
            print(f"  ERROR        : {ps['error']}")
        print() """
        

    # ── Tech Detection (Member 5) ────────────────────────
    if args.techdetect:
        logger.info("Running Technology detection...")
        results['techdetect'] = run_techdetect(args.target)

    # ── Report (Member 5) ────────────────────────────────
    logger.info("Generating report...")
    generate_report(results, args.target)

    logger.info("Recon completed.")


if __name__ == "__main__":
    main()
