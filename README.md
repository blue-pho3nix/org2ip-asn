# org2ip-asn

org2ip-asn finds the IPv4 ranges and ASNs belonging to an organization.

## Install

    go install github.com/blue-pho3nix/org2ip-asn@latest

## Usage
    org2ip-asn <org-name>
    org2ip-asn "IBM"
    
    or
    
    org2ip-asn <org-name> <org-name>
    org2ip-asn "IBM" "International Business Machines Corporation"

    or 

    cat org-names.txt | org2ip-asn 
    
Writes <first-org>-asns.txt and <first-org>-ipv4.txt:

    ibm-asns.txt    every ASN found
    ibm-ipv4.txt    every IPv4 range

Prefixes also go to stdout and progress to stderr, so `| httpx` and `>> file`
both work.

---

## How It works

- Queries bgp.he.net and CAIDA AS Rank to find organization ASNs and extract their corresponding IP ranges.
- Matches whole words against the organization name, not substrings or AS names.

## Why several names help

- CAIDA records the same company under multiple names and spelling variations.
- Passing multiple terms ("IBM" "Red Hat") ensures fragmented corporate branches and their full memberships are captured.

## Known gaps

- Subsidiaries aren't linked automatically. Parent companies and acquisitions must be seeded manually.

## Rate limiting

- Enforces a 1.5-second delay between bgp.he.net requests to prevent throttling.
- Automatically detects Cloudflare challenges and backs off/retries.
