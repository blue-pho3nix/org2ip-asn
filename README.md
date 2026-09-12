# org2ip-asn

org2ip-asn finds the IPv4 ranges and ASNs belonging to an organization.

## Install

    go install github.com/blue-pho3nix/org2ip-asn@latest

## Usage
1. Go to https://dnschecker.org/ and get your org from an in scope domain

<details>
  <summary>Image</summary>
  
![](https://github.com/user-attachments/assets/eb2871b2-5aa2-4ca5-b7ca-5ec0bbb1cc52)

</details>


2. Run `org2ip-asn`
```
    org2ip-asn <org-name>
    org2ip-asn "IBM"
    
    or
    
    org2ip-asn <org-name> <org-name>
    org2ip-asn "IBM" "International Business Machines Corporation"

    or 

    cat org-names.txt | org2ip-asn 
```    
Writes `<first-org>-asns.txt` and `<first-org>-ipv4.txt`.

Prefixes also go to stdout and progress to stderr, so `| httpx` and `>> file`
both work.

---

## How It Works

- Queries bgp.he.net and CAIDA AS Rank to find organization ASNs and extract their corresponding IP ranges.
- The organization name must match exactly, and is matched against the organization, not the AS name.

<details>
  <summary>Image</summary>

![](https://github.com/user-attachments/assets/06a4059e-d544-48ee-bf3e-9b6507b44ff3)

</details>

## Why Multiple Names Help You Out

- A company is registered under many organization names. For example, IBM: `IBM`, `IBM Cloud`, `International Business Machines Corporation`, other acquisitions, and more.
- Each name you pass is looked up separately, and the results are merged, so list every entity and acquisition you want covered.

## Rate Limiting

- Enforces a 1.5-second delay between bgp.he.net requests to prevent throttling.
- Automatically detects Cloudflare challenges and backs off/retries.

---

## Resources

### Video
[![Watch the video](https://i.ytimg.com/vi/SVfFpVig-nw/hqdefault.jpg)](https://www.youtube.com/watch?v=SVfFpVig-nw)

### URLs
- https://bgp.he.net/
- https://asrank.caida.org/

and, claude...

