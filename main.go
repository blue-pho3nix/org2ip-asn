/*
org2ip-asn finds the IPv4 ranges and ASNs belonging to an organization.

Examples:
	org2ip-asn "IBM"
	org2ip-asn "IBM" "International Business Machines Corporation"

Queries bgp.he.net and CAIDA AS Rank for organization ASNs and extracts corresponding IP ranges.

Writes <first-org>-asns.txt and <first-org>-ipv4.txt.
*/
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	heBase  = "https://bgp.he.net"
	delay   = 1500 * time.Millisecond // between HE page fetches; HE throttles
	retries = 4
	maxASN  = 4294967295

	caidaURL  = "https://api.asrank.caida.org/v2/graphql"
	caidaPage = 100
	caidaMax  = 1000
)

var challenge = []string{"Just a moment...", "cf_chl_opt", "Checking your browser"}

// ------------------------------------------------------------------- http

func fetch(client *http.Client, target string) string {
	var why string
	for attempt := 0; attempt < retries; attempt++ {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err := client.Do(req)
		if err != nil {
			why = err.Error()
		} else {
			body, rerr := io.ReadAll(resp.Body)
			resp.Body.Close()
			switch {
			case rerr != nil:
				why = rerr.Error()
			case resp.StatusCode != http.StatusOK:
				why = "HTTP " + strconv.Itoa(resp.StatusCode)
			default:
				page := string(body)
				blocked := false
				for _, c := range challenge {
					if strings.Contains(page, c) {
						blocked = true
						break
					}
				}
				if !blocked {
					return page
				}
				why = "challenge page"
			}
		}
		if attempt < retries-1 {
			wait := time.Duration(1<<attempt*3)*time.Second +
				time.Duration(rand.Intn(2000))*time.Millisecond
			fmt.Fprintf(os.Stderr, "[!] %s, retry in %.0fs\n", why, wait.Seconds())
			time.Sleep(wait)
		}
	}
	fmt.Fprintf(os.Stderr, "[!] giving up (%s)\n", why)
	return ""
}

func caidaPost(client *http.Client, query string) []byte {
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil
	}
	req, err := http.NewRequest("POST", caidaURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] CAIDA: %v, skipping\n", err)
		return nil
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(resp.Body)
	if rerr != nil || resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "[!] CAIDA: HTTP %d, skipping\n", resp.StatusCode)
		return nil
	}
	return raw
}

// ---------------------------------------------------------------- matching

/*
matches reports whether any needle appears in text as a whole word.

Substring matching breaks on short names: "ibm" sits inside FIBMESH PRIVATE
LIMITED, LTD SibMediaFon and ibml, none of which are IBM.
*/
func matches(text string, needles []string) bool {
	low := strings.ToLower(text)
	alnum := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b >= 0x80
	}
	for _, n := range needles {
		if n == "" {
			return true
		}
		for start := 0; start < len(low); {
			i := strings.Index(low[start:], n)
			if i < 0 {
				break
			}
			i += start
			end := i + len(n)
			okBefore := i == 0 || !alnum(low[i-1])
			okAfter := end >= len(low) || !alnum(low[end])
			if okBefore && okAfter {
				return true
			}
			start = i + 1
		}
	}
	return false
}

func toASN(token string) string {
	t := strings.TrimSpace(token)
	if strings.HasPrefix(t, "/") || strings.Contains(t, "://") ||
		strings.Contains(strings.ToLower(t), "bgp.he.net") {
		if k := strings.IndexAny(t, "#?"); k >= 0 {
			t = t[:k]
		}
		t = strings.TrimRight(t, "/")
		if k := strings.LastIndexByte(t, '/'); k >= 0 {
			t = t[k+1:]
		}
	} else if strings.ContainsAny(t, "/:.") {
		return ""
	}
	if len(t) > 2 && strings.EqualFold(t[:2], "AS") {
		t = t[2:]
	}
	n, err := strconv.ParseUint(t, 10, 64)
	if err != nil || n == 0 || n > maxASN {
		return ""
	}
	return "AS" + strconv.FormatUint(n, 10)
}

func asnNum(a string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(a, "AS"), 10, 64)
	return n
}

// ------------------------------------------------------------ html parsing

func lowered(s string) string {
	l := strings.ToLower(s)
	if len(l) != len(s) {
		return s
	}
	return l
}

func isBoundary(b byte) bool {
	return b == ' ' || b == '>' || b == '/' || b == '\t' || b == '\n' || b == '\r'
}

// elements returns the inner HTML of each <tag ...>...</tag> block in s.
func elements(s, tag string) []string {
	low := lowered(s)
	open, closing := "<"+tag, "</"+tag
	var out []string
	pos := 0
	for pos < len(low) {
		i := strings.Index(low[pos:], open)
		if i < 0 {
			break
		}
		i += pos
		after := i + len(open)
		if after >= len(s) || !isBoundary(s[after]) {
			pos = after
			continue
		}
		gt := strings.IndexByte(s[i:], '>')
		if gt < 0 {
			break
		}
		start := i + gt + 1
		j := strings.Index(low[start:], closing)
		if j < 0 {
			out = append(out, s[start:])
			break
		}
		out = append(out, s[start:start+j])
		pos = start + j + len(closing)
	}
	return out
}

// stripTags removes markup, unescapes entities and collapses whitespace.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
				b.WriteByte(' ')
			}
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return strings.Join(strings.Fields(html.UnescapeString(b.String())), " ")
}

func attr(tag, name string) string {
	low := lowered(tag)
	i := strings.Index(low, name+"=")
	if i < 0 {
		return ""
	}
	rest := tag[i+len(name)+1:]
	if rest == "" {
		return ""
	}
	q := rest[0]
	if q != '"' && q != '\'' {
		if end := strings.IndexAny(rest, " >"); end >= 0 {
			return html.UnescapeString(rest[:end])
		}
		return html.UnescapeString(rest)
	}
	end := strings.IndexByte(rest[1:], q)
	if end < 0 {
		return ""
	}
	return html.UnescapeString(rest[1 : 1+end])
}

type link struct{ href, text string }

func links(s string) []link {
	low := lowered(s)
	var out []link
	pos := 0
	for pos < len(low) {
		i := strings.Index(low[pos:], "<a")
		if i < 0 {
			break
		}
		i += pos
		if i+2 >= len(s) || !isBoundary(s[i+2]) {
			pos = i + 2
			continue
		}
		gt := strings.IndexByte(s[i:], '>')
		if gt < 0 {
			break
		}
		openTag := s[i : i+gt+1]
		start := i + gt + 1
		j := strings.Index(low[start:], "</a")
		if j < 0 {
			break
		}
		out = append(out, link{attr(openTag, "href"), stripTags(s[start : start+j])})
		pos = start + j
	}
	return out
}

// ---------------------------------------------------------------- prefixes

var reserved = func() []*net.IPNet {
	blocks := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	}
	out := make([]*net.IPNet, 0, len(blocks))
	for _, b := range blocks {
		if _, n, err := net.ParseCIDR(b); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func isGlobal4(n *net.IPNet) bool {
	ip := n.IP.To4()
	if ip == nil {
		return false
	}
	for _, r := range reserved {
		if r.Contains(ip) {
			return false
		}
	}
	return true
}

type prefixRow struct {
	prefix string
	desc   string
	ipnet  *net.IPNet
}

// prefixesFromASN pulls public IPv4 prefixes off an ASN's he.net page.
func prefixesFromASN(page string) []prefixRow {
	var out []prefixRow
	seen := map[string]bool{}
	for _, row := range elements(page, "tr") {
		cells := elements(row, "td")
		if len(cells) < 2 {
			continue
		}
		for _, l := range links(cells[0]) {
			if !strings.HasPrefix(l.href, "/net/") {
				continue
			}
			_, n, err := net.ParseCIDR(l.text)
			if err != nil || !isGlobal4(n) || seen[l.text] {
				continue // also skips HE's separate Bogon Prefixes table
			}
			seen[l.text] = true
			out = append(out, prefixRow{l.text, stripTags(cells[1]), n})
			break
		}
	}
	return out
}

// ------------------------------------------------------------------ he.net

// asnsFromHE pulls ASNs off a he.net search page whose Description matches.
func asnsFromHE(page string, needles []string) []string {
	var out []string
	for _, row := range elements(page, "tr") {
		cells := elements(row, "td")
		if len(cells) < 3 || stripTags(cells[1]) != "ASN" {
			continue
		}
		ls := links(cells[0])
		if len(ls) == 0 {
			continue
		}
		if asn := toASN(ls[0].text); asn != "" && matches(stripTags(cells[2]), needles) {
			out = append(out, asn)
		}
	}
	return out
}

// ------------------------------------------------------------------- caida

type caidaRow struct{ asn, asnName, org, orgID string }

type asnsResp struct {
	Data struct {
		Asns struct {
			Edges []struct {
				Node struct {
					Asn          string `json:"asn"`
					AsnName      string `json:"asnName"`
					Organization struct {
						OrgID   string `json:"orgId"`
						OrgName string `json:"orgName"`
					} `json:"organization"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"asns"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

/*
asnsFromCAIDA searches AS Rank by name, keeping rows whose ORGANISATION
matches. asrank.caida.org is a JS app, so this uses the GraphQL endpoint
behind its by-name search. Failures are non-fatal.
*/
func asnsFromCAIDA(client *http.Client, term string, needles []string) []caidaRow {
	var out []caidaRow
	name, _ := json.Marshal(term)
	for offset := 0; offset < caidaMax; offset += caidaPage {
		q := fmt.Sprintf(`{ asns(name: %s, first: %d, offset: %d) { `+
			`edges { node { asn asnName organization { orgId orgName } } } } }`,
			name, caidaPage, offset)
		raw := caidaPost(client, q)
		if raw == nil {
			return out
		}
		var parsed asnsResp
		if err := json.Unmarshal(raw, &parsed); err != nil {
			fmt.Fprintln(os.Stderr, "[!] CAIDA: bad JSON, skipping")
			return out
		}
		if len(parsed.Errors) > 0 {
			fmt.Fprintf(os.Stderr, "[!] CAIDA: %s, skipping\n", parsed.Errors[0].Message)
			return out
		}
		edges := parsed.Data.Asns.Edges
		for _, e := range edges {
			asn := toASN(e.Node.Asn)
			if asn == "" {
				continue
			}
			if matches(e.Node.Organization.OrgName, needles) {
				out = append(out, caidaRow{asn, e.Node.AsnName,
					e.Node.Organization.OrgName, e.Node.Organization.OrgID})
			}
		}
		if len(edges) < caidaPage {
			break
		}
	}
	return out
}

type orgResp struct {
	Data struct {
		Organization struct {
			OrgName string `json:"orgName"`
			Members struct {
				Asns struct {
					Edges []struct {
						Node struct {
							Asn     string `json:"asn"`
							AsnName string `json:"asnName"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"asns"`
			} `json:"members"`
		} `json:"organization"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

/*
orgMembers lists every ASN registered to one CAIDA organisation. A by-name
search only matches the org string CAIDA has on file, so a company recorded
under several spellings is under-reported without this.
*/
func orgMembers(client *http.Client, orgID string) []caidaRow {
	id, _ := json.Marshal(orgID)
	q := fmt.Sprintf(`{ organization(orgId: %s) { orgName members { asns `+
		`{ edges { node { asn asnName } } } } } }`, id)
	raw := caidaPost(client, q)
	if raw == nil {
		return nil
	}
	var parsed orgResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		fmt.Fprintln(os.Stderr, "[!] CAIDA: bad JSON, skipping")
		return nil
	}
	if len(parsed.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "[!] CAIDA: %s, skipping\n", parsed.Errors[0].Message)
		return nil
	}
	var out []caidaRow
	org := parsed.Data.Organization
	for _, e := range org.Members.Asns.Edges {
		if asn := toASN(e.Node.Asn); asn != "" {
			out = append(out, caidaRow{asn, e.Node.AsnName, org.OrgName, orgID})
		}
	}
	return out
}

// ------------------------------------------------------------------ output

func slug(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	parts := strings.FieldsFunc(b.String(), func(r rune) bool { return r == '-' })
	out := strings.Join(parts, "-")
	if len(out) > 40 { // trim on a separator, not mid-word
		out = out[:40]
		if k := strings.LastIndexByte(out, '-'); k > 0 {
			out = out[:k]
		}
	}
	if out == "" {
		return "org2ip-asn"
	}
	return out
}

func writeLines(path string, lines []string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s: %v\n", path, err)
		return
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
	fmt.Fprintf(os.Stderr, "[+] %d -> %s\n", len(lines), path)
}

// --------------------------------------------------------------------- main

var banner = []string{
	"\033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;94;40m▄▄▄▄▄\033[0;37;40m \033[0;94;40m▄▄▄\033[0;34;40m \033[0;37;40m \033[0;94;40m▄▄\033[0;37;40m \033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;34;40m    \033[0;37;40m \033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;34;40m \033[0;94;40m▄▄▄\033[0;37;40m \033[0;94;40m▄▄▄▄\033[0m",
	"\033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;40m██\033[0;34;40m   \033[0;37;40m \033[0;34;40m \033[0;94;40m▀██\033[0;37;40m \033[0;94;40m██\033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;34;40m    \033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;40m██▀\033[0;34;40m \033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0m",
	"\033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;40m██▄▀\033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m▄▄\033[0;37;40m \033[0;94;40m▄██▀\033[0;37;40m \033[0;94;40m██\033[0;37;40m \033[0;94;40m██▄█\033[0;37;40m \033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;94;40m██▄█\033[0;37;40m \033[0;94;40m▀██▄\033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0m",
	"\033[0;94;44m \033[0;94;40m█\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;44m▀\033[0;94;40m█\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;44m▐▀\033[0;34;40m \033[0;94;40m▀\033[0;94;44m▌\033[0;37;40m \033[0;94;44m▀▀\033[0;34;40m  \033[0;37;40m \033[0;94;44m▀\033[0;94;40m█\033[0;37;40m \033[0;94;44m▀\033[0;94;40m█\033[0;34;40m  \033[0;37;40m \033[0;34;40m▀▀▀▀\033[0;37;40m \033[0;94;44m \033[0;94;40m█\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;34;40m ▄\033[0;94;44m▀▀\033[0;37;40m \033[0;94;44m▀\033[0;94;40m█\033[0;34;40m \033[0;94;40m█\033[0m",
	"\033[0;34;40m▀▀▀▀\033[0;37;40m \033[0;34;40m▀▀ ▀\033[0;37;40m \033[0;34;40m▀▀▀▀▀\033[0;37;40m \033[0;34;40m▀▀▀▀\033[0;37;40m \033[0;34;40m▀▀\033[0;37;40m \033[0;34;40m▀▀  \033[0;37;40m      \033[0;34;40m▀▀ ▀\033[0;37;40m \033[0;34;40m▀▀▀ \033[0;37;40m \033[0;34;40m▀▀ ▀\033[0m",
}

/*
printBanner writes the logo to stderr, and only when stderr is a terminal, so
that redirecting output to a file leaves no escape sequences in it. NO_COLOR
suppresses it entirely.
*/
func printBanner() {
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	info, err := os.Stderr.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return
	}
	for _, l := range banner {
		fmt.Fprintln(os.Stderr, l)
	}
	fmt.Fprintln(os.Stderr)
}

func usage() {
	fmt.Fprint(os.Stderr, `org2ip-asn finds the IPv4 ranges and ASNs belonging to an organization.

Examples:
	org2ip-asn "IBM"
	org2ip-asn "IBM" "International Business Machines Corporation"

Queries bgp.he.net and CAIDA AS Rank for organization ASNs and extracts corresponding IP ranges.

Writes <first-org>-asns.txt and <first-org>-ipv4.txt.
`)
	os.Exit(1)
}

func main() {
	printBanner()
	if len(os.Args) < 2 {
		usage()
	}
	var terms, needles []string
	for _, a := range os.Args[1:] {
		if a = strings.TrimSpace(a); a != "" {
			terms = append(terms, a)
			needles = append(needles, strings.ToLower(a))
		}
	}
	if len(terms) == 0 {
		usage()
	}

	client := &http.Client{Timeout: 30 * time.Second}
	found := map[string]caidaRow{} // asn -> best known detail

	for i, term := range terms {
		if i > 0 {
			time.Sleep(delay)
		}
		fmt.Fprintf(os.Stderr, "[*] searching %q\n", term)

		// bgp.he.net
		u := heBase + "/search?search%5Bsearch%5D=" + url.QueryEscape(term) + "&commit=Search"
		he := asnsFromHE(fetch(client, u), needles)
		for _, a := range he {
			if _, ok := found[a]; !ok {
				found[a] = caidaRow{asn: a}
			}
		}
		fmt.Fprintf(os.Stderr, "    bgp.he.net: %d ASNs\n", len(he))

		// CAIDA AS Rank
		rows := asnsFromCAIDA(client, term, needles)
		fmt.Fprintf(os.Stderr, "    CAIDA: %d ASNs\n", len(rows))

		// expand every organisation those rows belong to
		var orgIDs []string
		seenOrg := map[string]bool{}
		for _, r := range rows {
			if cur, ok := found[r.asn]; !ok || cur.org == "" {
				found[r.asn] = r
			}
			if r.orgID != "" && !seenOrg[r.orgID] {
				seenOrg[r.orgID] = true
				orgIDs = append(orgIDs, r.orgID)
			}
		}
		for _, id := range orgIDs {
			added := 0
			for _, m := range orgMembers(client, id) {
				if cur, ok := found[m.asn]; !ok || cur.org == "" {
					if !ok {
						added++
					}
					found[m.asn] = m
				}
			}
			if added > 0 {
				fmt.Fprintf(os.Stderr, "    org expansion: +%d ASNs\n", added)
			}
		}
	}

	if len(found) == 0 {
		fmt.Fprintln(os.Stderr, "[!] no ASNs matched")
		os.Exit(1)
	}

	asns := make([]string, 0, len(found))
	for a := range found {
		asns = append(asns, a)
	}
	sort.Slice(asns, func(i, j int) bool { return asnNum(asns[i]) < asnNum(asns[j]) })

	fmt.Fprintf(os.Stderr, "[*] %d ASNs\n", len(asns))
	for _, a := range asns {
		r := found[a]
		fmt.Fprintf(os.Stderr, "      %-12s %-24s %s\n", a, r.asnName, r.org)
	}

	// prefixes
	var rows []prefixRow
	seen := map[string]bool{}
	for i, asn := range asns {
		if i > 0 {
			time.Sleep(delay)
		}
		fmt.Fprintf(os.Stderr, "[*] %s (%d/%d)\n", asn, i+1, len(asns))
		for _, p := range prefixesFromASN(fetch(client, heBase+"/"+asn)) {
			// A row naming someone else is another company's space announced
			// by this ASN: AS398037 is Nvidia's but also carries "Code200".
			if seen[p.prefix] || !(p.desc == "" || matches(p.desc, needles)) {
				continue
			}
			seen[p.prefix] = true
			rows = append(rows, p)
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].ipnet, rows[j].ipnet
		if c := strings.Compare(string(a.IP.To4()), string(b.IP.To4())); c != 0 {
			return c < 0
		}
		ao, _ := a.Mask.Size()
		bo, _ := b.Mask.Size()
		return ao < bo
	})

	prefixes := make([]string, 0, len(rows))
	for _, r := range rows {
		prefixes = append(prefixes, r.prefix)
	}

	stem := slug(terms[0])
	writeLines(stem+"-asns.txt", asns)
	writeLines(stem+"-ipv4.txt", prefixes)

	for _, p := range prefixes {
		fmt.Println(p)
	}
}
