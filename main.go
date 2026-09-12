/*
org2ip-asn finds the IPv4 ranges and ASNs belonging to an organization.

Examples:
	org2ip-asn "IBM"
	org2ip-asn "IBM" "International Business Machines Corporation"
	cat org-names.txt | org2ip-asn

Queries for organization ASNs and extracts corresponding IP ranges.

The organization name must match exactly, so "IBM" does not pull in IBM Cloud
or IBM Deutschland GmbH.

Writes <first-org>-asns.txt and <first-org>-ipv4.txt.
*/
package main

import (
	"bufio"
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
	delay   = 1500 * time.Millisecond 
	retries = 4
	maxASN  = 4294967295

	caidaURL  = "https://api.asrank.caida.org/v2/graphql"
	caidaPage = 100
	caidaMax  = 1000
)

var challenge = []string{"Just a moment...", "cf_chl_opt", "Checking your browser"}

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

func matches(text string, needles []string) bool {
	low := strings.ToLower(strings.TrimSpace(text))
	for _, n := range needles {
		if n == "" || low == n {
			return true
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
	if len(out) > 40 { 
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
}

var banner = []string{
	"\033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;94;40m▄▄▄▄▄\033[0;37;40m \033[0;94;40m▄▄▄\033[0;34;40m \033[0;37;40m \033[0;94;40m▄▄\033[0;37;40m \033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;34;40m    \033[0;37;40m \033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;34;40m \033[0;94;40m▄▄▄\033[0;37;40m \033[0;94;40m▄▄▄▄\033[0m",
	"\033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;40m██\033[0;34;40m   \033[0;37;40m \033[0;34;40m \033[0;94;40m▀██\033[0;37;40m \033[0;94;40m██\033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;34;40m    \033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;40m██▀\033[0;34;40m \033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0m",
	"\033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;40m██▄▀\033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m▄▄\033[0;37;40m \033[0;94;40m▄██▀\033[0;37;40m \033[0;94;40m██\033[0;37;40m \033[0;94;40m██▄█\033[0;37;40m \033[0;94;40m▄▄▄▄\033[0;37;40m \033[0;94;40m██▄█\033[0;37;40m \033[0;94;40m▀██▄\033[0;37;40m \033[0;94;40m██\033[0;34;40m \033[0;94;40m█\033[0m",
	"\033[0;94;44m \033[0;94;40m█\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;44m▀\033[0;94;40m█\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;94;44m▐▀\033[0;34;40m \033[0;94;40m▀\033[0;94;44m▌\033[0;37;40m \033[0;94;44m▀▀\033[0;34;40m  \033[0;37;40m \033[0;94;44m▀\033[0;94;40m█\033[0;37;40m \033[0;94;44m▀\033[0;94;40m█\033[0;34;40m  \033[0;37;40m \033[0;34;40m▀▀▀▀\033[0;37;40m \033[0;94;44m \033[0;94;40m█\033[0;34;40m \033[0;94;40m█\033[0;37;40m \033[0;34;40m ▄\033[0;94;44m▀▀\033[0;37;40m \033[0;94;44m▀\033[0;94;40m█\033[0;34;40m \033[0;94;40m█\033[0m",
	"\033[0;34;40m▀▀▀▀\033[0;37;40m \033[0;34;40m▀▀ ▀\033[0;37;40m \033[0;34;40m▀▀▀▀▀\033[0;37;40m \033[0;34;40m▀▀▀▀\033[0;37;40m \033[0;34;40m▀▀\033[0;37;40m \033[0;34;40m▀▀  \033[0;37;40m      \033[0;34;40m▀▀ ▀\033[0;37;40m \033[0;34;40m▀▀▀ \033[0;37;40m \033[0;34;40m▀▀ ▀\033[0m",
}

var useColor = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := os.Stderr.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}()

func blue(s string) string {
	if !useColor {
		return s
	}
	return "\033[94m" + s + "\033[0m"
}

func printBanner() {
	if !useColor {
		return
	}
	for _, l := range banner {
		fmt.Fprintln(os.Stderr, l)
	}
	fmt.Fprintln(os.Stderr)
}

func stdinNames() []string {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice != 0 {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func usage() {
	fmt.Fprint(os.Stderr, `org2ip-asn finds the IPv4 ranges and ASNs belonging to an organization.

Examples:
	org2ip-asn "IBM"
	org2ip-asn "IBM" "International Business Machines Corporation"
	cat org-names.txt | org2ip-asn

Queries for organization ASNs and extracts corresponding IP ranges.

The organization name must match exactly. For example, "IBM" does not pull in IBM Cloud
or IBM Deutschland GmbH.

Writes <first-org>-asns.txt and <first-org>-ipv4.txt.
`)
	os.Exit(1)
}

func main() {
	printBanner()

	names := append([]string{}, os.Args[1:]...)
	names = append(names, stdinNames()...)

	var terms, needles []string
	seenTerm := map[string]bool{}
	for _, a := range names {
		a = strings.TrimSpace(a)
		low := strings.ToLower(a)
		if a == "" || seenTerm[low] {
			continue
		}
		seenTerm[low] = true
		terms = append(terms, a)
		needles = append(needles, low)
	}
	if len(terms) == 0 {
		usage()
	}

	client := &http.Client{Timeout: 30 * time.Second}

	seenASN := map[string]caidaRow{}
	seenPfx := map[string]bool{}
	withPfx := map[string]bool{} 
	otherOrg := map[string]int{}  
	var rows []prefixRow

	addASN := func(r caidaRow) bool {
		if cur, ok := seenASN[r.asn]; ok {
			if cur.asnName == "" && r.asnName != "" {
				seenASN[r.asn] = r
			}
			return false
		}
		seenASN[r.asn] = r
		parts := []string{r.asn}
		if r.asnName != "" {
			parts = append(parts, r.asnName)
		}
		if r.org != "" {
			parts = append(parts, r.org)
		}
		fmt.Fprintf(os.Stderr, "      %s\n", strings.Join(parts, "  "))

		time.Sleep(delay)
		added, dup, skipped := 0, 0, 0
		for _, p := range prefixesFromASN(fetch(client, heBase+"/"+r.asn)) {
			if !(p.desc == "" || matches(p.desc, needles)) {
				otherOrg[p.desc]++
				skipped++
				continue
			}
			if seenPfx[p.prefix] {
				dup++
				continue
			}
			seenPfx[p.prefix] = true
			rows = append(rows, p)
			fmt.Fprintf(os.Stderr, "        %s\n", p.prefix)
			added++
		}

		if added > 0 {
			fmt.Fprintf(os.Stderr, "        %d new\n", added)
		}
		if added+dup > 0 {
			withPfx[r.asn] = true
		}
		return true
	}

	report := func(seen int) {
		if seen > 0 {
			fmt.Fprintf(os.Stderr, "      %d already seen\n", seen)
		}
	}

	for i, term := range terms {
		if i > 0 {
			time.Sleep(delay)
		}
		fmt.Fprintf(os.Stderr, "[*] searching %q\n", term)

		only := needles[i : i+1]

		u := heBase + "/search?search%5Bsearch%5D=" + url.QueryEscape(term) + "&commit=Search"
		he := asnsFromHE(fetch(client, u), only)
		fmt.Fprintf(os.Stderr, "    %s: %d ASNs\n", blue("bgp.he.net"), len(he))
		dupHE := 0
		for _, a := range he {
			if !addASN(caidaRow{asn: a, org: term}) {
				dupHE++
			}
		}
		report(dupHE)

		caida := asnsFromCAIDA(client, term, only)
		fmt.Fprintf(os.Stderr, "    %s: %d ASNs\n", blue("CAIDA"), len(caida))
		var orgIDs []string
		seenOrg := map[string]bool{}
		dupCAIDA := 0
		for _, r := range caida {
			if !addASN(r) {
				dupCAIDA++
			}
			if r.orgID != "" && !seenOrg[r.orgID] {
				seenOrg[r.orgID] = true
				orgIDs = append(orgIDs, r.orgID)
			}
		}
		report(dupCAIDA)

		for _, id := range orgIDs {
			members := orgMembers(client, id)
			fresh := 0
			for _, m := range members {
				if _, ok := seenASN[m.asn]; !ok {
					fresh++
				}
			}
			fmt.Fprintf(os.Stderr, "    %s: %d ASNs, %d new\n",
				blue("org expansion"), len(members), fresh)
			dupOrg := 0
			for _, m := range members {
				if !addASN(m) {
					dupOrg++
				}
			}
			report(dupOrg)
		}
	}

	if len(seenASN) == 0 {
		fmt.Fprintln(os.Stderr, "[!] no ASNs matched")
		os.Exit(1)
	}

	asns := make([]string, 0, len(withPfx))
	for a := range withPfx {
		asns = append(asns, a)
	}
	sort.Slice(asns, func(i, j int) bool { return asnNum(asns[i]) < asnNum(asns[j]) })

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
	asnFile, ipFile := stem+"-asns.txt", stem+"-ipv4.txt"
	writeLines(asnFile, asns)
	writeLines(ipFile, prefixes)

	for _, p := range prefixes {
		fmt.Println(p)
	}

	if len(otherOrg) > 0 {
		type skip struct {
			desc string
			n    int
		}
		list := make([]skip, 0, len(otherOrg))
		for d, n := range otherOrg {
			list = append(list, skip{d, n})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].n != list[j].n {
				return list[i].n > list[j].n
			}
			return list[i].desc < list[j].desc
		})
		fmt.Fprintf(os.Stderr,
			"[*] Skipped %d other names. Check them out and add applicable ones to your next list:\n",
			len(list))
		for _, k := range list {
			fmt.Fprintf(os.Stderr, "      %4d  %s\n", k.n, k.desc)
		}
	}
	
	fmt.Fprintf(os.Stderr, "[*] Found %d IP ranges and %d ASNs\n", len(prefixes), len(asns))
	fmt.Fprintf(os.Stderr, "[*] Check your %s and %s\n", asnFile, ipFile)
}
