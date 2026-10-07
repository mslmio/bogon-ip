package bogonip

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

var iana = flag.Bool("iana", false, "fetch IANA's special-purpose registries and check the table covers them")

var ianaRegistries = []string{
	"https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv",
	"https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv",
}

// Every address IANA's special-purpose registries mark not globally reachable is in a block, and space
// they mark globally reachable that a block covers is listed. It fetches them, so it runs only with -iana.
func TestIANA(t *testing.T) {
	if !*iana {
		t.Skip("fetches IANA's registries: run with -iana")
	}
	blocks := readBlocks(t)
	client := &http.Client{Timeout: time.Minute}
	for _, url := range ianaRegistries {
		entries, err := fetchRegistry(client, url)
		if err != nil {
			t.Errorf("%s: %v", url, err)
			continue
		}
		for _, g := range gaps(entries, blocks) {
			t.Errorf("IANA's %s (%s) is not globally reachable, and no block covers %s",
				canonical(g.entry.prefix), g.entry.name, spans(g.prefixes))
		}
		for _, c := range covered(entries, blocks) {
			t.Logf("IANA's %s (%s) is globally reachable, and the list calls %s a bogon",
				canonical(c.entry.prefix), c.entry.name, spans(c.prefixes))
		}
		t.Logf("%s: %d entries", url, len(entries))
	}
}

// A registry as IANA writes it: footnote marks, two blocks in one cell, a line break in a quoted
// cell, terminated entries with no flags, and entries inside another.
const ianaFixture = `Address Block,Name,RFC,Allocation Date,Termination Date,Source,Destination,Forwardable,Globally Reachable,Reserved-by-Protocol
192.0.0.0/24 [2],IETF Protocol Assignments,"[RFC6890], Section 2.1",2010-01,N/A,False,False,False,False,False
192.0.0.9/32,Port Control Protocol Anycast,[RFC7723],2015-10,N/A,True,True,True,True,False
"192.0.0.170/32, 192.0.0.171/32",NAT64/DNS64 Discovery,"[RFC8880][RFC7050], Section 2.2",2013-02,N/A,False,False,False,False,True
192.88.99.0/24,Deprecated (6to4 Relay Anycast),[RFC7526],2001-06,2015-03,,,,,
192.88.99.2/32,6a44-relay anycast address,[RFC6751],2012-10,N/A,True,True,True,False,False
255.255.255.255/32,Limited Broadcast,"[RFC8190]
        [RFC919], Section 7",1984-10,N/A,False,True,False,False,True
2001::/23,IETF Protocol Assignments,[RFC2928],2000-09,N/A,False [1],False [1],False [1],False [1],False
2001::/32,TEREDO,"[RFC4380]
        [RFC8190]",2006-01,N/A,True,True,True,N/A [2],False
2001:3::/32,AMT,[RFC7450],2014-12,N/A,True,True,True,True,False
2001:10::/28,Deprecated (previously ORCHID),[RFC4843],2007-03,2014-03,,,,,
`

func TestIANAParse(t *testing.T) {
	entries, err := parseRegistry(strings.NewReader(ianaFixture))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, fmt.Sprintf("%s %s reachable=%s", e.prefix, e.name, e.reachable))
	}
	want := []string{
		"192.0.0.0/24 IETF Protocol Assignments reachable=False",
		"192.0.0.9/32 Port Control Protocol Anycast reachable=True",
		"192.0.0.170/32 NAT64/DNS64 Discovery reachable=False",
		"192.0.0.171/32 NAT64/DNS64 Discovery reachable=False",
		"192.88.99.2/32 6a44-relay anycast address reachable=False",
		"255.255.255.255/32 Limited Broadcast reachable=False",
		"2001::/23 IETF Protocol Assignments reachable=False",
		"2001::/32 TEREDO reachable=N/A",
		"2001:3::/32 AMT reachable=True",
	}
	if !slices.Equal(got, want) {
		t.Errorf("parsed\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Teredo's N/A and AMT's True take their space out of the 2001::/23 around them, and a terminated
// entry does not. Adjacent gaps are one range.
func TestIANAGaps(t *testing.T) {
	entries, err := parseRegistry(strings.NewReader(ianaFixture))
	if err != nil {
		t.Fatal(err)
	}
	var blocks []block
	for _, cidr := range []string{"192.0.0.0/24", "2001:1::/32", "2001:2::/48", "2001:4::/30", "2001:8::/29",
		"2001:20::/27", "2001:40::/26", "2001:80::/25", "2001:100::/24"} {
		blocks = append(blocks, block{cidr: cidr, prefix: netip.MustParsePrefix(cidr)})
	}
	var got []string
	for _, g := range gaps(entries, blocks) {
		got = append(got, fmt.Sprintf("%s: %s", g.entry.prefix, spans(g.prefixes)))
	}
	want := []string{
		"192.88.99.2/32: 192.88.99.2/32",
		"255.255.255.255/32: 255.255.255.255/32",
		"2001::/23: 2001:2:1::-2001:2:ffff:ffff:ffff:ffff:ffff:ffff, 2001:10::/28",
	}
	if !slices.Equal(got, want) {
		t.Errorf("gaps\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A reachable entry lists the space a block covers, less any entry inside it, and neither a False entry
// nor Teredo's N/A lists any.
func TestIANACovered(t *testing.T) {
	entries, err := parseRegistry(strings.NewReader(ianaFixture))
	if err != nil {
		t.Fatal(err)
	}
	// No registry nests an entry inside a reachable one today, so this one is made up.
	entries = append(entries, ianaEntry{prefix: netip.MustParsePrefix("2001:3:4000::/34"), reachable: "False"})
	var blocks []block
	for _, cidr := range []string{"192.0.0.0/24", "2001::/32", "2001:3::/33"} {
		blocks = append(blocks, block{cidr: cidr, prefix: netip.MustParsePrefix(cidr)})
	}
	var got []string
	for _, c := range covered(entries, blocks) {
		got = append(got, fmt.Sprintf("%s: %s", c.entry.prefix, spans(c.prefixes)))
	}
	want := []string{
		"192.0.0.9/32: 192.0.0.9/32",
		"2001:3::/32: 2001:3::/34",
	}
	if !slices.Equal(got, want) {
		t.Errorf("covered\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

type ianaEntry struct {
	prefix    netip.Prefix
	name      string
	reachable string
}

// fetchRegistry refuses a registry with no entry marked not globally reachable, which a changed
// format would otherwise pass as having nothing to cover.
func fetchRegistry(client *http.Client, url string) ([]ianaEntry, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	entries, err := parseRegistry(resp.Body)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(entries, func(e ianaEntry) bool { return e.reachable == "False" }) {
		return nil, errors.New("no entry is marked not globally reachable")
	}
	return entries, nil
}

// footnote is a mark like " [2]" that IANA appends to a cell, citing a note below its table.
var footnote = regexp.MustCompile(`\s*\[\d+\]`)

// parseRegistry reads a registry's CSV, leaving out terminated entries. Each entry keeps its Globally
// Reachable value, and a value other than True, False or N/A is an error.
func parseRegistry(r io.Reader) ([]ianaEntry, error) {
	rows, err := csv.NewReader(r).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("no header")
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[strings.TrimPrefix(name, "\ufeff")] = i
	}
	for _, name := range []string{"Address Block", "Name", "Termination Date", "Globally Reachable"} {
		if _, ok := col[name]; !ok {
			return nil, fmt.Errorf("no %q column", name)
		}
	}
	var entries []ianaEntry
	for _, row := range rows[1:] {
		cell := func(name string) string {
			return strings.TrimSpace(footnote.ReplaceAllString(row[col[name]], ""))
		}
		if end := cell("Termination Date"); end != "N/A" && end != "" {
			continue
		}
		reachable := cell("Globally Reachable")
		if reachable != "True" && reachable != "False" && reachable != "N/A" {
			return nil, fmt.Errorf("%s: Globally Reachable is %q", cell("Address Block"), reachable)
		}
		entry := ianaEntry{name: cell("Name"), reachable: reachable}
		for _, s := range strings.Split(cell("Address Block"), ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return nil, err
			}
			entry.prefix = p.Masked()
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

type part struct {
	entry    ianaEntry
	prefixes []netip.Prefix
}

// gaps is the space each entry marks not globally reachable that no block covers. The most specific
// entry decides an address, so an entry leaves out every entry inside it.
func gaps(entries []ianaEntry, blocks []block) []part {
	var found []part
	for _, e := range entries {
		if e.reachable != "False" {
			continue
		}
		var exclude []netip.Prefix
		for _, other := range entries {
			if other.prefix != e.prefix && inside(e.prefix, other.prefix) {
				exclude = append(exclude, other.prefix)
			}
		}
		for _, b := range blocks {
			exclude = append(exclude, b.prefix)
		}
		if left := subtract(e.prefix, exclude); len(left) > 0 {
			found = append(found, part{entry: e, prefixes: left})
		}
	}
	return found
}

// covered is the space each entry marks globally reachable that a block covers, the most specific entry
// deciding each address as in gaps.
func covered(entries []ianaEntry, blocks []block) []part {
	var found []part
	for _, e := range entries {
		if e.reachable != "True" {
			continue
		}
		var cut []netip.Prefix
		for _, other := range entries {
			if other.prefix != e.prefix && inside(e.prefix, other.prefix) {
				cut = append(cut, other.prefix)
			}
		}
		decided := subtract(e.prefix, cut)
		for _, b := range blocks {
			cut = append(cut, b.prefix)
		}
		uncovered := subtract(e.prefix, cut)
		var blocked []netip.Prefix
		for _, p := range decided {
			blocked = append(blocked, subtract(p, uncovered)...)
		}
		if len(blocked) > 0 {
			found = append(found, part{entry: e, prefixes: blocked})
		}
	}
	return found
}

// subtract is what is left of p outside every prefix in cut, as the fewest prefixes.
func subtract(p netip.Prefix, cut []netip.Prefix) []netip.Prefix {
	split := false
	for _, c := range cut {
		if inside(c, p) {
			return nil
		}
		split = split || inside(p, c)
	}
	if !split {
		return []netip.Prefix{p}
	}
	a := p.Addr().AsSlice()
	a[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	upper, _ := netip.AddrFromSlice(a)
	return append(subtract(netip.PrefixFrom(p.Addr(), p.Bits()+1), cut),
		subtract(netip.PrefixFrom(upper, p.Bits()+1), cut)...)
}

// spans writes each run of adjacent prefixes as one range, first-last, and a prefix with none
// adjacent as its CIDR.
func spans(prefixes []netip.Prefix) string {
	var out []string
	for i := 0; i < len(prefixes); {
		j := i + 1
		for j < len(prefixes) && lastAddr(prefixes[j-1]).Next() == prefixes[j].Addr() {
			j++
		}
		if j == i+1 {
			out = append(out, canonical(prefixes[i]))
		} else {
			out = append(out, prefixes[i].Addr().String()+"-"+lastAddr(prefixes[j-1]).String())
		}
		i = j
	}
	return strings.Join(out, ", ")
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().AsSlice()
	for i := p.Bits(); i < len(a)*8; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	last, _ := netip.AddrFromSlice(a)
	return last
}
