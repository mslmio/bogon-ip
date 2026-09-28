package bogonip

import (
	"bytes"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite ipv4.txt and ipv6.txt from bogons.tsv")

// The plain lists are the table's blocks, one family each, in the table's order.
func TestLists(t *testing.T) {
	blocks := readBlocks(t)
	for _, list := range []struct {
		file string
		is4  bool
	}{{"ipv4.txt", true}, {"ipv6.txt", false}} {
		var want bytes.Buffer
		for _, b := range blocks {
			if b.prefix.Addr().Is4() == list.is4 {
				want.WriteString(b.cidr + "\n")
			}
		}
		if *update {
			if err := os.WriteFile(list.file, want.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(list.file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Errorf("%s does not match bogons.tsv: run go test -update", list.file)
		}
	}
}

// Each block is listed once, IPv4 before IPv6, and never after a block containing it, so the first
// block to match an address is the narrowest one that does.
func TestTable(t *testing.T) {
	blocks := readBlocks(t)
	seen := map[netip.Prefix]bool{}
	for i, b := range blocks {
		if seen[b.prefix] {
			t.Errorf("%s is listed twice", b.cidr)
		}
		seen[b.prefix] = true
		if i > 0 && !blocks[i-1].prefix.Addr().Is4() && b.prefix.Addr().Is4() {
			t.Errorf("%s: IPv4 blocks come before IPv6 ones", b.cidr)
		}
		for _, earlier := range blocks[:i] {
			if earlier.prefix != b.prefix && inside(earlier.prefix, b.prefix) {
				t.Errorf("%s is inside %s, which comes before it", b.cidr, earlier.cidr)
			}
		}
	}
}

// Each IPv4 block's 6to4 and Teredo forms are listed and named for it, and nothing else sits in 6to4's
// 2002::/16 or Teredo's 2001::/32, whose blocks match the server address in bits 32 to 63.
func TestMirrors(t *testing.T) {
	blocks := readBlocks(t)
	byPrefix := map[netip.Prefix]block{}
	for _, b := range blocks {
		byPrefix[b.prefix] = b
	}
	sixToFour := netip.MustParsePrefix("2002::/16")
	teredo := netip.MustParsePrefix("2001::/32")
	mirrors := map[netip.Prefix]bool{}
	for _, b := range blocks {
		if !b.prefix.Addr().Is4() {
			continue
		}
		for _, m := range []block{
			{prefix: wrap(sixToFour, b.prefix), name: "6to4 form of " + b.cidr, rfc: 3056},
			{prefix: wrap(teredo, b.prefix), name: "Teredo form of " + b.cidr, rfc: 4380},
		} {
			mirrors[m.prefix] = true
			got, ok := byPrefix[m.prefix]
			if !ok {
				t.Errorf("%s, the %s, is missing", canonical(m.prefix), m.name)
			} else if got.name != m.name || got.rfc != m.rfc {
				t.Errorf("%s is named %q with RFC %d, want %q with RFC %d", got.cidr, got.name, got.rfc,
					m.name, m.rfc)
			}
		}
	}
	for _, b := range blocks {
		if (inside(sixToFour, b.prefix) || inside(teredo, b.prefix)) && !mirrors[b.prefix] {
			t.Errorf("%s is inside 6to4 or Teredo space and wraps no IPv4 block", b.cidr)
		}
	}
}

// Every checker must give these answers: an IPv4-mapped address is judged as the IPv4 address it
// carries, and any other address by the blocks of its own family.
func TestVectors(t *testing.T) {
	blocks := readBlocks(t)
	seen := map[string]bool{}
	for i, row := range readTSV(t, "vectors.tsv", "address", "bogon", "why") {
		line := i + 2
		if seen[row[0]] {
			t.Errorf("vectors.tsv:%d: %s is listed twice", line, row[0])
		}
		seen[row[0]] = true
		addr, err := netip.ParseAddr(row[0])
		if err != nil || addr.Zone() != "" {
			t.Errorf("vectors.tsv:%d: %q is not an address without a zone", line, row[0])
			continue
		}
		if row[1] != "true" && row[1] != "false" {
			t.Errorf("vectors.tsv:%d: bogon is true or false, not %q", line, row[1])
			continue
		}
		if row[2] == "" {
			t.Errorf("vectors.tsv:%d: %s says nothing about why", line, row[0])
		}
		if got := judge(blocks, addr); got != (row[1] == "true") {
			t.Errorf("vectors.tsv:%d: %s says bogon %s, the table says %v", line, row[0], row[1], got)
		}
	}
}

type block struct {
	cidr   string
	prefix netip.Prefix
	name   string
	rfc    int
}

// readBlocks parses bogons.tsv and stops the test at any row that is not a canonical block, a name and
// an RFC number.
func readBlocks(t *testing.T) []block {
	t.Helper()
	var blocks []block
	for i, row := range readTSV(t, "bogons.tsv", "cidr", "name", "rfc") {
		line := i + 2
		p, err := netip.ParsePrefix(row[0])
		if err != nil {
			t.Fatalf("bogons.tsv:%d: %v", line, err)
		}
		if p != p.Masked() || row[0] != canonical(p) {
			t.Fatalf("bogons.tsv:%d: %s is written %s", line, row[0], canonical(p.Masked()))
		}
		if row[1] == "" || strings.TrimSpace(row[1]) != row[1] {
			t.Fatalf("bogons.tsv:%d: %s needs a name with no space around it", line, row[0])
		}
		rfc, err := strconv.Atoi(row[2])
		if err != nil || rfc <= 0 || strconv.Itoa(rfc) != row[2] {
			t.Fatalf("bogons.tsv:%d: %s has RFC %q, not a number", line, row[0], row[2])
		}
		blocks = append(blocks, block{cidr: row[0], prefix: p, name: row[1], rfc: rfc})
	}
	return blocks
}

// readTSV returns the rows below a tab-separated file's header, and stops the test unless every line
// ends in a bare newline and holds exactly the header's fields.
func readTSV(t *testing.T, file string, header ...string) [][]string {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasSuffix(text, "\n") || strings.Contains(text, "\r") {
		t.Fatalf("%s: every line ends in a bare newline", file)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if lines[0] != strings.Join(header, "\t") {
		t.Fatalf("%s: the header is %q", file, strings.Join(header, "\t"))
	}
	var rows [][]string
	for i, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != len(header) {
			t.Fatalf("%s:%d: want %d tab-separated fields", file, i+2, len(header))
		}
		rows = append(rows, fields)
	}
	return rows
}

// canonical is the RFC 5952 spelling Go prints, except that an IPv4-mapped block is written in hex, as
// IANA writes ::ffff:0:0/96, where Go prints ::ffff:0.0.0.0/96.
func canonical(p netip.Prefix) string {
	if !p.Addr().Is4In6() {
		return p.String()
	}
	b := p.Addr().As16()
	return fmt.Sprintf("::ffff:%x:%x/%d", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]),
		p.Bits())
}

// inside reports whether every address of inner is in outer.
func inside(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// wrap is the block of addresses in space whose next 32 bits are an address in the IPv4 block v4.
func wrap(space, v4 netip.Prefix) netip.Prefix {
	a := space.Addr().As16()
	b := v4.Addr().As4()
	copy(a[space.Bits()/8:], b[:])
	return netip.PrefixFrom(netip.AddrFrom16(a), space.Bits()+v4.Bits())
}

// judge is the rule every checker implements: unmap, then find a block of the address's own family.
func judge(blocks []block, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, b := range blocks {
		if b.prefix.Contains(addr) {
			return true
		}
	}
	return false
}
