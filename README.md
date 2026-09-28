# bogon-ip

The address blocks that must never appear as a public peer: unallocated, reserved, private, documentation, link-local and multicast space, plus the 6to4 and Teredo forms of every IPv4 block. One list, as plain text, for any language or tool to seed its own bogon check from, so that every checker built on it gives the same answer for every address.

```bash
curl -fsSL https://raw.githubusercontent.com/mslmio/bogon-ip/v1.0.0/ipv4.txt
```

## Files

| File | What it holds |
|---|---|
| `ipv4.txt`, `ipv6.txt` | One CIDR per line and nothing else: no header, no comments, a newline after the last line. |
| `bogons.tsv` | Every block with its name and the RFC that takes it out of circulation, IPv4 first. The two lists above are generated from it. |
| `vectors.tsv` | Addresses, and whether each is a bogon. Every checker built on this list must give these answers. |

Every file is UTF-8 with bare `\n` line endings, and every block is written in its canonical form ([RFC 5952](https://datatracker.ietf.org/doc/html/rfc5952) for IPv6, lower case and compressed), except that the IPv4-mapped block is `::ffff:0:0/96`, as IANA writes it.

## Judging an address

1. **An IPv4-mapped address is judged as the IPv4 address it carries.** `::ffff:10.0.0.1` is a bogon because `10.0.0.1` is, and `::ffff:8.8.8.8` is not one. A server listening on `::` sees every IPv4 client in this form, so a check that reads it as IPv6 calls each of them a bogon.
2. **Every other address is a bogon when a block of its own family contains it.** Nothing else is unwrapped: an IPv4-compatible address (`::8.8.8.8`, deprecated) stays IPv6 and falls in `::/96`, and 6to4 and Teredo addresses are matched against the blocks listed for them, so `2002:808:808::1`, the 6to4 form of `8.8.8.8`, is public. A Teredo address carries its server's IPv4 address in bits 32 to 63, and that is the address its blocks cover.
3. **Only addresses are in scope.** What a checker does with a string that is not an address, or with one that carries a zone (`fe80::1%eth0`), is its own decision, and `vectors.tsv` holds neither.

The blocks overlap: `::/3` contains `::1/128`, and `240.0.0.0/4` contains `255.255.255.255/32`. Each file lists a narrower block before any broader one that contains it, so the first block to match an address is the narrowest one that does, and its name is the most specific answer. A checker that binary-searches must merge the blocks first.

## Using it

Pin a release rather than tracking `main`. Vendor the files you need at that tag, record the tag beside them, and generate your language's table from the copy, so a reviewer can compare it with the release byte for byte. Test your checker against `vectors.tsv`, and against the first and last address of every block, which is what pins each mask's width.

## Releases

A block added or removed is a minor release, since it changes answers. A corrected name or RFC is a patch. A change to any file's format is a major. `CHANGELOG.md` says what each release changed.

## Changing the list

Edit `bogons.tsv`, then regenerate the plain lists and run the checks:

```bash
go test . -update
go test ./...
```

The checks refuse a block that is not canonical, a block listed twice, a block listed after one that contains it, an IPv4 block without both of its 6to4 and Teredo forms, and a vector the table does not agree with.

## License

MIT.
