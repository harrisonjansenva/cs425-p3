# P3: CIDR Arithmetic and Longest Prefix Match

- Name: Harrison Jansen van Beek
- Email: harrisonjansenva@u.boisestate.edu
- Class: CS425

## Known Bugs or Issues

None known. `make leak` and `make leak-test` could not be run on the macOS machine this
was written on (AddressSanitizer's leak detector is Linux only); the ASan builds ran
clean there with leak detection off, and the leak targets should be run on Codespaces/Onyx.

## Experience

Honestly, I thought this project was pretty easy. I used Claude code to implement it, I had it plan it out first, it made a great plan, and I let it go.

## Design

**Addresses** are `uint32_t` in host byte order. `ip_parse()` and `cidr_parse()` share one
hand-written scanner: each octet is 1 to 3 digits, no leading zero (except a lone `0`),
at most 255, with exactly three dots and nothing left over. The prefix is parsed the same
way with a maximum of 32. Nothing is written to the output unless the whole string is valid.

**The mask and /0.** `cidr_mask()` returns 0 for a prefix of 0 before it shifts, so the
undefined `<< 32` never happens, and clamps anything above 32 to 32. Everything else is
built from the mask: network is `addr & mask`, broadcast is `addr | ~mask`, and
`cidr_contains()` compares `addr & mask` with the block's `addr & mask`. Because the
default route's mask is 0, it contains every address with no special case.

**Host counts.** `cidr_host_count()` works in 64 bits so a /0 gives 2^32 - 2. A /31
(RFC 3021) has two usable addresses and its first and last host are the network and
broadcast addresses; a /32 has one, and all of network, broadcast, first and last host
are that address. /0 to /30 use network + 1 and broadcast - 1.

**Subnets.** `cidr_subnet()` rejects a non-network block, an `n` that is zero or not a
power of two, a new prefix over 32, and `i >= n`. The new prefix is the old one plus
log2(n), and subnet `i` starts at `network + i * 2^(32 - new_prefix)`, computed in 64 bits.
It returns one subnet per call, so `myapp split 0.0.0.0/0 2147483648` streams its output
instead of building an array.

**The table.** A `fwd_table_t` is a growable array of `route_t` (capacity starts at 4 and
doubles with `realloc`). `table_add()` copies the route and refuses host bits or a second
route for the same address and prefix. `table_load()` reads with `getline()`, strips
comments, skips blank lines, and stops at the first bad line, reporting its number; the
line buffer is freed on every path.

**Longest prefix match.** `table_lookup()` scans the whole table and keeps the matching
route with the largest prefix, so the result does not depend on insertion order. Since a
block can only appear once, no two matches have the same prefix. A trie would make lookup
cost at most 32 steps regardless of table size, but a linear scan is simple and enough here.

**Command line.** Exit codes are 0 for success, 1 for a bad command line or malformed
address, 2 for an unreadable table or a bad line (the table is loaded before any address
is looked at), and 3 when an address has no route. A lookup run reports every address,
then exits 1 if any was malformed, otherwise 3 if any was unreachable.

## Testing

`make check` runs the Unity tests in `tests/lab-test.c`, which cover every function in
`lab.h`, including /0, /31, /32, `0.0.0.0`, `255.255.255.255`, every malformed string from
the assignment, several routes matching one address, the same table added in a different
order, a table with no default route, and a table file with a bad line in the middle.
`make report` shows 100% line and branch coverage of `src/lab.c`.

