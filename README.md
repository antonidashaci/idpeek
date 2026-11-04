# idpeek

Paste an id. Find out what it tells a stranger.

```bash
python idpeek.py f81d4fae-7dec-11d0-a765-00a0c91e6bf6 1541815603606036480
```

```
UUID v1  f81d4fae-7dec-11d0-a765-00a0c91e6bf6
  created   1997-02-03T17:43:12.216876+00:00  (29.7 years ago)
  variant   RFC 4122
  clock_seq 10085
  node      00:a0:c9:1e:6b:f6
  node_is_random False
  uniqueness time + MAC + clock sequence, not entropy
  sortable  no
  leaks     the creation time, to 100 nanoseconds
  leaks     the node field is a real MAC address: it identifies the machine that generated this id, and every other id from it

Snowflake (twitter)  1541815603606036480
  created   2022-06-28T16:07:40.105000+00:00  (4.4 years ago)
  raw_timestamp 367597485448
  datacenter 11
  worker    26
  sequence  0
  sortable  yes, by time
  leaks     the creation time, to the millisecond
  leaks     no randomness at all: the next id from the same worker in the same millisecond is this one plus 1, so ids are enumerable
```

An id in a URL is public. Depending on which kind you picked, it is also
publishing the millisecond a row was created, the MAC address of the server
that created it, and — if it's sequential — how many customers you signed up
last week.

## Install

```bash
curl -O https://raw.githubusercontent.com/antonidashaci/idpeek/main/idpeek.py
```

Python 3.9+. No dependencies, nothing leaves the machine. Ids can also come in
on stdin, one per line.

## Formats

| | decoded |
| --- | --- |
| **UUID v1 / v6** | 60-bit Gregorian clock (100 ns), clock sequence, node — and whether the node is a real MAC or a random one |
| **UUID v3 / v5** | names the digest; a derived id is reproducible, so it is not a secret |
| **UUID v4** | 122 random bits |
| **UUID v7** | 48-bit Unix ms + 74 random bits |
| **UUID v8**, nil, max | labelled as such |
| **ULID** | 48-bit ms + 80 random bits, Crockford base32 |
| **Snowflake** | timestamp / datacenter / worker / sequence, against the Twitter, Discord, Instagram or Unix epoch |
| **MongoDB ObjectId** | 4-byte second, 5-byte random, 3-byte per-process counter |
| **KSUID** | 32-bit second from its own 2014 epoch + 128-bit payload |
| anything else | treated as an opaque token: alphabet detected, entropy estimated |

## Three things it gets right

**The multicast bit.** A UUID v1 whose node field has the low bit of the first
octet set is using a random node, not a MAC address. That single bit is the
difference between "this id identifies the machine" and "this id is fine" — so
it's reported, not assumed.

**The birthday bound, not the keyspace.** 122 random bits means a 50% chance of
a collision after about 2.9 **quintillion** ids — `sqrt(pi/2 · 2^122)` — not
after 5.3 undecillion. Quoting the keyspace is how a 64-bit random id ends up
sounding safe.

**Entropy only where there is entropy.** A v1 UUID with a real MAC gets no
collision bound at all: its uniqueness comes from the clock and the node, and a
birthday bound computed off 14 bits of clock sequence would be a lie with a
number attached.

Also: the narrowest alphabet wins when guessing a token's entropy. `deadbeef`
is hex at 4 bits a character, not base62 at 5.95 — the generous reading
overstates the entropy by 50%.

## Sort order

Pass several ids and it checks the thing you actually care about when choosing
between them:

```
lexical order does NOT match creation order
```

Which is the whole argument for ULID and UUID v7 over v4 — a sortable id keeps
a B-tree index appending at the right edge instead of writing into random
pages.

## As a library

```python
from idpeek import identify

found = identify("01HQ3V8M2P0000000000000000")
found.kind            # 'ULID'
found.created         # datetime, UTC
found.sortable        # True
found.random_bits     # 80
found.collision_after # 1.5e12
found.leaks           # ['the creation time, to the millisecond', ...]
```

`--json` for the same thing from a shell.

## Note on Snowflakes

A bare 64-bit integer cannot say which epoch it was minted against — the same
bits read as Twitter and as Discord are four years apart. The default is
Twitter; `--snowflake-epoch discord|instagram|unix` for the others. The one
thing it is never a guess about is the structure: 41 bits of time, 10 of
machine, 12 of sequence, no randomness.

## Tests

```bash
pytest
```

## License

MIT
