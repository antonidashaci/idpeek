#!/usr/bin/env python3
"""Decode an id and say what it gives away.

An id in a URL is public. Depending on which kind you picked, it may also be
telling the world the exact millisecond the row was created, the MAC address of
the machine that created it, and -- if it is sequential -- how many customers
you signed up last week and what the neighbouring ids are.

Paste any of UUID v1-v8, ULID, Snowflake, MongoDB ObjectId, KSUID, or a random
token, and this prints the timestamp, the structure, how much entropy is
actually in there, and what leaks.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# 1582-10-15, the day the Gregorian calendar started, in 100ns ticks.
GREGORIAN_EPOCH = datetime(1582, 10, 15, tzinfo=timezone.utc)
KSUID_EPOCH = 1_400_000_000  # seconds; chosen so a KSUID fits in 32 bits until 2150
SNOWFLAKE_EPOCHS = {
    "twitter": 1_288_834_974_657,
    "discord": 1_420_070_400_000,
    "instagram": 1_314_220_021_721,
    "unix": 0,
}

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

UUID_RE = re.compile(r"^\{?([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f]{4})-?"
                     r"([0-9a-f]{4})-?([0-9a-f]{12})\}?$", re.I)
ULID_RE = re.compile(r"^[0-7][0123456789ABCDEFGHJKMNPQRSTVWXYZ]{25}$", re.I)
OBJECTID_RE = re.compile(r"^[0-9a-f]{24}$", re.I)
KSUID_RE = re.compile(r"^[0-9A-Za-z]{27}$")
SNOWFLAKE_RE = re.compile(r"^\d{15,20}$")


@dataclass
class Id:
    kind: str
    value: str
    created: datetime | None = None
    sortable: bool = False
    random_bits: int = 0
    fields: dict[str, object] = field(default_factory=dict)
    leaks: list[str] = field(default_factory=list)

    @property
    def collision_after(self) -> float | None:
        """Ids before a 50% chance of a collision (the birthday bound).

        sqrt(pi/2 * 2**bits) -- not 2**bits, which is the mistake that makes a
        64-bit random id sound safe.
        """
        if not self.random_bits:
            return None
        return math.sqrt(math.pi / 2) * 2 ** (self.random_bits / 2)


def _decode_base(text: str, alphabet: str) -> int:
    base = len(alphabet)
    total = 0
    index = {c: i for i, c in enumerate(alphabet)}
    for char in text:
        total = total * base + index[char]
    return total


def _ms(milliseconds: int) -> datetime:
    return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)


def _human(count: float) -> str:
    for limit, suffix in ((1e18, "quintillion"), (1e15, "quadrillion"),
                          (1e12, "trillion"), (1e9, "billion"), (1e6, "million"),
                          (1e3, "thousand")):
        if count >= limit:
            return f"{count / limit:.1f} {suffix}"
    return f"{count:.0f}"


# --- UUID --------------------------------------------------------------------


def parse_uuid(text: str) -> Id | None:
    match = UUID_RE.match(text.strip())
    if not match:
        return None
    groups = [g.lower() for g in match.groups()]
    raw = int("".join(groups), 16)
    if raw == 0:
        return Id("UUID nil", text, fields={"note": "all zeroes"})
    if raw == (1 << 128) - 1:
        return Id("UUID max", text, fields={"note": "all ones"})

    version = int(groups[2][0], 16)
    variant_byte = int(groups[3][:2], 16)
    variant = (
        "RFC 4122" if variant_byte >> 6 == 0b10
        else "NCS (pre-standard)" if variant_byte >> 7 == 0
        else "Microsoft GUID" if variant_byte >> 5 == 0b110
        else "reserved"
    )
    out = Id(f"UUID v{version}", text, fields={"variant": variant})

    if version in (1, 6):
        if version == 1:
            ticks = (int(groups[2][1:], 16) << 48) | (int(groups[1], 16) << 32) \
                | int(groups[0], 16)
        else:  # v6 is v1 with the timestamp reordered so it sorts
            ticks = (int(groups[0], 16) << 28) | (int(groups[1], 16) << 12) \
                | int(groups[2][1:], 16)
        out.created = GREGORIAN_EPOCH + timedelta(microseconds=ticks / 10)
        node = int(groups[4], 16)
        clock_seq = int(groups[3], 16) & 0x3FFF
        multicast = bool(node >> 40 & 0x01)
        out.fields["clock_seq"] = clock_seq
        out.fields["node"] = ":".join(
            f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8)
        )
        out.fields["node_is_random"] = multicast
        out.sortable = version == 6
        # With a real MAC, uniqueness comes from the clock and the node, not
        # from entropy -- quoting a birthday bound off 14 bits of clock
        # sequence would be nonsense.
        out.random_bits = 14 + 47 if multicast else 0
        if not multicast:
            out.fields["uniqueness"] = "time + MAC + clock sequence, not entropy"
        out.leaks.append("the creation time, to 100 nanoseconds")
        if multicast:
            out.leaks.append(
                "the node field has the multicast bit set, so it is random "
                "rather than a real MAC address -- which is the safe choice"
            )
        else:
            out.leaks.append(
                "the node field is a real MAC address: it identifies the "
                "machine that generated this id, and every other id from it"
            )
    elif version == 7:
        out.created = _ms(int("".join(groups[:2]), 16))
        out.sortable = True
        out.random_bits = 74
        out.leaks.append("the creation time, to the millisecond")
    elif version == 4:
        out.random_bits = 122
    elif version in (3, 5):
        algorithm = "MD5" if version == 3 else "SHA-1"
        out.random_bits = 0
        out.fields["derivation"] = f"{algorithm} of a namespace plus a name"
        out.leaks.append(
            f"nothing by itself, but it is deterministic: anyone who guesses "
            f"the name can recompute it ({algorithm}), so it is not a secret"
        )
    elif version == 8:
        out.fields["note"] = "v8 is custom by definition; the layout is the vendor's"
    return out


# --- ULID, ObjectId, KSUID ---------------------------------------------------


def parse_ulid(text: str) -> Id | None:
    text = text.strip().upper()
    if not ULID_RE.match(text):
        return None
    try:
        value = _decode_base(text, CROCKFORD)
    except KeyError:
        return None
    out = Id("ULID", text, created=_ms(value >> 80), sortable=True, random_bits=80)
    out.fields["random"] = f"{value & ((1 << 80) - 1):020x}"
    out.leaks.append("the creation time, to the millisecond")
    out.leaks.append(
        "it sorts by time, so two ids reveal which row was created first -- and "
        "roughly how many were created in between, if ids are handed out in a run"
    )
    return out


def parse_objectid(text: str) -> Id | None:
    text = text.strip()
    if not OBJECTID_RE.match(text):
        return None
    seconds = int(text[:8], 16)
    out = Id("MongoDB ObjectId", text,
             created=datetime.fromtimestamp(seconds, tz=timezone.utc),
             sortable=True, random_bits=40)
    out.fields["random"] = text[8:18]
    out.fields["counter"] = int(text[18:], 16)
    out.leaks.append("the creation time, to the second")
    out.leaks.append(
        "the 3-byte counter is sequential per process: two ids a few requests "
        "apart differ by the number of documents created in between"
    )
    return out


def parse_ksuid(text: str) -> Id | None:
    text = text.strip()
    if not KSUID_RE.match(text):
        return None
    try:
        value = _decode_base(text, BASE62)
    except KeyError:
        return None
    if value >= 1 << 160:
        return None
    seconds = value >> 128
    out = Id("KSUID", text,
             created=datetime.fromtimestamp(seconds + KSUID_EPOCH, tz=timezone.utc),
             sortable=True, random_bits=128)
    out.fields["payload"] = f"{value & ((1 << 128) - 1):032x}"
    out.leaks.append("the creation time, to the second")
    return out


def parse_snowflake(text: str, flavour: str = "twitter") -> Id | None:
    text = text.strip()
    if not SNOWFLAKE_RE.match(text):
        return None
    value = int(text)
    if value >= 1 << 63:
        return None
    epoch = SNOWFLAKE_EPOCHS[flavour]
    out = Id(f"Snowflake ({flavour})", text,
             created=_ms((value >> 22) + epoch), sortable=True, random_bits=0)
    out.fields["raw_timestamp"] = value >> 22
    if flavour == "discord":
        out.fields["worker"] = (value >> 17) & 0x1F
        out.fields["process"] = (value >> 12) & 0x1F
    else:
        out.fields["datacenter"] = (value >> 17) & 0x1F
        out.fields["worker"] = (value >> 12) & 0x1F
    out.fields["sequence"] = value & 0xFFF
    out.leaks.append("the creation time, to the millisecond")
    out.leaks.append(
        "no randomness at all: the next id from the same worker in the same "
        "millisecond is this one plus 1, so ids are enumerable"
    )
    return out


def parse_token(text: str) -> Id:
    """Anything else: treat it as a random token and measure the alphabet."""
    text = text.strip()
    # Narrowest alphabet first: `deadbeef` is hex, not base62 with an unlucky
    # draw, and calling it base62 would overstate its entropy by 50%.
    alphabets = (
        ("hex", "0123456789abcdef", False),
        ("base32", CROCKFORD, False),
        ("base62", BASE62, True),
        ("base64url", BASE62 + "-_", True),
    )
    for name, alphabet, case_sensitive in alphabets:
        pool = set(alphabet) if case_sensitive else set(alphabet.lower())
        probe = text if case_sensitive else text.lower()
        if probe and all(char in pool for char in probe):
            bits = int(len(text) * math.log2(len(pool)))
            out = Id(f"opaque token ({name}, {len(text)} chars)", text,
                     random_bits=bits)
            out.fields["alphabet"] = name
            if bits < 64:
                out.leaks.append(
                    f"only ~{bits} bits: short enough to be worth guessing if "
                    "this is used as a capability (a share link, a reset token)"
                )
            return out
    return Id("unrecognised", text)


def identify(text: str, flavour: str = "twitter") -> Id:
    """First parser that recognises the shape wins; order matters.

    A 24-character hex string is an ObjectId, but it is also a valid UUID with
    the dashes removed -- so UUID is tried first and must demand 32 digits.
    """
    for parser in (parse_uuid, parse_ulid, parse_objectid, parse_ksuid):
        found = parser(text)
        if found:
            return found
    found = parse_snowflake(text, flavour)
    return found or parse_token(text)


def describe(found: Id) -> str:
    lines = [f"{found.kind}  {found.value}"]
    if found.created:
        age = datetime.now(timezone.utc) - found.created
        lines.append(f"  created   {found.created.isoformat()}  "
                     f"({_age(age)} ago)")
    for key, value in found.fields.items():
        lines.append(f"  {key:<9} {value}")
    lines.append(f"  sortable  {'yes, by time' if found.sortable else 'no'}")
    if found.random_bits:
        lines.append(f"  entropy   {found.random_bits} random bits -- a 50% "
                     f"chance of a collision after {_human(found.collision_after)} ids")
    for leak in found.leaks:
        lines.append(f"  leaks     {leak}")
    return "\n".join(lines)


def _age(delta: timedelta) -> str:
    seconds = abs(delta.total_seconds())
    sign = "-" if delta.total_seconds() < 0 else ""
    for limit, name in ((31_557_600, "year"), (2_629_800, "month"),
                        (86_400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= limit:
            return f"{sign}{seconds / limit:.1f} {name}s"
    return f"{sign}{seconds:.0f} seconds"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="idpeek",
        description="Decode an id -- UUID, ULID, Snowflake, ObjectId, KSUID -- "
                    "and report what it leaks.",
    )
    parser.add_argument("ids", nargs="*", help="ids to decode, or none to read stdin")
    parser.add_argument("--snowflake-epoch", default="twitter",
                        choices=sorted(SNOWFLAKE_EPOCHS),
                        help="which Snowflake dialect a bare integer is "
                             "(default twitter)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    values = args.ids or [line.strip() for line in sys.stdin if line.strip()]
    if not values:
        print("idpeek: nothing to decode", file=sys.stderr)
        return 2

    results = [identify(value, args.snowflake_epoch) for value in values]
    if args.json:
        print(json.dumps([{
            "kind": r.kind,
            "value": r.value,
            "created": r.created.isoformat() if r.created else None,
            "sortable": r.sortable,
            "random_bits": r.random_bits,
            "collision_after": r.collision_after,
            "fields": r.fields,
            "leaks": r.leaks,
        } for r in results], indent=2, default=str))
    else:
        for index, found in enumerate(results):
            if index:
                print()
            print(describe(found))
        timed = [r for r in results if r.created]
        if len(timed) > 1:
            order_matches = (
                [r.value for r in sorted(timed, key=lambda r: r.value)]
                == [r.value for r in sorted(timed, key=lambda r: r.created)]
            )
            print(f"\nlexical order {'matches' if order_matches else 'does NOT match'}"
                  " creation order")
    return 0 if any(r.kind != "unrecognised" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
