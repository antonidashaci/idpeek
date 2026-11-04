import json
from datetime import datetime, timezone

from idpeek import identify, main, parse_snowflake, parse_uuid

# A real v1 UUID (uuid1()), a v4, a v7, a ULID, an ObjectId, a KSUID.
V1 = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
V4 = "9b2f3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
V7 = "01931c6e-0c80-7000-8000-0123456789ab"
ULID = "01HQ3V8M2P0000000000000000"
OBJECTID = "65b1f2c3a4b5c6d7e8f90123"


def test_uuid_version_and_variant():
    found = parse_uuid(V4)
    assert found.kind == "UUID v4"
    assert found.fields["variant"] == "RFC 4122"
    assert found.random_bits == 122
    assert found.created is None
    assert not found.sortable


def test_uuid_accepts_braces_and_no_dashes():
    assert parse_uuid("{" + V4 + "}").kind == "UUID v4"
    assert parse_uuid(V4.replace("-", "")).kind == "UUID v4"
    assert parse_uuid(V4.upper()).kind == "UUID v4"


def test_a_v1_uuid_decodes_its_time_and_mac():
    found = parse_uuid(V1)
    assert found.kind == "UUID v1"
    # This is the UUID from RFC 4122's own example; it was minted in 1997.
    assert found.created.year == 1997
    assert found.fields["node"] == "00:a0:c9:1e:6b:f6"
    assert found.fields["node_is_random"] is False
    assert any("MAC address" in leak for leak in found.leaks)
    assert not found.sortable
    # Uniqueness here is the clock plus the MAC, so there is no entropy to
    # quote a birthday bound against.
    assert found.random_bits == 0
    assert found.collision_after is None


def test_a_random_node_is_recognised_by_the_multicast_bit():
    # Set the low bit of the first node octet: the "this is not a real MAC" flag.
    found = parse_uuid("f81d4fae-7dec-11d0-a765-01a0c91e6bf6")
    assert found.fields["node_is_random"] is True
    assert any("multicast bit" in leak for leak in found.leaks)
    assert found.random_bits > 14


def test_v6_is_v1_with_the_same_clock_reordered_to_sort():
    """v6 holds the identical 60-bit timestamp, just most-significant first."""
    time_low = int(V1[0:8], 16)
    time_mid = int(V1[9:13], 16)
    time_hi = int(V1[14:18], 16) & 0x0FFF
    ticks = (time_hi << 48) | (time_mid << 32) | time_low

    v6 = (f"{ticks >> 28:08x}-{(ticks >> 12) & 0xFFFF:04x}-"
          f"6{ticks & 0xFFF:03x}-{V1[19:23]}-{V1[24:]}")
    found = parse_uuid(v6)
    assert found.kind == "UUID v6"
    assert found.sortable
    assert found.created == parse_uuid(V1).created


def test_a_v7_uuid_is_unix_milliseconds():
    found = parse_uuid(V7)
    assert found.kind == "UUID v7"
    assert found.sortable
    assert found.random_bits == 74
    assert found.created > datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert any("millisecond" in leak for leak in found.leaks)


def test_a_name_based_uuid_is_not_a_secret():
    found = parse_uuid("3d813cbb-47fb-32ba-91df-831e1593ac29")  # v3
    assert found.kind == "UUID v3"
    assert found.random_bits == 0
    assert any("recompute" in leak for leak in found.leaks)


def test_nil_and_max_uuids():
    assert parse_uuid("00000000-0000-0000-0000-000000000000").kind == "UUID nil"
    assert parse_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff").kind == "UUID max"


def test_a_microsoft_guid_variant_is_named():
    found = parse_uuid("9b2f3c4d-5e6f-4a7b-cc9d-0e1f2a3b4c5d")
    assert found.fields["variant"] == "Microsoft GUID"


def test_not_a_uuid():
    assert parse_uuid("hello") is None
    assert parse_uuid("9b2f3c4d-5e6f-4a7b-8c9d") is None


# --- the other formats -------------------------------------------------------


def test_ulid():
    found = identify(ULID)
    assert found.kind == "ULID"
    assert found.sortable
    assert found.random_bits == 80
    assert found.created.year >= 2024


def test_a_ulid_is_not_confused_with_a_token():
    # ULIDs exclude I, L, O and U so they cannot be misread; one with a U is not
    # a ULID at all.
    assert identify("01HQ3V8M2P000000000000000U").kind.startswith("opaque token")


def test_objectid():
    found = identify(OBJECTID)
    assert found.kind == "MongoDB ObjectId"
    assert found.created.year == 2024
    assert found.fields["counter"] == 0xF90123
    assert any("sequential" in leak for leak in found.leaks)


def test_a_24_hex_string_is_an_objectid_not_a_short_uuid():
    assert identify(OBJECTID).kind == "MongoDB ObjectId"
    assert identify(V4.replace("-", "")).kind == "UUID v4"


def test_ksuid():
    found = identify("2SMY8SvZ0000000000000000000".replace("0", "1"))
    assert found.kind == "KSUID"
    assert found.random_bits == 128
    assert found.created is not None


def test_snowflake_epochs_differ_by_years():
    twitter = parse_snowflake("1541815603606036480", "twitter")
    discord = parse_snowflake("1541815603606036480", "discord")
    # The same 64 bits, read against two epochs, are four years apart.
    assert twitter.created.year == 2022
    assert discord.created.year == 2026
    assert twitter.fields["datacenter"] == 11
    assert twitter.fields["worker"] == 26
    assert discord.fields["process"] == 26
    assert any("enumerable" in leak for leak in twitter.leaks)


def test_a_snowflake_has_no_entropy_so_no_collision_bound():
    assert parse_snowflake("1541815603606036480").collision_after is None


def test_snowflake_rejects_a_number_too_big_for_64_bits():
    assert parse_snowflake("99999999999999999999") is None


# --- opaque tokens -----------------------------------------------------------


def test_hex_is_not_mistaken_for_base62():
    found = identify("deadbeefdeadbeef")
    assert "hex" in found.kind
    assert found.random_bits == 64


def test_a_base62_token_gets_six_bits_a_character():
    found = identify("Xy7Qz2Lm9Kp4Rt6Ws8Bn1")
    assert "base62" in found.kind
    assert found.random_bits == 125


def test_a_short_token_is_flagged_as_guessable():
    found = identify("abc123")
    assert found.random_bits < 64
    assert any("worth guessing" in leak for leak in found.leaks)


def test_collision_bound_is_the_birthday_bound_not_the_space():
    found = identify(V4)
    # 122 bits: ~2.9e18, not 5.3e36.
    assert 2e18 < found.collision_after < 4e18


def test_unrecognised():
    assert identify("not an id!!").kind == "unrecognised"


# --- CLI ---------------------------------------------------------------------


def test_cli_decodes_and_reports_leaks(capsys):
    assert main([V1]) == 0
    out = capsys.readouterr().out
    assert "UUID v1" in out
    assert "MAC address" in out
    assert "created" in out


def test_cli_compares_sort_order(capsys):
    assert main([V7, ULID]) == 0
    assert "creation order" in capsys.readouterr().out


def test_cli_json(capsys):
    assert main([V7, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report[0]["kind"] == "UUID v7"
    assert report[0]["random_bits"] == 74


def test_cli_snowflake_flavour(capsys):
    assert main(["1541815603606036480", "--snowflake-epoch", "discord"]) == 0
    assert "discord" in capsys.readouterr().out


def test_cli_exit_1_when_nothing_is_recognised(capsys):
    assert main(["not an id!!"]) == 1
