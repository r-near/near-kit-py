"""NEP-616 deterministic account IDs: derivation, canonical encoding, cross-language vectors."""

import pytest

from near import (
    derive_deterministic_account_id,
    deterministic_state_init,
    is_deterministic_account_id,
)
from near.wire import DeterministicAccountStateInit, GlobalContractIdentifier


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "little")


def _bytes(b: bytes) -> bytes:
    return _u32(len(b)) + b


# Golden vectors generated with near-kit-ts (utils/state-init.ts deriveAccountId,
# @noble/hashes keccak_256, @zorsh/zorsh 0.5.0) for the cases whose encoding does
# not involve map ordering. See the class docstring below for the map case.
TS_DERIVED_BY_HASH = "0sd7edcaae250c1c526ddd82f35d6034996c0c1060"  # code hash = bytes(range(32))
TS_DERIVED_EMPTY_BY_ACCOUNT = (
    "0s2293da2d32cd0a067950616036ff973884abab0a"  # publisher.near, no data
)


class TestDerivation:
    def test_matches_near_kit_ts_by_code_hash(self):
        state_init = DeterministicAccountStateInit(
            code=GlobalContractIdentifier.CodeHash(code_hash=bytes(range(32)))
        )
        assert derive_deterministic_account_id(state_init) == TS_DERIVED_BY_HASH

    def test_matches_near_kit_ts_by_account_without_data(self):
        state_init = DeterministicAccountStateInit(
            code=GlobalContractIdentifier.AccountId(account_id="publisher.near")
        )
        assert derive_deterministic_account_id(state_init) == TS_DERIVED_EMPTY_BY_ACCOUNT

    def test_shape(self):
        action = deterministic_state_init(account_id="publisher.near", deposit="1 NEAR")
        derived = derive_deterministic_account_id(action.state_init)
        assert len(derived) == 42
        assert is_deterministic_account_id(derived)

    def test_data_changes_the_id(self):
        without = deterministic_state_init(account_id="publisher.near", deposit="1 NEAR")
        with_data = deterministic_state_init(
            account_id="publisher.near", data={b"k": b"v"}, deposit="1 NEAR"
        )
        assert derive_deterministic_account_id(without.state_init) != (
            derive_deterministic_account_id(with_data.state_init)
        )


class TestCanonicalMap:
    """``data`` is a BTreeMap on the wire: keys sorted bytewise, no duplicates.

    Insertion order must not leak into the bytes, or two clients would derive
    two different IDs for the same state — the sandbox re-derives the ID from
    its own canonical encoding and rejects a mismatch, which the integration
    suite exercises with the same out-of-order keys used here.
    """

    def test_entries_sorted_bytewise_regardless_of_insertion_order(self):
        a = deterministic_state_init(
            account_id="p.near", data={b"zeta": b"last", b"alpha": b"first"}, deposit="1 NEAR"
        )
        b = deterministic_state_init(
            account_id="p.near", data={b"alpha": b"first", b"zeta": b"last"}, deposit="1 NEAR"
        )
        assert a.state_init.data == [(b"alpha", b"first"), (b"zeta", b"last")]
        assert a.state_init.to_borsh() == b.state_init.to_borsh()
        assert derive_deterministic_account_id(a.state_init) == derive_deterministic_account_id(
            b.state_init
        )

    def test_exact_bytes(self):
        action = deterministic_state_init(
            account_id="p.near", data={b"\x10": b"b", b"\x02": b"a"}, deposit="1 NEAR"
        )
        expected = (
            b"\x00\x01"  # DeterministicAccountStateInit::V1 tag, AccountId variant
            + _bytes(b"p.near")
            + _u32(2)  # map length
            + _bytes(b"\x02")
            + _bytes(b"a")
            + _bytes(b"\x10")
            + _bytes(b"b")
        )
        assert action.state_init.to_borsh() == expected

    def test_bytewise_not_lexicographic_by_length(self):
        # b"ab" < b"b" bytewise (0x61 < 0x62) even though it is longer.
        action = deterministic_state_init(
            account_id="p.near", data={b"b": b"", b"ab": b""}, deposit="1 NEAR"
        )
        assert [k for k, _ in action.state_init.data] == [b"ab", b"b"]

    def test_duplicate_keys_rejected(self):
        with pytest.raises(ValueError, match="duplicate state-init key"):
            DeterministicAccountStateInit(
                code=GlobalContractIdentifier.AccountId(account_id="p.near"),
                data=[(b"k", b"1"), (b"k", b"2")],
            )

    def test_round_trip_keeps_pairs(self):
        state_init = DeterministicAccountStateInit(
            code=GlobalContractIdentifier.CodeHash(code_hash=bytes(32)),
            data={b"k": b"v"},
        )
        assert DeterministicAccountStateInit.from_borsh(state_init.to_borsh()) == state_init

    def test_unknown_version_rejected_on_decode(self):
        state_init = DeterministicAccountStateInit(
            code=GlobalContractIdentifier.AccountId(account_id="p.near")
        )
        with pytest.raises(Exception, match="version"):
            DeterministicAccountStateInit.from_borsh(b"\x01" + state_init.to_borsh()[1:])


class TestIsDeterministicAccountId:
    @pytest.mark.parametrize(
        "account_id",
        [
            "0s" + "0" * 40,
            "0s2293da2d32cd0a067950616036ff973884abab0a",
        ],
    )
    def test_accepts(self, account_id):
        assert is_deterministic_account_id(account_id)

    @pytest.mark.parametrize(
        "account_id",
        [
            "alice.near",
            "0x2293da2d32cd0a067950616036ff973884abab0a",  # Ethereum-style implicit
            "0s2293da2d32cd0a067950616036ff973884abab0",  # 39 hex chars
            "0s2293da2d32cd0a067950616036ff973884abab0a0",  # 41 hex chars
            "0S2293DA2D32CD0A067950616036FF973884ABAB0A",  # uppercase
            "0s2293da2d32cd0a067950616036ff973884abab0g",  # non-hex
            "",
        ],
    )
    def test_rejects(self, account_id):
        assert not is_deterministic_account_id(account_id)
