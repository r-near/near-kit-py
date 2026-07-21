import json

import base58
import pytest

from near.errors import InvalidAccountIdError, InvalidKeyError
from near.keys import (
    Ed25519KeyPair,
    KeyPairSigner,
    KeyType,
    MlDsa65KeyPair,
    PublicKey,
    generate_key,
    generate_seed_phrase,
    is_valid_account_id,
    key_from_seed_phrase,
    key_from_test_seed,
    load_credentials,
    parse_key,
    validate_account_id,
)


class TestTestSeedDerivation:
    def test_nearcore_committed_vector(self):
        # nearcore core/crypto/src/signature.rs test vector for seed "test".
        kp = key_from_test_seed("test")
        assert str(kp.public_key) == "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847"

    def test_sandbox_default_seed(self):
        # The nearprotocol/sandbox Docker image inits with --test-seed sandbox.
        kp = key_from_test_seed("sandbox")
        assert str(kp.public_key) == "ed25519:8m5xVk5HSrudbw9pptQPLnFsKYAmGGng5hzvjgARxso4"

    def test_too_long_seed_rejected(self):
        with pytest.raises(InvalidKeyError):
            key_from_test_seed("x" * 33)

    def test_empty_seed_rejected(self):
        with pytest.raises(InvalidKeyError):
            key_from_test_seed("")


class TestEd25519:
    def test_generate_and_round_trip(self):
        kp = generate_key()
        restored = Ed25519KeyPair.from_string(kp.secret_key)
        assert restored.public_key == kp.public_key

    def test_sign_verify(self):
        kp = generate_key()
        sig = kp.sign(b"hello")
        assert len(sig) == 64
        assert kp.public_key.verify(sig, b"hello")
        assert not kp.public_key.verify(sig, b"tampered")

    def test_from_seed_32_bytes(self):
        kp = Ed25519KeyPair(b"\x01" * 32)
        assert kp.public_key.key_type == KeyType.ED25519

    def test_mismatched_embedded_pubkey_rejected(self):
        kp = Ed25519KeyPair(b"\x01" * 32)
        bad = b"\x01" * 32 + b"\x00" * 32
        with pytest.raises(InvalidKeyError, match="does not match"):
            Ed25519KeyPair(bad)
        # Sanity: the real 64-byte form works.
        import base58 as b58

        raw = b58.b58decode(kp.secret_key.removeprefix("ed25519:"))
        assert Ed25519KeyPair(raw).public_key == kp.public_key

    def test_bad_length(self):
        with pytest.raises(InvalidKeyError):
            Ed25519KeyPair(b"\x01" * 31)

    def test_from_string_requires_prefix(self):
        with pytest.raises(InvalidKeyError, match="must start with"):
            Ed25519KeyPair.from_string("ml-dsa-65:whatever")

    def test_repr_shows_public_key_only(self):
        kp = generate_key()
        assert repr(kp) == f"Ed25519KeyPair(public_key={kp.public_key})"
        assert kp.secret_key not in repr(kp)


class TestPublicKey:
    def test_parse_round_trip(self):
        kp = generate_key()
        parsed = PublicKey.parse(str(kp.public_key))
        assert parsed == kp.public_key

    def test_unsupported_prefix(self):
        with pytest.raises(InvalidKeyError):
            PublicKey.parse("rsa:abc")

    def test_hash_handle_rejected(self):
        with pytest.raises(InvalidKeyError, match="view handle"):
            PublicKey.parse("ml-dsa-65-hash:" + "1" * 32)

    def test_wrong_length_rejected(self):
        with pytest.raises(InvalidKeyError, match="32 bytes"):
            PublicKey.parse("ed25519:2VfE")

    def test_invalid_base58_rejected(self):
        # "0" is not in the base58 alphabet.
        with pytest.raises(InvalidKeyError, match="Invalid base58"):
            PublicKey.parse("ed25519:0000")

    def test_repr_round_trips(self):
        pk = generate_key().public_key
        assert repr(pk) == f"PublicKey('{pk}')"

    def test_secp256k1_parses_but_cannot_verify(self):
        data = bytes(range(64))
        key_string = "secp256k1:" + base58.b58encode(data).decode()
        pk = PublicKey.parse(key_string)
        assert pk.key_type == KeyType.SECP256K1
        assert str(pk) == key_string
        with pytest.raises(InvalidKeyError, match="not supported"):
            pk.verify(b"sig", b"msg")


class TestMlDsa65:
    def test_generate_sign_verify(self):
        kp = MlDsa65KeyPair.generate()
        assert len(kp.public_key.data) == 1952
        sig = kp.sign(b"hello")
        assert len(sig) == 3309
        assert kp.public_key.verify(sig, b"hello")
        assert not kp.public_key.verify(sig, b"tampered")

    def test_seed_round_trip(self):
        kp = MlDsa65KeyPair(b"\x02" * 32)
        restored = MlDsa65KeyPair.from_string(kp.secret_key)
        assert restored.public_key == kp.public_key

    def test_expanded_secret_rejected(self):
        with pytest.raises(InvalidKeyError, match="seed form"):
            MlDsa65KeyPair(b"\x00" * 4032)

    def test_hash_handle_rejected(self):
        with pytest.raises(InvalidKeyError, match="view handle"):
            MlDsa65KeyPair.from_string("ml-dsa-65-hash:" + "1" * 32)

    def test_wrong_seed_length_rejected(self):
        with pytest.raises(InvalidKeyError, match="32 bytes"):
            MlDsa65KeyPair(b"\x00" * 31)

    def test_from_string_requires_prefix(self):
        with pytest.raises(InvalidKeyError, match="must start with"):
            MlDsa65KeyPair.from_string("ed25519:whatever")

    def test_repr_hides_key_material(self):
        kp = MlDsa65KeyPair(b"\x02" * 32)
        assert repr(kp) == "MlDsa65KeyPair(public_key=PublicKey('ml-dsa-65:...'))"


class TestParseKey:
    def test_dispatch(self):
        ed = generate_key()
        assert isinstance(parse_key(ed.secret_key), Ed25519KeyPair)
        ml = MlDsa65KeyPair.generate()
        assert isinstance(parse_key(ml.secret_key), MlDsa65KeyPair)

    def test_secp256k1_unsupported(self):
        with pytest.raises(InvalidKeyError, match="secp256k1"):
            parse_key("secp256k1:abc")

    def test_unknown_prefix_rejected(self):
        with pytest.raises(InvalidKeyError, match="Unsupported key type"):
            parse_key("rsa:abc")


class TestSeedPhrases:
    def test_generate_lengths(self):
        assert len(generate_seed_phrase().split()) == 12
        assert len(generate_seed_phrase(24).split()) == 24

    def test_deterministic(self):
        phrase = generate_seed_phrase()
        a = key_from_seed_phrase(phrase)
        b = key_from_seed_phrase(phrase)
        assert a.public_key == b.public_key

    def test_normalization(self):
        phrase = generate_seed_phrase()
        messy = "  " + phrase.upper().replace(" ", "   ") + " "
        assert key_from_seed_phrase(messy).public_key == key_from_seed_phrase(phrase).public_key

    def test_invalid_phrase(self):
        with pytest.raises(InvalidKeyError):
            key_from_seed_phrase("not a valid phrase at all")

    def test_invalid_word_count(self):
        with pytest.raises(InvalidKeyError, match="word_count"):
            generate_seed_phrase(13)

    def test_non_hardened_path_rejected(self):
        with pytest.raises(InvalidKeyError, match="Invalid derivation path"):
            key_from_seed_phrase(generate_seed_phrase(), path="m/44'/397'/0")

    def test_derived_key_signs(self):
        kp = key_from_seed_phrase(generate_seed_phrase())
        assert kp.public_key.verify(kp.sign(b"x"), b"x")


class TestCredentials:
    def test_load(self, tmp_path):
        kp = generate_key()
        creds_dir = tmp_path / "testnet"
        creds_dir.mkdir()
        (creds_dir / "alice.testnet.json").write_text(
            json.dumps(
                {
                    "account_id": "alice.testnet",
                    "public_key": str(kp.public_key),
                    "private_key": kp.secret_key,
                }
            )
        )
        signer = load_credentials("alice.testnet", "testnet", credentials_dir=tmp_path)
        assert isinstance(signer, KeyPairSigner)
        assert signer.account_id == "alice.testnet"
        assert signer.public_key == kp.public_key

    def test_secret_key_field_accepted(self, tmp_path):
        kp = generate_key()
        creds_dir = tmp_path / "testnet"
        creds_dir.mkdir()
        (creds_dir / "bob.testnet.json").write_text(
            json.dumps({"account_id": "bob.testnet", "secret_key": kp.secret_key})
        )
        assert load_credentials("bob.testnet", "testnet", credentials_dir=tmp_path)

    def test_missing_file(self, tmp_path):
        with pytest.raises(InvalidKeyError, match="No credentials file"):
            load_credentials("ghost.testnet", "testnet", credentials_dir=tmp_path)

    def test_file_without_key_rejected(self, tmp_path):
        creds_dir = tmp_path / "testnet"
        creds_dir.mkdir()
        (creds_dir / "keyless.testnet.json").write_text(
            json.dumps({"account_id": "keyless.testnet"})
        )
        with pytest.raises(InvalidKeyError, match="no private_key"):
            load_credentials("keyless.testnet", "testnet", credentials_dir=tmp_path)


class TestAccountIds:
    @pytest.mark.parametrize(
        "account_id",
        ["alice.near", "sandbox", "a-b_c.d-e", "sub.alice.testnet", "ab", "0x123.near"],
    )
    def test_valid(self, account_id):
        assert is_valid_account_id(account_id)
        assert validate_account_id(account_id) == account_id

    @pytest.mark.parametrize(
        "account_id",
        ["a", "Alice.near", "a..b", "-ab", "ab-", "a b", "x" * 65, ""],
    )
    def test_invalid(self, account_id):
        assert not is_valid_account_id(account_id)
        with pytest.raises(InvalidAccountIdError):
            validate_account_id(account_id)
