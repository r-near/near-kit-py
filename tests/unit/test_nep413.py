import base64
import time

from near.keys import generate_key
from near.nep413 import SignedMessage, generate_nonce, sign_message, verify_message
from near.testing import sandbox_signer


def _signer():
    return sandbox_signer("test.near", seed="test")


# Golden vectors generated once with near-kit-ts (Ed25519KeyPair.signNep413Message),
# key = nearcore test-seed "test", nonce = bytes(range(32)). These prove byte-level
# interop with the TS implementation — the chain never sees NEP-413 payloads, so
# this is the only external oracle.
GOLDEN_NONCE = bytes(range(32))
GOLDEN_BASIC_SIG = (
    "7dK4FGg2H5hivvjklYoU8Xs7ZiBcMXrZenjsJTfIFDes0O+nc3brE2c1oSquISc4BHU5DU+qAKgJ+KOo6OAeAg=="
)
GOLDEN_CALLBACK_SIG = (
    "U6Bb6JdJmZn/kq9Wdz9wxUaafwcwirdaAHLQhv7aEGiz1uNtMzQpgxICYrQjFbQXVegJa6MZWnCs1W9cP2meDA=="
)


class TestGoldenVectors:
    def test_matches_near_kit_ts(self):
        signed = sign_message(_signer(), "Hello NEAR", "app.near", nonce=GOLDEN_NONCE)
        assert signed.public_key == "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847"
        assert signed.signature == GOLDEN_BASIC_SIG

    def test_matches_near_kit_ts_with_callback(self):
        signed = sign_message(
            _signer(),
            "Hello NEAR",
            "app.near",
            nonce=GOLDEN_NONCE,
            callback_url="https://example.com/cb",
        )
        assert signed.signature == GOLDEN_CALLBACK_SIG


class TestSignVerify:
    def test_round_trip(self):
        nonce = generate_nonce()
        signed = sign_message(_signer(), "login", "app.near", nonce=nonce)
        assert verify_message(signed, "login", "app.near", nonce)

    def test_tampered_message_fails(self):
        nonce = generate_nonce()
        signed = sign_message(_signer(), "login", "app.near", nonce=nonce)
        assert not verify_message(signed, "l0gin", "app.near", nonce)

    def test_wrong_recipient_fails(self):
        nonce = generate_nonce()
        signed = sign_message(_signer(), "login", "app.near", nonce=nonce)
        assert not verify_message(signed, "login", "evil.near", nonce)

    def test_wrong_key_fails(self):
        nonce = generate_nonce()
        signed = sign_message(_signer(), "login", "app.near", nonce=nonce)
        impostor = SignedMessage(
            account_id=signed.account_id,
            public_key=str(generate_key().public_key),
            signature=signed.signature,
        )
        assert not verify_message(impostor, "login", "app.near", nonce)

    def test_expired_nonce_fails(self):
        old = (int(time.time() * 1000) - 10 * 60 * 1000).to_bytes(8, "big") + bytes(24)
        signed = sign_message(_signer(), "login", "app.near", nonce=old)
        assert not verify_message(signed, "login", "app.near", old)
        # Opting out of expiry accepts it.
        assert verify_message(signed, "login", "app.near", old, max_age_ms=None)

    def test_future_nonce_fails(self):
        future = (int(time.time() * 1000) + 60_000).to_bytes(8, "big") + bytes(24)
        signed = sign_message(_signer(), "login", "app.near", nonce=future)
        assert not verify_message(signed, "login", "app.near", future)

    def test_generated_nonce_shape(self):
        nonce = generate_nonce()
        assert len(nonce) == 32
        timestamp = int.from_bytes(nonce[:8], "big")
        assert abs(timestamp - time.time() * 1000) < 5000

    def test_signature_is_base64(self):
        signed = sign_message(_signer(), "x", "y.near")
        assert len(base64.b64decode(signed.signature)) == 64
