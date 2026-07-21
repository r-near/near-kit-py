from near.actions import function_call, transfer
from near.delegate import (
    decode_signed_delegate,
    encode_signed_delegate,
    sign_delegate_action,
)
from near.keys import KeyPairSigner, generate_key
from near.wire import DelegateAction, delegate_action_signing_hash, to_wire_public_key


def _delegate(signer):
    return DelegateAction(
        sender_id="alice.near",
        receiver_id="counter.near",
        actions=[function_call("increment", {"by": 2}), transfer("1 yocto")],
        nonce=42,
        max_block_height=10_000,
        public_key=to_wire_public_key(signer.public_key),
    )


class TestDelegateRoundTrip:
    def test_sign_and_verify(self):
        signer = KeyPairSigner("alice.near", generate_key())
        signed = sign_delegate_action(_delegate(signer), signer)
        digest = delegate_action_signing_hash(signed.delegate_action)
        assert signer.public_key.verify(signed.signature.data, digest)

    def test_base64_transport_round_trip(self):
        signer = KeyPairSigner("alice.near", generate_key())
        signed = sign_delegate_action(_delegate(signer), signer)
        payload = encode_signed_delegate(signed)
        restored = decode_signed_delegate(payload)
        assert restored == signed
        # Signature still verifies after the round trip.
        digest = delegate_action_signing_hash(restored.delegate_action)
        assert signer.public_key.verify(restored.signature.data, digest)
