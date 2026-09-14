import pytest
from pyborsh import BorshDeserializationError

from near.actions import function_call, transfer
from near.delegate import (
    decode_any_signed_delegate,
    decode_signed_delegate,
    decode_signed_delegate_v2,
    delegate_sender,
    encode_signed_delegate,
    sign_delegate_action,
    sign_delegate_action_v2,
)
from near.keys import KeyPairSigner, generate_key
from near.wire import (
    Action,
    DelegateAction,
    DelegateActionV2,
    TransactionNonce,
    delegate_action_signing_hash,
    delegate_action_v2_signing_hash,
    to_wire_public_key,
)


def _delegate(signer):
    return DelegateAction(
        sender_id="alice.near",
        receiver_id="counter.near",
        actions=[function_call("increment", {"by": 2}), transfer("1 yocto")],
        nonce=42,
        max_block_height=10_000,
        public_key=to_wire_public_key(signer.public_key),
    )


def _delegate_v2(signer, nonce=None):
    return DelegateActionV2(
        sender_id="alice.near",
        receiver_id="counter.near",
        actions=[function_call("increment", {"by": 2}), transfer("1 yocto")],
        nonce=nonce or TransactionNonce.GasKeyNonce(nonce=42, nonce_index=1),
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


class TestDelegateV2RoundTrip:
    def test_sign_and_verify(self):
        signer = KeyPairSigner("alice.near", generate_key())
        signed = sign_delegate_action_v2(_delegate_v2(signer), signer)
        assert isinstance(signed, Action.DelegateV2)
        assert signed.delegate_action.v2.nonce == TransactionNonce.GasKeyNonce(
            nonce=42, nonce_index=1
        )
        digest = delegate_action_v2_signing_hash(signed.delegate_action)
        assert signer.public_key.verify(signed.signature.data, digest)

    def test_v1_signature_never_validates_v2(self):
        # Same fields, different domain tag: the hashes must differ.
        signer = KeyPairSigner("alice.near", generate_key())
        v1 = _delegate(signer)
        v2 = _delegate_v2(signer, nonce=TransactionNonce.Nonce(nonce=42))
        v2_signed = sign_delegate_action_v2(v2, signer)
        assert delegate_action_signing_hash(v1) != delegate_action_v2_signing_hash(
            v2_signed.delegate_action
        )

    def test_base64_transport_round_trip(self):
        signer = KeyPairSigner("alice.near", generate_key())
        signed = sign_delegate_action_v2(_delegate_v2(signer), signer)
        payload = encode_signed_delegate(signed)
        restored = decode_signed_delegate_v2(payload)
        assert restored == signed
        digest = delegate_action_v2_signing_hash(restored.delegate_action)
        assert signer.public_key.verify(restored.signature.data, digest)

    def test_decoding_the_wrong_version_fails_loudly(self):
        signer = KeyPairSigner("alice.near", generate_key())
        v1_payload = encode_signed_delegate(sign_delegate_action(_delegate(signer), signer))
        v2_payload = encode_signed_delegate(sign_delegate_action_v2(_delegate_v2(signer), signer))
        with pytest.raises(BorshDeserializationError):
            decode_signed_delegate_v2(v1_payload)
        with pytest.raises(BorshDeserializationError):
            decode_signed_delegate(v2_payload)


class TestAnyVersion:
    def test_auto_detects_version(self):
        signer = KeyPairSigner("alice.near", generate_key())
        v1 = sign_delegate_action(_delegate(signer), signer)
        v2 = sign_delegate_action_v2(_delegate_v2(signer), signer)
        assert decode_any_signed_delegate(encode_signed_delegate(v1)) == v1
        assert decode_any_signed_delegate(encode_signed_delegate(v2)) == v2

    def test_delegate_sender(self):
        signer = KeyPairSigner("alice.near", generate_key())
        assert delegate_sender(sign_delegate_action(_delegate(signer), signer)) == "alice.near"
        assert (
            delegate_sender(sign_delegate_action_v2(_delegate_v2(signer), signer)) == "alice.near"
        )
