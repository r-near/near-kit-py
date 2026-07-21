"""Test helpers for the NEAR sandbox.

Run the official sandbox like a database service::

    docker run -d -p 3030:3030 nearprotocol/sandbox:2.13.1

and connect with the deterministic root key::

    from near import Near
    from near.testing import sandbox_signer

    near = Near("sandbox", signer=sandbox_signer())

The image inits its chain with ``--test-seed`` (default ``"sandbox"``), so
the root account's key is derived from the seed — nothing needs to be
copied out of the container.
"""

from __future__ import annotations

from .keys import KeyPairSigner, key_from_test_seed

__all__ = ["sandbox_signer"]


def sandbox_signer(account_id: str = "sandbox", seed: str | None = None) -> KeyPairSigner:
    """The deterministic signer for a nearcore sandbox root account.

    By default the ``nearprotocol/sandbox`` image uses account ``sandbox``
    with test seed ``sandbox``; if you override ``NEAR_ROOT_ACCOUNT`` /
    ``NEAR_TEST_SEED`` on the container, pass the matching values here.
    """
    return KeyPairSigner(
        account_id=account_id,
        key_pair=key_from_test_seed(seed if seed is not None else account_id),
    )
