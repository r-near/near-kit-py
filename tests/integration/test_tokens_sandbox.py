"""End-to-end NEP-141 / NEP-171 tests against the vendored reference contracts.

The wasm fixtures are the canonical near-examples builds (FT and NFT), so the
contracts — not this SDK — define what a correct transfer looks like.
"""

from pathlib import Path

import pytest

from near import (
    ContractPanicError,
    FTMetadata,
    Near,
    TokenAmount,
    add_full_access_key,
    create_account,
    deploy_contract,
    function_call,
    generate_key,
    transfer,
)
from near.keys import KeyPairSigner

CONTRACTS = Path(__file__).parent.parent / "contracts"
TOTAL_SUPPLY = 10**33  # one billion whole tokens at the contract's 24 decimals

pytestmark = pytest.mark.integration


def _make_account(near: Near, name: str, deposit: str = "10 NEAR") -> KeyPairSigner:
    account_id = f"{name}.{near.signer.account_id}"
    key = generate_key()
    near.send_transaction(
        account_id,
        actions=[create_account(), transfer(deposit), add_full_access_key(key.public_key)],
        wait_until="FINAL",
    )
    return KeyPairSigner(account_id=account_id, key_pair=key)


def _deploy(near: Near, name: str, wasm: str, init_args: dict) -> str:
    account_id = f"{name}.{near.signer.account_id}"
    key = generate_key()
    near.send_transaction(
        account_id,
        actions=[
            create_account(),
            transfer("30 NEAR"),
            add_full_access_key(key.public_key),
            deploy_contract((CONTRACTS / wasm).read_bytes()),
            function_call("new_default_meta", init_args),
        ],
        wait_until="FINAL",
    )
    return account_id


@pytest.fixture(scope="session")
def ft(near, run_id):
    """Deploy the reference FT contract once per session (owner = sandbox root)."""
    return _deploy(
        near,
        f"ft-{run_id}",
        "fungible_token.wasm",
        {"owner_id": near.signer.account_id, "total_supply": str(TOTAL_SUPPLY)},
    )


@pytest.fixture(scope="session")
def nft(near, run_id):
    """Deploy the reference NFT contract once per session (owner = sandbox root)."""
    return _deploy(
        near, f"nft-{run_id}", "non_fungible_token.wasm", {"owner_id": near.signer.account_id}
    )


class TestFungibleToken:
    def test_metadata_parses_and_caches(self, near, ft):
        metadata = near.ft_metadata(ft)
        assert isinstance(metadata, FTMetadata)
        assert metadata.spec == "ft-1.0.0"
        assert metadata.symbol == "EXAMPLE"
        assert metadata.decimals == 24
        assert near.ft_metadata(ft) is metadata  # second read hits the cache

    def test_owner_balance_is_token_amount(self, near, ft):
        balance = near.ft_balance(ft)  # defaults to the signer (the owner)
        assert isinstance(balance, TokenAmount)
        assert balance.symbol == "EXAMPLE"
        assert balance.decimals == 24
        assert 0 < balance <= TOTAL_SUPPLY
        assert str(balance).endswith(" EXAMPLE")

    def test_transfer_with_register_moves_exact_balances(self, near, ft, unique_id):
        alice = _make_account(near, unique_id)
        owner_before = near.ft_balance(ft)
        near.ft_transfer(ft, alice.account_id, "2.5 EXAMPLE", register=True, wait_until="FINAL")
        alice_balance = near.ft_balance(ft, alice.account_id)
        assert alice_balance == TokenAmount.parse("2.5", near.ft_metadata(ft))
        assert str(alice_balance) == "2.5 EXAMPLE"
        assert owner_before - near.ft_balance(ft) == alice_balance

    def test_register_skips_deposit_when_already_registered(self, near, ft, unique_id):
        carol = _make_account(near, unique_id)
        near.ft_transfer(ft, carol.account_id, "1", register=True, wait_until="FINAL")
        near.ft_transfer(ft, carol.account_id, "0.5", register=True, wait_until="FINAL")
        assert near.ft_balance(ft, carol.account_id) == TokenAmount.parse(
            "1.5", near.ft_metadata(ft)
        )

    def test_transfer_without_register_surfaces_contract_panic(self, near, ft, unique_id):
        bob = _make_account(near, unique_id)
        with pytest.raises(ContractPanicError, match="not registered"):
            near.ft_transfer(ft, bob.account_id, "1 EXAMPLE")

    def test_transfer_call_refunds_when_receiver_cannot_handle(self, near, ft, unique_id):
        # A registered receiver with no ft_on_transfer: the receipt fails
        # (surfaced as a panic) and the contract refunds the full amount.
        dave = _make_account(near, unique_id)
        near.ft_transfer(ft, dave.account_id, "1", register=True, wait_until="FINAL")
        owner_before = near.ft_balance(ft)
        with pytest.raises(ContractPanicError):
            near.ft_transfer_call(ft, dave.account_id, "1", "a message", wait_until="FINAL")
        assert near.ft_balance(ft) == owner_before
        assert near.ft_balance(ft, dave.account_id) == TokenAmount.parse("1", near.ft_metadata(ft))

    def test_transfer_call_register_batches_storage_deposit(self, near, ft, unique_id):
        # An unregistered receiver: without register= the transfer itself panics
        # with "not registered"; with register=True the storage_deposit lands in
        # the same transaction, so only the (missing) ft_on_transfer fails and
        # the registration outlives the refund.
        frank = _make_account(near, unique_id)
        owner_before = near.ft_balance(ft)
        with pytest.raises(ContractPanicError):
            near.ft_transfer_call(
                ft, frank.account_id, "1", "a message", register=True, wait_until="FINAL"
            )
        assert near.view(ft, "storage_balance_of", {"account_id": frank.account_id}) is not None
        assert near.ft_balance(ft) == owner_before  # refunded, not lost


class TestNonFungibleToken:
    def test_mint_enumerate_transfer(self, near, nft, unique_id):
        token_id = f"token-{unique_id}"
        # The vendored reference contract predates `receiver_id`: minting
        # takes token_owner_id. Minting is contract-specific, so it goes
        # through plain `call` rather than a client method.
        near.call(
            nft,
            "nft_mint",
            {
                "token_id": token_id,
                "token_owner_id": near.signer.account_id,
                "token_metadata": {"title": "near-kit test token", "copies": 1},
            },
            deposit="0.1 NEAR",
            wait_until="FINAL",
        )

        metadata = near.nft_metadata(nft)
        assert metadata["spec"] == "nft-1.0.0"
        assert near.nft_metadata(nft) is metadata  # cached

        owned = near.nft_tokens_for_owner(nft)  # defaults to the signer
        assert any(t["token_id"] == token_id for t in owned)

        recipient = _make_account(near, f"{unique_id}n")
        near.nft_transfer(nft, recipient.account_id, token_id, wait_until="FINAL")
        token = near.nft_token(nft, token_id)
        assert token is not None
        assert token["owner_id"] == recipient.account_id
        assert any(
            t["token_id"] == token_id for t in near.nft_tokens_for_owner(nft, recipient.account_id)
        )

    def test_missing_token_is_none(self, near, nft):
        assert near.nft_token(nft, "no-such-token") is None


class TestAsyncTokens:
    async def test_ft_flow_mirrors_sync(self, anear, near, ft, unique_id):
        erin = _make_account(near, unique_id)
        metadata = await anear.ft_metadata(ft)
        assert metadata.symbol == "EXAMPLE"
        await anear.ft_transfer(ft, erin.account_id, "3.25", register=True, wait_until="FINAL")
        balance = await anear.ft_balance(ft, erin.account_id)
        assert str(balance) == "3.25 EXAMPLE"

    async def test_nft_views_mirror_sync(self, anear, nft):
        metadata = await anear.nft_metadata(nft)
        assert metadata["spec"] == "nft-1.0.0"
        assert await anear.nft_token(nft, "no-such-token") is None
