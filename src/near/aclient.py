"""The asynchronous NEAR client — same surface as :class:`near.Near`, awaited.

This mirrors ``client.py`` method-for-method; pure logic lives in
``_core.py`` so only the I/O choreography is duplicated. Keep the two files
in sync when changing either.
"""

from __future__ import annotations

import base64 as b64
from collections.abc import Sequence
from typing import Any, Self, cast

from . import _core
from .delegate import decode_signed_delegate, sign_delegate_action
from .errors import AccessKeyNotFoundError, AccountNotFoundError, InvalidNonceError, RpcError
from .keys import PublicKey, Signer
from .models import AccessKeyView, AccountView, KeyInfo, TransactionResult
from .nep413 import SignedMessage, sign_message as _nep413_sign
from .rpc import AsyncRpcTransport, raise_for_execution_failure
from .units import DEFAULT_GAS, ZERO, Amount, Gas
from .wire import (
    Action,
    AnyAction,
    DelegateAction,
    NonDelegateAction,
    sign_transaction,
    to_wire_public_key,
)

__all__ = ["AsyncNear"]


class AsyncNear:
    """The async twin of :class:`near.Near` for asyncio applications.

    ::

        async with AsyncNear(network="testnet", ...) as near:
            await near.call("counter.testnet", "increment")
    """

    def __init__(
        self,
        network: str | None = None,
        *,
        rpc_url: str | None = None,
        account_id: str | None = None,
        private_key: str | None = None,
        signer: Signer | None = None,
        timeout: float = 30.0,
        retries: int = 4,
        credentials_dir: Any = None,
    ) -> None:
        self.network = _core.resolve_network(network)
        self.rpc_url = _core.resolve_rpc_url(self.network, rpc_url)
        self.signer = _core.resolve_signer(
            network=self.network,
            account_id=account_id,
            private_key=private_key,
            signer=signer,
            credentials_dir=credentials_dir,
        )
        self._transport = AsyncRpcTransport(self.rpc_url, timeout=timeout, retries=retries)
        self._nonces = _core.NonceCache()

    @classmethod
    def from_file(
        cls,
        account_id: str,
        network: str = "mainnet",
        *,
        credentials_dir: Any = None,
        **kwargs: Any,
    ) -> AsyncNear:
        """A client signing as ``account_id`` using ``~/.near-credentials``."""
        from .keys import load_credentials

        signer = load_credentials(account_id, network, credentials_dir=credentials_dir)
        return cls(network, signer=signer, **kwargs)

    def with_signer(self, signer: Signer) -> AsyncNear:
        """A copy of this client using a different signer (shares the connection pool)."""
        clone = object.__new__(AsyncNear)
        clone.__dict__.update(self.__dict__)
        clone.signer = signer
        clone._nonces = _core.NonceCache()  # noqa: SLF001
        return clone

    # ------------------------------------------------------------------
    # Reads (no signer required)
    # ------------------------------------------------------------------

    async def view(
        self,
        contract_id: str,
        method: str,
        args: dict[str, Any] | Sequence[Any] | bytes | None = None,
        *,
        block: int | str | None = None,
    ) -> Any:
        """Call a read-only contract method. Free; returns the JSON-decoded result."""
        from .actions import encode_args

        args_b64 = b64.b64encode(encode_args(args)).decode()
        result = await self._transport.call(
            "query", _core.view_params(contract_id, method, args_b64, block)
        )
        return _core.decode_view_result(result, contract_id, method)

    async def balance(self, account_id: str | None = None) -> Amount:
        """The account's liquid balance (defaults to the signer's account)."""
        return (await self.account(account_id)).amount

    async def account(self, account_id: str | None = None) -> AccountView:
        """Account state: balance, locked stake, storage, code hash."""
        target = _core.default_account_id(self.signer, account_id)
        result = await self._transport.call("query", _core.account_params(target))
        return AccountView.model_validate(result)

    async def account_exists(self, account_id: str) -> bool:
        try:
            await self.account(account_id)
        except AccountNotFoundError:
            return False
        return True

    async def access_keys(self, account_id: str | None = None) -> list[KeyInfo]:
        """All access keys on the account."""
        target = _core.default_account_id(self.signer, account_id)
        result = await self._transport.call("query", _core.access_key_list_params(target))
        return [KeyInfo.model_validate(entry) for entry in result.get("keys", [])]

    async def access_key(self, account_id: str, public_key: str | PublicKey) -> AccessKeyView:
        """One access key's nonce and permission."""
        result = await self._fetch_access_key(account_id, str(public_key))
        return AccessKeyView.model_validate(result)

    async def transaction_status(
        self,
        tx_hash: str,
        *,
        sender_id: str | None = None,
        wait_until: str = _core.DEFAULT_WAIT,
    ) -> TransactionResult:
        """Look up a transaction by hash."""
        params = {
            "tx_hash": tx_hash,
            "sender_account_id": _core.default_account_id(self.signer, sender_id),
            "wait_until": wait_until,
        }
        return TransactionResult.model_validate(await self._transport.call("tx", params))

    async def rpc(self, method: str, params: Any) -> Any:
        """Escape hatch: raw JSON-RPC call (still gets typed error classification)."""
        return await self._transport.call(method, params)

    # ------------------------------------------------------------------
    # Writes (require a signer)
    # ------------------------------------------------------------------

    async def call(
        self,
        contract_id: str,
        method: str,
        args: dict[str, Any] | Sequence[Any] | bytes | None = None,
        *,
        gas: str | Gas = DEFAULT_GAS,
        deposit: str | Amount = ZERO,
        wait_until: str = _core.DEFAULT_WAIT,
        signer: Signer | None = None,
    ) -> TransactionResult:
        """Call a state-changing contract method (costs gas)."""
        from .actions import function_call

        action = function_call(method, args, gas=gas, deposit=deposit)
        return await self.send_transaction(
            contract_id, [action], wait_until=wait_until, signer=signer
        )

    async def send(
        self,
        receiver_id: str,
        amount: str | Amount,
        *,
        wait_until: str = _core.DEFAULT_WAIT,
        signer: Signer | None = None,
    ) -> TransactionResult:
        """Send NEAR tokens."""
        from .actions import transfer

        return await self.send_transaction(
            receiver_id, [transfer(amount)], wait_until=wait_until, signer=signer
        )

    async def send_transaction(
        self,
        receiver_id: str,
        actions: Sequence[AnyAction],
        *,
        wait_until: str = _core.DEFAULT_WAIT,
        signer: Signer | None = None,
    ) -> TransactionResult:
        """Sign and send a (possibly multi-action) transaction atomically."""
        active = _core.require_signer(signer or self.signer)
        key = _core.NonceCache.key(active)
        last_error: Exception | None = None

        for attempt in range(3):
            on_chain_nonce = None
            if attempt or not self._nonces.has(key):
                ak = await self._fetch_access_key(active.account_id, str(active.public_key))
                on_chain_nonce = int(ak["nonce"])
            nonce = self._nonces.reserve(key, on_chain_nonce)
            block = await self._transport.call("block", {"finality": "final"})
            block_hash = _core.block_hash_of(block)
            tx = _core.build_transaction(active, receiver_id, list(actions), nonce, block_hash)
            _, signed_raw = sign_transaction(tx, active)
            try:
                result = await self._transport.call(
                    "send_tx",
                    {
                        "signed_tx_base64": b64.b64encode(signed_raw).decode(),
                        "wait_until": wait_until,
                    },
                )
            except InvalidNonceError as exc:
                last_error = exc
                if exc.ak_nonce is not None:
                    self._nonces.sync_to(key, exc.ak_nonce)
                continue
            if wait_until != "NONE":
                raise_for_execution_failure(result)
            return TransactionResult.model_validate(result)

        raise last_error  # type: ignore[misc]

    # ------------------------------------------------------------------
    # Off-chain signing (NEP-413) and meta-transactions (NEP-366)
    # ------------------------------------------------------------------

    def sign_message(
        self,
        message: str,
        recipient: str,
        *,
        nonce: bytes | None = None,
        callback_url: str | None = None,
        signer: Signer | None = None,
    ) -> SignedMessage:
        """Sign an off-chain NEP-413 message (pure computation, hence not async)."""
        return _nep413_sign(
            _core.require_signer(signer or self.signer), message, recipient, nonce, callback_url
        )

    async def sign_delegate(
        self,
        receiver_id: str,
        actions: Sequence[NonDelegateAction],
        *,
        ttl_blocks: int = 600,
        max_block_height: int | None = None,
        nonce: int | None = None,
        signer: Signer | None = None,
    ) -> Action.SignedDelegate:
        """Sign a NEP-366 delegate action for a relayer to submit (user side)."""
        active = _core.require_signer(signer or self.signer)
        if nonce is None:
            ak = await self._fetch_access_key(active.account_id, str(active.public_key))
            nonce = int(ak["nonce"]) + 1
        if max_block_height is None:
            block = await self._transport.call("block", {"finality": "final"})
            max_block_height = int(block["header"]["height"]) + ttl_blocks
        delegate = DelegateAction(
            sender_id=active.account_id,
            receiver_id=receiver_id,
            actions=list(actions),
            nonce=nonce,
            max_block_height=max_block_height,
            public_key=to_wire_public_key(active.public_key),
        )
        return sign_delegate_action(delegate, active)

    async def send_delegate(
        self,
        signed: Action.SignedDelegate | str,
        *,
        wait_until: str = _core.DEFAULT_WAIT,
    ) -> TransactionResult:
        """Submit a user's signed delegate action, paying its gas (relayer side)."""
        if isinstance(signed, str):
            signed = decode_signed_delegate(signed)
        return await self.send_transaction(
            signed.delegate_action.sender_id, [signed], wait_until=wait_until
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def aclose(self) -> None:
        await self._transport.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        who = self.signer.account_id if self.signer else "read-only"
        return f"AsyncNear(network={self.network!r}, signer={who!r})"

    # ------------------------------------------------------------------

    async def _fetch_access_key(self, account_id: str, public_key: str) -> dict[str, Any]:
        result = await self._transport.call(
            "query", _core.access_key_params(account_id, public_key)
        )
        if isinstance(result, dict) and (error := result.get("error")):
            if "does not exist" in str(error):
                raise AccessKeyNotFoundError(account_id, public_key, data=result)
            raise RpcError(f"Query error: {error}", data=result)
        return cast("dict[str, Any]", result)
