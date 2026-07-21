"""First-class NEP-141 fungible tokens and NEP-171 NFTs.

``TokenAmount`` is to a token what ``Amount`` is to NEAR: an ``int`` of the
token's smallest raw units that knows its symbol and decimals, parses and
prints human strings, and rejects bare numbers at API boundaries — nobody
should ever count token zeros either.
"""

from __future__ import annotations

import re
from decimal import Decimal, localcontext
from typing import Any, Self

from pydantic import BaseModel, ConfigDict

from .errors import UnitParseError
from .units import ONE_YOCTO, Amount, Gas, _decimal_to_scaled_int, _format_scaled, as_gas
from .wire import Action

__all__ = ["FTMetadata", "TokenAmount"]

_TOKEN_RE = re.compile(r"^(\d+(?:\.\d+)?)(?:\s+(\S+))?$")


class FTMetadata(BaseModel):
    """NEP-148 fungible token metadata, as returned by ``ft_metadata``.

    Frozen: clients cache and share one instance per token, so mutating it
    would silently poison every later parse and transfer on that client.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    spec: str
    name: str
    symbol: str
    decimals: int
    icon: str | None = None
    reference: str | None = None
    reference_hash: str | None = None


class TokenAmount(int):
    """A fungible token amount, stored exactly as an ``int`` of raw units.

    Each instance carries the token's ``symbol`` and ``decimals``, so it can
    print itself back in human units. Construct from a human string via
    :meth:`parse` (needs the token's metadata), or from raw units directly::

        TokenAmount.parse("5.25 USDT", metadata)
        TokenAmount(5_250_000, symbol="USDT", decimals=6)

    ``+``/``-``/``*``/``//``/``%`` preserve the type (plain ints count as raw
    units); mixing different tokens — or a NEAR :class:`~near.units.Amount`,
    on either side — raises.
    """

    symbol: str
    decimals: int

    def __new__(cls, value: int, *, symbol: str, decimals: int) -> Self:
        if isinstance(value, bool) or not isinstance(value, int):
            raise UnitParseError(
                f"Raw token units must be an int, got {type(value).__name__}. "
                f"Use TokenAmount.parse() for human strings."
            )
        if value < 0:
            raise UnitParseError("Token amount must be non-negative")
        if decimals < 0:
            raise UnitParseError(f"Token decimals must be non-negative, got {decimals}")
        self = super().__new__(cls, value)
        self.symbol = symbol
        self.decimals = decimals
        return self

    @classmethod
    def parse(cls, text: str, metadata: FTMetadata) -> Self:
        """Parse ``"5.25"`` or ``"5.25 USDT"`` against the token's metadata.

        A symbol, if present, must match ``metadata.symbol`` (case-insensitive).
        """
        if not isinstance(text, str):
            raise UnitParseError(
                f"Bare numbers are ambiguous for token amounts: got {text!r}. "
                f'Write "5.25" or "5.25 {metadata.symbol}".'
            )
        m = _TOKEN_RE.match(text.strip())
        if not m:
            raise UnitParseError(
                f"Invalid token amount: {text!r}. Expected '5.25' or '5.25 {metadata.symbol}'."
            )
        number, symbol = m.group(1), m.group(2)
        if symbol is not None and symbol.upper() != metadata.symbol.upper():
            raise UnitParseError(
                f"Token symbol mismatch: expected {metadata.symbol!r}, got {symbol!r}"
            )
        raw = _decimal_to_scaled_int(number, metadata.decimals, f"{metadata.symbol} amount")
        return cls(raw, symbol=metadata.symbol, decimals=metadata.decimals)

    @property
    def display(self) -> Decimal:
        """The exact value in whole tokens as a :class:`~decimal.Decimal`."""
        with localcontext() as ctx:
            ctx.prec = 60
            return Decimal(int(self)).scaleb(-self.decimals)

    def __str__(self) -> str:
        return _format_scaled(int(self), self.decimals, self.symbol)

    def __repr__(self) -> str:
        return f"TokenAmount({int(self)}, symbol={self.symbol!r}, decimals={self.decimals})"

    def __getnewargs_ex__(self) -> tuple[tuple[int], dict[str, Any]]:
        # symbol/decimals are required by __new__, so tell copy/pickle how to
        # rebuild us (the default reconstructor calls __new__ with no args).
        return ((int(self),), {"symbol": self.symbol, "decimals": self.decimals})

    def __add__(self, other: Any) -> Any:
        self._reject_mixed(other)
        return self._preserve(super().__add__(other))

    def __radd__(self, other: Any) -> Any:
        self._reject_mixed(other)
        return self._preserve(super().__radd__(other))

    def __sub__(self, other: Any) -> Any:
        self._reject_mixed(other)
        return self._preserve(super().__sub__(other))

    def __rsub__(self, other: Any) -> Any:
        self._reject_mixed(other)
        return self._preserve(super().__rsub__(other))

    def __mul__(self, other: Any) -> Any:
        self._reject_mixed(other)
        return self._preserve(super().__mul__(other))

    def __rmul__(self, other: Any) -> Any:
        self._reject_mixed(other)
        return self._preserve(super().__rmul__(other))

    def __floordiv__(self, other: Any) -> Any:
        self._reject_mixed(other)
        return self._preserve(super().__floordiv__(other))

    def __mod__(self, other: Any) -> Any:
        self._reject_mixed(other)
        return self._preserve(super().__mod__(other))

    def _reject_mixed(self, other: Any) -> None:
        if isinstance(other, TokenAmount):
            if other.symbol.upper() != self.symbol.upper() or other.decimals != self.decimals:
                raise UnitParseError(
                    f"Cannot mix token amounts: {self.symbol} ({self.decimals} decimals) "
                    f"and {other.symbol} ({other.decimals} decimals)"
                )
        elif isinstance(other, Amount):
            raise UnitParseError(f"Cannot mix NEAR amounts and {self.symbol} token amounts")

    def _preserve(self, result: Any) -> Any:
        if result is NotImplemented or not isinstance(result, int) or result < 0:
            return result
        return TokenAmount(int(result), symbol=self.symbol, decimals=self.decimals)

    @classmethod
    def _validate(cls, value: Any) -> TokenAmount:
        # Pydantic boundary: raw wire values carry no symbol/decimals, so only
        # existing instances pass through — parse strings explicitly against
        # the token's metadata with TokenAmount.parse() first.
        if isinstance(value, cls):
            return value
        raise UnitParseError(
            f"Cannot validate {value!r} as a TokenAmount without token metadata. "
            f"Use TokenAmount.parse() or TokenAmount(raw, symbol=..., decimals=...)."
        )

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any) -> Any:
        from pydantic_core import core_schema

        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: str(int(v)), return_schema=core_schema.str_schema(), when_used="json"
            ),
        )


def as_token_amount(
    value: str | TokenAmount, metadata: FTMetadata, param: str = "amount"
) -> TokenAmount:
    """Coerce an API-boundary value to :class:`TokenAmount`, rejecting bare numbers."""
    if isinstance(value, TokenAmount):
        if value.symbol.upper() != metadata.symbol.upper() or value.decimals != metadata.decimals:
            raise UnitParseError(
                f"Token mismatch for {param!r}: got {value.symbol} "
                f"({value.decimals} decimals), the contract says {metadata.symbol} "
                f"({metadata.decimals} decimals)"
            )
        return value
    if isinstance(value, str):
        return TokenAmount.parse(value, metadata)
    raise UnitParseError(
        f"Bare numbers are ambiguous for {param!r}: got {value!r}. "
        f'Write "5.25" or "5.25 {metadata.symbol}", or use TokenAmount.parse().'
    )


# ---------------------------------------------------------------------------
# Action builders shared by the sync and async clients (pure, no I/O).
# ---------------------------------------------------------------------------


def _with_memo(args: dict[str, Any], memo: str | None) -> dict[str, Any]:
    if memo is not None:
        args["memo"] = memo
    return args


def ft_transfer_action(
    receiver_id: str, amount: TokenAmount, memo: str | None
) -> Action.FunctionCall:
    """The ``ft_transfer`` call with the 1 yoctoNEAR NEP-141 requires attached."""
    from .actions import function_call

    args = _with_memo({"receiver_id": receiver_id, "amount": str(int(amount))}, memo)
    return function_call("ft_transfer", args, deposit=ONE_YOCTO)


def ft_transfer_call_action(
    receiver_id: str, amount: TokenAmount, msg: str, memo: str | None, gas: str | Gas
) -> Action.FunctionCall:
    """The ``ft_transfer_call`` call (1 yoctoNEAR; gas covers ``ft_on_transfer``)."""
    from .actions import function_call

    args = _with_memo({"receiver_id": receiver_id, "amount": str(int(amount)), "msg": msg}, memo)
    return function_call("ft_transfer_call", args, deposit=ONE_YOCTO, gas=as_gas(gas))


def storage_deposit_action(account_id: str, deposit: Amount) -> Action.FunctionCall:
    """The NEP-145 ``storage_deposit`` registering ``account_id`` on the token."""
    from .actions import function_call

    return function_call("storage_deposit", {"account_id": account_id}, deposit=deposit)


def nft_transfer_action(receiver_id: str, token_id: str, memo: str | None) -> Action.FunctionCall:
    """The ``nft_transfer`` call with the 1 yoctoNEAR NEP-171 requires attached."""
    from .actions import function_call

    args = _with_memo({"receiver_id": receiver_id, "token_id": token_id}, memo)
    return function_call("nft_transfer", args, deposit=ONE_YOCTO)
