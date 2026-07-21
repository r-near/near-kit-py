"""Human-readable NEAR token amounts and gas.

``Amount`` is an ``int`` subclass denominated in yoctoNEAR; ``Gas`` is an
``int`` subclass in raw gas units. Both parse human strings (``"5 NEAR"``,
``"30 Tgas"``) and print themselves back the same way. Bare numbers are
rejected at API boundaries to prevent unit confusion — nobody should ever
count yocto zeros.
"""

from __future__ import annotations

import re
from decimal import Decimal, localcontext
from typing import Any, Self

from .errors import UnitParseError

__all__ = ["DEFAULT_GAS", "MAX_GAS", "ONE_YOCTO", "ZERO", "Amount", "Gas"]

YOCTO_PER_NEAR = 10**24
GAS_PER_TGAS = 10**12

_NEAR_RE = re.compile(r"^(\d+(?:\.\d+)?)\s+NEAR$", re.IGNORECASE)
_YOCTO_RE = re.compile(r"^(\d+)\s+yocto(?:NEAR)?$", re.IGNORECASE)
_TGAS_RE = re.compile(r"^(\d+(?:\.\d+)?)\s+Tgas$", re.IGNORECASE)
_BARE_NUMBER_RE = re.compile(r"^\d+(?:\.\d+)?$")


def _decimal_to_scaled_int(value: str, scale: int, what: str) -> int:
    """Convert a non-negative decimal string to an integer scaled by 10**scale."""
    whole, _, frac = value.partition(".")
    if len(frac) > scale:
        raise UnitParseError(f"{what} has more than {scale} decimal places: {value!r}")
    return int((whole or "0") + frac.ljust(scale, "0"))


def _format_scaled(value: int, scale: int, unit: str) -> str:
    whole, frac = divmod(value, 10**scale)
    if frac == 0:
        return f"{whole} {unit}"
    frac_str = str(frac).rjust(scale, "0").rstrip("0")
    return f"{whole}.{frac_str} {unit}"


class Amount(int):
    """A NEAR token amount, stored exactly as an ``int`` of yoctoNEAR.

    Construct from a human string or explicit classmethods::

        Amount("5 NEAR")  # 5 * 10**24 yocto
        Amount("1 yocto")
        Amount.near("0.25")
        Amount.yocto(1)

    Being an ``int``, it compares and does arithmetic exactly. Arithmetic
    with a :class:`~near.tokens.TokenAmount` raises on either side rather
    than silently mixing yoctoNEAR with token raw units.
    """

    def __new__(cls, value: str | int) -> Self:
        if isinstance(value, bool):
            raise UnitParseError("Cannot create an Amount from a bool")
        if isinstance(value, int):
            # int input is yoctoNEAR (the internal denomination).
            return super().__new__(cls, value)
        if isinstance(value, str):
            text = value.strip()
            if m := _NEAR_RE.match(text):
                return super().__new__(cls, _decimal_to_scaled_int(m.group(1), 24, "NEAR amount"))
            if m := _YOCTO_RE.match(text):
                return super().__new__(cls, int(m.group(1)))
            if _BARE_NUMBER_RE.match(text):
                raise UnitParseError(
                    f'Ambiguous amount: {value!r}. Did you mean "{text} NEAR"?\n'
                    f'  - Write "{text} NEAR" or Amount.near("{text}") for NEAR\n'
                    f'  - Write "{text} yocto" or Amount.yocto({text}) for yoctoNEAR'
                )
            raise UnitParseError(
                f"Invalid amount format: {value!r}. Expected '5 NEAR' or '1000 yocto'."
            )
        raise UnitParseError(f"Cannot create an Amount from {type(value).__name__}")

    @classmethod
    def near(cls, value: str | float | Decimal) -> Amount:
        """An amount given in whole NEAR (accepts int, str, Decimal, or float)."""
        if isinstance(value, bool):
            raise UnitParseError("Cannot create an Amount from a bool")
        text = str(value)
        if text.startswith("-"):
            raise UnitParseError("NEAR amount must be non-negative")
        if not _BARE_NUMBER_RE.match(text):
            raise UnitParseError(f"Invalid NEAR value: {value!r}")
        return cls(_decimal_to_scaled_int(text, 24, "NEAR amount"))

    @classmethod
    def yocto(cls, value: int) -> Amount:
        """An amount given in yoctoNEAR (10^-24 NEAR)."""
        if isinstance(value, bool) or not isinstance(value, int):
            raise UnitParseError(f"yocto amount must be an int, got {type(value).__name__}")
        if value < 0:
            raise UnitParseError("yocto amount must be non-negative")
        return cls(value)

    @property
    def as_near(self) -> Decimal:
        """The exact value in NEAR as a :class:`~decimal.Decimal`."""
        with localcontext() as ctx:
            ctx.prec = 60
            return Decimal(int(self)).scaleb(-24)

    def __str__(self) -> str:
        # Dust amounts read better in yocto than as 0.000...001 NEAR.
        if 0 < self < 10**21:
            return f"{int(self)} yocto"
        return _format_scaled(int(self), 24, "NEAR")

    def __repr__(self) -> str:
        return f"Amount('{self}')"

    def __add__(self, other: Any) -> Any:
        _reject_token_amount(other)
        return _wrap(super().__add__(other), type(self))

    def __radd__(self, other: Any) -> Any:
        _reject_token_amount(other)
        return _wrap(super().__radd__(other), type(self))

    def __sub__(self, other: Any) -> Any:
        _reject_token_amount(other)
        return _wrap(super().__sub__(other), type(self))

    def __rsub__(self, other: Any) -> Any:
        _reject_token_amount(other)
        return _wrap(super().__rsub__(other), type(self))

    def __mul__(self, other: Any) -> Any:
        _reject_token_amount(other)
        return _wrap(super().__mul__(other), type(self))

    def __rmul__(self, other: Any) -> Any:
        _reject_token_amount(other)
        return _wrap(super().__rmul__(other), type(self))

    def __floordiv__(self, other: Any) -> Any:
        _reject_token_amount(other)
        return _wrap(super().__floordiv__(other), type(self))

    def __mod__(self, other: Any) -> Any:
        _reject_token_amount(other)
        return _wrap(super().__mod__(other), type(self))

    @classmethod
    def _validate(cls, value: Any) -> Amount:
        # Pydantic boundary (RPC JSON): digit strings are yocto, per NEAR RPC convention.
        if isinstance(value, cls):
            return value
        if isinstance(value, str) and value.isdigit():
            return cls(int(value))
        return cls(value)

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any) -> Any:
        from pydantic_core import core_schema

        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: str(int(v)), return_schema=core_schema.str_schema(), when_used="json"
            ),
        )


class Gas(int):
    """A gas amount, stored as an ``int`` of raw gas units.

    Construct from a human string, a raw-unit digit string, or classmethods::

        Gas("30 Tgas")
        Gas("30000000000000")  # raw gas units (power users)
        Gas.tgas(30)
    """

    def __new__(cls, value: str | int) -> Self:
        if isinstance(value, bool):
            raise UnitParseError("Cannot create Gas from a bool")
        if isinstance(value, int):
            return super().__new__(cls, value)
        if isinstance(value, str):
            text = value.strip()
            if m := _TGAS_RE.match(text):
                return super().__new__(cls, _decimal_to_scaled_int(m.group(1), 12, "Tgas amount"))
            if text.isdigit():
                # Raw gas units, for power users specifying exact gas.
                return super().__new__(cls, int(text))
            raise UnitParseError(
                f"Invalid gas format: {value!r}. Expected '30 Tgas' or raw gas units as digits."
            )
        raise UnitParseError(f"Cannot create Gas from {type(value).__name__}")

    @classmethod
    def tgas(cls, value: str | float | Decimal) -> Gas:
        """A gas amount given in teragas."""
        text = str(value)
        if not _BARE_NUMBER_RE.match(text):
            raise UnitParseError(f"Invalid Tgas value: {value!r}")
        return cls(_decimal_to_scaled_int(text, 12, "Tgas amount"))

    @property
    def as_tgas(self) -> Decimal:
        """The exact value in Tgas as a :class:`~decimal.Decimal`."""
        with localcontext() as ctx:
            ctx.prec = 40
            return Decimal(int(self)).scaleb(-12)

    def __str__(self) -> str:
        return _format_scaled(int(self), 12, "Tgas")

    def __repr__(self) -> str:
        return f"Gas('{self}')"

    @classmethod
    def _validate(cls, value: Any) -> Gas:
        if isinstance(value, cls):
            return value
        return cls(value)

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any) -> Any:
        from pydantic_core import core_schema

        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: str(int(v)), return_schema=core_schema.str_schema(), when_used="json"
            ),
        )


def _wrap(result: Any, cls: type) -> Any:
    if result is NotImplemented or not isinstance(result, int) or result < 0:
        return result
    return cls(result)


def _reject_token_amount(other: Any) -> None:
    """Refuse arithmetic that would fold token raw units into yoctoNEAR.

    ``TokenAmount`` raises when an :class:`Amount` is on its left; this is the
    mirror guard for when the ``Amount`` is on the left (``int`` would happily
    add the two, silently producing a wrong NEAR value).
    """
    from .tokens import TokenAmount  # local import: tokens.py imports this module

    if isinstance(other, TokenAmount):
        raise UnitParseError(f"Cannot mix NEAR amounts and {other.symbol} token amounts")


ZERO = Amount(0)
ONE_YOCTO = Amount(1)
DEFAULT_GAS = Gas.tgas(30)
MAX_GAS = Gas.tgas(300)


def as_amount(value: str | Amount, param: str = "amount") -> Amount:
    """Coerce an API-boundary value to :class:`Amount`, rejecting bare numbers."""
    if isinstance(value, Amount):
        return value
    if isinstance(value, str):
        return Amount(value)
    raise UnitParseError(
        f"Bare numbers are ambiguous for {param!r}: got {value!r}. "
        f'Write "5 NEAR", "1 yocto", or use Amount.near()/Amount.yocto().'
    )


def as_gas(value: str | Gas, param: str = "gas") -> Gas:
    """Coerce an API-boundary value to :class:`Gas`, rejecting bare numbers."""
    if isinstance(value, Gas):
        return value
    if isinstance(value, str):
        return Gas(value)
    raise UnitParseError(
        f"Bare numbers are ambiguous for {param!r}: got {value!r}. "
        f'Write "30 Tgas" or use Gas.tgas().'
    )
