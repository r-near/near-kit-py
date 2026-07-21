import json
from decimal import Decimal

import pytest
from pydantic import BaseModel

from near.errors import UnitParseError
from near.units import DEFAULT_GAS, Amount, Gas, as_amount, as_gas


class TestAmountParsing:
    def test_near_string(self):
        assert Amount("5 NEAR") == 5 * 10**24

    def test_fractional_near(self):
        assert Amount("0.25 NEAR") == 25 * 10**22

    def test_case_insensitive(self):
        assert Amount("5 near") == Amount("5 NEAR")

    def test_yocto_string(self):
        assert Amount("1 yocto") == 1
        assert Amount("1000 yoctoNEAR") == 1000

    def test_int_is_yocto(self):
        assert Amount(10**24) == Amount("1 NEAR")

    def test_bare_number_string_rejected(self):
        with pytest.raises(UnitParseError, match="Ambiguous"):
            Amount("5")

    def test_garbage_rejected(self):
        with pytest.raises(UnitParseError):
            Amount("5 DOGE")

    def test_negative_rejected(self):
        with pytest.raises(UnitParseError):
            Amount("-5 NEAR")

    def test_too_many_decimals_rejected(self):
        with pytest.raises(UnitParseError, match="decimal places"):
            Amount("0." + "1" * 25 + " NEAR")

    def test_near_classmethod_exact(self):
        # 0.1 must be exact — no float artifacts.
        assert Amount.near("0.1") == 10**23
        assert Amount.near(0.1) == 10**23
        assert Amount.near(5) == 5 * 10**24
        assert Amount.near(Decimal("2.5")) == 25 * 10**23

    def test_yocto_classmethod(self):
        assert Amount.yocto(42) == 42
        with pytest.raises(UnitParseError):
            Amount.yocto(1.5)  # type: ignore[arg-type]
        with pytest.raises(UnitParseError):
            Amount.yocto(-1)

    def test_bool_rejected(self):
        with pytest.raises(UnitParseError, match="bool"):
            Amount(True)
        with pytest.raises(UnitParseError, match="bool"):
            Amount.near(True)
        with pytest.raises(UnitParseError, match="bool"):
            Amount.yocto(True)

    def test_float_rejected(self):
        with pytest.raises(UnitParseError, match="float"):
            Amount(1.5)  # type: ignore[arg-type]

    def test_near_classmethod_rejects_negative(self):
        with pytest.raises(UnitParseError, match="non-negative"):
            Amount.near("-1")

    def test_near_classmethod_rejects_garbage(self):
        with pytest.raises(UnitParseError, match="Invalid NEAR value"):
            Amount.near("1e5")


class TestAmountFormatting:
    def test_whole_near(self):
        assert str(Amount("5 NEAR")) == "5 NEAR"

    def test_fractional_trimmed(self):
        assert str(Amount("5.25 NEAR")) == "5.25 NEAR"
        assert str(Amount("5.250 NEAR")) == "5.25 NEAR"

    def test_dust_shows_yocto(self):
        assert str(Amount(1)) == "1 yocto"

    def test_zero(self):
        assert str(Amount(0)) == "0 NEAR"

    def test_repr_round_trips(self):
        amount = Amount("5.25 NEAR")
        assert eval(repr(amount)) == amount  # noqa: S307

    def test_as_near_decimal(self):
        assert Amount("5.25 NEAR").as_near == Decimal("5.25")
        # Large balances must not lose precision.
        big = Amount.near(10**9)
        assert big.as_near == Decimal(10**9)


class TestAmountArithmetic:
    def test_add_preserves_type(self):
        total = Amount("1 NEAR") + Amount("2 NEAR")
        assert isinstance(total, Amount)
        assert str(total) == "3 NEAR"

    def test_sum_works(self):
        total = sum([Amount("1 NEAR"), Amount("2 NEAR")])
        assert isinstance(total, Amount)

    def test_comparison(self):
        assert Amount("2 NEAR") > Amount("1 NEAR")
        assert Amount("1 NEAR") == 10**24

    def test_sub_preserves_type(self):
        change = Amount("3 NEAR") - Amount("1 NEAR")
        assert isinstance(change, Amount)
        assert str(change) == "2 NEAR"

    def test_reflected_ops_preserve_type(self):
        assert isinstance(10**24 + Amount("1 NEAR"), Amount)
        assert isinstance(3 * 10**24 - Amount("1 NEAR"), Amount)
        assert isinstance(2 * Amount("1 NEAR"), Amount)

    def test_mul_floordiv_mod_preserve_type(self):
        fee = Amount("3 NEAR")
        assert isinstance(fee * 2, Amount)
        assert isinstance(fee // 2, Amount)
        assert isinstance(fee % 2, Amount)
        assert str(fee // 3) == "1 NEAR"

    def test_negative_result_degrades_to_int(self):
        deficit = Amount("1 NEAR") - Amount("2 NEAR")
        assert not isinstance(deficit, Amount)
        assert deficit == -(10**24)

    def test_non_int_result_degrades(self):
        ratio = Amount("1 NEAR") * 0.5
        assert not isinstance(ratio, Amount)
        assert isinstance(ratio, float)


class TestGas:
    def test_tgas_string(self):
        assert Gas("30 Tgas") == 30 * 10**12

    def test_fractional_tgas(self):
        assert Gas("0.5 Tgas") == 5 * 10**11

    def test_raw_digits(self):
        assert Gas("30000000000000") == 30 * 10**12

    def test_tgas_classmethod(self):
        assert Gas.tgas(30) == Gas("30 Tgas")

    def test_str(self):
        assert str(Gas("30 Tgas")) == "30 Tgas"
        assert str(Gas("30.5 Tgas")) == "30.5 Tgas"

    def test_as_tgas(self):
        assert Gas("30 Tgas").as_tgas == Decimal(30)

    def test_default(self):
        assert Gas("30 Tgas") == DEFAULT_GAS

    def test_invalid(self):
        with pytest.raises(UnitParseError):
            Gas("30 gas")

    def test_bool_and_float_rejected(self):
        with pytest.raises(UnitParseError, match="bool"):
            Gas(True)
        with pytest.raises(UnitParseError, match="float"):
            Gas(1.5)  # type: ignore[arg-type]

    def test_tgas_classmethod_rejects_garbage(self):
        with pytest.raises(UnitParseError, match="Invalid Tgas value"):
            Gas.tgas("lots")

    def test_repr_round_trips(self):
        gas = Gas("30.5 Tgas")
        assert repr(gas) == "Gas('30.5 Tgas')"
        assert eval(repr(gas)) == gas  # noqa: S307


class _Wallet(BaseModel):
    """A tiny model exercising Amount/Gas at the pydantic (RPC JSON) boundary."""

    amount: Amount
    gas: Gas


class TestPydanticBoundary:
    def test_digit_strings_are_raw_units(self):
        # NEAR RPC sends balances/gas as digit strings of the base denomination.
        wallet = _Wallet.model_validate({"amount": "1000", "gas": "30000000000000"})
        assert wallet.amount == Amount.yocto(1000)
        assert wallet.gas == Gas.tgas(30)
        assert isinstance(wallet.amount, Amount)
        assert isinstance(wallet.gas, Gas)

    def test_instances_pass_through(self):
        wallet = _Wallet(amount=Amount("1 NEAR"), gas=DEFAULT_GAS)
        assert wallet.amount == 10**24
        assert wallet.gas is DEFAULT_GAS

    def test_ints_accepted(self):
        wallet = _Wallet.model_validate({"amount": 5, "gas": 7})
        assert wallet.amount == Amount.yocto(5)
        assert wallet.gas == Gas(7)

    def test_human_strings_still_parse(self):
        wallet = _Wallet.model_validate({"amount": "2 NEAR", "gas": "30 Tgas"})
        assert wallet.amount == Amount("2 NEAR")
        assert wallet.gas == DEFAULT_GAS

    def test_json_serializes_as_digit_strings(self):
        wallet = _Wallet(amount=Amount("1 NEAR"), gas=Gas.tgas(30))
        data = json.loads(wallet.model_dump_json())
        assert data == {"amount": str(10**24), "gas": str(30 * 10**12)}
        # And the serialized form round-trips.
        assert _Wallet.model_validate(data) == wallet


class TestBoundaryCoercion:
    def test_as_amount_accepts_amount_and_str(self):
        assert as_amount(Amount("1 NEAR")) == 10**24
        assert as_amount("1 NEAR") == 10**24

    def test_as_amount_rejects_bare_numbers(self):
        with pytest.raises(UnitParseError, match="Bare numbers"):
            as_amount(5)  # type: ignore[arg-type]
        with pytest.raises(UnitParseError, match="Bare numbers"):
            as_amount(5.0)  # type: ignore[arg-type]

    def test_as_gas_rejects_bare_numbers(self):
        with pytest.raises(UnitParseError, match="Bare numbers"):
            as_gas(30)  # type: ignore[arg-type]

    def test_as_gas_accepts_str_and_gas(self):
        assert as_gas("30 Tgas") == 30 * 10**12
        assert as_gas(Gas.tgas(30)) == 30 * 10**12
