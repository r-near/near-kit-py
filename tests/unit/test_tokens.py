import copy
import pickle
from decimal import Decimal

import pytest
from pydantic import BaseModel, ValidationError

from near import Amount, FTMetadata, TokenAmount
from near.errors import UnitParseError
from near.tokens import as_token_amount

USDT = FTMetadata(spec="ft-1.0.0", name="Tether USD", symbol="USDT", decimals=6)
WBTC = FTMetadata(spec="ft-1.0.0", name="Wrapped BTC", symbol="WBTC", decimals=8)


class TestParse:
    def test_bare_decimal_string(self):
        amount = TokenAmount.parse("5.25", USDT)
        assert amount == 5_250_000
        assert amount.symbol == "USDT"
        assert amount.decimals == 6

    def test_with_symbol(self):
        assert TokenAmount.parse("5.25 USDT", USDT) == 5_250_000

    def test_symbol_case_insensitive(self):
        assert TokenAmount.parse("5.25 usdt", USDT) == 5_250_000

    def test_whole_tokens(self):
        assert TokenAmount.parse("5", USDT) == 5_000_000

    def test_symbol_mismatch_rejected(self):
        with pytest.raises(UnitParseError, match="symbol mismatch"):
            TokenAmount.parse("5 WBTC", USDT)

    def test_too_many_decimals_rejected(self):
        with pytest.raises(UnitParseError, match="decimal places"):
            TokenAmount.parse("0.1234567", USDT)

    def test_negative_rejected(self):
        with pytest.raises(UnitParseError):
            TokenAmount.parse("-5", USDT)

    def test_garbage_rejected(self):
        with pytest.raises(UnitParseError):
            TokenAmount.parse("five USDT", USDT)

    def test_non_string_rejected(self):
        with pytest.raises(UnitParseError, match="Bare numbers"):
            TokenAmount.parse(5, USDT)  # type: ignore[arg-type]


class TestConstructor:
    def test_raw_units(self):
        amount = TokenAmount(42, symbol="USDT", decimals=6)
        assert amount == 42
        assert str(amount) == "0.000042 USDT"

    def test_float_rejected(self):
        with pytest.raises(UnitParseError):
            TokenAmount(1.5, symbol="USDT", decimals=6)  # type: ignore[arg-type]

    def test_bool_rejected(self):
        with pytest.raises(UnitParseError):
            TokenAmount(True, symbol="USDT", decimals=6)

    def test_negative_rejected(self):
        with pytest.raises(UnitParseError):
            TokenAmount(-1, symbol="USDT", decimals=6)


class TestFormatting:
    def test_str_trims_trailing_zeros(self):
        assert str(TokenAmount.parse("5.25", USDT)) == "5.25 USDT"
        assert str(TokenAmount.parse("5.250000", USDT)) == "5.25 USDT"

    def test_str_whole(self):
        assert str(TokenAmount.parse("5", USDT)) == "5 USDT"

    def test_str_zero(self):
        assert str(TokenAmount(0, symbol="USDT", decimals=6)) == "0 USDT"

    def test_str_zero_decimals_token(self):
        assert str(TokenAmount(7, symbol="TICKET", decimals=0)) == "7 TICKET"

    def test_display_is_exact_decimal(self):
        assert TokenAmount.parse("5.25", USDT).display == Decimal("5.25")
        # 24-decimal tokens must survive the trip without float artifacts.
        wnear = FTMetadata(spec="ft-1.0.0", name="Wrapped NEAR", symbol="wNEAR", decimals=24)
        amount = TokenAmount.parse("0.100000000000000000000001", wnear)
        assert amount == 10**23 + 1
        assert amount.display == Decimal("0.100000000000000000000001")

    def test_repr_is_evaluable(self):
        amount = TokenAmount.parse("5.25", USDT)
        clone = eval(repr(amount))  # noqa: S307
        assert clone == amount
        assert clone.symbol == "USDT"
        assert clone.decimals == 6


class TestArithmetic:
    def test_add_same_token_preserves_type(self):
        total = TokenAmount.parse("1.5", USDT) + TokenAmount.parse("2.5", USDT)
        assert isinstance(total, TokenAmount)
        assert str(total) == "4 USDT"

    def test_sub_same_token(self):
        left = TokenAmount.parse("2.5", USDT) - TokenAmount.parse("1", USDT)
        assert isinstance(left, TokenAmount)
        assert str(left) == "1.5 USDT"

    def test_sum_works(self):
        total = sum([TokenAmount.parse("1", USDT), TokenAmount.parse("2", USDT)])
        assert isinstance(total, TokenAmount)
        assert str(total) == "3 USDT"

    def test_plain_int_is_raw_units(self):
        amount = TokenAmount.parse("1", USDT) + 1
        assert isinstance(amount, TokenAmount)
        assert amount == 1_000_001

    def test_mul_floordiv_mod_preserve_type(self):
        balance = TokenAmount.parse("5", USDT)
        for result, expected in [
            (balance * 2, "10 USDT"),
            (2 * balance, "10 USDT"),
            (balance // 2, "2.5 USDT"),
            (balance % 3, "0.000002 USDT"),
        ]:
            assert isinstance(result, TokenAmount)
            assert str(result) == expected

    def test_half_the_balance_stays_spendable(self):
        # The canonical "send half my balance": still a TokenAmount, so the
        # API boundary accepts it instead of rejecting a bare int.
        half = TokenAmount.parse("5", USDT) // 2
        assert as_token_amount(half, USDT) is half

    def test_mixing_tokens_raises(self):
        with pytest.raises(UnitParseError, match="Cannot mix"):
            TokenAmount.parse("1", USDT) + TokenAmount.parse("1", WBTC)
        with pytest.raises(UnitParseError, match="Cannot mix"):
            TokenAmount.parse("1", USDT) - TokenAmount.parse("1", WBTC)
        with pytest.raises(UnitParseError, match="Cannot mix"):
            TokenAmount.parse("1", USDT) * TokenAmount.parse("1", WBTC)

    def test_mixing_with_near_amount_raises(self):
        with pytest.raises(UnitParseError, match="Cannot mix NEAR"):
            TokenAmount.parse("1", USDT) + Amount("1 NEAR")

    def test_mixing_with_near_amount_on_the_left_raises(self):
        # int.__add__ would happily fold token raw units into yoctoNEAR, so
        # Amount itself must refuse when it is the left operand.
        token = TokenAmount.parse("5.25", USDT)
        with pytest.raises(UnitParseError, match="Cannot mix NEAR"):
            Amount("1 NEAR") + token
        with pytest.raises(UnitParseError, match="Cannot mix NEAR"):
            Amount("1 NEAR") - token
        with pytest.raises(UnitParseError, match="Cannot mix NEAR"):
            Amount("1 NEAR") * token
        with pytest.raises(UnitParseError, match="Cannot mix NEAR"):
            Amount("1 NEAR") // token
        with pytest.raises(UnitParseError, match="Cannot mix NEAR"):
            Amount("1 NEAR") % token

    def test_sum_of_mixed_list_raises(self):
        with pytest.raises(UnitParseError, match="Cannot mix NEAR"):
            sum([Amount("1 NEAR"), TokenAmount.parse("1", USDT)])
        with pytest.raises(UnitParseError, match="Cannot mix NEAR"):
            sum([TokenAmount.parse("1", USDT), Amount("1 NEAR")])

    def test_negative_result_downgrades_to_int(self):
        result = TokenAmount.parse("1", USDT) - TokenAmount.parse("2", USDT)
        assert not isinstance(result, TokenAmount)
        assert result == -1_000_000

    def test_comparison_is_exact(self):
        assert TokenAmount.parse("2", USDT) > TokenAmount.parse("1.999999", USDT)


class TestValueSemantics:
    """TokenAmount must clear the same value-type bar as Amount."""

    def test_pickle_round_trip(self):
        amount = TokenAmount.parse("5.25", USDT)
        clone = pickle.loads(pickle.dumps(amount))  # noqa: S301
        assert clone == amount
        assert isinstance(clone, TokenAmount)
        assert clone.symbol == "USDT"
        assert clone.decimals == 6

    def test_copy_and_deepcopy(self):
        amount = TokenAmount.parse("5.25", USDT)
        for clone in (copy.copy(amount), copy.deepcopy(amount)):
            assert clone == amount
            assert isinstance(clone, TokenAmount)
            assert clone.symbol == "USDT"
            assert clone.decimals == 6


class TestBoundaryCoercion:
    def test_accepts_str_and_token_amount(self):
        assert as_token_amount("5.25", USDT) == 5_250_000
        existing = TokenAmount.parse("5.25", USDT)
        assert as_token_amount(existing, USDT) is existing

    def test_rejects_bare_numbers(self):
        with pytest.raises(UnitParseError, match="Bare numbers"):
            as_token_amount(5, USDT)  # type: ignore[arg-type]
        with pytest.raises(UnitParseError, match="Bare numbers"):
            as_token_amount(5.25, USDT)  # type: ignore[arg-type]

    def test_rejects_wrong_token(self):
        with pytest.raises(UnitParseError, match="Token mismatch"):
            as_token_amount(TokenAmount.parse("1", WBTC), USDT)


class TestFTMetadata:
    def test_optional_fields_default_none(self):
        assert USDT.icon is None
        assert USDT.reference is None
        assert USDT.reference_hash is None

    def test_validates_chain_shape(self):
        meta = FTMetadata.model_validate(
            {
                "spec": "ft-1.0.0",
                "name": "Example NEAR fungible token",
                "symbol": "EXAMPLE",
                "icon": "data:image/svg+xml,...",
                "reference": None,
                "reference_hash": None,
                "decimals": 24,
            }
        )
        assert meta.symbol == "EXAMPLE"
        assert meta.decimals == 24

    def test_frozen_against_cache_poisoning(self):
        # Clients cache and share one instance per token; a caller mutating it
        # must not silently corrupt every later parse on that client.
        with pytest.raises(ValidationError):
            USDT.decimals = 8


class TestPydanticIntegration:
    class Payload(BaseModel):
        amount: TokenAmount

    def test_instance_passes_through(self):
        amount = TokenAmount.parse("5.25", USDT)
        payload = self.Payload(amount=amount)
        assert payload.amount is amount

    def test_json_serializes_raw_units_string(self):
        # NEP-141 wire convention: raw units as a decimal string.
        payload = self.Payload(amount=TokenAmount.parse("5.25", USDT))
        assert payload.model_dump_json() == '{"amount":"5250000"}'

    def test_raw_values_rejected_without_metadata(self):
        with pytest.raises(ValidationError, match="without token metadata"):
            self.Payload(amount=5_250_000)  # type: ignore[arg-type]
        with pytest.raises(ValidationError, match="without token metadata"):
            self.Payload(amount="5.25")  # type: ignore[arg-type]
