import base64

from near.models import AccessKeyView, ExecutionOutcome, KeyInfo, TransactionResult
from near.units import Gas


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


class TestAccessKeyView:
    def test_full_access(self):
        view = AccessKeyView.model_validate({"nonce": 7, "permission": "FullAccess"})
        assert view.is_full_access
        assert view.nonce == 7

    def test_function_call_permission(self):
        view = AccessKeyView.model_validate(
            {
                "nonce": 0,
                "permission": {
                    "FunctionCall": {
                        "allowance": "1000",
                        "receiver_id": "app.near",
                        "method_names": [],
                    }
                },
            }
        )
        assert not view.is_full_access

    def test_key_info(self):
        info = KeyInfo.model_validate(
            {"public_key": "ed25519:abc", "access_key": {"nonce": 1, "permission": "FullAccess"}}
        )
        assert info.public_key == "ed25519:abc"
        assert info.access_key.is_full_access


class TestExecutionOutcome:
    def test_logs_and_gas(self):
        outcome = ExecutionOutcome.model_validate(
            {"id": "r1", "outcome": {"logs": ["a", "b"], "gas_burnt": 3 * 10**12}}
        )
        assert outcome.logs == ["a", "b"]
        assert outcome.gas_burnt == Gas.tgas(3)
        assert isinstance(outcome.gas_burnt, Gas)

    def test_missing_fields_default_empty(self):
        outcome = ExecutionOutcome.model_validate({"outcome": {}})
        assert outcome.id is None
        assert outcome.logs == []
        assert outcome.gas_burnt == Gas(0)


class TestTransactionResult:
    def test_success_value_and_json(self):
        result = TransactionResult.model_validate(
            {
                "transaction": {"hash": "9abc"},
                "status": {"SuccessValue": _b64(b'{"ok":true,"count":3}')},
            }
        )
        assert result.transaction_hash == "9abc"
        assert result.success_value == b'{"ok":true,"count":3}'
        assert result.json_value() == {"ok": True, "count": 3}

    def test_empty_success_value(self):
        result = TransactionResult.model_validate({"status": {"SuccessValue": ""}})
        assert result.success_value == b""
        assert result.json_value() is None

    def test_no_status(self):
        result = TransactionResult.model_validate({})
        assert result.transaction_hash is None
        assert result.success_value is None
        assert result.json_value() is None

    def test_string_status_has_no_success_value(self):
        result = TransactionResult.model_validate({"status": "NONE"})
        assert result.success_value is None

    def test_logs_collected_in_order(self):
        result = TransactionResult.model_validate(
            {
                "transaction_outcome": {"id": "t", "outcome": {"logs": ["first"]}},
                "receipts_outcome": [
                    {"id": "r1", "outcome": {"logs": ["second"]}},
                    {"id": "r2", "outcome": {"logs": []}},
                    {"id": "r3", "outcome": {"logs": ["third"]}},
                ],
            }
        )
        assert result.logs == ["first", "second", "third"]

    def test_logs_empty_when_no_outcomes(self):
        assert TransactionResult.model_validate({}).logs == []
