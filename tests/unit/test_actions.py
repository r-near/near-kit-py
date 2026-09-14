import pytest

from near import Amount, UnitParseError, generate_key
from near.actions import (
    add_gas_key,
    deterministic_state_init,
    encode_args,
    function_call,
    publish_contract,
    transfer_to_gas_key,
    use_global_contract,
    withdraw_from_gas_key,
)
from near.wire import AccessKeyPermission, GlobalContractDeployMode, GlobalContractIdentifier


class TestEncodeArgs:
    def test_none_becomes_empty_json_object(self):
        assert encode_args(None) == b"{}"

    def test_bytes_pass_through_untouched(self):
        raw = b"\x00\x01borsh-or-whatever"
        assert encode_args(raw) is raw

    def test_dict_encodes_compact_json(self):
        assert encode_args({"a": 1, "b": "two"}) == b'{"a":1,"b":"two"}'

    def test_list_encodes_json_array(self):
        assert encode_args([1, "two", None]) == b'[1,"two",null]'

    def test_function_call_with_raw_bytes_args(self):
        action = function_call("apply", b"\xde\xad", gas="10 Tgas", deposit="1 yocto")
        assert action.args == b"\xde\xad"
        assert action.gas == 10 * 10**12
        assert action.deposit == 1


class TestAddGasKey:
    def test_full_access_by_default(self):
        action = add_gas_key(generate_key().public_key, 4)
        permission = action.access_key.permission
        assert isinstance(permission, AccessKeyPermission.GasKeyFullAccess)
        assert permission.gas_key_info.num_nonces == 4
        assert permission.gas_key_info.balance == 0  # funded later via transfer_to_gas_key
        assert action.access_key.nonce == 0

    def test_function_call_restriction(self):
        action = add_gas_key(
            str(generate_key().public_key), 2, contract_id="app.near", method_names=("a", "b")
        )
        permission = action.access_key.permission
        assert isinstance(permission, AccessKeyPermission.GasKeyFunctionCall)
        assert permission.gas_key_info.num_nonces == 2
        assert permission.function_call.receiver_id == "app.near"
        assert permission.function_call.method_names == ["a", "b"]
        assert permission.function_call.allowance is None

    @pytest.mark.parametrize("num_nonces", [0, 1025, -1])
    def test_num_nonces_range(self, num_nonces):
        with pytest.raises(ValueError, match=r"1\.\.=1024"):
            add_gas_key(generate_key().public_key, num_nonces)

    @pytest.mark.parametrize("num_nonces", [True, "4", 4.0])
    def test_num_nonces_must_be_int(self, num_nonces):
        with pytest.raises(TypeError, match="num_nonces must be an int"):
            add_gas_key(generate_key().public_key, num_nonces)

    def test_method_names_need_a_contract(self):
        with pytest.raises(ValueError, match="requires contract_id"):
            add_gas_key(generate_key().public_key, 1, method_names=["m"])


class TestGasKeyTransfers:
    def test_amounts_are_human_units(self):
        pk = generate_key().public_key
        assert transfer_to_gas_key(pk, "1.5 NEAR").deposit == 15 * 10**23
        assert withdraw_from_gas_key(pk, Amount.near("0.25")).amount == 25 * 10**22

    def test_bare_numbers_rejected(self):
        pk = generate_key().public_key
        with pytest.raises(UnitParseError):
            transfer_to_gas_key(pk, 5)  # type: ignore[arg-type]
        with pytest.raises(UnitParseError):
            withdraw_from_gas_key(pk, 5)  # type: ignore[arg-type]


class TestGlobalContracts:
    def test_publish_modes(self):
        by_account = publish_contract(b"wasm")
        assert isinstance(by_account.deploy_mode, GlobalContractDeployMode.AccountId)
        by_hash = publish_contract(b"wasm", identified_by="hash")
        assert isinstance(by_hash.deploy_mode, GlobalContractDeployMode.CodeHash)
        assert by_hash.code == b"wasm"

    def test_unknown_mode_rejected(self):
        with pytest.raises(ValueError, match="identified_by"):
            publish_contract(b"wasm", identified_by="hashish")  # type: ignore[arg-type]

    def test_use_by_account_or_hash(self):
        by_account = use_global_contract(account_id="publisher.near")
        assert isinstance(by_account.contract_identifier, GlobalContractIdentifier.AccountId)
        by_hash = use_global_contract(code_hash=bytes(32))
        assert isinstance(by_hash.contract_identifier, GlobalContractIdentifier.CodeHash)

    def test_use_requires_exactly_one_reference(self):
        with pytest.raises(ValueError, match="exactly one"):
            use_global_contract()
        with pytest.raises(ValueError, match="exactly one"):
            use_global_contract(code_hash=bytes(32), account_id="p.near")


class TestDeterministicStateInit:
    def test_builds_canonical_state_init(self):
        action = deterministic_state_init(
            account_id="p.near", data={b"b": b"2", b"a": b"1"}, deposit="0.1 NEAR"
        )
        assert action.deposit == 10**23
        assert action.state_init.data == [(b"a", b"1"), (b"b", b"2")]
        assert isinstance(action.state_init.code, GlobalContractIdentifier.AccountId)

    def test_data_defaults_to_empty(self):
        action = deterministic_state_init(code_hash=bytes(32), deposit="1 yocto")
        assert action.state_init.data == []

    def test_bare_deposit_rejected(self):
        with pytest.raises(UnitParseError):
            deterministic_state_init(account_id="p.near", deposit=1)  # type: ignore[arg-type]

    def test_requires_exactly_one_reference(self):
        with pytest.raises(ValueError, match="exactly one"):
            deterministic_state_init(deposit="1 NEAR")
