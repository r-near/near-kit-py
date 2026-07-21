from near.actions import encode_args, function_call


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
