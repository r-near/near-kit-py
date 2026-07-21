"""Unit tests for RPC error classification and the transports' failure paths.

Error payloads below are hand-built copies of what real NEAR nodes return.
Transport tests use real sockets only: a closed local port for connection
failures and a stdlib HTTP server for malformed responses (no mocks).
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from near.errors import (
    AccountNotFoundError,
    ContractPanicError,
    InsufficientBalanceError,
    InvalidAccountIdError,
    InvalidNonceError,
    RpcError,
    TransactionExpiredError,
)
from near.rpc import (
    AsyncRpcTransport,
    RpcTransport,
    classify_rpc_error,
    raise_for_execution_failure,
)

# ---------------------------------------------------------------------------
# classify_rpc_error
# ---------------------------------------------------------------------------


def _handler_error(cause_name, info=None, data=None, message="Server error"):
    return {
        "name": "HANDLER_ERROR",
        "cause": {"name": cause_name, "info": info or {}},
        "code": -32000,
        "message": message,
        "data": data,
    }


class TestClassifyRpcError:
    def test_unknown_account(self):
        error = _handler_error("UNKNOWN_ACCOUNT", info={"requested_account_id": "ghost.near"})
        err = classify_rpc_error(error)
        assert isinstance(err, AccountNotFoundError)
        assert err.account_id == "ghost.near"
        assert err.data is error

    def test_invalid_account(self):
        error = _handler_error("INVALID_ACCOUNT", info={"requested_account_id": "UPPER.near"})
        err = classify_rpc_error(error)
        assert isinstance(err, InvalidAccountIdError)
        assert err.account_id == "UPPER.near"

    def test_invalid_nonce(self):
        error = _handler_error(
            "INVALID_TRANSACTION",
            data={
                "TxExecutionError": {
                    "InvalidTxError": {"InvalidNonce": {"tx_nonce": 5, "ak_nonce": 12}}
                }
            },
        )
        err = classify_rpc_error(error)
        assert isinstance(err, InvalidNonceError)
        assert err.ak_nonce == 12
        assert err.retryable is True
        assert "tx nonce 5" in str(err)
        assert "access key nonce 12" in str(err)

    def test_invalid_nonce_without_tx_execution_wrapper(self):
        # Some node versions omit the TxExecutionError nesting.
        error = _handler_error(
            "INVALID_TRANSACTION",
            data={"InvalidTxError": {"InvalidNonce": {"tx_nonce": 1, "ak_nonce": 3}}},
        )
        err = classify_rpc_error(error)
        assert isinstance(err, InvalidNonceError)
        assert err.ak_nonce == 3

    def test_not_enough_balance(self):
        error = _handler_error(
            "INVALID_TRANSACTION",
            data={
                "TxExecutionError": {
                    "InvalidTxError": {
                        "NotEnoughBalance": {
                            "signer_id": "poor.near",
                            "balance": str(10**24),
                            "cost": str(2 * 10**24),
                        }
                    }
                }
            },
        )
        err = classify_rpc_error(error)
        assert isinstance(err, InsufficientBalanceError)
        assert err.available == 10**24
        assert err.required == 2 * 10**24
        assert "poor.near" in str(err)
        assert "has 1 NEAR" in str(err)
        assert "needs 2 NEAR" in str(err)

    def test_not_enough_balance_without_amounts(self):
        error = _handler_error(
            "INVALID_TRANSACTION",
            data={"TxExecutionError": {"InvalidTxError": {"NotEnoughBalance": {}}}},
        )
        err = classify_rpc_error(error)
        assert isinstance(err, InsufficientBalanceError)
        assert err.required is None
        assert err.available is None
        assert "?" in str(err)

    def test_expired_transaction(self):
        error = _handler_error(
            "INVALID_TRANSACTION",
            data={"TxExecutionError": {"InvalidTxError": {"Expired": None}}},
        )
        err = classify_rpc_error(error)
        assert isinstance(err, TransactionExpiredError)
        assert err.retryable is True

    def test_unrecognized_invalid_tx_falls_back_to_rpc_error(self):
        error = _handler_error(
            "INVALID_TRANSACTION",
            data={"TxExecutionError": {"InvalidTxError": {"InvalidSignature": {}}}},
        )
        err = classify_rpc_error(error)
        assert isinstance(err, RpcError)
        assert err.code == "INVALID_TRANSACTION"
        assert err.retryable is False

    def test_invalid_transaction_with_non_dict_data(self):
        error = _handler_error("INVALID_TRANSACTION", data="opaque string")
        err = classify_rpc_error(error)
        assert isinstance(err, RpcError)
        assert err.code == "INVALID_TRANSACTION"

    def test_invalid_transaction_with_non_dict_invalid_tx(self):
        error = _handler_error(
            "INVALID_TRANSACTION",
            data={"TxExecutionError": {"InvalidTxError": "CostOverflow"}},
        )
        err = classify_rpc_error(error)
        assert isinstance(err, RpcError)
        assert err.code == "INVALID_TRANSACTION"

    @pytest.mark.parametrize(
        "cause", ["TIMEOUT_ERROR", "NO_SYNCED_BLOCKS", "NOT_SYNCED_YET", "INTERNAL_ERROR"]
    )
    def test_retryable_causes(self, cause):
        err = classify_rpc_error(_handler_error(cause))
        assert isinstance(err, RpcError)
        assert err.retryable is True
        assert err.code == cause

    @pytest.mark.parametrize("status_code", [408, 429, 503, 500, 599])
    def test_retryable_status_codes(self, status_code):
        err = classify_rpc_error({"message": "boom"}, status_code)
        assert isinstance(err, RpcError)
        assert err.retryable is True
        assert err.code == "UNKNOWN"

    @pytest.mark.parametrize("status_code", [None, 200, 400, 404])
    def test_non_retryable_status_codes(self, status_code):
        err = classify_rpc_error({"message": "boom"}, status_code)
        assert err.retryable is False

    def test_top_level_name_used_when_no_cause(self):
        err = classify_rpc_error({"name": "REQUEST_VALIDATION_ERROR", "message": "Parse error"})
        assert isinstance(err, RpcError)
        assert err.code == "REQUEST_VALIDATION_ERROR"
        assert "Parse error" in str(err)

    def test_empty_error_payload(self):
        err = classify_rpc_error({})
        assert isinstance(err, RpcError)
        assert err.code == "UNKNOWN"
        assert "RPC error" in str(err)


# ---------------------------------------------------------------------------
# raise_for_execution_failure
# ---------------------------------------------------------------------------


def _tx_result(status, tx_outcome=None, receipts=None):
    result = {"status": status, "receipts_outcome": receipts or []}
    if tx_outcome is not None:
        result["transaction_outcome"] = tx_outcome
    return result


class TestRaiseForExecutionFailure:
    def test_success_does_not_raise(self):
        result = _tx_result(
            {"SuccessValue": ""},
            tx_outcome={"id": "tx1", "outcome": {"logs": [], "status": {"SuccessReceiptId": "r1"}}},
            receipts=[{"id": "r1", "outcome": {"logs": [], "status": {"SuccessValue": ""}}}],
        )
        assert raise_for_execution_failure(result) is None

    def test_receipt_execution_error(self):
        failure = {
            "ActionError": {
                "index": 0,
                "kind": {"FunctionCallError": {"ExecutionError": "Smart contract panicked: nope"}},
            }
        }
        result = _tx_result(
            {"Failure": failure},
            tx_outcome={
                "id": "tx1",
                "outcome": {"logs": ["log-a"], "status": {"SuccessReceiptId": "r1"}},
            },
            receipts=[{"id": "r1", "outcome": {"logs": ["log-b"], "status": {"Failure": failure}}}],
        )
        with pytest.raises(ContractPanicError) as exc_info:
            raise_for_execution_failure(result)
        err = exc_info.value
        assert err.panic == "Smart contract panicked: nope"
        assert err.logs == ["log-a", "log-b"]
        assert err.receipt_id == "r1"
        assert err.data is result

    def test_host_error(self):
        failure = {"ActionError": {"kind": {"FunctionCallError": {"HostError": "GasExceeded"}}}}
        result = _tx_result(
            {"Failure": failure},
            receipts=[{"id": "r2", "outcome": {"logs": [], "status": {"Failure": failure}}}],
        )
        with pytest.raises(ContractPanicError, match="GasExceeded"):
            raise_for_execution_failure(result)

    def test_top_level_function_call_error(self):
        failure = {"FunctionCallError": {"ExecutionError": "wasm trap"}}
        result = _tx_result(
            {"Failure": failure},
            receipts=[{"id": "r3", "outcome": {"logs": [], "status": {"Failure": failure}}}],
        )
        with pytest.raises(ContractPanicError, match="wasm trap"):
            raise_for_execution_failure(result)

    def test_unrecognized_function_call_error_shape(self):
        failure = {"ActionError": {"kind": {"FunctionCallError": {"LinkError": {"msg": "bad"}}}}}
        result = _tx_result(
            {"Failure": failure},
            receipts=[{"id": "r4", "outcome": {"logs": [], "status": {"Failure": failure}}}],
        )
        with pytest.raises(ContractPanicError, match="LinkError"):
            raise_for_execution_failure(result)

    def test_action_error_summary_with_details(self):
        failure = {
            "ActionError": {
                "kind": {"LackBalanceForState": {"account_id": "a.near", "amount": "100"}}
            }
        }
        result = _tx_result(
            {"Failure": failure},
            receipts=[{"id": "r5", "outcome": {"logs": [], "status": {"Failure": failure}}}],
        )
        with pytest.raises(ContractPanicError) as exc_info:
            raise_for_execution_failure(result)
        assert exc_info.value.panic == "LackBalanceForState (account_id: a.near, amount: 100)"

    def test_action_error_summary_without_details(self):
        failure = {"ActionError": {"kind": {"DelegateActionExpired": {}}}}
        result = _tx_result(
            {"Failure": failure},
            receipts=[{"id": "r6", "outcome": {"logs": [], "status": {"Failure": failure}}}],
        )
        with pytest.raises(ContractPanicError) as exc_info:
            raise_for_execution_failure(result)
        assert exc_info.value.panic == "DelegateActionExpired"

    def test_unclassifiable_failure_stringified(self):
        failure = {"InvalidTxError": "whatever"}
        result = _tx_result(
            {"Failure": failure},
            receipts=[{"id": "r7", "outcome": {"logs": [], "status": {"Failure": failure}}}],
        )
        with pytest.raises(ContractPanicError, match="InvalidTxError"):
            raise_for_execution_failure(result)

    def test_top_level_status_failure_with_clean_receipts(self):
        # No receipt failed, but the overall status says Failure.
        result = _tx_result(
            {"Failure": {"ActionError": {"kind": {"AccountDoesNotExist": {"account_id": "g"}}}}}
        )
        with pytest.raises(ContractPanicError) as exc_info:
            raise_for_execution_failure(result)
        assert exc_info.value.panic == "AccountDoesNotExist (account_id: g)"
        assert exc_info.value.receipt_id is None

    def test_missing_outcomes_are_ignored(self):
        assert raise_for_execution_failure({"status": {"SuccessValue": ""}}) is None


# ---------------------------------------------------------------------------
# Transport failure paths (real sockets, no mocks)
# ---------------------------------------------------------------------------

CLOSED_PORT_URL = "http://127.0.0.1:39997"


@pytest.fixture
def raw_server():
    """Start real stdlib HTTP servers that answer every POST with a fixed body."""
    servers = []

    def start(status: int, body: bytes = b"<html>not json</html>"):
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path)
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}", hits

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


class TestSyncTransportFailures:
    def test_connection_error_retries_then_raises(self):
        transport = RpcTransport(CLOSED_PORT_URL, retries=1, retry_initial_delay=0.01)
        try:
            with pytest.raises(RpcError, match="RPC request failed") as exc_info:
                transport.call("block", {"finality": "final"})
            assert exc_info.value.retryable is True
            assert exc_info.value.method == "block"
        finally:
            transport.close()

    def test_non_json_200_raises_without_retry(self, raw_server):
        url, hits = raw_server(200)
        transport = RpcTransport(url, retries=3, retry_initial_delay=0.01)
        try:
            with pytest.raises(RpcError, match="Non-JSON response") as exc_info:
                transport.call("block", {})
            assert exc_info.value.retryable is False
            assert len(hits) == 1  # non-retryable: must not have retried
        finally:
            transport.close()

    def test_non_json_500_is_retried_then_raised(self, raw_server):
        url, hits = raw_server(500)
        transport = RpcTransport(url, retries=1, retry_initial_delay=0.01)
        try:
            with pytest.raises(RpcError, match="Non-JSON response") as exc_info:
                transport.call("block", {})
            assert exc_info.value.retryable is True
            assert len(hits) == 2  # initial attempt + one retry
        finally:
            transport.close()


class TestAsyncTransportFailures:
    async def test_connection_error_retries_then_raises(self):
        transport = AsyncRpcTransport(CLOSED_PORT_URL, retries=1, retry_initial_delay=0.01)
        try:
            with pytest.raises(RpcError, match="RPC request failed") as exc_info:
                await transport.call("block", {"finality": "final"})
            assert exc_info.value.retryable is True
        finally:
            await transport.aclose()

    async def test_non_json_200_raises_without_retry(self, raw_server):
        url, hits = raw_server(200)
        transport = AsyncRpcTransport(url, retries=3, retry_initial_delay=0.01)
        try:
            with pytest.raises(RpcError, match="Non-JSON response") as exc_info:
                await transport.call("block", {})
            assert exc_info.value.retryable is False
            assert len(hits) == 1
        finally:
            await transport.aclose()

    async def test_non_json_500_is_retried_then_raised(self, raw_server):
        url, hits = raw_server(500)
        transport = AsyncRpcTransport(url, retries=1, retry_initial_delay=0.01)
        try:
            with pytest.raises(RpcError, match="Non-JSON response") as exc_info:
                await transport.call("block", {})
            assert exc_info.value.retryable is True
            assert len(hits) == 2
        finally:
            await transport.aclose()
