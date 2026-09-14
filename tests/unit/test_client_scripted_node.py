"""Client behavior only a node with a mind of its own can provoke.

A stdlib HTTP server (real sockets, no mocking) answers JSON-RPC from a
reply function — per-method queues, or a node that enforces strict nonces —
and records what it was asked, so the strict nonce retry loop, its per-key
serialization and the error shapes the sandbox never produces can be pinned
down deterministically.
"""

import asyncio
import base64
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import base58
import pytest

from near import AccessKeyNotFoundError, AsyncNear, Near, transfer
from near.keys import KeyPairSigner, generate_key
from near.wire import SignedTransactionV1

BLOCK = {"result": {"header": {"hash": base58.b58encode(bytes(32)).decode(), "height": 100}}}
UNKNOWN_ACCESS_KEY = {
    "error": {
        "name": "HANDLER_ERROR",
        "cause": {
            "name": "UNKNOWN_ACCESS_KEY",
            "info": {"public_key": "ed25519:k", "block_height": 1},
        },
        "code": -32000,
        "message": "Server error",
        "data": "access key ed25519:k does not exist while viewing",
    }
}


def _sent(tx_hash: str = "tx") -> dict:
    return {
        "result": {
            "status": {"SuccessValue": ""},
            "transaction": {"hash": tx_hash, "nonce_mode": "strict"},
            "transaction_outcome": {
                "id": tx_hash,
                "outcome": {"logs": [], "status": {"SuccessReceiptId": "r1"}},
            },
            "receipts_outcome": [],
        }
    }


SENT = _sent()


def _access_key(nonce: int) -> dict:
    return {"result": {"nonce": nonce, "permission": "FullAccess", "block_height": 1}}


def _invalid_nonce(ak_nonce: int | None) -> dict:
    nonce_info = {"tx_nonce": 0, **({"ak_nonce": ak_nonce} if ak_nonce is not None else {})}
    return {
        "error": {
            "name": "HANDLER_ERROR",
            "cause": {"name": "INVALID_TRANSACTION", "info": {}},
            "code": -32000,
            "message": "Server error",
            "data": {"TxExecutionError": {"InvalidTxError": {"InvalidNonce": nonce_info}}},
        }
    }


def _sent_nonce(params: dict) -> int:
    signed = SignedTransactionV1.from_borsh(base64.b64decode(params["signed_tx_base64"]))
    return signed.transaction.nonce.nonce


@pytest.fixture
def rpc_server():
    """Start a JSON-RPC server answering from ``reply(method, params)``; records what it was asked."""
    servers = []

    def start(reply):
        seen: list[tuple[str, dict]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((request["method"], request["params"]))
                answer = reply(request["method"], request["params"])
                body = json.dumps({"jsonrpc": "2.0", "id": request["id"], **answer}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}", seen

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def scripted_node(rpc_server):
    """A node replying per method from a queue (the last reply repeats)."""

    def start(script: dict[str, list[dict]]):
        def reply(method: str, params: dict) -> dict:
            queue = script[method]
            return queue.pop(0) if len(queue) > 1 else queue[0]

        return rpc_server(reply)

    return start


@pytest.fixture
def strict_node(rpc_server):
    """A node enforcing strict nonces: a send lands only at current + 1 (advancing
    the key); anything else is an InvalidNonce naming the current nonce.
    """

    def start(nonce: int):
        state = {"nonce": nonce}
        lock = threading.Lock()

        def reply(method: str, params: dict) -> dict:
            if method == "block":
                return BLOCK
            with lock:
                if method == "query":
                    return _access_key(state["nonce"])
                sent = _sent_nonce(params)
                if sent != state["nonce"] + 1:
                    return _invalid_nonce(state["nonce"])
                state["nonce"] = sent
            return _sent(f"tx{sent}")

        return rpc_server(reply)

    return start


def _signer():
    return KeyPairSigner("alice.sandbox", generate_key())


class TestStrictNonceRecovery:
    """Strict mode wants exactly current + 1, so a nonce miss must resynchronize
    from what the node says — or re-fetch when it says nothing.
    """

    def test_refetches_when_the_node_reports_no_nonce(self, scripted_node):
        url, seen = scripted_node(
            {
                "query": [_access_key(10), _access_key(20)],
                "block": [BLOCK],
                "send_tx": [_invalid_nonce(None), SENT],
            }
        )
        with Near(rpc_url=url, signer=_signer(), retries=0) as near:
            result = near.send_transaction("bob.sandbox", [transfer("1 yocto")], strict_nonce=True)
        assert result.transaction_hash == "tx"
        queries = [params for method, params in seen if method == "query"]
        assert len(queries) == 2  # the second attempt went back to the node
        assert all(q["finality"] == "optimistic" for q in queries)
        assert [_sent_nonce(p) for m, p in seen if m == "send_tx"] == [11, 21]

    def test_resumes_from_the_reported_nonce(self, scripted_node):
        url, seen = scripted_node(
            {
                "query": [_access_key(10)],
                "block": [BLOCK],
                "send_tx": [_invalid_nonce(30), SENT],
            }
        )
        with Near(rpc_url=url, signer=_signer(), retries=0) as near:
            near.send_transaction("bob.sandbox", [transfer("1 yocto")], strict_nonce=True)
        assert [m for m, _ in seen].count("query") == 1
        assert [_sent_nonce(p) for m, p in seen if m == "send_tx"] == [11, 31]

    async def test_async_refetches_when_the_node_reports_no_nonce(self, scripted_node):
        url, seen = scripted_node(
            {
                "query": [_access_key(10), _access_key(20)],
                "block": [BLOCK],
                "send_tx": [_invalid_nonce(None), SENT],
            }
        )
        async with AsyncNear(rpc_url=url, signer=_signer(), retries=0) as near:
            await near.send_transaction("bob.sandbox", [transfer("1 yocto")], strict_nonce=True)
        assert [m for m, _ in seen].count("query") == 2
        assert [_sent_nonce(p) for m, p in seen if m == "send_tx"] == [11, 21]

    async def test_async_resumes_from_the_reported_nonce(self, scripted_node):
        url, seen = scripted_node(
            {
                "query": [_access_key(10)],
                "block": [BLOCK],
                "send_tx": [_invalid_nonce(30), SENT],
            }
        )
        async with AsyncNear(rpc_url=url, signer=_signer(), retries=0) as near:
            await near.send_transaction("bob.sandbox", [transfer("1 yocto")], strict_nonce=True)
        assert [_sent_nonce(p) for m, p in seen if m == "send_tx"] == [11, 31]


def _assert_took_turns(results, seen) -> None:
    """Six sends landed on the six nonces after 10, each fetching once: no collision, no retry."""
    assert sorted(r.transaction_hash for r in results) == [f"tx{n}" for n in range(11, 17)]
    assert [_sent_nonce(p) for m, p in seen if m == "send_tx"] == list(range(11, 17))
    assert [m for m, _ in seen].count("query") == 6


class TestStrictNonceSerialization:
    """Overlapping strict sends on one key would each fetch the same nonce and
    collide — three of them exhaust the retry budget — so the client runs them
    one at a time per key: every send fetches once and lands on the next nonce.
    """

    def test_threads_take_turns(self, strict_node):
        url, seen = strict_node(nonce=10)
        with (
            Near(rpc_url=url, signer=_signer(), retries=0) as near,
            ThreadPoolExecutor(max_workers=6) as pool,
        ):
            futures = [
                pool.submit(
                    near.send_transaction, "bob.sandbox", [transfer("1 yocto")], strict_nonce=True
                )
                for _ in range(6)
            ]
            results = [future.result() for future in futures]
        _assert_took_turns(results, seen)

    async def test_tasks_take_turns(self, strict_node):
        url, seen = strict_node(nonce=10)
        async with AsyncNear(rpc_url=url, signer=_signer(), retries=0) as near:
            results = await asyncio.gather(
                *(
                    near.send_transaction("bob.sandbox", [transfer("1 yocto")], strict_nonce=True)
                    for _ in range(6)
                )
            )
        _assert_took_turns(results, seen)


class TestStructuredUnknownAccessKey:
    """A structured UNKNOWN_ACCESS_KEY names only the key; the client restores
    the account it asked about (nearcore 2.13 itself reports the miss inside
    the query result, which the sandbox suite covers).
    """

    def test_sync(self, scripted_node):
        url, _ = scripted_node({"query": [UNKNOWN_ACCESS_KEY]})
        with Near(rpc_url=url, retries=0) as near, pytest.raises(AccessKeyNotFoundError) as info:
            near.access_key("alice.sandbox", "ed25519:k")
        assert info.value.account_id == "alice.sandbox"
        assert info.value.public_key == "ed25519:k"
        assert str(info.value) == "Access key ed25519:k not found for alice.sandbox"
        assert info.value.data["cause"]["name"] == "UNKNOWN_ACCESS_KEY"

    async def test_async(self, scripted_node):
        url, _ = scripted_node({"query": [UNKNOWN_ACCESS_KEY]})
        async with AsyncNear(rpc_url=url, retries=0) as near:
            with pytest.raises(AccessKeyNotFoundError) as info:
                await near.access_key("alice.sandbox", "ed25519:k")
        assert info.value.account_id == "alice.sandbox"
        assert info.value.data["cause"]["name"] == "UNKNOWN_ACCESS_KEY"
