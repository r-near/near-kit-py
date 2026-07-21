# near-kit

[![CI](https://github.com/r-near/near-kit-py/actions/workflows/ci.yml/badge.svg)](https://github.com/r-near/near-kit-py/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/r-near/near-kit-py/graph/badge.svg?token=pnZFDwQ326)](https://codecov.io/gh/r-near/near-kit-py)
[![PyPI version](https://img.shields.io/pypi/v/near-kit.svg)](https://pypi.org/project/near-kit/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A Pythonic SDK for NEAR Protocol. Feels like `requests`.**

```python
import near

near.view("counter.near", "get_count")          # one line, no setup
near.balance("alice.near")                       # -> Amount('42.5 NEAR')
```

Human-readable everywhere — `"10 NEAR"` and `"30 Tgas"`, never
`10000000000000000000000000`. Typed errors, exact integer math, sync *and*
async, and post-quantum keys. The Python sibling of
[near-kit](https://github.com/r-near/near-kit) for TypeScript.

## Install

```bash
uv add near-kit        # or: pip install near-kit
```

Python 3.11+.

## The rule of the API

> **Reads are stateless; if it signs, you need a client.**

Module functions cover one-off reads, `requests.get()`-style. A `Near`
client holds the stateful things: your signer, a nonce cache, and a
connection pool.

```python
from near import Near

# Explicit config...
client = Near(network="testnet",
              account_id="alice.testnet",
              private_key="ed25519:...")

# ...or zero-argument discovery: NEAR_NETWORK / NEAR_ACCOUNT_ID /
# NEAR_PRIVATE_KEY env vars, falling back to ~/.near-credentials.
client = Near()

# ...or straight from NEAR CLI credentials:
client = Near.from_file("alice.testnet", network="testnet")
```

### Reads

```python
client.view("counter.testnet", "get_count")
client.balance()                      # your balance -> Amount
client.balance("bob.testnet")         # anyone's
client.account("bob.testnet")         # AccountView (balance, storage, code hash)
client.account_exists("bob.testnet")
client.access_keys("bob.testnet")
client.transaction_status(tx_hash)
client.rpc("block", {"finality": "final"})   # escape hatch: any RPC method
```

### Writes

```python
client.send("bob.testnet", "5 NEAR")
client.call("counter.testnet", "increment", {"by": 2},
            deposit="0.1 NEAR", gas="30 Tgas")
```

Multi-action transactions are just data — a list of actions, one receiver,
executed atomically:

```python
from near import create_account, transfer, deploy_contract, function_call, add_full_access_key

client.send_transaction(
    "sub.alice.testnet",
    actions=[
        create_account(),
        transfer("5 NEAR"),
        add_full_access_key(key.public_key),
        deploy_contract(wasm_bytes),
        function_call("init", {"owner": "alice.testnet"}),
    ],
)
```

### Async

`AsyncNear` is the same surface, awaited — for FastAPI services, relayers,
and MCP servers:

```python
from near import AsyncNear

async with AsyncNear() as client:
    await client.call("counter.testnet", "increment")
    results = await asyncio.gather(*(client.send(acc, "0.1 NEAR") for acc in accounts))
```

Concurrent transactions from one account just work — the client manages
nonces and retries collisions automatically.

## Amounts are exact

`Amount` is an `int` subclass denominated in yoctoNEAR, so arithmetic and
comparisons are exact; it parses and prints human strings. Bare numbers are
rejected at API boundaries — unit confusion is a bug that should not compile.

```python
from near import Amount

bal = client.balance()          # Amount(5250000000000000000000000)
str(bal)                        # '5.25 NEAR'
bal.as_near                     # Decimal('5.25')
bal > Amount("1 NEAR")          # True
client.send("bob.near", 5)      # UnitParseError: write "5 NEAR" or "5 yocto"
```

## Typed errors

```python
from near import ContractPanicError, AccountNotFoundError

try:
    client.call("app.near", "buy", deposit="1 NEAR")
except ContractPanicError as e:
    print(e.panic)     # the contract's panic message
    print(e.logs)      # contract logs leading up to it
```

Every error derives from `NearError` with a stable `.code` and a
`.retryable` flag.

## Testing your app: the sandbox is a database

Run NEAR like you'd run postgres in CI:

```bash
docker run -d -p 3030:3030 nearprotocol/sandbox:2.13.1
```

The sandbox root account's key is deterministic (derived from the image's
test seed), so nothing needs to be copied out of the container:

```python
from near import Near
from near.testing import sandbox_signer

near = Near(rpc_url="http://localhost:3030", signer=sandbox_signer())
near.send("anything.sandbox", ...)   # root account, fully funded
```

GitHub Actions:

```yaml
services:
  near-sandbox:
    image: nearprotocol/sandbox:2.13.1
    ports: ["3030:3030"]
```

Or let pytest do all of it — installing near-kit registers a plugin. Its
`near_sandbox` fixture reuses `NEAR_SANDBOX_URL` or localhost:3030 when
reachable, otherwise starts (and later removes) a Docker sandbox on a free
port; `sandbox_near` is a `Near` client signing as the root account:

```python
from near import add_full_access_key, create_account, generate_key, transfer
from near.testing import fast_forward


def test_my_app(sandbox_near):
    key = generate_key()
    sandbox_near.send_transaction(  # root creates + funds a fresh account
        "alice.sandbox",
        actions=[create_account(), transfer("10 NEAR"), add_full_access_key(key.public_key)],
    )
    fast_forward(sandbox_near, 100)  # time travel: 100 blocks, no waiting
```

## Meta-transactions (NEP-366)

User signs, relayer pays gas:

```python
# User side — no gas spent:
signed = client.sign_delegate("app.near", actions=[function_call("claim", {})])
payload = encode_signed_delegate(signed)          # base64, POST it to your relayer

# Relayer side:
relayer.send_delegate(payload)
```

## Message signing (NEP-413)

Off-chain auth ("login with NEAR"):

```python
signed = client.sign_message("Login to MyApp", recipient="myapp.com")

# Server side:
from near import verify_message
verify_message(signed, "Login to MyApp", "myapp.com", nonce)
```

## Post-quantum keys

ML-DSA-65 (FIPS 204) keys work everywhere ed25519 keys do:

```python
from near import MlDsa65KeyPair

pq = MlDsa65KeyPair.generate()
client.send_transaction(account_id, actions=[add_full_access_key(pq.public_key)])
```

## Custom signers (KMS, HSM)

Anything with `account_id`, `public_key`, and `sign(message) -> bytes` is a
signer:

```python
class KmsSigner:
    account_id = "treasury.near"
    public_key = PublicKey.parse("ed25519:...")

    def sign(self, message: bytes) -> bytes:
        return kms.sign(key_id=..., message=message)

client = Near(network="mainnet", signer=KmsSigner())
```

## What's under the hood

Borsh serialization via [pyborsh](https://github.com/r-near/pyborsh)
(Pydantic-native, byte-verified against Rust), ed25519/ML-DSA via
[pyca/cryptography](https://cryptography.io), HTTP via
[httpx](https://www.python-httpx.org). Every transaction byte this library
produces is verified end-to-end against a real nearcore node in CI.

## License

MIT
