# versyn

**Cryptographic proof for AI decisions.** Sign every AI decision with Ed25519, verify it offline against a pinned public key. Signing goes through the API; verification is local and free. 100% verification coverage, zero per-check cost.

```bash
pip install versyn
```

## The problem: the "trust tax"

Most AI-monitoring tools audit decisions by sending each one to *another* large model to judge it. That costs money per check, so teams sample — they audit 1% and hope the other 99% was fine. Every un-audited decision is a blind spot a regulator or a lawsuit can walk into.

versyn removes that tax. Each decision is signed via the Versyn API (the event is sent to be signed). Verification, by contrast, is a signature check on your own machine — no server call, no external model, no per-check fee. You can certify **100%** of decisions instead of a sample, at effectively zero marginal cost.

## Verify a decision offline

```python
from versyn import VersynClient

client = VersynClient(api_key="vk_...")

event = {
    "kind": "agent.decision",
    "payload": {"agent": "underwriter", "action": "decline", "reason": "DTI_too_high"},
}

cert = client.certify(event)
print(client.verify(cert, original_event=event))   # True — local, no network
```

`verify()` runs entirely on your machine. It checks that the signature is valid against the pinned public key, **and** that the certificate hash binds to *your* event. Change one field and verification refuses it.

## Get a free key

```python
import versyn
key = versyn.register("you@company.com")   # 500 certifications/month, free
```

## It survives outages

If the API is unreachable or credits run out, `certify()` queues the event to a durable local file (atomic writes, thread-safe) instead of losing it. On restart the client reloads the queue; `flush_queue()` settles it later. No silent gaps.

## Verify against the published key yourself

The pinned key ships in the package and is also published at:

```
https://versyn.dev/.well-known/versyn-pubkey.txt
```

## What this is — and isn't

A versyn certificate proves a specific decision was signed at a specific time and has not been altered since. It is **tamper-evident, independently verifiable evidence**.

It does **not**, by itself, prove the decision was correct or lawful, and it is **not** regulatory compliance certification. It is the verifiable evidence layer your governance and auditors build on top of.

## License

MIT
