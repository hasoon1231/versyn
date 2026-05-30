import base64
import pytest
from nacl.signing import SigningKey
from versyn import _crypto
from versyn._exceptions import VersynValidationError


@pytest.fixture
def keypair():
    sk = SigningKey.generate()
    return sk, base64.b64encode(bytes(sk.verify_key)).decode()


def _make_cert(sk, event):
    hf = _crypto.local_hash(event)
    sig = sk.sign(bytes.fromhex(hf.split(":", 1)[1])).signature
    return {"hash": hf, "signature": "ed25519:" + base64.b64encode(sig).decode()}


def test_canonical_json_deterministic():
    assert _crypto.canonical_json({"b": 2, "a": 1}) == _crypto.canonical_json({"a": 1, "b": 2})


def test_local_hash_order_independent():
    assert _crypto.local_hash({"b": 2, "a": 1}) == _crypto.local_hash({"a": 1, "b": 2})


def test_local_hash_has_prefix():
    assert _crypto.local_hash({"x": 1}).startswith("sha256:")


def test_local_hash_rejects_unknown_algorithm():
    with pytest.raises(VersynValidationError):
        _crypto.local_hash({"x": 1}, algorithm="md5")


def test_decode_signature_both_forms():
    raw = b"x" * 64
    b64 = base64.b64encode(raw).decode()
    assert _crypto.decode_signature("ed25519:" + b64) == raw
    assert _crypto.decode_signature(b64) == raw


def test_verify_valid(keypair):
    sk, pub = keypair
    cert = _make_cert(sk, {"kind": "d", "payload": {"a": 1}})
    assert _crypto.offline_verify(cert, pubkey_b64=pub) is True


def test_verify_matching_event(keypair):
    sk, pub = keypair
    ev = {"kind": "d", "payload": {"a": 1}}
    assert _crypto.offline_verify(_make_cert(sk, ev), original_event=ev, pubkey_b64=pub) is True


def test_verify_tampered_raises(keypair):
    sk, pub = keypair
    cert = _make_cert(sk, {"kind": "d", "payload": {"action": "decline"}})
    with pytest.raises(VersynValidationError):
        _crypto.offline_verify(cert, original_event={"kind": "d", "payload": {"action": "approve"}}, pubkey_b64=pub)


def test_verify_bad_signature_false(keypair):
    sk, pub = keypair
    cert = _make_cert(sk, {"kind": "d", "payload": {"a": 1}})
    cert["signature"] = "ed25519:" + base64.b64encode(b"z" * 64).decode()
    assert _crypto.offline_verify(cert, pubkey_b64=pub) is False


def test_verify_malformed_raises(keypair):
    _, pub = keypair
    with pytest.raises(VersynValidationError):
        _crypto.offline_verify({"hash": "sha256:abc"}, pubkey_b64=pub)
