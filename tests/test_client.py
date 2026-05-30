import base64
import pytest
from nacl.signing import SigningKey
from versyn._client import VersynClient
from versyn import _crypto
from versyn._exceptions import VersynCreditExhaustedError, VersynValidationError


class _FakeResponse:
    def __init__(self, status_code, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}
        self.text = str(self._payload)
    def json(self):
        return self._payload


def _signed_cert(event):
    sk = SigningKey.generate()
    pub = base64.b64encode(bytes(sk.verify_key)).decode()
    hf = _crypto.local_hash(event)
    sig = sk.sign(bytes.fromhex(hf.split(":", 1)[1])).signature
    return {"certificate_id": "c", "hash": hf, "signature": "ed25519:" + base64.b64encode(sig).decode()}, pub


def test_402_queues_and_raises(tmp_path, monkeypatch):
    c = VersynClient(api_key="k", queue_path=str(tmp_path / "q.json"))
    monkeypatch.setattr(c, "_post", lambda *a, **k: _FakeResponse(402))
    with pytest.raises(VersynCreditExhaustedError):
        c.certify({"kind": "d", "payload": {"a": 1}})
    assert c.get_debt_report()["count"] == 1
    c.close()


def test_success_returns_cert(tmp_path, monkeypatch):
    c = VersynClient(api_key="k", queue_path=str(tmp_path / "q.json"))
    monkeypatch.setattr(c, "_post", lambda *a, **k: _FakeResponse(200, {"certificate_id": "c1", "hash": "h", "signature": "s"}))
    assert c.certify({"kind": "x", "payload": {}})["certificate_id"] == "c1"
    c.close()


def test_rejects_malformed(tmp_path):
    c = VersynClient(api_key="k", queue_path=str(tmp_path / "q.json"))
    with pytest.raises(VersynValidationError):
        c.certify({"no_kind": True})
    c.close()


def test_verify_offline(tmp_path):
    c = VersynClient(api_key="k", queue_path=str(tmp_path / "q.json"))
    ev = {"kind": "d", "payload": {"a": 1}}
    cert, pub = _signed_cert(ev)
    assert _crypto.offline_verify(cert, original_event=ev, pubkey_b64=pub) is True
    c.close()


def test_queue_reloads(tmp_path, monkeypatch):
    qp = str(tmp_path / "q.json")
    c1 = VersynClient(api_key="k", queue_path=qp)
    monkeypatch.setattr(c1, "_post", lambda *a, **k: _FakeResponse(402))
    try:
        c1.certify({"kind": "x", "payload": {}})
    except VersynCreditExhaustedError:
        pass
    c1.close()
    c2 = VersynClient(api_key="k", queue_path=qp)
    assert c2.get_debt_report()["count"] == 1
    c2.close()


def test_context_manager(tmp_path):
    with VersynClient(api_key="k", queue_path=str(tmp_path / "q.json")) as c:
        assert c is not None
