import json
import os
import threading
import pytest
from versyn._queue import OfflineQueue
from versyn._exceptions import VersynError


def test_persist_on_add(tmp_path):
    p = str(tmp_path / "q.json")
    OfflineQueue(persist_path=p).add({"x": 1})
    assert os.path.exists(p)


def test_durability_across_reload(tmp_path):
    p = str(tmp_path / "q.json")
    OfflineQueue(persist_path=p).add({"x": 1})
    q2 = OfflineQueue(persist_path=p); q2.load()
    assert len(q2) == 1


def test_thread_safety(tmp_path):
    q = OfflineQueue(persist_path=str(tmp_path / "q.json"))
    def w():
        for _ in range(50):
            q.add({"n": 1})
    ts = [threading.Thread(target=w) for _ in range(10)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert len(q) == 500


def test_max_size(tmp_path):
    q = OfflineQueue(persist_path=str(tmp_path / "q.json"), max_size=3)
    for _ in range(3): q.add({"x": 1})
    with pytest.raises(VersynError):
        q.add({"x": 1})


def test_atomic_valid_json(tmp_path):
    p = str(tmp_path / "q.json")
    OfflineQueue(persist_path=p).add({"x": 1})
    with open(p) as f: json.load(f)
    assert not os.path.exists(p + ".tmp")


def test_debt_report(tmp_path):
    q = OfflineQueue(persist_path=str(tmp_path / "q.json"))
    for _ in range(5): q.add({"x": 1})
    r = q.get_debt_report()
    assert r["count"] == 5 and r["estimated_exposure"] == 2500.0


def test_corrupted_recovers(tmp_path):
    p = str(tmp_path / "bad.json")
    with open(p, "w") as f: f.write("{not json")
    q = OfflineQueue(persist_path=p)
    with pytest.warns(UserWarning):
        q.load()
    assert len(q) == 0


def test_clear(tmp_path):
    q = OfflineQueue(persist_path=str(tmp_path / "q.json"))
    q.add({"x": 1}); q.clear()
    assert len(q) == 0
