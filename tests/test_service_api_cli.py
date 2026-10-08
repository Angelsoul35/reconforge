from __future__ import annotations

from fastapi.testclient import TestClient

from reconforge import cli
from reconforge.service import ReconService


def test_assess_ranks_and_aggregates():
    result = ReconService().assess("example.com")
    assert result["asset_count"] >= 1
    assert result["surface_score"] > 0
    scores = [a["score"] for a in result["assets"]]
    assert scores == sorted(scores, reverse=True)  # ranked by exposure
    assert sum(result["by_level"].values()) == result["asset_count"]


def test_assess_is_deterministic():
    a = ReconService().assess("example.com")
    b = ReconService().assess("example.com")
    assert a["surface_score"] == b["surface_score"]
    assert [x["host"] for x in a["assets"]] == [x["host"] for x in b["assets"]]


def test_api():
    import reconforge.main as main

    main._service = ReconService()
    client = TestClient(main.app)
    assert client.get("/health").json() == {"status": "ok"}

    resp = client.post("/assess", json={"target": "example.com"})
    assert resp.status_code == 200
    assert resp.json()["asset_count"] >= 1

    assert client.post("/assess", json={"target": ""}).status_code == 422


def test_cli_demo_runs(capsys):
    cli.demo()
    out = capsys.readouterr().out
    assert "surface score" in out
    assert "example.com" in out


def test_cli_main_dispatch(monkeypatch):
    called = {"demo": False}
    monkeypatch.setattr(cli, "demo", lambda: called.__setitem__("demo", True))
    monkeypatch.setattr("sys.argv", ["reconforge", "demo"])
    cli.main()
    assert called["demo"] is True
