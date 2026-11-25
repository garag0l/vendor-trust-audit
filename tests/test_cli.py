from __future__ import annotations

import json
import time
from pathlib import Path

from conftest import FIXTURE

from vendor_trust_audit import __version__
from vendor_trust_audit.cli import main
from vendor_trust_audit.vendors import resolve, snapshot

BASE = ["--gaad", str(FIXTURE), "--now", "2026-11-25", "--internal-accounts", "222233334444", "--org-id", "o-acme12345"]


def test_text_output_and_exit_code(capsys):
    assert main(BASE + ["--no-color"]) == 1
    out = capsys.readouterr().out
    assert "qubole (805246085872)" in out and "Datadog (464622532012)" in out
    assert "sister-account-deployer" not in out
    assert "\033[" not in out


def test_fail_on_none_and_critical(capsys):
    assert main(BASE + ["--fail-on", "none"]) == 0
    assert main(BASE + ["--fail-on", "critical"]) == 1
    capsys.readouterr()


def test_json(capsys):
    main(BASE + ["-f", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == __version__
    roles = {r["name"]: r for r in doc["roles"]}
    q = roles["qubole-integration"]
    assert q["dormant"] and q["principals"][0]["vendor"] == "qubole" and q["principals"][0]["has_external_id"]
    assert "secretsmanager" in q["readable_secret_classes"]
    assert doc["vendor_snapshot"]["commit"]


def test_sarif(tmp_path: Path, capsys):
    out = tmp_path / "r.sarif"
    main(BASE + ["-f", "sarif", "-o", str(out)])
    doc = json.loads(out.read_text())
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {f"VTA-00{i}" for i in range(1, 7)}
    assert all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"])
    assert {r["level"] for r in run["results"]} <= {"error", "warning", "note"}
    fps = [r["partialFingerprints"]["vta/v1"] for r in run["results"]]
    assert len(fps) == len(set(fps))


def test_external_id_values_are_not_printed(capsys):
    main(BASE + ["-f", "json"])
    main(BASE + ["--no-color", "--min-severity", "info"])
    main(BASE + ["-f", "sarif"])
    out = capsys.readouterr().out
    for secretish in ("QBL-7f3c9a1e-acme", "shared-ext-id-2024", "bk-unique-1"):
        assert secretish not in out


def test_cloudtrail_query(capsys):
    main(BASE + ["--cloudtrail-query", "2026-09-01"])
    out = capsys.readouterr().out
    assert "eventName = 'AssumeRole'" in out and "arn:aws:iam::111122223333:role/qubole-integration'" in out
    assert "GetSecretValue" in out and "'2026-09-01'" in out
    assert "internal-ci" not in out


def test_vendor_map_and_multiple_exports(tmp_path: Path, capsys):
    vm = tmp_path / "vendors.json"
    vm.write_text(json.dumps({"999988887777": "Acme ETL Co"}))
    main(["--gaad", str(FIXTURE), "--gaad", str(FIXTURE), "--now", "2026-11-25", "--vendor-map", str(vm), "-f", "json"])
    doc = json.loads(capsys.readouterr().out)
    vendors = {p["vendor"] for r in doc["roles"] for p in r["principals"]}
    assert "Acme ETL Co" in vendors


def test_internal_accounts_from_file(tmp_path: Path, capsys):
    f = tmp_path / "org.txt"
    f.write_text("222233334444\n")
    main(["--gaad", str(FIXTURE), "--now", "2026-11-25", "--internal-accounts", str(f), "-f", "json"])
    names = {r["name"] for r in json.loads(capsys.readouterr().out)["roles"]}
    assert "sister-account-deployer" not in names


def test_vendor_snapshot():
    snap = snapshot()
    assert snap["license"] == "Apache-2.0" and len(snap["commit"]) == 40
    assert len(snap["accounts"]) > 400
    assert resolve("805246085872")[0] == "qubole"
    assert resolve("000000000000") == ("", "")


def test_2000_roles_under_5_seconds(tmp_path: Path, capsys):
    base = json.loads(FIXTURE.read_text())
    roles = []
    for i in range(2000):
        r = dict(base["RoleDetailList"][i % len(base["RoleDetailList"])])
        r["RoleName"] = f"{r['RoleName']}-{i}"
        r["Arn"] = r["Arn"] + f"-{i}"
        roles.append(r)
    big = tmp_path / "big.json"
    big.write_text(json.dumps({**base, "RoleDetailList": roles}))
    t = time.perf_counter()
    main(["--gaad", str(big), "--now", "2026-11-25", "-f", "json", "--fail-on", "none"])
    assert time.perf_counter() - t < 5
    assert len(json.loads(capsys.readouterr().out)["roles"]) > 1000


def test_fixture_is_reproducible():
    import build_fixture

    assert json.loads(FIXTURE.read_text()) == build_fixture.build()
