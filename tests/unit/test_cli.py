from __future__ import annotations

from click.testing import CliRunner

import maws.api as api
import maws.cli as cli_mod


def test_ec2_terminate_requires_confirm(monkeypatch):
    # Patch the *imported* symbol used by the CLI module
    monkeypatch.setattr(
        cli_mod,
        "ec2_describe_instances",
        lambda instance_ids, profile=None, region=None: [
            api.InstanceSummary(instance_id=instance_ids[0], state="running", name_tag="alpha")
        ],
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["ec2", "terminate", "i-1"])

    assert result.exit_code != 0
    assert "Refusing to proceed without --confirm TERMINATE" in result.output


def test_ec2_terminate_dry_run_calls_api(monkeypatch):
    calls = {"dot": 0, "term": 0}

    monkeypatch.setattr(
        cli_mod,
        "ec2_describe_instances",
        lambda instance_ids, profile=None, region=None: [
            api.InstanceSummary(instance_id=instance_ids[0], state="running", name_tag="alpha")
        ],
    )

    def fake_dot(instance_ids, profile=None, region=None, dry_run=False):
        calls["dot"] += 1
        assert dry_run is True
        return [(instance_ids[0], "/dev/sdf", "vol-data", True)]

    def fake_term(instance_ids, profile=None, region=None, dry_run=False, wait=False):
        calls["term"] += 1
        assert dry_run is True
        return [(instance_ids[0], "dry-run-ok")]

    # Patch the *imported* symbols used by maws.cli
    monkeypatch.setattr(cli_mod, "ec2_set_delete_on_termination", fake_dot)
    monkeypatch.setattr(cli_mod, "ec2_terminate_instances", fake_term)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["ec2", "terminate", "--dry-run", "--confirm", "TERMINATE", "i-1"],
    )

    assert result.exit_code == 0
    assert calls["dot"] == 1
    assert calls["term"] == 1
    assert "dry-run-ok" in result.output


def test_ec2_list_prints_table(monkeypatch):
    # Patch the *imported* ec2_list_instances used by the CLI module
    monkeypatch.setattr(
        cli_mod,
        "ec2_list_instances",
        lambda profile=None, region=None, state=None, name_contains=None: [
            {
                "InstanceId": "i-1",
                "State": "running",
                "Name": "alpha",
                "Type": "t3.micro",
                "AZ": "eu-west-2a",
                "PrivateIp": "10.0.0.1",
            }
        ],
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["ec2", "list"])

    assert result.exit_code == 0
    assert "InstanceId" in result.output
    assert "i-1" in result.output
    assert "alpha" in result.output
