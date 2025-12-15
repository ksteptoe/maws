from __future__ import annotations

from datetime import datetime, timezone

import pytest

import maws.api as api


class FakeWaiter:
    def __init__(self):
        self.wait_calls = []

    def wait(self, **kwargs):
        self.wait_calls.append(kwargs)


class FakeEC2:
    def __init__(self):
        self.modified = []
        self.terminated = []
        self.describe_instances_calls = []
        self.describe_volumes_calls = []
        self.waiter = FakeWaiter()

    def describe_instances(self, **kwargs):
        self.describe_instances_calls.append(kwargs)

        # Minimal instance structure for our functions
        instances = [
            {
                "InstanceId": "i-1",
                "InstanceType": "t3.micro",
                "PrivateIpAddress": "10.0.0.1",
                "Placement": {"AvailabilityZone": "eu-west-2a"},
                "State": {"Name": "running"},
                "Tags": [{"Key": "Name", "Value": "alpha"}],
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/sda1",
                        "Ebs": {"VolumeId": "vol-root", "DeleteOnTermination": True},
                    },
                    {
                        "DeviceName": "/dev/sdf",
                        "Ebs": {"VolumeId": "vol-data", "DeleteOnTermination": False},
                    },
                ],
            },
            {
                "InstanceId": "i-2",
                "InstanceType": "t3.micro",
                "PrivateIpAddress": "10.0.0.2",
                "Placement": {"AvailabilityZone": "eu-west-2b"},
                "State": {"Name": "stopped"},
                "Tags": [{"Key": "Name", "Value": "bravo"}],
                "BlockDeviceMappings": [],
            },
        ]

        # Filter by InstanceIds if present (simulates AWS)
        ids = kwargs.get("InstanceIds")
        if ids:
            instances = [i for i in instances if i["InstanceId"] in ids]

        return {"Reservations": [{"Instances": instances}]}

    def modify_instance_attribute(self, **kwargs):
        self.modified.append(kwargs)
        return {}

    def describe_volumes(self, **kwargs):
        self.describe_volumes_calls.append(kwargs)
        return {
            "Volumes": [
                {
                    "VolumeId": "vol-orphan-old",
                    "Size": 8,
                    "VolumeType": "gp3",
                    "Encrypted": True,
                    "AvailabilityZone": "eu-west-2a",
                    "CreateTime": datetime(2020, 1, 1, tzinfo=timezone.utc),
                    "Tags": [{"Key": "Name", "Value": "old-orphan"}],
                },
                {
                    "VolumeId": "vol-orphan-new",
                    "Size": 20,
                    "VolumeType": "gp3",
                    "Encrypted": False,
                    "AvailabilityZone": "eu-west-2a",
                    "CreateTime": datetime(2099, 1, 1, tzinfo=timezone.utc),
                    "Tags": [{"Key": "Name", "Value": "new-orphan"}],
                },
            ]
        }

    def terminate_instances(self, **kwargs):
        self.terminated.append(kwargs)
        # emulate success response
        return {
            "TerminatingInstances": [
                {"InstanceId": iid, "CurrentState": {"Name": "shutting-down"}}
                for iid in kwargs.get("InstanceIds", [])
            ]
        }

    def get_waiter(self, name: str):
        assert name == "instance_terminated"
        return self.waiter


class FakeSession:
    def __init__(self, ec2: FakeEC2):
        self._ec2 = ec2

    def client(self, service: str):
        assert service == "ec2"
        return self._ec2


def _patch_boto3(monkeypatch, ec2: FakeEC2):
    def fake_session(*args, **kwargs):
        return FakeSession(ec2)

    monkeypatch.setattr(api, "_boto3_session", lambda profile=None, region=None: fake_session())


def test_ec2_list_instances(monkeypatch):
    ec2 = FakeEC2()
    _patch_boto3(monkeypatch, ec2)

    items = api.ec2_list_instances(region="eu-west-2")
    assert len(items) == 2
    assert items[0]["Name"] == "alpha"
    assert items[1]["Name"] == "bravo"

    only_running = api.ec2_list_instances(region="eu-west-2", state="running")
    assert len(only_running) == 2  # our FakeEC2 doesn't implement Filters; ok to keep simple in unit tests


def test_ec2_set_delete_on_termination_changes_only_false(monkeypatch):
    ec2 = FakeEC2()
    _patch_boto3(monkeypatch, ec2)

    changes = api.ec2_set_delete_on_termination(["i-1"], region="eu-west-2", dry_run=False)

    # root mapping unchanged, data mapping changed
    assert ("i-1", "/dev/sda1", "vol-root", False) in changes
    assert ("i-1", "/dev/sdf", "vol-data", True) in changes

    # one modify call for /dev/sdf
    assert len(ec2.modified) == 1
    assert ec2.modified[0]["InstanceId"] == "i-1"
    assert ec2.modified[0]["BlockDeviceMappings"][0]["DeviceName"] == "/dev/sdf"
    assert ec2.modified[0]["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] is True


def test_ebs_scan_orphans_older_than_days_filters(monkeypatch):
    ec2 = FakeEC2()
    _patch_boto3(monkeypatch, ec2)

    # Older-than should exclude vol-orphan-new (2099)
    orphans = api.ebs_scan_orphaned_volumes(region="eu-west-2", older_than_days=1)
    assert any(v.volume_id == "vol-orphan-old" for v in orphans)
    assert all(v.volume_id != "vol-orphan-new" for v in orphans)


def test_ec2_terminate_instances_wait(monkeypatch):
    ec2 = FakeEC2()
    _patch_boto3(monkeypatch, ec2)

    res = api.ec2_terminate_instances(["i-1"], region="eu-west-2", dry_run=False, wait=True)
    assert res == [("i-1", "shutting-down")]
    assert ec2.waiter.wait_calls == [{"InstanceIds": ["i-1"]}]
