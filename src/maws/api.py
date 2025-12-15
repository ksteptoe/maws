from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from maws import __version__

_logger = logging.getLogger(__name__)


def setup_logging(loglevel: int) -> None:
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(
        level=loglevel,
        stream=sys.stdout,
        format=logformat,
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@dataclass(frozen=True)
class OrphanVolume:
    volume_id: str
    size_gib: int
    volume_type: str
    encrypted: bool
    create_time: datetime
    az: str
    name_tag: Optional[str]


@dataclass(frozen=True)
class InstanceSummary:
    instance_id: str
    state: str
    name_tag: Optional[str]


@dataclass(frozen=True)
class DailyCost:
    day: str  # YYYY-MM-DD
    amount: float
    unit: str


@dataclass(frozen=True)
class ServiceCost:
    service: str
    amount: float
    unit: str


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_name_tag(tags: Optional[List[Dict[str, str]]]) -> Optional[str]:
    if not tags:
        return None
    for t in tags:
        if t.get("Key") == "Name":
            return t.get("Value")
    return None


def _boto3_session(profile: Optional[str] = None, region: Optional[str] = None):
    try:
        import boto3  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError("boto3 is required. Install with: pip install boto3") from e

    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def _ec2_client(*, profile: Optional[str], region: Optional[str]):
    sess = _boto3_session(profile=profile, region=region)
    try:
        return sess.client("ec2")
    except Exception as e:
        name = e.__class__.__name__
        if name == "NoRegionError":
            raise RuntimeError(
                "AWS region is not set. Use --region (e.g. --region eu-west-2) "
                "or set a default region."
            ) from e
        raise


# Cost Explorer is effectively a us-east-1 endpoint (ce.us-east-1.amazonaws.com)
_CE_REGION = "us-east-1"


def _ce_client(*, profile: Optional[str], region: Optional[str]):
    # Keep signature aligned with other clients; we ignore `region` and force us-east-1.
    sess = _boto3_session(profile=profile, region=region)
    try:
        return sess.client("ce", region_name=_CE_REGION)
    except Exception as e:
        name = e.__class__.__name__
        if name == "NoRegionError":
            # Should not happen (we force region_name) but keep it friendly.
            raise RuntimeError(
                "AWS region is not set. Use --region (e.g. --region eu-west-2) "
                "or set a default region."
            ) from e
        raise


def _friendly_aws_error(e: Exception) -> RuntimeError:
    name = e.__class__.__name__
    if name in {"NoCredentialsError", "PartialCredentialsError"}:
        return RuntimeError(
            "AWS credentials not found.\n"
            "Fix:\n"
            "  • Put keys in ~/.aws/credentials under a profile (e.g. [pcs])\n"
            "  • Then run: maws --profile pcs --region eu-west-2 ...\n"
        )
    if name == "UnauthorizedOperation":
        return RuntimeError("AWS denied the request (UnauthorizedOperation). Check IAM permissions.")
    return RuntimeError(f"AWS error: {name}: {e}")


def ec2_describe_instances(
    instance_ids: Sequence[str],
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
) -> List[InstanceSummary]:
    ec2 = _ec2_client(profile=profile, region=region)
    try:
        resp = ec2.describe_instances(InstanceIds=list(instance_ids))
    except Exception as e:
        raise _friendly_aws_error(e) from e

    out: List[InstanceSummary] = []
    for r in resp.get("Reservations", []):
        for inst in r.get("Instances", []):
            out.append(
                InstanceSummary(
                    instance_id=inst["InstanceId"],
                    state=inst.get("State", {}).get("Name", "?"),
                    name_tag=_get_name_tag(inst.get("Tags")),
                )
            )
    return out


def ec2_list_block_device_mappings(
    instance_ids: Sequence[str],
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    ec2 = _ec2_client(profile=profile, region=region)
    try:
        resp = ec2.describe_instances(InstanceIds=list(instance_ids))
    except Exception as e:
        raise _friendly_aws_error(e) from e

    out: Dict[str, List[Dict[str, Any]]] = {}
    for r in resp.get("Reservations", []):
        for inst in r.get("Instances", []):
            iid = inst["InstanceId"]
            out[iid] = inst.get("BlockDeviceMappings", [])
    return out


def ec2_set_delete_on_termination(
    instance_ids: Sequence[str],
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    dry_run: bool = False,
) -> List[Tuple[str, str, str, bool]]:
    """
    Set DeleteOnTermination=True for all EBS mappings on given instance(s) where it is currently False.

    Returns tuples:
      (instance_id, device_name, volume_id, changed)
    """
    ec2 = _ec2_client(profile=profile, region=region)

    mappings_by_iid = ec2_list_block_device_mappings(
        instance_ids, profile=profile, region=region
    )

    changes: List[Tuple[str, str, str, bool]] = []
    for iid, mappings in mappings_by_iid.items():
        for m in mappings:
            device = m.get("DeviceName")
            ebs = m.get("Ebs")
            if not device or not ebs:
                continue
            vol_id = ebs.get("VolumeId", "?")
            current = bool(ebs.get("DeleteOnTermination", False))
            if current:
                changes.append((iid, device, vol_id, False))
                continue

            if dry_run:
                changes.append((iid, device, vol_id, True))
                continue

            try:
                ec2.modify_instance_attribute(
                    InstanceId=iid,
                    BlockDeviceMappings=[
                        {"DeviceName": device, "Ebs": {"DeleteOnTermination": True}}
                    ],
                )
            except Exception as e:
                raise _friendly_aws_error(e) from e

            changes.append((iid, device, vol_id, True))

    return changes


def ebs_scan_orphaned_volumes(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    older_than_days: Optional[int] = None,
) -> List[OrphanVolume]:
    ec2 = _ec2_client(profile=profile, region=region)

    try:
        resp = ec2.describe_volumes(
            Filters=[{"Name": "status", "Values": ["available"]}]
        )
    except Exception as e:
        raise _friendly_aws_error(e) from e

    cutoff: Optional[datetime] = None
    if older_than_days is not None:
        cutoff_ts = _utcnow().timestamp() - (older_than_days * 86400)
        cutoff = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc)

    out: List[OrphanVolume] = []
    for v in resp.get("Volumes", []):
        ct: datetime = v["CreateTime"]
        if ct.tzinfo is None:
            ct = ct.replace(tzinfo=timezone.utc)

        if cutoff is not None and ct > cutoff:
            continue

        out.append(
            OrphanVolume(
                volume_id=v["VolumeId"],
                size_gib=int(v["Size"]),
                volume_type=v.get("VolumeType", "?"),
                encrypted=bool(v.get("Encrypted", False)),
                create_time=ct,
                az=v.get("AvailabilityZone", "?"),
                name_tag=_get_name_tag(v.get("Tags")),
            )
        )
    return sorted(out, key=lambda x: x.create_time)


def ec2_terminate_instances(
    instance_ids: Sequence[str],
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    dry_run: bool = False,
    wait: bool = False,
) -> List[Tuple[str, str]]:
    """
    Terminate the given instances.

    Returns tuples:
      (instance_id, resulting_state)
    """
    ec2 = _ec2_client(profile=profile, region=region)

    try:
        resp = ec2.terminate_instances(InstanceIds=list(instance_ids), DryRun=dry_run)
    except Exception as e:
        # DryRunOperation is expected when DryRun=True and you have permission.
        if e.__class__.__name__ == "ClientError":
            msg = str(e)
            if "DryRunOperation" in msg:
                return [(iid, "dry-run-ok") for iid in instance_ids]
        raise _friendly_aws_error(e) from e

    results: List[Tuple[str, str]] = []
    for it in resp.get("TerminatingInstances", []):
        iid = it.get("InstanceId", "?")
        state = it.get("CurrentState", {}).get("Name", "?")
        results.append((iid, state))

    if wait and not dry_run:
        try:
            waiter = ec2.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=list(instance_ids))
        except Exception as e:
            raise _friendly_aws_error(e) from e

    return results


def ec2_list_instances(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    state: Optional[str] = None,
    name_contains: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    List EC2 instances with useful fields.

    state: optional instance state filter (running|stopped|terminated|pending|stopping|shutting-down)
    name_contains: optional case-insensitive substring match against Name tag
    """
    ec2 = _ec2_client(profile=profile, region=region)

    filters = []
    if state:
        filters.append({"Name": "instance-state-name", "Values": [state]})

    kwargs: Dict[str, Any] = {}
    if filters:
        kwargs["Filters"] = filters

    try:
        resp = ec2.describe_instances(**kwargs)
    except Exception as e:
        raise _friendly_aws_error(e) from e

    out: List[Dict[str, Any]] = []
    for r in resp.get("Reservations", []):
        for inst in r.get("Instances", []):
            tags = inst.get("Tags")
            name = _get_name_tag(tags) or ""

            if name_contains and name_contains.lower() not in name.lower():
                continue

            out.append(
                {
                    "InstanceId": inst["InstanceId"],
                    "State": inst.get("State", {}).get("Name", "?"),
                    "Name": name,
                    "Type": inst.get("InstanceType", "?"),
                    "AZ": inst.get("Placement", {}).get("AvailabilityZone", "?"),
                    "PrivateIp": inst.get("PrivateIpAddress", ""),
                }
            )

    # stable ordering: Name then InstanceId
    return sorted(out, key=lambda x: (x["Name"], x["InstanceId"]))


# -----------------------------------------------------------------------------
# Cost Explorer (Costs)

_VALID_COST_METRICS = {
    "UnblendedCost",
    "BlendedCost",
    "AmortizedCost",
    "NetUnblendedCost",
    "NetAmortizedCost",
}


def _ensure_metric(metric: str) -> str:
    if metric not in _VALID_COST_METRICS:
        raise RuntimeError(
            f"Unsupported metric '{metric}'. Choose one of: {', '.join(sorted(_VALID_COST_METRICS))}"
        )
    return metric


def _daterange_days(days: int) -> Tuple[str, str]:
    if days <= 0:
        raise RuntimeError("--days must be >= 1")
    today = date.today()
    start = (today - timedelta(days=days - 1)).isoformat()
    end = (today + timedelta(days=1)).isoformat()  # end is exclusive
    return start, end


def _first_of_month_to_tomorrow() -> Tuple[str, str]:
    today = date.today()
    start = today.replace(day=1).isoformat()
    end = (today + timedelta(days=1)).isoformat()  # end is exclusive
    return start, end


def costs_month_to_date_total(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    metric: str = "UnblendedCost",
) -> Tuple[float, str, str, str]:
    """
    Month-to-date total cost.
    Returns: (amount, unit, start, end_exclusive)
    """
    metric = _ensure_metric(metric)
    ce = _ce_client(profile=profile, region=region)
    start, end = _first_of_month_to_tomorrow()

    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=[metric],
        )
    except Exception as e:
        raise _friendly_aws_error(e) from e

    rbt = resp.get("ResultsByTime", [])
    if not rbt:
        return (0.0, "USD", start, end)

    total = rbt[0].get("Total", {}).get(metric, {})
    amt = float(total.get("Amount", 0.0))
    unit = str(total.get("Unit", "USD"))
    return (amt, unit, start, end)


def costs_daily(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    days: int = 14,
    metric: str = "UnblendedCost",
) -> List[DailyCost]:
    """
    Daily cost for the last N days (including today).
    """
    metric = _ensure_metric(metric)
    ce = _ce_client(profile=profile, region=region)
    start, end = _daterange_days(days)

    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="DAILY",
            Metrics=[metric],
        )
    except Exception as e:
        raise _friendly_aws_error(e) from e

    out: List[DailyCost] = []
    for day in resp.get("ResultsByTime", []):
        d = day.get("TimePeriod", {}).get("Start", "?")
        total = day.get("Total", {}).get(metric, {})
        amt = float(total.get("Amount", 0.0))
        unit = str(total.get("Unit", "USD"))
        out.append(DailyCost(day=d, amount=amt, unit=unit))

    return out


def costs_by_service(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    days: int = 30,
    metric: str = "UnblendedCost",
) -> List[ServiceCost]:
    """
    Aggregate cost by SERVICE over the last N days (including today).
    """
    metric = _ensure_metric(metric)
    ce = _ce_client(profile=profile, region=region)
    start, end = _daterange_days(days)

    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="DAILY",
            Metrics=[metric],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
    except Exception as e:
        raise _friendly_aws_error(e) from e

    totals: Dict[str, Tuple[float, str]] = {}
    for day in resp.get("ResultsByTime", []):
        for g in day.get("Groups", []):
            keys = g.get("Keys", [])
            service = keys[0] if keys else "Unknown"
            m = g.get("Metrics", {}).get(metric, {})
            amt = float(m.get("Amount", 0.0))
            unit = str(m.get("Unit", "USD"))
            prev_amt, _prev_unit = totals.get(service, (0.0, unit))
            totals[service] = (prev_amt + amt, unit)

    out = [ServiceCost(service=s, amount=a, unit=u) for (s, (a, u)) in totals.items()]
    return sorted(out, key=lambda x: x.amount, reverse=True)


def maws_api(loglevel: int) -> None:
    setup_logging(loglevel)
    _logger.info(f"Version: {__version__}")
    _logger.info("Use the CLI subcommands (e.g. `maws ebs ...`, `maws ec2 ...`).")
