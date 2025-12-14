# ---- Python API ----
# Functions in this module are imported by the CLI and can also be used directly
# from Python code.

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from maws import __version__

_logger = logging.getLogger(__name__)


def setup_logging(loglevel: int) -> None:
    """Setup basic logging."""
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
        raise RuntimeError(
            "boto3 is required. Add it to your dependencies: pip install boto3"
        ) from e

    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def ec2_list_block_device_mappings(
    instance_ids: Sequence[str],
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Return EC2 BlockDeviceMappings for each instance id.
    """
    sess = _boto3_session(profile=profile, region=region)
    ec2 = sess.client("ec2")

    resp = ec2.describe_instances(InstanceIds=list(instance_ids))
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

    Returns list of changes as tuples:
      (instance_id, device_name, volume_id, changed)
    """
    sess = _boto3_session(profile=profile, region=region)
    ec2 = sess.client("ec2")

    mappings_by_iid = ec2_list_block_device_mappings(
        instance_ids, profile=profile, region=region
    )

    changes: List[Tuple[str, str, str, bool]] = []
    for iid, mappings in mappings_by_iid.items():
        for m in mappings:
            device = m.get("DeviceName")
            ebs = m.get("Ebs")
            if not device or not ebs:
                continue  # skip instance-store or weird mappings
            vol_id = ebs.get("VolumeId", "?")
            current = bool(ebs.get("DeleteOnTermination", False))
            if current is True:
                changes.append((iid, device, vol_id, False))
                continue

            if dry_run:
                changes.append((iid, device, vol_id, True))
                continue

            ec2.modify_instance_attribute(
                InstanceId=iid,
                BlockDeviceMappings=[
                    {
                        "DeviceName": device,
                        "Ebs": {"DeleteOnTermination": True},
                    }
                ],
            )
            changes.append((iid, device, vol_id, True))

    return changes


def ebs_scan_orphaned_volumes(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    older_than_days: Optional[int] = None,
) -> List[OrphanVolume]:
    """
    Find orphaned EBS volumes (State=available), optionally filtered by age.

    older_than_days: if provided, only return volumes with CreateTime older than N days.
    """
    sess = _boto3_session(profile=profile, region=region)
    ec2 = sess.client("ec2")

    resp = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])
    vols = resp.get("Volumes", [])

    cutoff: Optional[datetime] = None
    if older_than_days is not None:
        cutoff = _utcnow()  # now
        # compare using a naive timedelta without importing timedelta for brevity
        cutoff = cutoff.replace()  # keep tz-aware

        # We'll compute cutoff by subtracting days using timestamp arithmetic
        cutoff_ts = cutoff.timestamp() - (older_than_days * 86400)
        cutoff = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc)

    out: List[OrphanVolume] = []
    for v in vols:
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


def maws_api(loglevel: int) -> None:
    """
    Backwards-compatible entry used by the original scaffold.
    The real functionality now lives in CLI subcommands.
    """
    setup_logging(loglevel)
    _logger.info(f"Version: {__version__}")
    _logger.info("Use the CLI subcommands (e.g. `maws ebs ...`).")
