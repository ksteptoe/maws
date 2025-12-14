from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
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
        # botocore exceptions are common; avoid hard dependency on botocore symbols
        name = e.__class__.__name__
        if name == "NoRegionError":
            raise RuntimeError(
                "AWS region is not set. Use --region (e.g. --region eu-west-2) "
                "or configure a default: `aws configure set region eu-west-2`."
            ) from e
        if name in {"NoCredentialsError", "PartialCredentialsError"}:
            raise RuntimeError(
                "AWS credentials not found. Configure credentials (aws configure) "
                "or set AWS_PROFILE / AWS_ACCESS_KEY_ID etc."
            ) from e
        raise


def ec2_list_block_device_mappings(
    instance_ids: Sequence[str],
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    ec2 = _ec2_client(profile=profile, region=region)

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
            if current is True:
                changes.append((iid, device, vol_id, False))
                continue

            if dry_run:
                changes.append((iid, device, vol_id, True))
                continue

            ec2.modify_instance_attribute(
                InstanceId=iid,
                BlockDeviceMappings=[
                    {"DeviceName": device, "Ebs": {"DeleteOnTermination": True}}
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
    ec2 = _ec2_client(profile=profile, region=region)

    resp = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])
    vols = resp.get("Volumes", [])

    cutoff: Optional[datetime] = None
    if older_than_days is not None:
        cutoff_ts = _utcnow().timestamp() - (older_than_days * 86400)
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
    setup_logging(loglevel)
    _logger.info(f"Version: {__version__}")
    _logger.info("Use the CLI subcommands (e.g. `maws ebs ...`).")
