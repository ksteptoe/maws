"""
To install run ``pip install .`` (or ``pip install -e .`` for editable mode)
which will install the command `maws` inside your current environment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Sequence

import click

from maws import __version__
from .api import ebs_scan_orphaned_volumes, ec2_set_delete_on_termination, setup_logging

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Ctx:
    loglevel: int
    profile: Optional[str]
    region: Optional[str]


def _format_table(rows, headers):
    # simple fixed-width table without external deps
    cols = list(zip(*([headers] + rows))) if rows else [headers]
    widths = [max(len(str(x)) for x in col) for col in cols]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    lines = [fmt.format(*headers)]
    lines.append(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        lines.append(fmt.format(*[str(x) for x in r]))
    return "\n".join(lines)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "--version")
@click.option("-v", "--verbose", "loglevel", flag_value=logging.INFO, default=True, help="INFO logging")
@click.option("-vv", "--very-verbose", "loglevel", flag_value=logging.DEBUG, help="DEBUG logging")
@click.option("--profile", default=None, help="AWS profile name (optional)")
@click.option("--region", default=None, help="AWS region (optional)")
@click.pass_context
def cli(ctx: click.Context, loglevel: int, profile: Optional[str], region: Optional[str]):
    """maws — AWS management utilities (EC2/EBS focus)."""
    setup_logging(loglevel)
    ctx.obj = Ctx(loglevel=loglevel, profile=profile, region=region)


@cli.group()
def ebs():
    """EBS-related tools."""


@ebs.command("set-delete-on-termination")
@click.argument("instance_ids", nargs=-1, required=True)
@click.option("--dry-run", is_flag=True, help="Show what would change without applying.")
@click.pass_obj
def ebs_set_delete_on_termination(ctx: Ctx, instance_ids: Sequence[str], dry_run: bool):
    """
    Set DeleteOnTermination=True for all EBS volumes attached to the given INSTANCE_IDS.

    Example:
      maws --region eu-west-2 ebs set-delete-on-termination i-123 i-456
    """
    changes = ec2_set_delete_on_termination(
        list(instance_ids),
        profile=ctx.profile,
        region=ctx.region,
        dry_run=dry_run,
    )

    rows = []
    changed_count = 0
    for iid, device, vol, changed in changes:
        rows.append([iid, device, vol, "YES" if changed else "no"])
        if changed:
            changed_count += 1

    click.echo(_format_table(rows, headers=["InstanceId", "Device", "VolumeId", "Changed"]))
    if dry_run:
        click.echo(f"\nDRY RUN: {changed_count} mapping(s) would be updated.")
    else:
        click.echo(f"\nDone: {changed_count} mapping(s) updated.")


@ebs.command("scan-orphans")
@click.option("--older-than-days", type=int, default=None, help="Only show volumes older than N days.")
@click.pass_obj
def ebs_scan_orphans(ctx: Ctx, older_than_days: Optional[int]):
    """
    List orphaned EBS volumes (State=available), which may be incurring cost.

    Example:
      maws ebs scan-orphans
      maws ebs scan-orphans --older-than-days 14
    """
    orphans = ebs_scan_orphaned_volumes(
        profile=ctx.profile,
        region=ctx.region,
        older_than_days=older_than_days,
    )

    if not orphans:
        click.echo("No orphaned (available) EBS volumes found.")
        return

    rows = []
    for v in orphans:
        rows.append(
            [
                v.volume_id,
                f"{v.size_gib}GiB",
                v.volume_type,
                "yes" if v.encrypted else "no",
                v.az,
                v.create_time.strftime("%Y-%m-%d"),
                v.name_tag or "",
            ]
        )

    click.echo(
        _format_table(
            rows,
            headers=["VolumeId", "Size", "Type", "Enc", "AZ", "Created", "NameTag"],
        )
    )
    click.echo(f"\nFound {len(orphans)} orphaned volume(s).")
