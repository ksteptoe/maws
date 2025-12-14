from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Sequence

import click

from maws import __version__
from .api import (
    ebs_scan_orphaned_volumes,
    ec2_describe_instances,
    ec2_list_instances,
    ec2_set_delete_on_termination,
    ec2_terminate_instances,
    setup_logging,
)

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Ctx:
    loglevel: int
    profile: Optional[str]
    region: Optional[str]


def _format_table(rows, headers):
    cols = list(zip(*([headers] + rows))) if rows else [headers]
    widths = [max(len(str(x)) for x in col) for col in cols]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    lines = [fmt.format(*headers)]
    lines.append(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        lines.append(fmt.format(*[str(x) for x in r]))
    return "\n".join(lines)


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "maws — AWS management utilities (EC2/EBS focus).\n"
        "\n"
        "Most useful commands:\n"
        "\n"
        "  maws ec2 list\n"
        "\n"
        "  maws ebs scan-orphans\n"
        "\n"
        "  maws ebs set-delete-on-termination --dry-run i-xxxxxxxxxxxxxxxxx\n"
        "\n"
        "  maws ec2 terminate --dry-run --confirm TERMINATE i-xxxxxxxxxxxxxxxxx\n"
        "\n"
        "  maws ec2 terminate --confirm TERMINATE --wait i-xxxxxxxxxxxxxxxxx\n"
        "\n"
        "Tip: set these once per shell session (or in ~/.bashrc):\n"
        "\n"
        "  export AWS_PROFILE=pcs\n"
        "  export AWS_DEFAULT_REGION=eu-west-2\n"
    ),
)
@click.version_option(__version__, "--version")
@click.option("-v", "--verbose", "loglevel", flag_value=logging.INFO, default=True, help="INFO logging")
@click.option("-vv", "--very-verbose", "loglevel", flag_value=logging.DEBUG, help="DEBUG logging")
@click.option("--profile", default=None, help="AWS profile name (optional)")
@click.option("--region", default=None, help="AWS region (optional), e.g. eu-west-2")
@click.pass_context
def cli(ctx: click.Context, loglevel: int, profile: Optional[str], region: Optional[str]):
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
    try:
        changes = ec2_set_delete_on_termination(
            list(instance_ids),
            profile=ctx.profile,
            region=ctx.region,
            dry_run=dry_run,
        )
    except RuntimeError as e:
        click.secho(str(e), fg="red")
        raise SystemExit(2)

    rows = []
    changed_count = 0
    for iid, device, vol, changed in changes:
        rows.append([iid, device, vol, "YES" if changed else "no"])
        if changed:
            changed_count += 1

    click.echo(_format_table(rows, headers=["InstanceId", "Device", "VolumeId", "Changed"]))
    click.echo(f"\n{'DRY RUN:' if dry_run else 'Done:'} {changed_count} mapping(s) {'would be' if dry_run else ''} updated.")


@ebs.command("scan-orphans")
@click.option("--older-than-days", type=int, default=None, help="Only show volumes older than N days.")
@click.pass_obj
def ebs_scan_orphans(ctx: Ctx, older_than_days: Optional[int]):
    try:
        orphans = ebs_scan_orphaned_volumes(
            profile=ctx.profile,
            region=ctx.region,
            older_than_days=older_than_days,
        )
    except RuntimeError as e:
        click.secho(str(e), fg="red")
        raise SystemExit(2)

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

    click.echo(_format_table(rows, headers=["VolumeId", "Size", "Type", "Enc", "AZ", "Created", "NameTag"]))
    click.echo(f"\nFound {len(orphans)} orphaned volume(s).")


@cli.group()
def ec2():
    """EC2 instance tools."""


@ec2.command("list")
@click.option(
    "--state",
    type=click.Choice(
        ["pending", "running", "stopping", "stopped", "shutting-down", "terminated"],
        case_sensitive=False,
    ),
    default=None,
    help="Filter by instance state.",
)
@click.option("--name-contains", default=None, help="Filter: Name tag contains this substring (case-insensitive).")
@click.pass_obj
def ec2_list(ctx: Ctx, state: Optional[str], name_contains: Optional[str]):
    try:
        items = ec2_list_instances(
            profile=ctx.profile,
            region=ctx.region,
            state=state.lower() if state else None,
            name_contains=name_contains,
        )
    except RuntimeError as e:
        click.secho(str(e), fg="red")
        raise SystemExit(2)

    if not items:
        click.echo("No instances found (with current filters).")
        return

    rows = [
        [i["InstanceId"], i["State"], i["Name"], i["Type"], i["AZ"], i["PrivateIp"]]
        for i in items
    ]
    click.echo(_format_table(rows, headers=["InstanceId", "State", "Name", "Type", "AZ", "PrivateIp"]))
    click.echo(f"\nFound {len(items)} instance(s).")


@ec2.command("terminate")
@click.argument("instance_ids", nargs=-1, required=True)
@click.option("--dry-run", is_flag=True, help="Validate permissions and show actions; do not change anything.")
@click.option("--skip-dot", is_flag=True, help="Skip setting DeleteOnTermination=True (not recommended).")
@click.option("--wait", is_flag=True, help="Wait until instances reach 'terminated'.")
@click.option(
    "--confirm",
    default=None,
    help="Safety gate: must be exactly TERMINATE to proceed (script-friendly).",
)
@click.pass_obj
def ec2_terminate(ctx: Ctx, instance_ids: Sequence[str], dry_run: bool, skip_dot: bool, wait: bool, confirm: Optional[str]):
    try:
        summaries = ec2_describe_instances(
            list(instance_ids), profile=ctx.profile, region=ctx.region
        )
    except RuntimeError as e:
        click.secho(str(e), fg="red")
        raise SystemExit(2)

    rows = [[s.instance_id, s.state, s.name_tag or ""] for s in summaries]
    click.echo(_format_table(rows, headers=["InstanceId", "State", "NameTag"]))
    click.echo("")

    if confirm != "TERMINATE":
        click.secho(
            "Refusing to proceed without --confirm TERMINATE (safety gate).",
            fg="yellow",
        )
        click.echo("Re-run with:  maws ec2 terminate --confirm TERMINATE <instance-ids...>")
        raise SystemExit(2)

    if not skip_dot:
        try:
            dot_changes = ec2_set_delete_on_termination(
                list(instance_ids),
                profile=ctx.profile,
                region=ctx.region,
                dry_run=dry_run,
            )
        except RuntimeError as e:
            click.secho(str(e), fg="red")
            raise SystemExit(2)

        dot_rows = []
        changed = 0
        for iid, dev, vol, did_change in dot_changes:
            dot_rows.append([iid, dev, vol, "YES" if did_change else "no"])
            if did_change:
                changed += 1

        click.echo(_format_table(dot_rows, headers=["InstanceId", "Device", "VolumeId", "DoT set"]))
        click.echo(f"\n{'DRY RUN:' if dry_run else 'Done:'} {changed} mapping(s) {'would be' if dry_run else ''} updated.\n")

    try:
        term_results = ec2_terminate_instances(
            list(instance_ids),
            profile=ctx.profile,
            region=ctx.region,
            dry_run=dry_run,
            wait=wait,
        )
    except RuntimeError as e:
        click.secho(str(e), fg="red")
        raise SystemExit(2)

    trows = [[iid, state] for (iid, state) in term_results]
    click.echo(_format_table(trows, headers=["InstanceId", "Result"]))
    click.echo("\nDone.")
