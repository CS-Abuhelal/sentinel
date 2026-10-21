from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.String(), primary_key=True),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding", JSONB(), nullable=False),
        sa.Column("advice", JSONB(), nullable=True),
        sa.Column("advice_state", sa.String(), nullable=True),
        sa.Column("advice_model", sa.String(), nullable=True),
        sa.Column("advice_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("host", "key", name="uq_findings_host_key"),
    )
    op.create_index("ix_findings_open", "findings", ["host", "status"])
    op.create_table(
        "sync_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("found", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("sync_runs")
    op.drop_index("ix_findings_open", table_name="findings")
    op.drop_table("findings")
