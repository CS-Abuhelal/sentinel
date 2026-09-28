from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "wazuh_alerts", sa.Column("grouped_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index("ix_wazuh_alerts_grouped_at", "wazuh_alerts", ["grouped_at"])
    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(), primary_key=True),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("group_key", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("first_alert_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_alert_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_level", sa.Integer(), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("incident", JSONB(), nullable=False),
        sa.Column("run", JSONB(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incidents_open", "incidents", ["host", "group_key", "status"])
    op.create_index("ix_incidents_last_alert_at", "incidents", ["last_alert_at"])


def downgrade() -> None:
    op.drop_index("ix_incidents_last_alert_at", table_name="incidents")
    op.drop_index("ix_incidents_open", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("ix_wazuh_alerts_grouped_at", table_name="wazuh_alerts")
    op.drop_column("wazuh_alerts", "grouped_at")
