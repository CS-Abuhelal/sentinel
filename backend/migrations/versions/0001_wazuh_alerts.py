from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wazuh_alerts",
        sa.Column("wazuh_id", sa.String(), primary_key=True),
        sa.Column("alert_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_name", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("event", JSONB(), nullable=False),
        sa.Column("alert", JSONB(), nullable=False),
        sa.Column("incident_id", sa.String(), nullable=True),
    )
    op.create_index("ix_wazuh_alerts_alert_time", "wazuh_alerts", ["alert_time"])


def downgrade() -> None:
    op.drop_index("ix_wazuh_alerts_alert_time", table_name="wazuh_alerts")
    op.drop_table("wazuh_alerts")
