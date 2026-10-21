from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from backend.app.db import database_url, metadata

url = context.config.get_main_option("sqlalchemy.url") or database_url()
engine = create_engine(url)
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=metadata)
    with context.begin_transaction():
        context.run_migrations()
engine.dispose()
