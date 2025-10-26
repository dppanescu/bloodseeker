from __future__ import annotations

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool, create_engine
from alembic import context
import os, sys

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add app path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from app.models import Base
    from app.config import settings
except Exception:
    Base = None
    settings = None

target_metadata = Base.metadata if Base else None

def _get_url() -> str:
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    if settings and getattr(settings, "database", None):
        return settings.database.url
    raise RuntimeError("DATABASE_URL is not set and settings.database.url missing")

def run_migrations_offline():
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    connectable = create_engine(_get_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()