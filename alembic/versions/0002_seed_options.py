from alembic import op
import sqlalchemy as sa

revision = "0002_seed_options"
down_revision = "0001_init"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("seed_domains", sa.Column("options", sa.JSON(), nullable=True))
    op.add_column("seed_domains", sa.Column("generator", sa.String(length=16), server_default="simple", nullable=False))

def downgrade():
    op.drop_column("seed_domains", "generator")
    op.drop_column("seed_domains", "options")
