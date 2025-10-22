from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_init'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('seed_domains',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table('variants',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('seed_id', sa.Integer(), sa.ForeignKey('seed_domains.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('domain', sa.String(length=255), nullable=False, index=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='new'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('seed_id', 'domain', name='uq_seed_domain_variant')
    )

    op.create_table('check_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('variant_id', sa.Integer(), sa.ForeignKey('variants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('ts', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('dns_ok', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('http_status', sa.Integer(), nullable=True),
        sa.Column('notes', sa.JSON(), nullable=True)
    )

    op.create_table('ct_candidates',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('seed_id', sa.Integer(), sa.ForeignKey('seed_domains.id', ondelete='CASCADE'), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False, server_default='certstream'),
        sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('seen_count', sa.Integer(), nullable=False, server_default='1')
    )

    op.create_table('alerts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('seed_id', sa.Integer(), sa.ForeignKey('seed_domains.id', ondelete='SET NULL'), nullable=True),
        sa.Column('variant_id', sa.Integer(), sa.ForeignKey('variants.id', ondelete='SET NULL'), nullable=True),
        sa.Column('level', sa.String(length=16), nullable=False),
        sa.Column('channel', sa.String(length=16), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )

def downgrade():
    op.drop_table('alerts')
    op.drop_table('ct_candidates')
    op.drop_table('check_runs')
    op.drop_table('variants')
    op.drop_table('seed_domains')
