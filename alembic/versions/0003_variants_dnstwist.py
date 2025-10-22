from alembic import op
import sqlalchemy as sa  # nu e folosit direct, dar e ok să rămână

# Identificatori Alembic
revision = "0003_variants_dnstwist"
down_revision = "0002_seed_options"   # înlocuiește cu ultimul tău head (vezi comanda mai jos)
branch_labels = None
depends_on = None

def upgrade():
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='fuzzer') THEN
            ALTER TABLE variants ADD COLUMN fuzzer VARCHAR(64);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='is_registered') THEN
            ALTER TABLE variants ADD COLUMN is_registered BOOLEAN;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='has_mx') THEN
            ALTER TABLE variants ADD COLUMN has_mx BOOLEAN;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='mx_count') THEN
            ALTER TABLE variants ADD COLUMN mx_count INTEGER;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='banner_http') THEN
            ALTER TABLE variants ADD COLUMN banner_http TEXT;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='banner_smtp') THEN
            ALTER TABLE variants ADD COLUMN banner_smtp TEXT;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='lsh_algo') THEN
            ALTER TABLE variants ADD COLUMN lsh_algo VARCHAR(16);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='lsh_distance') THEN
            ALTER TABLE variants ADD COLUMN lsh_distance DOUBLE PRECISION;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='phash_distance') THEN
            ALTER TABLE variants ADD COLUMN phash_distance DOUBLE PRECISION;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='screenshot_path') THEN
            ALTER TABLE variants ADD COLUMN screenshot_path TEXT;
        END IF;

        CREATE INDEX IF NOT EXISTS ix_variants_is_registered ON variants (is_registered);
    END$$;
    """)

def downgrade():
    op.execute("""
    DO $$
    BEGIN
        -- Ștergere index dacă există
        IF EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'variants' AND indexname = 'ix_variants_is_registered'
        ) THEN
            DROP INDEX ix_variants_is_registered;
        END IF;

        -- Drop coloane (idempotent)
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='screenshot_path') THEN
            ALTER TABLE variants DROP COLUMN screenshot_path;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='phash_distance') THEN
            ALTER TABLE variants DROP COLUMN phash_distance;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='lsh_distance') THEN
            ALTER TABLE variants DROP COLUMN lsh_distance;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='lsh_algo') THEN
            ALTER TABLE variants DROP COLUMN lsh_algo;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='banner_smtp') THEN
            ALTER TABLE variants DROP COLUMN banner_smtp;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='banner_http') THEN
            ALTER TABLE variants DROP COLUMN banner_http;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='mx_count') THEN
            ALTER TABLE variants DROP COLUMN mx_count;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='has_mx') THEN
            ALTER TABLE variants DROP COLUMN has_mx;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='is_registered') THEN
            ALTER TABLE variants DROP COLUMN is_registered;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='variants' AND column_name='fuzzer') THEN
            ALTER TABLE variants DROP COLUMN fuzzer;
        END IF;
    END$$;
    """)
