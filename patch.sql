-- sql/patch_add_dnstwist_columns.sql
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
