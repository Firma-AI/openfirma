-- Firma example agents — Supabase schema and seed data.
--
-- Apply once per Supabase project:
--   - Paste into the Supabase SQL editor and run, or
--   - `supabase db push` if you're using the CLI against this project.
--
-- This is deliberately insecure: `execute_sql` lets the agent (and therefore
-- anyone who can prompt the agent) run arbitrary SQL. It exists to preserve
-- the "intentionally unsafe tool" narrative from the demo. With Firma in
-- front, the sidecar enforces what queries are allowed over the wire; the
-- in-database function is the same permissive surface as the original
-- SQLite agent had.

-- 1. Products table -----------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.products (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price NUMERIC(10, 2) NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0
);

INSERT INTO public.products (id, name, category, price, stock) VALUES
    (1, 'Wireless Mouse', 'Electronics', 29.99, 150),
    (2, 'Mechanical Keyboard', 'Electronics', 89.99, 75),
    (3, 'USB-C Hub', 'Electronics', 49.99, 200),
    (4, 'Standing Desk', 'Furniture', 399.99, 30),
    (5, 'Ergonomic Chair', 'Furniture', 299.99, 45),
    (6, 'Monitor Arm', 'Furniture', 79.99, 120),
    (7, 'Notebook Pack (3)', 'Office Supplies', 12.99, 500),
    (8, 'Ballpoint Pens (10)', 'Office Supplies', 8.99, 800),
    (9, 'Webcam HD', 'Electronics', 59.99, 90),
    (10, 'Desk Lamp', 'Furniture', 44.99, 110)
ON CONFLICT (id) DO NOTHING;

SELECT setval(
    pg_get_serial_sequence('public.products', 'id'),
    COALESCE((SELECT MAX(id) FROM public.products), 1)
);

-- 2. Free-form SQL RPC --------------------------------------------------------

CREATE OR REPLACE FUNCTION public.execute_sql(query text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    result jsonb;
    first_word text;
BEGIN
    first_word := lower(split_part(trim(query), ' ', 1));

    IF first_word IN ('select', 'with', 'values', 'show', 'explain') THEN
        EXECUTE
            'SELECT COALESCE(jsonb_agg(t), ''[]''::jsonb) FROM (' || query || ') t'
            INTO result;
        RETURN result;
    END IF;

    EXECUTE query;
    RETURN jsonb_build_object('status', 'executed', 'statement', first_word);
EXCEPTION WHEN others THEN
    RETURN jsonb_build_object('error', SQLERRM, 'sqlstate', SQLSTATE);
END;
$$;

-- Allow the Supabase roles reachable via PostgREST to invoke this. The
-- publishable key (sb_publishable_...) hits the API as the `anon` role, so
-- that's the one that actually matters for the demo.
GRANT EXECUTE ON FUNCTION public.execute_sql(text) TO anon, authenticated, service_role;

-- 3. Storage bucket -----------------------------------------------------------
--
-- Create the bucket the agents write to. Adjust the name if you change the
-- SUPABASE_STORAGE_BUCKET env var.

INSERT INTO storage.buckets (id, name, public)
VALUES ('firma-demo', 'firma-demo', false)
ON CONFLICT (id) DO NOTHING;

-- Minimal permissive policies so the publishable key can read / write demo
-- objects. Tighten for any real deployment.
--
-- Postgres does not support `CREATE POLICY IF NOT EXISTS`, so we drop-then-
-- create to keep this script idempotent.

DROP POLICY IF EXISTS "firma-demo read" ON storage.objects;
CREATE POLICY "firma-demo read"
    ON storage.objects FOR SELECT
    USING (bucket_id = 'firma-demo');

DROP POLICY IF EXISTS "firma-demo write" ON storage.objects;
CREATE POLICY "firma-demo write"
    ON storage.objects FOR INSERT
    WITH CHECK (bucket_id = 'firma-demo');

DROP POLICY IF EXISTS "firma-demo update" ON storage.objects;
CREATE POLICY "firma-demo update"
    ON storage.objects FOR UPDATE
    USING (bucket_id = 'firma-demo');
