-- Creates the role the application connects as.
--
-- This runs once, on first initialisation of the Postgres data directory.
--
-- Why it exists: PostgreSQL exempts superusers and BYPASSRLS roles from every
-- row-level security policy, silently. If the application connects as the
-- cluster superuser, the tenant-isolation policies exist, appear in
-- pg_policies, and enforce nothing. The role below owns the schema (so it can
-- run migrations and FORCE row-level security on its own tables) but is
-- explicitly NOSUPERUSER NOBYPASSRLS, so the policies actually apply to it.
--
-- The container's POSTGRES_USER remains the superuser and is used only for
-- administration.

DO
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ocg_app') THEN
        CREATE ROLE ocg_app LOGIN PASSWORD 'ocg_password' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    ELSE
        ALTER ROLE ocg_app NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

-- The application role owns the schema so Alembic can create tables and apply
-- ALTER TABLE ... FORCE ROW LEVEL SECURITY to them.
ALTER SCHEMA public OWNER TO ocg_app;
GRANT ALL ON SCHEMA public TO ocg_app;
