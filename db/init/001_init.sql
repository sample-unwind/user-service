-- =============================================================================
-- User Service Database Schema
-- =============================================================================
-- Supports multitenancy via tenant_id column with PostgreSQL RLS.
-- Email and keycloak_user_id are unique per tenant (not globally).

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- Users Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    email TEXT NOT NULL,
    keycloak_user_id UUID NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Unique constraints per tenant
    CONSTRAINT users_tenant_email_unique UNIQUE (tenant_id, email),
    CONSTRAINT users_tenant_keycloak_unique UNIQUE (tenant_id, keycloak_user_id)
);

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_keycloak_user_id ON users(keycloak_user_id);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- =============================================================================
-- Row-Level Security (RLS) for Multitenancy
-- =============================================================================
-- STRICT POLICY: If app.tenant_id is not set or empty, NO rows are returned.
-- Uses CASE expression to avoid UUID cast errors on empty string.

-- Enable RLS on table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Force RLS to apply even to table owner
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- Drop existing policy if exists
DROP POLICY IF EXISTS tenant_isolation_policy ON users;

-- Create strict RLS policy
CREATE POLICY tenant_isolation_policy ON users
    FOR ALL
    USING (
        CASE 
            WHEN COALESCE(current_setting('app.tenant_id', true), '') = '' THEN false
            ELSE tenant_id = current_setting('app.tenant_id', true)::UUID
        END
    )
    WITH CHECK (
        CASE 
            WHEN COALESCE(current_setting('app.tenant_id', true), '') = '' THEN false
            ELSE tenant_id = current_setting('app.tenant_id', true)::UUID
        END
    );
