-- =============================================================================
-- 01_schema.sql  —  Fundament: Tabellen, Identitäts-GUCs, DB-Rollen
-- -----------------------------------------------------------------------------
-- Umsetzungsplan Schritt 1 · angriffsvektoren-und-verteidigung.md §2.
-- Setzt das Datenmodell (Multi-Tenant-Marktplatz) und die Infrastruktur für
-- die schaltbaren Verteidigungslayer DC-a (Grants), DC-b (RLS), DC-c (Masking).
--
-- Quellen:
--   [Q:postgres-session-config]  SET / set_config / current_setting / SET ROLE
--   [Q:postgres-pooling-state]   SET LOCAL + set_config(..., true) gegen Leakage
--   [Q:postgres-rls]             RLS-Modell (Owner umgeht RLS → FORCE)
--
-- WICHTIG (Fallstrick): Tabelleneigentümer und Superuser umgehen RLS. Das
-- Gateway MUSS sich mit einer nicht-privilegierten Login-Rolle (role_app)
-- verbinden und pro Anfrage per SET LOCAL ROLE in eine fachliche Rolle wechseln.
-- Zusätzlich setzen wir FORCE ROW LEVEL SECURITY (in 03_rls.sql), damit selbst
-- der Eigentümer den Policies unterliegt.  [Q:postgres-rls]
--
-- Laden als Eigentümer/Superuser:  psql -f 01_schema.sql
-- =============================================================================

-- Ein eigenes Schema für die Anwendungsobjekte hält den public-Namespace sauber.
CREATE SCHEMA IF NOT EXISTS app;

-- -----------------------------------------------------------------------------
-- Identitäts-Helfer (lesen die pro-Transaktion gesetzten Session-Variablen).
--
-- Das Gateway setzt pro Request INNERHALB einer Transaktion:
--   SET LOCAL ROLE role_customer | role_merchant | role_admin     (DC-a)
--   SELECT set_config('app.current_tenant',   <tenant>, true);    (DC-b Filter)
--   SELECT set_config('app.current_user',     <user_id>, true);
--   SELECT set_config('app.current_merchant', <merchant_id|''>, true);
--   SELECT set_config('app.current_role',     <customer|merchant|admin>, true);
--
-- `true` (= is_local / SET LOCAL) begrenzt den Wert strikt auf die Transaktion
-- und verhindert Leakage über gepoolte Verbindungen.  [Q:postgres-pooling-state]
-- current_setting(..., true) (missing_ok) liefert NULL statt Fehler, wenn die
-- Variable nicht gesetzt ist → sicheres Default-Deny.  [Q:postgres-session-config]
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.current_tenant() RETURNS text
    LANGUAGE sql STABLE
    AS $$ SELECT nullif(current_setting('app.current_tenant', true), '') $$;

CREATE OR REPLACE FUNCTION app.current_user_id() RETURNS bigint
    LANGUAGE sql STABLE
    AS $$ SELECT nullif(current_setting('app.current_user', true), '')::bigint $$;

CREATE OR REPLACE FUNCTION app.current_merchant_id() RETURNS bigint
    LANGUAGE sql STABLE
    AS $$ SELECT nullif(current_setting('app.current_merchant', true), '')::bigint $$;

CREATE OR REPLACE FUNCTION app.current_app_role() RETURNS text
    LANGUAGE sql STABLE
    AS $$ SELECT nullif(current_setting('app.current_role', true), '') $$;

-- =============================================================================
-- DB-Rollen (DC-a Träger).  NOLOGIN für fachliche Rollen; nur role_app loggt
-- ein und wechselt per SET ROLE. role_app erbt NICHT (INHERIT FALSE) → es hat
-- ohne expliziten SET ROLE keinerlei Tabellenrechte (Least Privilege).
-- SET TRUE erlaubt den Wechsel via SET ROLE.  [Q:postgres-privileges]
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_customer') THEN
        CREATE ROLE role_customer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_merchant') THEN
        CREATE ROLE role_merchant NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_admin') THEN
        CREATE ROLE role_admin NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_app') THEN
        -- Passwort hier nur Platzhalter; im Betrieb über Secret setzen.
        CREATE ROLE role_app LOGIN PASSWORD 'change_me'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END
$$;

-- role_app darf in die fachlichen Rollen wechseln, erbt sie aber nicht.
GRANT role_customer TO role_app WITH INHERIT FALSE, SET TRUE;
GRANT role_merchant TO role_app WITH INHERIT FALSE, SET TRUE;
GRANT role_admin    TO role_app WITH INHERIT FALSE, SET TRUE;

-- Basiszugriff auf die Schemata (keine Tabellenrechte — die kommen in 02_grants).
GRANT USAGE ON SCHEMA public TO role_app, role_customer, role_merchant, role_admin;
GRANT USAGE ON SCHEMA app    TO role_app, role_customer, role_merchant, role_admin;
GRANT EXECUTE ON FUNCTION
    app.current_tenant(), app.current_user_id(),
    app.current_merchant_id(), app.current_app_role()
    TO role_app, role_customer, role_merchant, role_admin;

-- =============================================================================
-- Datenmodell (§2). Denormalisiert: JEDE mandantengebundene Tabelle trägt
-- tenant_id, damit RLS-Policies ohne JOINs auskommen (einfach + schnell).
-- =============================================================================

-- Identitäts-/Stammtabelle. Eskalationsziel W2 (role-Spalte).
CREATE TABLE platform_users (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role        text   NOT NULL CHECK (role IN ('customer', 'merchant', 'admin')),
    tenant_id   text,                       -- NULL = plattformweit (admin)
    merchant_id bigint,                     -- gesetzt nur für Händler-Nutzer
    username    text NOT NULL UNIQUE
);

CREATE TABLE merchants (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id      text NOT NULL,
    name           text NOT NULL,
    payout_account text                     -- sensibel (W5, R2); DC-c-maskiert
);

CREATE TABLE customers (
    id        bigint PRIMARY KEY
                  REFERENCES platform_users (id) ON DELETE CASCADE,  -- 1:1 Identität
    tenant_id text NOT NULL,
    name      text NOT NULL,
    email     text,                         -- PII
    address   text                          -- PII
);

CREATE TABLE products (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    merchant_id   bigint NOT NULL REFERENCES merchants (id) ON DELETE CASCADE,
    tenant_id     text   NOT NULL,
    name          text   NOT NULL,          -- Freitext → S1 Stored-Injection-Vektor
    price         numeric(12,2) NOT NULL,
    internal_cost numeric(12,2)             -- sensibel (R3); DC-c-maskiert
);

CREATE TABLE orders (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers (id),
    merchant_id bigint NOT NULL REFERENCES merchants (id),
    tenant_id   text   NOT NULL,
    total       numeric(12,2) NOT NULL,     -- W3: darf nicht willkürlich änderbar sein
    status      text   NOT NULL DEFAULT 'placed',
    note        text                        -- Freitext → S1 Stored-Injection-Vektor
);

CREATE TABLE order_items (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id   bigint NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
    product_id bigint NOT NULL REFERENCES products (id),
    tenant_id  text   NOT NULL,
    qty        integer NOT NULL,
    price      numeric(12,2) NOT NULL
);

CREATE TABLE payments (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id   bigint NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
    tenant_id  text   NOT NULL,
    card_token text,                        -- hochsensibel (R3, G-R2); DC-c-maskiert
    amount     numeric(12,2) NOT NULL
);

-- Append-only Audit-Trail. Schreiben erlaubt, Ändern/Löschen verboten
-- (Grants in 02 + Trigger in 05_constraints.sql).
CREATE TABLE audit_log (
    id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor  text NOT NULL,
    action text NOT NULL,
    target text,
    ts     timestamptz NOT NULL DEFAULT now()
);

-- Indizes auf den RLS-Filterspalten (Performance der Policies).
CREATE INDEX idx_pu_tenant         ON platform_users (tenant_id);
CREATE INDEX idx_merchants_tenant  ON merchants (tenant_id);
CREATE INDEX idx_customers_tenant  ON customers (tenant_id);
CREATE INDEX idx_products_merchant ON products (merchant_id);
CREATE INDEX idx_products_tenant   ON products (tenant_id);
CREATE INDEX idx_orders_customer   ON orders (customer_id);
CREATE INDEX idx_orders_merchant   ON orders (merchant_id);
CREATE INDEX idx_orders_tenant     ON orders (tenant_id);
CREATE INDEX idx_order_items_order ON order_items (order_id);
CREATE INDEX idx_payments_order    ON payments (order_id);
