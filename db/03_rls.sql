-- =============================================================================
-- 03_rls.sql  —  DC-b: Row-Level Security (USING + WITH CHECK)
-- -----------------------------------------------------------------------------
-- Herzstück der Verteidigung (Beweis für H3c'). Erzwingt die ZEILEN-Grenzen
-- der Matrix (§2) deterministisch:
--   USING       → welche Zeilen sind sicht-/änderbar (Lese-/Vorbedingung).
--   WITH CHECK  → welche Zeilen dürfen GESCHRIEBEN werden (verhindert das
--                 Anlegen/Verschieben fremder oder eskalierter Zeilen → W1/W2/W5).
--
-- Owner/Superuser umgehen RLS → wir setzen FORCE ROW LEVEL SECURITY, damit
-- selbst der Eigentümer den Policies unterliegt; das Gateway verbindet ohnehin
-- als nicht-privilegiertes role_app + SET ROLE.  [Q:postgres-rls]
-- Ohne Policy + aktivierter RLS gilt Default-Deny.  [Q:postgres-rls]
--
-- Identität kommt aus den per Transaktion gesetzten GUCs (siehe 01_schema.sql).
--
-- Schaltbarkeit: per teardown/03_rls_down.sql wieder deaktivierbar.
-- Laden als Eigentümer/Superuser:  psql -f 03_rls.sql
-- =============================================================================

-- Idempotenz: vorhandene Policies droppen, damit das Skript wiederholbar ist.
DROP POLICY IF EXISTS pu_admin           ON platform_users;
DROP POLICY IF EXISTS pu_self_select     ON platform_users;
DROP POLICY IF EXISTS pu_self_update     ON platform_users;
DROP POLICY IF EXISTS merchants_admin    ON merchants;
DROP POLICY IF EXISTS merchants_own       ON merchants;
DROP POLICY IF EXISTS customers_admin     ON customers;
DROP POLICY IF EXISTS customers_self      ON customers;
DROP POLICY IF EXISTS customers_merchant_read ON customers;
DROP POLICY IF EXISTS products_admin      ON products;
DROP POLICY IF EXISTS products_browse     ON products;
DROP POLICY IF EXISTS products_merchant   ON products;
DROP POLICY IF EXISTS orders_admin        ON orders;
DROP POLICY IF EXISTS orders_customer     ON orders;
DROP POLICY IF EXISTS orders_merchant     ON orders;
DROP POLICY IF EXISTS order_items_admin   ON order_items;
DROP POLICY IF EXISTS order_items_customer ON order_items;
DROP POLICY IF EXISTS order_items_merchant ON order_items;
DROP POLICY IF EXISTS payments_admin      ON payments;
DROP POLICY IF EXISTS payments_customer   ON payments;
DROP POLICY IF EXISTS audit_admin_read    ON audit_log;
DROP POLICY IF EXISTS audit_append        ON audit_log;

-- RLS aktivieren + erzwingen (FORCE auch für den Eigentümer).
ALTER TABLE platform_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_users FORCE  ROW LEVEL SECURITY;
ALTER TABLE merchants      ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchants      FORCE  ROW LEVEL SECURITY;
ALTER TABLE customers      ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers      FORCE  ROW LEVEL SECURITY;
ALTER TABLE products       ENABLE ROW LEVEL SECURITY;
ALTER TABLE products       FORCE  ROW LEVEL SECURITY;
ALTER TABLE orders         ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders         FORCE  ROW LEVEL SECURITY;
ALTER TABLE order_items    ENABLE ROW LEVEL SECURITY;
ALTER TABLE order_items    FORCE  ROW LEVEL SECURITY;
ALTER TABLE payments       ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments       FORCE  ROW LEVEL SECURITY;
ALTER TABLE audit_log      ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log      FORCE  ROW LEVEL SECURITY;

-- =============================================================================
-- platform_users  —  Identität. Eskalationsziel W2.
-- =============================================================================
-- Admin: plattformweit (übergreifend).
CREATE POLICY pu_admin ON platform_users TO role_admin
    USING (true) WITH CHECK (true);

-- Kunde/Händler: nur die EIGENE Zeile, nur im eigenen Tenant.
CREATE POLICY pu_self_select ON platform_users FOR SELECT
    TO role_customer, role_merchant
    USING (tenant_id = app.current_tenant() AND id = app.current_user_id());

-- UPDATE nur eigene Zeile; WITH CHECK verhindert Tenant-/Identitätswechsel.
-- (role-Spalte ist zusätzlich per Grant gesperrt → W2 doppelt abgesichert.)
CREATE POLICY pu_self_update ON platform_users FOR UPDATE
    TO role_customer, role_merchant
    USING      (tenant_id = app.current_tenant() AND id = app.current_user_id())
    WITH CHECK (tenant_id = app.current_tenant() AND id = app.current_user_id());

-- =============================================================================
-- merchants  —  eigenes Profil/Auszahlungskonto (W5).
-- =============================================================================
CREATE POLICY merchants_admin ON merchants TO role_admin
    USING (true) WITH CHECK (true);

-- Händler: nur EIGENER Merchant-Datensatz; WITH CHECK verhindert Umbiegen auf
-- fremdes Konto (W5) und Tenant-Wechsel.
CREATE POLICY merchants_own ON merchants
    TO role_merchant
    USING      (tenant_id = app.current_tenant() AND id = app.current_merchant_id())
    WITH CHECK (tenant_id = app.current_tenant() AND id = app.current_merchant_id());
-- (Kunde hat keine Policy → Default-Deny: payout_account/merchants unsichtbar.)

-- =============================================================================
-- customers  —  eigenes Profil (Kunde), eigene Käufer (Händler, eingeschränkt).
-- =============================================================================
CREATE POLICY customers_admin ON customers TO role_admin
    USING (true) WITH CHECK (true);

-- Kunde: eigene Zeile lesen/ändern.
CREATE POLICY customers_self ON customers
    TO role_customer
    USING      (tenant_id = app.current_tenant() AND id = app.current_user_id())
    WITH CHECK (tenant_id = app.current_tenant() AND id = app.current_user_id());

-- Händler: nur Käufer, die bei IHM bestellt haben (eingeschränkt, nur lesen).
CREATE POLICY customers_merchant_read ON customers FOR SELECT
    TO role_merchant
    USING (
        tenant_id = app.current_tenant()
        AND EXISTS (
            SELECT 1 FROM orders o
            WHERE o.customer_id = customers.id
              AND o.merchant_id = app.current_merchant_id()
        )
    );

-- =============================================================================
-- products  —  Browsen (Kunde), eigene Produkte verwalten (Händler).
-- =============================================================================
CREATE POLICY products_admin ON products TO role_admin
    USING (true) WITH CHECK (true);

-- Kunde: alle Produkte im eigenen Tenant lesen (Katalog browsen).
CREATE POLICY products_browse ON products FOR SELECT
    TO role_customer
    USING (tenant_id = app.current_tenant());

-- Händler: nur eigene Produkte (lesen/schreiben). WITH CHECK verhindert
-- Cross-Tenant-Write und Zuordnung an fremden Merchant (W1).
CREATE POLICY products_merchant ON products
    TO role_merchant
    USING      (tenant_id = app.current_tenant() AND merchant_id = app.current_merchant_id())
    WITH CHECK (tenant_id = app.current_tenant() AND merchant_id = app.current_merchant_id());

-- =============================================================================
-- orders  —  eigene Bestellungen (Kunde), eigene Aufträge (Händler).
-- =============================================================================
CREATE POLICY orders_admin ON orders TO role_admin
    USING (true) WITH CHECK (true);

-- Kunde: eigene Bestellungen. WITH CHECK bindet customer_id+tenant → W1/W3
-- (Cross-Tenant- bzw. fremde-Order-Manipulation) ist ausgeschlossen.
CREATE POLICY orders_customer ON orders
    TO role_customer
    USING      (tenant_id = app.current_tenant() AND customer_id = app.current_user_id())
    WITH CHECK (tenant_id = app.current_tenant() AND customer_id = app.current_user_id());

-- Händler: nur eigene Aufträge (merchant_id). Cross-Tenant-Write W1 blockiert.
CREATE POLICY orders_merchant ON orders
    TO role_merchant
    USING      (tenant_id = app.current_tenant() AND merchant_id = app.current_merchant_id())
    WITH CHECK (tenant_id = app.current_tenant() AND merchant_id = app.current_merchant_id());

-- =============================================================================
-- order_items  —  an die zugehörige Bestellung gebunden.
-- =============================================================================
CREATE POLICY order_items_admin ON order_items TO role_admin
    USING (true) WITH CHECK (true);

CREATE POLICY order_items_customer ON order_items
    TO role_customer
    USING (
        tenant_id = app.current_tenant()
        AND EXISTS (SELECT 1 FROM orders o
                    WHERE o.id = order_items.order_id
                      AND o.customer_id = app.current_user_id())
    )
    WITH CHECK (
        tenant_id = app.current_tenant()
        AND EXISTS (SELECT 1 FROM orders o
                    WHERE o.id = order_items.order_id
                      AND o.customer_id = app.current_user_id())
    );

CREATE POLICY order_items_merchant ON order_items FOR SELECT
    TO role_merchant
    USING (
        tenant_id = app.current_tenant()
        AND EXISTS (SELECT 1 FROM orders o
                    WHERE o.id = order_items.order_id
                      AND o.merchant_id = app.current_merchant_id())
    );

-- =============================================================================
-- payments  —  hochsensibel (R3, G-R2). Händler hat KEINEN Zugriff (Default-Deny).
-- =============================================================================
CREATE POLICY payments_admin ON payments TO role_admin
    USING (true) WITH CHECK (true);

-- Kunde: nur Zahlungen zu EIGENEN Bestellungen lesen (card_token in DC-c maskiert).
CREATE POLICY payments_customer ON payments FOR SELECT
    TO role_customer
    USING (
        tenant_id = app.current_tenant()
        AND EXISTS (SELECT 1 FROM orders o
                    WHERE o.id = payments.order_id
                      AND o.customer_id = app.current_user_id())
    );

-- =============================================================================
-- audit_log  —  append-only. Admin liest; alle dürfen anhängen, niemand ändern.
-- (UPDATE/DELETE zusätzlich per fehlendem Grant + Trigger in 05 blockiert.)
-- =============================================================================
CREATE POLICY audit_admin_read ON audit_log FOR SELECT
    TO role_admin
    USING (true);

CREATE POLICY audit_append ON audit_log FOR INSERT
    TO role_customer, role_merchant, role_admin
    WITH CHECK (true);
