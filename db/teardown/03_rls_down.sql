-- =============================================================================
-- teardown/03_rls_down.sql  —  DC-b AUSschalten (für Experiment-Matrix)
-- -----------------------------------------------------------------------------
-- Deaktiviert Row-Level Security. Policies werden gedroppt und RLS/FORCE
-- abgeschaltet → es greifen nur noch die SQL-Standard-Privilegien (DC-a) und
-- ggf. Masking (DC-c). Disabling RLS entfernt Policies nicht zwingend, daher
-- droppen wir sie explizit für einen sauberen Zustand.  [Q:postgres-rls]
--
-- Wieder einschalten:  psql -f ../03_rls.sql
-- =============================================================================

DROP POLICY IF EXISTS pu_admin               ON platform_users;
DROP POLICY IF EXISTS pu_self_select         ON platform_users;
DROP POLICY IF EXISTS pu_self_update         ON platform_users;
DROP POLICY IF EXISTS merchants_admin        ON merchants;
DROP POLICY IF EXISTS merchants_own          ON merchants;
DROP POLICY IF EXISTS customers_admin        ON customers;
DROP POLICY IF EXISTS customers_self         ON customers;
DROP POLICY IF EXISTS customers_merchant_read ON customers;
DROP POLICY IF EXISTS products_admin         ON products;
DROP POLICY IF EXISTS products_browse        ON products;
DROP POLICY IF EXISTS products_merchant      ON products;
DROP POLICY IF EXISTS orders_admin           ON orders;
DROP POLICY IF EXISTS orders_customer        ON orders;
DROP POLICY IF EXISTS orders_merchant        ON orders;
DROP POLICY IF EXISTS order_items_admin      ON order_items;
DROP POLICY IF EXISTS order_items_customer   ON order_items;
DROP POLICY IF EXISTS order_items_merchant   ON order_items;
DROP POLICY IF EXISTS payments_admin         ON payments;
DROP POLICY IF EXISTS payments_customer      ON payments;
DROP POLICY IF EXISTS audit_admin_read       ON audit_log;
DROP POLICY IF EXISTS audit_append           ON audit_log;

ALTER TABLE platform_users NO FORCE ROW LEVEL SECURITY;
ALTER TABLE platform_users DISABLE  ROW LEVEL SECURITY;
ALTER TABLE merchants      NO FORCE ROW LEVEL SECURITY;
ALTER TABLE merchants      DISABLE  ROW LEVEL SECURITY;
ALTER TABLE customers      NO FORCE ROW LEVEL SECURITY;
ALTER TABLE customers      DISABLE  ROW LEVEL SECURITY;
ALTER TABLE products       NO FORCE ROW LEVEL SECURITY;
ALTER TABLE products       DISABLE  ROW LEVEL SECURITY;
ALTER TABLE orders         NO FORCE ROW LEVEL SECURITY;
ALTER TABLE orders         DISABLE  ROW LEVEL SECURITY;
ALTER TABLE order_items    NO FORCE ROW LEVEL SECURITY;
ALTER TABLE order_items    DISABLE  ROW LEVEL SECURITY;
ALTER TABLE payments       NO FORCE ROW LEVEL SECURITY;
ALTER TABLE payments       DISABLE  ROW LEVEL SECURITY;
ALTER TABLE audit_log      NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log      DISABLE  ROW LEVEL SECURITY;
