-- =============================================================================
-- 04_masking.sql  —  DC-c: Column-Masking (Variante A: Views + Spalten-REVOKE)
-- -----------------------------------------------------------------------------
-- Verhindert das Lesen sensibler Spalten in ansonsten sichtbaren Zeilen
-- (Angriff R3 / Erfolgsziel G-R2): card_token, internal_cost.
--
-- WICHTIGER FALLSTRICK [Q:postgres-privileges]:
--   "Granting the privilege at the table level and then revoking it for one
--    column will not do what one might wish: the table-level grant is unaffected
--    by a column-level operation."
-- → Spalten-Maskierung per Grant erfordert, das TABELLEN-weite SELECT zuerst
--   zurückzunehmen und dann SELECT NUR auf den erlaubten Spalten neu zu vergeben.
--   Genau das macht dieser Layer (und teardown/04_masking_down.sql kehrt es um).
--
-- Zusätzlich: maskierte Views mit security_invoker = true, damit die RLS-Policies
-- (DC-b) weiterhin mit der Identität des AUFRUFERS greifen (nicht des View-Owners).
--
-- Laden als Eigentümer/Superuser:  psql -f 04_masking.sql
-- =============================================================================

-- -----------------------------------------------------------------------------
-- products.internal_cost vor Kunden verbergen (Spalten-Grant statt Tabellen-Grant).
-- Händler behält Lesezugriff auf internal_cost EIGENER Produkte (Matrix §2).
-- -----------------------------------------------------------------------------
REVOKE SELECT ON products FROM role_customer;
GRANT  SELECT (id, merchant_id, tenant_id, name, price) ON products TO role_customer;

-- -----------------------------------------------------------------------------
-- payments.card_token vor Kunden verbergen.
-- -----------------------------------------------------------------------------
REVOKE SELECT ON payments FROM role_customer;
GRANT  SELECT (id, order_id, tenant_id, amount) ON payments TO role_customer;

-- -----------------------------------------------------------------------------
-- Maskierte Views (security_invoker → RLS des Aufrufers bleibt aktiv).
-- Das Gateway/I6-Templates lesen bevorzugt diese Views statt der Basistabellen.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW app.products_catalog
    WITH (security_invoker = true) AS
    SELECT id, merchant_id, tenant_id, name, price
    FROM products;

CREATE OR REPLACE VIEW app.payments_masked
    WITH (security_invoker = true) AS
    SELECT id, order_id, tenant_id, amount,
           '***MASKED***'::text AS card_token
    FROM payments;

-- Admin sieht card_token ebenfalls maskiert ("eingeschr." in §2) → nutzt die View.
GRANT SELECT ON app.products_catalog TO role_customer, role_merchant, role_admin;
GRANT SELECT ON app.payments_masked  TO role_customer, role_admin;
