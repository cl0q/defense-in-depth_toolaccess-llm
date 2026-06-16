-- =============================================================================
-- teardown/04_masking_down.sql  —  DC-c AUSschalten (für Experiment-Matrix)
-- -----------------------------------------------------------------------------
-- Entfernt die Column-Maskierung: maskierte Views werden gedroppt und der
-- Tabellen-weite SELECT für den Kunden wiederhergestellt (sensible Spalten
-- card_token / internal_cost wieder lesbar).
--
-- Hinweis [Q:postgres-privileges]: ein Tabellen-GRANT überdeckt die zuvor
-- gesetzten Spalten-GRANTs; wir nehmen letztere zur Sauberkeit zurück.
--
-- Wieder einschalten:  psql -f ../04_masking.sql
-- =============================================================================

DROP VIEW IF EXISTS app.products_catalog;
DROP VIEW IF EXISTS app.payments_masked;

-- Spalten-Grants entfernen und Tabellen-weiten SELECT zurückgeben.
REVOKE SELECT (id, merchant_id, tenant_id, name, price) ON products FROM role_customer;
GRANT  SELECT ON products TO role_customer;

REVOKE SELECT (id, order_id, tenant_id, amount) ON payments FROM role_customer;
GRANT  SELECT ON payments TO role_customer;
