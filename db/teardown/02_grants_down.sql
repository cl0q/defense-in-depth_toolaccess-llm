-- =============================================================================
-- teardown/02_grants_down.sql  —  DC-a AUSschalten (für Experiment-Matrix)
-- -----------------------------------------------------------------------------
-- Hebt die Per-Rolle-Least-Privilege-Grenzen auf: die fachlichen Rollen
-- erhalten volle DML-Rechte (kein Privilege-Layer mehr). DDL/DROP bleibt dem
-- Eigentümer vorbehalten; audit_log bleibt per Trigger (05) append-only.
--
-- Wieder einschalten:  psql -f ../02_grants.sql
-- =============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON platform_users, merchants, customers,
                                        products, orders, order_items, payments
    TO role_customer, role_merchant, role_admin;

-- audit_log: nur anhängen/lesen (Ändern/Löschen verhindert der Trigger ohnehin).
GRANT SELECT, INSERT ON audit_log TO role_customer, role_merchant, role_admin;
