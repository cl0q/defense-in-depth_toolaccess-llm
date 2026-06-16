-- =============================================================================
-- 02_grants.sql  —  DC-a: Per-Rolle Least-Privilege (Grants)
-- -----------------------------------------------------------------------------
-- Setzt die OPERATIONS-Grenzen der Berechtigungsmatrix (§2): welche Rolle auf
-- welcher Tabelle SELECT/INSERT/UPDATE/DELETE darf — inklusive der kritischen
-- Spalten-Grenzen für WRITE (kein UPDATE auf platform_users.role → W2; kein
-- UPDATE auf *.total → W3; kein UPDATE auf internal_cost → Cost-Manipulation).
--
-- Die READ-Maskierung sensibler Spalten (card_token, internal_cost, payout_account)
-- ist ein SEPARATER, einzeln schaltbarer Layer → siehe 04_masking.sql (DC-c).
-- DDL/DROP ist von Natur aus nur dem Eigentümer vorbehalten und NICHT grantbar
-- → W4 (DROP/TRUNCATE) ist konstruktionsbedingt blockiert.  [Q:postgres-privileges]
--
-- Schaltbarkeit: dieser Layer wird per teardown/02_grants_down.sql wieder
-- entfernt (für die Experiment-Matrix D0 / DA / DB / DC-* ...).
--
-- Laden als Eigentümer/Superuser:  psql -f 02_grants.sql
-- =============================================================================

-- Sauberer Ausgangszustand: erst alle Tabellenrechte der fachlichen Rollen
-- zurücknehmen (idempotent), dann gezielt minimal vergeben.
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM role_customer, role_merchant, role_admin;

-- -----------------------------------------------------------------------------
-- role_customer
--   Profil/Bestellungen lesen+schreiben (eigene, via RLS), Produkte browsen.
--   KEIN UPDATE auf platform_users (→ role-Eskalation W2 unmöglich).
--   KEIN UPDATE auf orders.total   (→ Self-serving-Write W3 unmöglich).
-- -----------------------------------------------------------------------------
GRANT SELECT                       ON platform_users TO role_customer;  -- nur lesen (eigene Zeile via RLS)
GRANT SELECT, UPDATE (name, email, address) ON customers TO role_customer;
GRANT SELECT                       ON products        TO role_customer;  -- browsen; Spalten-Maskierung in DC-c
GRANT SELECT, INSERT               ON orders          TO role_customer;  -- Bestellung aufgeben
GRANT UPDATE (status, note)        ON orders          TO role_customer;  -- stornieren / Notiz; NICHT total
GRANT SELECT, INSERT               ON order_items     TO role_customer;
GRANT SELECT                       ON payments        TO role_customer;  -- eigene; card_token-Maskierung in DC-c
GRANT INSERT                       ON audit_log       TO role_customer;  -- nur anhängen

-- -----------------------------------------------------------------------------
-- role_merchant
--   Eigene Produkte/Umsätze verwalten, eigene Käufer eingeschränkt sehen,
--   eigenes Auszahlungskonto ändern (W5 nur auf EIGENES — via RLS).
--   KEIN UPDATE auf products.internal_cost (→ Cost-Manipulation blockiert).
--   KEIN UPDATE auf orders.total          (→ W3 blockiert).
-- -----------------------------------------------------------------------------
GRANT SELECT                       ON platform_users TO role_merchant;  -- nur eigene Zeile (RLS)
GRANT SELECT (id, tenant_id, name) ON customers      TO role_merchant;  -- eigene Käufer, eingeschränkte PII
GRANT SELECT, INSERT, DELETE       ON products       TO role_merchant;  -- eigene Produkte anlegen/entfernen
GRANT UPDATE (name, price)         ON products       TO role_merchant;  -- NICHT internal_cost
GRANT SELECT                       ON orders         TO role_merchant;  -- eigene Bestellungen
GRANT UPDATE (status)              ON orders         TO role_merchant;  -- Status setzen; NICHT total
GRANT SELECT                       ON order_items    TO role_merchant;
GRANT SELECT, UPDATE (name, payout_account) ON merchants TO role_merchant;  -- eigenes Profil/Konto
GRANT INSERT                       ON audit_log      TO role_merchant;

-- -----------------------------------------------------------------------------
-- role_admin
--   Plattformweite Verwaltung. audit_log bleibt append-only (kein UPDATE/DELETE).
--   Zeilen-Sichtbarkeit regelt RLS (admin = USING(true)).
-- -----------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON platform_users, merchants, customers,
                                        products, orders, order_items, payments
                                     TO role_admin;
GRANT SELECT, INSERT                 ON audit_log TO role_admin;  -- append-only

-- Sequenzen: GENERATED ALWAYS AS IDENTITY benötigt KEINE separaten Sequenz-Grants.
