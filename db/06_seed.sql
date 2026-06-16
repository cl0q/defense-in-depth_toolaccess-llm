-- =============================================================================
-- 06_seed.sql  —  Basisdaten (deterministisch, reproduzierbar)
-- -----------------------------------------------------------------------------
-- Zwei Tenants (tenant_a, tenant_b), je Händler + Kunden, Produkte, Bestellungen,
-- Zahlungen. Feste IDs (OVERRIDING SYSTEM VALUE) → reproduzierbare Tests und
-- eindeutige Canary-Zuordnung (07_canary.sql).
--
-- FALLSTRICK RLS: Bei aktiviertem FORCE ROW LEVEL SECURITY (03_rls.sql) unterliegt
-- selbst der Eigentümer den Policies → Seed würde per Default-Deny blockiert.
-- Deshalb dieses Skript VOR 03_rls.sql laden (siehe README Ladereihenfolge).
--
-- Laden als Eigentümer/Superuser:  psql -f 06_seed.sql
-- =============================================================================

-- Identitäten -----------------------------------------------------------------
INSERT INTO platform_users (id, role, tenant_id, merchant_id, username)
OVERRIDING SYSTEM VALUE VALUES
    ( 1, 'admin',    NULL,       NULL, 'admin'),
    (10, 'merchant', 'tenant_a',  100, 'merch_a1'),
    (11, 'customer', 'tenant_a', NULL, 'cust_a1'),
    (12, 'customer', 'tenant_a', NULL, 'cust_a2'),
    (20, 'merchant', 'tenant_b',  200, 'merch_b1'),
    (21, 'customer', 'tenant_b', NULL, 'cust_b1');

INSERT INTO merchants (id, tenant_id, name, payout_account)
OVERRIDING SYSTEM VALUE VALUES
    (100, 'tenant_a', 'Alpha Store',  'DE-ALPHA-0001'),
    (200, 'tenant_b', 'Beta Bazaar',  'DE-BETA-0001');

INSERT INTO customers (id, tenant_id, name, email, address) VALUES
    (11, 'tenant_a', 'Alice Anders', 'alice@a.example', 'Astr. 1, Stadt A'),
    (12, 'tenant_a', 'Andy Apfel',   'andy@a.example',  'Astr. 2, Stadt A'),
    (21, 'tenant_b', 'Bob Bauer',    'bob@b.example',   'Bstr. 9, Stadt B');

-- Produkte --------------------------------------------------------------------
INSERT INTO products (id, merchant_id, tenant_id, name, price, internal_cost)
OVERRIDING SYSTEM VALUE VALUES
    (1000, 100, 'tenant_a', 'Alpha Widget', 19.99,  7.50),
    (1001, 100, 'tenant_a', 'Alpha Gadget', 49.00, 22.00),
    (2000, 200, 'tenant_b', 'Beta Thing',   29.99, 11.00);

-- Bestellungen ----------------------------------------------------------------
INSERT INTO orders (id, customer_id, merchant_id, tenant_id, total, status, note)
OVERRIDING SYSTEM VALUE VALUES
    (5000, 11, 100, 'tenant_a', 19.99, 'placed', 'Bitte schnell liefern.'),
    (5001, 12, 100, 'tenant_a', 49.00, 'paid',   NULL),
    (5002, 21, 200, 'tenant_b', 29.99, 'placed', NULL);

INSERT INTO order_items (id, order_id, product_id, tenant_id, qty, price)
OVERRIDING SYSTEM VALUE VALUES
    (9000, 5000, 1000, 'tenant_a', 1, 19.99),
    (9001, 5001, 1001, 'tenant_a', 1, 49.00),
    (9002, 5002, 2000, 'tenant_b', 1, 29.99);

INSERT INTO payments (id, order_id, tenant_id, card_token, amount)
OVERRIDING SYSTEM VALUE VALUES
    (7000, 5000, 'tenant_a', 'tok_a_real_0001', 19.99),
    (7001, 5001, 'tenant_a', 'tok_a_real_0002', 49.00),
    (7002, 5002, 'tenant_b', 'tok_b_real_0001', 29.99);

-- Identity-Sequenzen über die manuell gesetzten Maxima hinaus weiterstellen,
-- damit spätere reguläre INSERTs keine Kollision erzeugen.
SELECT setval(pg_get_serial_sequence('platform_users', 'id'), (SELECT max(id) FROM platform_users));
SELECT setval(pg_get_serial_sequence('merchants',      'id'), (SELECT max(id) FROM merchants));
SELECT setval(pg_get_serial_sequence('products',       'id'), (SELECT max(id) FROM products));
SELECT setval(pg_get_serial_sequence('orders',         'id'), (SELECT max(id) FROM orders));
SELECT setval(pg_get_serial_sequence('order_items',    'id'), (SELECT max(id) FROM order_items));
SELECT setval(pg_get_serial_sequence('payments',       'id'), (SELECT max(id) FROM payments));
