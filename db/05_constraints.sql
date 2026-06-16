-- =============================================================================
-- 05_constraints.sql  —  I5 (optional): Integritäts-Constraints + append-only
-- -----------------------------------------------------------------------------
-- Defense-in-Depth jenseits von Grants/RLS: harte DB-seitige Invarianten, die
-- auch dann greifen, wenn eine höhere Schicht versagt.
--   * audit_log strikt append-only (Trigger blockiert UPDATE/DELETE) → W4.
--   * Wertebereichs-CHECKs gegen unsinnige/feindliche Werte (z. B. negative
--     Beträge, ungültiger Bestellstatus) → härtet W3/W5 zusätzlich ab.
--
-- Laden als Eigentümer/Superuser:  psql -f 05_constraints.sql
-- =============================================================================

-- -----------------------------------------------------------------------------
-- audit_log: append-only erzwingen (selbst für Owner/Admin).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.audit_log_append_only()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% not allowed)', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_log_append_only ON audit_log;
CREATE TRIGGER trg_audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION app.audit_log_append_only();

-- -----------------------------------------------------------------------------
-- Wertebereiche / Statuswerte. ADD CONSTRAINT IF NOT EXISTS gibt es nicht →
-- defensiv erst droppen, dann anlegen (idempotent).
-- -----------------------------------------------------------------------------
ALTER TABLE products    DROP CONSTRAINT IF EXISTS chk_products_price_nonneg;
ALTER TABLE products    ADD  CONSTRAINT chk_products_price_nonneg CHECK (price >= 0);

ALTER TABLE products    DROP CONSTRAINT IF EXISTS chk_products_cost_nonneg;
ALTER TABLE products    ADD  CONSTRAINT chk_products_cost_nonneg
    CHECK (internal_cost IS NULL OR internal_cost >= 0);

ALTER TABLE orders      DROP CONSTRAINT IF EXISTS chk_orders_total_nonneg;
ALTER TABLE orders      ADD  CONSTRAINT chk_orders_total_nonneg CHECK (total >= 0);

ALTER TABLE orders      DROP CONSTRAINT IF EXISTS chk_orders_status;
ALTER TABLE orders      ADD  CONSTRAINT chk_orders_status
    CHECK (status IN ('placed', 'paid', 'shipped', 'delivered', 'cancelled', 'refunded'));

ALTER TABLE order_items DROP CONSTRAINT IF EXISTS chk_order_items_qty_pos;
ALTER TABLE order_items ADD  CONSTRAINT chk_order_items_qty_pos CHECK (qty > 0);

ALTER TABLE order_items DROP CONSTRAINT IF EXISTS chk_order_items_price_nonneg;
ALTER TABLE order_items ADD  CONSTRAINT chk_order_items_price_nonneg CHECK (price >= 0);

ALTER TABLE payments    DROP CONSTRAINT IF EXISTS chk_payments_amount_nonneg;
ALTER TABLE payments    ADD  CONSTRAINT chk_payments_amount_nonneg CHECK (amount >= 0);
