# Task: Implement Core Oracle Functionality
## Context
Addresses multiple oracle-related issues (H1-H5) that are all interconnected and require database-level changes to implement properly.

## Role
Database Security Engineer specializing in audit implementations and violation detection

## Deliverables
1. Implement audit trigger approach in PostgreSQL database for state diff detection
2. Create `app.audit_writes` table with triggers on core tables (orders, merchants, platform_users, products, payments)
3. Implement real database state querying in state_diff.py with proper violation detection logic
4. Add tenant-aware canary detection with full token parsing including numeric sentinels
5. Implement proper confidence interval calculations using Wilson score
6. Add success/failure detection and trace-id filtering capabilities to DB log analysis
7. Ensure all oracle components work together for complete violation detection pipeline

## Files to Touch
- db/07_canary.sql (audit table creation)
- oracle/state_diff.py (state difference implementation)
- oracle/canary.py (canary detection enhancement)
- oracle/db_log.py (log analysis enhancement)
- oracle/correlate.py (confidence interval correction)
- analysis/stats.py (Wilson score implementation reference)