-- DEVELOPMENT DATA migration role-binding fragment v1.
-- Remote execution is unauthorized by default.
-- This fragment is not standalone SQL. The v2 validator requires it to be inserted
-- exactly once immediately after the leading BEGIN of the exact bound canonical
-- initial migration so the entire schema migration executes under the dedicated
-- non-login migration identity and the role change expires with that transaction.
set local role avuhz_data_migration_service_dev;
