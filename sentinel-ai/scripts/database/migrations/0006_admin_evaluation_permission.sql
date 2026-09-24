-- SentinelAI 0006: ADMIN must be a superset of SECURITY_ANALYST. It lacked evaluation:run, so an admin could not
-- delegate the analyst role (privilege-escalation guard: you may only grant permissions you hold).
UPDATE roles
   SET permissions = permissions || '["evaluation:run"]'::jsonb
 WHERE name = 'ADMIN' AND NOT permissions ? 'evaluation:run';
