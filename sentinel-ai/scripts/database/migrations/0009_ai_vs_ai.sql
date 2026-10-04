-- 0009: "AI vs AI" - explainable decisions, the per-organization switch for the external LLM judge, red-team rounds.
-- Nothing here can hold prompt or response content: explanations carry detector names, scores, versions and a keyed
-- content HMAC; red-team rounds carry counts and examples that are synthetic and sanitized before they are stored.

-- ---------------------------------------------------------------- explanations
-- Why a decision was made (tier, detectors fired, classifier score, judge verdict WITHOUT its free-text reason, policy
-- rule, component versions, content HMAC). Written once with the event (the table stays append-only).
ALTER TABLE security_events ADD COLUMN explanation jsonb;
ALTER TABLE security_events ADD CONSTRAINT security_events_explanation_no_judge_reason
  CHECK (explanation IS NULL OR (explanation #> '{judge,reason}') IS NULL OR jsonb_typeof(explanation #> '{judge,reason}') = 'null');

-- ---------------------------------------------------------------- external judge switch
-- true: inputs the local classifier cannot decide may be sent (already sanitized) to the external LLM judge.
-- false: the judge is never called for this organization; the local classifier decides alone.
ALTER TABLE organizations ADD COLUMN external_judge boolean NOT NULL DEFAULT true;

-- ---------------------------------------------------------------- red team
CREATE TABLE red_team_rounds (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  round             integer NOT NULL CHECK (round >= 1),
  dataset_version   text NOT NULL CHECK (length(dataset_version) BETWEEN 1 AND 64),
  generator_model   text NOT NULL CHECK (length(generator_model) BETWEEN 1 AND 128),
  engine_version    text NOT NULL CHECK (length(engine_version) BETWEEN 1 AND 256),
  attacks           integer NOT NULL CHECK (attacks >= 0),
  blocked           integer NOT NULL CHECK (blocked >= 0),
  slipped           integer NOT NULL CHECK (slipped >= 0),
  per_category      jsonb NOT NULL,          -- {category: {attacks, blocked, slipped, by_tier: {...}}}
  examples          jsonb NOT NULL DEFAULT '[]'::jsonb,  -- synthetic, sanitized, truncated (see scripts/security/red_team.py)
  cost_usd          real NOT NULL DEFAULT 0 CHECK (cost_usd >= 0),
  ran_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, round),
  CHECK (blocked + slipped = attacks)
);
CREATE INDEX red_team_rounds_org_idx ON red_team_rounds (organization_id, round DESC);

ALTER TABLE red_team_rounds ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON red_team_rounds USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id());
-- Append-only evidence: rounds are recorded, never edited.
GRANT SELECT, INSERT ON red_team_rounds TO sentinel_app;
