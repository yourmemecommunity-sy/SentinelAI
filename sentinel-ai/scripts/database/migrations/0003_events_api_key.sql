-- SentinelAI 0003: attribute events to the API key that made the request (no user for machine callers).
ALTER TABLE security_events ADD COLUMN api_key_id uuid;
CREATE INDEX security_events_api_key_idx ON security_events (organization_id, api_key_id);
