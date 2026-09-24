-- SentinelAI 0007: file scans are auditable events.
ALTER TABLE security_events DROP CONSTRAINT security_events_event_type_check;
ALTER TABLE security_events ADD CONSTRAINT security_events_event_type_check
  CHECK (event_type IN ('scan','ai_request','ai_response','fail_closed','policy_change','auth','file_scan'));
