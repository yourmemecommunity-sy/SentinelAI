# policy-engine

Planned responsibility: policy authoring, versioning, storage-backed evaluation with scoping by
user/team/org/application/provider/model/environment/time/network.

**Status: skeleton only.** In Phase 1 the evaluation library lives in
`services/security-engine/app/policies` (ADR-0003) so decisions are in-process and fail closed.
`/ready` returns 503 here so callers cannot mistake this skeleton for a working service.
