# Trusted human authority

Approval authority is resolved server-side into TrustedExecutionContext, not read from a command payload. Approval contexts require caller type HUMAN, a stable opaque human principal reference, an organization reference, tenant binding, and one trusted Slice 1 authority role: CLIENT_DECISION_AUTHORITY or SEKINFRA_ENGAGEMENT_AUTHORITY.

The approval-specific guard rejects workloads, missing attribution, missing tenant binding, unsupported roles, and requested-role mismatch. A future identity-provider adapter implements TrustedIdentityResolver; it must establish these facts before command handling. n8n and other workloads cannot create human approvals from JSON claims.
