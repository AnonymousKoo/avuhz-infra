"""Pure non-authoritative Slice 1 projections from loaded in-memory records."""
def readiness(store,tenant_id,engagement_id=None):
 if not engagement_id:return {"readiness_state":"READY_TO_OPEN_ENGAGEMENT"}
 e=store.engagements.get(engagement_id)
 if not e or e["tenant_id"]!=tenant_id:return {"readiness_state":"HANDOFF_PENDING"}
 scopes=[s for s in store.scopes.values() if s["engagement_id"]==engagement_id and s["tenant_id"]==tenant_id]
 if not scopes:return {"readiness_state":"SCOPE_REQUIRED"}
 s=scopes[-1]
 if s["status"]=="APPROVED":return {"readiness_state":"SCOPE_APPROVED"}
 approvals=[a for a in store.approvals.values() if a.get("tenant_id")==tenant_id and a.get("subject_id")==s["diagnostic_scope_id"] and a.get("status")=="ACTIVE"]
 return {"readiness_state":"SCOPE_REVIEW_PENDING" if len(approvals)>=2 else "SCOPE_APPROVALS_REQUIRED"}
def engagement_summary(store,tenant_id,engagement_id):
 e=store.engagements.get(engagement_id)
 if not e or e["tenant_id"]!=tenant_id:return None
 return {"engagement_reference":engagement_id,"tenant_id":tenant_id,"engagement_state":e["engagement_state"],"onboarding_readiness":readiness(store,tenant_id,engagement_id)}
