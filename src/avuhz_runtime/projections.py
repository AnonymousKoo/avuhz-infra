"""Pure tenant-scoped projections for the reusable engagement system."""

def readiness(store, tenant_id, engagement_id=None):
    if not engagement_id:
        return {"readiness_state": "READY_TO_OPEN_ENGAGEMENT"}
    engagement = store.engagements.get(engagement_id)
    if not engagement or engagement.get("tenant_id") != tenant_id:
        return {"readiness_state": "HANDOFF_PENDING"}
    return {"readiness_state": "ENGAGEMENT_OPEN"}

def engagement_summary(store, tenant_id, engagement_id):
    engagement = store.engagements.get(engagement_id)
    if not engagement or engagement.get("tenant_id") != tenant_id:
        return None
    return {
        "engagement_reference": engagement_id,
        "tenant_id": tenant_id,
        "engagement_state": engagement["engagement_state"],
        "onboarding_readiness": readiness(store, tenant_id, engagement_id),
    }
