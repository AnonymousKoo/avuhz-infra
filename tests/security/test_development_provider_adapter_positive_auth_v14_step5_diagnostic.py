from __future__ import annotations

import unittest

from scripts import development_provider_adapter_positive_auth_v14 as executor
from avuhz_engineering.authorization_plan import authorize_step, validate_approval, validate_plan, validate_progress


class DevelopmentProviderAdapterPositiveAuthV14Step5DiagnosticTests(unittest.TestCase):
    def test_exact_step5_authorization_chain(self) -> None:
        moment = "2026-10-08T09:09:45Z"
        plan = executor.prior._load(executor.PLAN_PATH)
        approval = executor.prior._load(executor.APPROVAL_PATH)
        progress = executor.prior._load(executor.EXECUTION_PROGRESS_PATH)
        resource = executor.prior._load(executor.RESOURCE_PATH)

        validate_plan(plan, executor.SCHEMA_ROOT)
        validate_progress(plan, progress, executor.SCHEMA_ROOT)
        validate_approval(plan, approval, executor.SCHEMA_ROOT, moment)
        executor._validate_boundary(plan, resource, progress)

        request = executor._request_for(plan, progress)
        assertion = executor._capability_assertion(moment, resource)
        authorized = authorize_step(
            plan,
            approval,
            progress,
            request,
            executor.SCHEMA_ROOT,
            moment,
            trusted_preflight_assertions=[assertion],
        )
        state = authorized["step_states"][4]
        self.assertEqual(state["authorization_state"], "AUTHORIZED")
        self.assertFalse(state["authorization_consumed"])


if __name__ == "__main__":
    unittest.main()
