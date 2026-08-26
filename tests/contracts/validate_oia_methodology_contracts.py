#!/usr/bin/env python3
"""Validate Phase 5B-M2 methodology planning contracts and fictional fixtures."""
import copy, json, sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURES = ROOT / "contracts/fixtures/v1/oia-methodology.cases.json"
PLAN_ID = "urn:avuhz:schema:contracts:domain:oia-assessment-plan:v1"
ITEM_ID = "urn:avuhz:schema:contracts:domain:oia-inspection-item:v1"
COMMON_ID = "urn:avuhz:schema:contracts:domain:oia-methodology-common:v1"
ENVELOPE_ID = "urn:avuhz:schema:contracts:commands:command-envelope:v1"
CAPABILITY_ID = "urn:avuhz:schema:contracts:identity:capability:v1"
EVENT_ID = "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
IDEMPOTENCY_ID = "urn:avuhz:schema:contracts:orchestration:idempotency-record:v1"
COMMANDS = {
    "CreateOIAAssessmentPlan": "create-oia-assessment-plan",
    "ReviseOIAAssessmentPlan": "revise-oia-assessment-plan",
    "ReviewOIAAssessmentPlan": "review-oia-assessment-plan",
    "ApproveOIAAssessmentPlan": "approve-oia-assessment-plan",
    "CreateOIAInspectionItem": "create-oia-inspection-item",
    "UpdateOIAInspectionItem": "update-oia-inspection-item",
    "MarkOIAInspectionItemBlocked": "mark-oia-inspection-item-blocked",
}
PAYLOAD_IDS = {name: f"urn:avuhz:schema:contracts:commands:{slug}-payload:v1" for name, slug in COMMANDS.items()}
LENSES = ["PROCESS", "PEOPLE_AND_ACCOUNTABILITY", "SYSTEMS_AND_CONFIGURATION", "DATA_AND_INFORMATION", "INTEGRATIONS_AND_HANDOFFS", "ACCESS_AND_CONTROL", "TIMING_AND_CAPACITY", "EXCEPTIONS_AND_RESILIENCE", "CUSTOMER_AND_FINANCIAL_OUTCOME", "MEASUREMENT_AND_VISIBILITY"]
ACTIONS = ["VIEW_CONFIGURATION", "VIEW_OPERATIONAL_STATE", "VIEW_LOGS", "VIEW_METRICS", "VIEW_ACCESS_CONFIGURATION", "VIEW_NETWORK_CONFIGURATION", "VIEW_SECURITY_CONFIGURATION", "VIEW_COMPLIANCE_EVIDENCE", "NON_DESTRUCTIVE_CONNECTIVITY_TEST", "NON_DESTRUCTIVE_PERMISSION_TEST"]
COVERAGE = ["NOT_STARTED", "IN_PROGRESS", "PARTIALLY_EVIDENCED", "SUFFICIENTLY_EVIDENCED", "BLOCKED", "NOT_APPLICABLE"]
INTERVENTIONS = ["CONFIGURATION_CHANGE", "PROCESS_CHANGE", "INTEGRATION_CHANGE", "ACCESS_OR_PERMISSION_CHANGE", "OBSERVABILITY_CHANGE", "SECURITY_HARDENING", "FURTHER_INVESTIGATION"]

def load(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)

def fail(message):
    print(f"oia-methodology-contract validation: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)

def pointer(document, fragment):
    current = document
    for part in ([] if not fragment else fragment[1:].split("/")):
        current = current[part.replace("~1", "/").replace("~0", "~")]
    return current

def expand(value, document, schemas):
    if isinstance(value, dict):
        if "$ref" in value:
            reference = value["$ref"]
            target_document = document if reference.startswith("#") else schemas[reference.partition("#")[0]]
            target = pointer(target_document, reference.partition("#")[2])
            return {**expand(copy.deepcopy(target), target_document, schemas), **{key: expand(child, document, schemas) for key, child in value.items() if key != "$ref"}}
        return {key: expand(child, document, schemas) for key, child in value.items()}
    if isinstance(value, list):
        return [expand(child, document, schemas) for child in value]
    return value

def iter_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                yield child
            yield from iter_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_refs(child)

def valid(schema_id, value, schemas):
    schema = expand(schemas[schema_id], schemas[schema_id], schemas)
    return not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value))

def payloads(plans, items):
    plan = plans[0]
    item = items[0]
    blocked = items[1]
    plan_content = {key: copy.deepcopy(plan[key]) for key in ("methodology_reference", "vertical_template_reference", "objectives", "process_areas", "completion_criteria", "limitations")}
    create_plan = {key: plan[key] for key in ("oia_assessment_plan_id", "engagement_id", "oia_assessment_id", "diagnostic_scope_id", "diagnostic_scope_version", "canonical_scope_digest")}
    create_plan.update(plan_content)
    create_item = {key: copy.deepcopy(item[key]) for key in ("oia_inspection_item_id", "engagement_id", "oia_assessment_id", "oia_assessment_plan_id", "plan_version", "objective_id", "process_area_id", "what_to_inspect", "why_it_matters", "inspection_lenses", "planned_target_action", "expected_evidence", "sampling_strategy", "required", "materiality", "limitations", "assessor_notes")}
    update_item = {key: copy.deepcopy(item[key]) for key in ("oia_inspection_item_id", "coverage_state", "sufficiency_evaluation", "limitations", "stop_reason", "stop_rationale", "intervention_class", "linked_evidence_ids", "assessor_notes")}
    return {
        "CreateOIAAssessmentPlan": create_plan,
        "ReviseOIAAssessmentPlan": {"oia_assessment_plan_id": plan["oia_assessment_plan_id"], "current_plan_version": 1, "replacement_plan_version": 2, **plan_content},
        "ReviewOIAAssessmentPlan": {"oia_assessment_plan_id": plan["oia_assessment_plan_id"], "plan_version": 1},
        "ApproveOIAAssessmentPlan": {"oia_assessment_plan_id": plan["oia_assessment_plan_id"], "plan_version": 1},
        "CreateOIAInspectionItem": create_item,
        "UpdateOIAInspectionItem": update_item,
        "MarkOIAInspectionItemBlocked": {key: copy.deepcopy(blocked[key]) for key in ("oia_inspection_item_id", "blocked_reason", "blocked_explanation", "limitations")},
    }

def main():
    paths = sorted(SCHEMA_ROOT.rglob("*.schema.json"))
    schemas = {load(path)["$id"]: load(path) for path in paths}
    if len(schemas) != len(paths):
        fail("schema IDs must be present and unique")
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
        for reference in iter_refs(schema):
            try:
                target = schema if reference.startswith("#") else schemas[reference.partition("#")[0]]
                pointer(target, reference.partition("#")[2])
            except (KeyError, TypeError):
                fail(f"unresolved reference: {reference}")
    for schema_id in (PLAN_ID, ITEM_ID, COMMON_ID, *PAYLOAD_IDS.values()):
        if schema_id not in schemas:
            fail(f"missing schema: {schema_id}")
    fixtures = load(FIXTURES)
    plans = [case["value"] for case in fixtures["plans"]]
    items = [case["value"] for case in fixtures["inspection_items"]]
    for case in fixtures["plans"]:
        if not valid(PLAN_ID, case["value"], schemas):
            fail(f"plan fixture rejected: {case['name']}")
    for case in fixtures["inspection_items"]:
        if not valid(ITEM_ID, case["value"], schemas):
            fail(f"inspection fixture rejected: {case['name']}")
    if "vertical_template_reference" in plans[2]:
        fail("universal-methodology-only plan fixture is not represented")
    for plan, item in zip(plans, items):
        if (plan["tenant_id"], plan["engagement_id"], plan["oia_assessment_id"], plan["oia_assessment_plan_id"], plan["plan_version"]) != (item["tenant_id"], item["engagement_id"], item["oia_assessment_id"], item["oia_assessment_plan_id"], item["plan_version"]):
            fail("plan/item tenant and version correlation fixture drifted")
    common = schemas[COMMON_ID]["$defs"]
    if common["inspectionLens"]["enum"] != LENSES or common["coverageState"]["enum"] != COVERAGE or common["interventionClass"]["enum"] != INTERVENTIONS:
        fail("frozen methodology vocabulary drifted")
    phase5a_actions = schemas["urn:avuhz:schema:contracts:domain:assessment-access-grant:v1"]["$defs"]["permittedDiagnosticAction"]["enum"]
    if common["diagnosticAction"].get("$ref") != "urn:avuhz:schema:contracts:domain:assessment-access-grant:v1#/$defs/permittedDiagnosticAction" or phase5a_actions != ACTIONS:
        fail("Phase 5A diagnostic action vocabulary was not reused exactly")
    revision = copy.deepcopy(plans[0]); revision.update(plan_version=2, supersedes_plan_version=1, state="APPROVED", record_version=4, reviewed_by="human.reviewer-001", approved_by="human.approver-001", reviewed_at="2030-01-15T17:00:00Z", approved_at="2030-01-15T18:00:00Z", updated_at="2030-01-15T18:00:00Z")
    if not valid(PLAN_ID, revision, schemas):
        fail("approved immutable plan revision is not representable")
    negatives = []
    def bad(base, **changes):
        value = copy.deepcopy(base); value.update(changes); negatives.append(value)
    bad(items[0], inspection_lenses=["UNKNOWN_LENS"])
    bad(items[0], coverage_state="COMPLETE")
    bad(items[0], intervention_class="DEPLOY_SOFTWARE")
    bad(items[1], blocked_reason="WAITING")
    changed = copy.deepcopy(items[0]); changed["planned_target_action"]["diagnostic_action"] = "MODIFY_CONFIGURATION"; negatives.append(changed)
    for field in ("credentials", "access_authorized", "grant_active", "payment_verified", "agreement_valid", "scope_authorized", "target_authorized", "action_authorized", "provider_response", "raw_logs", "content_blob"):
        bad(plans[0], **{field: "synthetic-forbidden-value"})
    bad(plans[0], oia_assessment_plan_id="malformed")
    bad(plans[0], tenant_id="different-tenant")
    for value in negatives:
        schema_id = ITEM_ID if "oia_inspection_item_id" in value else PLAN_ID
        if valid(schema_id, value, schemas):
            fail("security negative unexpectedly passed")
    if items[1]["coverage_state"] != "BLOCKED" or items[1]["blocked_reason"] != "BLOCKED_BY_AUTHORITY" or items[1]["linked_evidence_ids"]:
        fail("authority-blocked representability fixture drifted")
    if items[2]["sufficiency_evaluation"]["state"] != "INSUFFICIENT" or items[2]["limitations"][0]["classification"] != "SYSTEM_UNAVAILABLE":
        fail("honest limitation fixture drifted")
    command_payloads = payloads(plans, items)
    for command, value in command_payloads.items():
        if not valid(PAYLOAD_IDS[command], value, schemas):
            fail(f"valid command payload rejected: {command}")
        if schemas[PAYLOAD_IDS[command]].get("additionalProperties") is not False:
            fail(f"command payload is not strict: {command}")
    envelope = schemas[ENVELOPE_ID]
    if not set(COMMANDS) <= set(envelope["$defs"]["commandType"]["enum"]):
        fail("command envelope vocabulary incomplete")
    if not {"OIA_ASSESSMENT_PLAN", "OIA_INSPECTION_ITEM"} <= set(envelope["$defs"]["subjectType"]["enum"]):
        fail("command subject vocabulary incomplete")
    human_plan_commands = {"ReviewOIAAssessmentPlan", "ApproveOIAAssessmentPlan"}
    human_boundary = any(set(rule.get("if", {}).get("properties", {}).get("command_type", {}).get("enum", [])) == human_plan_commands and rule.get("then", {}).get("properties", {}).get("caller_type", {}).get("const") == "HUMAN" for rule in envelope["$defs"]["envelopeCore"]["allOf"])
    if not human_boundary:
        fail("trusted-human plan review and approval boundary is not frozen")
    capabilities = schemas[CAPABILITY_ID]["enum"]
    if not {"oia:plan:write", "oia:plan:review", "oia:plan:approve", "oia:inspection:manage"} <= set(capabilities):
        fail("methodology capability vocabulary incomplete")
    events = schemas[EVENT_ID]["properties"]["event_type"]["enum"]
    required_events = {"oia.assessment_plan_created", "oia.assessment_plan_revised", "oia.assessment_plan_reviewed", "oia.assessment_plan_approved", "oia.inspection_item_created", "oia.inspection_item_blocked", "oia.inspection_item_progressed"}
    if not required_events <= set(events):
        fail("methodology event vocabulary incomplete")
    idempotent_commands = schemas[IDEMPOTENCY_ID]["properties"]["command_type"]["enum"]
    if not set(COMMANDS) <= set(idempotent_commands) or "idempotency_scope" in schemas[IDEMPOTENCY_ID]["properties"]:
        fail("command-scoped idempotency not preserved")
    forbidden_names = {"credentials", "access_authorized", "grant_active", "payment_verified", "agreement_valid", "scope_authorized", "target_authorized", "action_authorized", "payload", "raw", "data", "provider_response", "content_blob"}
    for schema_id in (PLAN_ID, ITEM_ID, COMMON_ID, *PAYLOAD_IDS.values()):
        def property_names(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "properties": yield from child.keys()
                    yield from property_names(child)
            elif isinstance(value, list):
                for child in value: yield from property_names(child)
        if forbidden_names & set(property_names(schemas[schema_id])):
            fail(f"forbidden storage or authority field in {schema_id}")
    print(f"oia-methodology-contract validation: PASS (3 plans, 3 inspection items, {len(negatives)} security negatives, 7 commands, all refs resolved)")

if __name__ == "__main__":
    main()
