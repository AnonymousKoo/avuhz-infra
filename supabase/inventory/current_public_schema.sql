


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE SCHEMA IF NOT EXISTS "public";


ALTER SCHEMA "public" OWNER TO "pg_database_owner";


COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE TYPE "public"."engagement_event_type" AS ENUM (
    'engagement_created',
    'status_advanced',
    'document_signed',
    'payment_received',
    'engagement_flagged',
    'credentials_provisioned'
);


ALTER TYPE "public"."engagement_event_type" OWNER TO "postgres";


CREATE TYPE "public"."engagement_status" AS ENUM (
    'intake',
    'booking_scheduled',
    'nda_sa_audit_signed',
    'payment_received',
    'credentials_provisioned',
    'oia_walkthrough_complete',
    'findings_delivered',
    'conversion_decision_pending',
    'nda_sa_ongoing_signed',
    'remainder_payment_received',
    'ongoing_service_active',
    'closed_lost',
    'enterprise_flagged'
);


ALTER TYPE "public"."engagement_status" OWNER TO "postgres";


CREATE TYPE "public"."engagement_urgency" AS ENUM (
    'urgent',
    'exploring'
);


ALTER TYPE "public"."engagement_urgency" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_engagements_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
  new.updated_at = now();
  return new;
end;
$$;


ALTER FUNCTION "public"."set_engagements_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
NEW.updated_at = now();
RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_updated_at"() OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."alerts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "lead_id" "uuid",
    "type" "text" NOT NULL,
    "severity" "text" DEFAULT 'warning'::"text",
    "resolved" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "source" "text",
    "title" "text",
    "description" "text",
    "metadata" "jsonb",
    "client_id" "uuid",
    "tenant_id" "uuid"
);


ALTER TABLE "public"."alerts" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."automation_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "lead_id" "uuid",
    "type" "text",
    "severity" "text",
    "title" "text",
    "message" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "client_id" "uuid",
    "tenant_id" "uuid"
);


ALTER TABLE "public"."automation_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."client_config" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "client_name" "text",
    "email_from" "text",
    "client_id" "text",
    "notification_email" "text",
    "booking_url" "text",
    "followedup_enabled" boolean DEFAULT true,
    "followup_delay_1" bigint DEFAULT '60'::bigint,
    "followup_delay_2" bigint DEFAULT '360'::bigint,
    "followedup_delay_3" bigint DEFAULT '1440'::bigint,
    "active" boolean DEFAULT true,
    "oia_form_url" "text",
    "stripe_payment_url" "text",
    "client_email" "text",
    "client_domain" "text",
    "cal_booking_url" "text",
    "resend_from_name" "text",
    "logo_url" "text",
    "brand_color" "text"
);


ALTER TABLE "public"."client_config" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."demo_assets" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "client_id" "uuid",
    "vertical" "text" NOT NULL,
    "demo_slug" "text" NOT NULL,
    "lead_loss" "jsonb",
    "compliance_gaps" "jsonb",
    "top_findings" "jsonb",
    "pipeline_sample" "jsonb",
    "vertical_terminology" "jsonb",
    "revenue_goal" numeric,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "tenant_id" "uuid"
);


ALTER TABLE "public"."demo_assets" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."engagement_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "tenant_id" "uuid" NOT NULL,
    "engagement_id" "uuid" NOT NULL,
    "event_type" "public"."engagement_event_type" NOT NULL,
    "event_data" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "idempotency_key" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."engagement_events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."engagements" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "tenant_id" "uuid" NOT NULL,
    "company_name" "text",
    "contact_name" "text",
    "contact_email" "text",
    "contact_phone" "text",
    "industry" "text",
    "problem_statement" "text",
    "urgency" "public"."engagement_urgency" NOT NULL,
    "status" "public"."engagement_status" DEFAULT 'intake'::"public"."engagement_status" NOT NULL,
    "enterprise_flag" boolean DEFAULT false NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."engagements" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."event_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "lead_id" "uuid",
    "event_type" "text",
    "metadata" "jsonb",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "client_id" "uuid",
    "tenant_id" "uuid"
);


ALTER TABLE "public"."event_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "tenant_id" "uuid" NOT NULL,
    "event_type" "text" NOT NULL,
    "aggregate_type" "text" NOT NULL,
    "aggregate_id" "uuid" NOT NULL,
    "payload" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "idempotency_key" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."incident_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "workflow_name" "text",
    "node_name" "text",
    "error_message" "text",
    "payload" "jsonb",
    "resolved" boolean DEFAULT false,
    "severity" "text",
    "status" "text" DEFAULT 'open'::"text",
    "metadata" "jsonb",
    "client_id" "uuid",
    "tenant_id" "uuid"
);


ALTER TABLE "public"."incident_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."infrastructure_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "source" "text" NOT NULL,
    "event_type" "text" NOT NULL,
    "severity" "text" NOT NULL,
    "hostname" "text",
    "service_name" "text",
    "message" "text",
    "metric_value" numeric,
    "threshold_value" numeric,
    "acknowledged" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "client_id" "uuid"
);


ALTER TABLE "public"."infrastructure_events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."oia_submissions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text",
    "email" "text",
    "business_type" "text",
    "submission_data" "jsonb",
    "submitted_at" timestamp with time zone DEFAULT "now"(),
    "reviewed" boolean DEFAULT false,
    "reviewed_at" timestamp with time zone,
    "notes" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "staff_count" "text",
    "average_loan_size" "text",
    "monthly_loan_value" "text",
    "lead_response_process" "text",
    "lost_leads_monthly" "text",
    "crm_system" "text",
    "followup_attempts" "text",
    "followup_manager" "text",
    "tools_list" "text",
    "tech_frustration" "text",
    "security_program" "text",
    "npi_storage" "text",
    "breach_response_plan" "text",
    "last_compliance_review" "text",
    "trid_tracking" "text",
    "monthly_inquiries" "text",
    "close_rate" "text",
    "turned_down_business" "text",
    "revenue_goal_12mo" "text",
    "upcoming_deadlines" "text",
    "deployment_contact" "text",
    "ideal_operation" "text",
    "submission_id" "text",
    "form_name" "text",
    "pdf_url" "text",
    "re_license_type" "text",
    "re_primary_side" "text",
    "re_monthly_volume" "text",
    "re_referral_partners" "text",
    "re_compliance_concern" "text",
    "re_eo_insurance" "text",
    "re_active" "text",
    "business_name" "text",
    "client_id" "uuid",
    "tenant_id" "uuid"
);


ALTER TABLE "public"."oia_submissions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."pipeline_stages" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "stage_order" integer NOT NULL,
    "timeout_hours" integer DEFAULT 24 NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."pipeline_stages" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."revenue_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "lead_id" "uuid",
    "type" "text" NOT NULL,
    "amount" numeric DEFAULT 0,
    "status" "text" DEFAULT 'pending'::"text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."revenue_events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."sekinfra" (
    "name" "text" NOT NULL,
    "email" "text" NOT NULL,
    "phone" "text",
    "business_type" "text",
    "source" "text",
    "status" "text",
    "payment_status" "text",
    "intake_status" boolean,
    "booking_status" "text",
    "last_email_sent" timestamp with time zone,
    "last_followup" timestamp with time zone,
    "payment_amount" numeric,
    "paid_not_booked" boolean,
    "needs_followup" boolean,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "followup_count" integer DEFAULT 0,
    "operational_state" "text" DEFAULT 'new_lead'::"text",
    "lifecycle_stage" "text" DEFAULT 'intake'::"text",
    "infrastructure_status" "text" DEFAULT 'unknown'::"text",
    "security_status" "text" DEFAULT 'unknown'::"text",
    "automation_status" "text" DEFAULT 'inactive'::"text",
    "oia_completed" boolean DEFAULT false,
    "deployment_started" boolean DEFAULT false,
    "dashboard_ready" boolean DEFAULT false,
    "go_live" boolean DEFAULT false,
    "next_followup" timestamp with time zone,
    "followup_status" "text" DEFAULT 'active'::"text",
    "welcome_email_sent" boolean DEFAULT false,
    "oia_email_sent" boolean DEFAULT false,
    "deployment_email_sent" boolean DEFAULT false,
    "dashboard_email_sent" boolean DEFAULT false,
    "go_live_email_sent" boolean DEFAULT false,
    "payment_received" boolean DEFAULT false,
    "booked_call" boolean DEFAULT false,
    "booking_date" timestamp with time zone,
    "total_incidents" integer DEFAULT 0,
    "uptime_percentage" numeric DEFAULT 100,
    "active_alerts" integer DEFAULT 0,
    "risk_level" "text" DEFAULT 'low'::"text",
    "oia_submitted" boolean DEFAULT false,
    "oia_submitted_at" timestamp with time zone,
    "business_name" "text",
    "employee_count" "text",
    "operational_pain" "text",
    "next_action" "text",
    "stage_entered_at" timestamp with time zone DEFAULT "now"(),
    "last_action" "text",
    "last_action_at" timestamp with time zone,
    "pipeline_stage" "text" DEFAULT 'intake_received'::"text",
    "booking_confirmed" boolean DEFAULT false,
    "is_test" boolean DEFAULT false,
    "call_completed_at" timestamp with time zone,
    "oia_sent_at" timestamp with time zone,
    "oia_returned_at" timestamp with time zone,
    "payment_received_at" timestamp with time zone,
    "agreement_signed_at" timestamp with time zone,
    "deployment_started_at" timestamp with time zone,
    "deployed_at" timestamp with time zone,
    "reengagement_date" timestamp with time zone,
    "oia_gap_count" integer,
    "oia_risk_level" "text",
    "oia_teaser_summary" "text",
    "oia_full_summary" "text",
    "oia_next_steps" "text",
    "oia_recommended_tier" "text",
    "stripe_payment_id" "text",
    "docuseal_contract_id" "text",
    "payment_date" timestamp with time zone,
    "re_active" "text",
    "re_license_type" "text",
    "re_monthly_volume" "text",
    "re_primary_side" "text",
    "re_transaction_management" "text",
    "re_client_communication" "text",
    "re_referral_partners" "text",
    "re_compliance_concern" "text",
    "re_eo_insurance" "text",
    "demo_slug" "text",
    "tenant_id" "uuid" DEFAULT "gen_random_uuid"(),
    "video_url" "text",
    "demo_url" "text"
);


ALTER TABLE "public"."sekinfra" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."sla_rules" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "client_id" "text" DEFAULT 'Sekinfra'::"text",
    "stage" "text" NOT NULL,
    "max_hours" integer NOT NULL,
    "severity" "text" DEFAULT 'high'::"text",
    "escalation_action" "text",
    "active" boolean DEFAULT true,
    "tenant_id" "uuid"
);


ALTER TABLE "public"."sla_rules" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."tenant_users" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "tenant_id" "uuid" NOT NULL,
    "auth_user_id" "uuid",
    "role" "text" DEFAULT 'broker'::"text" NOT NULL,
    "full_name" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."tenant_users" OWNER TO "postgres";


ALTER TABLE ONLY "public"."sekinfra"
    ADD CONSTRAINT "Sek Field_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."alerts"
    ADD CONSTRAINT "alerts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."automation_logs"
    ADD CONSTRAINT "automation_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."client_config"
    ADD CONSTRAINT "client_config_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."demo_assets"
    ADD CONSTRAINT "demo_assets_demo_slug_key" UNIQUE ("demo_slug");



ALTER TABLE ONLY "public"."demo_assets"
    ADD CONSTRAINT "demo_assets_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."engagement_events"
    ADD CONSTRAINT "engagement_events_idempotency_key_key" UNIQUE ("idempotency_key");



ALTER TABLE ONLY "public"."engagement_events"
    ADD CONSTRAINT "engagement_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."engagements"
    ADD CONSTRAINT "engagements_id_tenant_id_key" UNIQUE ("id", "tenant_id");



ALTER TABLE ONLY "public"."engagements"
    ADD CONSTRAINT "engagements_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."event_logs"
    ADD CONSTRAINT "event_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_idempotency_key_key" UNIQUE ("idempotency_key");



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."incident_logs"
    ADD CONSTRAINT "incident_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."infrastructure_events"
    ADD CONSTRAINT "infrastructure_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."oia_submissions"
    ADD CONSTRAINT "oia_submissions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."oia_submissions"
    ADD CONSTRAINT "oia_submissions_submission_id_key" UNIQUE ("submission_id");



ALTER TABLE ONLY "public"."pipeline_stages"
    ADD CONSTRAINT "pipeline_stages_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."revenue_events"
    ADD CONSTRAINT "revenue_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."sekinfra"
    ADD CONSTRAINT "sekinfra_email_unique" UNIQUE ("email");



ALTER TABLE ONLY "public"."sla_rules"
    ADD CONSTRAINT "sla_rules_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."tenant_users"
    ADD CONSTRAINT "tenant_users_pkey" PRIMARY KEY ("id");



CREATE INDEX "engagement_events_engagement_created_at_idx" ON "public"."engagement_events" USING "btree" ("engagement_id", "created_at" DESC);



CREATE INDEX "engagement_events_tenant_created_at_idx" ON "public"."engagement_events" USING "btree" ("tenant_id", "created_at" DESC);



CREATE INDEX "engagements_tenant_status_idx" ON "public"."engagements" USING "btree" ("tenant_id", "status");



CREATE INDEX "idx_demo_assets_tenant_id" ON "public"."demo_assets" USING "btree" ("tenant_id");



CREATE INDEX "idx_events_aggregate" ON "public"."events" USING "btree" ("aggregate_type", "aggregate_id");



CREATE INDEX "idx_events_tenant" ON "public"."events" USING "btree" ("tenant_id");



CREATE INDEX "idx_sekinfra_email" ON "public"."sekinfra" USING "btree" ("email");



CREATE INDEX "idx_sekinfra_followup" ON "public"."sekinfra" USING "btree" ("followup_status", "next_followup");



CREATE INDEX "idx_sekinfra_operational_state" ON "public"."sekinfra" USING "btree" ("operational_state");



CREATE INDEX "idx_sekinfra_tenant_id" ON "public"."sekinfra" USING "btree" ("tenant_id");



CREATE INDEX "idx_tenant_users_tenant_id" ON "public"."tenant_users" USING "btree" ("tenant_id");



CREATE OR REPLACE TRIGGER "engagements_set_updated_at" BEFORE UPDATE ON "public"."engagements" FOR EACH ROW EXECUTE FUNCTION "public"."set_engagements_updated_at"();



CREATE OR REPLACE TRIGGER "set_updated_at" BEFORE UPDATE ON "public"."sekinfra" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at"();



ALTER TABLE ONLY "public"."demo_assets"
    ADD CONSTRAINT "demo_assets_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."sekinfra"("id");



ALTER TABLE ONLY "public"."engagement_events"
    ADD CONSTRAINT "engagement_events_engagement_tenant_fkey" FOREIGN KEY ("engagement_id", "tenant_id") REFERENCES "public"."engagements"("id", "tenant_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "public"."client_config"("id");



ALTER TABLE ONLY "public"."tenant_users"
    ADD CONSTRAINT "tenant_users_auth_user_id_fkey" FOREIGN KEY ("auth_user_id") REFERENCES "auth"."users"("id");



CREATE POLICY "Allow authenticated inserts to automation_logs" ON "public"."automation_logs" FOR INSERT TO "authenticated" WITH CHECK (true);



CREATE POLICY "Allow authenticated reads from automation_logs" ON "public"."automation_logs" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "Allow service role insert" ON "public"."automation_logs" FOR INSERT TO "service_role" WITH CHECK (true);



CREATE POLICY "Allow service role insert automation logs" ON "public"."automation_logs" FOR INSERT TO "service_role" WITH CHECK (true);



CREATE POLICY "Allow service role read automation logs" ON "public"."automation_logs" FOR SELECT TO "service_role" USING (true);



CREATE POLICY "Allow service role select" ON "public"."automation_logs" FOR SELECT TO "service_role" USING (true);



CREATE POLICY "Allow service role to read sla_rules" ON "public"."sla_rules" FOR SELECT TO "service_role" USING (true);



ALTER TABLE "public"."alerts" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "anon_demo_assets_read" ON "public"."demo_assets" FOR SELECT TO "anon" USING (true);



CREATE POLICY "anon_demo_read_limited" ON "public"."sekinfra" FOR SELECT TO "anon" USING (("demo_slug" IS NOT NULL));



CREATE POLICY "authenticated_full_access" ON "public"."alerts" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."automation_logs" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."client_config" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."event_logs" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."events" TO "authenticated" USING (true);



CREATE POLICY "authenticated_full_access" ON "public"."incident_logs" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."infrastructure_events" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."oia_submissions" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."pipeline_stages" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."revenue_events" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."sekinfra" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_full_access" ON "public"."sla_rules" TO "authenticated" USING (true) WITH CHECK (true);



CREATE POLICY "authenticated_read_pipeline_stages" ON "public"."pipeline_stages" FOR SELECT TO "authenticated" USING (true);



ALTER TABLE "public"."automation_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."client_config" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."demo_assets" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."engagement_events" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "engagement_events_insert_own_tenant" ON "public"."engagement_events" FOR INSERT TO "authenticated" WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."tenant_users"
  WHERE (("tenant_users"."auth_user_id" = "auth"."uid"()) AND ("tenant_users"."tenant_id" = "engagement_events"."tenant_id")))));



CREATE POLICY "engagement_events_select_own_tenant" ON "public"."engagement_events" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."tenant_users"
  WHERE (("tenant_users"."auth_user_id" = "auth"."uid"()) AND ("tenant_users"."tenant_id" = "engagement_events"."tenant_id")))));



ALTER TABLE "public"."engagements" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "engagements_insert_own_tenant" ON "public"."engagements" FOR INSERT TO "authenticated" WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."tenant_users"
  WHERE (("tenant_users"."auth_user_id" = "auth"."uid"()) AND ("tenant_users"."tenant_id" = "engagements"."tenant_id")))));



CREATE POLICY "engagements_select_own_tenant" ON "public"."engagements" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."tenant_users"
  WHERE (("tenant_users"."auth_user_id" = "auth"."uid"()) AND ("tenant_users"."tenant_id" = "engagements"."tenant_id")))));



CREATE POLICY "engagements_update_own_tenant" ON "public"."engagements" FOR UPDATE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."tenant_users"
  WHERE (("tenant_users"."auth_user_id" = "auth"."uid"()) AND ("tenant_users"."tenant_id" = "engagements"."tenant_id"))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."tenant_users"
  WHERE (("tenant_users"."auth_user_id" = "auth"."uid"()) AND ("tenant_users"."tenant_id" = "engagements"."tenant_id")))));



ALTER TABLE "public"."event_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."incident_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."infrastructure_events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."oia_submissions" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."pipeline_stages" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."revenue_events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."sekinfra" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "service_role_all" ON "public"."alerts" TO "service_role" USING (true);



CREATE POLICY "service_role_all" ON "public"."events" TO "service_role" USING (true);



CREATE POLICY "service_role_all" ON "public"."pipeline_stages" TO "service_role" USING (true);



CREATE POLICY "service_role_all" ON "public"."revenue_events" TO "service_role" USING (true);



ALTER TABLE "public"."sla_rules" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."tenant_users" ENABLE ROW LEVEL SECURITY;


GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";



GRANT ALL ON TABLE "public"."alerts" TO "anon";
GRANT ALL ON TABLE "public"."alerts" TO "authenticated";
GRANT ALL ON TABLE "public"."alerts" TO "service_role";



GRANT ALL ON TABLE "public"."automation_logs" TO "anon";
GRANT ALL ON TABLE "public"."automation_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."automation_logs" TO "service_role";



GRANT ALL ON TABLE "public"."client_config" TO "anon";
GRANT ALL ON TABLE "public"."client_config" TO "authenticated";
GRANT ALL ON TABLE "public"."client_config" TO "service_role";



GRANT SELECT ON TABLE "public"."demo_assets" TO "anon";
GRANT SELECT ON TABLE "public"."demo_assets" TO "authenticated";



GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."engagement_events" TO "anon";
GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."engagement_events" TO "authenticated";
GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."engagement_events" TO "service_role";



GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."engagements" TO "anon";
GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."engagements" TO "authenticated";
GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."engagements" TO "service_role";



GRANT ALL ON TABLE "public"."event_logs" TO "anon";
GRANT ALL ON TABLE "public"."event_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."event_logs" TO "service_role";



GRANT ALL ON TABLE "public"."events" TO "anon";
GRANT ALL ON TABLE "public"."events" TO "authenticated";
GRANT ALL ON TABLE "public"."events" TO "service_role";



GRANT ALL ON TABLE "public"."incident_logs" TO "anon";
GRANT ALL ON TABLE "public"."incident_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."incident_logs" TO "service_role";



GRANT ALL ON TABLE "public"."infrastructure_events" TO "anon";
GRANT ALL ON TABLE "public"."infrastructure_events" TO "authenticated";
GRANT ALL ON TABLE "public"."infrastructure_events" TO "service_role";



GRANT ALL ON TABLE "public"."oia_submissions" TO "anon";
GRANT ALL ON TABLE "public"."oia_submissions" TO "authenticated";
GRANT ALL ON TABLE "public"."oia_submissions" TO "service_role";



GRANT ALL ON TABLE "public"."pipeline_stages" TO "anon";
GRANT ALL ON TABLE "public"."pipeline_stages" TO "authenticated";
GRANT ALL ON TABLE "public"."pipeline_stages" TO "service_role";



GRANT ALL ON TABLE "public"."revenue_events" TO "anon";
GRANT ALL ON TABLE "public"."revenue_events" TO "authenticated";
GRANT ALL ON TABLE "public"."revenue_events" TO "service_role";



GRANT ALL ON TABLE "public"."sekinfra" TO "anon";
GRANT ALL ON TABLE "public"."sekinfra" TO "authenticated";
GRANT ALL ON TABLE "public"."sekinfra" TO "service_role";



GRANT ALL ON TABLE "public"."sla_rules" TO "anon";
GRANT ALL ON TABLE "public"."sla_rules" TO "authenticated";
GRANT ALL ON TABLE "public"."sla_rules" TO "service_role";



GRANT ALL ON TABLE "public"."tenant_users" TO "anon";
GRANT ALL ON TABLE "public"."tenant_users" TO "authenticated";
GRANT ALL ON TABLE "public"."tenant_users" TO "service_role";



ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT UPDATE ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT UPDATE ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT UPDATE ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLES TO "service_role";







