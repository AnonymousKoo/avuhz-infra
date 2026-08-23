-- Forward-only, additive vocabulary extension for a recorded trusted human approval.
-- Existing lifecycle event meanings and legacy tables remain unchanged.

alter table public.avuhz_lifecycle_events
  drop constraint avuhz_lifecycle_events_event_type_check;

alter table public.avuhz_lifecycle_events
  add constraint avuhz_lifecycle_events_event_type_check
  check (event_type in (
    'engagement.handoff.accepted',
    'engagement.opened',
    'diagnostic_scope.submitted',
    'diagnostic_scope.approved',
    'diagnostic_scope.rejected',
    'human_approval.recorded'
  ));
