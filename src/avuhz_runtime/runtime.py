"""Validation then guards only; future handlers are intentionally absent."""
from .models import ValidationFailure
def prepare_and_guard_command(validator,pipeline,raw,context,snapshot,evaluated_at):
    result=validator.prepare(raw)
    return result if isinstance(result,ValidationFailure) else pipeline.evaluate(result.prepared,context,snapshot,evaluated_at)
