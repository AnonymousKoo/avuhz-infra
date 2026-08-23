"""Provider-neutral boundary for server-side trusted identity resolution."""
from typing import Protocol
from .guards import TrustedExecutionContext
class TrustedIdentityResolver(Protocol):
 def resolve(self, authenticated_identity: object) -> TrustedExecutionContext: ...
