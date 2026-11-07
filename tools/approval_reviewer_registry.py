"""Profile-scoped native smart-review providers; builtin cannot be replaced by name."""
import logging
from agent.provider_registry import ProviderRegistry
from tools.approval_reviewer import ApprovalReviewer

_registry = ProviderRegistry(label='Approval reviewer', provider_cls=ApprovalReviewer,
                             logger=logging.getLogger(__name__), builtin_names=frozenset({'builtin'}))
_registry.export(globals())
