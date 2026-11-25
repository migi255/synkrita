"""Opt-in bounded reuse of pure artifact validation, never authorization or answers."""
from collections import OrderedDict
from contextvars import ContextVar
from copy import deepcopy

from synkrita.models import canonical, digest

_active = ContextVar('synkrita_artifact_validation_reuse', default=None)
VALIDATOR_REVISION = 'artifact-validation-reuse-v1'


class ValidationReuse:
    """Same cache available to conventional callers and Synkrita.

    Callers must freshly check visibility, checksums and dependencies before
    entering checked(). Context exit discards cached values. This cannot extend
    a capability's TTL, grant access, fetch current data or establish semantics.
    """
    def __init__(self, store, *, max_entries=4, max_bytes=2097152):
        if type(max_entries) is not int or not 1 <= max_entries <= 16:
            raise ValueError('Invalid validation entry budget')
        if type(max_bytes) is not int or not 1 <= max_bytes <= 8388608:
            raise ValueError('Invalid validation byte budget')
        self.store, self.max_entries, self.max_bytes = store, max_entries, max_bytes
        self._items, self._bytes = OrderedDict(), 0
        self.metrics = {'validation_attempts': 0, 'hits': 0, 'evictions': 0, 'uncacheable': 0}

    def __enter__(self):
        if hasattr(self, '_token'):
            raise ValueError('Validation context is already active')
        self._token = _active.set(self)
        return self

    def __exit__(self, *args):
        _active.reset(self._token)
        del self._token
        self._items.clear()
        self._bytes = 0

    def checked(self, profile, artifact, loader):
        # Full artifact digest includes source/view, invocation, raw bytes,
        # declaration, identity evidence, timestamps and dependency metadata.
        key = (VALIDATOR_REVISION, profile, digest(artifact))
        if key in self._items:
            self.metrics['hits'] += 1
            value, size = self._items.pop(key)
            self._items[key] = (value, size)
            return deepcopy(value)
        self.metrics['validation_attempts'] += 1
        value = loader()  # Exceptions are never retained as successful proof.
        size = len(canonical(value).encode())
        if size > self.max_bytes:
            self.metrics['uncacheable'] += 1
            return value
        while self._items and (len(self._items) >= self.max_entries or self._bytes + size > self.max_bytes):
            _, (_, removed) = self._items.popitem(last=False)
            self._bytes -= removed
            self.metrics['evictions'] += 1
        self._items[key] = (deepcopy(value), size)
        self._bytes += size
        return value


def checked_artifact(store, profile, artifact, loader):
    cache = _active.get()
    if cache is None or cache.store is not store:
        return loader()
    return cache.checked(profile, artifact, loader)
