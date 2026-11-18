"""mongomock lags behind pymongo: newer pymongo passes a `sort=` kwarg to bulk
updates that mongomock doesn't accept. Drop it (we never use it) for tests only."""
import functools

import mongomock.collection as mc

for _name in ("add_update", "add_replace"):
    _orig = getattr(mc.BulkOperationBuilder, _name, None)
    if _orig:
        @functools.wraps(_orig)
        def _patched(self, *a, _orig=_orig, **kw):
            kw.pop("sort", None)
            return _orig(self, *a, **kw)
        setattr(mc.BulkOperationBuilder, _name, _patched)
