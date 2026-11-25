"""Observed upstream requests, independent of planner operation counts."""
from collections import Counter
import time


class UpstreamMetrics:
    def __init__(self):
        self.methods = Counter()
        self.elapsed_ms = 0.0
        self.errors = 0

    def record(self, method):
        self.methods[method] += 1
        return time.perf_counter()

    def finish(self, start, failed=False):
        self.elapsed_ms += (time.perf_counter() - start) * 1000
        self.errors += int(failed)

    def snapshot(self):
        return {'requests': sum(self.methods.values()), 'methods': dict(self.methods),
                'elapsed_ms': round(self.elapsed_ms, 3), 'errors': self.errors}
