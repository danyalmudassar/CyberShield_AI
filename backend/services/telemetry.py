"""Bounded, process-local operational signals; never accept arbitrary log fields."""
import json
import logging
import sys
import threading
from datetime import datetime, timezone

logger = logging.getLogger('cybershield.operations')
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)

BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)
_lock = threading.Lock()
_requests = {}


def event(name, *, request_id=None, scan_id=None, status=None, duration_seconds=None,
          route=None, method=None, error_type=None):
    fields = dict(event=name, timestamp=datetime.now(timezone.utc).isoformat())
    fields.update({key: value for key, value in locals().copy().items()
                   if key in ('request_id', 'scan_id', 'status', 'duration_seconds', 'route', 'method', 'error_type')
                   and value is not None})
    logger.info(json.dumps(fields, separators=(',', ':'), allow_nan=False))


def observe_request(route, method, status, duration):
    method = method if method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS') else 'OTHER'
    # Route is supplied only from the matched router template, never the raw URL.
    key = (route, method, str(status // 100) + 'xx')
    with _lock:
        value = _requests.setdefault(key, {'count': 0, 'duration_sum_seconds': 0.0,
                                           'duration_buckets': [0] * (len(BUCKETS) + 1)})
        value['count'] += 1
        value['duration_sum_seconds'] += duration
        for index, bound in enumerate(BUCKETS):
            if duration <= bound:
                value['duration_buckets'][index] += 1
        value['duration_buckets'][-1] += 1


def request_metrics():
    with _lock:
        return [{'route': route, 'method': method, 'status_class': status,
                 'count': values['count'], 'duration_sum_seconds': values['duration_sum_seconds'],
                 'duration_buckets': {str(bound): count for bound, count in
                                      zip((*BUCKETS, '+Inf'), values['duration_buckets'])}}
                for (route, method, status), values in sorted(_requests.items())]
