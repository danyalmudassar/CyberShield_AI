"""Scope must survive a real spawn, independently of parent monkeypatches."""
import multiprocessing as mp

from agents.orchestrator import _stage_process_wrapper
from utils.target_policy import current_scope, scope_for_target


def _scope_probe():
    from utils.http_client import get
    from utils.target_policy import TargetPolicyError
    scope = current_scope()
    try:
        # A metadata literal cannot cause a DNS query even if scope propagation
        # regresses. Check the specific origin-policy error, not any exception.
        get('http://169.254.169.254/latest/meta-data')
    except TargetPolicyError as exc:
        error = str(exc)
    else:
        error = ''
    return scope, error


def test_original_scope_is_preserved_in_spawned_stage():
    scope = scope_for_target('http://example.com:8080', allow_private=True)
    ctx = mp.get_context('spawn')
    parent, child = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_stage_process_wrapper,
                          args=(child, _scope_probe, (), {}, None, scope))
    process.start()
    child.close()
    try:
        assert parent.poll(10), 'Stage returned no result'
        status, result = parent.recv()
        assert status == 'OK'
        assert result[0] == scope
        assert 'scan scope' in result[1]
        process.join(timeout=2)
        assert not process.is_alive()
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        parent.close()
