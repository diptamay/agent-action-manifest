"""Binding helpers for a trusted, read-only transaction-status adapter.

These helpers do not query a transaction store, authenticate its response or make an
absent operation final. The adapter must supply terminal, causally correlated evidence.
"""
from check_containment import manifest_digest, digest, parse_time

RECONCILIATION_BINDINGS = (
    'execution_id', 'manifest_id', 'manifest_digest', 'request_digest',
    'idempotency_key', 'action_id', 'profile_digest', 'effect_target_digest',
)


def reconciliation_context(execution: dict, manifest: dict) -> dict:
    if execution['manifest_id'] != manifest['manifest_id'] or execution['manifest_digest'] != manifest_digest(manifest):
        raise ValueError('Execution and Manifest do not match')
    return {
        'execution_id': execution['execution_id'], 'manifest_id': manifest['manifest_id'],
        'manifest_digest': execution['manifest_digest'], 'request_digest': manifest['request_digest'],
        'idempotency_key': execution['idempotency_key'], 'action_id': manifest['action_target']['action_id'],
        'profile_digest': manifest['profile_ref']['profile_digest'],
        'effect_target_digest': digest(manifest['action_target']['effect_target']),
    }


def make_reconciliation_evidence(execution: dict, manifest: dict, disposition: str,
                                 observed_at: str, *, final: bool, source: str,
                                 source_version: str, evidence_ref: str,
                                 transaction_ref: str) -> dict:
    """Call AFTER a read-only lookup of this attempt's transaction/idempotency status.

    COMMITTED/NOT_COMMITTED require final=True and terminal downstream evidence.
    UNKNOWN is non-final. NOT_COMMITTED means this exact attempt cannot commit later,
    not merely 'not visible yet'; it never means 'not attempted'. A transaction_ref can
    identify a terminal transaction, cancellation/fence receipt, or idempotency record.
    """
    if disposition not in ('COMMITTED', 'NOT_COMMITTED', 'UNKNOWN'):
        raise ValueError('unknown reconciliation disposition')
    if type(final) is not bool or final != (disposition != 'UNKNOWN'):
        raise ValueError('only definitive transaction dispositions may be final')
    parse_time(observed_at)
    if any(not isinstance(x, str) or not x.strip() for x in (source, source_version, evidence_ref, transaction_ref)):
        raise ValueError('source, source_version, evidence_ref and transaction_ref must be non-empty')
    return {'record_type': 'ReconciliationEvidence', **reconciliation_context(execution, manifest),
            'disposition': disposition, 'final': final, 'observed_at': observed_at,
            'source': source, 'source_version': source_version, 'evidence_ref': evidence_ref,
            'transaction_ref': transaction_ref}
