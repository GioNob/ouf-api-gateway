"""Supervised existing lease authority; never creates authority or starts workloads."""


def supervise(coordinator, check_configuration, poll_seconds, stop, *, log=print):
    """Use the existing common lock/journal for startup, every refresh and stop.

    Stopping seals QUIESCED with leaseAuthorized=false. Restart therefore needs
    a separate approved reauthorization; this supervisor never re-arms its journal.
    """
    flows = coordinator.configuration['providerFlows']
    if type(poll_seconds) is not int or not 1 <= poll_seconds <= 300 or not flows \
            or any(type(f['leaseSeconds']) is not int or poll_seconds * 2 > f['leaseSeconds'] for f in flows):
        raise ValueError('bounded poll interval within the lease ceiling required')
    try:
        check_configuration()
        if not stop.is_set():
            coordinator.fresh_start()
            log('SEMANTIC_COORDINATED_START=PASS OLD_SETS_REVOKED=true FRESH_DNS=true START_AUTHORIZED=false', flush=True)
            while not stop.wait(poll_seconds):
                check_configuration()
                coordinator.refresh()
                log('SEMANTIC_COORDINATED_CYCLE=PASS FRESH_DNS=true COMMON_LOCK=true', flush=True)
    finally:
        # Ownership and journal checks remain mandatory even after a failed
        # refresh/configuration check. Failure propagates; never print STOP=PASS
        # when revocation cannot be proven. Foreign structures are preserved.
        coordinator.quiesce()
        log('SEMANTIC_COORDINATED_STOP=PASS SETS_REVOKED=true REAUTHORIZATION_REQUIRED=true', flush=True)
