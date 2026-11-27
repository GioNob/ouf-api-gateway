#!/usr/bin/env python3
"""Read-only preflight helpers for the release-owned UDP search route."""
from ops.apisix.deploy_status_execute import Admin

ROUTE_ID='execute-urban-object-search'
ROUTE_URI='/internal/capabilities/v1/execute/urban.object.search'


class SearchAdmin(Admin):
    def check_public(self):
        super().check_public()
        probe=dict(GatewayBindingRef='capability://urban.object.search',
                   CapabilityID='urban.object.search',Owner='udp',OperationClass='SEARCH',
                   Arguments={'type':'ouf:Asset'},
                   Identity=dict(ServicePrincipalID='probe',PrincipalID='probe',TenantID='probe',
                                 ActorType='HUMAN',AuthenticationContextRef='1'),
                   AuthorizationDecisionRef='probe',CorrelationID='probe',
                   IdempotencyKey='probe',AttemptID='11111111-1111-4111-8111-111111111111',
                   RequestHash='44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
                   MaxResultBytes=262144)
        code,_=self.curl(ROUTE_URI,'POST',probe)
        if code!=401:raise RuntimeError(f'unauthenticated UDP search HTTP {code}')


def main():
    raise SystemExit('execute-urban-object-search is owned by the governed Gateway release')


if __name__ == '__main__':
    main()
