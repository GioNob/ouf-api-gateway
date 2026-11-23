"""Exercise the release schema gate offline, including the incident of 23 November."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import mcp_dispatch_contract as contracts
from tools.apisix_request_schema import dispatch_validation, verify_dispatch_arguments


class SearchContractTest(unittest.TestCase):
    def test_predecessor_search_envelope_includes_every_manifest_type(self):
        path = Path(__file__).resolve().parents[1] / 'schemas/mcp-gateway-semantic-search-dispatch-v1.json'
        validation = dispatch_validation(json.loads(path.read_bytes()), 65536)
        resource = {'kind': 'routes', 'id': 'mcp-semantic-search',
                    'body': {'uri': contracts.EXECUTE_PATH + '/semantic/search',
                             'plugins': {'request-validation': validation}}}
        verify_dispatch_arguments([resource])
        args = validation['body_schema']['properties']['Arguments']
        args['properties']['type']['enum'].remove('DATATYPE')
        with self.assertRaisesRegex(ValueError, 'mcp-semantic-search: Arguments differ'):
            verify_dispatch_arguments([resource])

    def test_real_batch_manifest_takes_precedence_over_provisional_snapshot(self):
        provisional = json.loads(contracts.SEARCH_BATCH_CONTRACT.read_bytes())
        self.assertEqual(provisional['provenance']['kind'], 'contract-derived')
        published = copy.deepcopy(provisional)
        del published['provenance']
        published.update(publicationState='ACTIVE')
        manifest = {'capabilities': [published]}
        try:
            with patch.object(contracts, 'MANIFEST') as source:
                source.read_bytes.return_value = json.dumps(manifest).encode()
                contracts.capability_contracts.cache_clear()
                self.assertEqual(contracts.capability_contracts()[contracts.SEARCH_BATCH], published)
        finally:
            contracts.capability_contracts.cache_clear()
