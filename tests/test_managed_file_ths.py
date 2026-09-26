import unittest

from tools.materialize_managed_file_ths import materialize, CAP
from ops.apisix.deploy_managed_file_ths import select


class ManagedFileThsTest(unittest.TestCase):
    def runtime(self):
        return {'x-ouf-installation': {'installationId': 'lab', 'revision': 5},
                'routes': [{'id': 'trusted-human-managed-file-upload',
                            'uri': '/api/managed-sources/v1/files',
                            'x-ouf-policy': {'identity': 'OIDC', 'requiredScope': CAP,
                                             'allowedActorTypes': ['HUMAN']},
                            'x-ouf-capability': {'capabilityId': CAP},
                            'x-ouf-backend-binding': {'service': 'ouf-onboarding', 'port': 8080,
                                                      'path': '/api/managed-sources/v1/files'}}]}

    def test_picker_is_only_a_ui_route_bound_to_existing_upload(self):
        route = select(materialize(self.runtime()))
        self.assertEqual(route['uri'], '/trusted-human/managed-files/*')
        self.assertEqual(route['labels']['ouf-capability'], CAP)
        self.assertEqual(route['plugins']['proxy-control'], {'request_buffering': False})
        self.assertEqual(route['upstream']['nodes'], {'ouf-onboarding:8080': 1})

    def test_missing_or_changed_upload_binding_fails_closed(self):
        runtime = self.runtime()
        runtime['routes'].clear()
        with self.assertRaises(ValueError):
            materialize(runtime)
        runtime = self.runtime()
        runtime['routes'][0]['x-ouf-policy']['requiredScope'] = 'wrong'
        with self.assertRaises(ValueError):
            materialize(runtime)

    def test_installer_rejects_unbounded_or_different_route(self):
        doc = materialize(self.runtime())
        doc['routes'][0]['plugins']['proxy-control'] = {'request_buffering': True}
        with self.assertRaises(ValueError):
            select(doc)


if __name__ == '__main__':
    unittest.main()
