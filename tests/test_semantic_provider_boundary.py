import unittest
from urllib.parse import urlencode
from tools.semantic_provider_boundary import (
    HEAD, MIDDLE, PATTERNS, PREFIX, TAIL, ProviderRequestDenied,
    validate_search_form, validate_fetch_form, validate_provider_endpoint,
)


def owner_query(kind='CLASS', intent='teatro'):
    literal=intent.replace('\\','\\\\').replace('"','\\"').replace('\n',' ').replace('\r',' ')
    return PREFIX+HEAD+PATTERNS[kind]+MIDDLE+literal+TAIL


def search(query):return urlencode({'query':query,'format':'application/sparql-results+json'}).encode()


class ProviderBoundaryTest(unittest.TestCase):
    def validate(self,query):return validate_search_form(search(query),max_bytes=65536,max_intent_chars=2000)
    def test_all_six_owner_generated_read_patterns_are_admitted(self):
        for kind in PATTERNS:
            with self.subTest(kind=kind):
                query=owner_query(kind)
                self.assertEqual(self.validate(query),{'artifactType':kind,'query':query})
    def test_escaped_external_text_is_data_even_when_it_contains_query_keywords(self):
        for intent in ('Città e società', '" } SERVICE <https://evil.test> {', 'INSERT DELETE LOAD', 'a\\b'):
            with self.subTest(intent=intent):self.validate(owner_query(intent=intent))
    def test_arbitrary_sparql_update_service_unbounded_search_and_extra_statements_are_rejected(self):
        for query in ('SELECT * WHERE {?s ?p ?o}', 'INSERT DATA {<a> <b> <c>}',
                      owner_query()+'; DELETE WHERE {?s ?p ?o}',
                      owner_query().replace('LIMIT 50','LIMIT 500000'),
                      owner_query().replace('?resource a owl:Class .','SERVICE <https://evil.test> {?s ?p ?o}')):
            with self.subTest(query=query),self.assertRaises(ProviderRequestDenied):self.validate(query)
    def test_unescaped_closing_quote_and_controls_are_rejected(self):
        for intent in ('"))) } SERVICE <https://evil.test> { #', 'x\x00y', 'x\ty'):
            query=PREFIX+HEAD+PATTERNS['CLASS']+MIDDLE+intent+TAIL
            with self.subTest(intent=intent),self.assertRaises(ProviderRequestDenied):self.validate(query)
    def test_exact_form_fields_no_duplicate_query_no_endpoint_override(self):
        valid=search(owner_query())
        for body in (valid+b'&query=other',valid+b'&endpoint=https%3A%2F%2Fevil.test',b'query=%ZZ&format=x',b'query=%ff&format=x'):
            with self.subTest(body=body),self.assertRaises(ProviderRequestDenied):validate_search_form(body,max_bytes=65536,max_intent_chars=2000)
    def test_empty_or_long_intent_and_request_size_limits_are_enforced(self):
        for intent in ('',' '*4,'x'*2001):
            with self.subTest(intent=intent),self.assertRaises(ProviderRequestDenied):self.validate(owner_query(intent=intent))
        with self.assertRaises(ProviderRequestDenied):validate_search_form(search(owner_query()),max_bytes=5,max_intent_chars=2000)
    def test_candidate_identity_is_namespace_bound_without_network_dereference(self):
        uri='https://vocabulary.custom-domain.test/models/place#Theatre'
        body=urlencode({'uri':uri}).encode()
        self.assertEqual(validate_fetch_form(body,max_bytes=4096,namespace_prefixes=['https://vocabulary.custom-domain.test/models/place#']),{'canonicalUri':uri})
    def test_candidate_cannot_replace_namespace_or_use_a_sparql_escape(self):
        prefix='https://vocabulary.custom-domain.test/models/'
        for uri in ('https://evil.test/model','https://vocabulary.custom-domain.test/models-attacker/X',
                    prefix+'X> } SERVICE <https://evil.test> {', 'file:///etc/passwd',
                    'https://user:password@vocabulary.custom-domain.test/models/X',prefix+'X?url=https://evil.test'):
            with self.subTest(uri=uri),self.assertRaises(ProviderRequestDenied):validate_fetch_form(urlencode({'uri':uri}).encode(),max_bytes=4096,namespace_prefixes=[prefix])
    def test_trusted_endpoint_is_parameterized_without_a_lab_host_port_or_path(self):
        for endpoint in ('https://catalog.custom-domain.test:15443/query-endpoint','https://another.example/sparql'):
            self.assertEqual(validate_provider_endpoint(endpoint),endpoint)
        for endpoint in ('http://catalog.example/sparql','https://user:password@catalog.example/sparql','https://catalog.example/','https://catalog.example/sparql#x'):
            with self.subTest(endpoint=endpoint),self.assertRaises(ProviderRequestDenied):validate_provider_endpoint(endpoint)
    def test_namespace_allowlist_is_mandatory_and_has_a_resource_boundary(self):
        for prefixes in ([],['https://vocabulary.custom-domain.test/models']):
            with self.assertRaises(ProviderRequestDenied):validate_fetch_form(b'uri=https%3A%2F%2Fvocabulary.custom-domain.test%2Fmodels%2FX',max_bytes=4096,namespace_prefixes=prefixes)

if __name__=='__main__':unittest.main()
