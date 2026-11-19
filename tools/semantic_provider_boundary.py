"""Bound the existing Semantic provider request grammar; no network or deployment I/O.

Installation bindings supply destinations. Candidate IRIs identify semantic data;
they never become a destination URL. This validator must run at the technical
southbound adapter before forwarding the admitted request to its registered endpoint.
"""
import re
from urllib.parse import parse_qsl, urlsplit


class ProviderRequestDenied(ValueError):
    pass


PREFIX = ('PREFIX owl: <http://www.w3.org/2002/07/owl#>\n'
          'PREFIX skos: <http://www.w3.org/2004/02/skos/core#>\n'
          'PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n')
PATTERNS = {
    'CLASS': '?resource a owl:Class .',
    'PROPERTY': 'VALUES ?kind { owl:ObjectProperty owl:DatatypeProperty } ?resource a ?kind .',
    'RELATIONSHIP': '?resource a owl:ObjectProperty .',
    'CONCEPT': '?resource a skos:Concept .',
    'VOCABULARY': '?resource a skos:ConceptScheme .',
    'ONTOLOGY': '?resource a owl:Ontology .',
}
HEAD = 'SELECT DISTINCT ?resource ?label WHERE { '
MIDDLE = ' OPTIONAL { ?resource rdfs:label|skos:prefLabel ?label } FILTER(CONTAINS(LCASE(STR(COALESCE(?label,?resource))),LCASE("'
TAIL = '"))) } ORDER BY ?resource LIMIT 50'
LITERAL = re.compile(r'(?:[^"\\\x00-\x1f]|\\[\\"])*\Z')


def _form(body, max_bytes, fields):
    if type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
        raise ProviderRequestDenied('REQUEST_LIMIT_INVALID')
    if not isinstance(body, bytes) or len(body) > max_bytes:
        raise ProviderRequestDenied('REQUEST_TOO_LARGE')
    try:
        text = body.decode('utf-8', errors='strict')
        if re.search(r'%(?![0-9A-Fa-f]{2})', text):
            raise ValueError()
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True,
                          encoding='utf-8', errors='strict', max_num_fields=len(fields))
    except (ValueError, UnicodeError):
        raise ProviderRequestDenied('REQUEST_ENCODING_INVALID') from None
    if len(pairs) != len(fields) or {k for k, _ in pairs} != set(fields):
        raise ProviderRequestDenied('REQUEST_FIELDS_INVALID')
    return dict(pairs)


def validate_search_form(body, *, max_bytes, max_intent_chars):
    if type(max_intent_chars) is not int or not 1 <= max_intent_chars <= 2000:
        raise ProviderRequestDenied('INTENT_LIMIT_INVALID')
    form = _form(body, max_bytes, ('query', 'format'))
    if form['format'] != 'application/sparql-results+json':
        raise ProviderRequestDenied('RESPONSE_FORMAT_INVALID')
    query = form['query']
    for artifact_type, pattern in PATTERNS.items():
        start = PREFIX + HEAD + pattern + MIDDLE
        if query.startswith(start) and query.endswith(TAIL):
            literal = query[len(start):-len(TAIL)]
            if not LITERAL.fullmatch(literal):
                break
            # Only backslash and quote escapes are admitted by the owner's grammar.
            intent = re.sub(r'\\([\\"])', r'\1', literal)
            if not intent.strip() or len(intent) > max_intent_chars:
                raise ProviderRequestDenied('INTENT_INVALID')
            return {'artifactType': artifact_type, 'query': query}
    raise ProviderRequestDenied('SEARCH_GRAMMAR_REJECTED')


def validate_fetch_form(body, *, max_bytes, namespace_prefixes):
    form = _form(body, max_bytes, ('uri',))
    uri = form['uri']
    if not isinstance(namespace_prefixes, (list, tuple)) or not namespace_prefixes:
        raise ProviderRequestDenied('NAMESPACE_BINDING_REQUIRED')
    for prefix in namespace_prefixes:
        _semantic_iri(prefix)
        if not prefix.endswith(('/', '#')):
            raise ProviderRequestDenied('NAMESPACE_BOUNDARY_REQUIRED')
    _semantic_iri(uri)
    if not any(uri.startswith(prefix) and len(uri) > len(prefix) for prefix in namespace_prefixes):
        raise ProviderRequestDenied('CANDIDATE_NAMESPACE_REJECTED')
    # Returned value is data for a bounded query at the registered provider.
    # Do not pass it to an HTTP client, Jena network resolver or redirect resolver.
    return {'canonicalUri': uri}


def _semantic_iri(value):
    if not isinstance(value, str) or len(value) > 2048 or re.search(r'[\x00-\x20<>"{}|\\^`]', value):
        raise ProviderRequestDenied('SEMANTIC_IRI_INVALID')
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ProviderRequestDenied('SEMANTIC_IRI_INVALID') from None
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or port == 0:
        raise ProviderRequestDenied('SEMANTIC_IRI_INVALID')
    if re.search(r'%(?![0-9A-Fa-f]{2})', value):
        raise ProviderRequestDenied('SEMANTIC_IRI_INVALID')


def validate_provider_endpoint(value):
    """Validate a trusted installation URL, without resolving it or claiming egress readiness."""
    _semantic_iri(value)
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or parsed.fragment or not parsed.path or parsed.path == '/':
        raise ProviderRequestDenied('PROVIDER_ENDPOINT_INVALID')
    return value
