"""Check browser requests against APISIX documents generated entirely offline."""
import json
import os
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

import pytest

from ops.apisix.deploy_managed_file_ths import select, select_login
from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config
from tools.materialize_managed_file_ths import materialize as picker
from tools.materialize_onboarding_review import materialize as review
from tools.materialize_permission_proposals import materialize as permissions
from tools.materialize_resolution_ths import materialize as resolution

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "config/ths-page-route-contract-v1.json").read_text(encoding="utf-8"))


def browser_requests():
    for name, surface in CONTRACT["surfaces"].items():
        page = surface["page"]
        yield name, "GET", page
        for asset in surface["scripts"] + surface["stylesheets"]:
            yield name, "GET", urljoin(page, asset)
        for method, paths in surface["api"].items():
            for path in paths:
                yield name, method, urljoin(page, path)
    for method, paths in CONTRACT["oidc"].items():
        for path in paths:
            yield "oidc", method, path


@pytest.fixture(scope="module")
def routes():
    projection = json.loads((ROOT / "tests/fixtures/installation-projection-lab.json").read_text())
    runtime = apply_projection(compile_config(ROOT / "ouf-config"), projection)
    existing = permissions(runtime, "$ENV://OIDC_SECRET", "DELEGATION_KEY", "AUTHORIZATION_OWNER_KEY")
    workflows = review(existing, runtime, "DELEGATION_KEY", "ONBOARDING_OWNER_KEY")
    managed = picker(runtime)
    return [*workflows["routes"], select(managed), select_login(managed), *resolution(runtime, "$ENV://OIDC_SECRET")]


def covers(route, method, path):
    if "methods" in route and method not in route["methods"]:
        return False
    # These browser routes have no additional APISIX match conditions.
    conditions = ("vars", "host", "hosts", "remote_addr", "remote_addrs", "filter_func")
    if route.get("status") == 0 or any(route.get(key) for key in conditions):
        return False
    for pattern in route.get("uris", [route.get("uri", "")]):
        # A terminal wildcard must cover every value of the first dynamic segment.
        if pattern.endswith("*") and path.partition("{")[0].startswith(pattern[:-1]):
            return True
        if "{" not in path and pattern == path:
            return True
    return False


def test_contract_scope():
    assert CONTRACT["version"] == 1
    assert set(CONTRACT["surfaces"]) == {
        "authorization", "managed-files", "onboarding", "semantic", "resolution", "profile-recovery",
        "ingestion-run-recovery",
    }
    assert CONTRACT["oidc"]["GET"]


@pytest.mark.parametrize(
    "surface,method,path",
    [pytest.param(*row, id=" ".join(row)) for row in browser_requests()],
)
def test_browser_request_has_route(routes, surface, method, path):
    assert any(covers(route, method, path) for route in routes), (
        f"No materialized APISIX route for {surface}: {method} {path}"
    )


def test_exact_page_does_not_cover_a_sibling_script():
    page = "/trusted-human/authorization/"
    route = {"uris": [page, page + "permissions.js"], "methods": ["GET"]}
    assert covers(route, "GET", page + "permissions.js")
    assert not covers(route, "POST", page + "permissions.js")
    assert not covers(route, "GET", page + "session.js")


class PageAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.stylesheets = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        if tag == "link" and "stylesheet" in attrs.get("rel", "").lower().split():
            self.stylesheets.append(attrs["href"])


@pytest.mark.parametrize("surface", CONTRACT["surfaces"])
def test_assets_match_onboarding_html(surface):
    checkout = os.environ.get("OUF_ONBOARDING_CHECKOUT")
    if not checkout:
        pytest.skip("Set OUF_ONBOARDING_CHECKOUT to compare owner HTML")
    spec = CONTRACT["surfaces"][surface]
    assets = PageAssets()
    assets.feed((Path(checkout) / "src/main/resources/ths" / spec["html"]).read_text(encoding="utf-8"))
    assets.close()
    for actual, expected in ((assets.scripts, spec["scripts"]), (assets.stylesheets, spec["stylesheets"])):
        assert [urljoin(spec["page"], url) for url in actual] == [urljoin(spec["page"], url) for url in expected]
