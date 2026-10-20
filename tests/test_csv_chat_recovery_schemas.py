"""Closed schemas for durable CSV discovery; no target/runtime actions."""
import copy
import json
import unittest
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]

def envelope(capability, arguments):
    return {
        "GatewayBindingRef": "capability://" + capability,
        "CapabilityID": capability, "Owner": "onboarding", "OperationClass": "READ",
        "Arguments": arguments,
        "Identity": {"ServicePrincipalID": "mcp-fixture", "PrincipalID": "user-fixture",
                     "TenantID": "tenant-fixture", "ActorType": "HUMAN",
                     "AuthenticationContextRef": "fixture"},
        "AuthorizationDecisionRef": "fixture-decision", "CorrelationID": "fixture-correlation",
        "IdempotencyKey": "fixture-read", "AttemptID": "11111111-1111-4111-8111-111111111111",
        "RequestHash": "a"*64, "MaxResultBytes": 65536,
    }

class CsvRecoverySchemasTest(unittest.TestCase):
    def test_owned_asset_page_and_exact_preview_remain_disjoint(self):
        schema = json.loads((ROOT/"schemas/mcp-gateway-managed-file-dispatch-v1.json").read_text())
        validator = Draft202012Validator(schema)
        cap = "ouf.managed-source.preview"
        cursor = "11111111-1111-4111-8111-111111111111"
        for args in [
            {"view":"ASSETS"}, {"view":"ASSETS","limit":1},
            {"view":"ASSETS","limit":50,"afterAssetId":cursor},
            {"assetId":cursor,"profileId":cursor}, {"assetId":cursor,"jobId":cursor},
        ]:
            self.assertTrue(validator.is_valid(envelope(cap,args)), args)
        for args in [
            {"view":"ASSETS","limit":0}, {"view":"ASSETS","limit":51},
            {"view":"ASSETS","limit":"2"}, {"view":"ASSETS","afterAssetId":"bad"},
            {"view":"ASSETS","afterAssetId":cursor.replace("1","A",1)},
            {"view":"ASSETS","assetId":cursor}, {"view":"ASSETS","tenantId":"other"},
            {"view":"ASSETS","subjectId":"other"}, {"view":"OTHER"},
        ]:
            self.assertFalse(validator.is_valid(envelope(cap,args)), args)

    def test_latest_review_is_read_only_and_cannot_mix_version_or_authority(self):
        schema = json.loads((ROOT/"schemas/mcp-gateway-onboarding-review-read-dispatch-v1.json").read_text())
        validator = Draft202012Validator(schema)
        cap = "ouf.managed-source.onboarding.read"
        version = "11111111-1111-4111-8111-111111111111"
        for args in [{"sourceId":"source-fixture","view":"LATEST"},
                     {"sourceId":"source-fixture","onboardingVersionId":version}]:
            good = envelope(cap,args)
            self.assertTrue(validator.is_valid(good), args)
            for field,value in [("Owner","other"),("OperationClass","COMMAND"),("CapabilityID","ouf.onboarding.configuration.write")]:
                bad = copy.deepcopy(good); bad[field] = value
                self.assertFalse(validator.is_valid(bad))
        for args in [
            {"sourceId":"source-fixture","view":"LATEST","onboardingVersionId":version},
            {"sourceId":"source-fixture","view":"LATEST","approvedBy":"agent"},
            {"sourceId":"source-fixture","view":"LATEST","tenantId":"other"},
            {"sourceId":"../escape","view":"LATEST"}, {"view":"LATEST"},
        ]:
            self.assertFalse(validator.is_valid(envelope(cap,args)), args)

if __name__ == "__main__":
    unittest.main()
