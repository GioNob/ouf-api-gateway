import shutil
from pathlib import Path
import pytest,yaml
from tools.compile_config import compile_config,ConfigError
ROOT=Path(__file__).resolve().parents[1]
def test_runtime_writes_are_workload_only_and_namespace_reads_preserve_uri():
    routes={r['id']:r for r in compile_config(ROOT/'ouf-config')['routes']}
    for name in ('r2b-lake-write','r2b-handoff-write'):
        r=routes[name]
        assert r['methods']==['POST']
        assert r['x-ouf-policy']['allowedServiceIdentities']==['ouf-ingestion-runtime']
        assert not r['x-ouf-capability']['toolEligible']
    for name in ('r2b-publication-resolution','r2b-object-read'):
        assert 'proxy-rewrite' not in routes[name]['plugins']
        assert routes[name]['uri'].endswith('/*')
def test_wildcard_cannot_rewrite_to_an_unbounded_backend(tmp_path):
    config=tmp_path/'config';shutil.copytree(ROOT/'ouf-config',config)
    path=config/'routes/northbound/r2b-object-read.yaml';value=yaml.safe_load(path.read_text());value['spec']['backendBinding']['path']='/api/internal/v1/handoffs';path.write_text(yaml.safe_dump(value))
    with pytest.raises(ConfigError,match='bounded namespace'):compile_config(config)
