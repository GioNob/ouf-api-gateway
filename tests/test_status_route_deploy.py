import copy
import importlib.util
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('deploy',Path(__file__).resolve().parents[1]/'ops/apisix/deploy_status_execute.py')
deploy=importlib.util.module_from_spec(spec);spec.loader.exec_module(deploy)

class Admin:
    def __init__(self,fail=None):
        self.db={'first':{'id':'first','uri':'/old'}};self.original=copy.deepcopy(self.db);self.fail=fail;self.saved=None;self.changed=[]
    def save_snapshot(self,value):self.saved=copy.deepcopy(value)
    def check_public(self):
        if self.fail=='probe':raise RuntimeError('probe failure')
    def __call__(self,method,route_id,data=None):
        if method=='GET':return (200,{'value':copy.deepcopy(self.db[route_id])}) if route_id in self.db else (404,{})
        assert self.saved is not None
        self.changed.append((method,route_id))
        if method=='PUT':
            if self.fail=='put' and route_id=='second':return 500,{}
            self.db[route_id]=copy.deepcopy(data);return 200,{}
        self.db.pop(route_id,None);return 204,{}

@pytest.mark.parametrize('fail',['put','probe'])
def test_partial_deploy_restores_old_and_removes_new(fail):
    admin=Admin(fail)
    with pytest.raises(RuntimeError):deploy.apply_routes([{'id':'first','uri':'/new'},{'id':'second','uri':'/second'}],admin)
    assert admin.db==admin.original
    assert admin.saved=={'first':admin.original['first'],'second':None}

def test_success_keeps_snapshot_and_updated_routes():
    admin=Admin();routes=[{'id':'first','uri':'/new'},{'id':'second','uri':'/second'}]
    deploy.apply_routes(routes,admin)
    assert list(admin.db.values())==routes and admin.saved['first']['uri']=='/old'
