"""Factor repeated MCP union constraints for the APISIX JSON Schema engine.

MCP clients need complete object schemas in union branches. APISIX also checks
the closed parent object: repeating its properties inside every branch exposes
a validator incompatibility for an omitted optional discriminant. Remove only
identical constraints that the enclosing object already enforces. Unknown
properties stay denied by that parent; branch selectors and prohibitions stay.
"""
import copy


def project(schema):
    value=copy.deepcopy(schema)
    def visit(node):
        if isinstance(node,list):return [visit(item) for item in node]
        if not isinstance(node,dict):return node
        node={key:visit(item) for key,item in node.items()}
        properties=node.get('properties')
        if node.get('type')!='object' or node.get('additionalProperties') is not False \
                or not isinstance(properties,dict) or not isinstance(node.get('oneOf'),list):
            return node
        branches=[]
        for original in node['oneOf']:
            branch=copy.deepcopy(original)
            if not isinstance(branch,dict) or branch.get('type')!='object' \
                    or branch.get('additionalProperties') is not False \
                    or not isinstance(branch.get('properties'),dict) \
                    or set(branch['properties'])!=set(properties):
                branches.append(branch);continue
            # Parent and child both apply, so P AND (P AND B) == P AND B.
            # Keep every differing constraint, including nested unions.
            remaining={}
            for key,definition in branch['properties'].items():
                common=properties[key]
                if definition==common:continue
                if isinstance(definition,dict) and isinstance(common,dict):
                    remaining[key]={k:v for k,v in definition.items() if k not in common or v!=common[k]}
                else:remaining[key]=definition
            branch.pop('type');branch.pop('additionalProperties');branch.pop('properties')
            if remaining:branch['properties']=remaining
            if 'required' in branch:
                branch['required']=[key for key in branch['required'] if key not in node.get('required',[])]
                if not branch['required']:branch.pop('required')
            branches.append(branch)
        node['oneOf']=branches
        return node
    return visit(value)
