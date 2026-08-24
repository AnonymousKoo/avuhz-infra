import copy,json,sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from avuhz_runtime.schema_registry import SchemaRegistry
f=json.load(open(ROOT/'contracts/fixtures/v1/assessment-access-proposal.cases.json'));v=Draft202012Validator(SchemaRegistry(ROOT/'contracts/schemas/v1').expanded('urn:avuhz:schema:contracts:domain:assessment-access-proposal:v1'))
for x in f['positive']:
 a=copy.deepcopy(f['base']);a.update(x);assert not list(v.iter_errors(a))
for k,x in f['negative']:
 a=copy.deepcopy(f['base']);a.pop(k) if x is None else a.__setitem__(k,x);assert list(v.iter_errors(a))
print('assessment-access-proposal validation: PASS')
