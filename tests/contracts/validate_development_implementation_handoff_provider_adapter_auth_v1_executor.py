from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=ROOT/'.github/workflows/development-implementation-handoff-provider-adapter-auth-v1-execution.yml'
s=p.read_text()
assert p.is_file()
assert '644f239b-c7cb-4c30-85a4-95efbfe85ae4' in s
assert 'sha256:67b9ebbcd55612edbfbdc3f51f6b8288abd92d3ecef2c35c88cddfa72f5d49fb' in s
assert 'avuhz-implementation-handoff-provider-adapter-development@example.invalid' in s
assert s.count('--request POST') == 1
assert s.count('email_confirm') >= 2
assert '"password":' not in s
assert "'password':" not in s
assert 'provider_mutation_succeeded=true' in s
print('provider-adapter Auth v1 executor: PASS')
