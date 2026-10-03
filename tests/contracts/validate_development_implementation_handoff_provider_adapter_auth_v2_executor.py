from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=ROOT/'.github/workflows/development-implementation-handoff-provider-adapter-auth-v2-execution.yml'
s=p.read_text()
assert p.is_file()
assert '305d2d98-0d87-42bc-90a4-f0cd5e66ea7c' in s
assert 'sha256:bef8d098f593a67bf476a17e76fcf17fbda9986c76ac765c2e2253d5904672b4' in s
assert 'avuhz-implementation-handoff-provider-adapter-development@example.invalid' in s
assert '56d784cb-195b-4c26-91a3-b9d4978a2acc' in s
assert 'sha256:db637c44ca9976669dfb9345904504725c2892896b20acd1615a334a95614504' in s
assert 'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_IMPLEMENTATION_HANDOFF_ADAPTER_V2_EPHEMERAL' in s
assert '2026-10-03T15:00:00Z' in s and '2026-10-03T19:00:00Z' in s
assert s.count('--request POST') == 1
assert s.count('email_confirm') >= 2
assert '"password":' not in s
assert "'password':" not in s
assert 'provider_mutation_succeeded=true' in s
print('provider-adapter Auth v2 executor: PASS')
