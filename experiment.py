"""Compile real Swift string comparisons; pass invented records only."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
DENIED = ["com.1password.1password", "com.1password.safari", "com.bitwarden.desktop",
          "com.dashlane.dashlanephonefinal", "com.lastpass.LastPass", "com.nordsec.nordpass",
          "me.proton.pass.electron", "me.proton.pass.catalyst"]

def fixtures():
    result = []
    for index, bundle in enumerate(DENIED):
        for label, query in [("exact", bundle), ("upper", bundle.upper()), ("swap", bundle.swapcase())]:
            result.append(dict(id=f"blocked-{index}-{label}", family="exact-blocked" if label == "exact" else "case-variant",
                               query=query, descriptors=[dict(bundleIdentifier=bundle, pid=100+index)]))
    for id_, family, query, identity, pid in [
        ("mixed-record", "case-variant", "com.1Password.1Password", "COM.1PASSWORD.1PASSWORD", 201),
        ("lastpass-lower", "case-variant", "com.lastpass.lastpass", "com.lastpass.LastPass", 202),
        ("ordinary", "benign", "org.example.notes", "org.example.notes", 301),
        ("ordinary-upper", "benign", "ORG.EXAMPLE.NOTES", "org.example.notes", 301),
        ("missing", "absent", "org.example.absent", "org.example.notes", 301),
        ("suffix-lookalike", "absent", "com.1password.1password.extra", "com.1password.1password", 101),
        ("whitespace", "exact-blocked", "  com.1password.1password\n", "com.1password.1password", 101),
        ("unlisted-vault", "limitation", "org.example.unlistedvault", "org.example.unlistedvault", 401),
        ("nil-identity", "absent", "org.example.absent", None, 501),
    ]:
        result.append(dict(id=id_, family=family, query=query, descriptors=[dict(bundleIdentifier=identity,pid=pid)]))
    return result

class Engine:
    def __enter__(self):
        manifest=json.loads((ROOT/'upstream/provenance.json').read_text())
        assert hashlib.sha256((ROOT/'upstream/Policy.swift').read_bytes()).hexdigest()==manifest['snippet_sha256']
        self.tmp=tempfile.TemporaryDirectory(prefix='app-identity-lab-')
        self.binary=Path(self.tmp.name)/'probe'
        subprocess.run(['swiftc','-module-cache-path',str(Path(self.tmp.name)/'cache'),
                        str(ROOT/'upstream/Policy.swift'),str(ROOT/'main.swift'),'-o',str(self.binary)],check=True,capture_output=True,text=True)
        return self
    def run(self, fault='none'):
        process=subprocess.run([str(self.binary),fault],input=json.dumps(fixtures()),text=True,capture_output=True,check=True)
        return json.loads(process.stdout)
    def __exit__(self,*args): self.tmp.cleanup()

def expected(row):
    family=row['family']
    if family=='exact-blocked':return 'denied',None
    if family=='case-variant' and row['method']=='resolved-identity-check':return 'denied',None
    if family=='absent':return 'not-found',None
    fixture=next(f for f in fixtures() if f['id']==row['id'])
    return 'captured',fixture['descriptors'][0]['pid']

def mismatches(rows):
    return [r['id']+':'+r['method'] for r in rows if (r['outcome'],r.get('capturedPID'))!=expected(r)]

def make_artifacts(rows):
    assert not mismatches(rows),mismatches(rows)
    out=ROOT/'artifacts';out.mkdir(exist_ok=True)
    groups=[]
    for family in ['exact-blocked','case-variant','benign','absent','limitation']:
        pair=[r for r in rows if r['family']==family]
        groups.append(dict(family=family,pairs=len(pair)//2,original_captures=sum(r['outcome']=='captured' for r in pair if r['method']=='original-query-check'),
                           resolved_captures=sum(r['outcome']=='captured' for r in pair if r['method']=='resolved-identity-check')))
    payload=dict(scope='Pinned Swift string-policy/resolution slices with synthetic records; no desktop or model',fixture_pairs=len(fixtures()),rows=rows,groups=groups)
    (out/'run.json').write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n')
    text=['# Exact component evidence','','No apps or models run. Counts are selected fixture pairs, not attack rates.','',
          '| Family | Pairs | Original captures | Resolved-check captures |','|---|---:|---:|---:|']
    text += [f"| {g['family']} | {g['pairs']} | {g['original_captures']} | {g['resolved_captures']} |" for g in groups]
    text += ['','## Complete chronological traces','', 'Capture means recording an invented PID in memory, not interacting with an app.','']
    for r in rows:text += [f"### {r['id']} / {r['method']}",f"Query: `{r['query'].strip()}`",f"Outcome: **{r['outcome']}**; capture: `{r.get('capturedPID')}`",' → '.join(r['trace']),'']
    (out/'evidence.md').write_text('\n'.join(text).rstrip()+'\n')
    return groups

if __name__=='__main__':
    with Engine() as engine: print(json.dumps(make_artifacts(engine.run()),indent=2))
