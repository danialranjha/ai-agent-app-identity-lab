from pathlib import Path
import io,json,unittest
from experiment import Engine,mismatches

root=Path(__file__).resolve().parent
suite=unittest.defaultTestLoader.discover(str(root/'tests'))
stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
print(stream.getvalue())
with Engine() as engine:
    faults={f:mismatches(engine.run(f)) for f in ['skip-check','deny-all']}
data=dict(tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),fault_mismatches=faults)
out=root/'artifacts';out.mkdir(exist_ok=True);(out/'checks.json').write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
assert result.wasSuccessful() and len(faults['skip-check'])==27 and len(faults['deny-all'])==3
