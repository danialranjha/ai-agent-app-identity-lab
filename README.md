# AI-agent app identity lab

A desktop-control tool can check one spelling of an app identifier and then resolve a different spelling to the same app. This lab runs exact Swift policy and bundle-matching slices from a pinned Open Computer Use source file against invented app records. It compares the original query check with a proposed check of the resolved identity.

All 18 selected case-variant fixtures reach an in-memory record capture under the original logic; none do under the proposed check. Both ordinary-app fixtures retain the same invented process ID. No apps, AI models, accessibility services, screenshots or desktop actions run.

## Hypothesis and threat model

An exact, case-sensitive denylist check can miss a differently cased query that a case-insensitive matcher resolves to a blocked app. Resolving the record, checking its identifier against a denylist with **both sides normalized**, and then passing that same checked record to the next operation closes that mismatch for the selected ASCII identifiers.

Assume a caller controls the bundle-ID spelling and the system has already obtained a trusted list of running-app descriptors. Here that list is entirely synthetic. The surrounding program, denylist and descriptor identities remain trusted. The experiment does not show prompt injection, acquisition of local caller permissions, tampering with identities, or a complete desktop exploit.

The sink only appends an invented integer process ID to a JSON trace. Source-listed public identifiers are strings in fixtures, never instructions to launch or query those applications. The executable imports Foundation, not AppKit. It contains no application discovery, launching, UI interaction, file-reading payload, network request or credential access. The Python harness compiles a fixed program in a temporary directory, supplies fixed JSON fixtures on stdin, and cleans up its compiler cache and binary.

## Reproduce

Requires Python 3.10+ standard library and Swift with Foundation (`swiftc` on PATH). Validated on macOS arm64 with Apple Swift 6.0.2 and Python 3.12.4. No third-party package installation or network access is required. A first compile may take tens of seconds.

```sh
python3 experiment.py
python3 checks.py
```

Direct test equivalent:

```sh
python3 -m unittest discover -s tests -v
```

`experiment.py` rebuilds [run.json](artifacts/run.json) and [evidence.md](artifacts/evidence.md). `checks.py` runs the tests and records exact mismatched cases under two deliberately broken interventions in [checks.json](artifacts/checks.json). Artifact bytes contain no timestamps, random directories or machine paths.

## Results

33 selected fixture pairs, 66 method invocations. These are deterministic coverage cases, not independent attack samples, success probabilities or measurements of production prevalence.

| Fixture family | Pairs | Original captures | Resolved-check captures |
|---|---:|---:|---:|
| Exact blocked spellings, including whitespace trim | 9 | 0 | 0 |
| Case variants, including mixed-case stored record and denylist entry | 18 | 18 | 0 |
| Ordinary app, exact and uppercase query | 2 | 2 | 2 |
| Missing ID, suffix look-alike and nil descriptor identity | 3 | 0 | 0 |
| Unlisted app, explicit denylist limitation | 1 | 1 | 1 |

All 11 test methods pass. Removing the proposed check creates 27 expectation mismatches; denying every resolved app creates 3. These are fixture/method mismatches detected by tests, not 27 or 3 failing test methods. The fault checks demonstrate that ordinary controls and blocked-target checks both matter.

## Technical walkthrough

### Verified source and extraction

[CVE-2026-108721](https://nvd.nist.gov/vuln/detail/CVE-2026-108721) describes a local caller case-variant bypass in Open Computer Use through 1.0.0. The [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/108xxx/CVE-2026-108721.json) cites the pinned file below and attributes discovery to HaiND. This lab independently reproduces the narrow comparison mismatch, not the advisory's screenshots or password-manager interaction. No fixed release or vendor-approved patch is asserted.

Source: [AppDiscovery.swift at 8a3a7dec06402db2d760368cb24676ad3ba42c49](https://github.com/iFurySt/open-codex-computer-use/blob/8a3a7dec06402db2d760368cb24676ad3ba42c49/packages/OpenComputerUseKit/Sources/OpenComputerUseKit/AppDiscovery.swift).

- `resolve` trims the query and tests the raw bundle identifier against the policy before returning the matching descriptor.
- The bundle-ID branch of `resolvedRunningApp` compares identifiers using Foundation's `caseInsensitiveCompare`.
- `AppSafetyPolicy.isBlocked` uses `Set<String>.contains`, an exact string membership check. One stored entry itself has mixed case: `com.lastpass.LastPass`.

[Policy.swift](upstream/Policy.swift) copies the original enum through `isBlocked` verbatim and adds its closing brace. The unrelated `permissionDenied` constructor is omitted. The exact bundle-match return expression is copied into a small wrapper accepting synthetic `Descriptor` records. No source code is imported that can discover, launch or drive an app. The dot-containing-query branch is the only branch modeled.

[provenance.json](upstream/provenance.json) records source size (20,347 bytes), verified Git blob `88a533a3babd85892234acfed6bf415a14e63fe1`, full-file and snippet SHA-256 values, source commit and extraction scope. The harness verifies the slice hash before compilation. [MIT license](upstream/LICENSE) accompanies the upstream slices. The harness and proposed intervention are independent additions.

### Control and intervention

**Original query check:** apply the exact upstream policy to the trimmed query, then use the upstream matching expression. Record the matched synthetic PID if the policy allowed it.

**Resolved identity check:** use the same matching expression, normalize the matched record's identifier and every denylist entry to lowercase, then reject listed identities before recording a PID. If allowed, capture the exact checked record. This is an experimental intervention, not a released fix. Resolution here only searches an in-memory list; it cannot launch or activate an app.

### One paired trace

Fixture `mixed-record` supplies `com.1Password.1Password`. Its invented running record has identifier `COM.1PASSWORD.1PASSWORD`, PID 201. The original exact policy misses the supplied spelling; the case-insensitive matcher finds that record.

```text
original-query-check
  query-policy:allow
  resolve:pid=201,id=COM.1PASSWORD.1PASSWORD
  capture:pid=201

resolved-identity-check
  resolve:pid=201,id=COM.1PASSWORD.1PASSWORD
  resolved-policy:deny
```

Both paths resolve the same synthetic identity. The intervention changes whether that record reaches the capture. It does not open a safer app, repair the request or carry out the action using an approved substitute.

### Coverage and controls

Each of eight source-listed identifiers has its exact spelling, uppercase spelling and swapped-case spelling. Additional cases exercise whitespace handling, lowercase input for the mixed-case policy entry, differently cased stored identity, ordinary exact/uppercase matching, missing identity, a suffix look-alike, a nil descriptor identifier, and an unlisted app. Matching a suffix is not the same as matching an app identifier; those absent cases produce no capture under either method.

The fixture expectation oracle is declared separately from the Swift comparison code. Tests inspect actual captured PID and chronological events, not only an `allowed` label. Repeat execution must produce the same rows. Deliberate faults affect only the proposed intervention and must violate the independent expectations. The normal source slices are unchanged by fault tests.

### Limits that matter

An invented unlisted vault record still reaches capture under both methods. Case-consistent checking only enforces the list you have; it does not discover every sensitive app or establish a complete app permission policy.

These fixtures cover ASCII identifiers from the pinned policy. Lowercasing is not established as the correct identity rule for arbitrary Unicode, paths, URLs, aliases or other systems. No name-based discovery, OS bundle resolution, launch-before-check behavior, PID reuse, concurrent process replacement, app signing identity, screenshot path, action handler or end-to-end authorization flow is tested. Checking a record and acting on that same stable identity remains an integration requirement. Resolving by a side-effecting launch would require additional policy before that side effect.

The experiment assumes trusted descriptors. It cannot repair a resolver that lies about which app a record represents. It does not demonstrate current release exposure, a remote exploit, leaked secrets, or how frequently a model selects a case-variant name.

## Supported engineering check

At the boundary before any desktop action, make the identity check agree with the resolver's identity semantics, check the resolved app record, and pass that same checked record onward. For this ASCII fixture boundary, normalize both the resolved identifier and policy entries. Regression-test case variants of every denied identifier alongside ordinary-app controls, and separately validate all resolution and action paths in the real integration.
