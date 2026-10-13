# Exact component evidence

No apps or models run. Counts are selected fixture pairs, not attack rates.

| Family | Pairs | Original captures | Resolved-check captures |
|---|---:|---:|---:|
| exact-blocked | 9 | 0 | 0 |
| case-variant | 18 | 18 | 0 |
| benign | 2 | 2 | 2 |
| absent | 3 | 0 | 0 |
| limitation | 1 | 1 | 1 |

## Complete chronological traces

Capture means recording an invented PID in memory, not interacting with an app.

### blocked-0-exact / original-query-check
Query: `com.1password.1password`
Outcome: **denied**; capture: `None`
query-policy:deny

### blocked-0-exact / resolved-identity-check
Query: `com.1password.1password`
Outcome: **denied**; capture: `None`
resolve:pid=100,id=com.1password.1password → resolved-policy:deny

### blocked-0-upper / original-query-check
Query: `COM.1PASSWORD.1PASSWORD`
Outcome: **captured**; capture: `100`
query-policy:allow → resolve:pid=100,id=com.1password.1password → capture:pid=100

### blocked-0-upper / resolved-identity-check
Query: `COM.1PASSWORD.1PASSWORD`
Outcome: **denied**; capture: `None`
resolve:pid=100,id=com.1password.1password → resolved-policy:deny

### blocked-0-swap / original-query-check
Query: `COM.1PASSWORD.1PASSWORD`
Outcome: **captured**; capture: `100`
query-policy:allow → resolve:pid=100,id=com.1password.1password → capture:pid=100

### blocked-0-swap / resolved-identity-check
Query: `COM.1PASSWORD.1PASSWORD`
Outcome: **denied**; capture: `None`
resolve:pid=100,id=com.1password.1password → resolved-policy:deny

### blocked-1-exact / original-query-check
Query: `com.1password.safari`
Outcome: **denied**; capture: `None`
query-policy:deny

### blocked-1-exact / resolved-identity-check
Query: `com.1password.safari`
Outcome: **denied**; capture: `None`
resolve:pid=101,id=com.1password.safari → resolved-policy:deny

### blocked-1-upper / original-query-check
Query: `COM.1PASSWORD.SAFARI`
Outcome: **captured**; capture: `101`
query-policy:allow → resolve:pid=101,id=com.1password.safari → capture:pid=101

### blocked-1-upper / resolved-identity-check
Query: `COM.1PASSWORD.SAFARI`
Outcome: **denied**; capture: `None`
resolve:pid=101,id=com.1password.safari → resolved-policy:deny

### blocked-1-swap / original-query-check
Query: `COM.1PASSWORD.SAFARI`
Outcome: **captured**; capture: `101`
query-policy:allow → resolve:pid=101,id=com.1password.safari → capture:pid=101

### blocked-1-swap / resolved-identity-check
Query: `COM.1PASSWORD.SAFARI`
Outcome: **denied**; capture: `None`
resolve:pid=101,id=com.1password.safari → resolved-policy:deny

### blocked-2-exact / original-query-check
Query: `com.bitwarden.desktop`
Outcome: **denied**; capture: `None`
query-policy:deny

### blocked-2-exact / resolved-identity-check
Query: `com.bitwarden.desktop`
Outcome: **denied**; capture: `None`
resolve:pid=102,id=com.bitwarden.desktop → resolved-policy:deny

### blocked-2-upper / original-query-check
Query: `COM.BITWARDEN.DESKTOP`
Outcome: **captured**; capture: `102`
query-policy:allow → resolve:pid=102,id=com.bitwarden.desktop → capture:pid=102

### blocked-2-upper / resolved-identity-check
Query: `COM.BITWARDEN.DESKTOP`
Outcome: **denied**; capture: `None`
resolve:pid=102,id=com.bitwarden.desktop → resolved-policy:deny

### blocked-2-swap / original-query-check
Query: `COM.BITWARDEN.DESKTOP`
Outcome: **captured**; capture: `102`
query-policy:allow → resolve:pid=102,id=com.bitwarden.desktop → capture:pid=102

### blocked-2-swap / resolved-identity-check
Query: `COM.BITWARDEN.DESKTOP`
Outcome: **denied**; capture: `None`
resolve:pid=102,id=com.bitwarden.desktop → resolved-policy:deny

### blocked-3-exact / original-query-check
Query: `com.dashlane.dashlanephonefinal`
Outcome: **denied**; capture: `None`
query-policy:deny

### blocked-3-exact / resolved-identity-check
Query: `com.dashlane.dashlanephonefinal`
Outcome: **denied**; capture: `None`
resolve:pid=103,id=com.dashlane.dashlanephonefinal → resolved-policy:deny

### blocked-3-upper / original-query-check
Query: `COM.DASHLANE.DASHLANEPHONEFINAL`
Outcome: **captured**; capture: `103`
query-policy:allow → resolve:pid=103,id=com.dashlane.dashlanephonefinal → capture:pid=103

### blocked-3-upper / resolved-identity-check
Query: `COM.DASHLANE.DASHLANEPHONEFINAL`
Outcome: **denied**; capture: `None`
resolve:pid=103,id=com.dashlane.dashlanephonefinal → resolved-policy:deny

### blocked-3-swap / original-query-check
Query: `COM.DASHLANE.DASHLANEPHONEFINAL`
Outcome: **captured**; capture: `103`
query-policy:allow → resolve:pid=103,id=com.dashlane.dashlanephonefinal → capture:pid=103

### blocked-3-swap / resolved-identity-check
Query: `COM.DASHLANE.DASHLANEPHONEFINAL`
Outcome: **denied**; capture: `None`
resolve:pid=103,id=com.dashlane.dashlanephonefinal → resolved-policy:deny

### blocked-4-exact / original-query-check
Query: `com.lastpass.LastPass`
Outcome: **denied**; capture: `None`
query-policy:deny

### blocked-4-exact / resolved-identity-check
Query: `com.lastpass.LastPass`
Outcome: **denied**; capture: `None`
resolve:pid=104,id=com.lastpass.LastPass → resolved-policy:deny

### blocked-4-upper / original-query-check
Query: `COM.LASTPASS.LASTPASS`
Outcome: **captured**; capture: `104`
query-policy:allow → resolve:pid=104,id=com.lastpass.LastPass → capture:pid=104

### blocked-4-upper / resolved-identity-check
Query: `COM.LASTPASS.LASTPASS`
Outcome: **denied**; capture: `None`
resolve:pid=104,id=com.lastpass.LastPass → resolved-policy:deny

### blocked-4-swap / original-query-check
Query: `COM.LASTPASS.lASTpASS`
Outcome: **captured**; capture: `104`
query-policy:allow → resolve:pid=104,id=com.lastpass.LastPass → capture:pid=104

### blocked-4-swap / resolved-identity-check
Query: `COM.LASTPASS.lASTpASS`
Outcome: **denied**; capture: `None`
resolve:pid=104,id=com.lastpass.LastPass → resolved-policy:deny

### blocked-5-exact / original-query-check
Query: `com.nordsec.nordpass`
Outcome: **denied**; capture: `None`
query-policy:deny

### blocked-5-exact / resolved-identity-check
Query: `com.nordsec.nordpass`
Outcome: **denied**; capture: `None`
resolve:pid=105,id=com.nordsec.nordpass → resolved-policy:deny

### blocked-5-upper / original-query-check
Query: `COM.NORDSEC.NORDPASS`
Outcome: **captured**; capture: `105`
query-policy:allow → resolve:pid=105,id=com.nordsec.nordpass → capture:pid=105

### blocked-5-upper / resolved-identity-check
Query: `COM.NORDSEC.NORDPASS`
Outcome: **denied**; capture: `None`
resolve:pid=105,id=com.nordsec.nordpass → resolved-policy:deny

### blocked-5-swap / original-query-check
Query: `COM.NORDSEC.NORDPASS`
Outcome: **captured**; capture: `105`
query-policy:allow → resolve:pid=105,id=com.nordsec.nordpass → capture:pid=105

### blocked-5-swap / resolved-identity-check
Query: `COM.NORDSEC.NORDPASS`
Outcome: **denied**; capture: `None`
resolve:pid=105,id=com.nordsec.nordpass → resolved-policy:deny

### blocked-6-exact / original-query-check
Query: `me.proton.pass.electron`
Outcome: **denied**; capture: `None`
query-policy:deny

### blocked-6-exact / resolved-identity-check
Query: `me.proton.pass.electron`
Outcome: **denied**; capture: `None`
resolve:pid=106,id=me.proton.pass.electron → resolved-policy:deny

### blocked-6-upper / original-query-check
Query: `ME.PROTON.PASS.ELECTRON`
Outcome: **captured**; capture: `106`
query-policy:allow → resolve:pid=106,id=me.proton.pass.electron → capture:pid=106

### blocked-6-upper / resolved-identity-check
Query: `ME.PROTON.PASS.ELECTRON`
Outcome: **denied**; capture: `None`
resolve:pid=106,id=me.proton.pass.electron → resolved-policy:deny

### blocked-6-swap / original-query-check
Query: `ME.PROTON.PASS.ELECTRON`
Outcome: **captured**; capture: `106`
query-policy:allow → resolve:pid=106,id=me.proton.pass.electron → capture:pid=106

### blocked-6-swap / resolved-identity-check
Query: `ME.PROTON.PASS.ELECTRON`
Outcome: **denied**; capture: `None`
resolve:pid=106,id=me.proton.pass.electron → resolved-policy:deny

### blocked-7-exact / original-query-check
Query: `me.proton.pass.catalyst`
Outcome: **denied**; capture: `None`
query-policy:deny

### blocked-7-exact / resolved-identity-check
Query: `me.proton.pass.catalyst`
Outcome: **denied**; capture: `None`
resolve:pid=107,id=me.proton.pass.catalyst → resolved-policy:deny

### blocked-7-upper / original-query-check
Query: `ME.PROTON.PASS.CATALYST`
Outcome: **captured**; capture: `107`
query-policy:allow → resolve:pid=107,id=me.proton.pass.catalyst → capture:pid=107

### blocked-7-upper / resolved-identity-check
Query: `ME.PROTON.PASS.CATALYST`
Outcome: **denied**; capture: `None`
resolve:pid=107,id=me.proton.pass.catalyst → resolved-policy:deny

### blocked-7-swap / original-query-check
Query: `ME.PROTON.PASS.CATALYST`
Outcome: **captured**; capture: `107`
query-policy:allow → resolve:pid=107,id=me.proton.pass.catalyst → capture:pid=107

### blocked-7-swap / resolved-identity-check
Query: `ME.PROTON.PASS.CATALYST`
Outcome: **denied**; capture: `None`
resolve:pid=107,id=me.proton.pass.catalyst → resolved-policy:deny

### mixed-record / original-query-check
Query: `com.1Password.1Password`
Outcome: **captured**; capture: `201`
query-policy:allow → resolve:pid=201,id=COM.1PASSWORD.1PASSWORD → capture:pid=201

### mixed-record / resolved-identity-check
Query: `com.1Password.1Password`
Outcome: **denied**; capture: `None`
resolve:pid=201,id=COM.1PASSWORD.1PASSWORD → resolved-policy:deny

### lastpass-lower / original-query-check
Query: `com.lastpass.lastpass`
Outcome: **captured**; capture: `202`
query-policy:allow → resolve:pid=202,id=com.lastpass.LastPass → capture:pid=202

### lastpass-lower / resolved-identity-check
Query: `com.lastpass.lastpass`
Outcome: **denied**; capture: `None`
resolve:pid=202,id=com.lastpass.LastPass → resolved-policy:deny

### ordinary / original-query-check
Query: `org.example.notes`
Outcome: **captured**; capture: `301`
query-policy:allow → resolve:pid=301,id=org.example.notes → capture:pid=301

### ordinary / resolved-identity-check
Query: `org.example.notes`
Outcome: **captured**; capture: `301`
resolve:pid=301,id=org.example.notes → resolved-policy:allow → capture:pid=301

### ordinary-upper / original-query-check
Query: `ORG.EXAMPLE.NOTES`
Outcome: **captured**; capture: `301`
query-policy:allow → resolve:pid=301,id=org.example.notes → capture:pid=301

### ordinary-upper / resolved-identity-check
Query: `ORG.EXAMPLE.NOTES`
Outcome: **captured**; capture: `301`
resolve:pid=301,id=org.example.notes → resolved-policy:allow → capture:pid=301

### missing / original-query-check
Query: `org.example.absent`
Outcome: **not-found**; capture: `None`
query-policy:allow → resolve:none

### missing / resolved-identity-check
Query: `org.example.absent`
Outcome: **not-found**; capture: `None`
resolve:none

### suffix-lookalike / original-query-check
Query: `com.1password.1password.extra`
Outcome: **not-found**; capture: `None`
query-policy:allow → resolve:none

### suffix-lookalike / resolved-identity-check
Query: `com.1password.1password.extra`
Outcome: **not-found**; capture: `None`
resolve:none

### whitespace / original-query-check
Query: `com.1password.1password`
Outcome: **denied**; capture: `None`
query-policy:deny

### whitespace / resolved-identity-check
Query: `com.1password.1password`
Outcome: **denied**; capture: `None`
resolve:pid=101,id=com.1password.1password → resolved-policy:deny

### unlisted-vault / original-query-check
Query: `org.example.unlistedvault`
Outcome: **captured**; capture: `401`
query-policy:allow → resolve:pid=401,id=org.example.unlistedvault → capture:pid=401

### unlisted-vault / resolved-identity-check
Query: `org.example.unlistedvault`
Outcome: **captured**; capture: `401`
resolve:pid=401,id=org.example.unlistedvault → resolved-policy:allow → capture:pid=401

### nil-identity / original-query-check
Query: `org.example.absent`
Outcome: **not-found**; capture: `None`
query-policy:allow → resolve:none

### nil-identity / resolved-identity-check
Query: `org.example.absent`
Outcome: **not-found**; capture: `None`
resolve:none
