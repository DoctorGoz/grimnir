# Salesforce Experience Cloud: testing methodology

Methodology for a Salesforce Experience Cloud site (formerly Community) and the Apex backend behind it. It backs the three playbooks in `rules/playbooks/`:

- `salesforce-experience-cloud-guest.yaml`: unauthenticated Guest User data exposure.
- `salesforce-apex-injection-logic.yaml`: Apex-layer SOQL injection, parameter tampering, insecure deserialization, `without sharing` chains.
- `salesforce-visualforce-xss.yaml`: Visualforce, Aura and LWC cross-site scripting.

`specter/scripts/sf-guest-map.py` automates the read-only mapping step. Route targets here from the Salesforce section of the `target-classification` skill. Lead agent is Specter.

Everything here is a configuration and code-quality class. None of it is a Salesforce platform 0day: a hardened, well-coded org leaks nothing.

## Authorization and the vendor's testing policy

Salesforce requires approval for penetration testing against production orgs and restricts destructive techniques. Read the vendor's current security-assessment policy before scheduling work.

- Prefer a sandbox, Developer Edition or scratch org for anything intrusive, and for building a proof of concept.
- Guest data-read enumeration is low-touch. Treat production writes and any fuzzing as gated on written approval from the program.
- Expect Event Monitoring, login history and the audit trail to record your activity.
- Mask or anonymize real data you touch. Revert every test write.

## Shared-responsibility model

The vendor owns infrastructure and platform security. The customer owns user permissions, sharing rules, profiles and permission sets, configuration, and all custom code. Nearly every finding is in the customer half.

The stack, top to bottom: permissions and sharing, custom code (Apex, Visualforce, Aura, LWC) and configuration, Apex controllers, business logic, SOQL over objects (standard, and custom with a `__c` suffix), then fields and records. The Lightning UI renders it (Aura is older, LWC newer). A gap in any layer (missing `with sharing`, absent CRUD/FLS checks, injectable SOQL, unescaped Visualforce output) can cascade into privilege escalation, data leakage or a full record-level bypass.

## Fingerprinting

- Paths: `/s/`, `/s/topic`, `/s/article`, `/s/contactsupport`.
- Domains: `*.force.com`, `*.secure.force.com`, `*.live.siteforce.com`, `*.my.site.com`.
- Aura endpoint variants: `/s/sfsites/aura`, `/aura`, `/sfsites/aura`. LWC Apex path: `/webruntime/api/apex/execute`.
- Response tells: `"actions":[`, `aura:clientOutOfSync`, `aura:invalidSession`.
- Cookies: `BrowserId`, `renderCtx`, `sfdc-stream`.
- Download servlets: `/servlet/servlet.FileDownload`, `/sfc/servlet.shepherd/...`.

## The guest request model

Experience Cloud serves a Lightning app to anonymous visitors as the org's Guest User. Every data request is one POST to the aura endpoint with `aura.token=undefined`, so the guest surface is whatever the Guest User profile and guest sharing rules expose.

Harvest two live values from the `/s/` bootstrap:

- `fwuid`: the framework build id, found in the `app.js` URL.
- `appId`: the `loaded` value for `APPLICATION@markup://siteforce:communityApp`.

POST form fields:

| Field | Value |
|---|---|
| `message` | `{"actions":[{"id":"1","descriptor":"<DESCRIPTOR>","callingDescriptor":"UNKNOWN","params":{...}}]}` |
| `aura.context` | `{"mode":"PROD","fwuid":"...","app":"siteforce:communityApp","loaded":{"APPLICATION@markup://siteforce:communityApp":"<appId>"}}` |
| `aura.pageURI` | `/s/` |
| `aura.token` | `undefined` (some orgs want `null`; no session cookie) |

The context expires with each Salesforce framework build. If actions return `clientOutOfSync`, re-extract `fwuid` and `appId`. A transient 500 mid-sweep is rate limiting: cool down and re-probe with the same context.

Authenticated variant: capture a POST from your own org or portal account, transplant the cookies, `aura.context` and `aura.token`, and change only `message`.

### Controller catalog

Descriptors are `serviceComponent://ui.force.components.controllers.<pkg>.<Controller>/ACTION$<method>` unless shown as `aura://`.

| Controller and action | Purpose | Notes |
|---|---|---|
| `hostConfig.HostConfigController/ACTION$getConfigData` | Object catalog | `apiNamesToKeyPrefixes` lists every guest-visible object with its 3-character key prefix. The discovery primitive. |
| `OneController/ACTION$getCurrentApp` | Extended object listing | Complements `getConfigData`. |
| `aura://RecordUiController/ACTION$getObjectInfo` | Object metadata | Field map for one `ObjectApiName`; the FLS review input. |
| `SelectableListDataProviderController/ACTION$getItems` | List rows | `entityNameOrId`, `layoutType`, `pageSize` (up to 1000), `currentPage`, `getCount`. Not an existence oracle. |
| `ScopedResultsDataProviderController/ACTION$getLookupItems` | Search enumeration | `scope` plus a `term` of 4 or more characters. |
| `detail.DetailController/ACTION$getRecord` | One record by id | `recordId`, `layoutType`, `mode`. |
| `RecordGvpController/ACTION$getRecord` | One record with fields | Alternate reader. |
| `aura://RecordUiController/ACTION$getRecordWithFields` | One record with fields | UI-API, sharing-safe. |
| `aura://ApexActionController/ACTION$execute` | Invoke Apex | `namespace`, `classname`, `method`, `params`, `cacheable`. No enumeration oracle. |
| `/webruntime/api/apex/execute` | LWC Apex call | The modern imperative and `@wire` path; URL-encoded params. |

Objects worth checking: `Account`, `Contact`, `Case`, `Lead`, `Opportunity`, `User`, `Attachment`, `EmailMessage`, `CaseComment`, `Note`, `Document`, `ContentDocument`, `ContentVersion`, and every `__c` object.

Download servlets by key prefix: Document `015` at `/servlet/servlet.FileDownload?file=<Id>`; ContentDocument `069` at `/sfc/servlet.shepherd/document/download/<Id>`; ContentVersion `068` at `/sfc/servlet.shepherd/version/download/<Id>`.

### Custom Apex discovery

There is no enumeration oracle, so harvest real names:

1. Search proxy history for `apex%3a%2f%2f` (URL-encoded `apex://`).
2. Search responses for `compound://c`; the `componentDefs[].ac[]` entries give method name `n`, descriptor, return type `rt` and parameters `pa`.
3. Fetch `/auraCmpDef?aura.app=markup://siteforce:communityApp&_def=markup://c:<COMPONENT>` for full signatures.
4. If `ApexClass` is readable at the tested privilege, list it and read `Body`: that is the source, so audit it directly.

## The three-layer access model

Test each layer separately:

- OLS, object-level security: can the principal see the object at all.
- FLS, field-level security: which columns come back.
- RLS, record-level security (sharing): which rows come back.

A guest leak or authorization bug is a gap in one of the three. `without sharing` Apex bypasses RLS entirely.

## Oracle discipline

- `getItems` is not an existence oracle. A garbage object name returns success with zero rows; only a non-zero count means anything.
- `getRecordWithFields` is sharing-safe and answers "resource does not exist" for anything unreachable, so it cannot confirm an id exists.
- `ApexActionController` returns the same "No apex action available" for real and fake classes. Blind Apex enumeration is dead.
- A reply under about 12 KB usually means access denied or own-record-only. Sort fuzz results by length, descending, to find leaks.
- Run a negative control (garbage name, fake id, your own value) before claiming any oracle.

## Vulnerability families

**A. Guest data exposure.** Object rows, records or files the guest should not reach. Highest value: sensitive custom fields hidden from the UI but readable programmatically (password hashes, TOTP secrets, API keys).

**B. Apex injection and logic.**
- SOQL injection: user input concatenated into dynamic `Database.query`. Returns-all payloads include `X' OR Name LIKE '%` and `') OR (Name LIKE '%`. Proof is out-of-filter rows compared with a benign value. Defenses that stop it: bind variables, `WITH SECURITY_ENFORCED`, `escapeSingleQuotes`.
- Parameter tampering: a client argument (profile, owner id, status, a public-versus-internal flag) shapes the result set. Intercept the Apex call, decode, edit one value.
- Insecure deserialization: a generic importer builds sObjects from attacker input and upserts without CRUD/FLS checks. Confirm with a marker record, then revert it.
- `without sharing` chains: an `@AuraEnabled` method running in system context that reads or writes by a supplied id.

**C. Visualforce and configuration.** `escape="false"` output and unescaped merge fields; hard-coded secrets in Apex, pages or static resources (callouts belong in Named Credentials); over-permissioned profiles (`Modify All Data`, `View All Data`); record-id tampering.

**D. Wider community surface.** Test from every persona (guest, portal user, partner, integration, employee) for horizontal and vertical escalation. Hit `/apex/<Page>` and Aura/LWC components directly, bypassing hidden navigation. Check session cookie flags, clickjack protection, CSP Trusted Sites, outdated third-party JavaScript without SRI, CSRF on state-changing actions, debug output left in components, and unmasked data in sandboxes.

## Quick checklist

Missing `with sharing`; no CRUD/FLS enforcement (`isAccessible`, `WITH SECURITY_ENFORCED`, `Security.stripInaccessible()`); SOQL injection in search boxes and URL parameters; Visualforce XSS; hard-coded secrets; over-permissive profiles; record-id tampering; guest-readable custom objects and fields.

## Reproduction skeleton (unauthenticated guest)

1. GET `/s/`; extract `fwuid` and `appId`.
2. `getConfigData` for the object catalog, including `__c` objects.
3. `getItems` per object for counts; `getRecord` or `getRecordWithFields` on surfaced ids, looking for fields the guest should not see.
4. `getObjectInfo` for FLS; look for sensitive custom fields.
5. Harvest Apex names, then call them through `ApexActionController` or `/webruntime/api/apex/execute`.
6. Download content by key prefix. Save every response as evidence.

`sf-guest-map.py` automates steps 1, 2 and 4, the counts of step 3 and the name harvest of step 5, read-only. It does not read individual records, call Apex or download files; those steps need a human decision on the minimum data that proves exposure.

## Finding versus working as designed

Never submit the first list:

- Success with zero rows on a standard object.
- Public help content: Knowledge articles, Topics, hero and logo images, site `Network` configuration.
- A list returning only the guest's own site-user profile.
- Config files holding only org-bound or encrypted managed-package license blobs and pod names.
- A parameter that changes results within your own entitlement.
- SOQL metacharacters reflected in an error with no out-of-filter data.

Reportable:

- A business object returning customer or user rows.
- A record read returning another user's fields.
- A guest-readable secret field.
- A guest-invocable `without sharing` method.
- A download of an internal or customer document.
- Injection returning out-of-filter data.
- An accepted arbitrary-object write.

Apply the harm check: retrieve the minimum data, redact PII, revert every write.

## Severity ceiling

The realistic ceiling is Critical: guest-readable credentials or PII, `without sharing` Apex, SOQL injection dumping an object, arbitrary DML. The modal outcome on a hardened org is Low. Secure Guest User Record Access (default since Winter '21) strips the guest from most sharing paths, and `with sharing` as the default (since 2019) closes casual injection. State the ceiling honestly per target.

Small misconfigurations compound. A real-world critical chain in this class combined an over-broad guest profile (hundreds of fields and dozens of tabs exposed), unauthenticated reads of internal Knowledge and custom objects, no rate limiting or guest-activity monitoring, and loose FLS/OLS into bulk PII exfiltration. The guest data lane is often the anchor.

## Tooling

- `specter/scripts/sf-guest-map.py`: this repo's read-only guest mapper.
- aura-dump (community): dumps objects, fields and Apex given credentials.
- Salesforce CLI (`sf`) and Salesforce Inspector: authenticated, for an org you are authorized in (program-provisioned test org, your own portal user, or your own developer org).
- Salesforce Code Analyzer and PMD (Apex ruleset): static review once you can read Apex and Visualforce source.

Automated tools miss business logic; manual review still finds the logic flaws.

## Open lanes

Authenticated portal-user testing (cross-user record access, guest-to-authenticated boundary, create and update authorization); Chatter and `ConnectApi` feeds; Aura component-registry enumeration; a CRUD/FLS write matrix; blind SOQL injection variants; connected-app and OAuth surface; the REST and Bulk API layers behind the site.
