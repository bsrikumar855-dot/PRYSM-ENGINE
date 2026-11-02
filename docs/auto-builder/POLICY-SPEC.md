# PRYSM policy & decision specification v1.1 (normative for M1)

v1.1 (2026-10-30) adds rulings for 15 ambiguities and 3 design holes found by the independent labeller (DEC-19): see §1 load rules, §2 domain `accept`, §3, §4 guidance, §5, §6.

Source of truth for `src/core`. Expected results in the evaluation corpus are derived **from this document**, not from the code. Implements DEC-02, DEC-04, DEC-07. If the spec is ambiguous, the engine must deny and the ambiguity is a spec bug to be logged in DECISIONS.md.

## 1. Policy document (strict JSON)

```json
{
  "policy_schema_version": 1,
  "name": "support-agent",
  "mode": "enforce",
  "tools": {
    "send_email": {
      "risk": "high", "external_effect": true, "read_only": false, "fail_mode": "closed",
      "args": { "to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"},
                "cc": {"type": "string", "optional": true} }
    }
  },
  "rules": [
    { "id": "email.corp-only", "effect": "permit", "reason_code": "email_corp",
      "match": { "tools": ["send_email"],
                 "args": { "to": {"domain_suffix": "corp.com"} },
                 "provenance": { "to": {"all_in": ["trusted-user", "policy-constant"]} } } }
  ]
}
```

- `mode`: `"enforce"` or `"monitor_only"`. Part of the hash. `decide()` computes the same decision in both modes; the guard (M2) implements monitor semantics.
- `tools[name]`: `risk` ∈ low|medium|high; `external_effect` bool; `read_only` bool; `fail_mode` ∈ `closed` | `open_on_audit_failure` (only legal when `risk`=low and `read_only`=true); `args` map name → `{type, optional?}` with `type` ∈ string|number|boolean|string[]. Optional `schema_hash` (string) is stored for M3 proxy pinning, not used by `decide()`.
- `rules[]`: `id` (unique), `effect` ∈ permit|deny, `reason_code` (identifier), `match` object. No priority, no specificity, no other effects.
- `match` keys (all optional; all present keys must hold = AND; empty `match` object is **rejected at load**): `agents` string[] (agentId ∈ list), `scopes_any` string[] (ctx.scopes ∩ list non-empty), `tools` string[] (must name tools that exist in `tools`), `args` {argName: predicate} (argName must be declared for **every** tool in `tools` if `tools` present, else declared for at least one tool), `provenance` {argName: {all_in?: string[], any_in?: string[]}}, `session_tainted` bool.
- `policy_schema_version` must be the number `1` (missing, `"1"`, other ⇒ load error). Empty `rules: []`, `tools: {}` and `args: {}` are legal. Load errors also for: predicate/arg-type mismatch (`range` on a non-number arg; `glob`/`max_length`/`domain_*`/`path_within` on a non-string arg — `string[]` args count as string; `equals`/`in` literal types not matching the arg type); `in: []`; `range` with `min` > `max` or non-finite bounds; `max_length` not a non-negative integer; `case_insensitive` not a boolean; a predicate object with zero or more than one operator key; `match.provenance` keys not declared (same rule as `match.args`); raw byte-order-mark `EF BB BF` prefix on byte input.
- Unknown keys anywhere ⇒ load error. Duplicate JSON keys ⇒ load error. Keys `__proto__`, `constructor`, `prototype` ⇒ load error. BOM ⇒ load error. Strings must not contain control chars (U+0000–U+001F, U+007F–U+009F), zero-width (U+200B–U+200F, U+2060, U+FEFF), bidi controls (U+202A–U+202E, U+2066–U+2069). Identifiers (`name`, tool names, arg names, rule ids, reason codes, agent ids/scopes in `match`) match `^[A-Za-z0-9_.:-]{1,64}$` (tool/arg names without `:`; provenance labels also allow `:`). Limits: file ≤ 1 MiB, ≤ 1000 rules, ≤ 256 entries per list, nesting depth ≤ 8.

## 2. Predicates (on argument values)

Strings are compared after Unicode NFC. No type coercion: a predicate on a value of the wrong type does not match.
- `{"equals": v}` strict equality (string|number|boolean).
- `{"in": [v…]}` ≤256 entries, strict equality, same type rules.
- `{"glob": "pat"}` only `*` (zero or more of any char including `/`) and `?` (exactly one code point); case-sensitive; linear-time iterative matcher; whole-string match. Pattern length ≤ 256.
- `{"range": {"min"?: n, "max"?: n}}` number, finite, inclusive; `-0` treated as `0`; NaN/Infinity can't occur (rejected at snapshot).
- `{"max_length": n}` string length in code points ≤ n.
- `{"domain_suffix": "corp.com", "accept": ["email"]}` / `{"domain_exact": "docs.corp.com", "accept": ["url"]}` — `accept` is **required**, a non-empty subset of `"url"`, `"email"`, `"host"`; the argument must be in one of the accepted forms (§3) or the predicate does not match. Policy values must already be lowercase ASCII LDH hostnames (no trailing dot, no wildcard, no IP literal) else load error.
- `{"path_within": {"root": "/workspace", "case_insensitive": false}}` — see §4. `case_insensitive` is **required**. `root` must be absolute and already normalised (no `.`/`..`/`//`/trailing slash except root `/`). **Guidance:** `glob`/`equals`/`in` operate on the raw string and are NOT path-safe; use `path_within` for every path rule, and use `case_insensitive: true` on *deny* path rules.

String-array args (`string[]`): quantification depends on rule effect (v1.2, §10.1): a **deny** rule matches if **any** element satisfies the predicate, a **permit** rule only if **all** elements do; an empty array matches neither (so a deny rule cannot block an empty-array call, and the 'deny if present' idiom of §10.9 does not apply to `string[]`).

## 3. Host extraction and domain matching

Pre-checks on the raw argument string (any failure ⇒ predicate does not match): no non-ASCII code point (> U+007F) anywhere; no whitespace or control characters anywhere (leading/trailing included); no backslash `\` anywhere; no `%`.
Forms (the predicate's `accept` list decides which are tried; the form is chosen by the string's shape, not tried in turn):
- **url** — contains `://`: parse with WHATWG `URL` (parse exception ⇒ no match); scheme must be `http` or `https`; username and password must be empty; host = `url.hostname`.
- **email** — contains `@` and no `://`: exactly one `@`; local part must match `^[A-Za-z0-9._+-]{1,64}$`; host = text after `@`; that text must not contain `/ ? # : [ ]`.
- **host** — anything else: must not contain `/ ? # : [ ]` or `@`; host = the string.
A string whose shape is not in `accept` ⇒ no match (e.g. `mailto:bob@corp.com` has `@` and a local part with `:` ⇒ no match; a bare host or URL in an `email`-only predicate ⇒ no match).
Then: `URL.domainToASCII`; empty ⇒ no match; lowercase; strip exactly one trailing `.`; reject if empty label, label >63 chars, total >253, any char outside `[a-z0-9-]` and `.`, a label starting/ending with `-`; if the final label is all digits (IPv4-like, any WHATWG-normalised form) ⇒ no match. IP literals never satisfy domain predicates.
`domain_exact`: host === value. `domain_suffix`: host === value **or** host ends with `"." + value` (dot boundary). The URL parser's view of the host is authoritative; tools must use the same parser (sink duty).

## 4. Lexical path matching (`path_within`)

Lexical only; symlinks/junctions are the sink's duty (guard helper in M2). Algorithm on a string value (after NFC):
1. No match if it contains NUL, a `%` followed by two hex digits (percent-encoding, any case), a `:` anywhere except as the 2nd char of a drive prefix `X:`, a `?` or `*` or `"` `<` `>` `|`, or starts with `\\` (UNC / `\\?\` / `\\.\`) or `//`.
2. Replace `\` with `/`. Must be absolute: starts with `/` or `X:/` (drive letter; drive upper-cased). Relative ⇒ no match.
3. Split on `/`, drop empty and `.` segments, resolve `..` (a `..` above the root ⇒ no match). Any segment that, ignoring case, is a Windows reserved device name (CON, PRN, AUX, NUL, COM1–9, LPT1–9), optionally followed by `.ext`, ⇒ no match; any segment ending in `.` or space ⇒ no match; any segment matching `^[^.]{1,8}~\d+` (8.3 short name) ⇒ no match.
4. Recompose `/seg/seg` (drive prefix preserved). If `case_insensitive`, lowercase both sides (ASCII + Unicode `toLowerCase`).
5. Match iff normalised === root or starts with `root + "/"` (root `/` matches every absolute path without a drive prefix).

## 5. Request and snapshot

`decide(policy, request)` input: `{ tool: string, args: object, ctx: { agentId: string, userId?: string, scopes?: string[], sessionTainted?: boolean, provenance?: { [argName]: string[] } } }`. Shape is strict: top-level keys exactly `tool`, `args`, `ctx`; `ctx` keys only those listed; `ctx` missing/null/non-object, `agentId` missing or not a non-empty string, `args` missing/null/array/non-object, wrong-typed ctx fields (`userId` not string, `scopes` not string[], `sessionTainted` not boolean, `provenance` not a map of string[]), or unknown keys at either level ⇒ **deny `invalid_request`**. Depth counts the request root object as depth 1; size = UTF-8 bytes of `JSON.stringify(request)`.
Snapshot rules (`snapshotRequest`) — reject with `invalid_request` unless the whole request is **plain JSON data**: only null/boolean/finite number/string/array/plain object (prototype `Object.prototype` or `null`), no accessors, no Proxy, no symbols, no cycles, no sparse arrays, no `undefined`, no BigInt, no `-0` (normalised to 0), no lone surrogates. Keys `__proto__`/`constructor`/`prototype` rejected. Limits: JSON size ≤ 64 KiB, depth ≤ 8, ≤ 64 keys per object, ≤ 256 array items, strings ≤ 8192 code units — exceed ⇒ `limit_exceeded`. Result is a deep-frozen deep copy; **this copy is what the tool must receive.** A provenance label not matching `^[A-Za-z0-9_.:-]{1,64}$` (including empty or >64 chars) ⇒ `invalid_request`; `ctx.provenance` keys must be declared args of the tool, otherwise `invalid_request` (checked only once the tool is known, see §6 step 3b); tags never come from `args`.

## 6. Decision algorithm (total, deterministic, order-independent)

Reason codes (stable enum): `permitted`, `denied_by_rule`, `default_deny`, `unknown_tool`, `invalid_args`, `invalid_request`, `limit_exceeded`, `tainted_session`, `engine_error`, `audit_unavailable` (guard-only).

1. Snapshot failure ⇒ **deny** `invalid_request` / `limit_exceeded`.
2. `tool` not in policy ⇒ **deny** `unknown_tool`.
3. Args strict: every key in `args` must be declared; every non-optional declared arg present; types match (`string[]` = array of strings) ⇒ else **deny** `invalid_args`.
3b. `ctx.provenance` keys not declared args of the tool ⇒ **deny** `invalid_request`. (So an unknown tool with a bad provenance key yields `unknown_tool`.)
4. For each rule (iterated in any order — result must not depend on order) compute `matches`:
   - `agents`/`scopes_any`/`tools`/`session_tainted` (`session_tainted: true` matches iff `ctx.sessionTainted === true`; `false` iff not true).
   - `args` predicate for arg `a`: if `a` present ⇒ evaluate predicate; if absent (optional arg) ⇒ **no match** for both effects (safety comes from default deny and strict args, not from absent-arg polarity; there are no negated predicates).
   - `provenance` for arg `a`: labels = `ctx.provenance[a]` if given and non-empty, else `["untrusted:unknown"]`. `all_in` ⇒ every label ∈ list; `any_in` ⇒ at least one label ∈ list. If `a` absent (optional) ⇒ no match.
5. Let D = matched deny rules, P = matched permit rules.
6. If D non-empty ⇒ **deny** `denied_by_rule`.
7. Else if `ctx.sessionTainted === true` and tool.`external_effect`: permit only if some P rule has `match.session_tainted === true`; otherwise **deny** `tainted_session`.
8. Else if P non-empty ⇒ **permit** `permitted`.
9. Else ⇒ **deny** `default_deny`.
10. Any thrown exception inside `decide()` ⇒ **deny** `engine_error` (never rethrow, never fail open).

Result: `{ effect, reason_code, matched: { deny: ruleId[], permit: ruleId[] } (sorted ascending by id), policy_version, mode, trace: [{rule, matched, why}…] (sorted by id) }`. No wall-clock, randomness, network, locale-dependent comparison (use code-point order), or mutable state.

## 7. Policy version

`policy_version = "sha256:" + hex(SHA-256(UTF-8(JCS(parsedPolicy with rules sorted by id))))` (v1.2, §10.6), JCS = RFC 8785 (keys sorted by UTF-16 code units, ECMAScript number serialisation). Two files that parse to the same document have the same version; any semantic change (including `mode`) changes it. Loader reads bytes once; hashes and parses that same buffer. Loaded policy is deep-frozen.

## 8. Public API (src/core/index.ts)

`loadPolicy(bytes: Uint8Array|string): LoadedPolicy` (throws `PolicyError{code,path,message}`; messages never echo values longer than 40 chars) · `snapshotRequest(x): Request` (throws `RequestError{code}`) · `decide(policy, request): Decision` (never throws; guards should use `evaluate(policy, raw) → {decision, snapshot|null}` and pass the snapshot to the tool, only when `decision.effect === "permit"`; the snapshot may be non-null on deny, and `request_digest` is the digest of the NFC-normalised snapshot, not of the raw input — §10.5) · `jcs(value): string` · `hostFromString`, `matchPathWithin`, `globMatch` exported for tests.

## 9. Rulings appendix (v1.1.1, from second labelling round; DEC-20)
1. A predicate with keys beyond its operator (e.g. `accept` on `glob`) ⇒ load error (unknown key).
2. Request `tool` not a string ⇒ deny `invalid_request`.
3. Depth counts containers only; scalar leaves add no level.
4. Any request/ctx label that violates the label pattern ⇒ `invalid_request` even when the tool is unknown (label check is step 1; only the *undeclared-key* check waits for step 3b).
5. `policy_schema_version` is accepted iff its parsed value is the number 1 (`1.0`, `1e0` accepted).
6. Duplicate entries in `accept` are legal (set semantics).
7. Empty lists in `match` (`agents`, `scopes_any`, `tools`, `all_in`, `any_in`) and an empty `range` ⇒ load error.
8. WHATWG-dependent cases (e.g. `https://@corp.com/`) are not labelled; behaviour follows Node's `URL` and is covered only by the sink-parity duty.

## 10. v1.2 amendments (M1 review pass; DEC-21). These supersede earlier text where they conflict.
1. **string[] quantification depends on effect (F-01).** A predicate on a `string[]` arg: in a **deny** rule it matches if **any** element satisfies it; in a **permit** rule it matches only if **all** elements satisfy it. Empty array ⇒ no match for both effects. `provenance` is unaffected.
2. **Work bounds (F-02, F-05).** The request walk counts *every visit* (shared references are visited each time they are reached): total containers visited ≤ 4096, total nodes ≤ 16384, and the running byte estimate is checked at every node, entry and element — exceeding any ⇒ `limit_exceeded`. `decide()` has a deterministic work budget of 5,000,000 glob steps (not wall-clock); exceeding ⇒ deny `limit_exceeded`. A glob may contain at most 4 `*` (load error otherwise). Pattern NFC and code-point arrays are computed once at load.
3. **path_within is ASCII-only (F-04, F-06, F-09).** A path value containing any non-ASCII code point ⇒ no match; policy roots must be ASCII (load error). Reserved device names additionally include `CONIN$` and `CONOUT$` (case-insensitive, with or without extension). Consequence: non-ASCII file names are unsupported in the MVP (they default-deny); this is documented, not a bug.
4. **Snapshot normalises (F-09).** `snapshotRequest` returns string values and object keys in NFC; the tool must receive the snapshot, so the compared string is the used string.
5. **Evaluate API (F-03).** `evaluate(policy, raw) → { decision, snapshot: Request | null }` snapshots once and decides on that snapshot (`snapshot` is null when the snapshot step fails). `isSnapshot(x)` and `toolInfo(policy, name) → {risk, external_effect, read_only, fail_mode} | undefined` are exported. `Decision` gains `request_digest` (`sha256:` hex of JCS(snapshot); `null` when no snapshot) and `matched_reasons: [{id, effect, reason_code}]` sorted by id. A non-loaded policy ⇒ deny `engine_error` with `policy_version: "unknown"`. The guard applies its own fail-closed default for tools `toolInfo` does not know (treat as high-risk, `fail_mode` closed). Guards must call `evaluate` and pass `snapshot` (never the raw object) to the tool.
6. **Policy version (A-07).** Hash is over JCS of the parsed policy with `rules` sorted by `id` (ids are unique), so reordering rules does not change `policy_version`.
7. **Forbidden characters in policy strings** additionally: U+00AD, U+034F, U+061C, U+180E, U+2028, U+2029, U+FFF9–U+FFFB, U+FE00–U+FE0F, U+E0000–U+E007F. Source files must write these as `\u` escapes.
8. **`accept` duplicates are deduplicated before the 256-entry cap.**
9. **Idiom — "deny if present":** `{"max_length": 8192}` on an optional **string** arg denies whenever the arg is present (any string ≤ the request limit), since an absent optional arg matches nothing. It does not work for `string[]` args (an empty array matches neither effect).
10. **Extra strictness already implemented (documented):** path values starting `/\` or `\/` after conversion, a reserved name rejected even if a later `..` pops it, empty `match.args`/`match.provenance` objects rejected at load, and a rule predicate whose arg type conflicts across tools (no `tools` clause) rejected at load.

## 11. v1.3 amendments (M1 pass 3; DEC-22)
11. **Tri-state matchers (N-01).** `path_within` and `domain_suffix`/`domain_exact` return `match`, `no_match` or `unparseable` (the value is not a path/host/URL/email the matcher can interpret: non-ASCII path, `%`, reserved name, bad host form, wrong accept form …). In a **deny** rule `unparseable` counts as a match; in a **permit** rule it counts as no match. For `string[]` args the effect-dependent any/all quantification (§10.1) applies to these tri-state results (deny: any element match-or-unparseable; permit: all elements match). Rationale: a deny rule must not be bypassed by a value the matcher cannot parse while a broader permit of another predicate kind matches.
12. **Metered work (N-02).** Every predicate evaluation charges the shared deterministic work budget (glob steps as before; path/host normalisation charge one step per code unit of the value); results of `normalizePath`/`hostFromString` are cached per (value, form) within one `decide()`. Exceeding the budget ⇒ deny `limit_exceeded`. A 1000-rule policy against a maximal `string[]`/8192-char value must finish in ≤ 250 ms on the dev machine.
13. **Immutability (N-03).** `toolInfo()` returns a frozen copy; compiled policy structures (maps, sets, arrays) are frozen at compile time.
14. **Forbidden characters (N-04/F-07).** Policy strings reject any code point in `\p{Cf}`, `\p{Zl}`, `\p{Zp}`, `\p{Cc}`, `\p{Co}`, `\p{Cn}` and any non-ASCII whitespace (`\p{Zs}` other than U+0020) — a scan of all code points through `loadPolicy` must reject each. (Supersedes the enumerated list in §10.7; source files still use `\u` escapes or Unicode property classes.)
15. **Clarification of "unparseable" (ruling after second v1.3 labelling).** `unparseable` means the matcher could not interpret the value at all: for `path_within` every no-match cause of §4 steps 1–3 (non-ASCII, `%`-hex, NUL/control, `: ? * " < > |`, UNC or `//` start, relative or empty path, `..` above root, reserved device name, segment ending in `.` or space, 8.3 short name); for domain predicates every pre-check, form, host-normalisation or IP-literal rejection of §3. `no_match` means a normalised absolute path / valid host was obtained and it is simply outside the root / not the suffix. Consequence for explanations: such calls report `denied_by_rule` naming the deny rule, and the trace marks the match as `unparseable`.

## 12. v1.4 rulings from the independent differential run (DEC-37; 100 000 cases, seed 20261102; second implementation written without reading src/core). Supersede earlier text where they conflict.
1. **Precedence of limits over validity.** When a request violates both a resource limit (§5: total bytes, depth, key/item/string/visit counts, work budget) and a validity rule (non-plain value, symbol key, Proxy, lone surrogate, bad label, forbidden key), the result is `limit_exceeded`. Rationale: limits bound the work done before validity is established. Both deny. (The independent reference had chosen the opposite order; it is changed to match.)
2. **Size is measured on the NFC snapshot.** The 64 KiB request limit applies to the UTF-8 bytes of `JSON.stringify` of the **NFC-normalised snapshot**, i.e. exactly what the tool would receive. Raw pre-NFC size is not the measure. (A request that is 65 537 raw bytes but 65 536 after NFC is within the limit.)
3. **`path_within` roots may be drive-prefixed.** A root such as `C:/work` is accepted when it is absolute, already normalised and has an **uppercase** drive letter; matching against drive-prefixed values follows §4 (drive letter upper-cased before comparison). A root `/workspace` never matches a drive-prefixed path and vice versa.
4. **Argument type conflicts without a `tools` clause.** A rule predicate with no `tools` clause is checked against every tool that declares that argument; `string` and `string[]` are compatible for the predicates defined on strings (§1 counts `string[]` as string), so such a predicate loads. A load error arises only when the predicate's required type is incompatible with one of the declared types (for example `range` on a tool where the argument is a string).
5. **Other deny-safe readings adopted from the reference's ambiguity list (documented, no behavioural change):** forbidden characters in policy strings are the union of §10.7 and §11.14; glob pattern length counts UTF-16 code units; every control character in a path is "unparseable"; the reserved-name, trailing-dot and 8.3 checks apply to every segment encountered including segments a later `..` removes; two keys that collide after NFC make the request `invalid_request`; the size measure is exact, not an estimate; policy documents require `name`, `mode`, `tools`, `rules` and each tool's `args`.
