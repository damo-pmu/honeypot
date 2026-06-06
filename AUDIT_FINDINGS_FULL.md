# Audit Findings — Full Technical Details

Date: 2026-06-06

This file contains exhaustive findings extracted from static analysis of the repository under `honeypot/`.

--

1) Template keys and generators

- `RESPONSE_TEMPLATES` keys (from `src/response/router.py`):
  - `cisco_router/show_version` ([src/response/router.py](src/response/router.py#L67-L76))
  - `ai_challenge/cognitive_trap` ([src/response/router.py](src/response/router.py#L76-L84))
  - `windows_server/credentials` ([src/response/router.py](src/response/router.py#L84-L92))
  - `jenkins_instance/config` ([src/response/router.py](src/response/router.py#L92-L100))
  - `cisco_router/running_config` ([src/response/router.py](src/response/router.py#L100-L109))

- Decoy generators (return `template_name`) in `src/response/fake_env.py`:
  - `generate_cisco_decoy` → `template_name="cisco_router"` ([src/response/fake_env.py](src/response/fake_env.py#L36-L50))
  - `generate_windows_decoy` → `template_name="windows_server"` ([src/response/fake_env.py](src/response/fake_env.py#L52-L93))
  - `generate_jenkins_decoy` → `template_name="jenkins_ci"` ([src/response/fake_env.py](src/response/fake_env.py#L94-L131))

- Whitelist in `SafetyIsolator.ALLOWED_TEMPLATES` (`src/response/safety.py`):
  - `cisco_router/show_version`, `cisco_router/running_config`, `cisco_router/show_arp`, `cisco_router/show_cdp`
  - `windows_server/credentials`, `windows_server/web_config`, `windows_server/notes`
  - `jenkins_ci/config`, `jenkins_ci/users`, `jenkins_ci/secrets`
  - `ai_challenge/cognitive_trap`, `adversarial/timing_challenge`, `adversarial/context_trap` ([src/response/safety.py](src/response/safety.py#L28-L46))

*Finding — mismatch:* `router.py` references `jenkins_instance/config` but `fake_env.py` uses `jenkins_ci` and `safety.py` allows `jenkins_ci/*`. This will cause `SafetyIsolator.validate_response` to reject `jenkins_instance/config` responses as not allowlisted.

--

2) Secret-like literal occurrences (file / excerpt)

- `src/response/fake_env.py`:
  - NTLM-like string in SAM file: `Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::` ([src/response/fake_env.py](src/response/fake_env.py#L56-L60))
  - Connection string with `Password=SuperSecret123!` ([src/response/fake_env.py](src/response/fake_env.py#L62-L65))
  - TODO with `Old: admin123` / `New: Summer2024!` ([src/response/fake_env.py](src/response/fake_env.py#L66-L69))
  - SSH key-like fragment: `ssh-rsa AAAAB3NzaC1yc2E... fake-key-for-attacker` ([src/response/fake_env.py](src/response/fake_env.py#L75-L78))

- `src/response/router.py`:
  - `cisco_router/running_config` contains `username admin privilege 15 secret 5 $1$vXJt$kHJvqUeXZJfHQhVvJQvJQv` ([src/response/router.py](src/response/router.py#L111-L113))
  - `windows_server/credentials` contains NTLM-like hash `Administrator:500:...` ([src/response/router.py](src/response/router.py#L113-L116))

- Tests (sample sensitive fixtures):
  - `tests/test_response_security.py` includes a private key stub and `Contact: admin@hiddenlabs.cc` ([tests/test_response_security.py](tests/test_response_security.py#L66-L76)).
  - `tests/test_response_engine.py` includes `-----BEGIN RSA PRIVATE KEY----` and sample contact strings ([tests/test_response_engine.py](tests/test_response_engine.py#L80-L94)).

*Finding — risk:* these literals are intentionally fake for decoys/tests, but they resemble real secrets. Ensure they are clearly marked FAKE and that CI has a scanner preventing accidental inclusion of real keys.

--

3) Environment variables / provider keys inconsistencies

- `.env.example` contains `API_KEY_OPENROUTER` ([.env.example](.env.example#L11-L12)) while `docker-compose.yml` injects `OPENROUTER_API_KEY=${API_KEY_OPENROUTER:-demo}` ([docker-compose.yml](docker-compose.yml#L14-L16)).
- Tests expect `OPENROUTER_API_KEY` (see `tests/test_llm_provider.py` where `OPENROUTER_API_KEY` is set) ([tests/test_llm_provider.py](tests/test_llm_provider.py#L20-L22)).
- `LOCAL_LLM_MODEL` is used by the local LLM classifier and tested in `tests/test_response_security.py`.

*Finding — risk:* mismatch of variable names leads to operational confusion. Standardize on a single env var (recommendation: `OPENROUTER_API_KEY` for provider, and `LOCAL_LLM_MODEL` for local path) and update `.env.example` and `docker-compose.yml`.

--

4) Auth / endpoint exposure mapping

- All API routers in `src/api/endpoints` generally depend on `get_db()` (DB session) but do not use an authentication dependency by default (`Depends(require_auth)` or an OAuth dependency) — this matches current design where many endpoints are public.
- `dashboard` router implements cookie-based auth logic using `src/api/middleware/session.py` and uses `DASHBOARD_PASS` (env `DASHBOARD_PASS`) for the login check. Some dashboard API endpoints are intentionally public (see `get_live_feed` and `get_live_feed_public`).

List of endpoints (file → notable auth behavior):
- `src/api/endpoints/dashboard.py` — templated UI: `/dashboard/` served publicly (commented TEMPORARY), `/dashboard/login` handles password via `DASHBOARD_PASS`; some API routes are public per code comments.
- `src/api/endpoints/*` other routers (attackers, sessions, commands, ioc, enrichment, response, analytics, attacks) do not apply authentication middleware — accessed publicly.

*Finding — recommendation:* document which endpoints must remain public (for Cloudflare/Grafana compatibility) and which must be restricted. Add optional `require_auth` dependency to sensitive endpoints and gate via env-configured toggles.

--

5) Identifier model inconsistencies

- `src/core/database.py`: `AttackerDB` uses `ip` as primary key (Column String(45), primary_key=True) ([src/core/database.py](src/core/database.py#L14-L30)).
- `src/api/endpoints/attackers.py`: API returns numeric `attacker_id` computed by enumerating DB rows (1-based) rather than returning `ip` — this creates mismatch between API docs expecting `{attacker_id}` and DB primary key (`ip`). ([src/api/endpoints/attackers.py](src/api/endpoints/attackers.py#L30-L60)).
- `src/api/endpoints/sessions.py`: `SessionCreate` model doesn't define `id` but `create_session` later reads `session.id` when building `SessionDB` (possible AttributeError if caller omits id). ([src/api/endpoints/sessions.py](src/api/endpoints/sessions.py#L16-L64)).

*Finding — risk:* API consumers may be confused; possible runtime errors. Decide canonical identifiers (prefer stable string UUIDs for sessions and use `ip` for attackers or add numeric `id` field in DB) and update code/docs.

--

6) TODOs and developer markers

- `src/response/fake_env.py` contains `TODO: Change password before vacation` with real-like password examples ([src/response/fake_env.py](src/response/fake_env.py#L66-L69)).
- `PLANS/dashboard-modern-plan.md` references `DASHBOARD_PASSWORD=xxx` as placeholder.

--

7) Recommended quick checks / CI additions

- Add a secrets scan step in CI using `detect-secrets` or `gitleaks` configured to fail on real private keys and long token patterns.
- Add unit tests:
  - Verify all `template_name` returned by generators (`get_decoy_by_template`, `generate_*`) belong to `SafetyIsolator.ALLOWED_TEMPLATES` (or align keys).
  - Verify `create_session` POST accepts/returns expected `id` behavior (client-provided vs server-generated). Add schema test.
  - Validate `.env.example` matches `docker-compose.yml` injected variables.

--

Appendix: quick file pointers (evidence)

- Templates & response: `src/response/router.py`, `src/response/fake_env.py`, `src/response/safety.py`.
- Secrets-like literals: `src/response/fake_env.py`, `src/response/router.py`, `tests/test_response_security.py`, `tests/test_response_engine.py`.
- Env files: `.env.example`, `.env.local.example`, `docker-compose.yml`, `tests/test_llm_provider.py`.
- API endpoints: `src/api/endpoints/*` and `app.py` mounting routers.

--

If you want, I can now produce precise patch(es) for Phase 1 (template unification, replace fake secrets with FAKE_* placeholders, align env var names, fix session/session-id behavior) and include unit tests. Confirm if you want (A) automatic patch apply, (B) generate PR/patch for review, or (C) stop after this audit.
