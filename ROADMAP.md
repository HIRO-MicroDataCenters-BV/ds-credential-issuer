# ds-credential-issuer — roadmap

## Phase 1 — scaffold + mint (this PR)

- [x] Repo bootstrap: develop + main branches, LICENSE, pyproject, CI
- [x] Settings via env (`DS__` prefix, nested `__` delimiter)
- [x] Issuer identity via HCF's dkms-bin (`core/issuer_identity.py`) —
      creates the per-site issuer AID on first boot
- [x] ACDC mint (`core/acdc_issuer.py`) — signs with issuer's current key
- [x] `POST /credentials` endpoint fully implemented
- [x] IPEX grant wrapper matching `ds-login/app/core/ipex_grant.py` shape
- [x] ds-auth optional integration (same pattern as ds-policy-engine, ds-catalog)
- [x] FastAPI OpenAPI with every endpoint declared (stubs return 501)
- [x] Dockerfile (multi-stage, dkms-bin baked in)
- [x] Helm chart (deployment + service + PVC + optional ingress + optional ds-auth env)
- [x] CI: ruff + mypy + pytest + docker build-push on push to develop

## Phase 2 — full IPEX scope (follow-up PRs, one endpoint per PR)

- [ ] **TEL registry wiring** — anchor every mint as an issuance event in a
      KERI TEL.
- [ ] **`GET /credentials?subject=<aid>`** — list credentials this issuer
      has minted, filtered by subject. Reads from the registry.
- [ ] **`GET /credentials/{said}`** — fetch state (issued / revoked /
      issued-at timestamp).
- [ ] **`POST /credentials/{said}/revoke`** — anchor a revocation event.
      Idempotent.
- [ ] **Schema registry** — SQLite table of trusted ACDC schemas by SAID;
      `GET /schemas`, `GET /schemas/{said}`, `POST /schemas`. Minting
      refuses unknown schema SAIDs once the registry is populated.
- [ ] **Mesagkesto client** (`core/mesagkesto_client.py`) — delivers IPEX
      grants to a recipient AID. Backs `POST /credentials/{said}/present`.
- [ ] **Full IPEX `exn` wrapping** — current grants are a pragmatic JSON
      shape ds-login understands. Phase 2 wraps them in KERI `exn`
      messages so wallets that speak full IPEX natively can forward them.

## Phase 3 — operational hardening

- [ ] Multi-sig issuance (threshold > 1) — commit a second-signer policy
      to the issuer habitat and enforce before mint.
- [ ] Key rotation — periodic rotation ceremony, publish the new keys
      through witnesses, keep the TEL / historical signatures verifiable.
- [ ] Audit stream — every mint / revoke emitted to `ds-clearing-house`.
- [ ] Metrics (Prometheus) — mint rate, revoke rate, failure counts, TEL
      size.
- [ ] Rate limiting per authenticated caller.

## Phase 4 — federation + wallet UX

- [ ] Wallet-facing issuance UI (invite link → wallet picks up grant).
- [ ] Cross-site issuer discovery via DKMS watcher.
- [ ] Partner-trust posture surfaced to verifiers (eg "HUS-issued" badge).
