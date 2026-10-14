# ds-credential-issuer

**Per-node ACDC credential issuer** for the Hiro NextGen EU dataspace. Mints verifiable credentials, anchors them to a KERI TEL registry, and delivers them as IPEX grants that [ds-login](https://github.com/HIRO-MicroDataCenters-BV/ds-login) verifies under the **open-federation** trust model (any DKMS-anchored issuer is accepted).

One instance per site. HUS, KI, UVA each run their own; so can partner organisations.

## Where it sits

```
operator ──POST /credentials──▶ ds-credential-issuer
                                 │ KERIpy habery
                                 │ (per-site AID + LMDB keystore + TEL)
                                 │
                                 ▼
                                 anchor issuance event
                                 ──────────────▶ DKMS witness(es)
                                                     │
                                 ◀───── IPEX grant ──┘
                                 (ACDC + sig + OOBIs for the issuer's witnesses)

operator ──deliver grant to user────▶
                                             user wallet ──POST /login/verify──▶ ds-login
```

## Endpoints

| Method | Path                             | Permission       | Phase | Purpose |
|--------|----------------------------------|------------------|-------|---------|
| POST   | `/credentials`                   | `issuer:write`   | 1     | Mint an ACDC bound to a subject AID, return an IPEX grant |
| GET    | `/credentials`                   | `issuer:read`    | 2     | List credentials (filter by subject) |
| GET    | `/credentials/{said}`            | `issuer:read`    | 2     | Fetch one credential's state |
| POST   | `/credentials/{said}/revoke`     | `issuer:write`   | 2     | Anchor a revocation event to the TEL |
| POST   | `/credentials/{said}/present`    | `issuer:write`   | 2     | Deliver a grant via mesagkesto |
| GET    | `/schemas`                       | `issuer:read`    | 2     | List registered ACDC schemas |
| GET    | `/schemas/{said}`                | `issuer:read`    | 2     | Fetch one schema |
| POST   | `/schemas`                       | `issuer:admin`   | 2     | Register a new ACDC schema |
| GET    | `/health-check/`                 | public           | 1     | Liveness + exposes issuer AID |

Phase 1 (this scaffold) implements the mint endpoint fully; Phase 2 endpoints return `501 Not Implemented` with a ROADMAP pointer so nothing ships half-finished.

## Running locally

```bash
cd server
poetry install --with dev,test
export DS__ISSUER__HABERY_PATH=./dev-keystore
export DS__ISSUER__WITNESS_URLS='["http://localhost:3232"]'
poetry run uvicorn app.main:app --host 0.0.0.0 --port 8080
```

The first boot creates a new issuer AID at `./dev-keystore/`; subsequent boots reopen it. The AID is logged + exposed by `GET /health-check/`.

## Deployment

Helm chart in `server/charts/ds-credential-issuer/`. Per-site values live in `ds-gitops/<site>-services/credential-issuer/values.yaml` and point the issuer at that site's DKMS (witnesses + mesagkesto) and ds-policy-engine for auth.

A minimum site values file:

```yaml
image:
  tag: "develop"

issuer:
  name: hus-issuer
  witnessUrls:
    - http://ds-dkms-witness-1:3232
  witnessOobis:
    - "https://dkms-witness-1.hus.nextgen.hiro-develop.nl/oobi/<witness-AID>"
  mesagkestoUrl: http://ds-dkms-mesagkesto:8081

auth:
  enabled: true
  jwksUrl: http://ds-login:8080/.well-known/jwks.json
  policyEngineUrl: http://ds-policy-engine:8000

persistence:
  size: 2Gi
```

## Trust model

**Open federation**: any DKMS-anchored issuer AID is a valid issuer. Verifiers (`ds-login`) resolve the issuer's KEL by querying witnesses directly at the URLs embedded in each IPEX grant and verify the issuer signature against the issuer's live current signing key. No central allowlist — the chain of trust is anchored in KERI's own cryptography.

Access control for *this* service (who gets to call `POST /credentials`) is a separate concern, enforced via `ds-auth` using the `issuer:write` / `issuer:read` / `issuer:admin` permissions.

## See also

- [ds-dkms](https://github.com/HIRO-MicroDataCenters-BV/ds-dkms) — Helm chart for the KERI stack (witness + watcher + mesagkesto)
- [ds-login](https://github.com/HIRO-MicroDataCenters-BV/ds-login) — verifies IPEX grants, issues session JWTs
- [ds-auth](https://github.com/HIRO-MicroDataCenters-BV/ds-auth) — middleware every ds-* service uses to gate requests
- [ROADMAP.md](./ROADMAP.md) — what's shipped and what's queued

## License

MIT — see [LICENSE](LICENSE).
