# Hosted relay API

This crate defines the private HTTP contracts for Concurro callers. Depend on
`concurro-relay-hosted-api` from the same Git tag as the deployed verifier.
It builds independently of the Sponsor and native proof source trees.

## Owner API v1

Send the owner bearer in `Authorization`.

| Request | Result |
| ---- | ---- |
| `GET /owner/v1/registrations/{code}` | Device name, routes and `expires_at`, or `404 unknown_registration` |
| `POST /owner/v1/approvals` | `{relay_id}` after durable approval. An identical retry returns the same ID. A conflicting approval returns `409 approval_conflict` |
| `GET /owner/v1/relays?user_id={id}` | Server start, check time and registered relays for this owner, including idle capacity and active slots |

Timestamps use RFC 3339. Unobserved relay liveness is represented by
`last_seen: null`. Versioned API errors use `{error: {code, message}}`.

## Inference

Send the inference bearer and POST provider-native JSON with the requested model
to `/dispatch/v2/messages` (Claude) or `/dispatch/v2/responses` (Codex).

- `x-concurro-claim` holds the exchange's compact EdDSA/Ed25519 JWS. The header has
  `alg: EdDSA`, `typ: JWT` and `kid`. The issuer is `concurro-exchange` and
  `iat` and `exp` are integral Unix seconds. The exchange issues one claim per
  session and reuses it for that session's requests. Exchange and verifier use
  synchronized clocks for issue and expiry checks.
- `x-concurro-request` identifies one exchange inference request. The verifier
  spends one call per admitted ID and charges input plus output tokens from
  provider-reported usage. Calls for one session enter serially, so once reported
  usage reaches the token limit the verifier refuses the next call. The last
  admitted call can finish even if it crosses the limit. On interruption, the
  verifier charges the usage it observed and marks partial counts as incomplete.
  The call and expiry allowances still apply when the provider reports no usage.
- The signed `sub` identifies the retained native lease. The provider route,
  relay, owner, entry, record and version must match the verifier's approval.
  The requested model must be present in `models`.

| Status and code | Meaning |
| ---- | ---- |
| `400 invalid_request_id` | Missing or ambiguous exchange request ID |
| `400 invalid_body` | Invalid provider request JSON or missing model |
| `403 forbidden` | Missing or wrong private bearer |
| `403 claim_refused` | Missing, invalid, expired, out-of-scope or revoked claim |
| `409 request_reused` | The request ID already spent an admitted call |
| `429 allowance_spent` | The call or token allowance is spent |
| `503 unavailable` | The verifier cannot reach a native link or persist allowance |

Check the error code to distinguish verifier allowance exhaustion from a provider
rate limit. A successful dispatch streams the provider response. Codex can also
request a non-streaming response.

## Release

Send the release bearer to `POST /release/v1/claims/{jti}` with no request body.
The verifier returns `204 No Content` after the release is durable and aborts
the claim's active native lease. Repeating the release succeeds. An as-yet unseen
claim ID is fenced as well.
