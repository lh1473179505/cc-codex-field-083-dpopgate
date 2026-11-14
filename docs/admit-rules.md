# Admit rules

Reuse `load_json` and `load_text`. This lab is a DPoP subset that uses `HS256` instead of a public-key JWS algorithm. Proofs carry a JWK in the header (`kty=oct`, `k` is base64url of the raw HMAC key). This lab does not make network calls.

`--token` and `--proof` are compact JOSE strings (three base64url segments). The signing input is `base64url(utf8(json.dumps(header, separators=(",", ":"), sort_keys=True))) + "." + base64url(utf8(json.dumps(payload, separators=(",", ":"), sort_keys=True)))`. HMAC-SHA256 of that input, base64url-encoded without padding, is the signature.

## JWK thumbprint and ath

`jkt` is the lowercase hex SHA-256 of the JWK thumbprint input: a UTF-8 JSON object with only `k` and `kty` (in that sorted order: `k` then `kty`), no `kid`/`alg`, no whitespace (`json.dumps(..., separators=(",", ":"), sort_keys=True)`). `ath` is the lowercase hex SHA-256 of the *raw access-token string* (the compact JWT, not a decoded payload).

`--as-keys` maps the access-token header `kid` to a hex HMAC key (fall back to `default` if present). `--client-keys` is only used when a proof JWK has no `k` but has a `kid`; the usual fixtures put `k` on the JWK itself.

## Proof checks

1. Header `typ` must be `dpop+jwt` (case-insensitive) (`bad_typ`).
2. `alg` must be `HS256` (`bad_alg`).
3. Header must contain a JWK object with `kty` (`missing_jwk`).
4. The proof signature must verify with the JWK key (`bad_signature`). A malformed compact JWT is also `bad_signature`.
5. `htm` (uppercased) must equal the request `method` uppercased (`htm_mismatch`).
6. `htu` must match the request `url` after normalization (`htu_mismatch`). Normalization: lowercase scheme and host, drop a default port (`https` 443, `http` 80), keep a non-default port, keep the path as written (no slash fixing), keep the query string if present, and drop the fragment.
7. `iat` must be within `policy.clock_skew` seconds of `request.now` (default 300) (`iat_window`). A missing or non-integer `iat` is also `iat_window`.
8. `jti` must be present and must not appear in `--replay` `used` entries whose `iat` is within `policy.replay_window` seconds of now (default 300). A used entry may be a string (the jti, treated as iat=now) or `{jti, iat}`. Missing `jti` or a hit is `jti_replay`.
9. If `request.nonce` is a non-null, non-empty value, or if `policy.required_nonce` is set and the request did not override it with a null nonce, the proof must have a `nonce` claim equal to that value (`missing_nonce`, `nonce_mismatch`). When `request.nonce` is present, it is the required value. When it is omitted, `policy.required_nonce` applies if set.
10. `ath` must equal the hash of the access-token string (`ath_mismatch`).

## Access token

The access token must verify with the AS key from `--as-keys`. It must have `exp >= request.now` (`access_expired`). `cnf.jkt` must equal the proof JWK thumbprint (`jkt_mismatch` — also used when the access token signature does not verify). If `policy.audience` is set, the token `aud` must equal it or, when `aud` is a list, contain it (`aud_mismatch`).

## Report and exit

Report: `decision`, `reason_codes`, `jkt`, `jti`, `notes`. Stable order: `bad_typ`, `bad_alg`, `bad_signature`, `missing_jwk`, `htm_mismatch`, `htu_mismatch`, `iat_window`, `jti_replay`, `missing_nonce`, `nonce_mismatch`, `ath_mismatch`, `jkt_mismatch`, `access_expired`, `aud_mismatch`.

`allow` exits 0, `deny` exits 1, load failures exit 2.

## Public fixtures

`--policy fixtures/policy.json --as-keys fixtures/as-keys.json --client-keys fixtures/client-keys.json --replay fixtures/cases/NAME/replay.json --request fixtures/cases/NAME/request.json --token fixtures/cases/NAME/token.jwt --proof fixtures/cases/NAME/proof.jwt`:

- `ok-bound` → allow
- `htu-path` → deny `htu_mismatch`
- `htm-method` → deny `htm_mismatch`
- `jti-replay` → deny `jti_replay`
- `ath-mismatch` → deny `ath_mismatch`
- `jkt-mismatch` → deny `jkt_mismatch`
- `iat-stale` → deny `iat_window`
- `missing-nonce` → deny `missing_nonce`
- `access-expired` → deny `access_expired`
