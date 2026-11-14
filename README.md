# dpopgate

A DPoP admission tool for a snapshot of a request, an access token, and a proof JWT (lab HS256).

`python -m dpopgate inspect --request fixtures/cases/ok-bound/request.json --proof fixtures/cases/ok-bound/proof.jwt --token fixtures/cases/ok-bound/token.jwt` prints the method and URL.

`python -m dpopgate admit` evaluates the DPoP proof and access token against `docs/admit-rules.md`: HS256 signature verification, normalized `htm`/`htu`, the `iat` clock-skew window, `jti` replay window, `ath`, `cnf.jkt`, server `nonce`, and the access token `exp`/`aud`. It writes a JSON report (`decision`, `reason_codes`, `jkt`, `jti`, `notes`) and exits 0 for allow, 1 for deny, 2 for load failures.

```sh
python -m dpopgate admit \
  --request fixtures/cases/ok-bound/request.json \
  --proof fixtures/cases/ok-bound/proof.jwt \
  --token fixtures/cases/ok-bound/token.jwt \
  --replay fixtures/cases/ok-bound/replay.json \
  --policy fixtures/policy.json \
  --as-keys fixtures/as-keys.json \
  --client-keys fixtures/client-keys.json \
  --report /tmp/dpopgate-report.json
```

Standard library only. No Docker, no live HTTP.
