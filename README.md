# dpopgate

A DPoP admission tool for a snapshot of a request, an access token, and a proof JWT (lab HS256).

`python -m dpopgate inspect --request fixtures/cases/ok-bound/request.json --proof fixtures/cases/ok-bound/proof.jwt --token fixtures/cases/ok-bound/token.jwt` already prints the method and URL. `admit` is still a stub.

Standard library only. No Docker, no live HTTP.
