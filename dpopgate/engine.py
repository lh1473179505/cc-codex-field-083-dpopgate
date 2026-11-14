"""Admission engine for the lab DPoP subset (HS256 proofs, standard library only)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any
from urllib.parse import urlsplit

REASON_ORDER = [
    "bad_typ",
    "bad_alg",
    "bad_signature",
    "missing_jwk",
    "htm_mismatch",
    "htu_mismatch",
    "iat_window",
    "jti_replay",
    "missing_nonce",
    "nonce_mismatch",
    "ath_mismatch",
    "jkt_mismatch",
    "access_expired",
    "aud_mismatch",
]

DEFAULT_PORTS = {"https": 443, "http": 80}


def _b64url_decode(segment: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64url segment") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise ValueError("malformed compact JWT")
    header_raw, payload_raw, signature = parts
    try:
        header = json.loads(_b64url_decode(header_raw))
        payload = json.loads(_b64url_decode(payload_raw))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("malformed JWT segments") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header and payload must be JSON objects")
    signing_input = _b64url_encode(_canonical(header)) + "." + _b64url_encode(_canonical(payload))
    return header, payload, signing_input.encode("ascii"), _b64url_decode(signature)


def _hmac_verify(key: bytes, signing_input: bytes, signature: bytes) -> bool:
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def _proof_key_bytes(jwk: Any, client_keys: dict[str, str]) -> bytes | None:
    if not isinstance(jwk, dict):
        return None
    raw_k = jwk.get("k")
    if isinstance(raw_k, str):
        try:
            return _b64url_decode(raw_k)
        except ValueError:
            return None
    kid = jwk.get("kid")
    if isinstance(kid, str):
        hex_key = client_keys.get(kid)
        if isinstance(hex_key, str):
            try:
                return bytes.fromhex(hex_key)
            except ValueError:
                return None
    return None


def _jwk_thumbprint(jwk: dict[str, Any], key_bytes: bytes) -> str:
    k_value = jwk.get("k")
    if not isinstance(k_value, str):
        k_value = _b64url_encode(key_bytes)
    canonical = json.dumps(
        {"k": k_value, "kty": jwk.get("kty", "oct")},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _normalize_url(url: Any) -> str | None:
    if not isinstance(url, str) or not url:
        return None
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        if not scheme or not host:
            return None
        try:
            port = parts.port
        except ValueError:
            return None
        if port is not None and DEFAULT_PORTS.get(scheme) != port:
            netloc = f"{host}:{port}"
        else:
            netloc = host
        normalized = f"{scheme}://{netloc}{parts.path}"
        if parts.query:
            normalized += "?" + parts.query
        return normalized
    except ValueError:
        return None


def _required_nonce(request: dict[str, Any], policy: dict[str, Any]) -> str | None:
    request_nonce = request.get("nonce")
    if isinstance(request_nonce, str) and request_nonce:
        return request_nonce
    if "nonce" not in request:
        policy_nonce = policy.get("required_nonce")
        if isinstance(policy_nonce, str) and policy_nonce:
            return policy_nonce
    return None


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def admit(request: dict[str, Any], proof: str, access_token: str, replay: dict[str, Any], policy: dict[str, Any], as_keys: dict[str, str], client_keys: dict[str, str]) -> dict[str, Any]:
    reasons: set[str] = set()
    notes: list[str] = []
    now = request.get("now")
    clock_skew = policy.get("clock_skew", 300)
    replay_window = policy.get("replay_window", 300)

    header: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    try:
        header, payload, signing_input, signature = _decode_jwt(proof)
    except ValueError:
        reasons.add("bad_signature")
        notes.append("proof is not a well-formed compact JWT")

    jwk: Any = None
    jkt: str | None = None
    if header is not None:
        if str(header.get("typ", "")).lower() != "dpop+jwt":
            reasons.add("bad_typ")
            notes.append(f"proof header typ is {header.get('typ')!r}, expected dpop+jwt")
        if header.get("alg") != "HS256":
            reasons.add("bad_alg")
            notes.append(f"proof header alg is {header.get('alg')!r}, expected HS256")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict) or not jwk.get("kty"):
            reasons.add("missing_jwk")
            notes.append("proof header is missing a JWK object with kty")
            jwk = None

    key_bytes = _proof_key_bytes(jwk, client_keys) if jwk is not None else None
    if jwk is not None and key_bytes is None:
        reasons.add("bad_signature")
        notes.append("proof JWK did not resolve to an HMAC key")
    if jwk is not None and key_bytes is not None:
        jkt = _jwk_thumbprint(jwk, key_bytes)
        if header is not None and not _hmac_verify(key_bytes, signing_input, signature):
            reasons.add("bad_signature")
            notes.append("proof HMAC-SHA256 signature did not verify")

    if payload is not None:
        proof_method = payload.get("htm")
        request_method = request.get("method")
        if not isinstance(proof_method, str) or not isinstance(request_method, str) or proof_method.upper() != request_method.upper():
            reasons.add("htm_mismatch")
            notes.append(f"htm {proof_method!r} does not match request method {request_method!r}")

        proof_url = _normalize_url(payload.get("htu"))
        request_url = _normalize_url(request.get("url"))
        if proof_url is None or request_url is None or proof_url != request_url:
            reasons.add("htu_mismatch")
            notes.append(f"htu {proof_url!r} does not match normalized request URL {request_url!r}")

        iat = payload.get("iat")
        if not _is_int(now) or not _is_int(iat) or abs(now - iat) > clock_skew:
            reasons.add("iat_window")
            notes.append(f"proof iat {iat!r} is outside clock_skew={clock_skew} of now {now!r}")

        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti:
            reasons.add("jti_replay")
            notes.append("proof is missing a jti claim")
        else:
            for entry in replay.get("used", []) if isinstance(replay, dict) else []:
                if isinstance(entry, str):
                    entry_jti, entry_iat = entry, now
                elif isinstance(entry, dict):
                    entry_jti = entry.get("jti")
                    entry_iat = entry.get("iat", now)
                else:
                    continue
                if entry_jti == jti and _is_int(now) and _is_int(entry_iat) and abs(now - entry_iat) <= replay_window:
                    reasons.add("jti_replay")
                    notes.append(f"jti {jti!r} was already used within replay_window={replay_window}")
                    break

        required_nonce = _required_nonce(request, policy)
        if required_nonce is not None:
            proof_nonce = payload.get("nonce")
            if proof_nonce is None:
                reasons.add("missing_nonce")
                notes.append(f"proof nonce is missing; {required_nonce!r} is required")
            elif proof_nonce != required_nonce:
                reasons.add("nonce_mismatch")
                notes.append(f"proof nonce {proof_nonce!r} does not equal required {required_nonce!r}")

        expected_ath = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
        if payload.get("ath") != expected_ath:
            reasons.add("ath_mismatch")
            notes.append("proof ath is not the SHA-256 hash of the raw access token")

    token_header: dict[str, Any] | None = None
    token_payload: dict[str, Any] | None = None
    try:
        token_header, token_payload, token_signing_input, token_signature = _decode_jwt(access_token)
    except ValueError:
        reasons.add("jkt_mismatch")
        notes.append("access token is not a well-formed compact JWT")

    if token_header is not None:
        kid = token_header.get("kid")
        as_key_hex = as_keys.get(kid) if isinstance(kid, str) else None
        if as_key_hex is None:
            as_key_hex = as_keys.get("default")
        token_verified = False
        if isinstance(as_key_hex, str):
            try:
                as_key = bytes.fromhex(as_key_hex)
                token_verified = _hmac_verify(as_key, token_signing_input, token_signature)
            except ValueError:
                token_verified = False
        if not token_verified:
            reasons.add("jkt_mismatch")
            notes.append("access token signature did not verify with the AS keys")

        if not _is_int(token_payload.get("exp")) or not _is_int(now) or token_payload["exp"] < now:
            reasons.add("access_expired")
            notes.append(f"access token exp {token_payload.get('exp')!r} is before now {now!r}")

        token_jkt = (token_payload.get("cnf") or {}).get("jkt") if isinstance(token_payload.get("cnf"), dict) else None
        if jkt is None or token_jkt != jkt:
            reasons.add("jkt_mismatch")
            notes.append(f"access token cnf.jkt {token_jkt!r} does not match proof JWK thumbprint {jkt!r}")

        audience = policy.get("audience")
        if audience:
            token_aud = token_payload.get("aud")
            if token_aud != audience and not (isinstance(token_aud, list) and audience in token_aud):
                reasons.add("aud_mismatch")
                notes.append(f"access token aud {token_aud!r} does not match policy audience {audience!r}")

    reason_codes = [code for code in REASON_ORDER if code in reasons]
    if not reason_codes:
        notes.insert(0, "all DPoP admission checks passed")
        decision = "allow"
    else:
        decision = "deny"
    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "jkt": jkt,
        "jti": payload.get("jti") if payload is not None else None,
        "notes": notes,
    }
