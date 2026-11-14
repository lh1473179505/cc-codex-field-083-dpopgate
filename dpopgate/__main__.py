"""CLI. inspect already works; admit is the piece to implement."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from dpopgate.load import LoadError, load_json, load_text

def build_parser():
    p=argparse.ArgumentParser(prog="dpopgate")
    sub=p.add_subparsers(dest="cmd", required=True)
    ins=sub.add_parser("inspect")
    ins.add_argument("--request", required=True)
    ins.add_argument("--proof", required=True)
    ins.add_argument("--token", required=True)
    adm=sub.add_parser("admit")
    adm.add_argument("--request", required=True)
    adm.add_argument("--proof", required=True)
    adm.add_argument("--token", required=True)
    adm.add_argument("--replay", required=True)
    adm.add_argument("--policy", required=True)
    adm.add_argument("--as-keys", required=True)
    adm.add_argument("--client-keys", required=True)
    adm.add_argument("--report", required=True)
    return p

def main(argv=None)->int:
    args=build_parser().parse_args(argv)
    try:
        request=load_json(args.request)
        proof=load_text(args.proof)
        token=load_text(args.token)
    except (LoadError, OSError) as exc:
        print(f"failed to load request or tokens: {exc}", file=sys.stderr)
        return 2
    if args.cmd=="inspect":
        print(json.dumps({"method":request.get("method"),"url":request.get("url"),"now":request.get("now"),
                          "nonce":request.get("nonce"),"proof_chars":len(proof),"token_chars":len(token)}, indent=2))
        return 0
    try:
        replay=load_json(args.replay)
        policy=load_json(args.policy)
        as_keys=load_json(args.as_keys)
        client_keys=load_json(args.client_keys)
    except (LoadError, OSError) as exc:
        print(f"failed to load policy or keys: {exc}", file=sys.stderr)
        return 2
    from dpopgate.engine import admit
    try:
        report=admit(request, proof, token, replay, policy, as_keys, client_keys)
    except NotImplementedError as exc:
        print(str(exc), file=sys.stderr); return 2
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    d=str(report.get("decision","")).lower()
    if d=="allow": return 0
    if d=="deny": return 1
    print("report is missing a decision of allow or deny", file=sys.stderr)
    return 2

if __name__=="__main__":
    raise SystemExit(main())
