#!/usr/bin/env python3
"""Generate a synthetic AAM v0.4.0 Profile, Manifest, Card and execution result.

The demo uses only in-memory state, public demonstration keys and a synthetic
email-draft adapter. It performs no network request and sends no email.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from v4_regressions import make_gate, propose, v4_profile
from render_card import check_parity, project


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    gate, _, _ = make_gate()
    try:
        profile = v4_profile()
        publication = gate.publish_profile(profile)
        if not publication["published"]:
            raise RuntimeError("Profile publication failed: " + "; ".join(publication["reasons"]))
        proposal = propose(gate, profile["profile_id"], "demo-v4-action")
        if proposal["decision"]["decision"] != "ALLOW":
            raise RuntimeError("proposal failed: " + json.dumps(proposal["decision"]))
        manifest = proposal["manifest"]
        card = project(manifest)
        parity = check_parity(card, manifest)
        if not parity["ok"]:
            raise RuntimeError("Card parity failed: " + json.dumps(parity))
        execution = gate.execute(manifest["manifest_id"])

        artifacts = {
            "profile.json": profile,
            "manifest.json": manifest,
            "card.json": card,
            "gate-decision.json": proposal["decision"],
            "execution-result.json": execution,
            "aggregate-snapshot.json": gate.aggregate_snapshot(),
        }
        for name, value in artifacts.items():
            (args.out / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"output": str(args.out), "files": sorted(artifacts),
                          "execution_state": execution["execution_state"]}, indent=2))
        return 0
    finally:
        gate.close()


if __name__ == "__main__":
    raise SystemExit(main())
