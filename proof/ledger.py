"""Tamper-evident forecast ledger.

Every entry is one JSON line. Each entry's hash covers its own content AND the
previous entry's hash, so editing, deleting or reordering any past line breaks
every hash after it. Entries can also carry an Ed25519 signature over the hash,
so a reader can check who wrote them.

This file has no Pulse-specific imports on purpose: it is the verifier a fund
runs on its own machine.

    python ledger.py <record_dir>            # verify ledger.jsonl (+ pubkey.txt if present)

Only the standard library is needed, plus `cryptography` to check signatures.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

GENESIS_PREV = "0" * 64
TYPES = ("genesis", "scan", "forecast", "outcome")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def entry_hash(seq: int, ts: float, typ: str, data: dict, prev: str) -> str:
    return hashlib.sha256(canonical({"seq": seq, "ts": ts, "type": typ, "data": data, "prev": prev})).hexdigest()


# ---------- signing (optional) ----------

def load_private_key(b64: Optional[str]):
    """Ed25519 private key from base64 of the 32 raw bytes, or None."""
    if not b64:
        return None
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(b64))


def public_key_b64(private_key) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _verify_sig(pub_b64: str, digest_hex: str, sig_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), bytes.fromhex(digest_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------- writing ----------

class Ledger:
    def __init__(self, path: str, private_key=None):
        self.path = path
        self.key = private_key
        self.entries: List[dict] = []
        if os.path.exists(path):
            with open(path) as f:
                self.entries = [json.loads(line) for line in f if line.strip()]

    @property
    def head(self) -> Tuple[int, str]:
        if not self.entries:
            return -1, GENESIS_PREV
        return self.entries[-1]["seq"], self.entries[-1]["hash"]

    def append(self, typ: str, data: dict, ts: float) -> dict:
        if typ not in TYPES:
            raise ValueError(f"unknown entry type {typ}")
        seq, prev = self.head
        seq += 1
        h = entry_hash(seq, ts, typ, data, prev)
        e = {"seq": seq, "ts": ts, "type": typ, "data": data, "prev": prev, "hash": h, "sig": None}
        if self.key is not None:
            e["sig"] = base64.b64encode(self.key.sign(bytes.fromhex(h))).decode()
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a") as f:
            f.write(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n")
        self.entries.append(e)
        return e


# ---------- verification ----------

def verify_entries(entries: List[dict], pub_b64: Optional[str] = None, require_sig: bool = False) -> Dict:
    """Check the whole chain. Returns {"ok": bool, "errors": [...], "counts": {...}, "head": ...}."""
    errors: List[str] = []
    prev = GENESIS_PREV
    forecasts: Dict[int, dict] = {}
    resolved = set()
    counts = {t: 0 for t in TYPES}
    unsigned = 0
    last_ts = None
    for i, e in enumerate(entries):
        where = f"line {i + 1}"
        try:
            seq, ts, typ, data = e["seq"], e["ts"], e["type"], e["data"]
        except (KeyError, TypeError):
            errors.append(f"{where}: missing fields")
            break
        if seq != i:
            errors.append(f"{where}: seq {seq}, expected {i} (a line was deleted, inserted or moved)")
        if e.get("prev") != prev:
            errors.append(f"{where}: prev hash does not match the line before it")
        h = entry_hash(seq, ts, typ, data, e.get("prev", ""))
        if h != e.get("hash"):
            errors.append(f"{where}: content does not match its hash (the line was edited)")
        if typ not in TYPES:
            errors.append(f"{where}: unknown type {typ}")
        if last_ts is not None and ts < last_ts:
            errors.append(f"{where}: timestamp goes backwards")
        last_ts = ts
        if i == 0 and typ != "genesis":
            errors.append("line 1: first entry must be genesis")
        if e.get("sig"):
            if pub_b64 and not _verify_sig(pub_b64, e.get("hash", ""), e["sig"]):
                errors.append(f"{where}: signature does not verify")
        else:
            unsigned += 1
        if typ == "forecast":
            if not (ts < float(data.get("close_ts", 0))):
                errors.append(f"{where}: forecast recorded at or after the market closed")
            p = data.get("model_prob")
            if not isinstance(p, (int, float)) or not 0 <= p <= 1:
                errors.append(f"{where}: model_prob out of range")
            forecasts[seq] = data
        if typ == "outcome":
            for ref in data.get("forecast_seqs", []):
                f = forecasts.get(ref)
                if f is None:
                    errors.append(f"{where}: outcome refers to forecast #{ref}, which does not come earlier")
                elif f.get("ticker") != data.get("ticker"):
                    errors.append(f"{where}: outcome ticker does not match forecast #{ref}")
                elif ref in resolved:
                    errors.append(f"{where}: forecast #{ref} resolved twice")
                resolved.add(ref)
            if data.get("result") not in (0, 1):
                errors.append(f"{where}: result must be 0 or 1")
        counts[typ] = counts.get(typ, 0) + 1
        prev = e.get("hash", "")
    if require_sig and unsigned:
        errors.append(f"{unsigned} entries are unsigned")
    head = (entries[-1]["seq"], entries[-1]["hash"]) if entries else None
    return {"ok": not errors, "errors": errors, "counts": counts, "unsigned": unsigned,
            "resolved_forecasts": len(resolved), "head": head}


def read_entries(path: str) -> List[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def verify_dir(record_dir: str) -> Dict:
    pub = None
    pk = os.path.join(record_dir, "pubkey.txt")
    if os.path.exists(pk):
        pub = open(pk).read().strip() or None
    res = verify_entries(read_entries(os.path.join(record_dir, "ledger.jsonl")), pub, require_sig=bool(pub))
    anchors_dir = os.path.join(record_dir, "anchors")
    hashes = {e["hash"]: e["seq"] for e in read_entries(os.path.join(record_dir, "ledger.jsonl"))}
    anchored, bad = 0, []
    if os.path.isdir(anchors_dir):
        for name in sorted(os.listdir(anchors_dir)):
            if name.endswith(".ots"):
                h = name.split("-", 1)[-1][:-4]
                if h in hashes:
                    anchored += 1
                else:
                    bad.append(name)
    if bad:
        res["ok"] = False
        res["errors"].append(f"anchor files for hashes not in the ledger: {', '.join(bad[:5])}")
    res["anchors"] = anchored
    return res


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    d = argv[0] if argv else "record"
    r = verify_dir(d)
    c = r["counts"]
    print(f"Ledger: {sum(c.values())} entries ({c.get('forecast', 0)} forecasts, "
          f"{c.get('outcome', 0)} outcomes, {c.get('scan', 0)} scans), {r['anchors']} Bitcoin-anchored heads")
    if r["ok"]:
        print("VERIFIED: chain intact, every forecast was recorded before its market closed"
              + (", all signatures valid." if r["unsigned"] == 0 else f" ({r['unsigned']} entries unsigned)."))
        print("To check an anchor against Bitcoin: ots verify anchors/<file>.ots -d <hash>  (opentimestamps-client)")
        return 0
    print("FAILED:")
    for err in r["errors"][:50]:
        print("  -", err)
    return 1


if __name__ == "__main__":
    sys.exit(main())
