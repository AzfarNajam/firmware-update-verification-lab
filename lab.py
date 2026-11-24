"""Lesson 1: exercise MCUboot imgtool with synthetic, non-executable payloads."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent
HEADER_SIZE = 512
SLOT_SIZE = 65536
VALID_MESSAGE = "Image was correctly validated"


def imgtool(*args: str | Path) -> subprocess.CompletedProcess[str]:
    """Run the real upstream CLI; keep its output as experiment evidence."""
    return subprocess.run(
        [sys.executable, "-m", "imgtool.main", *map(str, args)],
        text=True, capture_output=True, timeout=30, check=False,
    )


def require_success(*args: str | Path) -> None:
    result = imgtool(*args)
    if result.returncode != 0:
        raise RuntimeError(f"imgtool {args[0]} failed:\n{result.stdout}{result.stderr}")


def sign(payload: Path, output: Path, key: Path, version: str = "2.0.0") -> None:
    require_success(
        "sign", "--key", key, "--version", version,
        "--align", "4", "--header-size", str(HEADER_SIZE), "--pad-header",
        "--slot-size", str(SLOT_SIZE), payload, output,
    )


def classify_verification(result: subprocess.CompletedProcess[str]) -> str:
    """A crashed tool is an ERROR, never evidence of a security rejection."""
    if result.returncode == 0 and VALID_MESSAGE in result.stdout:
        return "ACCEPT"
    known_rejections = (
        "Image has an invalid hash", "No signature found for the given key",
        "Key type does not match TLV record",
        "Invalid image magic; is this an MCUboot image?",
        "Invalid TLV info magic; is this an MCUboot image?",
    )
    if result.returncode == 1 and any(x in result.stdout for x in known_rejections):
        return "REJECT"
    return "ERROR"


def verify_case(name: str, image: Path, public_key: Path | None,
                expected: str, explanation: str, run_dir: Path) -> dict:
    args = ["verify"]
    if public_key is not None:
        args += ["--key", str(public_key)]
    args.append(str(image))
    result = imgtool(*args)
    observed = classify_verification(result)
    return {
        "name": name, "expected": expected, "observed": observed,
        "passed": observed == expected, "explanation": explanation,
        "image": str(image.relative_to(run_dir)),
        "image_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        "verification_key": str(public_key.relative_to(run_dir)) if public_key else None,
        "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
    }


def run_demo(base_dir: Path) -> dict:
    """Create fresh disposable keys and images; preserve every experiment run."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = base_dir / f"{stamp}-{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=False)
    keys = run_dir / "keys"
    keys.mkdir()
    trusted_private = keys / "manufacturer-private.pem"
    trusted_public = keys / "manufacturer-public.pem"
    attacker_private = keys / "attacker-private.pem"
    for path in (trusted_private, attacker_private):
        require_success("keygen", "--type", "ed25519", "--key", path)
    require_success("getpub", "--key", trusted_private, "--encoding", "pem",
                    "--output", trusted_public)

    # This data is a stand-in for firmware bytes, NOT a compiled MCU program.
    payload = run_dir / "sensor-payload.bin"
    payload.write_bytes(b"LAB ONLY: synthetic temperature sensor payload\n" * 32)
    good = run_dir / "signed-v2.bin"
    sign(payload, good, trusted_private)

    # Modify one byte inside the payload, leaving the original signature intact.
    tampered = run_dir / "tampered-v2.bin"
    changed = bytearray(good.read_bytes())
    changed[HEADER_SIZE + 10] ^= 0x01
    tampered.write_bytes(changed)

    attacker_payload = run_dir / "attacker-payload.bin"
    attacker_payload.write_bytes(b"LAB ONLY: attacker-controlled replacement\n" * 32)
    forged = run_dir / "attacker-signed-v2.bin"
    sign(attacker_payload, forged, attacker_private)
    old = run_dir / "signed-v1.bin"
    sign(payload, old, trusted_private, version="1.0.0")

    scenarios = [
        ("valid_signature", good, trusted_public, "ACCEPT",
         "The trusted manufacturer's public key verifies the signed image."),
        ("changed_payload", tampered, trusted_public, "REJECT",
         "One payload byte changed after signing; the integrity check fails."),
        ("untrusted_signer", forged, trusted_public, "REJECT",
         "A valid signature from another key is not a trusted signature."),
        ("hash_only_control", forged, None, "ACCEPT",
         "Deliberately weak control: no trusted key supplied. A matching hash does not authenticate the manufacturer."),
        ("old_signed_image", old, trusted_public, "ACCEPT",
         "Signature verification alone has no device version state and does not prevent downgrades. This is a baseline, not a safe update policy."),
    ]
    cases = [verify_case(*scenario, run_dir=run_dir) for scenario in scenarios]
    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Host-side MCUboot imgtool verification; synthetic payloads; no bootloader execution",
        "imgtool_version": importlib.metadata.version("imgtool"),
        "python_version": platform.python_version(), "platform": platform.platform(),
        "run_dir": str(run_dir.resolve()), "cases": cases,
        "passed": sum(case["passed"] for case in cases), "total": len(cases),
    }
    (run_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["demo"])
    parser.parse_args()
    try:
        report = run_demo(ROOT / "artifacts")
    except (RuntimeError, OSError, subprocess.TimeoutExpired, importlib.metadata.PackageNotFoundError) as exc:
        print(f"Experiment could not finish: {exc}", file=sys.stderr)
        print("Install requirements.txt in a Python virtual environment and retry.", file=sys.stderr)
        return 2
    print("\nFirmware update lab | Lesson 1: who signed this image?\n")
    for case in report["cases"]:
        label = "PASS" if case["passed"] else "FAIL"
        print(f"[{label}] {case['name']}: {case['observed']} (expected {case['expected']})")
        print(f"       {case['explanation']}")
    print(f"\n{report['passed']}/{report['total']} expected outcomes observed.")
    print("PASS means the experiment matched its prediction, not that every policy is secure.")
    print(f"Evidence: {Path(report['run_dir']) / 'report.json'}")
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
