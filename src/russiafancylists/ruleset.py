import json
import re
import shutil
import subprocess
from pathlib import Path

TIMEOUT = 30


def generate_sing_box_ruleset(
    rule_key: str, input_file: Path, json_output_file: Path, srs_output_file: Path
):
    """Build ruleset JSON and compile it to binary .srs using sing-box CLI."""
    if not shutil.which("sing-box"):
        raise RuntimeError("sing-box binary is not installed or not in PATH")

    rules_dict = {}
    with open(input_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if rule_key == "domain_suffix":
                line = re.sub(r"^\.", "", line)
                rules_dict.setdefault("domain_suffix", []).append(line)
            elif rule_key == "domain":
                # If domain is an SLD (exactly one dot), map as domain_suffix
                if line.count(".") == 1:
                    rules_dict.setdefault("domain_suffix", []).append(line)
                else:
                    rules_dict.setdefault("domain", []).append(line)
            else:
                rules_dict.setdefault(rule_key, []).append(line)

    ruleset = {"version": 5, "rules": [rules_dict]}

    json_output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(json_output_file, "w", encoding="utf-8") as f:
        json.dump(ruleset, f, indent=2)

    srs_output_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Upgrade JSON to the highest version supported by local sing-box binary
        cmd_upgrade = ["sing-box", "rule-set", "upgrade", "-w", str(json_output_file)]
        try:
            subprocess.run(
                cmd_upgrade,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
            )
        except subprocess.TimeoutExpired as te:
            stderr_msg = (
                te.stderr.decode(errors="replace").strip()
                if te.stderr
                else "No stderr captured"
            )
            raise RuntimeError(
                f"sing-box command {cmd_upgrade} timed out after {TIMEOUT} seconds. Stderr: {stderr_msg}"
            ) from te

        # Compile upgraded JSON to binary .srs format
        cmd_compile = [
            "sing-box",
            "rule-set",
            "compile",
            "--output",
            str(srs_output_file),
            str(json_output_file),
        ]
        try:
            subprocess.run(
                cmd_compile,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
            )
        except subprocess.TimeoutExpired as te:
            stderr_msg = (
                te.stderr.decode(errors="replace").strip()
                if te.stderr
                else "No stderr captured"
            )
            raise RuntimeError(
                f"sing-box command {cmd_compile} timed out after {TIMEOUT} seconds. Stderr: {stderr_msg}"
            ) from te
    except subprocess.CalledProcessError as e:
        stderr_msg = (
            e.stderr.decode(errors="replace").strip()
            if e.stderr
            else "No stderr captured"
        )
        raise RuntimeError(f"sing-box execution failed: {stderr_msg}") from e
