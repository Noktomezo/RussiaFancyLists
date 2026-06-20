import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

TIMEOUT = 30


def find_binary(tool_name: str) -> str:
    """Finds the executable path for the given tool, preferring thirdparty/ folder."""
    # 1. Look in thirdparty folder
    tp_dir = Path(__file__).resolve().parents[2] / "thirdparty" / tool_name
    if tp_dir.is_dir():
        suffix = ""
        if sys.platform == "win32":
            suffix = "-windows-amd64.exe"
        elif sys.platform.startswith("linux"):
            suffix = "-linux-amd64"

        if suffix:
            binary_path = tp_dir / f"{tool_name}{suffix}"
            if binary_path.exists():
                # Make sure it's executable on Unix/Linux
                if sys.platform != "win32":
                    with contextlib.suppress(Exception):
                        os.chmod(binary_path, 0o755)
                return str(binary_path)

    # 2. Fall back to system PATH
    system_path = shutil.which(tool_name)
    if system_path:
        return system_path

    raise RuntimeError(
        f"Could not find binary for '{tool_name}' in thirdparty or system PATH"
    )


def generate_sing_box_ruleset(
    rule_key: str, input_file: Path, json_output_file: Path, srs_output_file: Path
):
    """Build ruleset JSON and compile it to binary .srs using sing-box CLI."""
    sing_box_bin = find_binary("sing-box")

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

    ruleset = {"version": 3, "rules": [rules_dict]}

    json_output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(json_output_file, "w", encoding="utf-8") as f:
        json.dump(ruleset, f, indent=2)

    srs_output_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Compile JSON to binary .srs format
        cmd_compile = [
            sing_box_bin,
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


def generate_mihomo_ruleset(
    rule_key: str, input_file: Path, yaml_output_file: Path, mrs_output_file: Path
):
    """Build ruleset YAML and compile it to binary .mrs using mihomo CLI."""
    mihomo_bin = find_binary("mihomo")

    # Map rule_key to Mihomo behavior
    if rule_key in ("domain", "domain_suffix"):
        behavior = "domain"
    elif rule_key == "source_ip_cidr":
        behavior = "ipcidr"
    else:
        raise ValueError(f"Unsupported rule key for mihomo: {rule_key}")

    items = []
    with open(input_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if behavior == "domain":
                # Remove leading dots if any
                line = re.sub(r"^\.", "", line)
            items.append(line)

    # 1. Output YAML ruleset
    yaml_lines = ["payload:"]
    for item in items:
        # Wrap in single quotes to escape any special characters like * or +
        yaml_lines.append(f"  - '{item}'")

    yaml_output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(yaml_output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(yaml_lines) + "\n")

    # 2. Compile to .mrs format
    mrs_output_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        cmd_compile = [
            mihomo_bin,
            "convert-ruleset",
            behavior,
            "yaml",
            str(yaml_output_file),
            str(mrs_output_file),
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
                f"mihomo command {cmd_compile} timed out after {TIMEOUT} seconds. Stderr: {stderr_msg}"
            ) from te
    except subprocess.CalledProcessError as e:
        stderr_msg = (
            e.stderr.decode(errors="replace").strip()
            if e.stderr
            else "No stderr captured"
        )
        raise RuntimeError(f"mihomo execution failed: {stderr_msg}") from e
