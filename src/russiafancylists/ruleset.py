import re
import json
import shutil
import subprocess
from pathlib import Path

def generate_sing_box_ruleset(rule_key: str, input_file: Path, json_output_file: Path, srs_output_file: Path):
    """Build ruleset JSON and compile it to binary .srs using sing-box CLI."""
    if not shutil.which("sing-box"):
        raise RuntimeError("sing-box binary is not installed or not in PATH")
        
    values = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                if rule_key == "domain_suffix":
                    line = re.sub(r'^\.', '', line)
                values.append(line)
                
    ruleset = {
        "version": 4,
        "rules": [
            {
                rule_key: values
            }
        ]
    }
    
    json_output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(json_output_file, 'w', encoding='utf-8') as f:
        json.dump(ruleset, f, indent=2)
        
    srs_output_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run([
            "sing-box", "rule-set", "compile",
            "--output", str(srs_output_file),
            str(json_output_file)
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"sing-box compilation failed: {e.stderr.decode().strip()}")
