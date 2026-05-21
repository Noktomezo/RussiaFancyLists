import sys
from pathlib import Path

def main():
    root_dir = Path(__file__).parent.parent
    combined_path = root_dir / "lists" / "hosts" / "combined.lst"
    ready_path = root_dir / "lists" / "hosts" / "ready-to-use.lst"
    
    if not combined_path.exists():
        print(f"Error: {combined_path} does not exist.")
        sys.exit(1)
    if not ready_path.exists():
        print(f"Error: {ready_path} does not exist.")
        sys.exit(1)
        
    with open(combined_path, "r", encoding="utf-8") as f:
        combined_lines = [line.rstrip() for line in f]
        
    with open(ready_path, "r", encoding="utf-8") as f:
        all_ready_lines = [line.rstrip() for line in f]
        
    # Dynamically skip header lines by advancing past the first blank line
    header_end_idx = 0
    for idx, line in enumerate(all_ready_lines):
        if not line.strip():
            header_end_idx = idx + 1
            break
            
    ready_lines = all_ready_lines[header_end_idx:]
        
    # Normalize trailing empty lines
    while combined_lines and not combined_lines[-1]:
        combined_lines.pop()
    while ready_lines and not ready_lines[-1]:
        ready_lines.pop()
        
    # Check if lines match
    if len(combined_lines) != len(ready_lines):
        print(f"Mismatch: combined.lst has {len(combined_lines)} lines, but ready-to-use.lst body has {len(ready_lines)} lines.")
        sys.exit(1)
        
    mismatches = 0
    for idx, (l1, l2) in enumerate(zip(combined_lines, ready_lines)):
        if l1 != l2:
            print(f"Mismatch at line {idx + 1}:")
            print(f"  combined: {repr(l1)}")
            print(f"  ready   : {repr(l2)}")
            mismatches += 1
            if mismatches >= 10:
                print("Too many mismatches, aborting check.")
                break
                
    if mismatches > 0:
        sys.exit(1)
        
    print("Verification successful: combined.lst is in sync with ready-to-use.lst.")
    sys.exit(0)

if __name__ == "__main__":
    main()
