# Coding Agent Guidelines (AGENTS.md)

This file contains global rules, workflow requirements, and architectural guidelines that must be strictly followed by all coding agents working on the **RussiaFancyLists** repository.

---

## 🚀 Workflow Guidelines

### 1. Full Download Before Final Push
- **Rule**: Before making your final commit and pushing changes to the repository, you must run the list generation pipeline in **full download mode** (without skipping downloads):
  ```powershell
  uv run russiafancylists --keep-temp
  ```
- **Exception**: Using the `--skip-download` flag is **only** permitted during active local development to speed up iteration and testing:
  ```powershell
  uv run russiafancylists --skip-download --keep-temp
  ```

### 2. Mandatory Verification
- After generating hosts/lists, you must run the verification script to ensure domain parity holds across files:
  ```powershell
  uv run python scripts/verify_hosts_sync.py
  ```
- Do not commit or push changes if the verification script fails.

### 3. Mandatory Ruff Formatting & Linting
- **Rule**: If your changes touch any Python (`.py`) files, you must run `ruff` to format and check the code before committing:
  ```powershell
  uv run ruff format .
  uv run ruff check .
  ```
- All checks must pass cleanly.

---

## 📐 Hosts Architecture & Parity Constraints

### 1. Separate Hosts Families
- The generated hosts files are organized into the following families:
  1. **Smart Hosts Files**: `smart.hosts`, `smart-no-crutch.hosts` (multi-provider solution, actively SNI-probed across all non-RU proxy endpoints, keeping only validated working `[IP - domain]` pairs).
  2. **Dedicated Provider Files (with Crutches)**: `geohide.hosts`, `malw.hosts`, `mafioznik.hosts` (strictly scoped to each provider's source domains).
  3. **No-Crutch Provider Files**: `geohide-no-crutch.hosts`, `malw-no-crutch.hosts`, `mafioznik-no-crutch.hosts` (each provider's source domains with crutches excluded).
  4. **Only-Crutch Hosts File**: `only-crutch.hosts` (direct service IP mappings).
- **Parity & Consistency Rules**:
  - Every `.hosts` file must have a corresponding `.adguard.txt` file with **100% exact domain parity**.
  - `smart.hosts` domain set must equal the exact union of `smart-no-crutch.hosts` and `only-crutch.hosts`.
  - For each provider file with crutches, its no-crutch counterpart must be a subset whose difference contains only crutches.
  - All domains across all hosts files must be valid subsets of `lists/geoblock/full.lst` ∪ `only-crutch.hosts`.
  - No Russian IP addresses are permitted anywhere in `.hosts` or `.adguard.txt` files.
  - The verification script `verify_hosts_sync.py` checks these rules accordingly.

### 2. The `# Crutch` Section
- The header comment for custom/direct IP mappings must be exactly `# Crutch` (with no Russian translations or extra suffixes).
- The crutch section in standard hosts files must use the global `global_custom` mapping.
- **Definition of Crutch**: A crutch maps a domain directly to an unblocked IP address in its subnet (e.g., bypassing local censorship).

### 3. No-Crutch Hosts Files
- In all `-no-crutch.hosts` (and `-no-crutch.adguard.txt`) files, all crutch/direct domains (e.g., `facebook.com`, `api.fitbit.com`) must be **completely cut out/removed**.
- *Rationale*: These files are tailored for users who route all non-geoblocked traffic through a VPN, making crutch entries redundant or undesirable.
