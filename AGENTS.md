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
- The generated hosts files are split into two distinct families:
  1. **Standard Hosts Files (with Crutches)**: `combined.hosts`, `malw.hosts`, `mafioznik.hosts`, `geohide-v*.hosts`.
  2. **No-Crutch Hosts Files**: `combined-no-crutch.hosts`, `malw-no-crutch.hosts`, `geohide-v*-no-crutch.hosts`.
- **Parity Rules**:
  - All standard hosts files (except `mafioznik.hosts`) must contain **exactly identical domains** and match `combined.hosts`.
  - All no-crutch hosts files (except `mafioznik-no-crutch.hosts`) must contain **exactly identical domains** and match `combined-no-crutch.hosts`.
  - `mafioznik.hosts` and `mafioznik-no-crutch.hosts` are restricted to only Mafioznik's original allowed domains and the crutch section, verified as subsets.
  - The verification script `verify_hosts_sync.py` checks these rules accordingly.

### 2. The `# Crutch` Section
- The header comment for custom/direct IP mappings must be exactly `# Crutch` (with no Russian translations or extra suffixes).
- The crutch section in all standard hosts files must be **identical** across all providers (sharing the global `global_custom` mapping).
- **Definition of Crutch**: A crutch maps a domain to a custom, direct IP (e.g. bypassing local censorship or routing specifically to a target SNI proxy).

### 3. No-Crutch Hosts Files
- In the `-no-crutch.hosts` files (including `combined-no-crutch.hosts`), all crutch/direct domains (e.g., `facebook.com`, `api.fitbit.com`) must be **completely cut out/removed**.
- *Rationale*: These files are tailored for users who route all non-geoblocked traffic through a VPN, making crutch entries redundant or undesirable.
