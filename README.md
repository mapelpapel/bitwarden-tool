# Bitwarden Vault Tool (`bitwarden_tool.py`)

A cross-platform command-line tool (Windows, Linux, macOS) for cleaning, comparing, merging, converting, and auditing **Bitwarden exports** in both **JSON** (unencrypted & password-protected encrypted) and **CSV** formats.

## Features

* **Format Interoperability:** Processes and combines any mix of Bitwarden **JSON** (unencrypted or `passwordProtected: true`) and **CSV** exports.
* **Native Cryptography:** Decrypts password-protected Bitwarden JSON backups (PBKDF2-SHA256 & Argon2id) and optionally re-encrypts outputs in a Bitwarden-compatible format (`encKeyValidation_DO_NOT_EDIT` + AES-256-CBC-HMAC-SHA256).
* **Structure Conversion:** Converts between **personal vaults** (`folders` / `folder` including `favorite`) and **organization vaults** (`collections` without `favorite`), as well as between JSON and CSV.
* **Smart-Merge:** Intelligently merges near-duplicates—both with identical names and with differing names, provided the folder/collection, username, password, and at least one URI match.
* **Interactive Conflict Resolution (`-r`):** Resolves conflicts in single-value fields (`notes`, `login.totp`, `favorite`, `reprompt`, `fido2Credentials`) directly in the terminal via single-key controls (no `Enter` required), an inline pre-filled editor, or a multi-line editor.
* **Clean Re-Import (`import-diff`):** Extracts only new entries and entries updated via Smart-Merge or conflict resolution relative to a base vault, generating a final checklist of existing entries that must be deleted from the target vault before importing.
* **Structured Markdown Audit Reports (`-l`, `-d`, `-L`):** Generates compact overviews or extended audit reports (including item type breakdowns, URIs, TOTP/passkey status, custom field names, and conflict details) in the terminal and saves them as a structured `.md` file (`bitwarden_report.md` by default).

## Installation & Prerequisites

* **Python 3.10+**
* **Unencrypted JSON and CSV exports:** No external dependencies (uses only the Python standard library).
* **Encrypted JSON exports (optional):**

```bash
pip install cryptography argon2-cffi
```

## Usage

```bash
python bitwarden_tool.py <mode> <files...> [options]
```

### Available Modes (`<mode>`)

| Mode | Files | Description |
| :--- | :--- | :--- |
| `dedup` | 1 file | Removes exact duplicates (or merges near-duplicates with `-s`) within a single file. |
| `merge` | 2+ files | Combines multiple exports without duplicates. |
| `intersect` | 2+ files | Intersection: Outputs only entries present in **all** specified files. |
| `difference` | 2+ files | Symmetric difference (XOR): Outputs entries present in an **odd number** of files (for 2 files: all differences). |
| `import-diff` | 2+ files | Treats the **1st file as the base vault** and extracts all new and merged entries from the remaining files for a clean re-import. |
| `convert` | 1 file | Converts an export between `personal`/`org` (`-t`) and/or `json`/`csv` (`-F` / `-o`). |

## Options

| Option | Short | Description |
| :--- | :--- | :--- |
| `--output <FILE>` | `-o` | Target filename (default: `bitwarden_output.csv` if all inputs are CSV, otherwise `bitwarden_output.json`). Automatically appends `_encrypted` when `-e` is used. |
| `--output-format {json,csv}` | `-F` | Forces the output format (`json` or `csv`), overriding the file extension in `-o`. |
| `--list` | `-l` | Displays only the preview or report in the terminal without writing a vault file. |
| `--list-output [FILE]` | `-L` | Saves the preview or report as a structured Markdown file (default: `bitwarden_report.md`). |
| `--detailed-report` | `-d` | Generates an extended report with item type statistics, URIs, TOTP/passkey status, custom field names, note previews, and conflict details. |
| `--smart-merge` | `-s` | Merges near-duplicates and reports conflicts in single-value fields. |
| `--resolve-conflicts` | `-r` | Launches interactive conflict resolution in the terminal when conflicts occur (automatically enables `-s`). |
| `--target-format {personal,org}` | `-t` | Converts the vault structure to `personal` (`folders` + `favorite`) or `org` (`collections`) and allows mixing both structures. |
| `--password <PASSWORD>` | `-p` | Password for encrypted JSON files (if omitted, prompts securely via hidden input). |
| `--encrypt` | `-e` | Saves the output as a password-protected, encrypted Bitwarden JSON file. |

## Smart-Merge & Conflict Resolution in Detail

### How are two entries matched as belonging together?

1. **Core Identity:** Same folder/collection, type, name, username, password, and archive status (`archivedDate`).
2. **URI Matching with Differing Names (Logins):** Same folder/collection, identical (non-empty) username + password, and **at least one matching URI**. When names differ, the name from the last specified file is kept.

### How are fields merged?

* **List fields (merged without duplicates):** `uris`, `fields`, `passwordHistory`, `collections`.
* **Single-value fields (adopted if at most one entry has content):** `favorite`, `notes`, `reprompt`, `login.totp`, `login.fido2Credentials`.
* **Conflicts:** If multiple entries contain different values in a single-value field, the entry is flagged with `[! CONFLICT: <Field> !]`. Using `-r` (`--resolve-conflicts`), conflicts can be resolved interactively:
  * **Single-key controls:** Select via `1`–`9`, `m` (merge with newline), `e` (inline editor pre-filled with the merged suggestion, using `\n` for newlines), or `n` (true multi-line editor, finished with `.` on a new line)—each triggered immediately on keypress without pressing `Enter`.

## Practical Examples

### 1. Reconcile an existing vault with a backup (`import-diff`)

Checks which entries from `backup.json` are missing or updated in `my_vault.json`, resolves conflicts interactively, and saves a detailed Markdown audit report (`bitwarden_report.md`):

```bash
python bitwarden_tool.py import-diff my_vault.json backup.json -r -d -o reimport.json -L
```

*Note: At the end of the output, a checklist (`DELETE BEFORE IMPORT`) lists all entries that must be deleted from `my_vault.json` prior to importing to prevent duplicates.*

### 2. Combine multiple backups (CSV & encrypted JSON)

Merges an old CSV backup with a current encrypted JSON backup using Smart-Merge and saves the result encrypted (`combined_encrypted.json`):

```bash
python bitwarden_tool.py merge old.csv new_encrypted.json -s -e -o combined.json
```

### 3. Preview differences between two exports

Displays all differences (symmetric difference) between two files in the terminal without writing an output file:

```bash
python bitwarden_tool.py difference export_january.json export_november.json -s -l
```

### 4. Convert a personal export into an organization structure

Converts a personal export into the org format (`collections` without `favorite`):

```bash
python bitwarden_tool.py convert personal_export.json -t org -o org_import.json
```

### 5. Deduplicate a CSV export

Removes duplicates from a CSV file and automatically saves the result back as CSV (`bitwarden_output.csv`):

```bash
python bitwarden_tool.py dedup export.csv -s
```

## Notes on CSV Exports & Security

* **CSV Data Loss:** The Bitwarden CSV format does not support extended JSON metadata such as `passwordHistory`, URI match types, custom field types (Hidden/Boolean/Linked), passkeys (`fido2Credentials`), SSH keys, or timestamps. When mixing CSV and JSON or exporting from JSON to CSV, the tool displays appropriate warnings.
* **Account-Restricted Exports:** Encrypted Bitwarden exports of type *Account-restricted* (`passwordProtected: false`) are tied to the internal account key on the Bitwarden server and cannot be decrypted locally. Please select **Password protected** or **Unencrypted** when exporting from Bitwarden.
* **Report Security:** Neither the terminal output nor the Markdown report files saved via `-L` ever expose plaintext passwords or TOTP secrets.