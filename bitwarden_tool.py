import argparse
import base64
import copy
import csv
import getpass
import hashlib
import hmac
import json
import os
import sys
import uuid

if os.name == 'nt':
    import msvcrt
else:
    import termios
    import tty
    try:
        import readline
    except ImportError:
        readline = None

# Item types in Bitwarden JSON exports
TYPE_NAMES = {
    1: "login",
    2: "note",
    3: "card",
    4: "identity",
    5: "sshKey"
}

CSV_TYPE_TO_INT = {
    "login": 1,
    "note": 2,
    "card": 3,
    "identity": 4
}

INT_TO_CSV_TYPE = {v: k for k, v in CSV_TYPE_TO_INT.items()}

# CSV column order matching current Bitwarden CSV exports
PERSONAL_CSV_COLS = [
    'folder', 'favorite', 'type', 'name', 'notes', 'fields',
    'reprompt', 'archivedDate',
    'login_uri', 'login_username', 'login_password', 'login_totp'
]

ORG_CSV_COLS = [
    'collections', 'type', 'name', 'notes', 'fields',
    'reprompt', 'archivedDate',
    'login_uri', 'login_username', 'login_password', 'login_totp'
]

REQUIRED_CSV_BASE_COLS = {
    'type', 'name', 'notes', 'fields',
    'login_uri', 'login_username', 'login_password', 'login_totp'
}

# Single-value fields that smart-merge combines only if at most one entry has content
SINGLE_VALUE_MERGE_KEYS = {'favorite', 'notes', 'reprompt'}
SINGLE_VALUE_LOGIN_KEYS = {'totp', 'fido2Credentials'}

# Text-capable conflict fields where merging or pre-filled editing makes sense
EDITABLE_CONFLICT_FIELDS = {'notes', 'login.totp'}

# Multi-value list fields that smart-merge combines and deduplicates
MULTI_VALUE_ITEM_KEYS = {'fields', 'passwordHistory'}
MULTI_VALUE_LOGIN_KEYS = {'uris'}


# ==============================================================================
# Bitwarden Cryptography Helpers (Password-Protected Encrypted JSON)
# ==============================================================================

def _get_crypto_primitives():
    """Imports cryptography primitives on demand so unencrypted usage stays zero-dependency."""
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return Cipher, algorithms, modes, padding
    except ImportError:
        sys.exit(
            "Error: Processing encrypted Bitwarden JSON files requires the 'cryptography' library.\n"
            "Install it via: pip install cryptography"
        )


def _derive_master_key(password: str, salt: str, kdf_type: int, iterations: int, memory: int = None, parallelism: int = None) -> bytes:
    """Derives the 32-byte Bitwarden master key using PBKDF2-SHA256 (kdf=0) or Argon2id (kdf=1)."""
    pwd_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    if kdf_type == 0:
        return hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, iterations, dklen=32)
    elif kdf_type == 1:
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError:
            sys.exit(
                "Error: This file uses Argon2id KDF, which requires 'argon2-cffi'.\n"
                "Install it via: pip install argon2-cffi"
            )
        salt_hash = hashlib.sha256(salt_bytes).digest()
        return hash_secret_raw(
            secret=pwd_bytes,
            salt=salt_hash,
            time_cost=iterations,
            memory_cost=(memory or 64) * 1024,
            parallelism=parallelism or 4,
            hash_len=32,
            type=Type.ID
        )
    else:
        sys.exit(f"Error: Unsupported Bitwarden KDF type '{kdf_type}'.")


def _stretch_key(master_key: bytes) -> tuple[bytes, bytes]:
    """Expands a 32-byte master key into (enc_key, mac_key) using HKDF-Expand (SHA-256)."""
    enc_key = hmac.new(master_key, b"enc\x01", hashlib.sha256).digest()
    mac_key = hmac.new(master_key, b"mac\x01", hashlib.sha256).digest()
    return enc_key, mac_key


def _decrypt_enc_string(enc_string: str, enc_key: bytes, mac_key: bytes) -> bytes:
    """Decrypts a Bitwarden CipherString (format: '2.<iv_b64>|<ct_b64>|<mac_b64>')."""
    Cipher, algorithms, modes, padding = _get_crypto_primitives()

    if not isinstance(enc_string, str) or not enc_string.startswith("2."):
        raise ValueError("Unsupported cipher string format (expected type 2: AesCbc256_HmacSha256_B64).")

    parts = enc_string[2:].split("|")
    if len(parts) != 3:
        raise ValueError("Malformed Bitwarden cipher string.")

    iv = base64.b64decode(parts[0])
    ct = base64.b64decode(parts[1])
    mac = base64.b64decode(parts[2])

    computed_mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, computed_mac):
        raise ValueError("MAC verification failed (wrong password or corrupted data).")

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


def _encrypt_to_enc_string(plaintext_bytes: bytes, enc_key: bytes, mac_key: bytes) -> str:
    """Encrypts bytes into a Bitwarden CipherString (format: '2.<iv_b64>|<ct_b64>|<mac_b64>')."""
    Cipher, algorithms, modes, padding = _get_crypto_primitives()

    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()

    return (
        f"2.{base64.b64encode(iv).decode('ascii')}|"
        f"{base64.b64encode(ct).decode('ascii')}|"
        f"{base64.b64encode(mac).decode('ascii')}"
    )


def decrypt_bitwarden_payload(data: dict, filepath: str, password_cache: list[str]) -> dict:
    """Decrypts a password-protected Bitwarden JSON export (supports both current and legacy formats)."""
    if not data.get('passwordProtected'):
        sys.exit(
            f"Error in '{filepath}': This file is an account-restricted encrypted export ('passwordProtected: false').\n"
            "Account-restricted exports can only be decrypted by the originating Bitwarden account on the server.\n"
            "Please re-export using 'Encrypted -> Password protected' or 'Unencrypted'."
        )

    salt = data.get('salt')
    kdf_type = data.get('kdfType', 0)
    kdf_iterations = data.get('kdfIterations', 600000)
    kdf_memory = data.get('kdfMemory')
    kdf_parallelism = data.get('kdfParallelism')
    enc_key_validation = data.get('encKeyValidation_DO_NOT_EDIT')
    enc_key_legacy = data.get('encKey')
    encrypted_data = data.get('data')

    if not salt or not encrypted_data or (not enc_key_validation and not enc_key_legacy):
        sys.exit(f"Error in '{filepath}': Missing cryptographic metadata ('salt', 'data', or key validation field).")

    def try_with_password(pwd: str) -> dict:
        master_key = _derive_master_key(pwd, salt, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
        m_enc_key, m_mac_key = _stretch_key(master_key)

        if enc_key_validation:
            _decrypt_enc_string(enc_key_validation, m_enc_key, m_mac_key)
            plaintext = _decrypt_enc_string(encrypted_data, m_enc_key, m_mac_key)
        else:
            vault_sym_key = _decrypt_enc_string(enc_key_legacy, m_enc_key, m_mac_key)
            if len(vault_sym_key) != 64:
                raise ValueError("Decrypted symmetric key has unexpected length.")
            v_enc_key, v_mac_key = vault_sym_key[:32], vault_sym_key[32:]
            plaintext = _decrypt_enc_string(encrypted_data, v_enc_key, v_mac_key)

        return json.loads(plaintext.decode('utf-8'))

    for cached_pwd in password_cache:
        try:
            return try_with_password(cached_pwd)
        except ValueError:
            continue

    basename = os.path.basename(filepath)
    for attempt in range(3):
        pwd = getpass.getpass(f"Enter export password for '{basename}': ")
        try:
            decrypted_dict = try_with_password(pwd)
            if pwd not in password_cache:
                password_cache.append(pwd)
            return decrypted_dict
        except ValueError:
            remaining = 2 - attempt
            if remaining > 0:
                print(f"Incorrect password. {remaining} attempt(s) remaining.")

    sys.exit(f"Error: Failed to decrypt '{filepath}' after 3 attempts.")


def encrypt_bitwarden_payload(inner_payload: dict, password: str) -> dict:
    """Encrypts a Bitwarden JSON export dict into the current password-protected Bitwarden JSON envelope."""
    salt = base64.b64encode(os.urandom(16)).decode('ascii')
    kdf_type = 0
    kdf_iterations = 600000

    master_key = _derive_master_key(password, salt, kdf_type, kdf_iterations)
    m_enc_key, m_mac_key = _stretch_key(master_key)

    validation_token = str(uuid.uuid4()).encode('utf-8')
    enc_key_validation = _encrypt_to_enc_string(validation_token, m_enc_key, m_mac_key)

    plaintext_bytes = json.dumps(inner_payload, ensure_ascii=False).encode('utf-8')
    encrypted_data = _encrypt_to_enc_string(plaintext_bytes, m_enc_key, m_mac_key)

    return {
        "encrypted": True,
        "passwordProtected": True,
        "salt": salt,
        "kdfType": kdf_type,
        "kdfIterations": kdf_iterations,
        "encKeyValidation_DO_NOT_EDIT": enc_key_validation,
        "data": encrypted_data
    }


def resolve_output_filename(output_path: str, out_file_format: str, is_encrypted: bool) -> str:
    """Adjusts output extension (.json / .csv) and ensures '_encrypted' is in the name when encrypted."""
    directory, filename = os.path.split(output_path)
    stem, ext = os.path.splitext(filename)

    expected_ext = f".{out_file_format}"
    if ext.lower() != expected_ext:
        ext = expected_ext

    if is_encrypted and "encrypted" not in stem.lower():
        stem = f"{stem}_encrypted"

    new_filename = f"{stem}{ext}"
    return os.path.join(directory, new_filename) if directory else new_filename


# ==============================================================================
# Unified Vault Loaders (JSON & CSV -> Normalized Internal Item Representation)
# ==============================================================================

def parse_csv_fields(raw_fields: str) -> list[dict]:
    """Parses Bitwarden CSV 'fields' lines ('Name: Value') into JSON field objects."""
    if not raw_fields:
        return []
    result = []
    for line in raw_fields.splitlines():
        if not line.strip():
            continue
        if ": " in line:
            fname, fval = line.split(": ", 1)
        elif ":" in line:
            fname, fval = line.split(":", 1)
        else:
            fname, fval = line, ""
        result.append({"name": fname, "value": fval, "type": 0, "linkedId": None})
    return result


def parse_csv_uris(raw_uris: str) -> list[dict]:
    """Parses comma-separated Bitwarden CSV 'login_uri' strings into JSON uri objects."""
    if not raw_uris:
        return []
    result = []
    for part in raw_uris.split(','):
        cleaned = part.strip()
        if cleaned:
            result.append({"match": None, "uri": cleaned})
    return result


def load_csv_vault(filepath: str):
    """Loads a Bitwarden CSV export and converts rows into normalized internal JSON item dicts."""
    try:
        with open(filepath, mode='r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []

            if 'folder' in header:
                vault_format = 'personal'
            elif 'collections' in header:
                vault_format = 'org'
            else:
                sys.exit(
                    f"Error in '{filepath}': Neither 'folder' nor 'collections' found. "
                    "Is this a valid Bitwarden CSV export?"
                )

            missing = [c for c in REQUIRED_CSV_BASE_COLS if c not in header]
            if missing:
                sys.exit(f"Error in '{filepath}': Missing required CSV columns: {', '.join(missing)}")

            normalized_items = []
            for row in reader:
                raw_type = (row.get('type') or 'login').strip()
                itype = CSV_TYPE_TO_INT.get(raw_type, 1)

                item = {
                    "type": itype,
                    "name": row.get('name') or "",
                    "notes": (row.get('notes') or "") or None,
                    "fields": parse_csv_fields(row.get('fields') or ""),
                    "reprompt": 1 if (row.get('reprompt') or "").strip() == "1" else 0
                }

                archived = (row.get('archivedDate') or "").strip()
                if archived:
                    item["archivedDate"] = archived

                if vault_format == 'personal':
                    item['_folder'] = (row.get('folder') or "").strip()
                    item['favorite'] = (row.get('favorite') or "").strip() == "1"
                else:
                    raw_cols = row.get('collections') or ""
                    col_names = sorted(dict.fromkeys(
                        c.strip() for c in raw_cols.split(',') if c.strip()
                    ))
                    item['_collections'] = col_names

                if itype == 1:
                    item["login"] = {
                        "uris": parse_csv_uris(row.get('login_uri') or ""),
                        "username": (row.get('login_username') or "") or None,
                        "password": (row.get('login_password') or "") or None,
                        "totp": (row.get('login_totp') or "") or None
                    }
                elif itype == 2:
                    item["secureNote"] = {"type": 0}

                normalized_items.append(item)

            return normalized_items, vault_format, "csv"

    except Exception as e:
        sys.exit(f"Unexpected error while reading CSV '{filepath}': {e}")


def load_json_vault(filepath: str, password_cache: list[str]):
    """Loads a Bitwarden JSON export (unencrypted or encrypted) into normalized internal item dicts."""
    try:
        with open(filepath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        sys.exit(f"Error: '{filepath}' is not a valid JSON file ({e}).")
    except Exception as e:
        sys.exit(f"Unexpected error while reading '{filepath}': {e}")

    if not isinstance(data, dict):
        sys.exit(f"Error in '{filepath}': Root JSON element must be an object.")

    if data.get('encrypted') is True:
        data = decrypt_bitwarden_payload(data, filepath, password_cache)

    if 'items' not in data:
        sys.exit(f"Error in '{filepath}': Missing 'items' array. Is this a valid Bitwarden JSON export?")

    if 'collections' in data:
        vault_format = 'org'
        id_to_name = {c['id']: c['name'] for c in data.get('collections', []) if 'id' in c and 'name' in c}
    else:
        vault_format = 'personal'
        id_to_name = {fld['id']: fld['name'] for fld in data.get('folders', []) if 'id' in fld and 'name' in fld}

    normalized_items = []
    for raw_item in data.get('items', []):
        item = copy.deepcopy(raw_item)
        if vault_format == 'personal':
            fid = item.pop('folderId', None)
            item['_folder'] = id_to_name.get(fid, "") if fid else ""
            item.pop('collectionIds', None)
        else:
            cids = item.pop('collectionIds', None) or []
            col_names = sorted(dict.fromkeys(id_to_name[cid] for cid in cids if cid in id_to_name))
            item['_collections'] = col_names
            item.pop('folderId', None)
            item.pop('favorite', None)

        normalized_items.append(item)

    return normalized_items, vault_format, "json"


def load_vault_auto(filepath: str, password_cache: list[str]):
    """Automatically detects whether a file is JSON or CSV and loads it."""
    if not os.path.isfile(filepath):
        sys.exit(f"Error: The file '{filepath}' was not found.")

    ext = os.path.splitext(filepath)[1].lower()
    if ext == '.csv':
        return load_csv_vault(filepath)
    elif ext == '.json':
        return load_json_vault(filepath, password_cache)

    with open(filepath, mode='r', encoding='utf-8-sig') as f:
        prefix = f.read(64).lstrip()
    if prefix.startswith('{'):
        return load_json_vault(filepath, password_cache)
    return load_csv_vault(filepath)


# ==============================================================================
# Core Vault Comparison & Smart-Merge Logic (CSV-Compatible Core Projection)
# ==============================================================================

def canonicalize(obj):
    """Creates a deterministic, hashable representation of any Python structure."""
    if isinstance(obj, dict):
        return tuple(sorted((k, canonicalize(v)) for k, v in obj.items()))
    elif isinstance(obj, list):
        return tuple(canonicalize(x) for x in obj)
    return obj


def convert_item_format(item, source_format, target_format):
    """Converts a normalized item dictionary between 'personal' and 'org' structure."""
    converted = copy.deepcopy(item)
    if source_format == target_format:
        return converted

    if source_format == 'personal' and target_format == 'org':
        folder_name = converted.pop('_folder', "")
        converted['_collections'] = [folder_name] if folder_name else []
        converted.pop('favorite', None)
        converted.pop('folderId', None)

    elif source_format == 'org' and target_format == 'personal':
        col_names = converted.pop('_collections', [])
        converted['_folder'] = col_names[0] if col_names else ""
        converted.setdefault('favorite', False)
        converted.pop('collectionIds', None)
        converted.pop('organizationId', None)

    return converted


def get_core_signature(item, ignore_mergeable=False):
    """
    Computes a hashable signature using ONLY the CSV-relevant functional attributes
    (folder/collections, favorite, type, name, notes, fields [name+value], reprompt,
    archivedDate, login_uri [uri strings], login_username, login_password, login_totp).
    """
    sig_dict = {
        'type': item.get('type', 1),
        'name': (item.get('name') or '').strip(),
        'archivedDate': (item.get('archivedDate') or '').strip(),
    }

    if '_folder' in item:
        sig_dict['_folder'] = (item.get('_folder') or '').strip()
    elif '_collections' in item and not ignore_mergeable:
        sig_dict['_collections'] = tuple(sorted(item.get('_collections') or []))

    if not ignore_mergeable:
        if '_folder' in item:
            sig_dict['favorite'] = bool(item.get('favorite'))
        sig_dict['notes'] = item.get('notes') or ''
        sig_dict['reprompt'] = 1 if item.get('reprompt') == 1 else 0

        norm_fields = []
        for fld in (item.get('fields') or []):
            if isinstance(fld, dict):
                norm_fields.append((fld.get('name') or '', fld.get('value') or ''))
        sig_dict['fields'] = tuple(norm_fields)

    if item.get('type') == 1:
        login_obj = item.get('login') or {}
        sig_dict['username'] = (login_obj.get('username') or '').strip()
        sig_dict['password'] = login_obj.get('password') or ''

        if not ignore_mergeable:
            uris = [
                u.get('uri').strip()
                for u in (login_obj.get('uris') or [])
                if isinstance(u, dict) and isinstance(u.get('uri'), str) and u.get('uri').strip()
            ]
            sig_dict['uris'] = tuple(uris)
            sig_dict['totp'] = (login_obj.get('totp') or '').strip()

    return canonicalize(sig_dict)


def extract_uri_set(item) -> set[str]:
    """Returns the set of non-empty URI strings from a login item."""
    if item.get('type') != 1 or not isinstance(item.get('login'), dict):
        return set()
    uris = item['login'].get('uris') or []
    return {
        u['uri'].strip()
        for u in uris
        if isinstance(u, dict) and isinstance(u.get('uri'), str) and u['uri'].strip()
    }


def items_match_for_smart_merge(item_a, item_b) -> bool:
    """
    Determines whether two items should be grouped for smart-merge:
    1. Exact core identity match (same folder, type, name, username, password, archivedDate)
    2. Login URI-based match even if 'name' differs:
       same folder/collection + non-empty identical username & password + at least 1 shared URI.
    """
    if get_core_signature(item_a, ignore_mergeable=True) == get_core_signature(item_b, ignore_mergeable=True):
        return True

    if item_a.get('type') != 1 or item_b.get('type') != 1:
        return False

    if (item_a.get('archivedDate') or '').strip() != (item_b.get('archivedDate') or '').strip():
        return False

    if '_folder' in item_a or '_folder' in item_b:
        if item_a.get('_folder', "") != item_b.get('_folder', ""):
            return False
    else:
        cols_a = set(item_a.get('_collections', []))
        cols_b = set(item_b.get('_collections', []))
        if cols_a != cols_b and not (cols_a & cols_b):
            return False

    login_a = item_a.get('login') or {}
    login_b = item_b.get('login') or {}

    user_a = (login_a.get('username') or "").strip()
    user_b = (login_b.get('username') or "").strip()
    pass_a = login_a.get('password') or ""
    pass_b = login_b.get('password') or ""

    if not user_a or not pass_a:
        return False
    if user_a != user_b or pass_a != pass_b:
        return False

    uris_a = extract_uri_set(item_a)
    uris_b = extract_uri_set(item_b)
    return bool(uris_a & uris_b)


def group_records_for_smart_merge(records):
    """Clusters records into connected components using items_match_for_smart_merge."""
    n = len(records)
    visited = [False] * n
    groups = []

    for i in range(n):
        if visited[i]:
            continue
        visited[i] = True
        component = [records[i]]
        queue = [i]

        while queue:
            curr_idx = queue.pop(0)
            curr_item = records[curr_idx][0]
            for j in range(n):
                if not visited[j] and items_match_for_smart_merge(curr_item, records[j][0]):
                    visited[j] = True
                    component.append(records[j])
                    queue.append(j)

        groups.append(component)

    return groups


def is_meaningful(key, val):
    """Checks whether a single-value field contains actual user data."""
    if val is None or val == "" or val is False:
        return False
    if key == 'reprompt' and val == 0:
        return False
    return True


def merge_object_lists(lists, key_fn=canonicalize):
    """Deduplicates lists of JSON objects preserving order and rich JSON attributes."""
    seen = set()
    merged = []
    for lst in lists:
        if not lst:
            continue
        for entry in lst:
            sig = key_fn(entry)
            if sig not in seen:
                seen.add(sig)
                merged.append(copy.deepcopy(entry))
    return merged


def uri_dedup_key(u):
    """Deduplicates URIs by their actual URI string."""
    if isinstance(u, dict):
        return (u.get('uri') or '').strip()
    return canonicalize(u)


def field_dedup_key(f):
    """Deduplicates custom fields by (name, value)."""
    if isinstance(f, dict):
        return (f.get('name') or '', f.get('value') or '')
    return canonicalize(f)


def read_single_key(prompt_text: str) -> str:
    """Reads a single keypress immediately without requiring Enter (cross-platform)."""
    sys.stdout.write(prompt_text)
    sys.stdout.flush()

    if os.name == 'nt':
        ch = msvcrt.getwch()
        if ch == '\x03':
            raise KeyboardInterrupt
        if ch in ('\x00', '\xe0'):
            msvcrt.getwch()
            print()
            return ''
        print(ch)
        return ch.lower()
    else:
        if not sys.stdin.isatty():
            return input().strip().lower()[:1]
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == '\x03':
                raise KeyboardInterrupt
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        print(ch)
        return ch.lower()


def _win32_prefill_console(text: str) -> bool:
    """Injects prefill characters into the Windows console input buffer via Win32 WriteConsoleInputW."""
    import ctypes
    from ctypes import wintypes

    STD_INPUT_HANDLE = -10
    KEY_EVENT = 0x0001

    class KEY_EVENT_RECORD(ctypes.Structure):
        _fields_ = [
            ("bKeyDown", wintypes.BOOL),
            ("wRepeatCount", wintypes.WORD),
            ("wVirtualKeyCode", wintypes.WORD),
            ("wVirtualScanCode", wintypes.WORD),
            ("uChar", wintypes.WCHAR),
            ("dwControlKeyState", wintypes.DWORD),
        ]

    class EVENT_UNION(ctypes.Union):
        _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]

    class INPUT_RECORD(ctypes.Structure):
        _fields_ = [
            ("EventType", wintypes.WORD),
            ("Event", EVENT_UNION),
        ]

    kernel32 = ctypes.windll.kernel32
    h_stdin = kernel32.GetStdHandle(STD_INPUT_HANDLE)
    if h_stdin in (0, -1, None):
        return False

    records = (INPUT_RECORD * (len(text) * 2))()
    for i, ch in enumerate(text):
        for j, key_down in enumerate((True, False)):
            rec = records[i * 2 + j]
            rec.EventType = KEY_EVENT
            rec.Event.KeyEvent.bKeyDown = key_down
            rec.Event.KeyEvent.wRepeatCount = 1
            rec.Event.KeyEvent.wVirtualKeyCode = 0
            rec.Event.KeyEvent.wVirtualScanCode = 0
            rec.Event.KeyEvent.uChar = ch
            rec.Event.KeyEvent.dwControlKeyState = 0

    written = wintypes.DWORD(0)
    success = kernel32.WriteConsoleInputW(h_stdin, records, len(records), ctypes.byref(written))
    return bool(success and written.value > 0)


def prompt_prefilled(prompt_text: str, prefill: str) -> str:
    """Prompts for user input with editable prefill on Windows (Win32 API) and Unix/macOS (readline)."""
    editable_prefill = prefill.replace("\r\n", "\n").replace("\n", "\\n")

    if os.name == 'nt':
        sys.stdout.write(prompt_text)
        sys.stdout.flush()
        if _win32_prefill_console(editable_prefill):
            raw_input = input()
        else:
            print(f"\nSuggested value (copy/edit, use \\n for newlines):\n{editable_prefill}")
            val = input("[Press Enter to accept suggestion or type new value]: ")
            raw_input = val if val != "" else editable_prefill
    elif readline is not None:
        def hook():
            readline.insert_text(editable_prefill)
            readline.redisplay()
        readline.set_pre_input_hook(hook)
        try:
            raw_input = input(prompt_text)
        finally:
            readline.set_pre_input_hook(None)
    else:
        print(f"Suggested value (use \\n for newlines):\n{editable_prefill}")
        val = input(prompt_text)
        raw_input = val if val != "" else editable_prefill

    return raw_input.replace("\\n", "\n")


def prompt_multiline_editor(field_path: str, prefill: str) -> str:
    """Allows entering real multi-line text using Enter for new lines and a single '.' line to finish."""
    print(f"\nMulti-line input for '{field_path}'.")
    print("Press Enter for new lines. Type a single '.' on a new line (or Ctrl+Z + Enter) to finish.")
    if prefill:
        print(f"--- Current merged suggestion ---\n{prefill}\n---------------------------------")

    lines = []
    while True:
        try:
            line = input("> ")
        except EOFError:
            break
        if line == ".":
            break
        lines.append(line)
    return "\n".join(lines)


def resolve_group_conflicts_interactively(group, conflicts: dict):
    """Interactively resolves single-value conflicts for a smart-merge group."""
    item_name = group[-1][0].get('name') or "<Unnamed>"
    login_user = (group[-1][0].get('login') or {}).get('username') or "-"
    print("\n" + "=" * 60)
    print(f"CONFLICT RESOLUTION: '{item_name}' (User: {login_user})")
    print("=" * 60)

    resolved_top = {}
    resolved_login = {}

    for field_path, options in conflicts.items():
        print(f"\nField '{field_path}' has {len(options)} conflicting values:")
        for idx, (val, srcs) in enumerate(options, start=1):
            display_val = repr(val) if isinstance(val, str) else str(val)
            print(f"  [{idx}] {display_val}   (from: {', '.join(srcs)})")

        can_merge_or_edit = field_path in EDITABLE_CONFLICT_FIELDS
        if can_merge_or_edit:
            merged_suggestion = "\n".join(str(v) for v, _ in options if v)
            print("  [m] Merge all values (joined with newline)")
            print("  [e] Edit pre-filled value inline (use \\n for newlines)")
            print("  [n] Enter multi-line text (press Enter for new lines, '.' to finish)")

        valid_hint = f"1-{len(options)}" + (", m, e, n" if can_merge_or_edit else "")
        while True:
            choice = read_single_key(f"Choose option ({valid_hint}): ")

            if choice.isdigit() and 1 <= int(choice) <= len(options):
                chosen_val = copy.deepcopy(options[int(choice) - 1][0])
                break
            elif can_merge_or_edit and choice == 'm':
                chosen_val = merged_suggestion
                break
            elif can_merge_or_edit and choice == 'e':
                chosen_val = prompt_prefilled(f"Edit '{field_path}' (\\n = newline): ", merged_suggestion)
                break
            elif can_merge_or_edit and choice == 'n':
                chosen_val = prompt_multiline_editor(field_path, merged_suggestion)
                break
            else:
                print(f"Invalid key. Please press {valid_hint}.")

        if field_path.startswith("login."):
            resolved_login[field_path.split(".", 1)[1]] = chosen_val
        else:
            resolved_top[field_path] = chosen_val

    print("=" * 60 + "\n")
    return resolved_top, resolved_login


def inspect_and_merge_group(group, interactive: bool = False):
    """
    Attempts to smart-merge a group of (item, sources).
    Returns:
      - status: 'merged' | 'conflict'
      - items_with_meta: list of (item, sources, conflict_details_dict)
    """
    if len(group) == 1:
        return 'merged', [(copy.deepcopy(group[0][0]), list(group[0][1]), {})]

    base = copy.deepcopy(group[0][0])

    names = list(dict.fromkeys(
        itm.get('name').strip()
        for itm, _ in group
        if isinstance(itm.get('name'), str) and itm.get('name').strip()
    ))
    if names:
        base['name'] = names[-1]

    conflicts = {}  # field_path -> list of (value, sources)
    resolved_top = {}
    resolved_login = {}

    # 1. Inspect single-value top-level keys (favorite, notes, reprompt)
    for key in SINGLE_VALUE_MERGE_KEYS:
        val_map = {}
        for itm, srcs in group:
            v = itm.get(key)
            if is_meaningful(key, v):
                s = canonicalize(v)
                if s not in val_map:
                    val_map[s] = [v, list(srcs)]
                else:
                    val_map[s][1] = list(dict.fromkeys(val_map[s][1] + list(srcs)))

        if len(val_map) > 1:
            conflicts[key] = [(v, srcs) for v, srcs in val_map.values()]
        elif len(val_map) == 1:
            only_val = next(iter(val_map.values()))[0]
            resolved_top[key] = copy.deepcopy(only_val)

    # 2. Inspect single-value login sub-keys (totp, fido2Credentials)
    if base.get('type') == 1 and any(isinstance(itm.get('login'), dict) for itm, _ in group):
        base.setdefault('login', {})
        for lkey in SINGLE_VALUE_LOGIN_KEYS:
            val_map = {}
            for itm, srcs in group:
                login_obj = itm.get('login') or {}
                v = login_obj.get(lkey)
                if is_meaningful(lkey, v):
                    s = canonicalize(v)
                    if s not in val_map:
                        val_map[s] = [v, list(srcs)]
                    else:
                        val_map[s][1] = list(dict.fromkeys(val_map[s][1] + list(srcs)))

            if len(val_map) > 1:
                conflicts[f"login.{lkey}"] = [(v, srcs) for v, srcs in val_map.values()]
            elif len(val_map) == 1:
                only_val = next(iter(val_map.values()))[0]
                resolved_login[lkey] = copy.deepcopy(only_val)

    if conflicts:
        if interactive:
            user_top, user_login = resolve_group_conflicts_interactively(group, conflicts)
            resolved_top.update(user_top)
            resolved_login.update(user_login)
        else:
            return 'conflict', [(copy.deepcopy(itm), list(srcs), conflicts) for itm, srcs in group]

    for k, v in resolved_top.items():
        base[k] = v

    if base.get('type') == 1 and any(isinstance(itm.get('login'), dict) for itm, _ in group):
        base.setdefault('login', {})
        for lk, lv in resolved_login.items():
            base['login'][lk] = lv

        for lkey in MULTI_VALUE_LOGIN_KEYS:
            all_lists = [(itm.get('login') or {}).get(lkey, []) for itm, _ in group]
            if any(all_lists):
                ordered_lists = [
                    sorted(lst, key=lambda u: 0 if isinstance(u, dict) and u.get('match') is not None else 1)
                    for lst in all_lists if lst
                ]
                base['login'][lkey] = merge_object_lists(ordered_lists, key_fn=uri_dedup_key)

    for key in MULTI_VALUE_ITEM_KEYS:
        all_lists = [itm.get(key, []) for itm, _ in group]
        if any(all_lists):
            kfn = field_dedup_key if key == 'fields' else canonicalize
            base[key] = merge_object_lists(all_lists, key_fn=kfn)

    if '_collections' in base:
        merged_cols = list(dict.fromkeys(
            c for itm, _ in group for c in itm.get('_collections', [])
        ))
        base['_collections'] = sorted(merged_cols)

    combined_sources = list(dict.fromkeys(src for _, srcs in group for src in srcs))
    return 'merged', [(base, combined_sources, {})]


def smart_merge_records(records, interactive: bool = False):
    """Groups records via smart-merge rules, merges compatible items, and flags/resolves conflicts."""
    groups = group_records_for_smart_merge(records)

    result_records = []
    for group in groups:
        status, items_meta = inspect_and_merge_group(group, interactive=interactive)
        if status == 'merged':
            for itm, srcs, _ in items_meta:
                result_records.append((itm, srcs, "", {}))
        else:
            for itm, srcs, cdict in items_meta:
                flag = f"[! CONFLICT: {', '.join(cdict.keys())} !]"
                result_records.append((itm, srcs, flag, cdict))

    return result_records


def compute_import_diff(unique_records, base_filename, interactive: bool = False):
    """
    Compares other files against the 1st file (base_filename) for clean re-import.
    Returns (result_records, entries_to_delete_in_base, unresolved_base_conflicts).
    """
    groups = group_records_for_smart_merge(unique_records)
    result_records = []
    entries_to_delete = []
    unresolved_base_conflicts = []

    for group in groups:
        base_entries = [entry for entry in group if base_filename in entry[1]]
        other_entries = [entry for entry in group if base_filename not in entry[1]]

        # Case 1: Purely new entries (not in base vault)
        if not base_entries:
            status, items_meta = inspect_and_merge_group(other_entries, interactive=interactive)
            if status == 'merged':
                for itm, srcs, _ in items_meta:
                    result_records.append((itm, srcs, "", {}))
            else:
                for itm, srcs, cdict in items_meta:
                    flag = f"[! CONFLICT ({', '.join(cdict.keys())}) IN NEW FILES !]"
                    result_records.append((itm, srcs, flag, cdict))
            continue

        # Case 2: Only in base vault -> nothing to import or delete
        if not other_entries:
            continue

        # Case 3: Exists in base vault AND has differing version(s) in other files
        status, items_meta = inspect_and_merge_group(group, interactive=interactive)
        if status == 'merged':
            merged_item, combined_sources, _ = items_meta[0]
            base_sig = get_core_signature(base_entries[0][0], ignore_mergeable=False)
            merged_sig = get_core_signature(merged_item, ignore_mergeable=False)
            if merged_sig != base_sig or len(base_entries) > 1:
                result_records.append((
                    merged_item,
                    combined_sources,
                    f"[! REPLACE IN {base_filename} !]",
                    {}
                ))
                for base_itm, _ in base_entries:
                    entries_to_delete.append(base_itm)
        else:
            conflict_dict = items_meta[0][2]
            conflict_fields = list(conflict_dict.keys())
            for base_itm, _ in base_entries:
                unresolved_base_conflicts.append((base_itm, conflict_fields))

            for itm, srcs, cdict in items_meta:
                if base_filename not in srcs:
                    flag = f"[! CONFLICT ({', '.join(cdict.keys())}) WITH {base_filename} !]"
                    result_records.append((itm, srcs, flag, cdict))

    return result_records, entries_to_delete, unresolved_base_conflicts


# ==============================================================================
# Terminal & File Report Builders
# ==============================================================================

def get_item_display_info(item, target_format):
    """Extracts (container_name, item_name, identifier_or_type) for display."""
    if target_format == 'personal':
        container = item.get('_folder', "")
    else:
        cols = item.get('_collections', [])
        container = ", ".join(cols) if cols else ""

    name = item.get('name') or "-"
    itype = item.get('type', 1)

    if itype == 1:
        user = (item.get('login') or {}).get('username') or "-"
    else:
        user = f"<{TYPE_NAMES.get(itype, 'item')}>"

    return container, name, user


def format_detailed_item_lines(item, target_format, sources, flag, conflict_details) -> list[str]:
    """Formats comprehensive non-secret audit metadata lines for an item in --detailed-report mode."""
    lines = []
    itype = item.get('type', 1)
    type_str = TYPE_NAMES.get(itype, f"unknown({itype})")

    meta_flags = [f"Type: {type_str}"]
    if target_format == 'personal':
        meta_flags.append(f"Favorite: {'Yes' if item.get('favorite') else 'No'}")
    meta_flags.append(f"Reprompt: {'Yes' if item.get('reprompt') == 1 else 'No'}")

    archived = (item.get('archivedDate') or "").strip()
    if archived:
        meta_flags.append(f"Archived: {archived}")

    if itype == 1:
        login_obj = item.get('login') or {}
        has_pw = bool(login_obj.get('password'))
        has_totp = bool(login_obj.get('totp'))
        passkeys = login_obj.get('fido2Credentials') or []
        meta_flags.append(f"Password: {'Set' if has_pw else 'Empty'}")
        meta_flags.append(f"TOTP: {'Set' if has_totp else 'No'}")
        if passkeys:
            meta_flags.append(f"Passkeys: {len(passkeys)}")

    lines.append(f"      Meta    : {' | '.join(meta_flags)}")
    lines.append(f"      Sources : {', '.join(sources)}")

    if flag:
        lines.append(f"      Status  : {flag}")

    if itype == 1:
        uris = [
            u.get('uri').strip()
            for u in ((item.get('login') or {}).get('uris') or [])
            if isinstance(u, dict) and isinstance(u.get('uri'), str) and u.get('uri').strip()
        ]
        if uris:
            lines.append(f"      URIs    : {', '.join(uris)}")

    fields = item.get('fields') or []
    if fields:
        field_names = [f.get('name') or '<unnamed>' for f in fields if isinstance(f, dict)]
        lines.append(f"      Fields  : {', '.join(field_names)} ({len(field_names)} total)")

    pw_hist = item.get('passwordHistory') or []
    if pw_hist:
        lines.append(f"      History : {len(pw_hist)} previous password(s)")

    notes = (item.get('notes') or "").strip()
    if notes:
        single_line_notes = notes.replace("\r\n", " ").replace("\n", " / ")
        if len(single_line_notes) > 90:
            single_line_notes = single_line_notes[:87] + "..."
        lines.append(f"      Notes   : {single_line_notes}")

    if conflict_details:
        lines.append("      Conflict Details:")
        for fpath, options in conflict_details.items():
            lines.append(f"        - Field '{fpath}':")
            for idx, (val, srcs) in enumerate(options, start=1):
                val_preview = repr(val) if isinstance(val, str) else str(val)
                if len(val_preview) > 75:
                    val_preview = val_preview[:72] + "..."
                lines.append(f"            Option {idx} ({', '.join(srcs)}): {val_preview}")

    return lines


def build_summary_report(
    records,
    target_format: str,
    total_files: int,
    always_show_sources: bool = False,
    detailed: bool = False,
    mode: str = "",
    input_files: list[str] = None
) -> str:
    """Builds the formatted result report string (compact or detailed)."""
    lines = []
    total_entries = len(records)

    if detailed:
        lines.append("=" * 76)
        lines.append("BITWARDEN VAULT DETAILED REPORT")
        lines.append("=" * 76)
        if mode:
            lines.append(f"Mode           : {mode}")
        lines.append(f"Vault Format   : {target_format}")
        if input_files:
            lines.append(f"Input Files    : {', '.join(input_files)}")
        lines.append(f"Total Entries  : {total_entries}")

        # Breakdown by item type
        type_counts = {}
        archived_count = 0
        for itm, _, _, _ in records:
            tname = TYPE_NAMES.get(itm.get('type', 1), 'other')
            type_counts[tname] = type_counts.get(tname, 0) + 1
            if (itm.get('archivedDate') or "").strip():
                archived_count += 1

        if type_counts:
            breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(type_counts.items()))
            lines.append(f"Type Breakdown : {breakdown}")
        if archived_count:
            lines.append(f"Archived Items : {archived_count}")
        lines.append("=" * 76)

    if total_entries == 0:
        lines.append("\n=== Result List (0 entries) ===")
        lines.append("The result list is empty.\n")
        return "\n".join(lines)

    container_label = "Folder" if target_format == "personal" else "Collection"
    empty_label = f"(No {container_label})"

    enriched = []
    for item, sources, flag, cdict in records:
        container, name, user = get_item_display_info(item, target_format)
        enriched.append((container, name, user, sources, flag, item, cdict))

    enriched.sort(key=lambda x: (x[0].lower(), x[1].lower(), x[2].lower()))

    max_name_len = max(max(len(x[1]) for x in enriched), len("Name"))
    max_user_len = max(max(len(x[2]) for x in enriched), len("Username / Type"))
    replace_count = sum(1 for x in enriched if x[4].startswith("[! REPLACE"))
    conflict_count = sum(1 for x in enriched if x[4].startswith("[! CONFLICT"))

    lines.append(f"\n=== Result List ({total_entries} {'entry' if total_entries == 1 else 'entries'}) ===")
    if replace_count > 0:
        lines.append(
            f"NOTE: {replace_count} {'entry is' if replace_count == 1 else 'entries are'} "
            f"marked with '[! REPLACE ... !]' — delete existing version(s) in your target vault before importing!"
        )
    if conflict_count > 0:
        lines.append(
            f"WARNING: {conflict_count} {'entry has' if conflict_count == 1 else 'entries have'} "
            f"unresolved '[! CONFLICT ... !]' — re-run with '--resolve-conflicts' (-r) to resolve interactively!"
        )

    grouped = {}
    for entry in enriched:
        grouped.setdefault(entry[0], []).append(entry)

    for folder_name, group in grouped.items():
        display_folder = folder_name if folder_name else empty_label
        lines.append(f"\n[{display_folder}] ({len(group)})")
        for _, name, user, sources, flag, item, cdict in group:
            suffix_parts = []
            if flag:
                suffix_parts.append(flag)
            if always_show_sources or len(sources) < total_files:
                suffix_parts.append(f"[in: {', '.join(sources)}]")

            suffix = f"  {' '.join(suffix_parts)}" if suffix_parts else ""
            lines.append(f"  {name:<{max_name_len}}  |  {user:<{max_user_len}}{suffix}")

            if detailed:
                lines.extend(format_detailed_item_lines(item, target_format, sources, flag, cdict))

    lines.append("\n==================================\n")
    return "\n".join(lines)


def build_import_diff_summary(entries_to_delete, unresolved_conflicts, target_format, base_filename) -> str:
    """Builds the consolidated post-processing summary string with column headers for 'import-diff'."""
    if not entries_to_delete and not unresolved_conflicts:
        return ""

    lines = []
    container_label = "Folder" if target_format == "personal" else "Collection"
    empty_label = f"(No {container_label})"

    lines.append("\n" + "!" * 76)
    lines.append(f"IMPORT-DIFF SUMMARY FOR '{base_filename}'")
    lines.append("!" * 76)

    if entries_to_delete:
        del_rows = []
        for itm in entries_to_delete:
            container, name, user = get_item_display_info(itm, target_format)
            display_container = container if container else empty_label
            del_rows.append((display_container, name, user))

        del_rows.sort(key=lambda x: (x[0].lower(), x[1].lower(), x[2].lower()))
        max_c = max(max(len(r[0]) for r in del_rows), len(container_label))
        max_n = max(max(len(r[1]) for r in del_rows), len("Name"))
        max_u = max(max(len(r[2]) for r in del_rows), len("Username / Type"))

        lines.append(f"\n1. DELETE BEFORE IMPORT ({len(del_rows)} {'entry' if len(del_rows) == 1 else 'entries'}):")
        lines.append(f"   These entries were merged/resolved and must be deleted from '{base_filename}' prior to import:\n")
        header = f"     Status  {container_label:<{max_c}}  |  {'Name':<{max_n}}  |  {'Username / Type':<{max_u}}"
        lines.append(header)
        lines.append("     " + "-" * (len(header) - 5))
        for container, name, user in del_rows:
            lines.append(f"     [ ]     {container:<{max_c}}  |  {name:<{max_n}}  |  {user:<{max_u}}")

    if unresolved_conflicts:
        conf_rows = []
        for itm, cfields in unresolved_conflicts:
            container, name, user = get_item_display_info(itm, target_format)
            display_container = container if container else empty_label
            conf_rows.append((display_container, name, user, ", ".join(cfields)))

        conf_rows.sort(key=lambda x: (x[0].lower(), x[1].lower(), x[2].lower()))
        max_c = max(max(len(r[0]) for r in conf_rows), len(container_label))
        max_n = max(max(len(r[1]) for r in conf_rows), len("Name"))
        max_u = max(max(len(r[2]) for r in conf_rows), len("Username / Type"))
        max_f = max(max(len(r[3]) for r in conf_rows), len("Conflict Fields"))

        step_num = "2" if entries_to_delete else "1"
        lines.append(f"\n{step_num}. UNRESOLVED CONFLICTS ({len(conf_rows)} {'entry' if len(conf_rows) == 1 else 'entries'}):")
        lines.append(f"   These entries conflict with '{base_filename}' and would create duplicates on import:\n")
        header = (
            f"     Status  {container_label:<{max_c}}  |  {'Name':<{max_n}}  |  "
            f"{'Username / Type':<{max_u}}  |  {'Conflict Fields':<{max_f}}"
        )
        lines.append(header)
        lines.append("     " + "-" * (len(header) - 5))
        for container, name, user, cfields_str in conf_rows:
            lines.append(f"     [!]     {container:<{max_c}}  |  {name:<{max_n}}  |  {user:<{max_u}}  |  {cfields_str:<{max_f}}")
        lines.append("\n   TIP: Re-run with '--resolve-conflicts' (-r) to interactively merge or choose values for these conflicts!")

    lines.append("\n" + "!" * 76 + "\n")
    return "\n".join(lines)


def _escape_md_cell(text: str) -> str:
    """Escapes pipe characters and newlines so Markdown tables stay intact."""
    return str(text).replace("|", "\\|").replace("\r\n", " ").replace("\n", " / ")


def build_markdown_report(
    records,
    target_format: str,
    total_files: int,
    always_show_sources: bool = False,
    detailed: bool = False,
    mode: str = "",
    input_files: list[str] = None,
    entries_to_delete: list = None,
    unresolved_conflicts: list = None,
    base_filename: str = ""
) -> str:
    """Builds a structured Markdown report (.md) for saving via --list-output (-L)."""
    lines = ["# Bitwarden Vault Report", ""]
    total_entries = len(records)

    # 1. Metadata & Overview Table
    lines.append("## Overview")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("| :--- | :--- |")
    if mode:
        lines.append(f"| **Mode** | `{mode}` |")
    lines.append(f"| **Vault Structure** | `{target_format}` |")
    if input_files:
        lines.append(f"| **Input Files** | {', '.join(f'`{f}`' for f in input_files)} |")
    lines.append(f"| **Total Entries** | {total_entries} |")

    if detailed:
        type_counts = {}
        archived_count = 0
        for itm, _, _, _ in records:
            tname = TYPE_NAMES.get(itm.get('type', 1), 'other')
            type_counts[tname] = type_counts.get(tname, 0) + 1
            if (itm.get('archivedDate') or "").strip():
                archived_count += 1

        if type_counts:
            breakdown = ", ".join(f"{k}: **{v}**" for k, v in sorted(type_counts.items()))
            lines.append(f"| **Type Breakdown** | {breakdown} |")
        if archived_count:
            lines.append(f"| **Archived Items** | {archived_count} |")

    lines.append("")

    # 2. Result List grouped by Folder / Collection
    lines.append(f"## Result List ({total_entries} {'entry' if total_entries == 1 else 'entries'})")
    lines.append("")

    if total_entries == 0:
        lines.append("*The result list is empty.*")
        lines.append("")
    else:
        container_label = "Folder" if target_format == "personal" else "Collection"
        empty_label = f"(No {container_label})"

        enriched = []
        for item, sources, flag, cdict in records:
            container, name, user = get_item_display_info(item, target_format)
            enriched.append((container, name, user, sources, flag, item, cdict))

        enriched.sort(key=lambda x: (x[0].lower(), x[1].lower(), x[2].lower()))

        replace_count = sum(1 for x in enriched if x[4].startswith("[! REPLACE"))
        conflict_count = sum(1 for x in enriched if x[4].startswith("[! CONFLICT"))

        if replace_count > 0:
            lines.append(
                f"> **Note:** {replace_count} {'entry is' if replace_count == 1 else 'entries are'} "
                f"marked with `REPLACE` — delete existing version(s) in your target vault before importing."
            )
            lines.append("")
        if conflict_count > 0:
            lines.append(
                f"> **Warning:** {conflict_count} {'entry has' if conflict_count == 1 else 'entries have'} "
                f"unresolved conflicts — re-run with `--resolve-conflicts` (`-r`) to resolve interactively."
            )
            lines.append("")

        grouped = {}
        for entry in enriched:
            grouped.setdefault(entry[0], []).append(entry)

        for folder_name, group in grouped.items():
            display_folder = folder_name if folder_name else empty_label
            lines.append(f"### {display_folder} ({len(group)})")
            lines.append("")

            if not detailed:
                lines.append("| Name | Username / Type | Status | Sources |")
                lines.append("| :--- | :--- | :--- | :--- |")
                for _, name, user, sources, flag, _, _ in group:
                    src_str = ", ".join(f"`{s}`" for s in sources) if (always_show_sources or len(sources) < total_files) else "All files"
                    status_str = f"**`{flag}`**" if flag else "OK"
                    lines.append(
                        f"| {_escape_md_cell(name)} | {_escape_md_cell(user)} | "
                        f"{_escape_md_cell(status_str)} | {_escape_md_cell(src_str)} |"
                    )
                lines.append("")
            else:
                for _, name, user, sources, flag, item, cdict in group:
                    itype = item.get('type', 1)
                    type_str = TYPE_NAMES.get(itype, f"unknown({itype})")
                    status_badge = f" — **`{flag}`**" if flag else ""
                    lines.append(f"#### {name} (`{user}`){status_badge}")
                    lines.append("")
                    lines.append(f"- **Type:** `{type_str}`")
                    lines.append(f"- **Sources:** {', '.join(f'`{s}`' for s in sources)}")

                    meta_flags = []
                    if target_format == 'personal':
                        meta_flags.append(f"Favorite: {'Yes' if item.get('favorite') else 'No'}")
                    meta_flags.append(f"Reprompt: {'Yes' if item.get('reprompt') == 1 else 'No'}")
                    archived = (item.get('archivedDate') or "").strip()
                    if archived:
                        meta_flags.append(f"Archived: `{archived}`")
                    if itype == 1:
                        login_obj = item.get('login') or {}
                        meta_flags.append(f"Password: {'Set' if login_obj.get('password') else 'Empty'}")
                        meta_flags.append(f"TOTP: {'Set' if login_obj.get('totp') else 'No'}")
                        passkeys = login_obj.get('fido2Credentials') or []
                        if passkeys:
                            meta_flags.append(f"Passkeys: {len(passkeys)}")
                    lines.append(f"- **Attributes:** {' | '.join(meta_flags)}")

                    if itype == 1:
                        uris = [
                            u.get('uri').strip()
                            for u in ((item.get('login') or {}).get('uris') or [])
                            if isinstance(u, dict) and isinstance(u.get('uri'), str) and u.get('uri').strip()
                        ]
                        if uris:
                            lines.append(f"- **URIs:** {', '.join(f'`{u}`' for u in uris)}")

                    fields = item.get('fields') or []
                    if fields:
                        field_names = [f.get('name') or '<unnamed>' for f in fields if isinstance(f, dict)]
                        lines.append(f"- **Custom Fields ({len(field_names)}):** {', '.join(f'`{fn}`' for fn in field_names)}")

                    pw_hist = item.get('passwordHistory') or []
                    if pw_hist:
                        lines.append(f"- **Password History:** {len(pw_hist)} previous password(s)")

                    notes = (item.get('notes') or "").strip()
                    if notes:
                        single_line_notes = notes.replace("\r\n", " ").replace("\n", " / ")
                        if len(single_line_notes) > 120:
                            single_line_notes = single_line_notes[:117] + "..."
                        lines.append(f"- **Notes Preview:** {single_line_notes}")

                    if cdict:
                        lines.append("- **Conflict Details:**")
                        for fpath, options in cdict.items():
                            lines.append(f"  - Field `{fpath}`:")
                            for idx, (val, srcs) in enumerate(options, start=1):
                                val_preview = repr(val) if isinstance(val, str) else str(val)
                                lines.append(f"    - Option {idx} ({', '.join(f'`{s}`' for s in srcs)}): `{val_preview}`")

                    lines.append("")

    # 3. Post-Processing Summary for import-diff
    if mode == "import-diff" and (entries_to_delete or unresolved_conflicts):
        container_label = "Folder" if target_format == "personal" else "Collection"
        empty_label = f"(No {container_label})"

        lines.append("---")
        lines.append("")
        lines.append(f"## Pre-Import Checklist for `{base_filename}`")
        lines.append("")

        if entries_to_delete:
            del_rows = []
            for itm in entries_to_delete:
                container, name, user = get_item_display_info(itm, target_format)
                display_container = container if container else empty_label
                del_rows.append((display_container, name, user))
            del_rows.sort(key=lambda x: (x[0].lower(), x[1].lower(), x[2].lower()))

            lines.append(f"### 1. Delete Before Import ({len(del_rows)} {'entry' if len(del_rows) == 1 else 'entries'})")
            lines.append("")
            lines.append(f"These entries were merged/resolved and must be deleted from `{base_filename}` prior to import:")
            lines.append("")
            lines.append(f"| Done | {container_label} | Name | Username / Type |")
            lines.append("| :---: | :--- | :--- | :--- |")
            for container, name, user in del_rows:
                lines.append(
                    f"| [ ] | {_escape_md_cell(container)} | {_escape_md_cell(name)} | {_escape_md_cell(user)} |"
                )
            lines.append("")

        if unresolved_conflicts:
            conf_rows = []
            for itm, cfields in unresolved_conflicts:
                container, name, user = get_item_display_info(itm, target_format)
                display_container = container if container else empty_label
                conf_rows.append((display_container, name, user, ", ".join(f"`{cf}`" for cf in cfields)))
            conf_rows.sort(key=lambda x: (x[0].lower(), x[1].lower(), x[2].lower()))

            step_num = "2" if entries_to_delete else "1"
            lines.append(f"### {step_num}. Unresolved Conflicts ({len(conf_rows)} {'entry' if len(conf_rows) == 1 else 'entries'})")
            lines.append("")
            lines.append(f"These entries conflict with `{base_filename}` and would create duplicates on import:")
            lines.append("")
            lines.append(f"| Status | {container_label} | Name | Username / Type | Conflict Fields |")
            lines.append("| :---: | :--- | :--- | :--- | :--- |")
            for container, name, user, cfields_str in conf_rows:
                lines.append(
                    f"| ⚠️ | {_escape_md_cell(container)} | {_escape_md_cell(name)} | "
                    f"{_escape_md_cell(user)} | {cfields_str} |"
                )
            lines.append("")
            lines.append("> **Tip:** Re-run with `--resolve-conflicts` (`-r`) to interactively merge or choose values for these conflicts.")
            lines.append("")

    return "\n".join(lines).strip() + "\n"

# ==============================================================================
# Export Builders (JSON and CSV)
# ==============================================================================

def build_export_json(items, target_format):
    """Reconstructs a valid Bitwarden JSON export with fresh UUIDs for folders/collections and items."""
    export_items = []

    if target_format == 'personal':
        folder_names = sorted(dict.fromkeys(
            itm.get('_folder', "") for itm in items if itm.get('_folder')
        ))
        name_to_id = {fname: str(uuid.uuid4()) for fname in folder_names}
        folders_array = [{"id": fid, "name": fname} for fname, fid in name_to_id.items()]

        for itm in items:
            clean = copy.deepcopy(itm)
            fname = clean.pop('_folder', "")
            clean['id'] = str(uuid.uuid4())
            clean['folderId'] = name_to_id[fname] if fname else None
            clean.pop('collectionIds', None)
            clean.pop('organizationId', None)
            export_items.append(clean)

        return {
            "encrypted": False,
            "folders": folders_array,
            "items": export_items
        }

    else:
        col_names = sorted(dict.fromkeys(
            cname for itm in items for cname in itm.get('_collections', []) if cname
        ))
        name_to_id = {cname: str(uuid.uuid4()) for cname in col_names}
        collections_array = [
            {"id": cid, "organizationId": None, "name": cname, "externalId": None}
            for cname, cid in name_to_id.items()
        ]

        for itm in items:
            clean = copy.deepcopy(itm)
            cnames = clean.pop('_collections', [])
            clean['id'] = str(uuid.uuid4())
            clean['collectionIds'] = [name_to_id[c] for c in cnames if c in name_to_id]
            clean.pop('folderId', None)
            clean.pop('favorite', None)
            export_items.append(clean)

        return {
            "encrypted": False,
            "collections": collections_array,
            "items": export_items
        }


def write_export_csv(items, target_format, filepath):
    """Exports normalized items into a Bitwarden-compatible CSV file."""
    cols = PERSONAL_CSV_COLS if target_format == 'personal' else ORG_CSV_COLS
    rows = []
    skipped_unsupported_types = 0

    for itm in items:
        itype = itm.get('type', 1)
        if itype not in INT_TO_CSV_TYPE:
            skipped_unsupported_types += 1
            continue

        login_obj = itm.get('login') or {}
        uris_list = [
            u.get('uri', '').strip()
            for u in (login_obj.get('uris') or [])
            if isinstance(u, dict) and u.get('uri', '').strip()
        ]
        fields_list = [
            f"{fld.get('name', '')}: {fld.get('value', '')}"
            for fld in (itm.get('fields') or [])
            if isinstance(fld, dict)
        ]

        row_dict = {
            'type': INT_TO_CSV_TYPE[itype],
            'name': itm.get('name') or '',
            'notes': itm.get('notes') or '',
            'fields': '\n'.join(fields_list),
            'reprompt': '1' if itm.get('reprompt') == 1 else '0',
            'archivedDate': itm.get('archivedDate') or '',
            'login_uri': ', '.join(uris_list),
            'login_username': login_obj.get('username') or '',
            'login_password': login_obj.get('password') or '',
            'login_totp': login_obj.get('totp') or ''
        }

        if target_format == 'personal':
            row_dict['folder'] = itm.get('_folder', '')
            row_dict['favorite'] = '1' if itm.get('favorite') else '0'
        else:
            row_dict['collections'] = ', '.join(itm.get('_collections', []))

        rows.append([row_dict[c] for c in cols])

    with open(filepath, mode='w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        writer.writerows(rows)

    return len(rows), skipped_unsupported_types


def print_csv_data_loss_warnings(all_inputs_csv: bool, has_json_input: bool, is_csv_output: bool, skipped_count: int = 0):
    """Displays data loss warnings ONLY when actual metadata/feature loss can occur."""
    if all_inputs_csv and is_csv_output:
        return

    if has_json_input and not all_inputs_csv:
        print(
            "WARNING (Mixed CSV + JSON Input): CSV files lack advanced Bitwarden JSON metadata "
            "(such as passwordHistory, URI match rules, custom field types, passkeys/FIDO2, and SSH keys). "
            "Entries sourced from CSV will not carry those JSON-exclusive fields."
        )

    if has_json_input and is_csv_output:
        print(
            "WARNING (JSON -> CSV Data Loss): Exporting JSON data to CSV drops JSON-exclusive fields, "
            "including passwordHistory, URI match types, custom field types (hidden/boolean/linked), "
            "passkeys (fido2Credentials), card/identity structured fields, and timestamps."
        )
        if skipped_count > 0:
            print(
                f"WARNING (JSON -> CSV Data Loss): {skipped_count} item(s) (e.g., SSH keys) are unsupported by "
                "Bitwarden's CSV format and were omitted."
            )


def resolve_output_encryption_password() -> str:
    """Prompts for an encryption password with confirmation."""
    while True:
        pwd1 = getpass.getpass("Enter password to encrypt output JSON: ")
        if not pwd1:
            print("Password cannot be empty.")
            continue
        pwd2 = getpass.getpass("Confirm encryption password: ")
        if pwd1 != pwd2:
            print("Passwords do not match. Please try again.")
            continue
        return pwd1


def main():
    parser = argparse.ArgumentParser(
        description="Bitwarden Unified JSON & CSV Backup, Decryption & Conversion Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "mode",
        choices=["dedup", "merge", "intersect", "difference", "import-diff", "convert"],
        help=(
            "Available modes:\n"
            "  dedup       : Remove duplicates from 1 file\n"
            "  merge       : Combine 2 or more files without duplicates\n"
            "  intersect   : Intersection of 2 or more files\n"
            "  difference  : Symmetric difference across 2 or more files\n"
            "  import-diff : Extract new & smart-merged entries compared to the 1st file (base vault)\n"
            "  convert     : Convert 1 file between 'personal'/'org' or 'json'/'csv' formats"
        )
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Path(s) to Bitwarden JSON (unencrypted/encrypted) or CSV files (mixing allowed)"
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output vault filename (default: 'bitwarden_output.csv' if all inputs are CSV, otherwise 'bitwarden_output.json')"
    )
    parser.add_argument(
        "-F", "--output-format",
        choices=["json", "csv"],
        help="Explicitly set output vault file format ('json' or 'csv'; overrides default and -o extension)"
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="Only display the result list/report without writing the vault output file"
    )
    parser.add_argument(
        "-L", "--list-output",
        nargs="?",
        const="bitwarden_report.md",
        default=None,
        help="Save the preview list / report output as a Markdown file (default: 'bitwarden_report.md')"
    )
    parser.add_argument(
        "-d", "--detailed-report",
        action="store_true",
        help="Generate an extended audit report (includes item types, URIs, TOTP/passkey flags, field names, notes, and conflict details)"
    )
    parser.add_argument(
        "-s", "--smart-merge",
        action="store_true",
        help=(
            "Smart-merge near-identical entries and report conflicts:\n"
            "  - Matches entries with same identity OR same folder/collection + username + password + >=1 shared URI\n"
            "  - Deduplicates 'uris', 'fields', 'passwordHistory', and 'collections'\n"
            "  - Combines 'favorite', 'notes', 'reprompt', 'totp', and 'fido2Credentials' if only one entry has content"
        )
    )
    parser.add_argument(
        "-r", "--resolve-conflicts",
        action="store_true",
        help="Interactively resolve smart-merge conflicts in the terminal (implies -s/--smart-merge)"
    )
    parser.add_argument(
        "-t", "--target-format",
        choices=["personal", "org"],
        help=(
            "Convert vault structure and allow mixing personal & org exports:\n"
            "  personal : Uses 'folders'/'folder' and includes 'favorite'\n"
            "  org      : Uses 'collections' and drops 'favorite'"
        )
    )
    parser.add_argument(
        "-p", "--password",
        help="Password for encrypted JSON files (if omitted, prompts interactively when needed)"
    )
    parser.add_argument(
        "-e", "--encrypt",
        action="store_true",
        help="Encrypt the output vault file (forces JSON output if -F is not set)"
    )

    args = parser.parse_args()

    if args.resolve_conflicts:
        args.smart_merge = True

    # 1. Validate file count arguments
    if args.mode in ["dedup", "convert"] and len(args.files) != 1:
        sys.exit(f"Error: The '{args.mode}' mode requires exactly 1 file.")
    elif args.mode in ["merge", "intersect", "difference", "import-diff"] and len(args.files) < 2:
        sys.exit(f"Error: The '{args.mode}' mode requires at least 2 files.")

    password_cache = [args.password] if args.password else []

    # 2. Load files (auto-detecting JSON vs CSV and decrypting if encrypted)
    loaded_items = [load_vault_auto(f, password_cache) for f in args.files]
    item_lists = [x[0] for x in loaded_items]
    vault_formats = [x[1] for x in loaded_items]
    file_formats = [x[2] for x in loaded_items]

    all_inputs_csv = all(ff == "csv" for ff in file_formats)
    has_json_input = "json" in file_formats

    # Determine effective output file format
    if args.output_format:
        out_file_format = args.output_format
    elif args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext in [".csv", ".json"]:
            out_file_format = ext[1:]
        else:
            out_file_format = "json" if args.encrypt else ("csv" if all_inputs_csv else "json")
    else:
        if args.encrypt:
            out_file_format = "json"
        elif all_inputs_csv:
            out_file_format = "csv"
        else:
            out_file_format = "json"

    if args.encrypt and out_file_format == "csv":
        sys.exit("Error: Encryption (-e/--encrypt) is only supported for JSON output, not CSV.")

    raw_output_path = args.output if args.output else f"bitwarden_output.{out_file_format}"

    if len(set(vault_formats)) > 1 and not args.target_format:
        sys.exit(
            "Error: Personal exports ('folders'/'folder') and organization exports ('collections') "
            "cannot be combined unless '--target-format personal' or '--target-format org' is specified."
        )

    effective_vault_format = args.target_format if args.target_format else vault_formats[0]
    converted_lists = [
        [convert_item_format(itm, fmt, effective_vault_format) for itm in items]
        for items, fmt in zip(item_lists, vault_formats)
    ]

    basenames = [os.path.basename(f) for f in args.files]
    display_names = basenames if len(set(basenames)) == len(basenames) else args.files

    # Deduplicate each file individually using CSV-compatible core signature
    sig_to_sources = {}
    unique_records = []
    seen_overall = set()

    for items, fname in zip(converted_lists, display_names):
        seen_in_file = set()
        for itm in items:
            sig = get_core_signature(itm, ignore_mergeable=False)
            if sig in seen_in_file:
                continue
            seen_in_file.add(sig)

            if sig not in sig_to_sources:
                sig_to_sources[sig] = []
            sig_to_sources[sig].append(fname)

            if sig not in seen_overall:
                seen_overall.add(sig)
                unique_records.append((itm, sig))

    base_records = [(itm, sig_to_sources[sig]) for itm, sig in unique_records]

    # 3. Filter and process records according to selected mode
    total_files = len(args.files)
    entries_to_delete = []
    unresolved_base_conflicts = []

    if args.mode in ["dedup", "merge", "convert"]:
        if args.smart_merge:
            records = smart_merge_records(base_records, interactive=args.resolve_conflicts)
        else:
            records = [(itm, srcs, "", {}) for itm, srcs in base_records]

    elif args.mode == "intersect":
        if args.smart_merge:
            merged = smart_merge_records(base_records, interactive=args.resolve_conflicts)
            records = [(itm, srcs, flag, cdict) for itm, srcs, flag, cdict in merged if len(srcs) == total_files]
        else:
            records = [(itm, srcs, "", {}) for itm, srcs in base_records if len(srcs) == total_files]

    elif args.mode == "difference":
        if args.smart_merge:
            merged = smart_merge_records(base_records, interactive=args.resolve_conflicts)
            records = [(itm, srcs, flag, cdict) for itm, srcs, flag, cdict in merged if len(srcs) % 2 == 1]
        else:
            records = [(itm, srcs, "", {}) for itm, srcs in base_records if len(srcs) % 2 == 1]

    elif args.mode == "import-diff":
        records, entries_to_delete, unresolved_base_conflicts = compute_import_diff(
            base_records, display_names[0], interactive=args.resolve_conflicts
        )

    # 4. Build and display the summary / detailed report
    report_text = build_summary_report(
        records,
        effective_vault_format,
        total_files,
        always_show_sources=(args.mode in ["intersect", "import-diff"]),
        detailed=args.detailed_report,
        mode=args.mode,
        input_files=display_names
    )
    print(report_text)

    # 5. Save vault result only if --list (-l) was NOT specified
    if not args.list:
        final_items = [itm for itm, _, _, _ in records]
        final_output_path = resolve_output_filename(raw_output_path, out_file_format, args.encrypt)

        if out_file_format == "json":
            export_payload = build_export_json(final_items, effective_vault_format)
            if args.encrypt:
                out_pwd = args.password if args.password else resolve_output_encryption_password()
                export_payload = encrypt_bitwarden_payload(export_payload, out_pwd)

            try:
                with open(final_output_path, mode='w', encoding='utf-8') as f:
                    json.dump(export_payload, f, indent=2, ensure_ascii=False)
                print_csv_data_loss_warnings(
                    all_inputs_csv=all_inputs_csv,
                    has_json_input=has_json_input,
                    is_csv_output=False
                )
                enc_label = "encrypted " if args.encrypt else ""
                print(
                    f"Done! {len(final_items)} entries saved in {enc_label}"
                    f"'{effective_vault_format}' JSON format to '{final_output_path}'."
                )
            except PermissionError:
                sys.exit(f"Error: Permission denied when writing to '{final_output_path}' (is the file currently open?).")

        else:
            try:
                written_count, skipped_count = write_export_csv(
                    final_items, effective_vault_format, final_output_path
                )
                print_csv_data_loss_warnings(
                    all_inputs_csv=all_inputs_csv,
                    has_json_input=has_json_input,
                    is_csv_output=True,
                    skipped_count=skipped_count
                )
                print(
                    f"Done! {written_count} entries saved in '{effective_vault_format}' CSV format "
                    f"to '{final_output_path}'."
                )
            except PermissionError:
                sys.exit(f"Error: Permission denied when writing to '{final_output_path}' (is the file currently open?).")
    else:
        print_csv_data_loss_warnings(
            all_inputs_csv=all_inputs_csv,
            has_json_input=has_json_input,
            is_csv_output=False
        )
        print(
            f"Preview only (--list): {len(records)} entries found "
            f"({effective_vault_format} structure), no vault file written."
        )

    # 6. Build and display consolidated post-processing summary for import-diff
    diff_summary_text = ""
    if args.mode == "import-diff":
        diff_summary_text = build_import_diff_summary(
            entries_to_delete,
            unresolved_base_conflicts,
            effective_vault_format,
            display_names[0]
        )
        if diff_summary_text:
            print(diff_summary_text)

    # 7. Save Markdown report output if --list-output (-L) was specified
    if args.list_output:
        report_path = args.list_output
        if not os.path.splitext(report_path)[1]:
            report_path += ".md"

        md_report = build_markdown_report(
            records=records,
            target_format=effective_vault_format,
            total_files=total_files,
            always_show_sources=(args.mode in ["intersect", "import-diff"]),
            detailed=args.detailed_report,
            mode=args.mode,
            input_files=display_names,
            entries_to_delete=entries_to_delete,
            unresolved_conflicts=unresolved_base_conflicts,
            base_filename=display_names[0]
        )
        try:
            with open(report_path, mode='w', encoding='utf-8') as f:
                f.write(md_report)
            print(f"Markdown report saved to '{report_path}'.")
        except PermissionError:
            sys.exit(f"Error: Permission denied when writing report to '{report_path}' (is the file currently open?).")


if __name__ == "__main__":
    main()