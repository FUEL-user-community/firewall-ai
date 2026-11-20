import os
import io
import csv
import re
import logging
from googleapiclient.discovery import build
from google.oauth2 import service_account
from googleapiclient.http import MediaIoBaseDownload
try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

logger = logging.getLogger(__name__)

_FOLDER_MIME = "application/vnd.google-apps.folder"
_SKIP_DRIVE_DIRS = frozenset({".git", "__pycache__", ".slots", ".state", "tests", "_legacy", ".venv", "venv"})
_DRIVE_TEXT_EXTS = (
    ".md", ".markdown", ".txt", ".yaml", ".yml", ".py", ".json", ".log", ".xml", ".conf"
)
_DRIVE_TEXT_MIMES = (
    "text/markdown",
    "text/plain",
    "text/x-markdown",
    "text/x-python",
    "application/json",
    "application/xml",
    "text/xml",
)


def _sanitize_external_text(text: str) -> str:
    """Neutralize prompt-injection control sentinels in external Drive documents."""
    try:
        from core.integrations.board_sync import neutralize_board_prose
        return neutralize_board_prose(text or "")
    except Exception:
        out = text or ""
        out = re.sub(r"\[SYSTEM\s*:", "[BOARD-QUOTED-SYSTEM:", out, flags=re.IGNORECASE)
        out = re.sub(r"\[Step\s+\d+", "[BOARD-QUOTED-STEP", out, flags=re.IGNORECASE)
        out = re.sub(r"GEMINI_FILE_URI\s*:", "BOARD_QUOTED_URI:", out, flags=re.IGNORECASE)
        return out


def _is_sensitive_drive_item(name: str) -> bool:
    """Block accidental credential, device-secret, or raw running-config files in Drive."""
    base = (name or "").rsplit("/", 1)[-1].strip().lower()
    if not base:
        return True
    if base.startswith(".env") or base in ("devices.yaml", "devices.yml"):
        return True
    if "service_account" in base or "gdrive_token" in base or "oauth_token" in base or "running_config" in base:
        return True
    if base.endswith((".pem", ".key", ".pfx", ".p12")):
        return True
    return False


def _list_drive_items_recursive(service, root_folder_id: str, max_depth: int = 3) -> list:
    """
    List readable files under `root_folder_id`, traversing nested folders up to `max_depth`.
    When no folder items exist at the root level, executes a single flat `files.list` call.
    """
    collected = []

    def _walk(parent_id: str, prefix: str, depth: int):
        res = service.files().list(
            q=f"'{parent_id}' in parents and trashed = false",
            spaces="drive",
            fields="files(id, name, mimeType)",
        ).execute()
        for entry in res.get("files", []):
            raw_name = entry.get("name", "")
            mime = entry.get("mimeType", "")
            if mime == _FOLDER_MIME:
                if depth < max_depth and raw_name not in _SKIP_DRIVE_DIRS and not raw_name.startswith("."):
                    sub_prefix = f"{prefix}{raw_name}/" if prefix else f"{raw_name}/"
                    _walk(entry["id"], sub_prefix, depth + 1)
                continue
            rel_name = f"{prefix}{raw_name}" if prefix else raw_name
            if _is_sensitive_drive_item(rel_name):
                continue
            collected.append({
                "id": entry["id"],
                "name": rel_name,
                "mimeType": mime,
            })

    _walk(root_folder_id, "", 0)
    return collected


def _query_or_walk_drive(service, folder_id: str, target: str = None) -> list:
    """Fast direct-name query when `target` is a bare filename, falling back to recursive tree walk."""
    items = []
    if target and "/" not in target:
        try:
            target_safe = target.replace("'", "\\'")
            query = f"'{folder_id}' in parents and name contains '{target_safe}' and trashed = false"
            results = service.files().list(
                q=query, spaces="drive", fields="files(id, name, mimeType)"
            ).execute()
            items = [
                it for it in results.get("files", [])
                if it.get("mimeType") != _FOLDER_MIME and not _is_sensitive_drive_item(it.get("name", ""))
            ]
        except Exception:
            items = []
    if not items:
        all_items = _list_drive_items_recursive(service, folder_id, max_depth=3)
        items = _find_matching_items(target, all_items) if target else all_items
    return items


def _init_drive_service():
    """Initializes the Google Drive API service via unified thread-safe GoogleDriveClient singleton."""
    try:
        from core.integrations.gdrive_client import GoogleDriveClient
        client = GoogleDriveClient.get_instance(mode="readonly")
        return client.get_service()
    except Exception as e:
        logger.error(f"[DRIVE-RAG] Failed to initialize Drive service: {e}")
        return None, str(e)

def query_knowledge_base(action: str, target: str = None, start_page: int = None, end_page: int = None, panos_version: str = None, **kwargs) -> str:
    """
    Query the Google Drive Knowledge Base for official PAN-OS documentation.
    
    Args:
        action (str): 'list_contents' (finds matching docs and returns Table of Contents/First pages) 
                      or 'read_slice' (reads specific pages from a target doc).
        target (str): The name of the document to search for or read from.
        start_page (int): Starting page number (inclusive) for 'read_slice'.
        end_page (int): Ending page number (inclusive) for 'read_slice'.
        panos_version (str): Optional PAN-OS software version (e.g. '10.2', '11.1') to match version-specific CLI manuals and release notes.
    """
    if not action or not isinstance(action, str):
        return "Error: 'action' parameter is required ('list_contents', 'read_toc', or 'read_slice')."

    service, err_msg = _init_drive_service()
    if not service:
        return f"Error: Google Drive API not configured. Details: {err_msg}"
        
    folder_id = os.getenv("KNOWLEDGE_BASE_FOLDER_ID") or os.getenv("GOOGLE_DRIVE_FOLDER_ID")
    if not folder_id:
        return "Error: Missing KNOWLEDGE_BASE_FOLDER_ID or GOOGLE_DRIVE_FOLDER_ID in environment."

    clean_action = action.strip().lower()
    if target and _is_sensitive_drive_item(target):
        return f"Error: Access to sensitive/credential file '{target}' is forbidden."

    if clean_action in ('list_contents', 'read_toc', 'read_toc_'):
        try:
            items = _query_or_walk_drive(service, folder_id, target=target)

            # Filter by panos_version if specified and matching documents exist
            if panos_version and items:
                v_clean = str(panos_version).strip().lower()
                version_matched = [it for it in items if v_clean in it.get('name', '').lower()]
                if version_matched:
                    items = version_matched

            if not items:
                return f"No documents found matching '{target or 'all'}'. Try different keywords."

            response_lines = ["--- KNOWLEDGE BASE DOCUMENTS ---"]
            for item in items:
                response_lines.append(f"Document: {item['name']} (ID: {item['id']})")

            if target and len(items) == 1:
                # If specifically querying one doc, try to extract its TOC or CSV summary
                file_id = items[0]['id']
                actual_name = items[0]['name']
                mime_type = items[0].get('mimeType', '')
                if _is_csv_item(actual_name, mime_type):
                    response_lines.append("\n--- EXTRACTING CSV CVE DATA ---")
                    csv_text = _extract_csv_summary(service, file_id, panos_version=panos_version, max_rows=10)
                    response_lines.append(csv_text)
                elif _is_markdown_or_text_item(actual_name, mime_type):
                    response_lines.append("\n--- EXTRACTING MARKDOWN / TEXT PREVIEW ---")
                    response_lines.append(_extract_text_document(service, file_id, max_chars=4000))
                else:
                    response_lines.append("\n--- EXTRACTING TABLE OF CONTENTS (Pages 1-5) ---")
                    toc_text = _extract_pdf_pages(service, file_id, 1, 5)
                    response_lines.append(toc_text)

            response_lines.append("\nINSTRUCTIONS:")
            response_lines.append("To read specific sections, use action='read_slice' with the exact 'target' name and the 'start_page' / 'end_page'.")

            return "\n".join(response_lines)

        except Exception as e:
            return f"Error listing Knowledge Base contents: {e}"

    elif clean_action == 'read_slice':
        if not target:
            return "Error: 'read_slice' requires 'target'."

        try:
            items = _query_or_walk_drive(service, folder_id, target=target)

            # Filter by panos_version if specified and matching documents exist
            if panos_version and items:
                v_clean = str(panos_version).strip().lower()
                version_matched = [it for it in items if v_clean in it.get('name', '').lower()]
                if version_matched:
                    items = version_matched

            if not items:
                return f"Error: Document '{target}' not found."

            file_id = items[0]['id']
            actual_name = items[0]['name']
            mime_type = items[0].get('mimeType', '')
            if _is_sensitive_drive_item(actual_name):
                return f"Error: Access to sensitive/credential file '{actual_name}' is forbidden."

            # Route tabular CSV documents through structured CSV parser (pages optional)
            if _is_csv_item(actual_name, mime_type):
                extracted = _extract_csv_summary(service, file_id, panos_version=panos_version, max_rows=20)
                if str(extracted).startswith(("Error", "PDF Extraction Failed")):
                    return f"Error: Could not read '{actual_name}': {extracted}"
                return f"--- READING CSV DATA: {actual_name} ---\n\n{extracted}"

            # Route Markdown and plain-text documents directly instead of feeding pypdf
            if _is_markdown_or_text_item(actual_name, mime_type):
                extracted = _extract_text_document(service, file_id, max_chars=16000)
                if str(extracted).startswith("Error"):
                    return f"Error: Could not read '{actual_name}': {extracted}"
                return f"--- READING MARKDOWN: {actual_name} ---\n\n{extracted}"

            if not start_page or not end_page:
                return "Error: 'read_slice' requires 'target', 'start_page', and 'end_page'."

            if not HAS_PYPDF:
                return "Error: 'pypdf' library is missing. Cannot slice PDF documents. (pip install pypdf)"
            
            extracted = _extract_pdf_pages(service, file_id, int(start_page), int(end_page))
            if str(extracted).startswith(("Error", "PDF Extraction Failed")):
                return f"Error: Could not read '{actual_name}' (mimeType {mime_type or 'unknown'}): {extracted}"
            return f"--- READING SLICE: {actual_name} (Pages {start_page}-{end_page}) ---\n\n{extracted}"
            
        except Exception as e:
            return f"Error reading slice from '{target}': {e}"
            
    else:
        return f"Error: Unknown action '{action}'. Use 'list_contents', 'read_toc', or 'read_slice'."


def _find_matching_items(target: str, items: list) -> list:
    """Resilient multi-token and substring matching for Drive document names."""
    if not target or not items:
        return items
    t_clean = str(target).lower().replace('.pdf', '').replace('.csv', '').strip()

    # 1. Exact case-insensitive substring
    sub = [it for it in items if t_clean in it.get('name', '').lower()]
    if sub:
        return sub

    # 2. Token overlap: split target into meaningful keywords (e.g. 'networking', 'admin')
    clean_delims = re.sub(r'[-_&/\\:]', ' ', t_clean)
    tokens = [tok for tok in clean_delims.split() if len(tok) >= 3 and tok not in ('the', 'and', 'for', 'pan', 'os')]
    if tokens:
        tok_matched = [it for it in items if all(tok in it.get('name', '').lower() for tok in tokens)]
        if tok_matched:
            return tok_matched
        any_matched = [it for it in items if any(tok in it.get('name', '').lower() for tok in tokens)]
        if any_matched:
            return any_matched

    return []


def _is_csv_item(name: str, mime_type: str = "") -> bool:
    """Returns True if the file name or MIME type indicates a CSV spreadsheet."""
    n = (name or "").lower()
    m = (mime_type or "").lower()
    return n.endswith('.csv') or 'csv' in m or 'comma-separated' in m


def _is_markdown_or_text_item(name: str, mime_type: str = "") -> bool:
    """Returns True if the file name or MIME type indicates text, code, structured config, or Markdown."""
    n = (name or "").lower()
    m = (mime_type or "").lower()
    return n.endswith(_DRIVE_TEXT_EXTS) or m in _DRIVE_TEXT_MIMES


def _extract_text_document(service, file_id: str, max_chars: int = 16000) -> str:
    """Downloads a Markdown, source code, or plain-text document from Drive without invoking pypdf."""
    try:
        request = service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            _, done = downloader.next_chunk()
        text = fh.getvalue().decode('utf-8-sig', errors='replace')
        return _sanitize_external_text(text[:max_chars])
    except Exception as e:
        return f"Error extracting text document: {e}"


def _extract_csv_summary(service, file_id: str, panos_version: str = None, max_rows: int = 15) -> str:
    """Downloads and parses a tabular CSV/CVE database with PAN-OS version filtering."""
    try:
        request = service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()

        raw_bytes = fh.getvalue()
        try:
            text = raw_bytes.decode('utf-8-sig', errors='replace')
        except Exception:
            text = raw_bytes.decode('latin-1', errors='replace')

        reader = csv.reader(io.StringIO(text))
        rows = [r for r in reader if any(cell.strip() for cell in r)]
        if not rows:
            return "CSV file is empty."

        header = rows[0]
        data_rows = rows[1:]

        # Normalize version and branch (e.g. '10.0.12-h3' -> '10.0')
        v_clean = ""
        branch = ""
        if panos_version:
            v_clean = str(panos_version).strip().lower()
            m = re.match(r'^(\d+\.\d+)', v_clean)
            if m:
                branch = m.group(1)

        version_matches = []
        critical_fallback = []

        score_col_indices = {
            idx for idx, h in enumerate(header)
            if any(tok in h.lower() for tok in ("cvss", "score", "severity"))
        }

        for row in data_rows:
            row_str = " ".join(row).lower()
            # Exclude CVSS/score columns when matching PAN-OS branch (prevents CVSS '10.0' matching PAN-OS '10.0')
            version_cells = [
                cell for idx, cell in enumerate(row)
                if idx not in score_col_indices
            ]
            version_haystack = " ".join(version_cells).lower()
            # Also strip inline 'cvss: 10.0' / 'score 10.0' phrases in free-text descriptions
            version_haystack = re.sub(r'\b(?:cvss|score)[:\s/v0-9.]*\b10\.0\b', '', version_haystack)

            matched = False
            if v_clean:
                if re.search(r'(?<![\d.])' + re.escape(v_clean) + r'(?![\d])', version_haystack):
                    matched = True
                elif branch and re.search(r'(?<![\d.])' + re.escape(branch) + r'(?:\.\d+|\b)', version_haystack):
                    matched = True

            if matched:
                version_matches.append(row)
            elif any(sev in row_str for sev in ['critical', 'high', '9.', '10.0', 'cvss: 9', 'cvss: 10']):
                critical_fallback.append(row)

        if version_matches:
            selected = version_matches[:max_rows]
            status_line = f"Identified {len(version_matches)} CVE advisories matching PAN-OS version '{panos_version}' (displaying top {len(selected)}):"
        elif v_clean:
            selected = critical_fallback[:max_rows] if critical_fallback else data_rows[:max_rows]
            status_line = f"No entries explicitly tagged for version '{panos_version}'. Displaying top {len(selected)} high/critical CVE advisories:"
        else:
            selected = data_rows[:max_rows]
            status_line = f"Displaying top {len(selected)} CVE / advisory records:"

        table_lines = [status_line, ""]
        table_lines.append("| " + " | ".join(h.strip() for h in header) + " |")
        table_lines.append("| " + " | ".join("---" for _ in header) + " |")

        for r in selected:
            padded = r + [""] * (len(header) - len(r))
            clean_cells = [c.replace("\n", " ").replace("|", "\\|").strip() for c in padded[:len(header)]]
            table_lines.append("| " + " | ".join(clean_cells) + " |")

        return _sanitize_external_text("\n".join(table_lines))
    except Exception as e:
        logger.exception(f"[DRIVE-CSV] Error parsing CSV file {file_id}: {e}")
        return f"Error extracting CSV data: {e}"


def _extract_pdf_pages(service, file_id: str, start_page: int, end_page: int) -> str:
    """Downloads PDF from Drive and extracts specific pages."""
    try:
        request = service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            
        fh.seek(0)
        
        reader = pypdf.PdfReader(fh)
        total_pages = len(reader.pages)

        # Bounds validation (M2)
        if start_page > end_page:
            return f"Error: start_page ({start_page}) cannot be greater than end_page ({end_page})."
        if start_page < 1:
            return f"Error: start_page ({start_page}) must be >= 1."
        if (end_page - start_page + 1) > 50:
            return f"Error: Requested slice ({end_page - start_page + 1} pages) exceeds 50-page maximum limit per call."
        
        # 1-indexed to 0-indexed translation, handle bounds
        start_idx = max(0, start_page - 1)
        end_idx = min(total_pages, end_page)
        
        if start_idx >= total_pages:
            return f"Error: Start page {start_page} is beyond document length ({total_pages} pages)."
            
        text_blocks = []
        for i in range(start_idx, end_idx):
            page = reader.pages[i]
            text = page.extract_text()
            if text:
                text_blocks.append(f"[--- PAGE {i + 1} ---]\n{_sanitize_external_text(text)}")
                
        return "\n\n".join(text_blocks)
        
    except Exception as e:
        return f"PDF Extraction Failed: {e}"