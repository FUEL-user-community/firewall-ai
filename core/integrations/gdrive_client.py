"""
Unified Thread-Safe Google Drive v3 Transport Client.

Consolidates OAuth / Service Account / ADC initialization previously duplicated
across `drive_knowledge.py` and `google_export.py`, and powers `board_sync.py`.

Counter-Logic Protections:
- Per-client `threading.RLock()` around `googleapiclient` HTTP execution (httplib2 is not thread-safe!).
- Scope-separated cached clients (`readonly` vs `readwrite`).
- Explicit `insufficientParentPermissions` reporting rather than silent root-orphan fallback when `strict_parent=True`.
"""

import io
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SCOPES_READONLY = ("https://www.googleapis.com/auth/drive.readonly",)
SCOPES_READWRITE = (
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive",
)


class GoogleDriveClient:
    """Thread-safe wrapper around Google Drive API v3."""

    _instances: Dict[str, "GoogleDriveClient"] = {}
    _cls_lock = threading.Lock()

    def __init__(self, mode: str = "readonly"):
        self.mode = "readwrite" if mode == "readwrite" else "readonly"
        self.scopes = list(SCOPES_READWRITE if self.mode == "readwrite" else SCOPES_READONLY)
        self._io_lock = threading.RLock()
        self._service = None
        self._last_error: Optional[str] = None

    @classmethod
    def get_instance(cls, mode: str = "readonly") -> "GoogleDriveClient":
        key = "readwrite" if mode == "readwrite" else "readonly"
        if key not in cls._instances:
            with cls._cls_lock:
                if key not in cls._instances:
                    cls._instances[key] = cls(mode=key)
        return cls._instances[key]

    @classmethod
    def reset(cls) -> None:
        with cls._cls_lock:
            cls._instances.clear()

    def get_service(self) -> Tuple[Optional[Any], Optional[str]]:
        """Lazy-load and return `(service, error_msg)`."""
        with self._io_lock:
            if self._service is not None:
                return self._service, None
            creds_file = os.getenv("GCP_SERVICE_ACCOUNT_FILE", "").strip()
            try:
                from googleapiclient.discovery import build
                from google.oauth2 import service_account

                if creds_file and os.path.exists(creds_file):
                    creds = service_account.Credentials.from_service_account_file(
                        creds_file, scopes=self.scopes
                    )
                else:
                    import google.auth
                    creds, _ = google.auth.default(scopes=self.scopes)

                self._service = build("drive", "v3", credentials=creds, cache_discovery=False)
                self._last_error = None
                return self._service, None
            except Exception as e:
                self._last_error = str(e)
                logger.debug(f"[GDRIVE] Drive service ({self.mode}) unavailable: {e}")
                return None, self._last_error

    def list_folder_files(
        self,
        folder_id: str,
        name_contains: Optional[str] = None,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """Thread-safe listing of non-trashed files inside `folder_id`."""
        with self._io_lock:
            service, err = self.get_service()
            if not service:
                raise RuntimeError(f"Google Drive unavailable: {err}")
            safe_folder = folder_id.replace("'", "\\'")
            clauses = [f"'{safe_folder}' in parents", "trashed = false"]
            if name_contains:
                safe_name = name_contains.replace("'", "\\'")
                clauses.append(f"name contains '{safe_name}'")
            q = " and ".join(clauses)
            res = (
                service.files()
                .list(
                    q=q,
                    spaces="drive",
                    pageSize=min(max(1, int(page_size)), 1000),
                    orderBy="createdTime asc",
                    fields="files(id, name, mimeType, createdTime, size)",
                )
                .execute()
            )
            return list(res.get("files", []))

    def download_bytes(self, file_id: str) -> bytes:
        """Thread-safe binary/text media download from Google Drive."""
        with self._io_lock:
            service, err = self.get_service()
            if not service:
                raise RuntimeError(f"Google Drive unavailable: {err}")
            from googleapiclient.http import MediaIoBaseDownload

            request = service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()
            return fh.getvalue()

    def upload_markdown_immutable(
        self,
        filename: str,
        content: str,
        folder_id: str,
        strict_parent: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a brand-new immutable `.md` file in `folder_id` via `files.create`.
        Never calls `files.update` (defeating Drive v3 Last-Write-Wins clobbering).
        """
        if self.mode != "readwrite":
            raise PermissionError("GoogleDriveClient must be initialized in 'readwrite' mode for uploads.")
        with self._io_lock:
            service, err = self.get_service()
            if not service:
                raise RuntimeError(f"Google Drive write service unavailable: {err}")
            from googleapiclient.http import MediaIoBaseUpload

            metadata: Dict[str, Any] = {
                "name": filename,
                "mimeType": "text/markdown",
                "parents": [folder_id],
            }
            media = MediaIoBaseUpload(
                io.BytesIO(content.encode("utf-8")),
                mimetype="text/markdown",
                resumable=False,
            )
            try:
                created = (
                    service.files()
                    .create(body=metadata, media_body=media, fields="id, name, webViewLink, createdTime")
                    .execute()
                )
                return created
            except Exception as create_err:
                if "insufficientParentPermissions" in str(create_err) and not strict_parent:
                    metadata.pop("parents", None)
                    media_retry = MediaIoBaseUpload(
                        io.BytesIO(content.encode("utf-8")),
                        mimetype="text/markdown",
                        resumable=False,
                    )
                    created = (
                        service.files()
                        .create(body=metadata, media_body=media_retry, fields="id, name, webViewLink, createdTime")
                        .execute()
                    )
                    created["orphaned_to_root"] = True
                    return created
                raise
