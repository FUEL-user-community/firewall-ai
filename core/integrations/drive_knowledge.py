import os
import io
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

def _init_drive_service():
    """Initializes the Google Drive API service using Service Account Key or ADC."""
    creds_file = os.getenv("GCP_SERVICE_ACCOUNT_FILE")
    scopes = ['https://www.googleapis.com/auth/drive.readonly']
    
    try:
        # Path 1: User provided a local service account key file
        if creds_file and os.path.exists(creds_file):
            logger.info(f"[DRIVE-RAG] Authenticating using service account key: {creds_file}")
            creds = service_account.Credentials.from_service_account_file(creds_file, scopes=scopes)
        else:
            # Path 2: Fallback to Application Default Credentials (ADC)
            import google.auth
            logger.info("[DRIVE-RAG] Authenticating using Application Default Credentials (ADC)...")
            creds, project = google.auth.default(scopes=scopes)
            
        service = build('drive', 'v3', credentials=creds, cache_discovery=False)
        return service, None
    except Exception as e:
        logger.error(f"[DRIVE-RAG] Failed to initialize Drive service: {e}")
        return None, str(e)

def query_knowledge_base(action: str, target: str = None, start_page: int = None, end_page: int = None, **kwargs) -> str:
    """
    Query the Google Drive Knowledge Base for official PAN-OS documentation.
    
    Args:
        action (str): 'list_contents' (finds matching docs and returns Table of Contents/First pages) 
                      or 'read_slice' (reads specific pages from a target doc).
        target (str): The name of the document to search for or read from.
        start_page (int): Starting page number (inclusive) for 'read_slice'.
        end_page (int): Ending page number (inclusive) for 'read_slice'.
    """
    service, err_msg = _init_drive_service()
    if not service:
        return f"Error: Google Drive API not configured. Details: {err_msg}"
        
    folder_id = os.getenv("KNOWLEDGE_BASE_FOLDER_ID") or os.getenv("OBSIDIAN_DRIVE_FOLDER_ID") or os.getenv("GOOGLE_DRIVE_FOLDER_ID")
    if not folder_id:
        return "Error: Missing KNOWLEDGE_BASE_FOLDER_ID or GOOGLE_DRIVE_FOLDER_ID in environment."

    if action == 'list_contents':
        if not target:
            # List all documents
            query = f"'{folder_id}' in parents and trashed = false"
        else:
            # Search for specific target (escape single quotes to prevent Drive API injection)
            target_safe = target.replace("'", "\\'")
            query = f"'{folder_id}' in parents and name contains '{target_safe}' and trashed = false"
            
        try:
            results = service.files().list(q=query, spaces='drive', fields='files(id, name, mimeType)').execute()
            items = results.get('files', [])
            
            if not items:
                return f"No documents found matching '{target or 'all'}'. Try different keywords."
                
            response_lines = ["--- KNOWLEDGE BASE DOCUMENTS ---"]
            for item in items:
                response_lines.append(f"Document: {item['name']} (ID: {item['id']})")
                
            if target and len(items) == 1:
                # If specifically querying one doc, try to extract its TOC (first 5 pages)
                response_lines.append("\n--- EXTRACTING TABLE OF CONTENTS (Pages 1-5) ---")
                file_id = items[0]['id']
                toc_text = _extract_pdf_pages(service, file_id, 1, 5)
                response_lines.append(toc_text)
                
            response_lines.append("\nINSTRUCTIONS:")
            response_lines.append("To read specific sections, use action='read_slice' with the exact 'target' name and the 'start_page' / 'end_page'.")
            
            return "\n".join(response_lines)
            
        except Exception as e:
            return f"Error listing Knowledge Base contents: {e}"

    elif action == 'read_slice':
        if not target or not start_page or not end_page:
            return "Error: 'read_slice' requires 'target', 'start_page', and 'end_page'."
            
        if not HAS_PYPDF:
            return "Error: 'pypdf' library is missing. Cannot slice PDF documents. (pip install pypdf)"
            
        try:
            target_safe = target.replace("'", "\\'")
            query = f"'{folder_id}' in parents and name contains '{target_safe}' and trashed = false"
            results = service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
            items = results.get('files', [])
            
            if not items:
                return f"Error: Document '{target}' not found."
                
            file_id = items[0]['id']
            actual_name = items[0]['name']
            
            extracted = _extract_pdf_pages(service, file_id, int(start_page), int(end_page))
            return f"--- READING SLICE: {actual_name} (Pages {start_page}-{end_page}) ---\n\n{extracted}"
            
        except Exception as e:
            return f"Error reading slice from '{target}': {e}"
            
    else:
        return f"Error: Unknown action '{action}'. Use 'list_contents' or 'read_slice'."


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
                text_blocks.append(f"[--- PAGE {i + 1} ---]\n{text}")
                
        return "\n\n".join(text_blocks)
        
    except Exception as e:
        return f"PDF Extraction Failed: {e}"