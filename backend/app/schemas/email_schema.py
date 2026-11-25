from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class ExtractedURL(BaseModel):
    raw_url: str
    domain: str
    subdomain: str
    suffix: str
    is_ip_address: bool = False
    is_shortened: bool = False
    anchor_text: Optional[str] = None
    mismatched_anchor: bool = False


class AttachmentMetadata(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_executable_or_macro: bool = False


class EmailAuthResults(BaseModel):
    spf_status: str = "none"          # pass, fail, softfail, neutral, none
    dkim_status: str = "none"         # pass, fail, none
    dmarc_status: str = "none"        # pass, fail, none
    has_spf_dns_record: bool = False
    has_dmarc_dns_record: bool = False
    dmarc_policy: Optional[str] = None
    authentication_summary: List[str] = Field(default_factory=list)


class ParsedEmail(BaseModel):
    message_id: Optional[str] = None
    subject: str = ""
    sender_display_name: str = ""
    sender_email: str = ""
    sender_domain: str = ""
    reply_to_email: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path_email: Optional[str] = None
    recipients: List[str] = Field(default_factory=list)
    cc: List[str] = Field(default_factory=list)
    date: Optional[str] = None

    # Body & Structural Indicators
    body_text: str = ""
    body_html: str = ""
    urls: List[ExtractedURL] = Field(default_factory=list)
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    auth_results: EmailAuthResults = Field(default_factory=EmailAuthResults)

    # Immediate Heuristic Flags
    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False
    display_name_contains_email: bool = False
    raw_headers: Dict[str, Any] = Field(default_factory=dict)