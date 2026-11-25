import re
import hashlib
import email
from email import policy
from email.utils import parseaddr, getaddresses
from typing import List, Tuple, Optional
from bs4 import BeautifulSoup
import tldextract
import dns.resolver

from app.schemas.email_schema import (
    ParsedEmail,
    ExtractedURL,
    AttachmentMetadata,
    EmailAuthResults,
)

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf",
    ".ps1", ".hta", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".zip", ".rar"
}

URL_REGEX = re.compile(r"https?://[^\s<>\"'\]\)]+", re.IGNORECASE)
IP_URL_REGEX = re.compile(r"^https?://\d{1,3}(\.\d{1,3}){3}", re.IGNORECASE)


def _extract_domain(email_addr: str) -> str:
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].lower().strip("> ")
    return ""


def _parse_auth_header(auth_header: str) -> Tuple[str, str, str]:
    """Parses Authentication-Results header for SPF, DKIM, and DMARC verdicts."""
    if not auth_header:
        return "none", "none", "none"
    header_lower = auth_header.lower()

    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|temperror|permerror|none)", header_lower)
    dkim_match = re.search(r"dkim=(pass|fail|neutral|temperror|permerror|none)", header_lower)
    dmarc_match = re.search(r"dmarc=(pass|fail|bestguesspass|none)", header_lower)

    spf = spf_match.group(1) if spf_match else "none"
    dkim = dkim_match.group(1) if dkim_match else "none"
    dmarc = dmarc_match.group(1) if dmarc_match else "none"
    return spf, dkim, dmarc


def _check_dns_records(domain: str) -> Tuple[bool, bool, Optional[str]]:
    """Queries live DNS TXT records to verify if the sender domain publishes SPF & DMARC."""
    if not domain:
        return False, False, None

    has_spf = False
    has_dmarc = False
    dmarc_policy = None

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    # Check SPF
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                has_spf = True
                break
    except Exception:
        pass

    # Check DMARC
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                has_dmarc = True
                pol_match = re.search(r"p=(none|quarantine|reject)", txt, re.IGNORECASE)
                if pol_match:
                    dmarc_policy = pol_match.group(1).lower()
                break
    except Exception:
        pass

    return has_spf, has_dmarc, dmarc_policy


def _extract_urls(body_text: str, body_html: str) -> List[ExtractedURL]:
    """Extracts unique URLs from plain text and HTML anchor tags, flagging mismatches."""
    seen_urls = {}

    if body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href.lower().startswith(("http://", "https://")):
                continue
            anchor = tag.get_text(strip=True)
            seen_urls[href] = anchor

    for match in URL_REGEX.findall(body_text or ""):
        clean_url = match.rstrip(".,;:!?")
        if clean_url not in seen_urls:
            seen_urls[clean_url] = None

    extracted: List[ExtractedURL] = []
    for raw_url, anchor in seen_urls.items():
        ext = tldextract.extract(raw_url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
        is_ip = bool(IP_URL_REGEX.match(raw_url))
        is_short = registered_domain in SHORTENER_DOMAINS

        mismatched = False
        if anchor and ("http://" in anchor.lower() or "https://" in anchor.lower() or "." in anchor):
            anchor_ext = tldextract.extract(anchor)
            anchor_domain = f"{anchor_ext.domain}.{anchor_ext.suffix}".lower() if anchor_ext.suffix else ""
            if anchor_domain and anchor_domain != registered_domain:
                mismatched = True

        extracted.append(
            ExtractedURL(
                raw_url=raw_url,
                domain=registered_domain,
                subdomain=ext.subdomain.lower(),
                suffix=ext.suffix.lower(),
                is_ip_address=is_ip,
                is_shortened=is_short,
                anchor_text=anchor,
                mismatched_anchor=mismatched,
            )
        )

    return extracted


def parse_eml_bytes(raw_bytes: bytes, check_live_dns: bool = True) -> ParsedEmail:
    """Parses raw .eml bytes into a structured ParsedEmail object."""
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    sender_name, sender_addr = parseaddr(msg.get("From", ""))
    sender_addr = sender_addr.lower()
    sender_domain = _extract_domain(sender_addr)

    _, reply_to_addr = parseaddr(msg.get("Reply-To", ""))
    reply_to_addr = reply_to_addr.lower() if reply_to_addr else None
    reply_to_domain = _extract_domain(reply_to_addr) if reply_to_addr else None

    _, return_path_addr = parseaddr(msg.get("Return-Path", ""))
    return_path_addr = return_path_addr.lower() if return_path_addr else None
    return_path_domain = _extract_domain(return_path_addr) if return_path_addr else None

    recipients = [addr.lower() for _, addr in getaddresses(msg.get_all("To", [])) if addr]
    cc_list = [addr.lower() for _, addr in getaddresses(msg.get_all("Cc", [])) if addr]

    body_text_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[AttachmentMetadata] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            content_type = part.get_content_type()

            if "attachment" in content_disposition.lower() or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                filename = part.get_filename() or "unnamed_attachment"
                sha256 = hashlib.sha256(payload).hexdigest()
                ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                attachments.append(
                    AttachmentMetadata(
                        filename=filename,
                        content_type=content_type,
                        size_bytes=len(payload),
                        sha256=sha256,
                        is_executable_or_macro=ext in DANGEROUS_EXTENSIONS,
                    )
                )
            elif content_type == "text/plain":
                try:
                    body_text_parts.append(part.get_content())
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    body_html_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
            if content_type == "text/html":
                body_html_parts.append(content)
            else:
                body_text_parts.append(content)
        except Exception:
            pass

    body_text = "\n".join(body_text_parts).strip()
    body_html = "\n".join(body_html_parts).strip()

    if not body_text and body_html:
        body_text = BeautifulSoup(body_html, "html.parser").get_text(separator=" ", strip=True)

    urls = _extract_urls(body_text, body_html)

    auth_header = msg.get("Authentication-Results", "")
    spf_status, dkim_status, dmarc_status = _parse_auth_header(auth_header)

    has_spf_dns, has_dmarc_dns, dmarc_policy = (False, False, None)
    if check_live_dns and sender_domain:
        has_spf_dns, has_dmarc_dns, dmarc_policy = _check_dns_records(sender_domain)

    auth_summary: List[str] = []
    if spf_status in {"fail", "softfail"}:
        auth_summary.append(f"SPF check reported '{spf_status}'.")
    if dkim_status == "fail":
        auth_summary.append("DKIM signature verification failed.")
    if dmarc_status == "fail":
        auth_summary.append("DMARC policy alignment failed.")
    if check_live_dns and sender_domain and not has_dmarc_dns:
        auth_summary.append(f"Sender domain '{sender_domain}' has no published DMARC DNS record.")

    auth_results = EmailAuthResults(
        spf_status=spf_status,
        dkim_status=dkim_status,
        dmarc_status=dmarc_status,
        has_spf_dns_record=has_spf_dns,
        has_dmarc_dns_record=has_dmarc_dns,
        dmarc_policy=dmarc_policy,
        authentication_summary=auth_summary,
    )

    reply_to_mismatch = bool(reply_to_domain and sender_domain and reply_to_domain != sender_domain)
    return_path_mismatch = bool(return_path_domain and sender_domain and return_path_domain != sender_domain)
    display_name_contains_email = "@" in sender_name and sender_addr not in sender_name.lower()

    headers_dict = {k: str(v) for k, v in msg.items()}

    return ParsedEmail(
        message_id=msg.get("Message-ID"),
        subject=msg.get("Subject", ""),
        sender_display_name=sender_name,
        sender_email=sender_addr,
        sender_domain=sender_domain,
        reply_to_email=reply_to_addr,
        reply_to_domain=reply_to_domain,
        return_path_email=return_path_addr,
        recipients=recipients,
        cc=cc_list,
        date=msg.get("Date"),
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
        auth_results=auth_results,
        reply_to_mismatch=reply_to_mismatch,
        return_path_mismatch=return_path_mismatch,
        display_name_contains_email=display_name_contains_email,
        raw_headers=headers_dict,
    )


def parse_eml_file(file_path: str, check_live_dns: bool = True) -> ParsedEmail:
    with open(file_path, "rb") as f:
        return parse_eml_bytes(f.read(), check_live_dns=check_live_dns)