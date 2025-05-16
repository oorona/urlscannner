import asyncio
import json
import ssl
import socket
from urllib.parse import urlparse, unquote,ParseResult
import ipaddress
import datetime
import logging
from typing import Dict, Any, Optional, List, Tuple
import os
import re
import time
from urllib.parse import urlparse
import httpx
import aiohttp
import dns.asyncresolver
import whois # Note: python-whois library is synchronous
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError
import tldextract # For reliable domain/subdomain extraction
from OpenSSL import SSL # For more detailed cert info if needed (complementary to std ssl)
import OpenSSL
from dotenv import load_dotenv
import argparse

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
logger = logging.getLogger(__name__) # Use __name__ for logger

# --- Constants ---
COMMON_LEGIT_DOMAINS = { # Add more top-level domains often impersonated
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "office.com", "live.com", "outlook.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "paypal.com", "ebay.com",
    "twitter.com", "linkedin.com", "netflix.com", "spotify.com",
    "discord.com", "discord.gg", "slack.com",
    "binance.com", "coinbase.com",
    # Add major banks, government sites, etc., relevant to your users
}
RISKY_TLDS = {".zip", ".mov", ".xyz", ".tk", ".info", ".pw", ".top", ".club", ".online", ".live"} # Not definitive, but higher risk association

class AsyncURLAnalyzer:
    """
    Asynchronously analyzes URLs to gather information for scam detection.
    """

    def __init__(self, user_agent: str = None):
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
        # Shared session for HTTP requests
        self._session: Optional[aiohttp.ClientSession] = None
        # Shared resolver
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.nameservers = ['8.8.8.8', '1.1.1.1'] # Use reliable public DNS
         # --- LLM Configuration ---
        self.llm_token = os.getenv("OPENWEBUI_TOKEN")
        # Ensure the URL points to the correct API endpoint path
        llm_base = os.getenv("OPENWEBUI_URL").rstrip('/')
        # Append common API paths if not present (adjust based on your service)
        if not llm_base.endswith(("/v1", "/api/chat/completions")):
            # Heuristic: if looks like base OpenWebUI/Ollama URL, append path
            if "localhost:3000" in llm_base or "127.0.0.1:3000" in llm_base:
                 self.llm_api_url = f"{llm_base}/api/chat/completions"
            elif "localhost:8080" in llm_base or "127.0.0.1:8080" in llm_base or "localhost:11434" in llm_base:
                 self.llm_api_url = f"{llm_base}/v1/chat/completions" # Common for Ollama/LMStudio compatible
            else:
                 self.llm_api_url = f"{llm_base}/api/chat/completions" # Generic guess
            logger.warning(f"LLM URL did not end with standard API path. Using inferred URL: {self.llm_api_url}")
        else:
             self.llm_api_url = llm_base # Assume provided URL includes the full path

        self.llm_model = os.getenv("OPENWEBUI_LLM_MODEL", "mistral:latest") # Default model

        # --- Load LLM Prompts ---
        self.llm_system_prompt = os.getenv("LLM_SYSTEM_PROMPT").replace("\\n", "\n") 
        self.llm_user_prompt_template = os.getenv("LLM_USER_PROMPT_TEMPLATE").replace("\\n", "\n")
        print(self.llm_system_prompt)
        print(self.llm_user_prompt_template)


        if not self.llm_token:
            logger.warning("OPENWEBUI_TOKEN not found in environment. LLM classification will be disabled.")
        if not self.llm_api_url:
            logger.warning("OPENWEBUI_URL not found or invalid in environment. LLM classification will be disabled.")
        else:
             logger.info(f"LLM Classification configured: URL='{self.llm_api_url}', Model='{self.llm_model}'")

    async def _get_session(self) -> aiohttp.ClientSession:
        """Creates or returns the shared aiohttp session."""
        if self._session is None or self._session.closed:
            headers = {'User-Agent': self.user_agent}
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def close_session(self):
        """Closes the shared aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
            logging.info("aiohttp session closed.")

    def _parse_url(self, url: str) -> Tuple[Optional[ParseResult], Optional[str]]:
        """Safely parses a URL string."""
        try:
            # Prepend https:// if scheme is missing, common in user input
            if '://' not in url:
                url = 'https://' + url
            parsed: Optional[ParseResult] = urlparse(url) # Call the urlparse function
            if not parsed or not parsed.netloc: # Basic check if parsing yielded a network location
                return None, f"Could not parse network location (domain/IP) from URL: {url}"
            return parsed, None
        except Exception as e:
            logging.warning(f"URL parsing failed for '{url}': {e}") # Added logging
            return None, f"URL parsing failed: {e}"

    def _extract_domain_parts(self, netloc: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
         """Extracts subdomain, domain, TLD, and registered domain using tldextract."""
         try:
             ext = tldextract.extract(netloc)
             # registered_domain is subdomain + domain + suffix if subdomain exists, else domain + suffix
             registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain else None
             return ext.subdomain, ext.domain, ext.suffix, registered_domain
         except Exception as e:
             logging.warning(f"tldextract failed for '{netloc}': {e}")
             # Fallback logic if tldextract fails (less accurate)
             parts = netloc.split('.')
             if len(parts) >= 2:
                 return ".".join(parts[:-2]) if len(parts) > 2 else "", parts[-2], parts[-1], f"{parts[-2]}.{parts[-1]}"
             else:
                 return "", "", "", netloc # Likely just a hostname or invalid

    # 1. Check URL Malformed
    async def check_url_malformed(self, url: str) -> Dict[str, Any]:
        """
        Checks for suspicious patterns in the URL structure itself (async wrapper).
        Focuses on domain/host characteristics based on Point 2 of the initial analysis.
        """
        result: Dict[str, Any] = {
            "is_ip_address": False,
            "uses_punycode": False,
            "suspicious_tld": None,
            "deceptive_subdomain": None,
            "potential_typosquatting": None, # Domain that might be a typo of a known one
            "domain_parts": {},
            "analysis_flags": [] # List of strings describing found issues
        }

        parsed_url, error = self._parse_url(url)
        if error:
            result["error"] = error
            result["analysis_flags"].append("URL_PARSING_FAILED")
            return result

        netloc = parsed_url.netloc
        if not netloc:
             result["error"] = "Parsed URL has no network location (domain/IP)."
             result["analysis_flags"].append("MISSING_NETLOC")
             return result

        # Check for IP Address Host
        try:
            ipaddress.ip_address(netloc)
            result["is_ip_address"] = True
            result["analysis_flags"].append("HOST_IS_IP_ADDRESS")
        except ValueError:
            # Not an IP address, proceed with domain analysis
            pass

        # Extract domain parts using tldextract
        subdomain, domain, tld, registered_domain = self._extract_domain_parts(netloc)
        result["domain_parts"] = {
            "full_host": netloc,
            "subdomain": subdomain,
            "domain": domain,
            "tld": tld,
            "registered_domain": registered_domain,
        }

        if not registered_domain:
            result["error"] = "Could not determine registered domain."
            result["analysis_flags"].append("UNKNOWN_REGISTERED_DOMAIN")
            # Don't perform further domain-based checks if we don't have a registered domain
            return result


        # Check for Punycode (IDN Homograph Attack vector)
        if netloc.startswith("xn--") or ".xn--" in netloc:
            result["uses_punycode"] = True
            result["analysis_flags"].append("USES_PUNYCODE")
            try:
                 decoded_netloc = netloc.encode('ascii').decode('idna')
                 result["domain_parts"]["decoded_host"] = decoded_netloc
            except Exception as e:
                 logging.warning(f"Could not decode punycode host {netloc}: {e}")
                 result["domain_parts"]["decoded_host"] = "[DECODING_FAILED]"


        # Check for Risky TLDs
        if tld and f".{tld}" in RISKY_TLDS:
            result["suspicious_tld"] = tld
            result["analysis_flags"].append("SUSPICIOUS_TLD")

        # Check for Deceptive Subdomains (e.g., paypal.com.security.scamdomain.com)
        if subdomain:
            # Check if a common legit domain is *part* of the subdomain string
            normalized_subdomain = subdomain.lower()
            for legit_domain in COMMON_LEGIT_DOMAINS:
                # Check if legit domain appears as a whole word or part in the subdomain
                # e.g., "paypal.com" in "paypal.com.secure" or "service-paypal.com"
                if legit_domain in normalized_subdomain.split('.'):
                     result["deceptive_subdomain"] = subdomain # Flag the whole subdomain
                     result["analysis_flags"].append("DECEPTIVE_SUBDOMAIN_PATTERN")
                     break
                 # More complex check: is the legit domain used like 'login-microsoft' etc.
                if (f"-{legit_domain.split('.')[0]}" in normalized_subdomain or
                    f"{legit_domain.split('.')[0]}-" in normalized_subdomain):
                     result["deceptive_subdomain"] = subdomain
                     result["analysis_flags"].append("DECEPTIVE_SUBDOMAIN_PATTERN")
                     break


        # Basic Typosquatting Check (simple similarity, needs improvement for production)
        # This is a very basic check. Real typosquatting detection is complex.
        if registered_domain:
            normalized_reg_domain = registered_domain.lower()
            for legit_domain in COMMON_LEGIT_DOMAINS:
                if normalized_reg_domain != legit_domain:
                    # Example check: replacing 'o' with '0', 'l' with '1', adding/removing hyphen
                    potential_typos = [
                        legit_domain.replace('o', '0'), legit_domain.replace('l', '1'),
                        legit_domain.replace('.', '-'), legit_domain.replace('-', ''),
                        legit_domain + "-", "-" + legit_domain.split('.')[0] + "." + legit_domain.split('.')[-1]
                    ]
                    # Check common TLD variations if base domain matches
                    legit_base = legit_domain.split('.')[0]
                    if domain == legit_base and f".{tld}" != legit_domain.split('.')[-1]:
                        potential_typos.append(f"{legit_base}.{tld}") # e.g., google.xyz vs google.com

                    if normalized_reg_domain in potential_typos:
                        result["potential_typosquatting"] = legit_domain
                        result["analysis_flags"].append("POTENTIAL_TYPOSQUATTING")
                        break
                    # Could add Levenshtein distance check here for more advanced matching
                    # from Levenshtein import distance
                    # if distance(normalized_reg_domain, legit_domain) <= 2: # Threshold of 1 or 2
                    #    result["potential_typosquatting"] = legit_domain
                    #    result["analysis_flags"].append("POTENTIAL_TYPOSQUATTING_SIMILARITY")
                    #    break


        return result

    # 2. Check URL Reachability
    async def check_url_reachability(self, url: str, timeout: int = 10) -> Dict[str, Any]:
        """Checks if the URL is reachable and returns the final status code after redirects."""
        result: Dict[str, Any] = {"url": url, "reachable": False, "status_code": None, "final_url": url, "error": None}
        session = await self._get_session()
        try:
            async with session.get(url, allow_redirects=True, timeout=timeout) as response:
                result["reachable"] = True
                result["status_code"] = response.status
                result["final_url"] = str(response.url) # Capture URL after redirects
                # Optionally read a small part of the body to ensure connection isn't abruptly closed
                # await response.read(1024)
        except aiohttp.ClientConnectorCertificateError as e:
            result["error"] = f"SSL Certificate Error: {e}"
        except aiohttp.ClientConnectorError as e:
             result["error"] = f"Connection Error: {e}" # DNS resolution failed, connection refused etc.
        except asyncio.TimeoutError:
            result["error"] = f"Request timed out after {timeout} seconds."
        except aiohttp.ClientError as e: # Catch other general aiohttp errors
            result["error"] = f"HTTP Client Error: {e}"
        except Exception as e:
            result["error"] = f"An unexpected error occurred during reachability check: {e}"

        if result["error"]:
             result["reachable"] = False # Ensure reachable is False if any error occurred

        return result

    # 3. Check DNS Records
    async def check_dns_records(self, domain: str) -> Dict[str, Any]:
        """Retrieves common DNS records for the domain."""
        result: Dict[str, Any] = {"domain": domain, "records": {}, "error": None}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        async def query(record_type):
            try:
                answers = await self._resolver.resolve(domain, record_type)
                # Extract relevant data from answer objects
                if record_type in ["A", "AAAA"]:
                    return [a.to_text() for a in answers]
                elif record_type == "MX":
                    return sorted([f"{a.preference} {a.exchange.to_text()}" for a in answers])
                elif record_type in ["NS", "CNAME"]:
                     return [a.target.to_text() for a in answers]
                elif record_type == "TXT":
                     # TXT records can be multi-part, join them
                     return [" ".join(t.decode('utf-8') for t in a.strings) for a in answers]
            except dns.resolver.NoAnswer:
                logging.info(f"No {record_type} record found for {domain}")
                return []
            except dns.resolver.NXDOMAIN:
                 # This error should ideally be caught once, but check per type just in case
                 raise dns.resolver.NXDOMAIN(f"Domain not found: {domain}")
            except dns.exception.Timeout:
                logging.warning(f"DNS query timeout for {record_type} @ {domain}")
                return ["[TIMEOUT]"]
            except Exception as e:
                logging.warning(f"Error querying {record_type} for {domain}: {e}")
                return [f"[ERROR: {e}]"]
            return [] # Should not be reached normally

        try:
            query_tasks = [query(rtype) for rtype in record_types]
            record_results = await asyncio.gather(*query_tasks)

            for rtype, data in zip(record_types, record_results):
                 if data: # Only add if there are records or an error message for that type
                     result["records"][rtype] = data

        except dns.resolver.NXDOMAIN as e:
             result["error"] = f"NXDOMAIN: The domain does not exist. ({e})"
        except Exception as e:
            result["error"] = f"An unexpected DNS error occurred: {e}"

        return result

    # 4. Check SSL Certificate
    async def check_ssl_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Retrieves and parses the SSL certificate for the hostname."""
        result: Dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "connected_successfully": False,
            "certificate_found": False,
            "details": {},
            "error": None
        }
        # Using the standard ssl module context is fine for connection
        context = ssl.create_default_context()
        context.check_hostname = False # We'll verify hostname manually against SANs/CN
        context.verify_mode = ssl.CERT_NONE # Don't verify chain here, just fetch the cert

        conn = None
        sock = None # Define sock outside try block for finally clause
        try:
            # Establish non-blocking socket connection first
            loop = asyncio.get_running_loop()
            # Use loop.sock_connect for async connection setup if preferred,
            # but create_connection works fine in executor for simplicity here.
            # Or keep sync socket connection as it's often fast enough:
            sock = socket.create_connection((hostname, port), timeout=5)

            # Wrap socket using standard ssl module first to get cert
            conn = context.wrap_socket(sock, server_hostname=hostname)
            result["connected_successfully"] = True

            der_cert = conn.getpeercert(binary_form=True)
            if not der_cert:
                result["error"] = "Could not retrieve certificate (getpeercert returned None)."
                # Ensure socket/conn are closed even on early return
                if conn: conn.close()
                if sock: sock.close()
                return result

            # --- Use pyOpenSSL to parse the DER certificate ---
            # V-- The Fix --V
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
            # ^-- The Fix --^
            result["certificate_found"] = True

            # Extract basic info
            subject_parts = x509.get_subject().get_components()
            issuer_parts = x509.get_issuer().get_components()
            # Decode bytes to strings, handle potential errors
            result["details"]["subject"] = dict((k.decode('utf-8', 'ignore'), v.decode('utf-8', 'ignore')) for k, v in subject_parts)
            result["details"]["issuer"] = dict((k.decode('utf-8', 'ignore'), v.decode('utf-8', 'ignore')) for k, v in issuer_parts)


            # Common Name (CN) from Subject
            result["details"]["common_name"] = result["details"]["subject"].get("CN")

            # Dates (pyOpenSSL returns bytes, need decoding)
            not_before_str = x509.get_notBefore()
            not_after_str = x509.get_notAfter()
            if not_before_str:
                 # Decode from bytes before parsing
                 result["details"]["valid_from"] = datetime.datetime.strptime(not_before_str.decode('ascii'), '%Y%m%d%H%M%SZ').isoformat() + "Z"
            if not_after_str:
                 # Decode from bytes before parsing
                 result["details"]["valid_until"] = datetime.datetime.strptime(not_after_str.decode('ascii'), '%Y%m%d%H%M%SZ').isoformat() + "Z"

            # Validity Period & Status
            # (Assuming valid_from and valid_until were successfully parsed above)
            if "valid_from" in result["details"] and "valid_until" in result["details"]:
                 now_utc = datetime.datetime.now(datetime.timezone.utc)
                 # Parse ISO strings back to datetime objects for comparison
                 not_before = datetime.datetime.fromisoformat(result["details"]["valid_from"].replace("Z", "+00:00"))
                 not_after = datetime.datetime.fromisoformat(result["details"]["valid_until"].replace("Z", "+00:00"))

                 result["details"]["validity_days"] = (not_after - not_before).days

                 if now_utc < not_before:
                     result["details"]["validity_status"] = "Not yet valid"
                 elif now_utc > not_after:
                     result["details"]["validity_status"] = "Expired"
                 else:
                     days_left = (not_after - now_utc).days
                     result["details"]["validity_status"] = f"Valid ({days_left} days remaining)"
                     if days_left < 30:
                         result["details"]["validity_status"] += " [EXPIRES_SOON]"
            else:
                 result["details"]["validity_status"] = "Could not determine validity dates."


            # Subject Alternative Names (SANs)
            sans = []
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                short_name = ext.get_short_name()
                # Decode short_name from bytes if necessary (depends on pyOpenSSL version)
                try:
                    short_name_str = short_name.decode('utf-8')
                except AttributeError: # Already a string
                    short_name_str = short_name

                if short_name_str == 'subjectAltName':
                    # pyOpenSSL returns SANs as a comma-separated string representation
                    sans_str = str(ext) # Use str() to get the representation
                    # Parse the string representation - be careful, format can vary slightly
                    # This basic split works for common cases like "DNS:example.com, DNS:www.example.com"
                    sans = [s.strip().replace("DNS:", "") for s in sans_str.split(',') if s.strip().startswith("DNS:")]
                    break
            result["details"]["subject_alt_names"] = sans

            # Check if hostname matches CN or SANs (case-insensitive)
            hostname_lower = hostname.lower()
            hostname_match = False
            cn = result["details"].get("common_name")
            if cn and cn.lower() == hostname_lower:
                hostname_match = True
            else: # Only check SANs if CN doesn't match
                for san in sans:
                    san_lower = san.lower()
                    # Handle wildcard SANs (*.example.com)
                    if san_lower.startswith("*."):
                        # Check if hostname ends with the part after '*' and has one more dot level
                        wildcard_part = san_lower[1:]
                        if hostname_lower.endswith(wildcard_part) and hostname_lower.count('.') == san_lower.count('.'):
                             hostname_match = True
                             break
                    elif san_lower == hostname_lower:
                        hostname_match = True
                        break
            result["details"]["hostname_match"] = hostname_match


        except OpenSSL.crypto.Error as e: # Catch crypto-specific errors
             result["error"] = f"pyOpenSSL Crypto Error: {e}"
        # Keep other exception handlers as they are
        except ssl.SSLCertVerificationError as e:
             result["error"] = f"SSL Certificate Verification Error: {e}"
        # ... rest of the existing except blocks ...
        except socket.gaierror:
            result["error"] = f"Could not resolve hostname: {hostname}"
        except socket.timeout:
            result["error"] = "Connection timed out."
        except ConnectionRefusedError:
            result["error"] = "Connection refused."
        except OSError as e: # Catch broader network errors
            result["error"] = f"Network OS Error: {e}"
        except Exception as e:
            # Log the full traceback for unexpected errors
            logging.exception(f"An unexpected error occurred during SSL check for {hostname}")
            result["error"] = f"An unexpected error occurred during SSL check: {type(e).__name__}"
        finally:
            # Ensure connection and socket are closed
            if conn:
                try: conn.close()
                except Exception: pass
            if sock:
                try: sock.close()
                except Exception: pass
        return result
    
    # 5. Check WHOIS Information
    async def check_whois_information(self, domain: str) -> Dict[str, Any]:
        """Retrieves WHOIS information for the domain (runs sync 'whois' in executor)."""
        result: Dict[str, Any] = {"domain": domain, "raw": None, "parsed": None, "error": None, "analysis_flags": []} # Initialize flags

        def sync_whois(d):
            # ... (sync_whois function remains the same) ...
            try:
                return whois.whois(d)
            except Exception as e:
                logging.warning(f"whois lookup for {d} failed: {e}")
                return f"Error during WHOIS lookup: {e}"


        loop = asyncio.get_running_loop()
        try:
            whois_data = await loop.run_in_executor(None, sync_whois, domain)
            #print(whois_data)
            if isinstance(whois_data, str) and "Error" in whois_data:
                result["error"] = whois_data
            elif whois_data and (whois_data.get('domain_name') or whois_data.get('emails')):
                #result["raw"] = whois_data.text if hasattr(whois_data, 'text') else None # Check if 'text' attr exists

                parsed_data = {}
                for k, v in whois_data.items():
                    # Handle lists of datetimes
                    if isinstance(v, list) and v and isinstance(v[0], datetime.datetime):
                        parsed_data[k] = sorted([item.isoformat() for item in v]) # Sort dates for consistency
                    # Handle single datetime
                    elif isinstance(v, datetime.datetime):
                        parsed_data[k] = v.isoformat()
                    # Exclude raw text attribute if present
                    elif k != 'text':
                        parsed_data[k] = v
                result["parsed"] = parsed_data

                # --- Add flags based on parsed data ---
                flags = [] # Use local list then assign to result

                status_value = parsed_data.get("status")
                if status_value:
                    is_redemption = False
                    if isinstance(status_value, list):
                        # Check if 'redemption' (case-insensitive) is in any string within the list
                        is_redemption = any("redemption" in s.lower() for s in status_value if isinstance(s, str))
                    elif isinstance(status_value, str):
                        # Check if 'redemption' is in the single status string
                        is_redemption = "redemption" in status_value.lower()

                    if is_redemption:
                        flags.append("DOMAIN_IN_REDEMPTION")


                if parsed_data.get("registrar") is None and parsed_data.get("creation_date") is None:
                   flags.append("WHOIS_DATA_LIMITED_OR_PROTECTED")


                creation_date_val = parsed_data.get("creation_date")
                if creation_date_val:
                    # creation_date can also be a list or single value
                    first_creation_date_str = None
                    if isinstance(creation_date_val, list):
                        if creation_date_val: # Ensure list is not empty
                             first_creation_date_str = creation_date_val[0]
                    elif isinstance(creation_date_val, str): # It's already isoformat string
                         first_creation_date_str = creation_date_val

                    if first_creation_date_str:
                        try:
                            # Parse ISO string back to datetime, make it timezone-aware (UTC)
                            create_dt = datetime.datetime.fromisoformat(first_creation_date_str.replace("Z", "+00:00"))
                            # Ensure create_dt is offset-aware before comparing with offset-aware now()
                            if create_dt.tzinfo is None:
                                 # If somehow it's naive, assume UTC? Or handle error. Assuming UTC here.
                                 create_dt = create_dt.replace(tzinfo=datetime.timezone.utc)

                            now_utc = datetime.datetime.now(datetime.timezone.utc)
                            if (now_utc - create_dt).days < 90:
                                flags.append("DOMAIN_RECENTLY_REGISTERED (<90 days)")
                        except (ValueError, TypeError) as date_err:
                            logging.warning(f"Could not parse creation date '{first_creation_date_str}': {date_err}")
                        except Exception as date_err: # Catch any other parsing issues
                            logging.warning(f"Unexpected error parsing creation date '{first_creation_date_str}': {date_err}")


                result["analysis_flags"] = flags

            else:
                result["error"] = "WHOIS data not found or appears incomplete."
                if isinstance(whois_data, str):
                    result["raw"] = whois_data

        except Exception as e:
            # Log the full traceback for unexpected errors
            logging.exception(f"Failed to execute WHOIS query for {domain}")
            result["error"] = f"Failed to execute WHOIS query: {type(e).__name__}"


        return result

    # 6. Extract Page Elements
    async def extract_page_elements(self, url: str, timeout: int = 20) -> Dict[str, Any]:
        """Uses Playwright (headless browser) to extract elements from the page."""
        result: Dict[str, Any] = {
            "url": url,
            "final_url": url, # Will be updated after navigation
            "title": None,
            "meta": {}, # Key-value pairs (name/property: content)
            "links": [], # List of hrefs
            "scripts": [], # List of srcs
            "forms": [], # List of form details (action, method, id, name)
            "text_preview": None, # First N characters of body text
            "error": None
        }
        pw_instance = None
        browser = None
        context = None
        page = None

        try:
            pw_instance = await async_playwright().start()
            # Use Chromium, but could use Firefox or WebKit
            browser = await pw_instance.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=self.user_agent,
                # Block common trackers/ads which can interfere or slow down
                # You might need to install 'ublock-origin' or use other blocklists
                # Example: java_script_enabled=False - but this breaks many sites
                ignore_https_errors=True, # Important for fetching content even if cert is bad
            )
            page = await context.new_page()

            # Navigate to the page
            try:
                response = await page.goto(url, wait_until='domcontentloaded', timeout=timeout * 1000)
                result["final_url"] = page.url # Get URL after potential redirects
                if response:
                     result["load_status"] = response.status
                else:
                     result["load_status"] = None # Should not happen often with goto
            except PlaywrightTimeoutError:
                 result["error"] = f"Page load timed out after {timeout} seconds."
                 # Try to grab whatever might have loaded anyway
            except PlaywrightError as e:
                 result["error"] = f"Playwright navigation error: {e}"
                 # Cannot proceed if navigation failed critically
                 await context.close()
                 await browser.close()
                 await pw_instance.stop()
                 return result


            # Extract elements even if there was a timeout (some might be available)
            try:
                result["title"] = await page.title()

                # Meta tags
                meta_elements = await page.locator('meta').all()
                for meta in meta_elements:
                    name = await meta.get_attribute('name')
                    prop = await meta.get_attribute('property')
                    content = await meta.get_attribute('content')
                    charset = await meta.get_attribute('charset')
                    key = name or prop # Prefer name, fallback to property
                    if key and content:
                         result["meta"][key.lower()] = content
                    elif charset:
                         result["meta"]["charset"] = charset # Store charset separately

                # Links (get absolute URLs)
                base_url = page.url
                link_elements = await page.locator('a[href]').all()
                links = set() # Use set to avoid duplicates
                for link in link_elements:
                     href = await link.get_attribute('href')
                     if href and not href.strip().startswith(('javascript:', 'mailto:', '#')):
                        try:
                            # Resolve relative URLs
                            parsed_link = urlparse(href)
                            if not parsed_link.scheme:
                                href = urljoin(base_url, href) # Requires: from urllib.parse import urljoin
                            links.add(href)
                        except Exception:
                             links.add(href) # Add as is if parsing/joining fails
                result["links"] = list(links)


                # Scripts
                script_elements = await page.locator('script[src]').all()
                scripts = set()
                for script in script_elements:
                    src = await script.get_attribute('src')
                    if src:
                         try:
                            parsed_src = urlparse(src)
                            if not parsed_src.scheme:
                                src = urljoin(base_url, src)
                            scripts.add(src)
                         except Exception:
                              scripts.add(src)
                result["scripts"] = list(scripts)


                # Forms
                form_elements = await page.locator('form').all()
                forms_data = []
                for form in form_elements:
                    action = await form.get_attribute('action') or ""
                    try:
                        parsed_action = urlparse(action)
                        if not parsed_action.scheme and not action.startswith("#"):
                            action = urljoin(base_url, action)
                    except Exception:
                        pass # Keep original action if parsing fails
                    forms_data.append({
                        "action": action,
                        "method": await form.get_attribute('method') or 'GET',
                        "id": await form.get_attribute('id') or "",
                        "name": await form.get_attribute('name') or ""
                     })
                result["forms"] = forms_data

                # Body text preview (first 500 chars, strip excessive whitespace)
                body_text = await page.locator('body').inner_text(timeout=5000) # Short timeout for text extraction
                result["text_preview"] = ' '.join(body_text.split()).strip()[:500] + ('...' if len(body_text) > 500 else '')


            except PlaywrightError as e:
                 # If element extraction fails after successful navigation
                 result["error"] = result.get("error", "") + f" | Playwright element extraction error: {e}"
            except Exception as e:
                 result["error"] = result.get("error", "") + f" | Unexpected error during element extraction: {e}"

            # Close browser resources
            await context.close()
            await browser.close()
            await pw_instance.stop()

        except Exception as e:
             # Catch errors during Playwright setup/teardown
             result["error"] = f"Playwright setup/teardown error: {e}"
             # Ensure resources are cleaned up if partially initialized
             if context and not context.is_closed(): await context.close()
             if browser and browser.is_connected(): await browser.close()
             if pw_instance: await pw_instance.stop()


        return result


    # 7. Analyze URL - Orchestrator
    async def analyze_url(self, url: str) -> str:
        """
        Calls all check functions concurrently and returns a JSON string
        suitable for LLM analysis.
        """
        start_time = datetime.datetime.now(datetime.timezone.utc)
        logging.info(f"Starting analysis for URL: {url}")

        final_report: Dict[str, Any] = {
            "analysis_metadata": {
                "original_url": url,
                "analysis_start_time_utc": start_time.isoformat(),
                "analysis_end_time_utc": None,
                "total_duration_seconds": None,
            },
            "url_structure": None,
            "reachability": None,
            "dns_records": None,
            "ssl_certificate": None,
            "whois_info": None,
            "page_content": None,
            "overall_summary": { # Basic summary based on collected data
                "potential_risks": [],
                "errors_encountered": []
            }
        }

        # --- Stage 1: Basic Parsing and Checks (Fast) ---
        parsed_url, parse_error = self._parse_url(url)
        if parse_error:
            final_report["overall_summary"]["errors_encountered"].append(f"Initial URL Parsing: {parse_error}")
            final_report["analysis_metadata"]["analysis_end_time_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            final_report["analysis_metadata"]["total_duration_seconds"] = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
            return json.dumps(final_report, indent=2) # Return early if URL is fundamentally unparsable

        hostname = parsed_url.netloc
        scheme = parsed_url.scheme
        port = parsed_url.port or (443 if scheme == 'https' else 80)
        is_https = (scheme == 'https')

        _, _, _, registered_domain = self._extract_domain_parts(hostname)
        if not registered_domain and not ipaddress.ip_address(hostname): # Only proceed if we have domain or it's an IP
              final_report["overall_summary"]["errors_encountered"].append("Could not determine registered domain or validate IP.")
              # Continue analysis but flag this issue

        # --- Stage 2: Concurrent Network/Data Retrieval ---
        tasks = {}
        tasks["structure"] = asyncio.create_task(self.check_url_malformed(url))
        tasks["reachability"] = asyncio.create_task(self.check_url_reachability(url))

        # Only run domain-specific checks if it's not an IP address
        if registered_domain:
             tasks["dns"] = asyncio.create_task(self.check_dns_records(registered_domain)) # Use registered domain for DNS/WHOIS
             tasks["whois"] = asyncio.create_task(self.check_whois_information(registered_domain))
        else:
            logging.info(f"Skipping DNS and WHOIS for IP address: {hostname}")
            final_report["dns_records"] = {"domain": hostname, "records": {}, "error": "Skipped for IP address"}
            final_report["whois_info"] = {"domain": hostname, "raw": None, "parsed": None, "error": "Skipped for IP address"}


        # Only run SSL check if it's HTTPS (or potentially standard HTTP on non-standard port, less common)
        if is_https or port != 80:
             tasks["ssl"] = asyncio.create_task(self.check_ssl_certificate(hostname, port))
        else:
             logging.info(f"Skipping SSL check for non-HTTPS URL: {url}")
             final_report["ssl_certificate"] = {"hostname": hostname, "port": port, "error": "Skipped for non-HTTPS scheme"}

        # Playwright check is potentially long-running, run concurrently
        tasks["content"] = asyncio.create_task(self.extract_page_elements(url))

        # Wait for all tasks to complete
        await asyncio.gather(*tasks.values(), return_exceptions=True) # Capture exceptions instead of raising

        # --- Stage 3: Populate Report and Summarize ---
        results = {name: task.result() if not task.exception() else {"error": f"Task raised an exception: {task.exception()}"}
                   for name, task in tasks.items()}

        final_report["url_structure"] = results.get("structure")
        final_report["reachability"] = results.get("reachability")
        if "dns" in results: final_report["dns_records"] = results["dns"]
        if "ssl" in results: final_report["ssl_certificate"] = results["ssl"]
        if "whois" in results: final_report["whois_info"] = results["whois"]
        final_report["page_content"] = results.get("content")

        # Populate summary based on results
        summary_risks = final_report["overall_summary"]["potential_risks"]
        summary_errors = final_report["overall_summary"]["errors_encountered"]

        # Function to safely check for errors or flags in results
        def check_result(data: Optional[Dict], section_name: str):
            if data is None:
                summary_errors.append(f"{section_name}: Analysis data is missing.")
                return
            if data.get("error"):
                 summary_errors.append(f"{section_name}: {data['error']}")
            if data.get("analysis_flags"): # Check for flags added by individual functions
                 summary_risks.extend([f"{section_name}: {flag}" for flag in data["analysis_flags"]])

        check_result(final_report["url_structure"], "URL Structure")
        check_result(final_report["reachability"], "Reachability")
        check_result(final_report["dns_records"], "DNS")
        check_result(final_report["ssl_certificate"], "SSL Certificate")
        check_result(final_report["whois_info"], "WHOIS")
        check_result(final_report["page_content"], "Page Content")

        # Add specific risk checks to summary
        if final_report.get("url_structure", {}).get("is_ip_address"): summary_risks.append("URL uses IP Address instead of domain.")
        if final_report.get("reachability", {}).get("status_code") and final_report["reachability"]["status_code"] >= 400: summary_risks.append(f"Reachability: HTTP Error Status {final_report['reachability']['status_code']}")
        if final_report.get("ssl_certificate", {}).get("details", {}).get("validity_status") == "Expired": summary_risks.append("SSL: Certificate Expired.")
        if final_report.get("ssl_certificate", {}).get("details", {}).get("hostname_match") is False: summary_risks.append("SSL: Hostname mismatch.")
        if final_report.get("page_content", {}).get("forms") and any("password" in form.get("id","").lower() or "password" in form.get("name","").lower() for form in final_report["page_content"]["forms"]):
             # Check if a password field exists on a page served over HTTP or with SSL issues
             ssl_ok = is_https and final_report.get("ssl_certificate", {}).get("certificate_found") and not final_report.get("ssl_certificate",{}).get("error")
             if not ssl_ok:
                  summary_risks.append("Content: Password form found on insecure page (HTTP or SSL issues).")


        # --- Stage 4: Finalize and Return ---
        end_time = datetime.datetime.now(datetime.timezone.utc)
        final_report["analysis_metadata"]["analysis_end_time_utc"] = end_time.isoformat()
        final_report["analysis_metadata"]["total_duration_seconds"] = (end_time - start_time).total_seconds()

        logging.info(f"Analysis complete for {url} in {final_report['analysis_metadata']['total_duration_seconds']:.2f} seconds.")

        # Clean up the session AFTER all tasks that might use it are done
        await self.close_session()

        # Use default=str to handle potential non-serializable types gracefully
        return json.dumps(final_report, indent=2, default=str)


# --- Example Usage ---

    async def get_llm_classification(self, url: str) -> Optional[Dict[str, str]]:
        """
        Asynchronously classifies the website analysis JSON using an LLM.

        Args:
            analysis_json_str: The JSON string output from analyze_url.

        Returns:
            A dictionary with 'classification' and 'confidence' on success,
            or None if LLM classification is disabled or fails.
        """
        if not self.llm_token or not self.llm_api_url:
            logger.info("LLM classification skipped: Token or URL not configured.")
            return None

        logger.info(f"Requesting LLM classification using model: {self.llm_model}")

        # Build the prompt (same as provided)
        system_msg = {
            "role": "system",
            "content": self.llm_system_prompt # Use loaded system prompt
        }
        try:
            # Format the user prompt template with the actual JSON data
            user_content = self.llm_user_prompt_template.format(url=url)
        except KeyError:
             logger.error("LLM User Prompt Template missing '{url}' placeholder!")
             return None # Cannot proceed without the placeholder
        except Exception as e:
            logger.error(f"Error formatting LLM user prompt: {e}")
            return None

        user_msg = {
            "role": "user",
            "content": user_content # Use formatted user prompt
        }
        # --- ---
        payload = {
            "model": self.llm_model,
            "messages": [system_msg, user_msg],
             # Optional: Add parameters like temperature, max_tokens if needed
              "temperature": 0,
             # "max_tokens": 50
        }
        headers = {
            "Authorization": f"Bearer {self.llm_token}",
            "Content-Type": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client: # Increased timeout for LLM
                response = await client.post(self.llm_api_url, headers=headers, json=payload)
                response.raise_for_status() # Raise exception for 4xx/5xx responses
                content = response.json()

            # Extract the model reply content (handle potential variations in response structure)
            if not content.get("choices"):
                 logger.error(f"LLM response missing 'choices' field: {content}")
                 return None
            first_choice = content["choices"][0]
            if not first_choice.get("message"):
                 logger.error(f"LLM choice missing 'message' field: {first_choice}")
                 return None
            reply = first_choice["message"].get("content", "").strip()

            if not reply:
                 logger.error(f"LLM response content is empty.")
                 return None

            logger.debug(f"Raw LLM reply: {reply}")

            # Parse JSON-only reply
            try:
                result = json.loads(reply)
                # Basic validation of expected keys
                if "scam" not in result or "confidence" not in result:
                    logger.error(f"LLM JSON response missing required keys ('scam', 'confidence'): {result}")
                    return None # Or return a dict indicating parsing failure
                # Basic validation of expected values (optional but good)
                if result.get("scam") not in ["YES", "NO"] or \
                   result.get("confidence") not in ["LOW","MEDIUM", "HIGH"]:
                   logger.warning(f"LLM response values outside expected set: {result}")
                   # Decide whether to still return it or treat as error

                logger.info(f"LLM Classification successful: {result}")
                return result # Contains 'classification' and 'confidence'
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON response from model: {reply}")
                return None # Failed to parse LLM response

        except httpx.HTTPStatusError as e:
            logger.error(f"LLM request failed: Status {e.response.status_code} - {e.response.text}")
            return None
        except httpx.RequestError as e:
            logger.error(f"LLM request connection error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during LLM classification: {e}", exc_info=True)
            return None
        
def sanitize_url_for_filename(url: str) -> str:
    """Creates a safe filename from a URL."""
    try:
        # Prepend scheme if missing for parsing
        if '://' not in url:
            url = 'https://' + url
        parsed = urlparse(url)
        # Use netloc (domain/ip) as base, remove common prefixes like www.
        filename_base = parsed.netloc
        if filename_base.startswith("www."):
             filename_base = filename_base[4:]

        if not filename_base: # Fallback if netloc is empty (e.g., data: URL)
            # Try using path, sanitized
            filename_base = parsed.path.strip('/') if parsed.path else f"url_{int(time.time())}"
            if not filename_base: # Final fallback
                 filename_base = f"analysis_{int(time.time())}"


        # Replace invalid filename characters (including dots usually safe but replacing just in case)
        # Keep hyphens and underscores. Replace others with underscore.
        sanitized = re.sub(r'[/:?&=#<>"\*\|\.\\]+', '_', filename_base) # Added dot replacement

        # Remove leading/trailing underscores
        sanitized = sanitized.strip('_')

        # Prevent potentially empty filenames after sanitization
        if not sanitized:
             sanitized = f"analysis_{int(time.time())}"

        # Limit length if necessary (optional)
        max_len = 100
        if len(sanitized) > max_len:
             sanitized = sanitized[:max_len]

        return f"{sanitized}.json"
    except Exception as e:
        logging.warning(f"Error sanitizing URL '{url}' for filename: {e}")
        # Fallback for any unexpected error during sanitization
        return f"error_filename_{int(time.time())}.json"
    
async def main():
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="Analyze URLs for potential risks and optionally classify using an LLM.")
    parser.add_argument(
        '--classify',
        action='store_true', # Sets args.classify to True if flag is present
        default=False,       # Default is False if flag is not present
        help='Enable LLM classification after URL data analysis.'
    )
    args = parser.parse_args()
    # --- ---

    # --- Load .env variables ---
    # Done early so Analyzer can use them during init
    dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    print(f"Loading .env file from: {dotenv_path}")
    load_dotenv(dotenv_path=dotenv_path)

    logger.info(".env file loaded (or attempted).")

    analyzer = AsyncURLAnalyzer() # Instantiated AFTER load_dotenv and argparse

    # --- Determine Output Directory based on args ---
    if args.classify:
        output_directory = "test_analysis_results_with_llm"
        logger.info("LLM classification step is ENABLED.")
    else:
        output_directory = "test_analysis_results_only"
        logger.info("LLM classification step is DISABLED.")

    # Ensure the output directory exists
    try:
        os.makedirs(output_directory, exist_ok=True)
        logger.info(f"Ensured output directory exists: {output_directory}")
    except OSError as e:
        logger.error(f"Could not create output directory '{output_directory}': {e}")
        print(f"ERROR: Could not create output directory '{output_directory}'. Exiting.")
        return

    urls_to_test = [
        '''
        "https://luchanakids.es/bono-familiar/"
        "https://google.com",
        "http://example.com",
        "https://github.com",                        # Standard, secure, developer platform
        "https://www.amazon.com",                    # E‑commerce giant, secure
        "https://www.microsoft.com/en-us/",          # Major company, secure, path included
        "https://developer.mozilla.org/en-US/docs/Web/HTTP",  # Educational, secure, complex path
        "https://www.wikipedia.org/",                # Well‑known non‑profit, secure
        "https://discord.com/",                      # The platform itself
        "https://www.cloudflare.com/",               # Security/Infrastructure company
        "https://openai.com/",                       # AI Company
        #"http://info.cern.ch/",                      # Historic, likely HTTP, but legitimate origin of the web
        "https://support.google.com/",               # Legitimate subdomain
        "https://aws.amazon.com/",                   # Legitimate subdomain
        "https://1.1.1.1", # IP Address Example
        "https://expired.badssl.com/", # Expired Cert Example
        "https://wrong.host.badssl.com/", # Hostname Mismatch Example
        "https://self-signed.badssl.com/", # Self-Signed Cert Example
        "https://untrusted-root.badssl.com/ ", # Untrusted Root Example
        "https://subdomain.prefixed-paypal.com.some-other-domain.xyz", # Deceptive subdomain example
        "http://a-domain-that-likely-does-not-exist-sdlkfjsdlkfjsd.xyz", # NXDOMAIN example
        "https://www.аррӏе.com/"
        "https://github.com/login", # Page with form
        "https://anomali.com", # Example of a security company website
        "http://example.com/path/to/a/very/long/resource/name/that/might/seem/unusual/index.php?param1=value1&param2=a_very_long_encoded_value_%20like_this&redirect=http://anothersite.com",   # Long URL with query params
        "http://g00gle.com", #(Often parked or malicious - check resolution cautiously if needed, but tool should flag structure)
        "http://micr0s0ft.com", #(Similar to above)
        "http://paypa1.com", #(Similar to above)
        "https://google-login-secure.com", #(Uses brand name, implies security, but isn't Google's real domain)
        "https://apple.support-icloud.com", #(Attempts to mimic support structure)
        "http://amazonn.co.uk", #(Slight misspelling, different TLD - may or may not resolve)
        "https://1.1.1.1/", #(Legitimate Cloudflare DNS, but direct IP use can be flagged contextually)
        #"http://52.15.123.45/paypal/login.php", # (Direct IP with path - could be legitimate or phishing)
        "https://google.com.login-secure-site.xyz", #(Real domain is login-secure-site.xyz, uses risky TLD)
        "http://amazon.co.uk.account-update.info", #(Real domain is account-update.info)
        "https://discord.com-gift-nitro.link", #(Looks like discord.com, but is discord.com-gift-nitro.link)
        "http://123456.cloudfront.net.maliciousdomain.ru/login.html", #(Abuses CDN subdomain appearance)
        "https://secure-bank-login.xyz", #(Generic, risky TLD)
        "http://free-crypto-giveaway.tk", #(Common scam pattern, risky TLD)
        "https://package-tracking-update.zip", #(.zip TLD known for abuse)
        "http://account-verification-required.pw", #(Urgency, risky TLD)
        "https://win-a-free-iphone-official.live" #(Too good to be true, risky TLD) 
        '''
    ]

    print(f"--- Starting URL analysis batch ({'including LLM classification' if args.classify else 'data analysis only'}) ---")
    print(f"Results will be saved in: ./{output_directory}/")

    try:
        for url in urls_to_test:
            print(f"\n--- Processing: {url} ---")
            analysis_json_str = None
            llm_classification_result = None # Initialize to None

            # 1. Analyze URL (Always runs)
            try:
                analysis_json_str = await analyzer.analyze_url(url)
                print(f"   ✅ URL Analysis complete.")
            except Exception as e:
                print(f"   ❌ ERROR during URL Analysis for {url}: {e}")
                logger.error(f"Analysis failed for URL: {url}", exc_info=True)
                analysis_json_str = None # Ensure it's None

            # 2. Classify using LLM (Conditionally runs)
            if args.classify and analysis_json_str: # Check flag AND if analysis succeeded
                print(f"   ▶️ Requesting LLM classification...")
                try:
                    llm_classification_result = await analyzer.get_llm_classification(analysis_json_str)
                    if llm_classification_result:
                        print(f"   ✅ LLM Classification result: {llm_classification_result}")
                    else:
                        # Check if LLM is configured before printing warning
                        if analyzer.llm_token and analyzer.llm_api_url:
                             print(f"   ⚠️ LLM Classification failed or returned invalid data.")
                        else:
                             print(f"   ℹ️ LLM Classification skipped (LLM not configured in .env).")
                except Exception as e:
                    print(f"   ❌ ERROR during LLM Classification for {url}: {e}")
                    logger.error(f"LLM classification failed for URL: {url}", exc_info=True)
                    llm_classification_result = None # Ensure it's None
            elif not args.classify:
                 print(f"   ℹ️ LLM Classification skipped (run with --classify to enable).")
            elif not analysis_json_str:
                 print(f"   ℹ️ LLM Classification skipped due to prior analysis error.")


            # 3. Save results (if analysis succeeded)
            if analysis_json_str:
                try:
                    analysis_data = json.loads(analysis_json_str)
                    # Add LLM result (will be None if classification wasn't run or failed)
                    analysis_data["llm_classification"] = llm_classification_result

                    filename = sanitize_url_for_filename(url)
                    filepath = os.path.join(output_directory, filename)

                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(analysis_data, f, indent=2, default=str)
                    print(f"   ✅ Combined analysis saved to: {filepath}")

                except json.JSONDecodeError as e:
                     print(f"   ❌ ERROR: Failed to re-parse analysis JSON for saving: {e}")
                     logger.error(f"Failed to re-parse analysis JSON for {url}", exc_info=True)
                except IOError as e:
                    print(f"   ❌ ERROR: Could not write analysis file {filepath}: {e}")
                    logging.error(f"Failed to write analysis file {filepath}", exc_info=True)
                except Exception as e:
                     print(f"   ❌ ERROR: Unexpected error saving file {filepath}: {e}")
                     logging.error(f"Unexpected error saving file {filepath}", exc_info=True)
            else:
                 print(f"   ℹ️ Skipping file save due to analysis failure.")

            print("-" * 20)

    finally:
        await analyzer.close_session()
        logger.info("Closed analyzer session in main test function.")
        print(f"--- Finished URL analysis batch ---")


if __name__ == "__main__":

    # --- Configure logging ---
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
    # Optionally set higher level for libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("playwright").setLevel(logging.WARNING)

    # --- Asyncio setup ---
    # (Keep Windows policy section if needed)
    # import sys
    # if sys.platform == 'win32':
    #      asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())

    