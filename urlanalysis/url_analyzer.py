#!/usr/bin/env python3
import asyncio
import json
import ssl
import socket
from urllib.parse import urlparse, ParseResult, urljoin
import ipaddress
import datetime # Ensure datetime is imported
import logging
from typing import Dict, Any, Optional, List, Tuple, Set
import time
import httpx
import aiohttp
import dns.asyncresolver
import whois
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError
import tldextract
from OpenSSL import crypto as PyOpenSSL_crypto
from dotenv import load_dotenv
import yaml
import redis.asyncio as aioredis
import os
import re # Added re for main_test_analyzer filename sanitization

logger = logging.getLogger(__name__)

DEFAULT_PIPELINE_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'analysis_pipeline_config.yaml')
DEFAULT_PROMPTS_DIR = os.path.join(os.path.dirname(__file__), 'prompts')

DOMAIN_STEP_CACHE_PREFIX = "urlscan:domain_step_cache:"
DOMAIN_STEP_CACHE_EXPIRY_SECONDS = 60 * 60 * 24 * 3

class AsyncURLAnalyzer:
    def __init__(self, pipeline_config_path: str = DEFAULT_PIPELINE_CONFIG_PATH,
                 redis_client: Optional[aioredis.Redis] = None):
        self.pipeline_config_path = pipeline_config_path
        self.config: Dict[str, Any] = self._load_pipeline_config()
        self.redis_client = redis_client # For domain-step caching in "full_url" mode

        # Read ANALYSIS_MODE from environment, default to "domain"
        self.analysis_mode = os.getenv("ANALYSIS_MODE", "domain").lower()
        logger.info(f"Analyzer initialized with ANALYSIS_MODE: {self.analysis_mode}")


        llm_cfg = self.config.get("llm_settings", {})
        self.llm_api_token = os.getenv(llm_cfg.get("api_token_env_var", "OPENWEBUI_TOKEN"))
        llm_base_url = os.getenv(llm_cfg.get("api_url_env_var", "OPENWEBUI_URL"), "")
        llm_api_path = llm_cfg.get("api_url_path", "/api/chat/completions")
        if llm_base_url:
            if llm_base_url.endswith('/'): llm_base_url = llm_base_url[:-1]
            self.llm_api_url = f"{llm_base_url}{llm_api_path}"
        else: self.llm_api_url = ""
        self.llm_model_name = os.getenv(llm_cfg.get("model_env_var", "OPENWEBUI_LLM_MODEL"), "mistral:latest")
        self.llm_default_temp = float(llm_cfg.get("default_temperature", 0.1))
        if not self.llm_api_token or not self.llm_api_url:
            logger.warning("LLM API token or base URL not fully configured in Analyzer.")
        else:
            logger.info(f"Analyzer LLM settings: API URL='{self.llm_api_url}', Model='{self.llm_model_name}'")

        self.prompts: Dict[str, str] = self._load_all_prompts()
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self._aiohttp_session: Optional[aiohttp.ClientSession] = None
        self._httpx_client: Optional[httpx.AsyncClient] = None
        self._dns_resolver = dns.asyncresolver.Resolver(); self._dns_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        ps_cfg = self.config.get("playwright_settings", {})
        self.playwright_enable_assessment_step = ps_cfg.get("enable_assessment_step", False)
        self.playwright_enable_for_final_report = ps_cfg.get("enable_for_final_report_if_scam", True)
        self.playwright_timeout = int(ps_cfg.get("timeout_seconds", 25))

    def _load_pipeline_config(self) -> Dict[str, Any]:
        try:
            with open(self.pipeline_config_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
                logger.info(f"Successfully loaded analysis pipeline config from '{self.pipeline_config_path}'")
                return cfg
        except FileNotFoundError:
            logger.error(f"FATAL: Pipeline config file not found: '{self.pipeline_config_path}'. Bot may not function correctly.")
            return {}
        except yaml.YAMLError as e:
            logger.error(f"FATAL: Error parsing YAML from '{self.pipeline_config_path}': {e}. Bot may not function correctly.")
            return {}
        except Exception as e:
            logger.error(f"FATAL: Unexpected error loading config '{self.pipeline_config_path}': {e}. Bot may not function correctly.")
            return {}

    def _resolve_config_path(self, file_path_in_config: str, base_dir: str) -> str:
        if not file_path_in_config: return ""
        if os.path.isabs(file_path_in_config): return file_path_in_config
        return os.path.join(base_dir, file_path_in_config)

    def _load_prompt_content(self, prompt_key: str, file_path: str) -> str:
        if not file_path:
            logger.warning(f"Prompt file path for key '{prompt_key}' is empty.")
            return ""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                logger.debug(f"Successfully loaded prompt '{prompt_key}' from '{file_path}'")
                return content
        except FileNotFoundError:
            logger.error(f"Prompt file not found for key '{prompt_key}' at '{file_path}'.")
            return ""
        except Exception as e:
            logger.error(f"Error loading prompt file for key '{prompt_key}' from '{file_path}': {e}")
            return ""

    def _load_all_prompts(self) -> Dict[str, str]:
        prompts_dict = {}
        if not self.config: return prompts_dict
        default_sys_prompt_path = self._resolve_config_path(
            self.config.get("default_step_system_prompt_file", ""), DEFAULT_PROMPTS_DIR
        )
        prompts_dict["default_step_system"] = self._load_prompt_content("default_step_system", default_sys_prompt_path)
        for step_cfg in self.config.get("analysis_steps", []):
            step_name = step_cfg.get("step_name")
            prompt_file_rel_path = step_cfg.get("prompt_file")
            if step_name and prompt_file_rel_path:
                full_prompt_path = self._resolve_config_path(prompt_file_rel_path, DEFAULT_PROMPTS_DIR)
                prompts_dict[step_name] = self._load_prompt_content(step_name, full_prompt_path)
        final_assessment_cfg = self.config.get("final_assessment_llm", {})
        final_prompt_rel_path = final_assessment_cfg.get("prompt_file")
        if final_prompt_rel_path:
            full_final_prompt_path = self._resolve_config_path(final_prompt_rel_path, DEFAULT_PROMPTS_DIR)
            prompts_dict["final_decider_assessment"] = self._load_prompt_content("final_decider_assessment", full_final_prompt_path)
        return prompts_dict

    async def _get_aiohttp_session(self) -> aiohttp.ClientSession:
        if self._aiohttp_session is None or self._aiohttp_session.closed:
            headers = {'User-Agent': self.user_agent}
            # Adjust connector to handle SSL verification properly if needed,
            # but for general reachability, system certs are usually fine.
            # For specific SSL checks (like in check_ssl_certificate), we handle SSL context manually.
            connector = aiohttp.TCPConnector(ssl=False) # SSL False for TCPConnector means it will use default SSL context for HTTPS
            self._aiohttp_session = aiohttp.ClientSession(headers=headers, connector=connector)
        return self._aiohttp_session

    async def _get_httpx_client(self) -> httpx.AsyncClient:
        if self._httpx_client is None or self._httpx_client.is_closed:
            self._httpx_client = httpx.AsyncClient(timeout=120.0) # Increased timeout for LLM calls
        return self._httpx_client

    async def close_sessions(self):
        if self._aiohttp_session and not self._aiohttp_session.closed:
            await self._aiohttp_session.close()
            logger.info("Analyzer's aiohttp session closed.")
        if self._httpx_client and not self._httpx_client.is_closed:
            await self._httpx_client.aclose()
            logger.info("Analyzer's httpx client closed.")

    def _parse_url_components(self, url: str) -> Dict[str, Any]:
        original_url = url
        # Improved initial URL fixing attempt
        if '://' not in url:
            # Check if it looks like a common domain without scheme (e.g., google.com/path)
            if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/.*)?$", url):
                url = 'https://' + url
            else: # Otherwise, default to https, but this might be less reliable for unusual inputs
                url = 'https://' + url

        components = {"original_url": original_url, "parsed_obj": None, "scheme": "https", "netloc": "", "port": 443, "domain_parts": {}, "error": None}
        try:
            parsed: Optional[ParseResult] = urlparse(url)
            components["parsed_obj"] = parsed # Store the raw ParseResult object

            if not parsed or not parsed.netloc: # A netloc is essential
                components["error"] = f"Could not parse network location from URL: {original_url}"
                return components

            components["scheme"] = parsed.scheme.lower() if parsed.scheme else "https" # Default to https if scheme missing
            components["netloc"] = parsed.netloc.lower()

            port_val = parsed.port
            if not port_val: # Infer port if not specified
                port_val = 443 if components["scheme"] == 'https' else 80
            components["port"] = port_val

            components["domain_parts"] = self._extract_domain_parts(components["netloc"])
            return components
        except Exception as e:
            logger.warning(f"URL parsing failed for '{original_url}': {e}")
            components["error"] = f"URL parsing failed: {e}"
            return components

    def _extract_domain_parts(self, netloc: str) -> Dict[str, Optional[str]]:
        try:
            # Remove port if present in netloc before passing to tldextract
            if ':' in netloc:
                netloc_no_port, _, _ = netloc.rpartition(':')
                if netloc_no_port: # Ensure it wasn't just e.g. ":80"
                    ext = tldextract.extract(netloc_no_port)
                else: # if it was just ":80", tldextract on empty string isn't useful
                    ext = tldextract.extract(netloc) # fallback to original netloc
            else:
                ext = tldextract.extract(netloc)

            registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None
            return {
                "full_host": netloc, # Original netloc (potentially with port)
                "subdomain": ext.subdomain or None,
                "domain_name": ext.domain or None,
                "tld": ext.suffix or None,
                "registered_domain": registered_domain
            }
        except Exception as e: # Fallback for safety, though tldextract is robust
            logger.error(f"tldextract failed for netloc '{netloc}': {e}", exc_info=True)
            parts = netloc.split('.')
            if len(parts) >= 2:
                return {
                    "full_host": netloc,
                    "subdomain": ".".join(parts[:-2]) or None,
                    "domain_name": parts[-2],
                    "tld": parts[-1],
                    "registered_domain": f"{parts[-2]}.{parts[-1]}"
                }
            return {
                "full_host": netloc, "subdomain": None,
                "domain_name": netloc if '.' not in netloc else None,
                "tld": None, "registered_domain": netloc if '.' in netloc else None
            }


    async def _call_llm(self, system_prompt: str, user_prompt: str, step_name_for_log: str) -> Dict[str, Any]:
        if not self.llm_api_token or not self.llm_api_url:
            msg = "LLM not configured (token or URL missing)."
            logger.error(f"Analyzer LLM Call for {step_name_for_log}: {msg}"); return {"error": msg}

        if not system_prompt: # Should not happen if default is loaded
            msg = "System prompt is empty."
            logger.error(f"Analyzer LLM Call for {step_name_for_log}: {msg}"); return {"error": msg}

        client = await self._get_httpx_client()
        payload = {
            "model": self.llm_model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": self.llm_default_temp,
            "response_format": {"type": "json_object"} # Standard way to request JSON
        }
        headers = {
            "Authorization": f"Bearer {self.llm_api_token}",
            "Content-Type": "application/json"
        }

        logger.debug(f"Analyzer LLM Call for '{step_name_for_log}': Model='{self.llm_model_name}'. User prompt (first 100 chars): {user_prompt[:100]}...")

        try:
            response = await client.post(self.llm_api_url, headers=headers, json=payload)
            response.raise_for_status() # Raises HTTPStatusError for 4xx/5xx responses
            response_json = response.json()

            # Standard OpenAI API response structure
            llm_content_str = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")

            if not llm_content_str:
                logger.error(f"Analyzer LLM Call for {step_name_for_log}: LLM response content empty. Full response: {response_json}")
                return {"error": "LLM response content empty", "raw_response_json": response_json}

            logger.debug(f"Analyzer LLM Call for {step_name_for_log}: Raw LLM content: {llm_content_str}")
            # Attempt to parse the content as JSON
            parsed_llm_response = json.loads(llm_content_str)

            # Validate required keys based on step type
            required_keys = ["scam", "confidence", "reason"] \
                if "final_decider" not in step_name_for_log \
                else ["overall_is_scam", "overall_confidence", "overall_reason"]

            if not all(k in parsed_llm_response for k in required_keys):
                logger.error(f"Analyzer LLM Call for {step_name_for_log}: LLM JSON missing required keys ({required_keys}). Got: {parsed_llm_response}")
                return {"error": "LLM JSON response missing required keys", "raw_response": parsed_llm_response}

            logger.info(f"Analyzer LLM Call for {step_name_for_log}: Assessment successful. Response: {parsed_llm_response}")
            return parsed_llm_response

        except httpx.HTTPStatusError as e:
            err_text = e.response.text[:500] # Limit error text length
            logger.error(f"Analyzer LLM Call for {step_name_for_log}: HTTP Status {e.response.status_code} - {err_text}", exc_info=True)
            return {"error": f"LLM HTTP Status Error: {e.response.status_code}", "details": err_text}
        except httpx.RequestError as e: # Catches network errors, timeouts etc.
            logger.error(f"Analyzer LLM Call for {step_name_for_log}: Connection error: {e}", exc_info=True)
            return {"error": f"LLM Request Connection Error: {type(e).__name__}"}
        except json.JSONDecodeError:
            logger.error(f"Analyzer LLM Call for {step_name_for_log}: Failed to parse LLM JSON response: '{llm_content_str}'", exc_info=True)
            return {"error": "LLM response not valid JSON", "raw_content": llm_content_str}
        except Exception as e: # Catch-all for other unexpected errors
            logger.error(f"Analyzer LLM Call for {step_name_for_log}: Unexpected error: {e}", exc_info=True)
            return {"error": f"Unexpected error in LLM call: {type(e).__name__}"}

    async def _get_raw_url_for_llm(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        return {"url_string": url_info.get("original_url")}

    async def check_url_reachability(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        url = url_info.get("original_url")
        result: Dict[str, Any] = {"url": url, "reachable": False, "status_code": None, "final_url": url, "error": None, "headers": {}}
        if not url:
            result["error"] = "URL for reachability check missing"
            return result
        session = await self._get_aiohttp_session()
        try:
            # Reduced timeout for reachability, as it's a quick check
            async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as response:
                result["reachable"] = True
                result["status_code"] = response.status
                result["final_url"] = str(response.url)
                result["headers"] = dict(response.headers)
        except aiohttp.ClientConnectorCertificateError as e: # SSL specific connection error
            result["error"] = f"SSL Certificate Error: {getattr(e, 'os_error', str(e))}"
        except aiohttp.ClientConnectorError as e: # Other connection errors (DNS, refused)
            result["error"] = f"Connection Error: {getattr(e, 'os_error', str(e))}"
        except asyncio.TimeoutError:
            result["error"] = f"Request timed out after 15 seconds."
        except aiohttp.ClientError as e: # Catch other aiohttp client errors
            result["error"] = f"HTTP Client Error: {type(e).__name__} - {str(e)}"
        except Exception as e: # Catch-all for unexpected issues
            result["error"] = f"Unexpected reachability error: {type(e).__name__} - {str(e)}"
            logger.warning(f"Unexpected reachability error for {url}: {e}", exc_info=True)

        logger.debug(f"Reachability for '{url}': Reachable={result['reachable']}, Status={result['status_code']}, FinalURL='{result['final_url']}', Error='{result['error']}'")
        return result

    async def check_dns_records(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        # Use 'registered_domain' if available, otherwise fallback to 'netloc'
        domain_to_check = url_info.get("domain_parts", {}).get("registered_domain") or url_info.get("netloc")

        if not domain_to_check:
            return {"error": "Domain/Netloc for DNS check missing", "domain": domain_to_check, "records_json_str":"{}"}

        result: Dict[str, Any] = {"domain": domain_to_check, "records": {}, "error": None}
        # Standard record types to check
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        async def query_dns_type(record_type_to_query: str):
            try:
                answers = await self._dns_resolver.resolve(domain_to_check, record_type_to_query)
                if record_type_to_query in ["A", "AAAA"]:
                    return [r.to_text() for r in answers]
                elif record_type_to_query == "MX":
                    # Sort by preference, then exchange
                    return sorted([f"{r.preference} {r.exchange.to_text()}" for r in answers])
                elif record_type_to_query in ["NS", "CNAME"]:
                    return [r.target.to_text() for r in answers] # Use to_text() for consistency
                elif record_type_to_query == "TXT":
                    # Join multi-string TXT records, decode with ignore for robustness
                    return [" ".join(txt_part.decode('utf-8','ignore') for txt_part in r.strings)]
            except dns.resolver.NoAnswer: return [] # No records of this type
            except dns.resolver.NXDOMAIN: raise dns.resolver.NXDOMAIN # Propagate NXDOMAIN
            except dns.exception.Timeout: return ["[TIMEOUT_QUERYING_DNS]"]
            except Exception as e: # Catch other DNS query errors
                logger.warning(f"DNS query error for {domain_to_check}/{record_type_to_query}: {type(e).__name__} - {e}")
                return [f"[ERROR_QUERYING_DNS_{record_type_to_query.upper()}: {type(e).__name__}]"]
            return [] # Should not be reached if handled above

        try:
            for r_type in record_types:
                records_data = await query_dns_type(r_type)
                if records_data: # Only add if records were found or an error placeholder was returned
                    result["records"][r_type] = records_data
        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN: Domain does not exist."
        except Exception as e: # Catch-all for unexpected errors during the loop
            result["error"] = f"Unexpected DNS resolution error: {type(e).__name__}"
            logger.error(f"Unexpected DNS error for {domain_to_check}: {e}", exc_info=True)

        # Serialize records to JSON string for the prompt
        try:
            result["records_json_str"] = json.dumps(result["records"], default=str)
        except TypeError:
            result["records_json_str"] = '{"error": "Failed to serialize DNS records to JSON"}'
            logger.error(f"Failed to serialize DNS records for {domain_to_check} to JSON", exc_info=True)

        log_dns_keys = list(result['records'].keys()) if result['records'] else "None"
        logger.debug(f"DNS for '{domain_to_check}': Found types {log_dns_keys}, Error='{result['error']}'")
        return result

    async def check_whois_information(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        domain = url_info.get("domain_parts", {}).get("registered_domain")
        if not domain:
            return {"error": "Registered domain for WHOIS check missing", "domain": domain, "parsed_json_str":"{}", "analysis_flags":[]}

        result: Dict[str, Any] = {"domain": domain, "parsed": None, "error": None, "analysis_flags": []}

        def sync_whois_lookup(d_lookup):
            try:
                # The python-whois library can sometimes be slow or hang.
                # It's run in an executor to avoid blocking the asyncio loop.
                return whois.whois(d_lookup)
            except Exception as e_lookup:
                logger.warning(f"WHOIS lookup for '{d_lookup}' failed in executor: {type(e_lookup).__name__} - {e_lookup}")
                return f"Error during WHOIS lookup: {type(e_lookup).__name__}"

        loop = asyncio.get_running_loop()
        try:
            # Increased timeout for run_in_executor might be needed if WHOIS is consistently slow
            whois_data = await asyncio.wait_for(loop.run_in_executor(None, sync_whois_lookup, domain), timeout=20.0)

            if isinstance(whois_data, str) and whois_data.startswith("Error"):
                result["error"] = whois_data
            elif whois_data and (whois_data.get('domain_name') or whois_data.get('emails')): # Basic check for some data
                parsed_data = {}
                # Convert datetime objects to ISO format strings for JSON serialization
                for k_item, v_item in whois_data.items():
                    if isinstance(v_item, list) and v_item and isinstance(v_item[0], datetime.datetime):
                        parsed_data[k_item] = sorted([dt_item.isoformat() for dt_item in v_item])
                    elif isinstance(v_item, datetime.datetime):
                        parsed_data[k_item] = v_item.isoformat()
                    elif k_item != 'text': # Exclude the raw text if desired, it can be very long
                        parsed_data[k_item] = v_item
                result["parsed"] = parsed_data

                # Basic analysis flags
                if not parsed_data.get("registrar") and not parsed_data.get("creation_date") and not parsed_data.get("emails"):
                    result["analysis_flags"].append("WHOIS_DATA_VERY_LIMITED")
                if any("privacy" in str(val).lower() or "redacted" in str(val).lower() for val in parsed_data.values() if val):
                     result["analysis_flags"].append("WHOIS_PRIVACY_SERVICE_LIKELY_USED")

            else:
                result["error"] = "WHOIS data not found, incomplete, or in unexpected format."
                if whois_data: # Log what was received if it wasn't an error string but still not useful
                     logger.debug(f"Unexpected WHOIS data structure for '{domain}': {str(whois_data)[:200]}")


        except asyncio.TimeoutError:
            result["error"] = "WHOIS lookup timed out after 20 seconds."
            logger.warning(f"WHOIS lookup timed out for domain: {domain}")
        except Exception as e: # Catch-all for other unexpected errors during WHOIS processing
            result["error"] = f"Unexpected error processing WHOIS for '{domain}': {type(e).__name__}"
            logger.error(f"WHOIS processing error for {domain}: {e}", exc_info=True)

        try:
            result["parsed_json_str"] = json.dumps(result.get("parsed"), default=str)
        except TypeError:
            result["parsed_json_str"] = '{"error": "Failed to serialize WHOIS data to JSON"}'
            logger.error(f"Failed to serialize WHOIS data for {domain} to JSON", exc_info=True)

        log_whois_keys = list(result['parsed'].keys()) if result['parsed'] else "None"
        logger.debug(f"WHOIS for '{domain}': Parsed keys {log_whois_keys}, Flags={result['analysis_flags']}, Error='{result['error']}'")
        return result

    async def check_ssl_certificate(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        hostname = url_info.get("netloc")
        port = url_info.get("port", 443) # Default to 443 if not specified
        original_url_scheme = url_info.get("scheme", "https") # Default to https

        result: Dict[str, Any] = {
            "hostname": hostname, "port": port,
            "details": {"hostname_match": False}, # Initialize hostname_match
            "error": None, "details_json_str": "{}"
        }

        if not hostname:
            result["error"] = "Hostname for SSL check missing"
            return result

        if original_url_scheme != "https":
            logger.info(f"Skipping SSL check for non-HTTPS scheme ('{original_url_scheme}') on URL: {url_info.get('original_url')}")
            result["error"] = f"Skipped SSL check for non-HTTPS scheme: {original_url_scheme}"
            return result

        # Configure SSL context: no verification here, just fetching the cert
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = None
        conn = None

        try:
            # Establish connection and wrap socket
            sock = socket.create_connection((hostname, port), timeout=10) # Connection timeout
            # server_hostname is crucial for SNI
            conn = context.wrap_socket(sock, server_hostname=hostname)
            der_cert = conn.getpeercert(binary_form=True)

            if not der_cert:
                result["error"] = "Could not retrieve certificate (getpeercert returned None)"
                return result # details_json_str already default

            x509 = PyOpenSSL_crypto.load_certificate(PyOpenSSL_crypto.FILETYPE_ASN1, der_cert)
            details: Dict[str, Any] = {"hostname_match": False} # Re-init for safety

            # Extract Subject and Issuer
            details["subject"] = dict((k.decode('utf-8', 'ignore'), v.decode('utf-8', 'ignore')) for k, v in x509.get_subject().get_components())
            details["issuer"] = dict((k.decode('utf-8', 'ignore'), v.decode('utf-8', 'ignore')) for k, v in x509.get_issuer().get_components())
            details["common_name"] = details["subject"].get("CN")

            # Dates: Convert ASN1GeneralizedTime to ISO format
            if x509.get_notBefore():
                details["valid_from"] = datetime.datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ').isoformat() + "Z"
            if x509.get_notAfter():
                details["valid_until"] = datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').isoformat() + "Z"

            # Hostname matching (CN and SANs)
            cert_hostnames_from_cert: Set[str] = set()
            if details["common_name"]:
                cert_hostnames_from_cert.add(details["common_name"])

            sans_str_list = []
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                short_name = ext.get_short_name().decode('utf-8', 'ignore')
                if short_name == 'subjectAltName':
                    sans_str_list.extend(s.strip() for s in str(ext).split(',')) # str(ext) gives DNS:name1, DNS:name2
                    break
            details["subject_alt_names_raw"] = sans_str_list # Store raw SANs string list

            for san_entry in sans_str_list:
                if san_entry.lower().startswith("dns:"):
                    cert_hostnames_from_cert.add(san_entry[4:])

            hostname_lower = hostname.lower()
            # More robust matching: exact match or wildcard match
            for cert_name_raw in cert_hostnames_from_cert:
                cert_name_lower = cert_name_raw.lower()
                if cert_name_lower == hostname_lower:
                    details["hostname_match"] = True; break
                if cert_name_lower.startswith("*."): # Wildcard
                    wildcard_base = cert_name_lower[2:]
                    # Ensure hostname is not just the wildcard base (e.g. *.example.com matches foo.example.com but not example.com)
                    if hostname_lower.endswith("." + wildcard_base) and len(hostname_lower) > len(wildcard_base) + 1:
                         # Check that the part replacing '*' contains no dots (e.g. *.example.com doesn't match sub.sub.example.com)
                        prefix = hostname_lower[:-(len(wildcard_base) + 1)]
                        if '.' not in prefix:
                            details["hostname_match"] = True; break
            result["details"] = details

        except socket.gaierror: result["error"] = f"Could not resolve hostname: {hostname}"
        except socket.timeout: result["error"] = f"Connection timed out ({hostname}:{port}) during SSL check."
        except ConnectionRefusedError: result["error"] = f"Connection refused ({hostname}:{port}) during SSL check."
        except ssl.SSLCertVerificationError as e: result["error"] = f"SSL Certificate Verification Error: {e.reason} (Code: {e.verify_code})"
        except ssl.SSLError as e: result["error"] = f"SSL Error: {getattr(e, 'reason', str(e))}" # More general SSL error
        except PyOpenSSL_crypto.Error as e: result["error"] = f"pyOpenSSL Certificate Parsing Error: {str(e)}"
        except Exception as e:
            result["error"] = f"Unexpected SSL check error: {type(e).__name__} - {str(e)}"
            logger.warning(f"Unexpected SSL check error for {hostname}:{port}: {e}", exc_info=True)
        finally:
            if conn:
                try: conn.shutdown(socket.SHUT_RDWR) # Graceful shutdown
                except OSError: pass # Ignore if already closed or error
                conn.close()
            if sock: sock.close()

        try:
            result["details_json_str"] = json.dumps(result["details"], default=str)
        except TypeError:
            result["details_json_str"] = '{"error": "Failed to serialize SSL details to JSON"}'
            logger.error(f"Failed to serialize SSL details for {hostname} to JSON", exc_info=True)

        log_cn = result['details'].get('common_name', 'N/A')
        log_match = result['details'].get('hostname_match', 'N/A')
        logger.debug(f"SSL for '{hostname}': CN='{log_cn}', Match={log_match}, Error='{result['error']}'")
        return result

    async def extract_page_elements(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        original_url = url_info.get("original_url")
        if not original_url:
            return {"error": "Original URL for Playwright missing", "url": original_url}

        result = {
            "url": original_url, "final_url": original_url, "title": None,
            "meta": {}, "links_count":0, "scripts_count":0, "forms_count":0,
            "text_preview_200": None, "error": None, "meta_description": None
        }
        pw_instance = None; browser = None; context = None; page = None # Define for finally block

        try:
            pw_instance = await async_playwright().start()
            # Using Chromium, ensure it's installed (python -m playwright install chromium)
            browser = await pw_instance.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=self.user_agent,
                ignore_https_errors=True, # Be cautious with this in security tools
                java_script_enabled=True # Usually needed for full page rendering
            )
            page = await context.new_page()
            # Navigate with a timeout
            await page.goto(original_url, wait_until='domcontentloaded', timeout=self.playwright_timeout * 1000)

            result["final_url"] = page.url
            result["title"] = await page.title()

            # Extract meta tags
            meta_elements = await page.locator('meta').all()
            for meta_el in meta_elements:
                name = await meta_el.get_attribute('name')
                prop = await meta_el.get_attribute('property')
                content = await meta_el.get_attribute('content')
                key_to_use = name or prop # Prefer name, fallback to property
                if key_to_use and content:
                    result["meta"][key_to_use.lower()] = content # Store with lowercase key

            # Get common meta descriptions
            result["meta_description"] = result["meta"].get("description") or \
                                       result["meta"].get("og:description") or \
                                       result["meta"].get("twitter:description")

            result["forms_count"] = await page.locator('form').count()
            result["scripts_count"] = await page.locator('script[src]').count() # Count external scripts
            result["links_count"] = await page.locator('a[href]').count() # Count anchor links

            # Get a preview of the body text, cleaner extraction
            try:
                body_text_full = await page.locator('body').inner_text(timeout=5000) # Timeout for text extraction
                # Normalize whitespace and take preview
                result["text_preview_200"] = ' '.join(body_text_full.split()).strip()[:200] + ('...' if len(body_text_full) > 200 else '')
            except PlaywrightTimeoutError:
                result["text_preview_200"] = "[Error: Timed out extracting body text]"
                logger.warning(f"Playwright: Timed out extracting body text from {original_url}")
            except PlaywrightError as text_extract_err:
                result["text_preview_200"] = f"[Error extracting body text: {type(text_extract_err).__name__}]"
                logger.warning(f"Playwright: Error extracting body text from {original_url}: {text_extract_err}")


        except PlaywrightTimeoutError:
            result["error"] = f"Playwright: Page load or navigation timed out after {self.playwright_timeout}s."
        except PlaywrightError as e: # Catch more specific Playwright errors
            result["error"] = f"Playwright: Error during page interaction - {type(e).__name__}: {str(e)}"
        except Exception as e: # Catch-all for other unexpected errors
            result["error"] = f"Playwright: Unexpected error - {type(e).__name__}: {str(e)}"
            logger.error(f"Playwright unexpected error for {original_url}: {e}", exc_info=True)
        finally:
            # Ensure resources are closed in reverse order of creation
            if page: await page.close()
            if context: await context.close()
            if browser and browser.is_connected(): await browser.close()
            if pw_instance: await pw_instance.stop()

        log_title = result['title'] if result['title'] else "N/A"
        logger.debug(f"Playwright for '{original_url}': Title='{log_title}', Error='{result['error']}'")
        return result

    async def get_holistic_url_assessment(self, url_to_analyze: str) -> Dict[str, Any]:
        start_time_mono = time.monotonic()
        current_date_iso = datetime.datetime.now(datetime.timezone.utc).isoformat() # Get current date for SSL prompt
        logger.info(f"Starting holistic assessment for URL: {url_to_analyze} (Mode: {self.analysis_mode})")

        url_components = self._parse_url_components(url_to_analyze)
        if url_components.get("error"):
            return {"original_url": url_to_analyze, "error": url_components["error"],
                    "assessment_summary": {"overall_is_scam": "ERROR", "overall_confidence": "NONE", "overall_reason": url_components["error"]}}

        all_results: Dict[str, Any] = {
            "original_url": url_to_analyze,
            "analysis_start_time_utc": current_date_iso, # Use the fetched current_date_iso
            "url_components": url_components, "steps_data": {}, "steps_llm_assessments": {},
            "errors_encountered": [], "final_llm_assessment": None,
            "assessment_summary": {"overall_is_scam": "UNKNOWN", "overall_confidence": "NONE", "overall_reason": "Assessment pending."}
        }
        step_system_prompt = self.prompts.get("default_step_system", "You are a helpful AI.")

        for step_cfg in self.config.get("analysis_steps", []):
            step_name = step_cfg.get("step_name")
            step_scope = step_cfg.get("scope", "url")

            execution_modes = step_cfg.get("execution_modes", ["domain", "full_url"])
            if self.analysis_mode not in execution_modes:
                logger.debug(f"Skipping step '{step_name}' due to ANALYSIS_MODE '{self.analysis_mode}'. Step runs in: {execution_modes}")
                continue

            is_enabled = step_cfg.get("enabled", True)
            enabled_cfg_key = step_cfg.get("enabled_config_key")
            if enabled_cfg_key:
                key_parts = enabled_cfg_key.split('.'); current_val = self.config
                try:
                    for part in key_parts: current_val = current_val[part]
                    is_enabled = bool(current_val)
                except (KeyError, TypeError): logger.warning(f"Cannot resolve dynamic enable key '{enabled_cfg_key}' for '{step_name}'. Using default: {is_enabled}")

            if not step_name or not is_enabled:
                logger.debug(f"Skipping step '{step_name}' (not defined or YAML disabled)."); continue

            logger.info(f"--- Running analysis step: {step_name} (Scope: {step_scope}) ---")
            data_source_method_name = step_cfg.get("data_source_method")
            step_user_prompt_template = self.prompts.get(step_name)
            step_result_package: Optional[Dict[str, Any]] = None
            domain_step_cache_key: Optional[str] = None
            registered_domain_for_cache = url_components.get("domain_parts", {}).get("registered_domain")

            use_internal_domain_step_cache = self.redis_client and step_scope == "domain" and registered_domain_for_cache and data_source_method_name and self.analysis_mode == "full_url"

            if use_internal_domain_step_cache and domain_step_cache_key: # Small fix: domain_step_cache_key might not be set yet
                domain_step_cache_key = f"{DOMAIN_STEP_CACHE_PREFIX}{registered_domain_for_cache}:{step_name}" # Define it here
                try:
                    cached_step_result_bytes = await self.redis_client.get(domain_step_cache_key)
                    if cached_step_result_bytes:
                        step_result_package = json.loads(cached_step_result_bytes.decode('utf-8'))
                        logger.info(f"Internal Domain-Step CACHE HIT for '{step_name}' on domain '{registered_domain_for_cache}'.")
                        if "data" in step_result_package: all_results["steps_data"][step_name] = step_result_package["data"]
                        if "llm" in step_result_package: all_results["steps_llm_assessments"][step_name] = step_result_package["llm"]
                        if step_result_package.get("data", {}).get("error"): all_results["errors_encountered"].append({"step":step_name, "type":"cached_data_error", "message":step_result_package["data"]["error"]})
                        if step_result_package.get("llm", {}).get("error"): all_results["errors_encountered"].append({"step":step_name, "type":"cached_llm_error", "message":step_result_package["llm"]["error"]})
                except Exception as e: logger.warning(f"Redis error GET domain-step cache for '{step_name}': {e}", exc_info=True)

            if step_result_package is None:
                step_data: Optional[Dict[str, Any]] = None; step_llm_assessment: Optional[Dict[str, Any]] = None
                if data_source_method_name:
                    try:
                        method_to_call = getattr(self, data_source_method_name)
                        step_data = await method_to_call(url_info=url_components)
                        all_results["steps_data"][step_name] = step_data
                        if step_data and step_data.get("error"):
                            logger.warning(f"Data gathering for '{step_name}' error: {step_data['error']}")
                            all_results["errors_encountered"].append({"step": step_name, "type": "data_error", "message": step_data['error']})
                    except AttributeError:
                        err_msg=f"Method '{data_source_method_name}' not found for '{step_name}'.";logger.error(err_msg)
                        all_results["errors_encountered"].append({"step":step_name,"type":"config_error","message":err_msg})
                        all_results["steps_data"][step_name]={"error":err_msg}; continue # Skip to next step
                    except Exception as e:
                        err_msg=f"Exception in data gathering for '{step_name}': {type(e).__name__} - {str(e)}";logger.error(err_msg,exc_info=True)
                        all_results["errors_encountered"].append({"step":step_name,"type":"data_exception","message":err_msg})
                        all_results["steps_data"][step_name]={"error":err_msg}; continue # Skip to next step

                if step_user_prompt_template:
                    current_step_data_for_prompt = all_results["steps_data"].get(step_name, {})
                    if current_step_data_for_prompt and not current_step_data_for_prompt.get("error"):
                        try:
                            # Pass current_date_iso to the prompt formatting
                            user_prompt_formatted = step_user_prompt_template.format(
                                data=current_step_data_for_prompt,
                                original_url=url_to_analyze,
                                current_date_iso=current_date_iso # Add current date here
                            )
                            step_llm_assessment = await self._call_llm(step_system_prompt, user_prompt_formatted, step_name)
                            all_results["steps_llm_assessments"][step_name] = step_llm_assessment
                            if step_llm_assessment.get("error"):
                                all_results["errors_encountered"].append({"step": step_name, "type": "llm_error", "message": step_llm_assessment['error']})
                        except KeyError as e:
                            # Check if the error is due to current_date_iso missing (only for ssl_certificate_assessment)
                            if step_name == "ssl_certificate_assessment" and 'current_date_iso' in str(e):
                                err_msg = f"Prompt format error for '{step_name}', 'current_date_iso' key missing or not used in prompt. Data: {list(current_step_data_for_prompt.keys()) if current_step_data_for_prompt else 'None'}"
                            else:
                                err_msg=f"Prompt format error for '{step_name}', key: {e}. Data: {list(current_step_data_for_prompt.keys()) if current_step_data_for_prompt else 'None'}"
                            logger.error(err_msg)
                            all_results["errors_encountered"].append({"step":step_name,"type":"prompt_format_error","message":err_msg})
                            all_results["steps_llm_assessments"][step_name]={"error":err_msg}
                        except Exception as e:
                            err_msg=f"Exception during LLM call for '{step_name}': {type(e).__name__} - {str(e)}";logger.error(err_msg,exc_info=True)
                            all_results["errors_encountered"].append({"step":step_name,"type":"llm_exception","message":err_msg})
                            all_results["steps_llm_assessments"][step_name]={"error":err_msg}
                    elif current_step_data_for_prompt and current_step_data_for_prompt.get("error"):
                        all_results["steps_llm_assessments"][step_name]={"info":f"Skipped LLM (due to data error in step)", "underlying_error":current_step_data_for_prompt.get("error")}
                    else: # No data or data source method
                        all_results["steps_llm_assessments"][step_name]={"info":"Skipped LLM (no data gathered or data source method)"}
                else: # No prompt file configured for this step
                    logger.info(f"Step '{step_name}' is data-gathering only (no LLM prompt configured).")


                if use_internal_domain_step_cache and domain_step_cache_key: # domain_step_cache_key should be defined if this block is reached
                    data_to_cache_for_step = {"data": all_results["steps_data"].get(step_name,{}), "llm": all_results["steps_llm_assessments"].get(step_name,{})}
                    try:
                        await self.redis_client.setex(domain_step_cache_key, DOMAIN_STEP_CACHE_EXPIRY_SECONDS, json.dumps(data_to_cache_for_step,default=str).encode('utf-8'))
                        logger.info(f"Internal Domain-Step result CACHED for '{step_name}' on domain '{registered_domain_for_cache}'.")
                    except Exception as e: logger.warning(f"Redis error SET domain-step cache for '{step_name}': {e}", exc_info=True)

        final_decider_prompt_template = self.prompts.get("final_decider_assessment")
        if final_decider_prompt_template:
            summary_parts = []
            # Ensure reachability_check data is included if available
            if "reachability_check" in all_results["steps_data"]:
                rc_data = all_results["steps_data"]["reachability_check"]
                summary_parts.append(f"Reachability Check: Reachable={rc_data.get('reachable')}, Status={rc_data.get('status_code')}, Final URL='{rc_data.get('final_url')}', Error='{rc_data.get('error', 'None')}'")

            for step_name_iter, assessment in all_results["steps_llm_assessments"].items():
                if assessment and not assessment.get("error") and "info" not in assessment : # Valid LLM assessment
                    summary_parts.append(f"- Step '{step_name_iter}': Scam='{assessment.get('scam', 'N/A')}', Confidence='{assessment.get('confidence', 'N/A')}', Reason='{assessment.get('reason', 'N/A')}'")
                elif assessment and assessment.get("error"):
                    summary_parts.append(f"- Step '{step_name_iter}': LLM Error='{assessment.get('error')}'")
                elif assessment and assessment.get("info"): # Info messages like "skipped"
                     summary_parts.append(f"- Step '{step_name_iter}': Info='{assessment.get('info')}'" + (f" (Details: {assessment.get('underlying_error')})" if assessment.get('underlying_error') else ""))
                elif step_name_iter in all_results["steps_data"] and all_results["steps_data"][step_name_iter].get("error"):
                    summary_parts.append(f"- Step '{step_name_iter}': Data Error='{all_results['steps_data'][step_name_iter].get('error')}'")
                else: # Data gathering only step or other unhandled cases
                    summary_parts.append(f"- Step '{step_name_iter}': No LLM assessment result or N/A.")

            final_user_prompt = final_decider_prompt_template.format(
                original_url=url_to_analyze,
                individual_assessments_summary_str="\n".join(summary_parts),
                current_date_iso=current_date_iso # Also pass current date to final decider if needed by its prompt
            )
            # Use default system prompt if final decider doesn't have a specific one in config
            final_system_prompt_key = self.config.get("final_assessment_llm",{}).get("system_prompt_file") # This might be just a filename
            final_system_prompt = self.prompts.get("final_decider_assessment_system") # Assuming you might add a specific one
            if not final_system_prompt and final_system_prompt_key : # if key exists but content not loaded under "final_decider_assessment_system"
                 final_system_prompt = self._load_prompt_content("final_decider_assessment_system", self._resolve_config_path(final_system_prompt_key, DEFAULT_PROMPTS_DIR))
            if not final_system_prompt : final_system_prompt = step_system_prompt # Fallback to default step system prompt

            logger.info("--- Calling Final Decider LLM ---")
            final_assessment = await self._call_llm(final_system_prompt, final_user_prompt, "final_decider_assessment")
            all_results["final_llm_assessment"] = final_assessment

            if final_assessment and not final_assessment.get("error"):
                all_results["assessment_summary"]["overall_is_scam"] = str(final_assessment.get("overall_is_scam", "UNKNOWN")).upper()
                all_results["assessment_summary"]["overall_confidence"] = str(final_assessment.get("overall_confidence", "NONE")).upper()
                all_results["assessment_summary"]["overall_reason"] = str(final_assessment.get("overall_reason", "Final LLM provided no specific reason."))
            else:
                err_msg = final_assessment.get("error", "Unknown error from Final Decider LLM")
                all_results["assessment_summary"]["overall_is_scam"] = "ERROR"
                all_results["assessment_summary"]["overall_confidence"] = "NONE"
                all_results["assessment_summary"]["overall_reason"] = f"Final LLM assessment failed: {err_msg}"
                all_results["errors_encountered"].append({"step":"final_decider_llm","type":"llm_error","message":err_msg})
        else:
            logger.error("Final decider LLM prompt template not loaded! Cannot perform final assessment.")
            all_results["assessment_summary"]["overall_is_scam"] = "ERROR"
            all_results["assessment_summary"]["overall_confidence"] = "NONE"
            all_results["assessment_summary"]["overall_reason"] = "Final decider LLM prompt not configured."
            all_results["errors_encountered"].append({"step":"final_decider_llm","type":"config_error","message":"Final decider prompt template missing"})


        all_results["analysis_duration_seconds"] = round(time.monotonic() - start_time_mono, 2)
        all_results["analysis_end_time_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        logger.info(f"Holistic assessment for '{url_to_analyze}' completed in {all_results['analysis_duration_seconds']:.2f}s. Verdict: Scam='{all_results['assessment_summary']['overall_is_scam']}', Conf='{all_results['assessment_summary']['overall_confidence']}'")
        return all_results

    async def generate_full_analysis_report_for_attachment(self, assessment_result: Dict[str, Any]) -> Optional[str]:
        final_summary = assessment_result.get("assessment_summary", {})
        original_url = assessment_result.get("original_url", "N/A")

        # Only generate if AI deemed it a scam
        if final_summary.get("overall_is_scam") != "YES":
            logger.info(f"URL '{original_url}' not deemed scam by AI. No detailed attachment report will be generated.")
            return None

        logger.info(f"Generating full analysis report for attachment for '{original_url}' (AI deemed scam).")
        report_data = {
            "original_url": original_url,
            "analysis_metadata": {
                "analysis_start_time_utc": assessment_result.get("analysis_start_time_utc"),
                "analysis_end_time_utc": assessment_result.get("analysis_end_time_utc"),
                "total_duration_seconds": assessment_result.get("analysis_duration_seconds"),
                "analysis_mode": self.analysis_mode # Add analysis mode to report
            },
            "url_components": assessment_result.get("url_components"),
            "final_assessment_summary": final_summary,
            "detailed_step_results": {}, # Initialize as dict
            "errors_encountered_during_assessment": assessment_result.get("errors_encountered", [])
        }

        # Populate detailed_step_results
        for step_name_key, data_val in assessment_result.get("steps_data", {}).items():
            if step_name_key not in report_data["detailed_step_results"]:
                 report_data["detailed_step_results"][step_name_key] = {}
            report_data["detailed_step_results"][step_name_key]["gathered_data"] = data_val

        for step_name_key, llm_val in assessment_result.get("steps_llm_assessments", {}).items():
            if step_name_key not in report_data["detailed_step_results"]:
                 report_data["detailed_step_results"][step_name_key] = {}
            report_data["detailed_step_results"][step_name_key]["llm_assessment"] = llm_val
            
        # Conditional Playwright data inclusion for the report if configured
        if self.playwright_enable_for_final_report:
            playwright_step_config = next((s_cfg for s_cfg in self.config.get("analysis_steps", []) if s_cfg.get("data_source_method") == "extract_page_elements"), None)
            playwright_step_name = playwright_step_config.get("step_name") if playwright_step_config else "page_content_assessment" # Default name if not found

            needs_playwright_run_for_report = True
            # Check if Playwright data already exists and is not errored from pipeline run
            if playwright_step_name in report_data["detailed_step_results"]:
                pw_data_from_pipeline = report_data["detailed_step_results"][playwright_step_name].get("gathered_data", {})
                if pw_data_from_pipeline and not pw_data_from_pipeline.get("error"):
                    needs_playwright_run_for_report = False
                    logger.info(f"Using existing Playwright data from pipeline for final report of '{original_url}'.")


            if needs_playwright_run_for_report:
                logger.info(f"Fetching Playwright data specifically for final report of '{original_url}'.")
                try:
                    # Use the original url_components passed to the main assessment
                    url_info_for_playwright = assessment_result.get("url_components", self._parse_url_components(original_url))
                    playwright_data_for_report = await self.extract_page_elements(url_info=url_info_for_playwright)

                    if playwright_step_name not in report_data["detailed_step_results"]:
                        report_data["detailed_step_results"][playwright_step_name] = {}
                    # Store it distinctly if it was run specifically for the report
                    report_data["detailed_step_results"][playwright_step_name]["gathered_data_for_report"] = playwright_data_for_report
                    if playwright_data_for_report.get("error"):
                        logger.warning(f"Error fetching Playwright data for final report: {playwright_data_for_report.get('error')}")
                except Exception as e_pw_report:
                    logger.error(f"Exception fetching Playwright data for final report of '{original_url}': {e_pw_report}", exc_info=True)
                    # Ensure the key exists before assigning error
                    if playwright_step_name not in report_data["detailed_step_results"]:
                        report_data["detailed_step_results"][playwright_step_name] = {}
                    report_data["detailed_step_results"][playwright_step_name]["gathered_data_for_report"] = {"error": f"Failed to fetch Playwright data for report: {str(e_pw_report)}"}
        try:
            return json.dumps(report_data, indent=2, default=str)
        except Exception as e_json:
            logger.error(f"Failed to serialize final report for '{original_url}': {e_json}", exc_info=True)
            # Fallback error JSON
            return json.dumps({"error": "Failed to serialize report", "details": str(e_json)}, indent=2)

async def main_test_analyzer():
    # Determine project root dynamically for .env loading
    # Assuming this script is in urlanalysis directory, .env is in parent.
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dotenv_path = os.path.join(project_root, '.env')

    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path=dotenv_path)
        logger.info(f"Successfully loaded .env file from: {dotenv_path}")
    else:
        logger.warning(f".env file not found at {dotenv_path}. LLM/Redis functionalities might be affected.")

    # Basic logging configuration for testing
    logging.basicConfig(
        level=logging.DEBUG, # Set to INFO for less verbose output
        format='%(asctime)s - %(levelname)s - [%(name)s:%(filename)s:%(lineno)d] - %(message)s',
        handlers=[logging.StreamHandler()] # Log to console
    )
    # Example: Set specific log levels for noisy libraries if needed
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('playwright').setLevel(logging.INFO)


    # Initialize analyzer (Redis client can be None for this test if not testing caching)
    analyzer = AsyncURLAnalyzer(redis_client=None)

    urls_to_test = [
        "http://google.com",
        "https://example.com",
        "http://testphp.vulnweb.com/", # A known vulnerable test site
        "https://thisdomainshouldnotexist-ajkdhflakjsdhf.com" # Non-existent
    ]

    output_dir = os.path.join(project_root, "test_holistic_analysis_results")
    os.makedirs(output_dir, exist_ok=True)

    try:
        for i, url in enumerate(urls_to_test):
            logger.info(f"\n--- Testing URL ({i+1}/{len(urls_to_test)}): {url} ---")
            assessment_result = await analyzer.get_holistic_url_assessment(url)

            # Sanitize URL for filename
            parsed_url_for_fn = urlparse(url)
            filename_base = re.sub(r'[^a-zA-Z0-9_-]', '_', parsed_url_for_fn.netloc or f"url_index_{i}")
            if not filename_base: filename_base = f"url_index_{i}_invalid_netloc" # Fallback if netloc is empty

            filepath_assessment = os.path.join(output_dir, f"{filename_base}_holistic_assessment.json")
            try:
                with open(filepath_assessment, 'w', encoding='utf-8') as f:
                    json.dump(assessment_result, f, indent=2, default=str)
                logger.info(f"Saved holistic assessment to: {filepath_assessment}")
            except IOError as e_io:
                logger.error(f"Failed to save assessment JSON for {url}: {e_io}")


            # Generate and save attachment report if AI deemed it a scam
            if assessment_result.get("assessment_summary", {}).get("overall_is_scam") == "YES":
                logger.info(f"URL '{url}' deemed scam by AI. Generating attachment report.")
                attachment_json_str = await analyzer.generate_full_analysis_report_for_attachment(assessment_result)
                if attachment_json_str:
                    filepath_attachment = os.path.join(output_dir, f"{filename_base}_attachment_report.json")
                    try:
                        with open(filepath_attachment, 'w', encoding='utf-8') as f:
                            f.write(attachment_json_str)
                        logger.info(f"Saved attachment report to: {filepath_attachment}")
                    except IOError as e_io_attach:
                         logger.error(f"Failed to save attachment report JSON for {url}: {e_io_attach}")
                else:
                    logger.warning(f"Attachment report generation returned None for scam-flagged URL: {url}")

    finally:
        await analyzer.close_sessions()
        logger.info("Analyzer sessions closed.")

if __name__ == "__main__":
    # Ensure asyncio event loop policy is set for Windows if running directly
    if os.name == 'nt': # Check for Windows
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main_test_analyzer())