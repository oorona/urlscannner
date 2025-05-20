#!/usr/bin/env python3
import asyncio
import json
import ssl
import socket
from urllib.parse import urlparse, ParseResult, urljoin
import ipaddress
import datetime
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

    # _load_pipeline_config, _resolve_config_path, _load_prompt_content, _load_all_prompts (same)
    # _get_aiohttp_session, _get_httpx_client, close_sessions (same)
    # _parse_url_components, _extract_domain_parts (same)
    # _call_llm (same)
    # Data Gathering Methods (_get_raw_url_for_llm, check_url_reachability, check_dns_records, etc. same)
    # Ensure check_ssl_certificate is the robust version
    # ... (All helper and data gathering methods from previous correct versions) ...
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
            connector = aiohttp.TCPConnector(ssl=False)
            self._aiohttp_session = aiohttp.ClientSession(headers=headers, connector=connector)
        return self._aiohttp_session

    async def _get_httpx_client(self) -> httpx.AsyncClient:
        if self._httpx_client is None or self._httpx_client.is_closed:
            self._httpx_client = httpx.AsyncClient(timeout=120.0)
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
        if '://' not in url:
            if not re.match(r"^[a-zA-Z0-9.-]+/", url) and '.' in url: url = 'https://' + url
            else: url = 'https://' + url
        components = {"original_url": original_url, "parsed_obj": None, "scheme": "https", "netloc": "", "port": 443, "domain_parts": {}, "error": None}
        try:
            parsed: Optional[ParseResult] = urlparse(url)
            components["parsed_obj"] = parsed
            if not parsed or not parsed.netloc:
                components["error"] = f"Could not parse network location from URL: {original_url}"; return components
            components["scheme"] = parsed.scheme.lower() if parsed.scheme else "https"
            components["netloc"] = parsed.netloc.lower()
            port_val = parsed.port
            if not port_val: port_val = 443 if components["scheme"] == 'https' else 80
            components["port"] = port_val
            components["domain_parts"] = self._extract_domain_parts(components["netloc"])
            return components
        except Exception as e:
            logger.warning(f"URL parsing failed for '{original_url}': {e}")
            components["error"] = f"URL parsing failed: {e}"; return components

    def _extract_domain_parts(self, netloc: str) -> Dict[str, Optional[str]]:
        try:
            ext = tldextract.extract(netloc)
            registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None
            return {"full_host": netloc, "subdomain": ext.subdomain or None,
                    "domain_name": ext.domain or None, "tld": ext.suffix or None,
                    "registered_domain": registered_domain}
        except Exception:
            parts = netloc.split('.')
            if len(parts) >= 2:
                return {"full_host": netloc, "subdomain": ".".join(parts[:-2]) or None,
                        "domain_name": parts[-2], "tld": parts[-1], "registered_domain": f"{parts[-2]}.{parts[-1]}"}
            return {"full_host": netloc, "subdomain": None, "domain_name": netloc if '.' not in netloc else None,
                    "tld": None, "registered_domain": netloc if '.' in netloc else None}

    async def _call_llm(self, system_prompt: str, user_prompt: str, step_name_for_log: str) -> Dict[str, Any]:
        if not self.llm_api_token or not self.llm_api_url:
            msg = "LLM not configured (token or URL missing)."
            logger.error(f"Analyzer LLM Call for {step_name_for_log}: {msg}"); return {"error": msg}
        if not system_prompt:
            msg = "System prompt is empty."
            logger.error(f"Analyzer LLM Call for {step_name_for_log}: {msg}"); return {"error": msg}
        client = await self._get_httpx_client()
        payload = {"model": self.llm_model_name,
                   "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                   "temperature": self.llm_default_temp, "response_format": {"type": "json_object"}}
        headers = {"Authorization": f"Bearer {self.llm_api_token}", "Content-Type": "application/json"}
        logger.debug(f"Analyzer LLM Call for '{step_name_for_log}': Model='{self.llm_model_name}'. User prompt (first 100): {user_prompt[:100]}...")
        try:
            response = await client.post(self.llm_api_url, headers=headers, json=payload)
            response.raise_for_status()
            response_json = response.json()
            llm_content_str = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
            if not llm_content_str:
                logger.error(f"Analyzer LLM Call for {step_name_for_log}: LLM response content empty.")
                return {"error": "LLM response empty", "raw_response_json": response_json}
            logger.debug(f"Analyzer LLM Call for {step_name_for_log}: Raw LLM content: {llm_content_str}")
            parsed_llm_response = json.loads(llm_content_str)
            required_keys = ["scam", "confidence", "reason"] if "final_decider" not in step_name_for_log else ["overall_is_scam", "overall_confidence", "overall_reason"]
            if not all(k in parsed_llm_response for k in required_keys):
                logger.error(f"Analyzer LLM Call for {step_name_for_log}: LLM JSON missing keys ({required_keys}). Got: {parsed_llm_response}")
                return {"error": "LLM JSON response missing required keys", "raw_response": parsed_llm_response}
            logger.info(f"Analyzer LLM Call for {step_name_for_log}: Assessment successful. Response: {parsed_llm_response}")
            return parsed_llm_response
        except httpx.HTTPStatusError as e: err_text = e.response.text[:500]; logger.error(f"Analyzer LLM Call for {step_name_for_log}: HTTP Status {e.response.status_code} - {err_text}"); return {"error": f"LLM HTTP Status Error: {e.response.status_code}", "details": err_text}
        except httpx.RequestError as e: logger.error(f"Analyzer LLM Call for {step_name_for_log}: Connection error: {e}"); return {"error": f"LLM Request Connection Error: {type(e).__name__}"}
        except json.JSONDecodeError: logger.error(f"Analyzer LLM Call for {step_name_for_log}: Failed to parse LLM JSON: '{llm_content_str}'"); return {"error": "LLM response not valid JSON", "raw_content": llm_content_str}
        except Exception as e: logger.error(f"Analyzer LLM Call for {step_name_for_log}: Unexpected error: {e}", exc_info=True); return {"error": f"Unexpected error in LLM call: {type(e).__name__}"}

    async def _get_raw_url_for_llm(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        return {"url_string": url_info.get("original_url")}

    async def check_url_reachability(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        url = url_info.get("original_url")
        result: Dict[str, Any] = {"url": url, "reachable": False, "status_code": None, "final_url": url, "error": None, "headers": {}}
        session = await self._get_aiohttp_session()
        try:
            async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=self.playwright_timeout // 2)) as response:
                result["reachable"] = True; result["status_code"] = response.status; result["final_url"] = str(response.url); result["headers"] = dict(response.headers)
        except aiohttp.ClientConnectorCertificateError as e: result["error"] = f"SSL Certificate Error: {e.os_error}"
        except aiohttp.ClientConnectorError as e: result["error"] = f"Connection Error: {e.os_error}"
        except asyncio.TimeoutError: result["error"] = f"Request timed out."
        except aiohttp.ClientError as e: result["error"] = f"HTTP Client Error: {type(e).__name__}"
        except Exception as e: result["error"] = f"Unexpected reachability error: {type(e).__name__}"
        logger.debug(f"Reachability for '{url}': Reachable={result['reachable']}, Status={result['status_code']}, Error={result['error']}")
        return result

    async def check_dns_records(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        domain = url_info.get("domain_parts", {}).get("registered_domain") or url_info.get("netloc")
        if not domain: return {"error": "Domain/Netloc for DNS check missing", "domain": domain, "records_json_str":"{}"}
        result: Dict[str, Any] = {"domain": domain, "records": {}, "error": None}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        async def query(record_type):
            try:
                answers = await self._dns_resolver.resolve(domain, record_type)
                if record_type in ["A", "AAAA"]: return [a.to_text() for a in answers]
                elif record_type == "MX": return sorted([f"{a.preference} {a.exchange.to_text()}" for a in answers])
                elif record_type in ["NS", "CNAME"]: return [a.target.to_text() for a in answers]
                elif record_type == "TXT": return [" ".join(t.decode('utf-8','ignore')) for t in a.strings]
            except dns.resolver.NoAnswer: return []
            except dns.resolver.NXDOMAIN: raise dns.resolver.NXDOMAIN
            except dns.exception.Timeout: return ["[TIMEOUT]"]
            except Exception as e: return [f"[ERROR_QUERYING_DNS_{record_type.upper()}: {type(e).__name__}]"]
            return []
        try:
            for rtype in record_types:
                records_data = await query(rtype)
                if records_data: result["records"][rtype] = records_data
        except dns.resolver.NXDOMAIN: result["error"] = "NXDOMAIN: Domain does not exist."
        except Exception as e: result["error"] = f"Unexpected DNS error: {type(e).__name__}"
        result["records_json_str"] = json.dumps(result["records"], default=str)
        logger.debug(f"DNS for '{domain}': Found keys {list(result['records'].keys())}, Error={result['error']}")
        return result
    
    async def check_whois_information(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        domain = url_info.get("domain_parts", {}).get("registered_domain")
        if not domain: return {"error": "Registered domain for WHOIS check missing", "domain": domain, "parsed_json_str":"{}", "analysis_flags":[]}
        result: Dict[str, Any] = {"domain": domain, "parsed": None, "error": None, "analysis_flags": []}
        def sync_whois(d):
            try: return whois.whois(d)
            except Exception as e: return f"Error: {type(e).__name__}"
        loop = asyncio.get_running_loop()
        try:
            whois_data = await loop.run_in_executor(None, sync_whois, domain)
            if isinstance(whois_data, str) and "Error" in whois_data: result["error"] = whois_data
            elif whois_data and (whois_data.get('domain_name') or whois_data.get('emails')):
                parsed_data = {}
                for k, v_item in whois_data.items():
                    if isinstance(v_item, list) and v_item and isinstance(v_item[0], datetime.datetime):
                        parsed_data[k] = sorted([item.isoformat() for item in v_item])
                    elif isinstance(v_item, datetime.datetime): parsed_data[k] = v_item.isoformat()
                    elif k != 'text': parsed_data[k] = v_item
                result["parsed"] = parsed_data
                if not parsed_data.get("registrar") and not parsed_data.get("creation_date"): result["analysis_flags"].append("WHOIS_DATA_LIMITED_OR_PROTECTED")
            else: result["error"] = "WHOIS data not found or incomplete."
        except Exception as e: result["error"] = f"Failed WHOIS execution: {type(e).__name__}"
        result["parsed_json_str"] = json.dumps(result.get("parsed"), default=str)
        logger.debug(f"WHOIS for '{domain}': Parsed keys {list(result['parsed'].keys()) if result['parsed'] else 'None'}, Error={result['error']}")
        return result

    async def check_ssl_certificate(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        hostname = url_info.get("netloc")
        port = url_info.get("port", 443)
        original_url_scheme = url_info.get("scheme", "https")
        result: Dict[str, Any] = {"hostname": hostname, "port": port, "details": {"hostname_match": False}, "error": None, "details_json_str": "{}"}
        if not hostname: result["error"] = "Hostname for SSL check missing"; return result
        if original_url_scheme != "https":
            logger.info(f"Skipping SSL check for non-HTTPS scheme ('{original_url_scheme}') on URL: {url_info.get('original_url')}")
            result["error"] = f"Skipped SSL check for non-HTTPS scheme: {original_url_scheme}"; return result
        context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
        sock = None; conn = None
        try:
            sock = socket.create_connection((hostname, port), timeout=5)
            conn = context.wrap_socket(sock, server_hostname=hostname)
            der_cert = conn.getpeercert(binary_form=True)
            if not der_cert: result["error"] = "Could not retrieve certificate"; result["details_json_str"] = json.dumps(result["details"], default=str); return result
            x509 = PyOpenSSL_crypto.load_certificate(PyOpenSSL_crypto.FILETYPE_ASN1, der_cert)
            details: Dict[str, Any] = {"hostname_match": False}
            details["subject"] = dict((k.decode('utf-8', 'ignore'), v.decode('utf-8', 'ignore')) for k, v in x509.get_subject().get_components())
            details["issuer"] = dict((k.decode('utf-8', 'ignore'), v.decode('utf-8', 'ignore')) for k, v in x509.get_issuer().get_components())
            details["common_name"] = details["subject"].get("CN")
            if x509.get_notBefore(): details["valid_from"] = datetime.datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ').isoformat() + "Z"
            if x509.get_notAfter(): details["valid_until"] = datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').isoformat() + "Z"
            cert_hostnames_from_cert: Set[str] = set(); 
            if details["common_name"]: cert_hostnames_from_cert.add(details["common_name"])
            sans_str_list = []
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                short_name = ext.get_short_name().decode('utf-8', 'ignore')
                if short_name == 'subjectAltName': sans_str_list.extend(s.strip() for s in str(ext).split(',')); break
            details["subject_alt_names_raw"] = sans_str_list
            for san_entry in sans_str_list:
                if san_entry.lower().startswith("dns:"): cert_hostnames_from_cert.add(san_entry[4:])
            hostname_lower = hostname.lower(); ext_hostname_to_check = self._extract_domain_parts(hostname_lower); match_found = False
            if ext_hostname_to_check.get("registered_domain"):
                for cert_name_raw in cert_hostnames_from_cert:
                    cert_name_lower = cert_name_raw.lower()
                    if cert_name_lower == hostname_lower: match_found = True; break
                    if cert_name_lower.startswith("*."):
                        wildcard_base = cert_name_lower[2:]
                        ext_cert_name_base = self._extract_domain_parts(wildcard_base)
                        if ext_hostname_to_check.get("registered_domain") == ext_cert_name_base.get("registered_domain") and \
                           ext_cert_name_base.get("registered_domain"): # Ensure base is not empty
                            if hostname_lower.endswith("." + ext_cert_name_base.get("registered_domain")):
                                prefix = hostname_lower[:-(len(ext_cert_name_base.get("registered_domain")) + 1)]
                                if prefix and '.' not in prefix: match_found = True; break
            details["hostname_match"] = match_found
            result["details"] = details; result["details_json_str"] = json.dumps(details, default=str) if details else "{}"
        except socket.gaierror: result["error"] = f"Could not resolve hostname: {hostname}"
        except socket.timeout: result["error"] = "Connection timed out during SSL check."
        except ConnectionRefusedError: result["error"] = "Connection refused during SSL check."
        except ssl.SSLError as e: result["error"] = f"SSL Error: {getattr(e, 'reason', str(e))}"
        except PyOpenSSL_crypto.Error as e: result["error"] = f"pyOpenSSL Certificate Parsing Error: {str(e)}"
        except Exception as e: result["error"] = f"Unexpected SSL check error: {type(e).__name__} - {str(e)}"; logger.warning(f"SSL Exc: {e}", exc_info=True)
        finally:
            if conn: 
                try: conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                conn.close()
            if sock: sock.close()
        logger.debug(f"SSL for '{hostname}': CN='{result['details'].get('common_name')}', Match={result['details'].get('hostname_match')}, Error={result['error']}")
        return result

    async def extract_page_elements(self, url_info: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        original_url = url_info.get("original_url")
        if not original_url: return {"error": "Original URL for Playwright missing", "url": original_url}
        result = {"url": original_url, "final_url": original_url, "title": None, "meta": {}, "links_count":0, "scripts_count":0, "forms_count":0, "text_preview_200": None, "error": None, "meta_description": None}
        pw_instance = None; browser = None
        try:
            pw_instance = await async_playwright().start()
            browser = await pw_instance.chromium.launch(headless=True)
            context = await browser.new_context(user_agent=self.user_agent, ignore_https_errors=True)
            page = await context.new_page()
            await page.goto(original_url, wait_until='domcontentloaded', timeout=self.playwright_timeout * 1000)
            result["final_url"] = page.url; result["title"] = await page.title()
            meta_elements = await page.locator('meta').all()
            for meta_el in meta_elements:
                name = await meta_el.get_attribute('name'); prop = await meta_el.get_attribute('property'); content = await meta_el.get_attribute('content')
                key = name or prop
                if key and content: result["meta"][key.lower()] = content
            result["meta_description"] = result["meta"].get("description") or result["meta"].get("og:description")
            result["forms_count"] = await page.locator('form').count()
            result["scripts_count"] = await page.locator('script[src]').count()
            result["links_count"] = await page.locator('a[href]').count()
            body_text_full = await page.locator('body').inner_text(timeout=5000)
            result["text_preview_200"] = ' '.join(body_text_full.split()).strip()[:200] + ('...' if len(body_text_full) > 200 else '')
            await context.close()
        except PlaywrightTimeoutError: result["error"] = "Playwright: Page load timed out."
        except PlaywrightError as e: result["error"] = f"Playwright: Navigation/extraction error - {type(e).__name__}"
        except Exception as e: result["error"] = f"Playwright: Unexpected error - {type(e).__name__}"
        finally:
            if browser and browser.is_connected(): await browser.close()
            if pw_instance: await pw_instance.stop()
        logger.debug(f"Playwright for '{original_url}': Title='{result['title']}', Error={result['error']}")
        return result

    async def get_holistic_url_assessment(self, url_to_analyze: str) -> Dict[str, Any]:
        start_time_mono = time.monotonic()
        logger.info(f"Starting holistic assessment for URL: {url_to_analyze} (Mode: {self.analysis_mode})")

        url_components = self._parse_url_components(url_to_analyze)
        if url_components.get("error"):
            return {"original_url": url_to_analyze, "error": url_components["error"], 
                    "assessment_summary": {"overall_is_scam": "ERROR", "overall_confidence": "NONE", "overall_reason": url_components["error"]}}

        all_results: Dict[str, Any] = {
            "original_url": url_to_analyze,
            "analysis_start_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "url_components": url_components, "steps_data": {}, "steps_llm_assessments": {}, 
            "errors_encountered": [], "final_llm_assessment": None,
            "assessment_summary": {"overall_is_scam": "UNKNOWN", "overall_confidence": "NONE", "overall_reason": "Assessment pending."}
        }
        step_system_prompt = self.prompts.get("default_step_system", "You are a helpful AI.")

        for step_cfg in self.config.get("analysis_steps", []):
            step_name = step_cfg.get("step_name")
            step_scope = step_cfg.get("scope", "url")
            
            # Determine if step should run based on ANALYSIS_MODE
            execution_modes = step_cfg.get("execution_modes", ["domain", "full_url"]) # Default to run in both modes
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

            # Use domain-step cache only in "full_url" mode, because in "domain" mode, the cog handles caching the final domain assessment.
            use_internal_domain_step_cache = self.redis_client and step_scope == "domain" and registered_domain_for_cache and data_source_method_name and self.analysis_mode == "full_url"

            if use_internal_domain_step_cache:
                domain_step_cache_key = f"{DOMAIN_STEP_CACHE_PREFIX}{registered_domain_for_cache}:{step_name}"
                try:
                    cached_step_result_bytes = await self.redis_client.get(domain_step_cache_key)
                    if cached_step_result_bytes:
                        step_result_package = json.loads(cached_step_result_bytes.decode('utf-8'))
                        logger.info(f"Internal Domain-Step CACHE HIT for '{step_name}' on domain '{registered_domain_for_cache}'.")
                        if "data" in step_result_package: all_results["steps_data"][step_name] = step_result_package["data"]
                        if "llm" in step_result_package: all_results["steps_llm_assessments"][step_name] = step_result_package["llm"]
                        # Log errors from cache
                        if step_result_package.get("data", {}).get("error"): all_results["errors_encountered"].append({"step":step_name, "type":"cached_data_error", "message":step_result_package["data"]["error"]})
                        if step_result_package.get("llm", {}).get("error"): all_results["errors_encountered"].append({"step":step_name, "type":"cached_llm_error", "message":step_result_package["llm"]["error"]})
                except Exception as e: logger.warning(f"Redis error GET domain-step cache for '{step_name}': {e}", exc_info=True)
            
            if step_result_package is None: # Cache miss or not applicable for internal cache
                step_data: Optional[Dict[str, Any]] = None; step_llm_assessment: Optional[Dict[str, Any]] = None
                if data_source_method_name:
                    try:
                        method_to_call = getattr(self, data_source_method_name)
                        step_data = await method_to_call(url_info=url_components)
                        all_results["steps_data"][step_name] = step_data
                        if step_data and step_data.get("error"): logger.warning(f"Data gathering for '{step_name}' error: {step_data['error']}"); all_results["errors_encountered"].append({"step": step_name, "type": "data_error", "message": step_data['error']})
                    # ... (rest of data gathering error handling) ...
                    except AttributeError: err_msg=f"Method '{data_source_method_name}' not found for '{step_name}'.";logger.error(err_msg);all_results["errors_encountered"].append({"step":step_name,"type":"config_error","message":err_msg});all_results["steps_data"][step_name]={"error":err_msg};continue
                    except Exception as e: err_msg=f"Exc in data gathering for '{step_name}': {type(e).__name__}";logger.error(err_msg,exc_info=True);all_results["errors_encountered"].append({"step":step_name,"type":"data_exception","message":err_msg});all_results["steps_data"][step_name]={"error":err_msg};continue
                
                if step_user_prompt_template:
                    current_step_data_for_prompt = all_results["steps_data"].get(step_name, {})
                    if current_step_data_for_prompt and not current_step_data_for_prompt.get("error"):
                        try:
                            user_prompt_formatted = step_user_prompt_template.format(data=current_step_data_for_prompt, original_url=url_to_analyze)
                            step_llm_assessment = await self._call_llm(step_system_prompt, user_prompt_formatted, step_name)
                            all_results["steps_llm_assessments"][step_name] = step_llm_assessment
                            if step_llm_assessment.get("error"): all_results["errors_encountered"].append({"step": step_name, "type": "llm_error", "message": step_llm_assessment['error']})
                        # ... (rest of LLM call error handling) ...
                        except KeyError as e: err_msg=f"Prompt format error for '{step_name}', key: {e}. Data: {list(current_step_data_for_prompt.keys()) if current_step_data_for_prompt else 'None'}";logger.error(err_msg);all_results["errors_encountered"].append({"step":step_name,"type":"prompt_format_error","message":err_msg});all_results["steps_llm_assessments"][step_name]={"error":err_msg}
                        except Exception as e: err_msg=f"Exc during LLM for '{step_name}': {type(e).__name__}";logger.error(err_msg,exc_info=True);all_results["errors_encountered"].append({"step":step_name,"type":"llm_exception","message":err_msg});all_results["steps_llm_assessments"][step_name]={"error":err_msg}
                    elif current_step_data_for_prompt and current_step_data_for_prompt.get("error"): all_results["steps_llm_assessments"][step_name]={"info":"Skipped (data error)", "underlying_error":current_step_data_for_prompt.get("error")}
                    else: all_results["steps_llm_assessments"][step_name]={"info":"Skipped (no data)"}
                else: logger.info(f"Step '{step_name}' is data-gathering only.")

                if use_internal_domain_step_cache and domain_step_cache_key:
                    data_to_cache_for_step = {"data": all_results["steps_data"].get(step_name,{}), "llm": all_results["steps_llm_assessments"].get(step_name,{})}
                    try:
                        await self.redis_client.setex(domain_step_cache_key, DOMAIN_STEP_CACHE_EXPIRY_SECONDS, json.dumps(data_to_cache_for_step,default=str).encode('utf-8'))
                        logger.info(f"Internal Domain-Step result CACHED for '{step_name}' on domain '{registered_domain_for_cache}'.")
                    except Exception as e: logger.warning(f"Redis error SET domain-step cache for '{step_name}': {e}", exc_info=True)

        # Final Decider LLM Call (same as before)
        # ... (same logic for preparing summary_parts and calling final decider LLM) ...
        final_decider_prompt_template = self.prompts.get("final_decider_assessment")
        if final_decider_prompt_template:
            summary_parts = []
            if "reachability_check" in all_results["steps_data"]: # Ensure reachability data is included in summary
                rc_data = all_results["steps_data"]["reachability_check"]
                summary_parts.append(f"Reachability Check: Reachable={rc_data.get('reachable')}, Status={rc_data.get('status_code')}, Final URL='{rc_data.get('final_url')}', Error='{rc_data.get('error', 'None')}'")
            for step_name, assessment in all_results["steps_llm_assessments"].items():
                if assessment and not assessment.get("error"): summary_parts.append(f"- {step_name}: Scam='{assessment.get('scam')}', Confidence='{assessment.get('confidence')}', Reason='{assessment.get('reason')}'")
                elif assessment and assessment.get("error"): summary_parts.append(f"- {step_name}: LLM Error='{assessment.get('error')}'")
                elif step_name in all_results["steps_data"] and all_results["steps_data"][step_name].get("error"): summary_parts.append(f"- {step_name}: Data Error='{all_results['steps_data'][step_name].get('error')}'")
                else: summary_parts.append(f"- {step_name}: No LLM assessment result or N/A.")
            final_user_prompt = final_decider_prompt_template.format(original_url=url_to_analyze, individual_assessments_summary_str="\n".join(summary_parts))
            final_system_prompt = self.prompts.get(self.config.get("final_assessment_llm",{}).get("system_prompt_file"), step_system_prompt)
            logger.info("--- Calling Final Decider LLM ---")
            final_assessment = await self._call_llm(final_system_prompt, final_user_prompt, "final_decider_assessment")
            all_results["final_llm_assessment"] = final_assessment
            if final_assessment and not final_assessment.get("error"):
                all_results["assessment_summary"]["overall_is_scam"] = str(final_assessment.get("overall_is_scam", "UNKNOWN")).upper()
                all_results["assessment_summary"]["overall_confidence"] = str(final_assessment.get("overall_confidence", "NONE")).upper()
                all_results["assessment_summary"]["overall_reason"] = str(final_assessment.get("overall_reason", "Final LLM no specific reason."))
            else: err=final_assessment.get("error","Unknown error");all_results["assessment_summary"]["overall_reason"]=f"Final LLM assessment failed: {err}";all_results["errors_encountered"].append({"step":"final_decider_llm","type":"llm_error","message":err})
        else: logger.error("Final decider LLM prompt not loaded!");all_results["assessment_summary"]["overall_reason"]="Final decider LLM prompt not configured.";all_results["errors_encountered"].append({"step":"final_decider_llm","type":"config_error","message":"Prompt missing"})


        all_results["analysis_duration_seconds"] = round(time.monotonic() - start_time_mono, 2)
        all_results["analysis_end_time_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        logger.info(f"Holistic assessment for '{url_to_analyze}' completed in {all_results['analysis_duration_seconds']:.2f}s. Verdict: Scam='{all_results['assessment_summary']['overall_is_scam']}', Conf='{all_results['assessment_summary']['overall_confidence']}'")
        return all_results

    async def generate_full_analysis_report_for_attachment(self, assessment_result: Dict[str, Any]) -> Optional[str]: # Same as before
        final_summary = assessment_result.get("assessment_summary", {})
        original_url = assessment_result.get("original_url", "N/A")
        if final_summary.get("overall_is_scam") != "YES":
            logger.info(f"URL '{original_url}' not deemed scam. No detailed report for attachment.")
            return None
        logger.info(f"Generating full analysis report for attachment for '{original_url}' (deemed scam).")
        report_data = {
            "original_url": original_url,
            "analysis_metadata": {
                "analysis_start_time_utc": assessment_result.get("analysis_start_time_utc"),
                "analysis_end_time_utc": assessment_result.get("analysis_end_time_utc"),
                "total_duration_seconds": assessment_result.get("analysis_duration_seconds"),
            },
            "url_components": assessment_result.get("url_components"),
            "final_assessment_summary": final_summary,
            "detailed_step_results": {},
            "errors_encountered_during_assessment": assessment_result.get("errors_encountered", [])
        }
        for step_name, data in assessment_result.get("steps_data", {}).items():
            report_data["detailed_step_results"][step_name] = {"gathered_data": data}
            if step_name in assessment_result.get("steps_llm_assessments", {}):
                report_data["detailed_step_results"][step_name]["llm_assessment"] = assessment_result["steps_llm_assessments"][step_name]
        if self.playwright_enable_for_final_report:
            playwright_step_config = next((s for s in self.config.get("analysis_steps", []) if s.get("data_source_method") == "extract_page_elements"), None)
            playwright_step_name = playwright_step_config.get("step_name") if playwright_step_config else "playwright_report_data"
            needs_playwright_run = True
            if playwright_step_name in report_data["detailed_step_results"]:
                pw_data = report_data["detailed_step_results"][playwright_step_name].get("gathered_data", {}) # Check if it was run as part of pipeline
                if not pw_data: # If not in pipeline data, check if it was added for report
                    pw_data = report_data["detailed_step_results"][playwright_step_name].get("gathered_data_for_report", {})
                if pw_data and not pw_data.get("error"): needs_playwright_run = False
            if needs_playwright_run:
                logger.info(f"Fetching/Re-fetching Playwright data for final report of '{original_url}'.")
                try:
                    url_info_for_pw = assessment_result.get("url_components", {"original_url": original_url})
                    playwright_data = await self.extract_page_elements(url_info=url_info_for_pw)
                    if playwright_step_name not in report_data["detailed_step_results"]: report_data["detailed_step_results"][playwright_step_name] = {}
                    report_data["detailed_step_results"][playwright_step_name]["gathered_data_for_report"] = playwright_data # Store under a distinct key
                    if playwright_data.get("error"): logger.warning(f"Error Playwright for final report: {playwright_data.get('error')}")
                except Exception as e: logger.error(f"Exc Playwright for final report: {e}", exc_info=True); report_data["detailed_step_results"][playwright_step_name or "playwright_final_report_data"] = {"gathered_data_for_report": {"error": str(e)}}
        try: return json.dumps(report_data, indent=2, default=str)
        except Exception as e: logger.error(f"Failed to serialize final report: {e}"); return json.dumps({"error": "Failed to serialize report", "details": str(e)}, indent=2)

# main_test_analyzer (same as before)
async def main_test_analyzer():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dotenv_path = os.path.join(project_root, '.env')
    if os.path.exists(dotenv_path): load_dotenv(dotenv_path=dotenv_path); logger.info(f".env loaded: {dotenv_path}")
    else: logger.warning(f".env not found at {dotenv_path}. LLM/Redis might fail.")
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - [%(name)s:%(lineno)d] - %(message)s')
    analyzer = AsyncURLAnalyzer(redis_client=None)
    urls_to_test = ["http://google.com", "https://example.com"]
    output_dir = os.path.join(project_root, "test_holistic_analysis_results")
    os.makedirs(output_dir, exist_ok=True)
    try:
        for i, url in enumerate(urls_to_test):
            logger.info(f"\n--- Testing URL ({i+1}/{len(urls_to_test)}): {url} ---")
            assessment_result = await analyzer.get_holistic_url_assessment(url)
            filename_base = re.sub(r'[^a-zA-Z0-9_-]', '_', urlparse(url).netloc or f"url_{i}"); filename_base = filename_base or f"url_{i}_invalid"
            filepath_assessment = os.path.join(output_dir, f"{filename_base}_holistic_assessment.json")
            with open(filepath_assessment, 'w', encoding='utf-8') as f: json.dump(assessment_result, f, indent=2, default=str)
            logger.info(f"Saved holistic assessment to: {filepath_assessment}")
            if assessment_result.get("assessment_summary", {}).get("overall_is_scam") == "YES":
                attachment_json_str = await analyzer.generate_full_analysis_report_for_attachment(assessment_result)
                if attachment_json_str:
                    filepath_attachment = os.path.join(output_dir, f"{filename_base}_attachment_report.json")
                    with open(filepath_attachment, 'w', encoding='utf-8') as f: f.write(attachment_json_str)
                    logger.info(f"Saved attachment report to: {filepath_attachment}")
    finally: await analyzer.close_sessions()

if __name__ == "__main__":
    asyncio.run(main_test_analyzer())