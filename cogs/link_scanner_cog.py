# cogs/link_scanner_cog.py
import discord
from discord.ext import commands
import os
import re
import json
import logging
import io
from typing import Dict, Any, Optional,Tuple

from urllib.parse import urlparse

# Corrected Redis imports
import redis.asyncio as aioredis 
from redis import exceptions as RedisExceptions


# Ensure the import path is correct based on your project structure
try:
    from urlanalysis.url_analyzer import AsyncURLAnalyzer
except ImportError:
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from urlanalysis.url_analyzer import AsyncURLAnalyzer


logger = logging.getLogger('discord.scanner.cog')

# --- Constants for Reactions ---
REACTION_SUSPICIOUS = '🚨'
REACTION_SAFE = '✅'
REACTION_CACHE = '💾'
REACTION_ERROR = '⚠️'

# Cache settings
FULL_URL_CACHE_PREFIX = "urlscan:full_assessment_cache:"
DOMAIN_CACHE_PREFIX = "urlscan:domain_assessment_cache:"
DEFAULT_CACHE_EXPIRY_SECONDS = 60 * 60 * 24 * 7 # 7 days

class LinkScannerCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        
        self.analysis_mode = os.getenv("ANALYSIS_MODE", "domain").lower()
        logger.info(f"LinkScannerCog initialized with ANALYSIS_MODE: {self.analysis_mode}")

        self.redis_client: Optional[aioredis.Redis] = None
        redis_host = os.getenv("REDIS_HOST", "localhost")
        redis_port = int(os.getenv("REDIS_PORT", "6379"))
        redis_db = int(os.getenv("REDIS_DB", "0"))
        redis_password_from_env = os.getenv("REDIS_PASSWORD")
        self.redis_password_to_use = redis_password_from_env if redis_password_from_env else None
        try:
            self.redis_client = aioredis.Redis(
                host=redis_host, port=redis_port, db=redis_db, 
                password=self.redis_password_to_use, decode_responses=False
            )
            logger.info(f"Cog Redis client configured for {redis_host}:{redis_port}. Password used: {'Yes' if self.redis_password_to_use else 'No'}")
        except Exception as e:
            logger.error(f"Cog failed to initialize Redis client: {e}. Caching will be unavailable.", exc_info=True)
            self.redis_client = None

        self.analyzer = AsyncURLAnalyzer(redis_client=self.redis_client) 

        self.suspicious_channel_id = int(os.getenv("SUSPICIOUS_CHANNEL_ID", "0"))
        self.suspicious_role_id = int(os.getenv("SUSPICIOUS_ROLE_ID", "0"))
        self.notify_user_ids_str = os.getenv("NOTIFY_USER_IDS", "")
        self.notify_user_ids = []
        if self.notify_user_ids_str:
            try:
                self.notify_user_ids = [int(uid.strip()) for uid in self.notify_user_ids_str.split(',') if uid.strip()]
            except ValueError:
                logger.error("Invalid user ID in NOTIFY_USER_IDS. Must be comma-separated integers.")
        
        self.url_regex = re.compile(
            r'(?:https?://|www\.)[^\s<>"()[\]{}]+|'
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|gov|edu|info|biz|io|ai|co|de|uk|ca|au|fr|gg|me|sh|ly|tv|us|jp|cn|ru|br|in|es|it|nl|be|xyz)\b|'
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}/[^\s<>"()[\]{}]*'
        )
        logger.info(f"LinkScannerCog loaded. Alert Channel: {self.suspicious_channel_id}, Role: {self.suspicious_role_id}, Mode: {self.analysis_mode}")


    async def _test_redis_connection(self):
        if self.redis_client:
            try:
                await self.redis_client.ping()
                logger.info("Cog successfully connected to Redis server.")
                return True
            except RedisExceptions.AuthenticationError as e:
                logger.error(f"Cog Redis auth failed: {e}. Caching unavailable.", exc_info=False)
                self.redis_client = None
                return False
            except RedisExceptions.ConnectionError as e:
                logger.error(f"Cog Redis connection failed: {e}. Caching unavailable.", exc_info=True)
                self.redis_client = None
                return False
            except Exception as e: 
                logger.error(f"Cog unexpected Redis ping error: {e}. Caching unavailable.", exc_info=True)
                self.redis_client = None
                return False
        return False

    async def cog_load(self):
        logger.info("LinkScannerCog is loading...")
        await self._test_redis_connection()

    async def cog_unload(self):
        logger.info("Unloading LinkScannerCog...")
        if self.analyzer:
            await self.analyzer.close_sessions()
            logger.info("Closed Analyzer sessions.")
        if self.redis_client:
            try:
                await self.redis_client.close()
                logger.info("Closed Cog Redis client connection.")
            except Exception as e:
                logger.error(f"Error closing Cog Redis client: {e}", exc_info=True)

    def _get_cache_key_and_normalization_target(self, url: str) -> Tuple[str, str]:
        if self.analysis_mode == "domain":
            try:
                parsed_components = self.analyzer._parse_url_components(url)
                domain_parts = parsed_components.get("domain_parts", {})
                target_for_analysis = domain_parts.get("registered_domain")
                if not target_for_analysis:
                    target_for_analysis = parsed_components.get("netloc", urlparse(url).netloc.lower())
                if not target_for_analysis:
                    logger.warning(f"Could not extract valid domain/netloc for '{url}' in domain mode. Using raw URL for key.")
                    target_for_analysis = url 
                cache_key = f"{DOMAIN_CACHE_PREFIX}{target_for_analysis}"
                return cache_key, target_for_analysis
            except Exception as e:
                logger.error(f"Error normalizing URL '{url}' for domain mode cache: {e}. Using full URL.")
                normalized_full = self._normalize_full_url(url)
                return f"{FULL_URL_CACHE_PREFIX}{normalized_full}", normalized_full
        else: # "full_url" mode
            normalized_full = self._normalize_full_url(url)
            cache_key = f"{FULL_URL_CACHE_PREFIX}{normalized_full}"
            return cache_key, normalized_full
            
    def _normalize_full_url(self, url: str) -> str:
        try:
            if '://' not in url:
                if url.startswith("www."): url = "http://" + url
                else: url = "https://" + url 
            parsed = urlparse(url); scheme = parsed.scheme.lower(); netloc = parsed.netloc.lower()
            if (scheme == 'http' and netloc.endswith(':80')) or (scheme == 'https' and netloc.endswith(':443')):
                netloc = netloc.rsplit(':', 1)[0]
            path = parsed.path
            if path != '/' and path.endswith('/'): path = path[:-1]
            if not path: path = '/'
            normalized = f"{scheme}://{netloc}{path}"
            if parsed.query: normalized += f"?{parsed.query}"
            return normalized
        except Exception as e: logger.warning(f"Failed to normalize full URL '{url}': {e}. Using original."); return url

    async def _get_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        if not self.redis_client: return None
        try:
            cached_data_bytes = await self.redis_client.get(cache_key)
            if cached_data_bytes:
                assessment_result = json.loads(cached_data_bytes.decode('utf-8'))
                logger.info(f"Cache HIT for key: {cache_key}")
                return assessment_result
            logger.debug(f"Cache MISS for key: {cache_key}")
            return None
        except RedisExceptions.RedisError as e: logger.error(f"Redis GET error for key '{cache_key}': {e}", exc_info=True)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode cached JSON for key '{cache_key}': {e}", exc_info=True)
            try: 
                if self.redis_client: await self.redis_client.delete(cache_key)
            except: pass 
        return None

    async def _save_to_cache(self, cache_key: str, assessment_result: Dict[str, Any]):
        if not self.redis_client: return
        try:
            data_to_cache_bytes = json.dumps(assessment_result, default=str).encode('utf-8')
            await self.redis_client.setex(cache_key, DEFAULT_CACHE_EXPIRY_SECONDS, data_to_cache_bytes)
            logger.info(f"Saved to cache with key: {cache_key}")
        except RedisExceptions.RedisError as e: logger.error(f"Redis SETEX error for key '{cache_key}': {e}", exc_info=True)
        except TypeError as e: logger.error(f"Failed to serialize result for key '{cache_key}': {e}", exc_info=True)

    @commands.Cog.listener(name="on_message")
    async def on_message_scan(self, message: discord.Message):
        if message.author == self.bot.user or not message.guild:
            return

        # Use a set to automatically handle duplicate URLs
        found_urls = set()

        # Scan the raw message content
        if message.content:
            for match in self.url_regex.finditer(message.content):
                found_urls.add(match.group(0))

        # Scan all embeds attached to the message
        if message.embeds:
            for embed in message.embeds:
                # Aggregate all text content from the embed into one string
                text_to_scan = []
                if embed.title and isinstance(embed.title, str):
                    text_to_scan.append(embed.title)
                if embed.description and isinstance(embed.description, str):
                    text_to_scan.append(embed.description)
                if embed.url and isinstance(embed.url, str):
                    text_to_scan.append(embed.url)
                if embed.author and embed.author.url and isinstance(embed.author.url, str):
                    text_to_scan.append(embed.author.url)
                if embed.footer and embed.footer.text and isinstance(embed.footer.text, str):
                    text_to_scan.append(embed.footer.text)
                
                for field in embed.fields:
                    if field.name and isinstance(field.name, str):
                        text_to_scan.append(field.name)
                    if field.value and isinstance(field.value, str):
                        text_to_scan.append(field.value)
                
                full_embed_text = "\n".join(text_to_scan)
                if full_embed_text:
                    for match in self.url_regex.finditer(full_embed_text):
                        found_urls.add(match.group(0))
        
        # If no URLs were found in content or embeds, exit
        if not found_urls:
            return
        
        # Sanitize and create a list of unique URLs to process
        unique_urls_to_process = list(dict.fromkeys(
            re.sub(r'[.,;:!?\)\]\}]$', '', raw_url) for raw_url in found_urls
        ))

        if not unique_urls_to_process:
            return
        
        logger.info(f"Found {len(unique_urls_to_process)} unique URL(s) in message {message.id} from {message.author} (content & embeds)")
        
        message_overall_status: str = "SAFE" 
        first_suspicious_assessment: Optional[Dict[str, Any]] = None
        first_suspicious_raw_url: Optional[str] = None
        reacted_cache = False

        for i, raw_url in enumerate(unique_urls_to_process, 1):
            cache_key, target_for_log = self._get_cache_key_and_normalization_target(raw_url)
            logger.debug(f"Processing URL ({i}/{len(unique_urls_to_process)}): Raw='{raw_url}', CacheKeyTarget='{target_for_log}', CacheKey='{cache_key}'")
            
            assessment_result = await self._get_from_cache(cache_key)
            if assessment_result:
                if not reacted_cache: 
                    try: await message.add_reaction(REACTION_CACHE); reacted_cache = True
                    except Exception: pass
            else:
                logger.info(f"Analyzing URL (cache miss for key '{cache_key}'): {raw_url}")
                try:
                    assessment_result = await self.analyzer.get_holistic_url_assessment(raw_url)
                    await self._save_to_cache(cache_key, assessment_result)
                except Exception as e:
                    logger.error(f"Critical error during URL analysis for '{raw_url}': {e}", exc_info=True)
                    assessment_result = {
                        "original_url": raw_url, 
                        "assessment_summary": {
                            "overall_is_scam": "ERROR", 
                            "overall_confidence": "NONE",
                            "overall_reason": f"Analysis pipeline failed: {type(e).__name__}"
                        },
                        "error": str(e)
                    }
            
            if assessment_result:
                summary = assessment_result.get("assessment_summary", {})
                is_scam_str = summary.get("overall_is_scam", "UNKNOWN").upper()
                if is_scam_str == "YES":
                    logger.warning(f"Suspicious link DETECTED: '{raw_url}'. Reason: {summary.get('overall_reason', 'N/A')}")
                    if message_overall_status != "SUSPICIOUS": message_overall_status = "SUSPICIOUS"
                    if not first_suspicious_assessment: 
                        first_suspicious_assessment = assessment_result
                        first_suspicious_raw_url = raw_url
                elif is_scam_str == "ERROR":
                    logger.error(f"Error analyzing '{raw_url}'. Reason: {summary.get('overall_reason', 'N/A')}")
                    if message_overall_status not in ["SUSPICIOUS", "ERROR"]: message_overall_status = "ERROR"
            else: 
                logger.error(f"Assessment result None for '{raw_url}'.")
                if message_overall_status not in ["SUSPICIOUS", "ERROR"]: message_overall_status = "ERROR"

        if message_overall_status == "SUSPICIOUS" and first_suspicious_assessment and first_suspicious_raw_url:
            try: await message.add_reaction(REACTION_SUSPICIOUS)
            except Exception: pass
            await self.handle_suspicious_link(message, first_suspicious_raw_url, first_suspicious_assessment)
        elif message_overall_status == "SAFE":
            if not any(str(r.emoji) in [REACTION_SUSPICIOUS, REACTION_ERROR] for r in message.reactions if r.me):
                try: await message.add_reaction(REACTION_SAFE)
                except Exception: pass
        elif message_overall_status == "ERROR":
            if not any(str(r.emoji) == REACTION_SUSPICIOUS for r in message.reactions if r.me):
                try: await message.add_reaction(REACTION_ERROR)
                except Exception: pass

    async def handle_suspicious_link(self, message: discord.Message, suspicious_raw_url: str, 
                                     assessment_result: Dict[str, Any]):
        member = message.author
        alert_channel = self.bot.get_channel(self.suspicious_channel_id) if self.suspicious_channel_id else None
        suspicious_role = message.guild.get_role(self.suspicious_role_id) if self.suspicious_role_id and message.guild else None

        summary = assessment_result.get("assessment_summary", {})
        reason = summary.get("overall_reason", "No specific reason provided by assessment.")
        confidence = summary.get("overall_confidence", "N/A")

        logger.info(f"Handling suspicious link '{suspicious_raw_url}' from {member.name} (ID: {member.id}). Reason: {reason}, Confidence: {confidence}")

        attachment_json_str: Optional[str] = None
        if summary.get("overall_is_scam") == "YES":
            try:
                attachment_json_str = await self.analyzer.generate_full_analysis_report_for_attachment(assessment_result)
                if not attachment_json_str:
                    logger.info(f"generate_full_analysis_report_for_attachment returned None for '{suspicious_raw_url}'.")
            except Exception as e:
                logger.error(f"Failed to generate attachment JSON for '{suspicious_raw_url}': {e}", exc_info=True)
        
        json_file_to_send: Optional[discord.File] = None
        if attachment_json_str:
            try:
                parsed_url_for_filename = urlparse(suspicious_raw_url)
                safe_filename_base = re.sub(r'[^a-zA-Z0-9_-]', '_', parsed_url_for_filename.netloc or parsed_url_for_filename.path or "unknown_url")
                json_filename = f"analysis_msg_{message.id}_{safe_filename_base[:30]}.json"
                json_file_to_send = discord.File(io.BytesIO(attachment_json_str.encode('utf-8')), filename=json_filename)
                logger.debug(f"Created discord.File object: {json_filename}")
            except Exception as e:
                logger.error(f"Failed to create discord.File object for attachment: {e}", exc_info=True)

        if alert_channel:
            embed = discord.Embed(
                title="🚨 Suspicious Link Detected by AI!",
                description=f"Found in message: {message.jump_url}",
                color=discord.Color.red(),
                timestamp=message.created_at
            )
            embed.add_field(name="Link Detected", value=f"`{discord.utils.escape_markdown(suspicious_raw_url)}`", inline=False)
            embed.add_field(name="Posted By", value=f"{member.mention} ({member.display_name})", inline=True)
            embed.add_field(name="User ID", value=f"`{member.id}`", inline=True)
            embed.add_field(name="In Channel", value=message.channel.mention if message.channel else "Unknown Channel", inline=True)
            embed.add_field(name="AI Assessed Confidence", value=str(confidence), inline=True)
            embed.add_field(name="AI Reason", value=discord.utils.escape_markdown(reason)[:1020] + ("..." if len(reason) > 1020 else ""), inline=False)
            embed.set_footer(text="Full AI analysis report attached if available and link deemed scam.")
            try:
                await alert_channel.send(embed=embed, file=json_file_to_send if json_file_to_send else discord.utils.MISSING)
                logger.info(f"Sent alert to #{alert_channel.name} for '{suspicious_raw_url}'. Attachment sent: {bool(json_file_to_send)}")
            except discord.HTTPException as e:
                logger.error(f"Failed to send alert to #{alert_channel.name} (HTTPException): {e.status} - {e.text}")
                if e.code == 40005 and json_file_to_send: 
                    try:
                        await alert_channel.send(embed=embed, content="*AI Analysis JSON attachment was too large to send.*")
                        logger.info(f"Sent alert to #{alert_channel.name} for '{suspicious_raw_url}' but attachment was too large.")
                    except Exception as fallback_e:
                        logger.error(f"Failed to send fallback alert message (attachment too large): {fallback_e}", exc_info=True)
            except Exception as e:
                logger.error(f"Unexpected error sending alert to #{alert_channel.name}: {e}", exc_info=True)
        else:
            if self.suspicious_channel_id != 0:
                logger.warning("Suspicious Channel ID configured but channel not found. Cannot send alert.")
            else:
                logger.info("Suspicious Channel ID not configured. Skipping channel alert.")

        if self.notify_user_ids:
            dm_embed = discord.Embed(
                title="🚨 AI Detected Suspicious Link Alert 🚨",
                description=f"A potentially suspicious link was detected by AI in **{message.guild.name if message.guild else 'Unknown Server'}**:",
                color=discord.Color.orange(),
                timestamp=message.created_at
            )
            dm_embed.add_field(name="Link", value=f"`{discord.utils.escape_markdown(suspicious_raw_url)}`", inline=False)
            dm_embed.add_field(name="Posted By", value=f"{member.mention} ({member.display_name} / ID: `{member.id}`)", inline=False)
            dm_embed.add_field(name="In Channel", value=message.channel.mention if message.channel else "N/A", inline=True)
            dm_embed.add_field(name="Message Link", value=message.jump_url, inline=True)
            dm_embed.add_field(name="AI Reason", value=discord.utils.escape_markdown(reason)[:1020], inline=False)
            dm_embed.set_footer(text=f"Alert Channel: #{alert_channel.name if alert_channel else 'Not Configured'}")

            for user_id_to_notify in self.notify_user_ids: # Corrected variable name
                try:
                    user_object = self.bot.get_user(user_id_to_notify) or await self.bot.fetch_user(user_id_to_notify)
                    if user_object: # CORRECTED: if condition for user_object
                        await user_object.send(embed=dm_embed) # CORRECTED: proper block
                    logger.info(f"Sent DM notification to {user_object.name if user_object else 'Unknown User'} ({user_id_to_notify})") # Check if user_object is None
                except discord.Forbidden: 
                    logger.warning(f"Cannot send DM to user {user_id_to_notify} (DMs disabled or bot blocked).")
                except Exception as e: 
                    logger.error(f"Failed to send DM to user {user_id_to_notify}: {e}", exc_info=True)
        
        if suspicious_role and isinstance(member, discord.Member):
            if suspicious_role not in member.roles:
                try:
                    await member.add_roles(suspicious_role, reason=f"Posted AI-flagged suspicious link: {suspicious_raw_url[:100]}")
                    logger.info(f"Assigned role '{suspicious_role.name}' to {member.name}")
                    try:
                        await member.send(f"You have been assigned the '{suspicious_role.name}' role in **{message.guild.name}** due to posting a link that our AI systems flagged as potentially suspicious. Please contact a moderator if you believe this is an error.")
                    except discord.Forbidden: 
                        logger.warning(f"Could not DM user {member.name} about role assignment (DMs disabled).")
                    except Exception as e:
                        logger.error(f"Error DMing user {member.name} about role assignment: {e}", exc_info=True)
                except discord.Forbidden: 
                    logger.error(f"Missing 'Manage Roles' permission or role '{suspicious_role.name}' is higher than bot's role. Cannot assign.")
                except Exception as e: 
                    logger.error(f"Failed to assign role '{suspicious_role.name}' to {member.name}: {e}", exc_info=True)
            else: 
                logger.info(f"User {member.name} already has role '{suspicious_role.name}'.")
        elif not suspicious_role and self.suspicious_role_id != 0:
            logger.warning(f"Suspicious Role ID {self.suspicious_role_id} configured but role not found in server '{message.guild.name if message.guild else 'Unknown Guild'}'.")

        try:
            reply_embed = discord.Embed(
                title="⚠️ Warning: Potentially Suspicious Link (AI Assessed)",
                description=(
                    f"{member.mention}, the link you posted has been flagged by our AI systems as potentially suspicious.\n"
                    f"**AI Assessment Reason:** {discord.utils.escape_markdown(reason)[:1500]}\n\n"
                    f"Please exercise caution. Moderators have been notified for review."
                ),
                color=discord.Color.orange(),
                timestamp=message.created_at
            )
            reply_embed.set_footer(text="This is an automated AI assessment. A human moderator may review this.")
            await message.reply(embed=reply_embed, mention_author=True)
            logger.info(f"Replied with AI warning to message {message.id}")
        except Exception as e:
            logger.error(f"Failed to reply with warning to message {message.id}: {e}", exc_info=True)

async def setup(bot: commands.Bot):
    if not os.getenv("SUSPICIOUS_CHANNEL_ID") and not os.getenv("NOTIFY_USER_IDS") and not os.getenv("SUSPICIOUS_ROLE_ID"):
         logger.warning("No primary action (Alert Channel ID, Notify User IDs, or Suspicious Role ID) is configured for LinkScannerCog. Actions may be limited.")
    
    cog_instance = LinkScannerCog(bot)
    await bot.add_cog(cog_instance)
    logger.info("LinkScannerCog has been prepared and added to the bot.")