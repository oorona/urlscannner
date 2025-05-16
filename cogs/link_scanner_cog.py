# cogs/link_scanner_cog.py

import discord
from discord.ext import commands
import os
import re
import json
import logging
import io # Required for file attachment
from typing import List, Optional, Tuple, Dict, Any # Added Dict, Any
from urllib.parse import urlparse # Needed for normalization
from urlanalysis.url_analyzer import AsyncURLAnalyzer # Assuming this is the correct import path


logger = logging.getLogger('discord.scanner') # Specific logger for the scanner

# --- Constants for Reactions ---
REACTION_SUSPICIOUS = '🚨' # Police car light emoji
REACTION_SAFE = '✅'       # Check mark button emoji
REACTION_CACHE = '💾'      # Floppy disk emoji for cache hit
URLLIST_FILENAME = "urllist.json" # Cache filename

class LinkScannerCog(commands.Cog):
    """
    Cog responsible for scanning messages for links, analyzing them using cache
    and external analyzer, taking action based on the analysis, and optionally
    using an LLM for classification (if configured in the analyzer).
    """
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # Instantiate the analyzer - it will load its own config from .env
        self.analyzer = AsyncURLAnalyzer()
        # Load Discord-specific config from .env
        self.suspicious_channel_id = int(os.getenv("SUSPICIOUS_CHANNEL_ID", "0"))
        self.suspicious_role_id = int(os.getenv("SUSPICIOUS_ROLE_ID", "0"))
        self.notify_user_ids = [int(uid.strip()) for uid in os.getenv("NOTIFY_USER_IDS", "").split(',') if uid.strip()]
        self.suspicion_threshold = int(os.getenv("SUSPICION_THRESHOLD", "3"))

        # Basic URL regex
        self.url_regex = re.compile(r'(?:https?://|www\.)[^\s<>"]+|https?://[^\s<>"]+')

        # --- Load URL Cache ---
        self.url_cache: Dict[str, Dict[str, Any]] = self._load_cache()
        logger.info(f"Loaded {len(self.url_cache)} URLs from cache file '{URLLIST_FILENAME}'.")

        # --- Initialization Checks (Log potential issues) ---
        if not self.suspicious_channel_id:
            logger.error("SUSPICIOUS_CHANNEL_ID is not set or invalid in .env file! Alerts disabled.")
        if not self.suspicious_role_id:
            logger.error("SUSPICIOUS_ROLE_ID is not set or invalid in .env file! Role assignment disabled.")
        if not self.notify_user_ids:
            logger.warning("NOTIFY_USER_IDS is not set or empty in .env file. No users will be DMed.")

        logger.info(f"LinkScannerCog loaded. Alert Channel: {self.suspicious_channel_id}, Role: {self.suspicious_role_id}, Threshold: {self.suspicion_threshold}")
        logger.info(f"Reactions: Safe='{REACTION_SAFE}', Suspicious='{REACTION_SUSPICIOUS}', Cache='{REACTION_CACHE}'")

    # --- Cache Handling Methods ---
    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        """Loads the URL cache from the JSON file."""
        if os.path.exists(URLLIST_FILENAME):
            try:
                with open(URLLIST_FILENAME, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    # Basic validation: ensure it's a dictionary
                    if isinstance(cache_data, dict):
                         # Optional: Deeper validation of structure if needed
                         return cache_data
                    else:
                         logger.warning(f"Cache file '{URLLIST_FILENAME}' contained invalid data type ({type(cache_data)}), starting with empty cache.")
                         return {}
            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON from cache file '{URLLIST_FILENAME}'. Starting with empty cache.", exc_info=True)
                return {}
            except IOError as e:
                logger.error(f"Could not read cache file '{URLLIST_FILENAME}': {e}. Starting with empty cache.")
                return {}
            except Exception as e:
                 logger.error(f"Unexpected error loading cache '{URLLIST_FILENAME}': {e}. Starting with empty cache.", exc_info=True)
                 return {}
        else:
            logger.info(f"Cache file '{URLLIST_FILENAME}' not found. Starting with empty cache.")
            return {}

    def _save_cache(self):
        """Saves the current URL cache to the JSON file."""
        logger.info(f"Attempting to save {len(self.url_cache)} URLs to cache file '{URLLIST_FILENAME}'.")
        try:
            with open(URLLIST_FILENAME, 'w', encoding='utf-8') as f:
                json.dump(self.url_cache, f, indent=2, default=str) # Use default=str for non-serializable types like datetime
            logger.info(f"Successfully saved cache file '{URLLIST_FILENAME}'.")
        except IOError as e:
            logger.error(f"Could not write cache file '{URLLIST_FILENAME}': {e}")
        except TypeError as e:
            logger.error(f"Failed to serialize cache data for '{URLLIST_FILENAME}': {e}. Cache NOT saved.")
        except Exception as e:
             logger.error(f"Unexpected error saving cache '{URLLIST_FILENAME}': {e}", exc_info=True)

    async def cog_unload(self):
        """Clean up resources and save cache when the cog is unloaded."""
        logger.info("Unloading LinkScannerCog...")
        self._save_cache() # Save cache before closing session
        if self.analyzer:
            await self.analyzer.close_session()
            logger.info("Closed URL analyzer session during cog unload.")

    def _normalize_url_for_cache(self, url: str) -> str:
        """
        Normalizes a URL string for consistent cache keys.
        Ensures scheme is present and lowercases hostname.
        """
        original_url = url # Keep original for logging if needed
        try:
            # Ensure scheme is present
            if '://' not in url:
                if url.startswith("www."):
                    url = "http://" + url # Assume http for www. if missing scheme
                else:
                    # Defaulting to http might be okay, but could be https.
                    # Parsing without scheme can be tricky. Let's try adding http as default guess.
                    url = "http://" + url

            parsed = urlparse(url)
            # Reconstruct with lowercase scheme and netloc, keep path/query/fragment case
            # Handle potential AttributeError if parsing fails badly (though try/except helps)
            scheme = parsed.scheme.lower() if parsed.scheme else 'http' # Default scheme
            netloc = parsed.netloc.lower() if parsed.netloc else '' # Lowercase domain/ip

            # Remove default ports (optional, but increases cache hits)
            if (scheme == 'http' and netloc.endswith(':80')) or \
               (scheme == 'https' and netloc.endswith(':443')):
                    netloc = netloc.rsplit(':', 1)[0]
            #netloc = netloc.rsplit(':', 1)[0]
            # Remove trailing '/' from path if path is not just '/' (optional)
            path = parsed.path
            if path != '/' and path.endswith('/'):
                  path = path[:-1]

            # Rebuild (consider if query params order matters - sorting them could increase cache hits but is complex)
            # For now, just use lowercase scheme/netloc
            #normalized = f"{scheme}://{netloc}{path}"
            normalized = f"{scheme}://{netloc}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            if parsed.fragment:
                normalized += f"#{parsed.fragment}"

            return normalized
        except Exception as e:
            logger.warning(f"Failed to normalize URL '{original_url}': {e}. Using original URL as cache key.")
            return original_url # Fallback to original URL if normalization fails

    # --- Main Event Listener ---
    @commands.Cog.listener(name="on_message")
    async def on_message_scan(self, message: discord.Message):
        # --- Basic Checks ---
        if message.author == self.bot.user: return
        if not message.guild: return # Ignore DMs
        if not message.content: return
        # --- Find Links ---
        urls_found = [match.group(0) for match in self.url_regex.finditer(message.content)]
        if not urls_found: return

        logger.info(f"Found {len(urls_found)} URL(s) in message {message.id} from {message.author} ({message.author.id}) on {message.channel.name} ({message.channel.id})")

        # --- Process Links ---
        message_contains_suspicious = False
        first_suspicious_url_details: Optional[Tuple[str, str]] = None # Stores (raw_url, analysis_json_str)

        for raw_url in urls_found:
            normalized_url = self._normalize_url_for_cache(raw_url)
            logger.debug(f"Processing URL: {raw_url} (Normalized: {normalized_url})")

            is_suspicious = False
            analysis_data: Optional[Dict[str, Any]] = None # Store the dict form
            analysis_json_str: Optional[str] = None # Store the string form
            # LLM result is now part of the analysis_data dict fetched from cache or added after analysis

            # --- Check Cache ---
            cache_hit = False
            if normalized_url in self.url_cache:
                cache_hit = True
                urls_found=True
                logger.info(f"Cache hit for URL: {normalized_url}")
                cached_entry = self.url_cache[normalized_url]
                llm_classification = cached_entry.get('llm_classification') # This should be the main analysis dict
                #analysis_data = cached_entry.get('analysis_data') # This should be the main analysis dict
                if llm_classification:
                    logger.info(f"LLM classification obtained from CACHE for {normalized_url}: {llm_classification}")
                    if llm_classification.get("scam") == "YES" and llm_classification.get("confidence") in ["HIGH" ]:       
                        is_suspicious = True                  
                        logger.warning(f"Suspicious link : {normalized_url} classified as scam by LLM.")
                    elif llm_classification.get('confidence') in ["LOW","MEDIUM"]:
                        logger.warning(f"Link  : {normalized_url} classified as low or Medium.")
                        analysis_json_str = await self.analyzer.analyze_url(raw_url) # Analyze original URL format
                        analysis_data = json.loads(analysis_json_str)

                        # 2. Determine suspicion based on new analysis
                        risk_count = len(analysis_data.get("overall_summary", {}).get("potential_risks", []))
                        error_count = len(analysis_data.get("overall_summary", {}).get("errors_encountered", []))
                        total_risk_count = risk_count + error_count
                        # Log the analysis result
                        logger.info(f"URL: {raw_url} | Risk Count: {total_risk_count} (Threshold: {self.suspicion_threshold})")
                        if total_risk_count >= self.suspicion_threshold :
                            is_suspicious = True
                            logger.warning(f"Suspicious link detected: {raw_url} (Risks: {total_risk_count}) posted by {message.author}")
                    else:   
                        is_suspicious = False # LLM didn't classify as scam
                        logger.warning(f"Clean Link : {raw_url} classified as clean by LLM.")
                #try: await message.add_reaction(REACTION_CACHE)
                #except Exception: pass # Ignore reaction errors
            # --- If Not in Cache or Cache Invalid, Analyze ---
            if not cache_hit: # Analyze if cache miss or invalid cache data
                logger.info(f"Cache miss or invalid cache for {raw_url}. Analyzing...")
                llm_classification: Optional[Dict[str, str]] = None
                try:
                    # 1. Get analysis data
                    '''                    
                    # 3. Optional: Call LLM if analysis succeeded
                    # Decide if your bot logic *needs* the LLM result immediately for actions
                    # If only for caching/later review, this could be deferred or done here.
                    # Let's assume we want it for the cache record if available.
                    '''
                    llm_classification = await self.analyzer.get_llm_classification(normalized_url)
                    if llm_classification:
                        logger.info(f"LLM classification obtained for {normalized_url}: {llm_classification}")
                        if llm_classification.get("scam") == "YES" and llm_classification.get("confidence") in ["HIGH"]:       
                            is_suspicious = True                  
                            logger.warning(f"Suspicious link : {normalized_url} classified as scam by LLM.")
                        elif llm_classification.get('confidence') in ["LOW","MEDIUM"]:
                            logger.warning(f"Link  : {normalized_url} classified as low or Medium.")
                            analysis_json_str = await self.analyzer.analyze_url(raw_url) # Analyze original URL format
                            analysis_data = json.loads(analysis_json_str)
                            
                            # 2. Determine suspicion based on new analysis
                            risk_count = len(analysis_data.get("overall_summary", {}).get("potential_risks", []))
                            error_count = len(analysis_data.get("overall_summary", {}).get("errors_encountered", []))
                            total_risk_count = risk_count + error_count
                            # Log the analysis result
                            logger.info(f"URL: {raw_url} | Risk Count: {total_risk_count} (Threshold: {self.suspicion_threshold})")
                            if total_risk_count >= self.suspicion_threshold :
                                is_suspicious = True
                                llm_classification['reason'] = "\n ".join(analysis_data.get("overall_summary").get("potential_risks") + analysis_data.get("overall_summary").get("errors_encountered"))
                                logger.warning(f"Suspicious link detected: {raw_url} (Risks: {total_risk_count}) posted by {message.author}")
                        else:   
                            is_suspicious = False # LLM didn't classify as scam
                            logger.warning(f"Clean Link : {raw_url} classified as clean by LLM.")

                    else:
                         # Log if LLM failed but config was present
                        if self.analyzer.llm_token and self.analyzer.llm_api_url:
                            logger.warning(f"LLM classification failed or returned invalid data for {raw_url}")

                    # 4. Update cache with both analysis and LLM results
                    self.url_cache[normalized_url] = {
                        'llm_classification': llm_classification # Store LLM dict or None
                    }
                    logger.warning(f"Updated cache for URL: {normalized_url}")

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to decode JSON response during analysis for URL {raw_url}: {e}")
                    normalized_url = None # Ensure unavailable for reporting
                    is_suspicious = False # Cannot determine suspicion
                except Exception as e:
                    logger.error(f"Unexpected error during URL analysis for {raw_url}: {e}", exc_info=True)
                    normalized_url = None # Ensure unavailable for reporting
                    is_suspicious = False # Cannot determine suspicion
                # End of analysis block

            # --- Handle results for this specific URL ---
            if is_suspicious:
                message_contains_suspicious = True
                # Record the first suspicious link and its JSON (if available)
                if not first_suspicious_url_details:
                    first_suspicious_url_details = (raw_url, normalized_url,) # Store tuple

                # Add reaction immediately (only once per message if suspicious)
                # Check if already added by cache hit or previous iteration
                if REACTION_SUSPICIOUS not in [r.emoji for r in message.reactions]:
                     try: await message.add_reaction(REACTION_SUSPICIOUS)
                     except Exception: pass
                # Optional: Break loop after first suspicious link if desired
                # break

            # End of loop for one URL

        # --- Post-Loop Actions ---

        # Add safe reaction only if URLs were found, none were suspicious, and no cache reaction added
        if urls_found and not message_contains_suspicious:
             already_reacted = any(r.emoji in [REACTION_SAFE, REACTION_SUSPICIOUS] for r in message.reactions if r.me)
             if not already_reacted:
                  try:
                      await message.add_reaction(REACTION_SAFE)
                  except Exception: pass

        # Take action if *any* link in the message was found suspicious
        if message_contains_suspicious and first_suspicious_url_details:
            suspicious_url, normalized_url = first_suspicious_url_details
            await self.handle_suspicious_link(message, suspicious_url, llm_classification,analysis_json_str)
        elif message_contains_suspicious and not first_suspicious_url_details:
             # This case means suspicion was flagged but details couldn't be stored (e.g., analysis failed entirely)
             logger.error(f"Message {message.id} flagged as suspicious, but could not retrieve details for reporting.")
             # You might still want to perform some action, like DMing mods without details


    # --- Action Handler ---
    async def handle_suspicious_link(self, message: discord.Message, suspicious_url: str, llm_classification: Dict[str, str],  analysis_json: Optional[str] = None):
        """Handles logging, notifications, role assignment, and file attachment for a suspicious link."""
        member = message.author
        alert_channel = self.bot.get_channel(self.suspicious_channel_id)
        suspicious_role = message.guild.get_role(self.suspicious_role_id) if message.guild else None

        # Check if required components exist before proceeding
        if not alert_channel and not self.notify_user_ids and not suspicious_role:
             logger.warning(f"Suspicious link {suspicious_url} detected, but no action configured (no alert channel, notify users, or role).")
             return

        logger.info(f"Taking action for suspicious link {suspicious_url} in message {message.id} by user {member.id}")

        
        # Prepare JSON file attachment (only if JSON is available)
        json_file = None
        if analysis_json:
            try:
                 # Ensure it's a valid JSON string before creating file
                 json.loads(analysis_json) # Test parsing
                 json_filename = f"analysis_msg_{message.id}_user_{member.id}.json"
                 json_file = discord.File(
                     io.StringIO(analysis_json), # Use io.StringIO for string data
                     filename=json_filename
                 )
                 logger.debug("Created JSON file object for attachment.")
            except json.JSONDecodeError:
                logger.error("Analysis data for attachment was not valid JSON.")
                json_file = None
            except Exception as e:
                 logger.error(f"Failed to create analysis file object: {e}")
                 json_file = None # Ensure it's None if creation fails
        
        # 1. Notify Alert Channel
        if alert_channel:
            embed = discord.Embed(
                title="🚨 Suspicious Link Detected!",
                description=f"Found in message: {message.jump_url}",
                color=discord.Color.red(),
                timestamp=message.created_at
            )
            reason= llm_classification.get("reason", "No reason provided.")
            embed.add_field(name="Link Detected", value=f"`{suspicious_url}`", inline=False)
            embed.add_field(name="Posted By", value=f"{member.mention} ({member.display_name})", inline=True)
            embed.add_field(name="User ID", value=f"`{member.id}`", inline=True)
            embed.add_field(name="In Channel", value=message.channel.mention, inline=True)
            embed.add_field(name="Reason", value=f"`{reason}`", inline=True)
            embed.set_footer(text="Investigate link. Full analysis attached (if available).")

            try:
                # Send embed and file (if it exists)
                await alert_channel.send(embed=embed, file=json_file if json_file else discord.utils.MISSING)
                log_msg = f"Sent alert to channel #{alert_channel.name} for link {suspicious_url}"
                if json_file: log_msg += " with JSON attachment."
                logger.info(log_msg)
            except discord.Forbidden:
                logger.error(f"Missing permissions (Send Messages/Attach Files?) in alert channel {self.suspicious_channel_id}")
            except discord.HTTPException as e:
                if e.code == 40005: # Request entity too large
                    logger.error(f"Failed to send alert: Analysis JSON file is too large.")
                    try: # Try sending embed without file
                        await alert_channel.send(embed=embed, content="*Analysis JSON attachment too large to send.*")
                    except Exception as fallback_e:
                         logger.error(f"Failed to send fallback alert message: {fallback_e}")
                else:
                    logger.error(f"Failed to send alert message to channel {self.suspicious_channel_id}: {e}")
            except Exception as e:
                 logger.error(f"Unexpected error sending alert message to channel {self.suspicious_channel_id}: {e}", exc_info=True)
        # End alert channel notification

        # 2. Notify Specific Users via DM
        if self.notify_user_ids:
            dm_message = (
                f"🚨 **Suspicious Link Alert** 🚨\n\n"
                f"A potentially suspicious link was detected in **{message.guild.name}**:\n"
                f"- **Link:** `{suspicious_url}`\n"
                f"- **Posted By:** {member.mention} ({member.display_name} / ID: `{member.id}`)\n"
                f"- **In Channel:** {message.channel.mention}\n"
                f"- **Message Link:** {message.jump_url}\n\n"
                f"Please review the full alert and analysis in the designated channel (#{alert_channel.name if alert_channel else 'N/A'})."
            )
            for user_id in self.notify_user_ids:
                try:
                    user = self.bot.get_user(user_id) or await self.bot.fetch_user(user_id)
                    if user:
                        await user.send(dm_message)
                        logger.info(f"Sent DM notification to user {user.name} ({user.id})")
                    else:
                        logger.warning(f"Could not find user with ID {user_id} to send DM.")
                except discord.Forbidden:
                    logger.warning(f"Cannot send DM to user {user_id} (likely blocked or DMs disabled).")
                except discord.HTTPException as e:
                    logger.error(f"Failed to send DM to user {user_id}: {e}")
                except Exception as e:
                     logger.error(f"Unexpected error sending DM to user {user_id}: {e}", exc_info=True)
        # End DM notification

        # 3. Assign Role
        if suspicious_role and isinstance(member, discord.Member):
            if suspicious_role in member.roles:
                 logger.info(f"User {member.id} already has the suspicious role ({suspicious_role.id}). Skipping.")
            else:
                try:
                    #await member.add_roles(suspicious_role, reason=f"Posted suspicious link: {suspicious_url}")
                    logger.info(f"Assigned role '{suspicious_role.name}' ({suspicious_role.id}) to user {member.name} ({member.id})")
                    try: # Attempt to notify user about role assignment
                        await member.send(f"You have been assigned the '{suspicious_role.name}' role in **{message.guild.name}** due to posting a potentially suspicious link ({suspicious_url}). Please contact a moderator if you believe this is an error.")
                    except discord.Forbidden:
                         logger.warning(f"Could not DM user {member.id} about role assignment.")
                    except Exception as e:
                         logger.error(f"Error DMing user {member.id} about role assignment: {e}")
                except discord.Forbidden:
                    logger.error(f"Missing 'Manage Roles' permission or role hierarchy issue. Cannot assign role {suspicious_role.id} to user {member.id}.")
                except discord.HTTPException as e:
                    logger.error(f"Failed to assign role {suspicious_role.id} to user {member.id}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error assigning role {suspicious_role.id} to user {member.id}: {e}", exc_info=True)
        elif not suspicious_role:
             # Logged during init if ID is invalid, but log again if role object not found in guild
             logger.warning(f"Could not find suspicious role object with ID {self.suspicious_role_id} in guild {message.guild.name} ({message.guild.id}) during action handling.")
        # End role assignment
        # 4. label the link as suspicious in the message with a embed reply to the message
        try:
            embed = discord.Embed(
                title="Warning---Suspicious Link Detected!",
                description=f"Found in message: {message.jump_url}",
                color=discord.Color.red(),
                timestamp=message.created_at
            )
            reason= llm_classification.get("reason")
            embed.add_field(name="Link Detected", value=f"`{suspicious_url}`", inline=False)
            embed.add_field(name="Posted By", value=f"{member.mention} ({member.display_name})", inline=True)
            embed.add_field(name="Reason", value=f"`{reason}`", inline=True)
            embed.set_footer(text="There will be consecuences.")
            await message.reply(embed=embed)
        except Exception as e:
             logger.error(f"Failed to reply to message {message.id} with suspicious link alert: {e}", exc_info=True)

# Setup function required by discord.py to load the cog
async def setup(bot: commands.Bot):
    # Perform pre-checks if necessary (e.g., ensuring critical env vars are set for Discord actions)
    if not os.getenv("SUSPICIOUS_CHANNEL_ID") and not os.getenv("NOTIFY_USER_IDS") and not os.getenv("SUSPICIOUS_ROLE_ID"):
         logger.critical("No action configured (Channel ID, Notify IDs, Role ID). Cog actions will be ineffective.")
         # Decide if you want to prevent loading:
         # raise commands.ExtensionFailed("No action environment variables configured.")
    await bot.add_cog(LinkScannerCog(bot))
    logger.info("LinkScannerCog has been loaded.")