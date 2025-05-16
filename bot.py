# bot.py
import discord
from discord.ext import commands
import os
import logging
import asyncio
import signal # Import the signal module

logger = logging.getLogger('bot')

# Define necessary intents (as before)
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.reactions = True

# Use commands.Bot (as before)
bot = commands.Bot(command_prefix="!", intents=intents)

# --- Bot Events ---
@bot.event
async def on_ready():
    """Called when the bot is ready and connected to Discord."""
    logger.info(f'Logged in as {bot.user.name} (ID: {bot.user.id})')
    logger.info(f'discord.py version: {discord.__version__}')
    logger.info('Bot is ready and listening for messages.')
    try:
        await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="for suspicious links"))
        logger.info("Set bot presence.")
    except Exception as e:
        logger.error(f"Failed to set presence: {e}")

# --- Load Cogs ---
async def load_extensions():
    """Loads all cogs from the 'cogs' directory."""
    initial_extensions = ['cogs.link_scanner_cog']
    for extension in initial_extensions:
        try:
            await bot.load_extension(extension)
            logger.info(f'Successfully loaded extension: {extension}')
        except Exception as e:
            logger.error(f'Failed to load extension {extension}.', exc_info=True)

# --- NEW: Graceful Shutdown Handling ---
async def shutdown(sig: signal.Signals, loop: asyncio.AbstractEventLoop):
    """Handles shutdown signals."""
    logger.warning(f"Received exit signal {sig.name}...")
    logger.info("Attempting graceful shutdown...")

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    logger.info(f"Cancelling {len(tasks)} outstanding tasks...")
    [task.cancel() for task in tasks]

    await asyncio.gather(*tasks, return_exceptions=True) # Wait for tasks to finish cancelling

    if not bot.is_closed():
        logger.info("Closing Discord bot connection...")
        await bot.close() # This should trigger cog_unload
        logger.info("Discord bot connection closed.")
    else:
         logger.info("Discord bot connection already closed.")

    logger.info("Stopping event loop...")
    loop.stop()


# --- Main Runner Function (Modified) ---
async def run_bot(token: str):
    """Initializes and runs the Discord bot with signal handling."""
    loop = asyncio.get_running_loop()

    # Add signal handlers
    # SIGINT is Ctrl+C, SIGTERM is sent by Docker stop/down
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig, lambda s=sig: asyncio.create_task(shutdown(s, loop))
        )
        logger.info(f"Registered shutdown handler for {sig.name}")

    async with bot: # Use async context manager
        await load_extensions()
        logger.info("Attempting to connect to Discord...")
        try:
            await bot.start(token)
        except discord.LoginFailure:
            logger.critical("Login Failed: Invalid Discord token.")
        except discord.PrivilegedIntentsRequired:
             logger.critical("Privileged Intents not enabled in Developer Portal.")
        except Exception as e:
             # Catch other potential errors during startup/runtime
             logger.critical(f"Bot runtime error: {e}", exc_info=True)
        finally:
             logger.info("Bot event loop finished or bot was closed.")
             # Ensure loop is stopped if shutdown handler wasn't called somehow
             if loop.is_running():
                 loop.stop()
                 logger.info("Stopped event loop from finally block.")