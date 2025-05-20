# main.py
import os
import sys
import asyncio
import logging # Keep logging import
from dotenv import load_dotenv

# --- Load Environment Variables ---
load_dotenv()
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# --- Logging Setup (Simplified to log to console/stdout) ---
logging.basicConfig(
    level=logging.INFO, # Or your desired level
    format='%(asctime)s:%(levelname)s:%(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)] # Explicitly log to stdout
)
# If you want different levels for different loggers, configure them after basicConfig
logging.getLogger('discord').setLevel(logging.INFO) # Example for discord.py library
logging.getLogger('urlanalysis').setLevel(logging.DEBUG) # Example for your analyzer

logger = logging.getLogger('main') # This logger will inherit the basicConfig settings

if not BOT_TOKEN:
    logger.critical("FATAL ERROR: DISCORD_BOT_TOKEN not found in .env file.")
    sys.exit(1) # Use sys.exit for cleaner exit

# Import the bot runner function AFTER loading .env
try:
    from bot import run_bot
except ImportError:
    logger.critical("Could not import run_bot from bot.py. Ensure bot.py exists.")
    sys.exit(1)
except Exception as e:
    logger.critical(f"Error importing from bot.py: {e}", exc_info=True)
    sys.exit(1)

# --- Main Execution ---
if __name__ == "__main__":
    if sys.platform == 'win32':
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            logger.info("Set WindowsSelectorEventLoopPolicy for Windows.")
        except Exception as e:
            logger.warning(f"Could not set WindowsSelectorEventLoopPolicy: {e}")

    try:
        logger.info("Starting bot...")
        asyncio.run(run_bot(BOT_TOKEN))
    except KeyboardInterrupt:
        logger.info("Bot shutdown requested by user.")
    except Exception as e:
        logger.critical(f"An unexpected error occurred in main execution: {e}", exc_info=True)
    finally:
        logger.info("Bot process finished.")