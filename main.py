# main.py
import os
import sys
import asyncio
import logging
from dotenv import load_dotenv

# --- Load Environment Variables ---
load_dotenv()
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# --- Logging Setup (Basic setup here, bot.py can configure more) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s:%(levelname)s:%(name)s: %(message)s')
log_formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s: %(message)s')
log_file_handler = logging.FileHandler('bot.log', encoding='utf-8', mode='w')
log_file_handler.setFormatter(log_formatter)
logging.getLogger().addHandler(log_file_handler) # Add handler to root logger

logger = logging.getLogger('main')

if not BOT_TOKEN:
    logger.critical("FATAL ERROR: DISCORD_BOT_TOKEN not found in .env file.")
    exit()

# Import the bot runner function AFTER loading .env
try:
    from bot import run_bot
except ImportError:
    logger.critical("Could not import run_bot from bot.py. Ensure bot.py exists.")
    exit()
except Exception as e:
    logger.critical(f"Error importing from bot.py: {e}", exc_info=True)
    exit()

# --- Main Execution ---
if __name__ == "__main__":
    # Handle Windows asyncio policy if needed
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