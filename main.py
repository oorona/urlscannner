# main.py
import os
import sys
import asyncio
import logging
import logging.handlers # For file rotation if desired later
from dotenv import load_dotenv

# --- Load Environment Variables ---
load_dotenv()
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# --- Logging Configuration ---
def setup_logging():
    # Get log levels from .env, with defaults
    log_level_main_str = os.getenv("LOG_LEVEL_MAIN", "INFO").upper()
    log_level_urla_str = os.getenv("LOG_LEVEL_URLANALYSIS", "WARNING").upper()
    log_level_discord_str = os.getenv("LOG_LEVEL_DISCORDPY", "INFO").upper()
    
    log_to_file_str = os.getenv("LOG_TO_FILE", "True").lower()
    log_file_path = os.getenv("LOG_FILE_PATH", "bot.log")
    log_format_str = os.getenv("LOG_FORMAT", "%(asctime)s - %(levelname)-8s - %(name)-25s - [%(filename)s:%(lineno)d] - %(message)s")

    # Convert string log levels to logging constants
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    
    main_level = log_levels.get(log_level_main_str, logging.INFO)
    urla_level = log_levels.get(log_level_urla_str, logging.WARNING)
    discord_level = log_levels.get(log_level_discord_str, logging.INFO)

    # Get the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(min(main_level, urla_level, discord_level)) # Set root to the lowest level to allow handlers to filter

    formatter = logging.Formatter(log_format_str)

    # Console Handler (always enabled)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    # Set the console handler's level to the main log level,
    # as it's the primary output for general bot operation.
    console_handler.setLevel(main_level)
    root_logger.addHandler(console_handler)

    # File Handler (optional)
    if log_to_file_str == "true":
        try:
            # Use RotatingFileHandler for better log management (optional, but good practice)
            # Max 5MB per file, keep 5 backup files.
            file_handler = logging.handlers.RotatingFileHandler(
                log_file_path, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            # File handler should also respect the main_level or the lowest configured if you want everything in the file.
            # For this setup, let's make it also respect main_level primarily, but it will catch anything from other loggers too if their level is lower.
            file_handler.setLevel(main_level) 
            root_logger.addHandler(file_handler)
            logging.info(f"Logging to file: {log_file_path}")
        except Exception as e:
            logging.error(f"Failed to set up file logging for {log_file_path}: {e}", exc_info=True)
            
    # Set specific log levels for different loggers
    logging.getLogger('main').setLevel(main_level)
    logging.getLogger('bot').setLevel(main_level) # For bot.py logs
    logging.getLogger('discord.scanner.cog').setLevel(main_level) # For your cog
    
    # urlanalysis logs will be prefixed by 'urlanalysis.' due to how getLogger(__name__) works
    # e.g., urlanalysis.url_analyzer
    logging.getLogger('urlanalysis').setLevel(urla_level) 
    
    logging.getLogger('discord').setLevel(discord_level) # discord.py library
    logging.getLogger('websockets').setLevel(discord_level) # Often noisy with discord.py
    logging.getLogger('httpx').setLevel(logging.WARNING) # httpx can be verbose at INFO
    logging.getLogger('aiohttp').setLevel(logging.WARNING) # aiohttp also

    # Initial log to confirm setup
    initial_logger = logging.getLogger('main')
    initial_logger.info(f"Logging initialized. Main level: {log_level_main_str}, UrlAnalysis level: {log_level_urla_str}, DiscordPy level: {log_level_discord_str}")

# Call the setup function
setup_logging()

# Get a logger for this file AFTER setup
logger = logging.getLogger('main')


if not BOT_TOKEN:
    logger.critical("FATAL ERROR: DISCORD_BOT_TOKEN not found in .env file.")
    sys.exit(1)

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
    # Removed Windows-specific event loop policy code
    # Docker environments (typically Linux-based) do not need this.

    try:
        logger.info("Starting bot...")
        asyncio.run(run_bot(BOT_TOKEN))
    except KeyboardInterrupt:
        logger.info("Bot shutdown requested by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical(f"An unexpected error occurred in main execution: {e}", exc_info=True)
    finally:
        logger.info("Bot process finished.")