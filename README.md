# Discord Link Scanner Bot: Advanced AI-Powered URL Analysis

This Discord bot **leverages Artificial Intelligence, specifically Large Language Models (LLMs)**, to automatically scan messages for URLs and perform a deep, multi-faceted analysis to determine if they are malicious or part of a scam. Unlike traditional scanners that rely solely on blocklists or simple heuristics, this bot employs a **configurable pipeline of AI-driven assessment steps**. Each piece of information gathered about a URL (such as its string structure, DNS records, WHOIS data, SSL certificate validity including comparison against the current date, and even page content via headless Browse) can be individually assessed by an LLM. Finally, a **"Decider" LLM synthesizes all these AI-powered insights** to make a holistic judgment on the URL's safety.

If a link is flagged as suspicious by this comprehensive AI analysis, the bot takes configurable actions such as alerting moderators, notifying users, and assigning roles.

## Core Features

* **AI-Driven Analysis Pipeline:**
    * **Multi-Step LLM Assessment:** Analyzes URLs through a configurable sequence of steps. Each step gathers data (URL structure, reachability, DNS, WHOIS, SSL, optional page content via Playwright) and then uses a dedicated Large Language Model (LLM) with a tailored prompt to assess that specific aspect for scam indicators. For SSL certificates, the current date is provided to the LLM for accurate temporal validation.
    * **"Final Decider" LLM:** After individual AI assessments, a final LLM synthesizes all findings to provide an overall scam classification (YES/NO) and confidence level (LOW/MEDIUM/HIGH) for the URL.
    * **Configurable & Modular:** The analysis pipeline, including which steps are run, their data sources, and the LLM prompts used, is defined in an external YAML file (`urlanalysis/analysis_pipeline_config.yaml`). Prompts for each LLM interaction are stored in separate, easily editable text files.
* **Discord Integration:**
    * Monitors all messages in servers it's added to.
    * Detects URLs within message content.
    * **Adds Reactions:** Adds ✅ (safe), 🚨 (suspicious), 💾 (cache hit), or ⚠️ (error) to messages based on the AI analysis outcome.
* **Alerting & Reporting:**
    * **Sends Detailed Alerts:** Posts an alert to a moderator channel for suspicious links, including the AI's reasoning and confidence.
    * **Attaches Full Analysis JSON:** If a link is deemed a scam by the AI, a comprehensive JSON report detailing all gathered data and individual AI step assessments is attached to the alert.
    * Notifies designated users via Direct Message.
* **User Actions:**
    * Assigns a specific role to users posting suspicious links.
    * Replies to the original message with a warning.
* **Performance & Scalability:**
    * Uses Redis for efficient caching of AI analysis results, reducing redundant processing.
    * Asynchronous operations for non-blocking performance.
* **Advanced Logging:**
    * **Configurable Levels:** Set different log levels for the main application, the `urlanalysis` module, and the `discord.py` library via `.env` variables.
    * **Optional File Logging:** Log output to a configurable file (e.g., `bot.log`) with rotation.
    * **Customizable Format:** Define the log message format through an environment variable.
* **Configuration:** Highly configurable via a `.env` file (for secrets, environment settings like API keys, Redis DSN, and logging preferences) and the `analysis_pipeline_config.yaml` (for the AI analysis workflow).
* **Technology:** Built with Python, `discord.py`, `httpx` for LLM communication, Playwright for web interaction, and various network analysis libraries. Designed for Docker deployment.

## How the AI Determines Suspicion

The bot's intelligence lies in its `url_analyzer.py` module and the configured AI pipeline:

1.  **Configuration Loading:** The `analysis_pipeline_config.yaml` file dictates the entire analysis flow. It specifies each step, what data to gather (e.g., DNS, WHOIS), and which prompt file to use for LLM assessment of that data.
2.  **Initial Checks:** A URL reachability check is performed early.
3.  **Sequential AI Assessment:** For each enabled step in the pipeline:
    * Relevant data is collected (e.g., SSL certificate details).
    * This data, along with contextual information like the **current date for SSL certificate validation**, is formatted into a specific prompt (loaded from `urlanalysis/prompts/`).
    * An LLM (configured via `.env`) assesses this information and returns a structured JSON response indicating if *this specific aspect* appears scam-like, along with confidence and reasoning.
4.  **"Final Decider" LLM:** Once all individual AI assessment steps are complete, their outputs, along with the reachability status, are summarized and presented to a final "Decider" LLM. This LLM uses a master prompt to evaluate the totality of the evidence and make the ultimate call on whether the URL is a scam, providing an overall confidence level and a summary reason.
5.  **Action Trigger:** The Discord bot cog then uses this final AI judgment to take appropriate actions (reactions, alerts, etc.).

This layered AI approach allows for a nuanced and context-aware analysis, going beyond simple pattern matching.

## Prerequisites

* Python 3.9+
* `pip` (Python package installer)
* Access to a Discord server where you have permissions to add bots and manage roles/channels.
* A Discord Bot Token.
* **Access to an LLM API:** Configured to be compatible with OpenAI's API structure (e.g., Ollama with an appropriate model, OpenWebUI, or other commercial/private LLMs). This includes an API key/token and the correct API endpoint URL.
* **Redis Instance:** A running Redis server for caching analysis results.
* Docker and Docker Compose for containerized deployment (recommended as primary deployment method).

## Installation

1.  **Clone the repository or download the files:**
    ```bash
    git clone <repository_url> # Or download and extract the ZIP
    cd discord-link-scanner-ai
    ```

2.  **Create and Configure `.env` file:**
    * Copy `.env.example` to `.env`.
    * Fill in all required values:
        * `DISCORD_BOT_TOKEN`
        * Discord Channel/Role/User IDs (`SUSPICIOUS_CHANNEL_ID`, `NOTIFY_USER_IDS`, `SUSPICIOUS_ROLE_ID`)
        * **LLM API Details:** `OPENWEBUI_TOKEN`, `OPENWEBUI_URL` (base URL, e.g., `http://localhost:11434`), `OPENWEBUI_LLM_MODEL` (e.g., `mistral:latest`).
        * **Redis Details:** `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB`, `REDIS_PASSWORD` (if any).
        * **Logging Configuration:**
            * `LOG_LEVEL_MAIN` (e.g., INFO)
            * `LOG_LEVEL_URLANALYSIS` (e.g., WARNING)
            * `LOG_LEVEL_DISCORDPY` (e.g., INFO)
            * `LOG_TO_FILE` (True or False)
            * `LOG_FILE_PATH` (e.g., bot.log)
            * `LOG_FORMAT` (e.g., "%(asctime)s - %(levelname)-8s - %(name)-25s - [%(filename)s:%(lineno)d] - %(message)s")

3.  **Configure the AI Analysis Pipeline:**
    * Review and customize `urlanalysis/analysis_pipeline_config.yaml` to define your desired analysis steps, enable/disable them, and set their corresponding prompt files.
    * Edit the prompt files in `urlanalysis/prompts/` to tailor the AI's behavior for each step and the final decision. **This is critical for accuracy.** For example, the `ssl_certificate_assessment_prompt.txt` now utilizes a `{current_date_iso}` placeholder.

4.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Install Playwright browsers** (if any Playwright-dependent steps are enabled):
    ```bash
    python -m playwright install
    ```

## Required Bot Permissions (Discord)

* View Channels
* Send Messages
* Read Message History
* Manage Roles
* Embed Links
* Attach Files (for detailed AI analysis reports)
* Add Reactions

**Important:** Enable **Message Content Intent**, **Server Members Intent**, and **Guilds Intent** for your bot in the Discord Developer Portal.

## Running the Bot

The primary method for running the bot is via Docker:

```bash
docker-compose up -d
```
Alternatively, for local development (after installation steps):

```bash
python main.py
```