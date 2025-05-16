# Discord Link Scanner Bot

This Discord bot automatically scans messages in a server for URLs. It uses a sophisticated analysis library (`url_analyzer.py`) to check if the links exhibit characteristics of scams or malicious sites. If a link is deemed suspicious based on a configurable threshold, the bot takes predefined actions.

## Features

*   Monitors all messages in the servers it's added to.
*   Detects URLs within message content.
*   Analyzes detected URLs using multiple checks (URL structure, reachability, DNS, SSL, WHOIS, page content extraction via headless browser).
*   Flags links as suspicious based on a configurable risk threshold.
*   **Adds Reactions:** Adds ✅ to messages with analyzed, non-suspicious links and 🚨 to messages with suspicious links.
*   **Sends Detailed Alerts:** Posts an alert message to a specific moderator channel when a suspicious link is found, **including the full JSON analysis report as an attachment**.
*   Notifies designated users via Direct Message about suspicious links.
*   Assigns a specific role to the user who posted the suspicious link.
*   Configurable via a `.env` file.
*   Uses `discord.py` Cogs for organization.
*   Clean startup structure (`main.py` -> `bot.py` -> cogs).

## Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)
*   Access to a Discord server where you have permissions to add bots and manage roles/channels.
*   A Discord Bot Token.

## Installation

1.  **Clone the repository or download the files:**
    ```bash
    git clone <repository_url> # Or download and extract the ZIP
    cd discord-link-scanner
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install Playwright browsers:** (Required by `url_analyzer.py`)
    ```bash
    python -m playwright install
    ```

## Configuration

1.  **Create a `.env` file** in the root directory by copying `.env.example` or creating it manually.

2.  **Edit the `.env` file** and fill in the required values:
    *   `DISCORD_BOT_TOKEN`: Your unique bot token.
    *   `SUSPICIOUS_CHANNEL_ID`: Numerical ID of the moderator alert channel.
    *   `NOTIFY_USER_IDS`: Comma-separated list of numerical User IDs for DM alerts.
    *   `SUSPICIOUS_ROLE_ID`: Numerical ID of the role to assign.
    *   `SUSPICION_THRESHOLD`: Integer (e.g., `3`) defining the number of risk flags needed to trigger actions.

## Required Bot Permissions

When inviting your bot, ensure it has these permissions:

*   **View Channels**
*   **Send Messages**
*   **Read Message History**
*   **Manage Roles**
*   **Embed Links**
*   **Attach Files:** Required to send the JSON analysis report.
*   **Add Reactions:** Required to react to messages with ✅ or 🚨.

**Important:** Enable the **Message Content Intent**, **Server Members Intent**, and potentially the **Presence Intent** (if using presence) for your bot in the Discord Developer Portal.

## Running the Bot

```bash
python main.py
```


## How Suspicion is Determined

The bot uses the url_analyzer.py library, which performs several checks:

*    **URL Structure**: Looks for typosquatting, deceptive subdomains, IP addresses instead of domains, risky TLDs, Punycode.

*    **Reachability**: Checks if the URL is live and gets the final status code after redirects.

*    **DNS Records**: Fetches A, AAAA, MX, NS, TXT records.

*    **SSL Certificate**: Validates the certificate, checks expiry, hostname match, and issuer.

*    **WHOIS Info**: Retrieves domain registration details (creation date, registrar, status). Flags recently registered domains.

*    **Page Content**: Uses a headless browser (Playwright) to visit the page (carefully!) and extracts title, meta tags, links, scripts, forms, and a text preview. Checks for insecure password forms.

The analyze_url function returns a JSON report summarizing these findings, including a list called potential_risks. The bot compares the number of risks in this list to the SUSPICION_THRESHOLD set in your .env file. If the count meets or exceeds the threshold, the link is flagged.

## Disclaimer

This bot is a tool to assist in identifying potentially harmful links. It is not foolproof.

*    **False Positives**: Legitimate links might occasionally be flagged.

*    **False Negatives**: Malicious links might evade detection.

*    **Resource Intensive**: Analyzing links, especially using the headless browser, can consume CPU and RAM. Monitor performance.

*    **Security**: Analyzing unknown links inherently carries some risk, although Playwright runs browsers in a sandboxed environment. Run the bot on a secure system.
