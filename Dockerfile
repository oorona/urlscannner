# Dockerfile

# 1. Base Image: Use an official Playwright image which includes Node, Python,
#    and crucially, the necessary OS dependencies for the browsers.
#    Choose a version compatible with your Playwright version (check requirements.txt if specific)
#    Using Jammy (Ubuntu 22.04 LTS based) is a good choice.
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

# 2. Set Environment Variables (Optional but recommended)
ENV PYTHONUNBUFFERED=1 \
    # Set Playwright's browsers path if needed explicitly, though defaults usually work
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# 3. Set Working Directory
WORKDIR /app

# 4. Install system packages if any additional are needed (e.g., whois CLI if python-whois relies on it)
#    The playwright base image is quite complete, so likely not needed unless a dependency fails.
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     whois \
#  && apt-get clean && rm -rf /var/lib/apt/lists/*

# 5. Copy requirements file first to leverage Docker cache
COPY requirements.txt .

# 6. Install Python dependencies
#    --no-cache-dir reduces image size slightly
RUN pip install --no-cache-dir -r requirements.txt

# 7. Install Playwright browsers *within* the image layer
#    Even though the base image has OS deps, this downloads the browser binaries.
#    Use --with-deps just in case, although base image should suffice.
RUN playwright install --with-deps
# Optional: Install only specific browsers if you know you only use one (e.g., chromium)
# RUN playwright install chromium --with-deps

# 8. Copy the rest of the application code
COPY . .

# 9. Create a non-root user and switch to it (Good Practice)
#    Run installs as root, then switch user.
RUN useradd --create-home --shell /bin/bash appuser
USER appuser
WORKDIR /home/appuser/app # Adjust WORKDIR if needed after user switch, but /app should be owned by root now. Let's copy again to user home dir? No, let's keep /app but grant permissions maybe.
# Re-copying to user's home is cleaner:
USER root
COPY --chown=appuser:appuser . /home/appuser/app
USER appuser
WORKDIR /home/appuser/app


# 10. Command to run the application
#     Use main.py as the entry point
CMD ["python", "main.py"]