# Use Python 3.12 slim as base image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies required for Chrome/Chromium and Playwright
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libwayland-client0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    libu2f-udev \
    libvulkan1 \
    curl \
    espeak-ng \
    && rm -rf /var/lib/apt/lists/*

# Install uv (Python package manager) for browser-use
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    /root/.local/bin/uvx --version

# Set environment variables early so playwright install uses the correct path
ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=0
ENV PATH="/root/.local/bin:/root/.cargo/bin:${PATH}"

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium) into PLAYWRIGHT_BROWSERS_PATH
RUN playwright install chromium
RUN playwright install-deps chromium

# Copy application code
COPY src/ ./src/
COPY .env.example .env

# Create logs directory
RUN mkdir -p src/logs

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "src/main.py"]
