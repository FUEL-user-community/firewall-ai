# ══════════════════════════════════════════════════════════════
# Core Defense — AI-Powered Firewall Assistant
# ══════════════════════════════════════════════════════════════
# Build:  docker build -t coredefense .
# Run:    docker run -p 8888:8888 --env-file .env coredefense
# ══════════════════════════════════════════════════════════════

FROM python:3.12-slim

# Prevent Python from buffering stdout/stderr (see logs in real time)
ENV PYTHONUNBUFFERED=1
ENV PORT=8888

WORKDIR /app

# Install dependencies first (cached layer — only rebuilds when requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Remove files the container doesn't need
RUN rm -rf .git .pytest_cache __pycache__ \
    slack_service start_slack_agent.bat \
    .env .env.example \
    core/service_account.json

EXPOSE 8888

# Health check — verify the server is responding
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8888/api/health')" || exit 1

CMD ["python", "server.py"]
