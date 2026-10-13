FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and source first for better layer caching
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install vibeshield core with backend extras
RUN pip install --no-cache-dir -e ".[backend]"

# Copy backend source
COPY backend/ ./backend/

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]