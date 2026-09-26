FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (build tools, procps for process inspection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py", "server", "--host", "0.0.0.0", "--port", "8000"]
