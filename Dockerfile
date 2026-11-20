FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -e .

ENV CANARY_LOG=/data/canary_events.jsonl
VOLUME /data

EXPOSE 8000
CMD ["mcp-canary", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
