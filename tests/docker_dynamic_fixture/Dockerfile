FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1

RUN python -m pip install --no-cache-dir "mcp>=2.0,<3"

COPY server.py /opt/mcpsentinel-fixture/server.py

ENTRYPOINT ["python", "/opt/mcpsentinel-fixture/server.py"]
