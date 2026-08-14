FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

ENV PYTHONDONTWRITEBYTECODE=1

RUN python -m pip install --no-cache-dir "mcp>=2.0,<3"

COPY server.py /opt/mcpsentinel-fixture/server.py

ENTRYPOINT ["python", "/opt/mcpsentinel-fixture/server.py"]
