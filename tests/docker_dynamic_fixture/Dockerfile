FROM python:3.12-slim@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65

ENV PYTHONDONTWRITEBYTECODE=1

RUN python -m pip install --no-cache-dir "mcp>=2.0,<3"

COPY server.py /opt/mcpsentinel-fixture/server.py

ENTRYPOINT ["python", "/opt/mcpsentinel-fixture/server.py"]
