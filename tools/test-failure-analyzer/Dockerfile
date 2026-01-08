FROM python:3.11-slim

WORKDIR /app

# Needed for cloning system-tests at a specific ref (agent branch) at runtime.
RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

ENV WORKDIR=/work
RUN mkdir -p /work

ENTRYPOINT ["python", "/app/agent_entrypoint.py"]



