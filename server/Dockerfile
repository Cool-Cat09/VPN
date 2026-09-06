FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
WORKDIR /app
COPY pyproject.toml ./
RUN uv sync --no-dev --no-install-project
RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 && \
    rm -rf /var/lib/apt/lists/*
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iproute2 \
    procps && \
    rm -rf /var/lib/apt/lists/*
COPY . .
ENTRYPOINT [ "uv", "run", "server.py" ] 
CMD [ "-b", "--bind", "-p", "--port" ]