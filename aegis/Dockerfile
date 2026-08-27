# Pin by digest in production: python:3.12-slim@sha256:<digest>
FROM python:3.12-slim AS build
WORKDIR /app
RUN pip install --no-cache-dir uv
COPY pyproject.toml ./
COPY src ./src
COPY configs ./configs
COPY web ./web
RUN uv venv && uv pip install --no-cache .

FROM python:3.12-slim
RUN useradd --uid 10001 --no-create-home aegis
WORKDIR /app
COPY --from=build /app /app
USER 10001
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "--factory", "aegis.api.v1.app:create_app", "--host", "0.0.0.0", "--port", "8000"]
