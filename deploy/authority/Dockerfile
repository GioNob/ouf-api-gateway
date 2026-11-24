FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ARG REVISION
LABEL org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source="https://github.com/GioNob/ouf-api-gateway"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY deploy/authority/requirements-authority.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements-authority.txt
COPY tools/analysis_*.py tools/iam_keycloak_decisions.py tools/mcp_dispatch_contract.py tools/authority_host.py tools/
COPY contracts/mcp-capabilities.json contracts/mcp-discovery-review-capabilities.json contracts/semantic-search-batch-v1.json contracts/
COPY deploy/authority/entrypoint.py .
USER 65532:65532
VOLUME ["/tmp"]
ENTRYPOINT ["python", "/app/entrypoint.py"]
