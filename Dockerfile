FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY data/lead_rules_catalog.json data/

# Install package with all extras
RUN pip install --no-cache-dir .[all]

# Download spaCy model for ML layer
RUN python -m spacy download en_core_web_lg

# Create data directories
RUN mkdir -p data/raw data/sanitized data/output

ENTRYPOINT ["precinct6-dataset"]
CMD ["--help"]
