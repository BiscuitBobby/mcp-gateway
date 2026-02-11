# Quick Start

Follow these steps to get the project up and running.

## First-Time Setup

Install Python dependencies and bootstrap OpenTelemetry:

```bash
pip install -r requirements.txt
opentelemetry-bootstrap -a install
```

---

## Start Observability Stack (Jaeger + OpenSearch)

This will start Jaeger, OpenSearch, the OTEL Collector, and related services via Docker Compose.

```bash
cd services
docker compose -f docker-compose.yml up
```

> Make sure Docker is installed and running before executing this step.

---

## Run the Application Server

From the project root directory:

```bash
python main.py
```

---


Once the server is running, your application should be available and connected to the observability stack.

If needed, you can stop the Docker services with:

```bash
docker compose down
```
