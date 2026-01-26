# Quick start

first time setup
```
pip install -r requirements.txt
opentelemetry-bootstrap -a install
```

set up open telemetry:
https://opentelemetry.io/docs/collector/quick-start/

```
opentelemetry-instrument \
  --service_name my-fastmcp-server \
  --exporter_otlp_endpoint http://localhost:4317 \
  fastmcp run server.py --transport http
```

get jaegar up and running
```
docker run --rm --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  -p 4318:4318 \
  -p 5778:5778 \
  -p 9411:9411 \
  cr.jaegertracing.io/jaegertracing/jaeger:latest
```
