from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from scapy.all import sniff, TCP, IP, Raw, get_if_list
from opentelemetry.trace import SpanKind, StatusCode
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry import trace
import threading
import hashlib
import struct
import random
import json
import time
import re


# --- OpenTelemetry Setup ---
resource = Resource.create({"service.name": "MCP Recon"})
provider = TracerProvider(resource=resource)
processor = BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4317"))
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)

tracer = trace.get_tracer("mcp.recon")

# --- MCP Protocol Fingerprints ---
MCP_METHODS = {
    "initialize",
    "initialized",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "tools/list",
    "tools/call",
    "logging/setLevel",
    "sampling/createMessage",
    "elicitation/create",
}

# Keys typically found in MCP initialize/capabilities objects
MCP_KEYWORDS = {"capabilities", "serverInfo", "instructions", "mcp-session-id"}

# Patterns for headers (still useful if they exist, but not required)
HEADER_PATTERNS = {
    "session_id": re.compile(r"mcp-session-id:\s*([^\r\n]+)", re.I),
    "protocol_version": re.compile(r"mcp-protocol-version:\s*([^\r\n]+)", re.I),
}


def extract_json_rpc(text):
    """URL-independent extraction of JSON-RPC objects."""
    results = []
    # Strip SSE 'data: ' prefix if present, but keep the JSON
    clean_text = re.sub(r"^data:\s*", "", text, flags=re.MULTILINE)

    start = 0
    while True:
        start = clean_text.find("{", start)
        if start == -1:
            break

        count = 0
        for i in range(start, len(clean_text)):
            if clean_text[i] == "{":
                count += 1
            elif clean_text[i] == "}":
                count -= 1

            if count == 0:
                try:
                    obj = json.loads(clean_text[start : i + 1])
                    if isinstance(obj, dict) and (
                        obj.get("jsonrpc") == "2.0" or "method" in obj
                    ):
                        results.append(obj)
                    start = i + 1
                    break
                except:
                    break
        else:
            break
        start += 1
    return results


def is_mcp_content(rpc_objects, payload):
    """Fingerprints content to see if it belongs to MCP."""
    for obj in rpc_objects:
        method = obj.get("method")
        if method in MCP_METHODS:
            return True, f"Method Match: {method}"

        params = obj.get("params", {})
        if isinstance(params, dict):
            if any(key in params for key in MCP_KEYWORDS):
                return True, "Keyword Match in Params"

        result = obj.get("result", {})
        if isinstance(result, dict):
            if any(key in result for key in MCP_KEYWORDS):
                return True, "Keyword Match in Result"

    if any(p.search(payload) for p in HEADER_PATTERNS.values()):
        return True, "MCP Header Match"

    return False, None


def flow_to_trace_id(src_ip, src_port, dst_ip, dst_port):
    """
    Derive a stable 128-bit OTel trace_id from the TCP 4-tuple.
    OTel expects trace_id as an int (128 bits).
    """
    flow = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    digest = hashlib.md5(flow.encode()).digest()  # 16 bytes
    # Pad to 16 bytes (md5 already is) and interpret as two 64-bit ints
    hi, lo = struct.unpack(">QQ", digest)
    return (hi << 64) | lo  # 128-bit int


def emit_span(packet, obj, reason):
    """Create and export a real OpenTelemetry span for one JSON-RPC object."""
    ip, tcp = packet[IP], packet[TCP]

    trace_id = flow_to_trace_id(ip.src, tcp.sport, ip.dst, tcp.dport)
    span_id = random.getrandbits(64)

    # Build a remote SpanContext so this span is linked to the sniffed flow's trace
    remote_ctx = trace.span.SpanContext(
        trace_id=trace_id,
        span_id=span_id,
        is_remote=True,
        trace_flags=trace.TraceFlags(0x01),  # sampled
    )
    link = trace.Link(context=remote_ctx)

    method = obj.get("method", "jsonrpc.response")
    is_error = "error" in obj

    with tracer.start_as_current_span(
        name=method,
        kind=SpanKind.CLIENT,
        links=[link],
    ) as span:
        # Network attributes (OpenTelemetry semantic conventions)
        span.set_attribute("net.transport", "ip_tcp")
        span.set_attribute("net.peer.ip", ip.src)
        span.set_attribute("net.peer.port", tcp.sport)
        span.set_attribute("net.host.ip", ip.dst)
        span.set_attribute("net.host.port", tcp.dport)

        # JSON-RPC / MCP attributes
        span.set_attribute("rpc.system", "jsonrpc")
        span.set_attribute("rpc.method", method)
        span.set_attribute("rpc.jsonrpc.version", obj.get("jsonrpc", "2.0"))
        span.set_attribute("rpc.jsonrpc.request_id", str(obj.get("id", "")))
        span.set_attribute("mcp.match_reason", reason)

        # Params, result, error as span events (truncated to stay within limits)
        if "params" in obj:
            span.add_event("params", {"message": str(obj["params"])[:500]})

        if "result" in obj:
            span.add_event("result", {"message": str(obj["result"])[:500]})

        if is_error:
            err = obj["error"]
            span.add_event("error", {"message": str(err)[:500]})
            span.set_status(StatusCode.ERROR, description=str(err.get("message", "")))
        else:
            span.set_status(StatusCode.OK)

    print(
        f"[span] {method} | {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} | {reason}"
    )


def process_packet(packet):
    if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
        return

    try:
        payload = packet[Raw].load.decode(errors="ignore")
    except:
        return

    rpc_objects = extract_json_rpc(payload)

    is_mcp, reason = is_mcp_content(rpc_objects, payload)

    if not is_mcp:
        return

    for obj in rpc_objects:
        emit_span(packet, obj, reason)


def main():
    interfaces = get_if_list()
    print("[*] MCP Recon — OpenTelemetry tracing active")
    print(f"[*] Exporting spans to http://localhost:4317")
    print(f"[*] Listening on {len(interfaces)} interface(s): {', '.join(interfaces)}")

    threads = []
    for iface in interfaces:
        def start_sniff(i=iface):
            sniff(iface=i, filter="tcp", prn=process_packet, store=False)

        t = threading.Thread(target=start_sniff, daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] Stopping — flushing spans...")
        provider.force_flush()
        print("[*] Done.")


if __name__ == "__main__":
    main()
