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
    # Core Methods
    "initialize",
    "initialized",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "prompts/list",
    "prompts/get",
    "tools/list",
    "tools/call",
    "logging/setLevel",
    "sampling/createMessage",
    "elicitation/create",
    "completion/complete",
    "$/cancelRequest",
    # Notifications
    "notifications/initialized",
    "notifications/message",
    "notifications/progress",
    "notifications/tasks/list_changed",
    "notifications/tasks/status",
    "notifications/resources/list_changed",
    "notifications/prompts/list_changed",
    "notifications/tools/list_changed",
}

# Key identifiers found in packets/JSON objects
MCP_KEYWORDS = {
    # Identity & Versioning
    "capabilities",
    "serverInfo",
    "instructions",
    "mcp-session-id",
    "mcp-protocol-version",
    # Transport & Config
    "transportType",
    "connectionType",
    "proxyFullAddress",
    "sseUrl",
    # Proxy/Auth
    "x-mcp-proxy-auth",
    "x-custom-auth-header",
    "x-custom-auth-headers",
    "client_id",
    "client_secret",
    "oauthScope",
    # Features
    "sampling",
    "elicitation",
    "roots",
}

# Patterns for headers found in HTTP/SSE transmissions
HEADER_PATTERNS = {
    "session_id": re.compile(r"mcp-session-id:\s*([^\r\n]+)", re.I),
    "protocol_version": re.compile(r"mcp-protocol-version:\s*([^\r\n]+)", re.I),
    "proxy_auth": re.compile(r"x-mcp-proxy-auth:\s*([^\r\n]+)", re.I),
    "custom_auth": re.compile(r"x-custom-auth-header:\s*([^\r\n]+)", re.I),
    "custom_headers": re.compile(r"x-custom-auth-headers:\s*([^\r\n]+)", re.I),
}

# Per-flow session cache: maps flow-key -> {session data}
# Keyed without src_port so all connections to the same server share session info.
_flow_sessions = {}
_flow_lock = threading.Lock()


def _find_next_brace_block(text, start):
    """Find the next balanced {…} block starting at or after `start`."""
    open_pos = text.find("{", start)
    if open_pos == -1:
        return None, -1

    count = 0
    for i in range(open_pos, len(text)):
        if text[i] == "{":
            count += 1
        elif text[i] == "}":
            count -= 1
        if count == 0:
            return text[open_pos : i + 1], i + 1

    return None, -1


def _try_parse_jsonrpc(raw_json):
    """Parse a JSON string, returning the object only if it looks like JSON-RPC."""
    try:
        obj = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError):
        return None

    if isinstance(obj, dict) and (obj.get("jsonrpc") == "2.0" or "method" in obj):
        return obj
    return None


def extract_json_rpc(text):
    """URL-independent extraction of JSON-RPC objects."""
    clean_text = re.sub(r"^data:\s*", "", text, flags=re.MULTILINE)
    results = []
    pos = 0

    while pos < len(clean_text):
        raw_json, end = _find_next_brace_block(clean_text, pos)
        if raw_json is None:
            break

        obj = _try_parse_jsonrpc(raw_json)
        if obj is not None:
            results.append(obj)

        pos = end

    return results


def _dict_scan_keywords(d):
    """Deep scan a dict for any MCP keywords."""
    if not isinstance(d, dict):
        return False

    found_key = False
    # Check keys
    if any(key in d for key in MCP_KEYWORDS):
        found_key = True

    # Recursively check nested dicts
    for v in d.values():
        if isinstance(v, dict) and _dict_scan_keywords(v) and found_key:
            return True
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict) and _dict_scan_keywords(item) and found_key:
                    return True
    return False


def is_mcp_content(rpc_objects, payload):
    """Fingerprints content to see if it belongs to MCP."""
    for name, p in HEADER_PATTERNS.items():
        if p.search(payload):
            print(f"\n{payload}\n")
            return True, f"Header Match: {name}"

    for obj in rpc_objects:
        method = obj.get("method")
        if method in MCP_METHODS:
            print(f"\n{payload}\n")
            return True, f"Method Match: {method}"

        # Scan params/result/error for keywords
        if _dict_scan_keywords(obj):
            print(f"\n{payload}\n")
            return True, "Keyword Match in JSON Body"

    return False, None


def flow_to_trace_id(src_ip, src_port, dst_ip, dst_port):
    """Derive a stable 128-bit OTel trace_id from the TCP 4-tuple."""
    flow = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    digest = hashlib.md5(flow.encode()).digest()
    hi, lo = struct.unpack(">QQ", digest)
    return (hi << 64) | lo


def _flow_key(ip, tcp):
    """Key for the session cache — ignores src_port so all connections to the same server share state."""
    return (ip.src, ip.dst, tcp.dport)


def _extract_headers_from_payload(payload):
    """Pull MCP-related header values out of a raw payload."""
    data = {}
    for name, p in HEADER_PATTERNS.items():
        match = p.search(payload)
        if match:
            data[name] = match.group(1).strip()
    return data


def _cache_session_data(key, new_data):
    """Merge new_data into the flow session cache and return the merged result."""
    with _flow_lock:
        existing = _flow_sessions.get(key, {})
        existing.update(new_data)
        _flow_sessions[key] = existing
        return dict(existing)


def _extract_mcp_session_data(obj, payload, ip, tcp):
    """Extract session data from headers/body, merging with the per-flow cache."""
    data = _extract_headers_from_payload(payload)

    # Check JSON body for specific fields
    if isinstance(obj, dict):
        if "mcp-session-id" in obj:
            data["session_id"] = obj["mcp-session-id"]

        for area in (obj.get("params", {}), obj.get("result", {})):
            if isinstance(area, dict):
                if "mcp-session-id" in area:
                    data["session_id"] = area["mcp-session-id"]
                if "transportType" in area:
                    data["transport_type"] = area["transportType"]
                if "connectionType" in area:
                    data["connection_type"] = area["connectionType"]

    # Merge with (and update) the per-flow cache
    key = _flow_key(ip, tcp)
    return _cache_session_data(key, data)


def _set_network_attributes(span, ip, tcp):
    span.set_attribute("net.transport", "ip_tcp")
    span.set_attribute("net.peer.ip", ip.src)
    span.set_attribute("net.peer.port", tcp.sport)
    span.set_attribute("net.host.ip", ip.dst)
    span.set_attribute("net.host.port", tcp.dport)


def _set_mcp_attributes(span, obj, method, reason, session_data):
    span.set_attribute("rpc.system", "jsonrpc")
    span.set_attribute("rpc.method", method)
    span.set_attribute("rpc.jsonrpc.version", obj.get("jsonrpc", "2.0"))
    span.set_attribute("rpc.jsonrpc.request_id", str(obj.get("id", "")))
    span.set_attribute("mcp.match_reason", reason)

    # Add session data as attributes
    for k, v in session_data.items():
        span.set_attribute(f"mcp.{k}", v)


def _add_payload_events(span, obj):
    for key in ("params", "result"):
        if key in obj:
            span.add_event(key, {"message": str(obj[key])[:500]})

    if "error" in obj:
        err = obj["error"]
        span.add_event("error", {"message": str(err)[:500]})
        span.set_status(StatusCode.ERROR, description=str(err.get("message", "")))
    else:
        span.set_status(StatusCode.OK)


def emit_span(packet, obj, reason, payload):
    """Create and export a real OpenTelemetry span for one JSON-RPC object."""
    ip, tcp = packet[IP], packet[TCP]

    session_data = _extract_mcp_session_data(obj, payload, ip, tcp)

    # Trace ID remains flow-based, but includes session identification as attributes
    trace_id = flow_to_trace_id(ip.src, tcp.sport, ip.dst, tcp.dport)
    span_id = random.getrandbits(64)

    remote_ctx = trace.span.SpanContext(
        trace_id=trace_id,
        span_id=span_id,
        is_remote=True,
        trace_flags=trace.TraceFlags(0x01),
    )

    method = obj.get("method", "jsonrpc.response")

    with tracer.start_as_current_span(
        name=method,
        kind=SpanKind.CLIENT,
        links=[trace.Link(context=remote_ctx)],
    ) as span:
        _set_network_attributes(span, ip, tcp)
        _set_mcp_attributes(span, obj, method, reason, session_data)
        _add_payload_events(span, obj)

    sid = session_data.get("session_id", "no-session-id")
    print(
        f"[span] {method} | SID: {sid[:8]}... | {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} | {reason}"
    )


def process_packet(packet):
    if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
        return

    try:
        payload = packet[Raw].load.decode(errors="ignore")
    except Exception:
        return

    # Always cache any MCP headers we see, even in packets with no JSON body.
    # This bridges the TCP segmentation gap.
    ip, tcp = packet[IP], packet[TCP]
    header_data = _extract_headers_from_payload(payload)
    if header_data:
        _cache_session_data(_flow_key(ip, tcp), header_data)

    rpc_objects = extract_json_rpc(payload)
    is_mcp, reason = is_mcp_content(rpc_objects, payload)
    if not is_mcp:
        return

    for obj in rpc_objects:
        emit_span(packet, obj, reason, payload)


def _sniff_interface(iface):
    sniff(iface=iface, filter="tcp", prn=process_packet, store=False)


def main():
    interfaces = get_if_list()
    print("[*] MCP Recon — Enhanced OpenTelemetry tracing active")
    print(f"[*] Exporting spans to http://localhost:4317")
    print(f"[*] Listening on {len(interfaces)} interface(s): {', '.join(interfaces)}")

    threads = [
        threading.Thread(target=_sniff_interface, args=(iface,), daemon=True)
        for iface in interfaces
    ]
    for t in threads:
        t.start()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] Stopping — flushing spans...")
        provider.force_flush()
        print("[*] Done.")


if __name__ == "__main__":
    main()
