# just for demo

database = dict()

def deep_update(dst: dict, src: dict):
    for k, v in src.items():
        if isinstance(v, dict):
            dst[k] = deep_update(dst.get(k, {}), v)
        else:
            dst[k] = v
    return dst


def get_scan_id(traceparent: str) -> str:
    parts = traceparent.split("-")
    if len(parts) < 2 or not parts[1]:
        raise ValueError("Invalid traceparent")

    return parts[1]

def store(scan_id: str, text_type: str, text: str, scan_results: dict):
    if scan_id not in database:
        database[scan_id] = {
            "input": None,
            "output": None,
            "scans": {}
        }

    database[scan_id][text_type] = text

    report = {
        "scans": scan_results
    }

    deep_update(database[scan_id], report)

    return database[scan_id]
