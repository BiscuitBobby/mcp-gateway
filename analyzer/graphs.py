from collections import defaultdict

def init_graph_state():
    return {
        "ratings": defaultdict(int),
        "threats": 0,
        "threat_severity": {"low": 0, "medium": 0, "high": 0},
        "threat_types": defaultdict(int),
        "rating_sum": 0,
        "rating_count": 0,
        "min_rating": float('inf'),
        "max_rating": 0,
    }

def build_graph_payload(scans, state=None):
    if state is None:
        state = init_graph_state()

    for scan in scans:
        rating = scan.get("rating")
        is_threat = scan.get("threat")
        category = scan.get("category")

        # Rating distribution and statistics
        if rating is not None:
            state["ratings"][rating] += 1
            state["rating_sum"] += rating
            state["rating_count"] += 1
            state["min_rating"] = min(state["min_rating"], rating)
            state["max_rating"] = max(state["max_rating"], rating)

            # Threat severity (only for threats)
            if is_threat:
                if rating <= 3:
                    state["threat_severity"]["low"] += 1
                elif rating <= 7:
                    state["threat_severity"]["medium"] += 1
                else:
                    state["threat_severity"]["high"] += 1

        # Count threats
        if is_threat:
            state["threats"] += 1

            # ---- Threat type classification ----

            # Prefer structured category
            if category:
                threat_type = category.strip().lower()

            # Fallback to keyword heuristics only if category missing
            else:
                threat_type = "unknown"

            state["threat_types"][threat_type] += 1

    return state


def finalize_graph(state):
    """
    Only calculate derived values at the very end.
    All heavy lifting is done incrementally in build_graph_payload.
    """
    # Calculate average rating (O(1) operation)
    avg_rating = (state["rating_sum"] / state["rating_count"]) if state["rating_count"] > 0 else 0
    
    # Handle edge case
    min_rating = state["min_rating"] if state["min_rating"] != float('inf') else 0
    
    # Calculate percentages only once at the end (O(1) per category)
    threat_total = state["threats"]
    severity_percentages = {
        "low": (state["threat_severity"]["low"] / threat_total * 100) if threat_total > 0 else 0,
        "medium": (state["threat_severity"]["medium"] / threat_total * 100) if threat_total > 0 else 0,
        "high": (state["threat_severity"]["high"] / threat_total * 100) if threat_total > 0 else 0,
    }
    
    threat_type_percentages = {
        threat_type: (count / threat_total * 100) if threat_total > 0 else 0
        for threat_type, count in state["threat_types"].items()
    }
    
    return {
        # Graph 1: Rating Distribution
        "rating_distribution": dict(state["ratings"]),
        
        # Graph 2: Threat Severity Breakdown
        "threat_severity_breakdown": {
            "counts": state["threat_severity"],
            "percentages": severity_percentages,
            "total_threats": threat_total,
        },
        
        # Graph 3: Threat Types Distribution
        "threat_types_distribution": {
            "counts": dict(state["threat_types"]),
            "percentages": threat_type_percentages,
        },
        
        # Graph 4: Rating Statistics
        "rating_statistics": {
            "average": round(avg_rating, 2),
            "min": min_rating,
            "max": state["max_rating"],
            "total_scans": state["rating_count"],
            "threat_rate": round((threat_total / state["rating_count"] * 100), 2) if state["rating_count"] > 0 else 0,
        },
        
        # Legacy
        "threats": threat_total,
    }