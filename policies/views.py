from .models import GlobalPolicyRequest, PolicyRequest
from fastapi import APIRouter, HTTPException
from config import settings
from typing import Dict
import json
import os


router = APIRouter()

CONFIG_FILE = "config.json"
POLICY_MAP_FILE = f"{settings.temp_dir}/key_policies.json"
GLOBAL_POLICIES = f"{settings.temp_dir}/policies.json"


def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    with open(path, "w") as f:
        json.dump(default, f, indent=2)
    return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def initialize_policy_map():
    if not os.path.exists(CONFIG_FILE):
        raise RuntimeError("config.json not found")

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    policy_map = load_json(POLICY_MAP_FILE, {})

    for key in config.keys():
        policy_map.setdefault(key, [])

    save_json(POLICY_MAP_FILE, policy_map)

initialize_policy_map()


@router.post("/add")
def add_policy(payload: PolicyRequest):
    policy_map = load_json(POLICY_MAP_FILE, {})

    policy_map.setdefault(payload.key, [])

    if payload.policy_name not in policy_map[payload.key]:
        policy_map[payload.key].append(payload.policy_name)

    save_json(POLICY_MAP_FILE, policy_map)

    return {"status": "ok", "key": payload.key, "policies": policy_map[payload.key]}


@router.post("/remove")
def remove_policy(payload: PolicyRequest):
    policy_map = load_json(POLICY_MAP_FILE, {})

    if payload.key in policy_map and payload.policy_name in policy_map[payload.key]:
        policy_map[payload.key].remove(payload.policy_name)
        save_json(POLICY_MAP_FILE, policy_map)
        return {"status": "ok"}

    raise HTTPException(status_code=404, detail="Policy or key not found")


@router.get("/{key}")
def get_policies(key: str):
    policy_map = load_json(POLICY_MAP_FILE, {})
    return {"key": key, "policies": policy_map.get(key, [])}


@router.post("/create")
def add_global_policy(payload: GlobalPolicyRequest):
    policies = load_json(GLOBAL_POLICIES, {})

    if payload.name in policies:
        raise HTTPException(status_code=400, detail="Policy already exists")

    policies[payload.name] = payload.description or ""

    save_json(GLOBAL_POLICIES, policies)

    return {
        "status": "ok",
        "policy": {
            "name": payload.name,
            "description": policies[payload.name],
        },
    }


@router.delete("/delete/{policy_name}")
def delete_global_policy(policy_name: str):
    policies = load_json(GLOBAL_POLICIES, {})
    policy_map = load_json(POLICY_MAP_FILE, {})

    if policy_name not in policies:
        raise HTTPException(status_code=404, detail="Policy not found")

    used_by = [k for k, v in policy_map.items() if policy_name in v]
    if used_by:
        raise HTTPException(
            status_code=409,
            detail=f"Policy in use by keys: {used_by}",
        )

    del policies[policy_name]
    save_json(GLOBAL_POLICIES, policies)

    return {"status": "ok", "deleted": policy_name}


@router.get("/")
def all_policies() -> Dict:
    return load_json(GLOBAL_POLICIES, {})
