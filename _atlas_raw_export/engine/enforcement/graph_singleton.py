# engine/enforcement/graph_singleton.py
from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional, Tuple

import requests


def graph_get_json(url: str, headers: dict, timeout: int = 30) -> Tuple[int, dict, str]:
    r = requests.get(url, headers=headers, timeout=timeout)
    text = r.text or ""
    try:
        data = r.json() if r.status_code < 400 else {}
    except Exception:
        data = {}
    return r.status_code, (data or {}), text


def graph_patch_json(url: str, headers: dict, payload: dict, timeout: int = 30) -> Tuple[int, dict, str]:
    h = {**headers, "Content-Type": "application/json"}
    r = requests.patch(url, headers=h, json=payload, timeout=timeout)
    text = r.text or ""
    try:
        data = r.json() if (r.text and r.status_code < 400) else {}
    except Exception:
        data = {}
    return r.status_code, (data or {}), text
def graph_put_json(url: str, headers: dict, payload: dict, timeout: int = 30) -> Tuple[int, dict, str]:
    h = {**headers, "Content-Type": "application/json"}
    r = requests.put(url, headers=h, json=payload, timeout=timeout)
    text = r.text or ""
    try:
        data = r.json() if (r.text and r.status_code < 400) else {}
    except Exception:
        data = {}
    return r.status_code, (data or {}), text


def verify_with_retries(
    get_fn: Callable[[], Tuple[int, dict, str]],
    is_desired_fn: Callable[[dict], bool],
    attempts: int = 5,
    delay_seconds: float = 2.0,
) -> Tuple[int, dict, str, int]:
    """
    Returns: (status, body, text, attempt_index_used)
    attempt_index_used is 1-based.
    """
    last = (0, {}, "", 0)
    for i in range(1, max(1, attempts) + 1):
        status, body, text = get_fn()
        last = (status, body, text, i)
        if status < 400 and is_desired_fn(body or {}):
            return status, (body or {}), (text or ""), i
        if i < attempts:
            time.sleep(delay_seconds)
    return last
