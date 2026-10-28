"""Tiny JSON-file persistence: approved users, pending review cases, daily quotas, audit log."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import date
from pathlib import Path
from typing import Any


class Store:
    def __init__(self, data_dir: str):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "state.json"
        self.log_path = self.dir / "cases.jsonl"
        self._lock = threading.Lock()
        self.state: dict[str, Any] = {"users": {}, "cases": {}, "msgmap": {}, "quota": {}, "seen_unknown": {}}
        if self.path.exists():
            try:
                self.state.update(json.loads(self.path.read_text()))
            except (OSError, json.JSONDecodeError):
                pass

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, ensure_ascii=False, indent=1))
        os.replace(tmp, self.path)

    # users approved at runtime (env ALLOWED_USERS is merged in by the bot)
    def add_user(self, uid: int, name: str) -> None:
        with self._lock:
            self.state["users"][str(uid)] = name
            self._save()

    def remove_user(self, uid: int) -> bool:
        with self._lock:
            existed = self.state["users"].pop(str(uid), None) is not None
            self._save()
            return existed

    def runtime_users(self) -> dict[int, str]:
        return {int(k): v for k, v in self.state["users"].items()}

    # cases
    def put_case(self, case_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self.state["cases"][case_id] = data
            # keep the file small: drop resolved cases older than 14 days
            cutoff = time.time() - 14 * 86400
            self.state["cases"] = {k: v for k, v in self.state["cases"].items()
                                   if v.get("status") == "pending" or v.get("created", 0) > cutoff}
            live = set(self.state["cases"])
            self.state["msgmap"] = {k: v for k, v in self.state["msgmap"].items() if v in live}
            self._save()

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        return self.state["cases"].get(case_id)

    def update_case(self, case_id: str, **kw: Any) -> None:
        with self._lock:
            if case_id in self.state["cases"]:
                self.state["cases"][case_id].update(kw)
                self._save()

    def map_msg(self, admin_msg_id: int, case_id: str) -> None:
        with self._lock:
            self.state["msgmap"][str(admin_msg_id)] = case_id
            self._save()

    def case_for_msg(self, admin_msg_id: int) -> str | None:
        return self.state["msgmap"].get(str(admin_msg_id))

    def pending(self) -> dict[str, dict[str, Any]]:
        return {k: v for k, v in self.state["cases"].items() if v.get("status") == "pending"}

    # last answered case per sender (for follow-up questions)
    def set_last(self, key: str, verdict: str, reply: str) -> None:
        with self._lock:
            self.state.setdefault("last", {})[key] = {"ts": time.time(), "verdict": verdict, "reply": reply}
            self._save()

    def last_case(self, key: str, within: int) -> dict[str, Any] | None:
        rec = self.state.get("last", {}).get(key)
        if rec and time.time() - rec["ts"] <= within:
            return rec
        return None

    # quota
    def take_quota(self, uid: int | str, limit: int) -> bool:
        today = date.today().isoformat()
        with self._lock:
            q = self.state["quota"]
            if q.get("_day") != today:
                q.clear()
                q["_day"] = today
            n = q.get(str(uid), 0)
            if n >= limit:
                return False
            q[str(uid)] = n + 1
            self._save()
            return True

    def should_notify_unknown(self, uid: int) -> bool:
        today = date.today().isoformat()
        with self._lock:
            if self.state["seen_unknown"].get(str(uid)) == today:
                return False
            self.state["seen_unknown"][str(uid)] = today
            self._save()
            return True

    # audit log (redacted text only, no images)
    def log_case(self, record: dict[str, Any]) -> None:
        with self._lock, self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
