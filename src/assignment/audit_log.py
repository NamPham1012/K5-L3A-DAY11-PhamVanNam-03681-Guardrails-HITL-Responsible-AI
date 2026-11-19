"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations
import time
import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Lưu input và thời điểm bắt đầu xử lý."""

        key = request_id or user_id

        self._open[key] = {
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_clock": time.perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Ghép output với input và lưu bản ghi audit."""

        key = request_id or user_id
        request_data = self._open.pop(key, None)

        # Nếu không tìm thấy input tương ứng, vẫn ghi nhận output.
        if request_data is None:
            request_data = {
                "request_id": request_id,
                "user_id": user_id,
                "input": None,
                "started_at": None,
                "started_clock": None,
            }

        started_clock = request_data.pop("started_clock")
        latency_ms = (
            round((time.perf_counter() - started_clock) * 1000, 2)
            if started_clock is not None
            else None
        )

        request_data.update(
            {
                "output": text,
                "blocked": blocked,
                "layer": layer,
                "finished_at": utc_now_iso(),
                "latency_ms": latency_ms,
            }
        )

        self.logs.append(request_data)

    def export_json(self, filepath: str | None = None):
        """Ghi audit log ra file JSON."""

        path = Path(filepath or default_audit_log_path())

        # Tạo thư mục chứa file nếu chưa tồn tại.
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as file:
            json.dump(self.logs, file, ensure_ascii=False, indent=2)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
