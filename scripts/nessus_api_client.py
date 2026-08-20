import json
import os
import ssl
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


def _load_repo_env() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


_load_repo_env()


class NessusApiClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.context = ssl.create_default_context() if verify_ssl else self._insecure_context()
        self.token = self._login()

    @staticmethod
    def _insecure_context() -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _request(self, path: str, method: str = "GET", payload: Dict[str, Any] | None = None) -> Any:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"X-Cookie": f"token={self.token}"} if hasattr(self, "token") else {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(request, context=self.context) as response:
            return json.loads(response.read().decode("utf-8"))

    def _login(self) -> str:
        body = json.dumps({"username": self.username, "password": self.password}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/session",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, context=self.context) as response:
            return json.loads(response.read().decode("utf-8"))["token"]

    def list_scans(self) -> List[Dict[str, Any]]:
        response = self._request("/scans")
        scans = response.get("scans", []) if isinstance(response, dict) else []
        return [scan for scan in scans if isinstance(scan, dict)]

    def download_scan(self, scan_id: int, output_path: Path, poll_seconds: int = 5) -> None:
        export = self._request(f"/scans/{scan_id}/export", "POST", {"format": "nessus"})
        file_id = export["file"]

        while True:
            status = self._request(f"/scans/{scan_id}/export/{file_id}/status").get("status")
            if status == "ready":
                break
            if status in {"error", "failed"}:
                raise RuntimeError(f"Nessus export failed for scan {scan_id}: {status}")
            time.sleep(poll_seconds)

        request = urllib.request.Request(
            f"{self.base_url}/scans/{scan_id}/export/{file_id}/download",
            headers={"X-Cookie": f"token={self.token}"},
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(request, context=self.context) as response:
            output_path.write_bytes(response.read())

        if output_path.stat().st_size == 0:
            raise RuntimeError(f"Nessus returned an empty export for scan {scan_id}")


def configured_nessus_client(base_url: str | None = None) -> NessusApiClient:
    base_url = base_url or os.getenv("NESSUS_URL") or os.getenv("NESSUS_OP_URL")
    username = os.getenv("NESSUS_USERNAME")
    password = os.getenv("NESSUS_PASSWORD") or os.getenv("NESSUS_OP_PASSWORD")
    if not base_url or not username or not password:
        raise RuntimeError(
            "Set NESSUS_URL, NESSUS_USERNAME, and NESSUS_PASSWORD "
            "(or NESSUS_OP_URL and NESSUS_OP_PASSWORD)."
        )
    return NessusApiClient(base_url, username, password)
