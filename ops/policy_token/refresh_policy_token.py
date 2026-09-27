#!/usr/bin/env python3
"""Renew one OUF workload bearer token without persisting access tokens outside /run."""
import json
import os
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"missing or invalid {name}")
    return value


def config() -> dict:
    gid_text = required("OUF_POLICY_TOKEN_RUNTIME_GID")
    if not gid_text.isdigit():
        raise ValueError("invalid runtime gid")
    gid = int(gid_text)
    endpoint = required("OUF_POLICY_TOKEN_ENDPOINT")
    if not endpoint.startswith("https://"):
        raise ValueError("token endpoint must use HTTPS")
    runtime_dir = Path(required("OUF_POLICY_TOKEN_RUNTIME_DIR"))
    if not runtime_dir.is_absolute() or not str(runtime_dir).startswith("/run/ouf-"):
        raise ValueError("runtime directory must be an absolute /run/ouf-* path")
    secret_file = Path(required("OUF_POLICY_TOKEN_SECRET_FILE"))
    if not secret_file.is_absolute():
        raise ValueError("secret file must be absolute")
    return {
        "client_id": required("OUF_POLICY_TOKEN_CLIENT_ID"),
        "secret_file": secret_file,
        "endpoint": endpoint,
        "runtime_dir": runtime_dir,
        "gid": gid,
        "required_scope": os.environ.get("OUF_POLICY_TOKEN_REQUIRED_SCOPE", "").strip(),
    }


def validate_response(result: dict) -> str:
    token = result.get("access_token")
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 16384
        or any(ch.isspace() for ch in token)
        or str(result.get("token_type", "")).lower() != "bearer"
    ):
        raise ValueError("invalid token response")
    expires = result.get("expires_in")
    if expires is not None and (not isinstance(expires, int) or expires < 30):
        raise ValueError("token lifetime too short")
    return token


def refresh() -> None:
    cfg = config()
    directory = cfg["runtime_dir"]
    directory.mkdir(mode=0o750, parents=False, exist_ok=True)
    os.chown(directory, 0, cfg["gid"])
    os.chmod(directory, 0o750)

    secret = cfg["secret_file"].read_text(encoding="utf-8").strip()
    if not secret or len(secret) > 4096 or any(ch.isspace() for ch in secret):
        raise ValueError("invalid client secret")

    form = {"grant_type": "client_credentials", "client_id": cfg["client_id"], "client_secret": secret}
    if cfg["required_scope"]:
        form["scope"] = cfg["required_scope"]
    body = urllib.parse.urlencode(form).encode("ascii")
    request = urllib.request.Request(
        cfg["endpoint"],
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise ValueError("token endpoint rejected request")
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("token response too large")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("invalid token response")
    token = validate_response(result)

    fd, temporary = tempfile.mkstemp(prefix=".token-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            os.fchown(stream.fileno(), 0, cfg["gid"])
            os.fchmod(stream.fileno(), 0o440)
            stream.write(token)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "token")
        dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        Path(temporary).unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        refresh()
    except Exception:
        raise SystemExit("OUF_POLICY_TOKEN_REFRESH_FAILED")
    print("OUF_POLICY_TOKEN_REFRESH_OK")
