#!/usr/bin/env python3
"""Install/update the generic OUF workload policy-token refresher.

Dry-run by default. --apply writes only versioned generic artifacts plus one
non-secret instance configuration and enables the corresponding timer.
"""
import argparse
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REFRESHER = ROOT / "ops/policy_token/refresh_policy_token.py"
SERVICE = ROOT / "ops/policy_token/ouf-policy-token@.service"
TIMER = ROOT / "ops/policy_token/ouf-policy-token@.timer"


def safe_instance(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value):
        raise ValueError("invalid instance")
    return value


def install_file(source: Path, target: Path, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name("." + target.name + ".tmp")
    shutil.copyfile(source, temporary)
    os.chown(temporary, 0, 0)
    os.chmod(temporary, mode)
    os.replace(temporary, target)


def write_config(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o755)
    content = "".join(f"{key}={value}\n" for key, value in values.items())
    temporary = path.with_name("." + path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chown(temporary, 0, 0)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--instance", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--secret-file", required=True, type=Path)
    p.add_argument("--runtime-gid", required=True, type=int)
    p.add_argument("--token-endpoint", required=True)
    p.add_argument("--required-scope", default="authorization.bundle.read")
    p.add_argument("--apply", action="store_true")
    a = p.parse_args()

    instance = safe_instance(a.instance)
    if os.geteuid() != 0:
        p.error("run as root")
    if not a.client_id or any(ch.isspace() for ch in a.client_id):
        p.error("invalid client id")
    if a.runtime_gid <= 0:
        p.error("runtime gid must be positive")
    if not a.token_endpoint.startswith("https://"):
        p.error("token endpoint must use HTTPS")
    secret = a.secret_file.resolve(strict=True)
    st = secret.stat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
        p.error("secret file must be root-owned and inaccessible to group/other")

    runtime_dir = f"/run/ouf-{instance}-auth"
    config = {
        "OUF_POLICY_TOKEN_CLIENT_ID": a.client_id,
        "OUF_POLICY_TOKEN_SECRET_FILE": str(secret),
        "OUF_POLICY_TOKEN_ENDPOINT": a.token_endpoint,
        "OUF_POLICY_TOKEN_RUNTIME_DIR": runtime_dir,
        "OUF_POLICY_TOKEN_RUNTIME_GID": str(a.runtime_gid),
        "OUF_POLICY_TOKEN_REQUIRED_SCOPE": a.required_scope,
    }

    print(f"INSTANCE={instance}")
    print(f"CLIENT_ID={a.client_id}")
    print(f"RUNTIME_DIR={runtime_dir}")
    print("SECRET_VALUE_NOT_READ_OR_PRINTED=true")
    if not a.apply:
        print("POLICY_TOKEN_INSTALL_DRY_RUN_OK=true")
        return

    install_file(REFRESHER, Path("/opt/ouf/ops/refresh-policy-token.py"), 0o755)
    install_file(SERVICE, Path("/etc/systemd/system/ouf-policy-token@.service"), 0o644)
    install_file(TIMER, Path("/etc/systemd/system/ouf-policy-token@.timer"), 0o644)
    write_config(Path(f"/etc/ouf/policy-token/{instance}.conf"), config)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", f"ouf-policy-token@{instance}.timer"], check=True)
    subprocess.run(["systemctl", "start", f"ouf-policy-token@{instance}.service"], check=True)

    token = Path(runtime_dir) / "token"
    token_st = token.stat()
    if (token_st.st_uid, token_st.st_gid, stat.S_IMODE(token_st.st_mode)) != (0, a.runtime_gid, 0o440):
        raise SystemExit("POLICY_TOKEN_INSTALL_FAILED")
    if token_st.st_size <= 0 or token_st.st_size > 16384:
        raise SystemExit("POLICY_TOKEN_INSTALL_FAILED")
    print("POLICY_TOKEN_INSTALL_APPLIED=true")
    print("TOKEN_METADATA_OK=true")


if __name__ == "__main__":
    main()
