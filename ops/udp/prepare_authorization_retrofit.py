#!/usr/bin/env python3
"""Prepare a private Authorization retrofit candidate for an already-staged R4a UDP.

This is deliberately separate from the initial R4a search rollout. It snapshots
the current live UDP, proves the search binding is already present, and adds only
the Authorization registry environment. No running container is changed.
"""
import argparse, json, os, re, stat, subprocess, tempfile
from pathlib import Path

AUTH_ENV={
    "OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE":"/run/ouf-udp-auth/token",
    "OUF_AUTHORIZATION_REFRESH_SECONDS":"30",
    "OUF_AUTHORIZATION_MAX_STALENESS_SECONDS":"300",
}
SEARCH_REQUIRED={
    "OUF_UDP_SEARCH_TENANT_ID","OUF_UDP_SEARCH_ISSUER","OUF_UDP_SEARCH_AUDIENCE",
    "OUF_UDP_SEARCH_WORKLOAD","OUF_UDP_SEARCH_OWNER_KEY_FILE",
}
ENV_RE=re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


def env_map(items):
    out={}
    for item in items:
        k,sep,v=item.partition("=")
        if not sep or not ENV_RE.fullmatch(k) or k in out or "\n" in v or "\r" in v:
            raise ValueError("invalid Docker environment")
        out[k]=v
    return out


def private_dir(path:Path):
    st=path.stat()
    if not path.is_dir() or st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o077:
        raise ValueError("backup root must be root-owned and private")


def write(path:Path,text:str,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            fd=-1
            f.write(text); f.flush(); os.fsync(f.fileno())
    finally:
        if fd!=-1: os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--projection",type=Path,default=Path("/opt/ouf/installation/active-projection.json"))
    p.add_argument("--backup-root",type=Path,default=Path("/opt/ouf/backup"))
    a=p.parse_args()
    if os.geteuid()!=0:
        p.error("run as root")

    private_dir(a.backup_root)
    projection=json.loads(a.projection.read_text())
    udp_id=projection["iam"]["workloadClients"]["udp"]
    api=projection["gateway"]["publicApiBaseUrl"].rstrip("/")
    revision=projection.get("revision")
    if udp_id!="ouf-udp" or not isinstance(revision,int) or revision<3 or not api.startswith("https://"):
        raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=installation projection invalid")
    registry_url=api+"/internal/capabilities/v1/authorization/policy-bundle/active"

    current=json.loads(subprocess.run(["docker","inspect","ouf-udp"],check=True,capture_output=True,text=True).stdout)[0]
    if not current["State"]["Running"] or current["Config"]["User"]!="10004:10004":
        raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=unexpected live UDP")
    env=env_map(current["Config"]["Env"])
    if not SEARCH_REQUIRED.issubset(env):
        raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=R4a search binding missing")
    if env["OUF_UDP_SEARCH_OWNER_KEY_FILE"]!="/run/secrets/udp-search-owner.key":
        raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=unexpected search key target")
    existing={k:v for k,v in env.items() if k.startswith("OUF_AUTHORIZATION_")}
    if existing:
        wanted=dict(AUTH_ENV); wanted["OUF_AUTHORIZATION_REGISTRY_URL"]=registry_url
        if existing==wanted:
            print("UDP_AUTHORIZATION_ALREADY_CONFIGURED=true")
            return
        raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=conflicting Authorization environment")

    mounts=current.get("Mounts") or []
    key=[m for m in mounts if m.get("Destination")=="/run/secrets/udp-search-owner.key"]
    if len(key)!=1 or key[0].get("RW") is not False:
        raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=search key mount missing")

    token=Path("/run/ouf-udp-auth/token")
    ts=token.stat()
    ds=token.parent.stat()
    if (ds.st_uid,ds.st_gid,stat.S_IMODE(ds.st_mode))!=(0,10004,0o750):
        raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=token directory metadata")
    if token.is_symlink() or (ts.st_uid,ts.st_gid,stat.S_IMODE(ts.st_mode))!=(0,10004,0o440) or not (0<ts.st_size<=16384):
        raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=token metadata")

    env.update(AUTH_ENV)
    env["OUF_AUTHORIZATION_REGISTRY_URL"]=registry_url
    root=Path(tempfile.mkdtemp(prefix="udp-auth-retrofit-",dir=a.backup_root))
    os.chmod(root,0o700)
    write(root/"udp.inspect.json",json.dumps(current,indent=2)+"\n")
    write(root/"udp.env","".join(f"{k}={v}\n" for k,v in env.items()))
    write(root/"meta.json",json.dumps({
        "old_id":current["Id"],
        "image_id":current["Image"],
        "projection_revision":revision,
        "registry_url":registry_url,
        "search_key_source":key[0]["Source"],
    },indent=2)+"\n")
    print("UDP_AUTH_RETROFIT_CANDIDATE="+str(root))
    print("ONLY_AUTHORIZATION_ENV_ADDED=true")
    print("RUNNING_CONTAINER_UNCHANGED=true")


if __name__=="__main__":
    main()
