#!/usr/bin/env python3
"""Roll out or roll back the prepared UDP Authorization retrofit."""
import argparse, json, os, re, stat, subprocess, time
from pathlib import Path

AUTH_KEYS={
 "OUF_AUTHORIZATION_REGISTRY_URL",
 "OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE",
 "OUF_AUTHORIZATION_REFRESH_SECONDS",
 "OUF_AUTHORIZATION_MAX_STALENESS_SECONDS",
}


def docker(*args):
    return subprocess.run(["docker",*args],check=True,capture_output=True,text=True).stdout.strip()


def inspect(name):
    return json.loads(docker("inspect",name))[0]


def env_map(items):
    out={}
    for item in items:
        k,sep,v=item.partition("=")
        if not sep or k in out: raise ValueError("invalid env")
        out[k]=v
    return out


def wait_ready(name):
    for i in range(20):
        try:
            docker("exec",name,"wget","-q","-O","/dev/null","http://127.0.0.1:8080/actuator/health/readiness")
            return
        except subprocess.CalledProcessError:
            if i==19: raise ValueError("UDP readiness failed")
            time.sleep(3)


def validate(candidate:Path):
    st=candidate.stat()
    if st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o700:
        raise ValueError("candidate metadata")
    old=json.loads((candidate/"udp.inspect.json").read_text())
    meta=json.loads((candidate/"meta.json").read_text())
    env=env_map((candidate/"udp.env").read_text().splitlines())
    previous=env_map(old["Config"]["Env"])
    if set(env)-set(previous)!=AUTH_KEYS or {k:v for k,v in env.items() if k not in AUTH_KEYS}!=previous:
        raise ValueError("candidate changes more than Authorization environment")
    if env["OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE"]!="/run/ouf-udp-auth/token":
        raise ValueError("unexpected token target")
    if env["OUF_AUTHORIZATION_REFRESH_SECONDS"]!="30" or env["OUF_AUTHORIZATION_MAX_STALENESS_SECONDS"]!="300":
        raise ValueError("unexpected refresh bounds")
    live=inspect("ouf-udp")
    if live["Id"]!=meta["old_id"] or live["Id"]!=old["Id"] or not live["State"]["Running"]:
        raise ValueError("live UDP changed since preparation")
    host=old["HostConfig"]
    nets=old["NetworkSettings"]["Networks"]
    if set(nets)!={"ouf-backend"} or old["Config"]["User"]!="10004:10004":
        raise ValueError("unexpected UDP network/user")
    if host["NetworkMode"]!="ouf-backend" or host["RestartPolicy"]["Name"]!="unless-stopped":
        raise ValueError("unexpected UDP launch")
    key=[m for m in old.get("Mounts",[]) if m.get("Destination")=="/run/secrets/udp-search-owner.key"]
    if len(key)!=1 or key[0]["RW"] is not False or key[0]["Source"]!=meta["search_key_source"]:
        raise ValueError("unexpected search key mount")
    return old,meta,host,nets


def create_args(old,meta,host,nets,candidate):
    name="ouf-udp"
    args=["create","--name",name,"--pull","never","--user",old["Config"]["User"],
          "--restart","unless-stopped","--network",host["NetworkMode"],
          "--shm-size",str(host["ShmSize"]),"--log-driver","json-file",
          "--env-file",str(candidate/"udp.env")]
    if host.get("Memory"):
        args += ["--memory",str(host["Memory"])]
    if host.get("MemorySwap"):
        args += ["--memory-swap",str(host["MemorySwap"])]
    args += ["--mount","type=bind,src="+meta["search_key_source"]+",dst=/run/secrets/udp-search-owner.key,readonly"]
    args += ["--mount","type=bind,src=/run/ouf-udp-auth,dst=/run/ouf-udp-auth,readonly"]
    for alias in sorted(set(nets["ouf-backend"].get("Aliases") or [])-{"ouf-udp",old["Id"][:12]}):
        args += ["--network-alias",alias]
    args.append(meta["image_id"])
    return args


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate",type=Path,required=True)
    g=p.add_mutually_exclusive_group()
    g.add_argument("--apply",action="store_true")
    g.add_argument("--rollback",action="store_true")
    a=p.parse_args()
    if os.geteuid()!=0: p.error("run as root")

    state=a.candidate/"rollout.json"
    if a.rollback:
        s=json.loads(state.read_text())
        live=inspect("ouf-udp")
        if live["Id"]==s["old_id"]:
            print("UDP_AUTH_RETROFIT_ROLLBACK_ALREADY_RESTORED=true"); return
        docker("update","--restart","no","ouf-udp")
        if live["State"]["Running"]: docker("stop","ouf-udp")
        docker("rm","ouf-udp")
        backup=inspect(s["backup"])
        if backup["Id"]!=s["old_id"]: raise SystemExit("UDP_AUTH_RETROFIT_ROLLBACK_BLOCKED=identity mismatch")
        docker("rename",s["backup"],"ouf-udp")
        docker("update","--restart","unless-stopped","ouf-udp")
        docker("start","ouf-udp")
        wait_ready("ouf-udp")
        print("UDP_AUTH_RETROFIT_ROLLBACK_RESTORED=true")
        return

    old,meta,host,nets=validate(a.candidate)
    args=create_args(old,meta,host,nets,a.candidate)
    if not a.apply:
        print("UDP_AUTH_RETROFIT_DRY_RUN_OK=true")
        print("ORIGINAL_ID_MATCH=true")
        print("ONLY_AUTHORIZATION_ENV_ADDED=true")
        print("TOKEN_MOUNT_WILL_BE_ADDED=true")
        print("NO_CONTAINER_CHANGED=true")
        return
    if state.exists(): raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=rollout state exists")
    backup="ouf-udp-preauth-"+meta["old_id"][:12]
    try: inspect(backup)
    except subprocess.CalledProcessError: pass
    else: raise SystemExit("UDP_AUTH_RETROFIT_BLOCKED=backup name exists")
    fd=os.open(state,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as f:
        json.dump({"old_id":meta["old_id"],"backup":backup},f); f.write("\n"); f.flush(); os.fsync(f.fileno())
    try:
        docker("update","--restart","no","ouf-udp")
        docker("stop","ouf-udp")
        docker("rename","ouf-udp",backup)
        docker(*args)
        docker("start","ouf-udp")
        wait_ready("ouf-udp")
        live=inspect("ouf-udp")
        if live["Image"]!=meta["image_id"] or not live["State"]["Running"]:
            raise ValueError("new UDP runtime invalid")
    except Exception:
        try:
            try:
                cur=inspect("ouf-udp")
                docker("update","--restart","no","ouf-udp")
                if cur["State"]["Running"]: docker("stop","ouf-udp")
                docker("rm","ouf-udp")
            except Exception: pass
            docker("rename",backup,"ouf-udp")
            docker("update","--restart","unless-stopped","ouf-udp")
            docker("start","ouf-udp")
            wait_ready("ouf-udp")
        finally:
            raise
    print("UDP_AUTH_RETROFIT_STAGED=true")
    print("ROLLBACK_CONTAINER="+backup)
    print("AUTHORIZATION_PROBE_REQUIRED=true")


if __name__=="__main__":
    main()
