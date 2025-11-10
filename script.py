#!/usr/bin/env python3

import subprocess
import argparse
import os
import sys
import json
import re
import time
from datetime import datetime
import yaml
from pathlib import Path

# ----------------------------------------------------------------------
# MAPPINGS
# ----------------------------------------------------------------------
INFRA_MAP = {
    "aws": {
        "ec2": "infra/aws/ec2",
        "api_gateway": "infra/aws/api_gateway",
        "cloudfront": "infra/aws/cloudfront"
    },
    "azure": {
        "vm": "infra/azure/vm",
        "app": "infra/azure/app"
    },
    "digitalocean": {"droplet": "infra/digitalocean/droplet"},
}

ROLE_MAP = {
    "redirector": [
        "aws:ec2", "aws:api_gateway", "aws:cloudfront",
        "azure:vm", "azure:app",
        "digitalocean:droplet"
    ],
    "phishserver": ["aws:ec2", "azure:vm", "digitalocean:droplet"]
}

# ----------------------------------------------------------------------
# GLOBALS
# ----------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INVENTORY_FILE = os.path.join(SCRIPT_DIR, "ansible", "inventory.ini")
REDIRECTOR_VARS = os.path.join(SCRIPT_DIR, "ansible", "group_vars", "redirector.yml")
PLAYBOOK_FILE = os.path.join(SCRIPT_DIR, "ansible", "playbook.yml")
ACTION_TYPE = "deploy"
TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE = None

# ----------------------------------------------------------------------
# LOGGING
# ----------------------------------------------------------------------
def init_log_file(action_type, provider=None, resource=None):
    global LOG_FILE
    # Only create log file for actual deploy/destroy
    if action_type not in ("deploy", "destroy"):
        return

    logs_dir = os.path.join(SCRIPT_DIR, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    parts = [action_type]
    if provider: parts.append(provider)
    if resource: parts.append(resource)
    parts.append(TIMESTAMP)
    log_path = os.path.join(logs_dir, "_".join(parts) + ".txt")
    LOG_FILE = open(log_path, "w")
    log(f"Log started: {log_path}", "INFO")

class bcolors:
    OKBLUE   = '\033[94m'
    OKGREEN  = '\033[92m'
    WARNING  = '\033[93m'
    FAIL     = '\033[91m'
    HEADER   = '\033[95m'
    ENDC     = '\033[0m'

def log(message, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO": bcolors.OKBLUE,
        "SUCCESS": bcolors.OKGREEN,
        "WARN": bcolors.WARNING,
        "ERROR": bcolors.FAIL,
        "FOLLOW ON": bcolors.HEADER,
    }
    color = colors.get(level.upper(), bcolors.OKBLUE)
    print(f"{color}[{level}] {ts} {message}{bcolors.ENDC}")

# ----------------------------------------------------------------------
# run_command
# ----------------------------------------------------------------------
def run_command(cmd, env=None, verbose=False, cwd=None):
    # Run command, capture ALL output
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        cwd=cwd,
        bufsize=1,
        universal_newlines=True
    )
    output = []
    for line in p.stdout:
        output.append(line)
        if verbose:
            print(line, end="")
        if LOG_FILE:
            LOG_FILE.write(line)
    p.wait()
    if p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, cmd)
    return "".join(output)
    
def run_terraform(path, env_vars, destroy=False, extra_vars=None, verbose=False):
    action = "Destroying" if destroy else "Deploying"
    log(f"{action} {os.path.basename(path)}")
    cmd = ["terraform", "destroy" if destroy else "apply", "-auto-approve"]
    if extra_vars:
        for k, v in extra_vars.items():
            cmd += ["-var", f"{k}={v}"]
    run_command(["terraform", "init"], env=env_vars, verbose=verbose, cwd=path)
    run_command(cmd, env=env_vars, verbose=verbose, cwd=path)
    log("Terraform done", "SUCCESS")

def extract_ip(tf_out):
    for v in tf_out.values():
        if isinstance(v, dict) and "value" in v:
            m = re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", str(v["value"]))
            if m: return m.group(0)
    return None

def extract_url(tf_out):
    for v in tf_out.values():
        if isinstance(v, dict) and "value" in v:
            s = str(v["value"])
            if s.startswith("https://"): return s
    return None

def extract_outputs(path):
    return json.loads(run_command(["terraform", "output", "-json"], cwd=path))

# ----------------------------------------------------------------------
# INVENTORY & GROUP VARS
# ----------------------------------------------------------------------
ANSIBLE_USER_MAP = {"azure": "admin-user", "aws": "ubuntu", "digitalocean": "root"}

def build_inventory(hosts_by_role):
    log("Writing inventory...")
    os.makedirs(os.path.dirname(INVENTORY_FILE), exist_ok=True)
    with open(INVENTORY_FILE, "w") as f:
        for role, hosts in hosts_by_role.items():
            f.write(f"[{role}]\n")
            for ip, prov, key in hosts:
                user = ANSIBLE_USER_MAP.get(prov, "root")
                f.write(
                    f"{ip} ansible_user={user} ansible_ssh_private_key_file={key} "
                    "ansible_port=22 ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n"
                )
            f.write("\n")
    log("Inventory ready", "SUCCESS")

def set_redirector_group_vars(domain, target, get_path="/", post_path="/", custom_header=None):
    os.makedirs(os.path.dirname(REDIRECTOR_VARS), exist_ok=True)
    with open(REDIRECTOR_VARS, "w") as f:
        f.write(f"redirect_domain: \"{domain}\"\n")
        f.write(f"redirect_target: \"{target}\"\n")
        f.write(f"get_path: \"{get_path}\"\n")
        f.write(f"post_path: \"{post_path}\"\n")
        if custom_header:
            name, val = custom_header.split(":", 1)
            f.write(f"custom_header_name: \"{name.strip()}\"\n")
            f.write(f"custom_header_value: \"{val.strip()}\"\n")
    log("group_vars written", "SUCCESS")

def run_ansible(verbose=False):
    if not os.path.exists(INVENTORY_FILE):
        log("No inventory → skip Ansible", "INFO")
        return
    log("Running playbook...", "INFO")
    run_command(["ansible-playbook", "-i", INVENTORY_FILE, PLAYBOOK_FILE], verbose=verbose)
    log("Ansible finished", "SUCCESS")

# ----------------------------------------------------------------------
# FOLLOW‑UP
# ----------------------------------------------------------------------
def show_followup(provider, resource, role, domain, target, ip,
                  api_gateway_url=None, cloudfront_url=None, proxy_app_url=None,
                  get_path=None, post_path=None, ssh_key=None, custom_header=None):
    ansible_user = ANSIBLE_USER_MAP.get(provider, "root")
    ssh_line = (
        f"ssh -i {ssh_key} {ansible_user}@{ip}"
        if ssh_key and ip and resource not in ("api_gateway", "cloudfront", "app") else ""
    )
    if role == "redirector":
        path_info = f"GET: {get_path} | POST: {post_path}"
        if provider == "aws" and resource == "api_gateway":
            msg = f"\n{api_gateway_url} → {target}\nPaths: {path_info}\n"
        elif provider == "aws" and resource == "cloudfront":
            msg = f"\n{cloudfront_url} → {target}\nPaths: {path_info}\n"
        elif provider == "azure" and resource == "app":
            msg = f"\n{proxy_app_url} → {target}\nPaths: {path_info}\n"
        else:
            msg = f"""
# Ensure your domain is pointing to: {ip}

# Paths: {path_info}

# Access:
{ssh_line}

# Verify DNS:
nslookup {domain}

# Certbot:
sudo certbot --apache --non-interactive --agree-tos -m admin@{domain} -d {domain} --redirect

# Replace SSL vhost:
sudo cp /etc/apache2/sites-available/000-default-ssl.conf /etc/apache2/sites-available/000-default-le-ssl.conf

# Reload Apache:
sudo systemctl restart apache2

# Edit redirect rules if needed. May need to comment out the deployed resource IP:
sudo vim /etc/apache2/redirect.rules

# Test Apache config (should hit target):
curl -X GET --header "{custom_header}" -A "Mozilla/5.0" https://{domain}{get_path} # GET test
curl -X POST --header "{custom_header}" -A "Mozilla/5.0" https://{domain}{post_path} -d "test" # POST test

# Access tmux:
sudo tmux a -t redirector
""".strip()
    else:  # phishserver
        msg = f"""
Server IP: {ip}
Access:
{ssh_line}
Tmux:
sudo tmux a -t phish
"""
    log("\n" + msg.lstrip("\n"), "FOLLOW ON")

# ----------------------------------------------------------------------
# VALIDATION & ENV
# ----------------------------------------------------------------------
APACHE_RES = {"ec2", "vm", "droplet"}
BLIND_RES  = {"api_gateway", "cloudfront", "app"}

def parse_deploy_argument(lst):
    out = []
    for s in lst:
        try:
            p, r, role = s.split(":")
        except Exception:
            log(f"Bad format: {s}", "ERROR")
            sys.exit(1)
        if p not in INFRA_MAP or r not in INFRA_MAP[p]:
            log(f"Unknown resource: {p}:{r}", "ERROR")
            sys.exit(1)
        out.append((p, r, role, os.path.join(SCRIPT_DIR, INFRA_MAP[p][r])))
    return out

def prepare_env_and_vars(prov, res, args, env):
    e = env.copy()
    v = {"get_path": args.get_path, "post_path": args.post_path}
    if prov == "aws":
        if args.aws_access_key: e["AWS_ACCESS_KEY_ID"] = args.aws_access_key
        if args.aws_secret_key: e["AWS_SECRET_ACCESS_KEY"] = args.aws_secret_key
        v.update({"aws_access_key": args.aws_access_key or "",
                  "aws_secret_key": args.aws_secret_key or ""})
        if res in ("api_gateway", "cloudfront"):
            v["redirector_target"] = args.redirect_to
            if args.get_path is not None: v["get_path"] = args.get_path
            if args.post_path is not None: v["post_path"] = args.post_path
        if res == "ec2":
            v["redirect_to"] = args.redirect_to
            v["pvt_key"] = args.ssh_key or ""
    elif prov == "digitalocean":
        if args.do_token: e["DIGITALOCEAN_TOKEN"] = args.do_token
        v.update({"do_token": args.do_token or "", "pvt_key": args.ssh_key or ""})
        v["redirect_to"] = args.redirect_to
    elif prov == "azure":
        if res == "app":
            v["redirector_target"] = args.redirect_to
            if args.get_path is not None: v["get_path"] = args.get_path
            if args.post_path is not None: v["post_path"] = args.post_path
        if res == "vm":
            v["redirect_to"] = args.redirect_to
            v["pvt_key"] = args.ssh_key or ""
    return e, v

# ----------------------------------------------------------------------
# CORE DEPLOYMENT LOGIC
# ----------------------------------------------------------------------
def process_deployment(args):
    global ACTION_TYPE
    ACTION_TYPE = "destroy" if args.action == "destroy" else "deploy"

    prr = f"{args.provider}:{args.resource}:{args.role}"
    items = [prr]
    deployments = parse_deploy_argument(items)

    # ------------------------------------------------------------------
    # EXTRACT VALUES (for validation)
    # ------------------------------------------------------------------
    prov, res, role, path = deployments[0]

    # ------------------------------------------------------------------
    # DRY-RUN: Show intent, exit early, NO LOG FILE
    # ------------------------------------------------------------------
    if args.dry_run:
        log(f"   Dry-run: {prov}:{res} will be {ACTION_TYPE}ed as a {role}.", "INFO")
        if res in BLIND_RES:
            log(f"     Traffic flow: {prov}:{res} → {args.redirect_to}", "INFO")
        else:
            dom = args.resource_domain or "???.example.com"
            log(f"     Traffic flow: {dom} →  {prov} Apache → {args.redirect_to}", "INFO")
            log(f"     Required paths: GET '{args.get_path or '??'}' | POST '{args.post_path or '??'}'", "INFO")
            log(f"     Required header: '{args.custom_header}'", "INFO")
            log(f"     SSH key used: {args.ssh_key}", "INFO")
        return

    # ------------------------------------------------------------------
    # VALIDATION: Smart vs Dumb (only on deploy)
    # ------------------------------------------------------------------
    if args.action == "deploy":
        is_smart = res in APACHE_RES
        is_dumb = res in BLIND_RES

        # ----- SMART: All fields required -----
        if is_smart:
            required = {
                "resource_domain": args.resource_domain,
                "get_path": args.get_path,
                "post_path": args.post_path,
                "custom_header": args.custom_header,
                "ssh_key": args.ssh_key
            }
            missing = [k for k, v in required.items() if not v]
            if missing:
                log(f"Smart redirector {prov}:{res} requires: {', '.join(missing)}", "ERROR")
                sys.exit(1)

        # ----- DUMB: Forbid smart fields -----
        if is_dumb:
            not_needed = []
            if args.resource_domain: not_needed.append("resource_domain")
            if args.get_path: not_needed.append("get_path")
            if args.post_path: not_needed.append("post_path")
            if args.custom_header: not_needed.append("custom_header")
            if args.ssh_key: not_needed.append("ssh_key")
            if not_needed:
                log(f"Dumb redirector {prov}:{res} doesn't need: {', '.join(not_needed)}", "ERROR")
                sys.exit(1)

            # CloudFront: apply defaults
            if res == "cloudfront":
                args.get_path = args.get_path or "/api"
                args.post_path = args.post_path or "/submit"
                log("CloudFront: using default paths /api and /submit", "INFO")

    # ------------------------------------------------------------------
    # PROVIDER CREDENTIAL VALIDATION
    # ------------------------------------------------------------------
    if prov == "aws" and not (args.aws_access_key and args.aws_secret_key):
        log("aws_access_key and aws_secret_key required", "ERROR")
        sys.exit(1)
    if prov == "digitalocean" and not args.do_token:
        log("do_token required", "ERROR")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Create log file
    # ------------------------------------------------------------------
    init_log_file(ACTION_TYPE, prov, res)

    # ------------------------------------------------------------------
    # ENVIRONMENT SETUP
    # ------------------------------------------------------------------
    base_env = os.environ.copy()
    if args.aws_access_key: base_env["AWS_ACCESS_KEY_ID"] = args.aws_access_key
    if args.aws_secret_key: base_env["AWS_SECRET_ACCESS_KEY"] = args.aws_secret_key
    if args.do_token: base_env["DIGITALOCEAN_TOKEN"] = args.do_token

    env, tf_vars = prepare_env_and_vars(prov, res, args, base_env)

    # ------------------------------------------------------------------
    # TERRAFORM EXECUTION
    # ------------------------------------------------------------------
    run_terraform(path, env, destroy=(args.action == "destroy"),
                  extra_vars=tf_vars, verbose=args.verbose)

    if args.action == "destroy":
        log(f"{prov}:{res}:{role} destroyed", "SUCCESS")
        if LOG_FILE: LOG_FILE.close()
        return

    # ------------------------------------------------------------------
    # TERRAFORM OUTPUTS
    # ------------------------------------------------------------------
    outputs = {}
    hosts_by_role = {}

    out = extract_outputs(path)
    outputs[f"{prov}:{res}:{role}"] = out
    ip = extract_ip(out)
    url = extract_url(out)

    if ip and res not in BLIND_RES:
        hosts_by_role.setdefault(role, []).append((ip, prov, args.ssh_key or ""))

    # ------------------------------------------------------------------
    # ANSIBLE (only for smart redirectors)
    # ------------------------------------------------------------------
    if hosts_by_role:
        log("Waiting 30s for system boot and apt locks...", "INFO")
        time.sleep(30)

        build_inventory(hosts_by_role)
        set_redirector_group_vars(
            domain=args.resource_domain or "",
            target=args.redirect_to,
            get_path=args.get_path,
            post_path=args.post_path,
            custom_header=args.custom_header
        )
        run_ansible(args.verbose)

    # ------------------------------------------------------------------
    # FINAL SUMMARY
    # ------------------------------------------------------------------
    log("Deployment complete", "SUCCESS")
    print()
    for key, out in outputs.items():
        p, r, role = key.split(":")
        name = f"{p}:{r}:{role}"
        ip_val = extract_ip(out)
        url_val = extract_url(out)
        cf = out.get("cloudfront_url", {}).get("value")
        gw = out.get("api_gateway_url", {}).get("value")
        pa = out.get("proxy_app_url", {}).get("value")
        value = ip_val or url_val or cf or gw or pa or "(pending)"
        if ip_val: value = "IP " + value
        print(f"{bcolors.OKGREEN}{name}:{bcolors.ENDC} {value}")

        show_followup(
            provider=p, resource=r, role=role,
            domain=args.resource_domain or "", target=args.redirect_to,
            ip=ip_val, api_gateway_url=url_val, cloudfront_url=cf, proxy_app_url=pa,
            get_path=args.get_path, post_path=args.post_path,
            custom_header=args.custom_header, ssh_key=args.ssh_key
        )

    if LOG_FILE:
        LOG_FILE.close()

# ----------------------------------------------------------------------
# MAIN – reads action from YAML + optional --config
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Deploy / destroy cloud infrastructure",formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "[Redirectors]\n"
            "   [Smart] (OPSEC focused)\n"
            "    aws:ec2\n"
            "    azure:vm\n"
            "    digitalocean:droplet\n"
            "\n"
            "   [Dumb] (Proxy everything)\n"
            "    aws:api_gateway\n"
            "    aws:cloudfront\n"
            "    azure:app\n"
            "\n"
            "[Phishservers]\n"
            " aws:ec2\n"
            " azure:vm\n"
            " digitalocean:droplet\n"
            "\n"
        )
    )
    parser.add_argument("-f","--file",required=True,help="Path to config file")
    parser.add_argument("-d","--dry-run", action="store_true",help="Show what would happen")
    parser.add_argument("-v","--verbose", action="store_true",help="Show Terraform/Ansible output")
    args = parser.parse_args()

    cfg_path = Path(SCRIPT_DIR) / args.file
    if not cfg_path.exists():
        log(f"Config file not found: {cfg_path}", "ERROR")
        sys.exit(1)

    with open(cfg_path) as f:
        cfg = yaml.safe_load(f) or {}

    # ------------------------------------------------------------------
    # VALIDATION: Core keys only — SAME STYLE AS SMART REDIRECTOR
    # ------------------------------------------------------------------
    required = {
        "action":      cfg.get("action"),
        "provider":    cfg.get("provider"),
        "resource":    cfg.get("resource"),
        "role":        cfg.get("role"),
        "redirect_to": cfg.get("redirect_to")
    }

    missing = [k for k, v in required.items() if not v]
    if missing:
        log(f"Required key(s) not found: {', '.join(missing)}", "ERROR")
        sys.exit(1)

    # Validate action
    if cfg["action"] not in ("deploy", "destroy"):
        log(f"Required action must be 'deploy' or 'destroy', got: {cfg['action']}", "ERROR")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Build FakeArgs
    # ------------------------------------------------------------------
    class FakeArgs:
        pass
    a = FakeArgs()
    a.action          = cfg["action"]
    a.provider        = cfg["provider"]
    a.resource        = cfg["resource"]
    a.role            = cfg["role"]
    a.redirect_to     = cfg["redirect_to"]
    a.resource_domain = cfg.get("resource_domain")
    a.get_path        = cfg.get("get_path")
    a.post_path       = cfg.get("post_path")
    a.custom_header   = cfg.get("custom_header")
    a.ssh_key         = cfg.get("ssh_key")
    a.aws_access_key  = cfg.get("aws_access_key")
    a.aws_secret_key  = cfg.get("aws_secret_key")
    a.do_token        = cfg.get("do_token")
    a.dry_run         = args.dry_run
    a.verbose         = args.verbose

    # ------------------------------------------------------------------
    # Proceed
    # ------------------------------------------------------------------
    process_deployment(a)
    
if __name__ == "__main__":
    main()