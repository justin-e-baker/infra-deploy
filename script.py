#!/usr/bin/env python3
import subprocess
import argparse
import os
import sys
import json
import re
import time
from datetime import datetime


# ==============================================
# MAPPINGS
# ==============================================
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

# ==============================================
# GLOBALS
# ==============================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
inventory_file = os.path.join(SCRIPT_DIR, "ansible", "inventory.ini")
redirector_vars_file = os.path.join(SCRIPT_DIR, "ansible", "group_vars", "redirector.yml")
playbook_file = os.path.join(SCRIPT_DIR, "ansible", "playbook.yml")
ACTION_TYPE = "deploy"
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = None

# ==============================================
# LOGGING
# ==============================================
def init_log_file(action_type, provider=None, resource=None):
    global log_file
    logs_dir = os.path.join(SCRIPT_DIR, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    parts = [action_type]
    if provider: parts.append(provider)
    if resource: parts.append(resource)
    parts.append(timestamp)

    log_filename = "_".join(parts) + ".txt"
    log_path = os.path.join(logs_dir, log_filename)
    log_file = open(log_path, "w")

class bcolors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKCYAN    = '\033[96m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'

def log(message, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO":      bcolors.OKBLUE,
        "SUCCESS":   bcolors.OKGREEN,
        "WARN":      bcolors.WARNING,
        "ERROR":     bcolors.FAIL,
        "DEBUG":     bcolors.OKCYAN,
        "FOLLOW ON": bcolors.HEADER
    }
    color = colors.get(level.upper(), bcolors.OKBLUE)
    prefix = f"[{level}]"

    os.system('')  
    print(f"{color}{timestamp} {prefix:<8} {message}{bcolors.ENDC}")
# ==============================================
# HELPERS
# ==============================================
def run_command(cmd, env=None, verbose=False, cwd=None):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, env=env, cwd=cwd)
    out = []
    for line in p.stdout:
        out.append(line)
        if verbose: print(line, end='')
    p.wait()
    if log_file: log_file.write(''.join(out))
    if p.returncode: raise subprocess.CalledProcessError(p.returncode, cmd)
    return ''.join(out)

def run_terraform(path, env_vars, destroy=False, extra_vars=None, verbose=False):
    log(f"{'Destroying' if destroy else 'Deploying'} {path.split(os.sep)[-1]}")
    cmd = ["terraform", "destroy" if destroy else "apply", "-auto-approve"]
    if extra_vars:
        for k,v in extra_vars.items():
            cmd += ["-var", f"{k}={v}"]
    run_command(["terraform","init"], env=env_vars, verbose=verbose, cwd=path)
    run_command(cmd, env=env_vars, verbose=verbose, cwd=path)
    log("Terraform done", "SUCCESS")

def extract_ip(out): 
    for v in out.values():
        if isinstance(v,dict) and "value" in v:
            m = re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", str(v["value"]))
            if m: return m.group(0)
    return None

def extract_url(out):
    for v in out.values():
        if isinstance(v,dict) and "value" in v:
            s = str(v["value"])
            if s.startswith("https://"): return s
    return None

def extract_outputs(path):
    return json.loads(run_command(["terraform","output","-json"], cwd=path))

# ==============================================
# INVENTORY & GROUP VARS
# ==============================================
ANSIBLE_USER_MAP = {"azure":"admin-user","aws":"ubuntu","digitalocean":"root"}

def build_inventory(hosts_by_role):
    log("Writing inventory...")
    os.makedirs(os.path.dirname(inventory_file), exist_ok=True)
    with open(inventory_file,"w") as f:
        for role,hosts in hosts_by_role.items():
            f.write(f"[{role}]\n")
            for ip,prov,key in hosts:
                user = ANSIBLE_USER_MAP.get(prov,"root")
                f.write(f"{ip} ansible_user={user} ansible_ssh_private_key_file={key} "
                        "ansible_port=22 ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n")
            f.write("\n")
    log("Inventory ready","SUCCESS")

def set_redirector_group_vars(domain, target, get_path="/", post_path="/", custom_header=None):
    os.makedirs(os.path.dirname(redirector_vars_file), exist_ok=True)
    with open(redirector_vars_file,"w") as f:
        f.write(f"redirect_domain: \"{domain}\"\n")
        f.write(f"redirect_target: \"{target}\"\n")
        f.write(f"get_path: \"{get_path}\"\n")
        f.write(f"post_path: \"{post_path}\"\n")
        if custom_header:
            name, val = custom_header.split(":",1)
            f.write(f"custom_header_name: \"{name.strip()}\"\n")
            f.write(f"custom_header_value: \"{val.strip()}\"\n")
    log("group_vars written","SUCCESS")

def run_ansible(verbose=False):
    if not os.path.exists(inventory_file):
        log("No inventory → skip Ansible","INFO")
        return
    log("Running playbook...")
    run_command(["ansible-playbook","-i",inventory_file,playbook_file], verbose=verbose)
    log("Ansible finished","SUCCESS")

# ==============================================
# FOLLOW-UP
# ==============================================
def show_followup(provider, resource, role, domain, target, ip,
                  api_gateway_url=None, cloudfront_url=None, proxy_app_url=None,
                  cdn_endpoint_name=None, get_path=None, post_path=None,
                  ssh_key=None, custom_header=None):
    ansible_user = ANSIBLE_USER_MAP.get(provider, "root")
    ssh_line = (
        f"ssh -i {ssh_key} {ansible_user}@{ip}"
        if ssh_key and ip and resource not in ("api_gateway", "cloudfront", "app") else ""
    )
    if role == "redirector":
        path_info = f"GET: {get_path} | POST: {post_path}"
        if provider == "aws" and resource == "api_gateway":
            message = f"\n{api_gateway_url} will forward traffic to {target}.\nPaths: {path_info}\n"
        elif provider == "aws" and resource == "cloudfront":
            message = f"\n{cloudfront_url} will forward traffic to {target}.\nPaths: {path_info}\n"
        elif provider == "azure" and resource == "app":
            message = f"\n{api_gateway_url} will forward traffic to {target}.\nPaths: {path_info}\n"
        else:
            message = f"""
\n# Ensure your domain is pointing to: {ip}

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
    elif role == "phishserver":
        message = f"""
Server deployed at: {ip}
Access:
{ssh_line}
Access tmux:
sudo tmux a -t phish
""".strip()
    else:
        message = f"\nDeployment complete for {provider}:{resource}:{role}.\n"
    log("\n" + message.lstrip("\n"), "FOLLOW ON")

# ==============================================
# ARGUMENT PARSING & VALIDATION
# ==============================================
def parse_deploy_argument(lst):
    out = []
    for s in lst:
        try: p,r,role = s.split(":")
        except: log(f"Bad format: {s}","ERROR"); sys.exit(1)
        if p not in INFRA_MAP or r not in INFRA_MAP[p]:
            log(f"Unknown: {p}:{r}","ERROR"); sys.exit(1)
        out.append((p,r,role, os.path.join(SCRIPT_DIR, INFRA_MAP[p][r])))
    return out

APACHE_RES = {"ec2","vm","droplet"}
BLIND_RES  = {"api_gateway","cloudfront","cdn","app"}

def prepare_env_and_vars(prov, res, args, env):
    e = env.copy()
    v = {"get_path":args.get_path, "post_path":args.post_path}
    if prov=="aws":
        if args.aws_access_key:  e["AWS_ACCESS_KEY_ID"] = args.aws_access_key
        if args.aws_secret_key: e["AWS_SECRET_ACCESS_KEY"] = args.aws_secret_key
        v.update({"aws_access_key":args.aws_access_key or "",
                  "aws_secret_key":args.aws_secret_key or ""})
        if res in ("api_gateway"):
            v["redirector_target"] = args.redirect_to
        if res in ("cloudfront"):
            v["redirector_target"] = args.redirect_to
            v["get_path"] = args.get_path or "/api"
            v["post_path"] = args.post_path or "/submit"
        if res=="ec2":
            v["redirect_to"] = args.redirect_to
            v["pvt_key"] = args.ssh_key or ""
    elif prov=="digitalocean":
        if args.do_token: e["DIGITALOCEAN_TOKEN"]=args.do_token
        v.update({"do_token":args.do_token or "", "pvt_key":args.ssh_key or ""})
        v["redirect_to"] = args.redirect_to
    elif prov=="azure":
        if res=="app":
            v["redirector_target"] = args.redirect_to
            if args.get_path is not None:
                v["get_path"] = args.get_path
            if args.post_path is not None:
                v["post_path"] = args.post_path 
        if res=="vm":
            v["redirect_to"] = args.redirect_to
            v["pvt_key"]=args.ssh_key or ""
    return e,v

# ==============================================
# MAIN
# ==============================================
def main():
    global ACTION_TYPE
    parser = argparse.ArgumentParser(
        description="Deploy cloud-based infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog = (
        "[Redirectors]\n"
        "  [Smart (OPSEC focused)]\n"
        "   aws:ec2\n"
        "   azure:vm\n"
        "   digitalocean:droplet\n"
        "\n"
        "  [Dumb (Proxy everything)]\n"
        "   aws:api_gateway\n"
        "   aws:cloudfront\n"
        "   azure:app\n"
        "\n"
        "[Phishservers]\n " + "\n ".join(ROLE_MAP["phishserver"]))
    )
    parser.add_argument("--deploy",nargs="+",metavar="provider:resource:role")
    parser.add_argument("--destroy",nargs="+",metavar="provider:resource:role")
    parser.add_argument("--resource-domain",help="Domain to point at the resource (not-malicious.com). Not required for dumb redirectors.")
    parser.add_argument("--redirect-to",required=True,help="Domain to forward traffic to (totally-legit.com)")
    parser.add_argument("--get-path",type=str, help='Path for GET requests ("/api")')
    parser.add_argument("--post-path",type=str, help='Path for POST requests ("/form")')
    parser.add_argument("--custom-header",help='Custom header for additional hardening ("Access-X-Control: True")')
    parser.add_argument("--aws-access-key")
    parser.add_argument("--aws-secret-key")
    parser.add_argument("--ssh-key")
    parser.add_argument("--do-token")
    parser.add_argument("--dry-run",action="store_true",help="Detail what would happen")
    parser.add_argument("-v","--verbose",action="store_true")
    args = parser.parse_args()

    ACTION_TYPE = "destroy" if args.destroy else "deploy"

    if args.deploy or args.destroy:
        for item in (args.deploy or args.destroy):
            prov, res, _ = item.split(":")
            if prov == "aws" and not (args.aws_access_key and args.aws_secret_key):
                log("AWS requires --aws-access-key and --aws-secret-key", "ERROR")
                sys.exit(1)
            if prov == "digitalocean" and not args.do_token:
                log("DigitalOcean requires --do-token", "ERROR")
                sys.exit(1)
                
    if args.deploy:
        for item in args.deploy:
            p,r,_ = item.split(":")
            if r in APACHE_RES and not args.resource_domain:
                log(f"--resource-domain required for {p}:{r} (Apache-based smart redirector)","ERROR"); sys.exit(1)
            if r in APACHE_RES and (not args.get_path or not args.post_path):
                log(f"--get-path and --post-path required for {p}:{r}","ERROR"); sys.exit(1)
            if r in APACHE_RES and not args.ssh_key:
                log(f"--ssh-key is required for {p}:{r} (Apache-based smart redirector)", "ERROR"); sys.exit(1)
            if r in APACHE_RES and not args.custom_header:
                log(f"--custom-header is required for {p}:{r} (Apache-based smart redirector)", "ERROR"); sys.exit(1)
    
    base_env = os.environ.copy()
    if args.aws_access_key:  base_env["AWS_ACCESS_KEY_ID"]=args.aws_access_key
    if args.aws_secret_key: base_env["AWS_SECRET_ACCESS_KEY"]=args.aws_secret_key
    if args.do_token:        base_env["DIGITALOCEAN_TOKEN"]=args.do_token

    hosts_by_role = {}
    outputs = {}
    deployed = False

    items = args.deploy or args.destroy or []
    deployments = parse_deploy_argument(items)
    for prov, res, role, path in deployments:
        init_log_file(ACTION_TYPE, prov, res)

    for prov,res,role,path in deployments:
        env,vars = prepare_env_and_vars(prov,res,args,base_env)

        if args.dry_run:
            blind = res in BLIND_RES
            action = "destroy" if args.destroy else "deploy"
            log(f" {prov}:{res} will be {action}ed as a {role}")

            if blind:
                log(f"  Traffic flow: {prov}:{res} -> {args.redirect_to}")
            else:
                domain = args.resource_domain or "???.example.com"
                log(f"  Traffic flow: {domain} -> {prov} Apache -> {args.redirect_to}")
                log(f"  Required paths: GET {args.get_path} || POST {args.post_path}")
                log(f"  Required custom header: '{args.custom_header}'")
                log(f"  SSH key used: {args.ssh_key}")

            continue

        run_terraform(path, env, destroy=bool(args.destroy), extra_vars=vars, verbose=args.verbose)
        if not args.destroy:
            out = extract_outputs(path)
            outputs[f"{prov}:{res}:{role}"] = out
            ip = extract_ip(out)
            url = extract_url(out)
            if ip:
                hosts_by_role.setdefault(role, []).append((ip,prov,args.ssh_key or ""))
            if role=="redirector": deployed=True

    # ——— ANSIBLE (only Apache) ———
    if hosts_by_role and not args.dry_run and not args.destroy:
        log("Waiting 30s for boot…")
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

    # ——— SUMMARY ———
    if outputs and not args.dry_run:
        log("DEPLOYMENT COMPLETE", "SUCCESS")
        print()

        for key, out in outputs.items():
            prov, res, role = key.split(":")
            name = f"{prov}:{res}:{role}"

            ip  = extract_ip(out)
            url = extract_url(out)
            cdn = out.get("cdn_endpoint_name", {}).get("value")
            cf  = out.get("cloudfront_url", {}).get("value")
            lb  = out.get("load_balancer_dns", {}).get("value")
            gw  = out.get("api_gateway_url", {}).get("value")
            pa  = out.get("proxy_app_url", {}).get("value")

            value = ip or url or cdn or cf or lb or gw or "(pending)"

            print(f"{bcolors.OKGREEN}{name} -> {bcolors.ENDC} {value}\n")

            show_followup(
                provider=prov,
                resource=res,
                role=role,
                domain=args.resource_domain or "",
                target=args.redirect_to,
                ip=ip,
                cdn_endpoint_name=cdn,
                api_gateway_url=url,
                cloudfront_url=cf,
                proxy_app_url=pa,
                get_path=args.get_path,
                post_path=args.post_path,
                custom_header=args.custom_header,
                ssh_key=args.ssh_key
            )
    if log_file: log_file.close()

if __name__=="__main__":
    main()