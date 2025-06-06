#!/usr/bin/env python3

import subprocess
import argparse
import os
import sys
import json
import re
import time
from datetime import datetime

INFRA_MAP = {
    "aws": {"ec2": "infra/aws/ec2", "lambda": "infra/aws/lambda"},
    "azure": {"vm": "infra/azure/vm", "cdn": "infra/azure/cdn"},
    "digitalocean": {"droplet": "infra/digitalocean/droplet"},
}

ANSIBLE_USER_MAP = {
    "azure": "admin-user",
    "aws": "ubuntu",
    "digitalocean": "root",
}

ROLE_MAP = {
    "redirector": [
        "aws:ec2",
        "aws:lambda",
        "azure:cdn",
        "azure:vm",
        "digitalocean:droplet"
    ],
    "phishserver": [
        "aws:ec2",
        "azure:vm",
        "digitalocean:droplet"
    ]
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
inventory_file = os.path.join(SCRIPT_DIR, "ansible", "inventory.ini")
redirector_vars_file = os.path.join(SCRIPT_DIR, "ansible", "group_vars", "redirector.yml")
playbook_file = os.path.join(SCRIPT_DIR, "ansible", "playbook.yml")

ACTION_TYPE = "deploy"
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_path = os.path.join(SCRIPT_DIR, f"{ACTION_TYPE}_{timestamp}.txt")
log_file = None

def init_log_file(action_type):
    global log_file, log_path
    logs_dir = os.path.join(SCRIPT_DIR, "logs")
    os.makedirs(logs_dir, exist_ok=True)  # Create logs/ if not exist
    log_path = os.path.join(logs_dir, f"{action_type}_{timestamp}.txt")
    log_file = open(log_path, "w")


def log(message, level="INFO"):
    color_codes = {
        "INFO": "\033[93m",
        "ERROR": "\033[91m",
        "SUCCESS": "\033[92m",
        "FOLLOW ON": "\033[94m"
    }
    tag = f"[{level}]"
    colored_tag = f"{color_codes.get(level, '')}{tag}\033[0m"
    output = f"{colored_tag} {message}"
    plain_output = f"{tag} {message}"
    print(output)
    log_file.write(plain_output + "\n")
    log_file.flush()

def run_command(cmd, env=None, verbose=False, cwd=None):
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        cwd=cwd
    )
    output_lines = []
    for line in process.stdout:
        output_lines.append(line)
        if verbose:
            print(line, end='')
    process.wait()
    output = ''.join(output_lines)
    log_file.write(output)
    log_file.flush()
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, cmd)
    return output

def run_terraform(path, env_vars, destroy=False, extra_vars=None, verbose=False):
    log(f"{'Destroying' if destroy else 'Deploying'} Terraform in: {path}")
    cmd = ["terraform", "destroy" if destroy else "apply", "-auto-approve"]
    if extra_vars:
        for k, v in extra_vars.items():
            cmd.extend(["-var", f"{k}={v}"])
    run_command(["terraform", "init"], env=env_vars, verbose=verbose, cwd=path)
    run_command(cmd, env=env_vars, verbose=verbose, cwd=path)
    log(f"Terraform {'destroy' if destroy else 'apply'} completed in {path}", "SUCCESS")

def extract_ip_from_output(output_json):
    for val in output_json.values():
        if isinstance(val, dict) and "value" in val:
            match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", str(val["value"]))
            if match:
                return match.group(0)
    return None

def extract_lambda_url(output_json):
    for val in output_json.values():
        if isinstance(val, dict) and "value" in val:
            val_str = str(val["value"])
            if val_str.startswith("https://"):
                return val_str
    return None

def extract_outputs(path):
    output = run_command(["terraform", "output", "-json"], cwd=path)
    return json.loads(output)

def build_inventory(hosts_by_role):
    log("Writing Ansible inventory...")
    os.makedirs(os.path.dirname(inventory_file), exist_ok=True)
    with open(inventory_file, "w") as f:
        for role, hosts in hosts_by_role.items():
            f.write(f"[{role}]\n")
            for ip, provider, ssh_key in hosts:
                ansible_user = ANSIBLE_USER_MAP.get(provider, "root")
                f.write(f"{ip} ansible_user={ansible_user} ansible_ssh_private_key_file={ssh_key} ansible_port=22 ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n")
            f.write("\n")
    log("Ansible inventory written.", "SUCCESS")

def set_redirector_group_vars(domain, target):
    os.makedirs(os.path.dirname(redirector_vars_file), exist_ok=True)
    with open(redirector_vars_file, "w") as f:
        f.write(f"redirect_domain: \"{domain}\"\n")
        f.write(f"redirect_target: \"{target}\"\n")
    log("Redirector group vars configured.", "SUCCESS")

def run_ansible(verbose=False):
    if not os.path.exists(inventory_file):
        log("No inventory file. Skipping Ansible.", "ERROR")
        return
    log("Running Ansible playbook...")
    run_command(["ansible-playbook", "-i", inventory_file, playbook_file], verbose=verbose)
    log("Ansible provisioning complete.", "SUCCESS")

def show_followup(provider, resource, role, domain, target, ip=None, cdn_endpoint_name=None, lambda_url=None, access_command=None, ssh_key=None):
    ansible_user = ANSIBLE_USER_MAP.get(provider, "root")
    # Use access_command if provided, else fallback to ssh line if applicable
    if access_command:
        ssh_line = access_command
    else:
        ssh_line = (
            f"ssh -i {ssh_key} {ansible_user}@{ip}"
            if ssh_key and ip and resource not in ("lambda", "cdn") else ""
        )

    if role == "redirector":
        if provider == "azure" and resource == "cdn":
            message = f"\n{domain} will point to {cdn_endpoint_name}.azureedge.net, which will forward traffic to {target}.\n"
        elif provider == "aws" and resource == "lambda":
            message = f"\n{lambda_url} will forward traffic to {target}.\n"
        else:
            message = f"""
Ensure your domain is pointing to: {ip}

Access:
{ssh_line}

Verify DNS:
nslookup {domain}

Certbot:
sudo certbot --apache --non-interactive --agree-tos -m admin@{domain} -d {domain} --redirect

Replace SSL vhost:
sudo cp /etc/apache2/sites-available/000-default-ssl.conf /etc/apache2/sites-available/000-default-le-ssl.conf

Reload Apache:
sudo systemctl restart apache2

Edit redirect rules if needed:
sudo vim /etc/apache2/redirect.rules

Test Apache config (should hit target):
curl --header "Access-X-Control: True" -A "Mozilla/5.0" https://{domain}/jquery/user/preferences

Access tmux:
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

    log(message, "FOLLOW ON")



def parse_deploy_argument(deploy_list):
    deployments = []
    for item in deploy_list:
        try:
            provider, resource, role = item.split(":")
        except ValueError:
            log(f"Invalid deploy argument: {item}. Use provider:resource:role format.", "ERROR")
            sys.exit(1)
        if provider not in INFRA_MAP or resource not in INFRA_MAP[provider]:
            log(f"No path mapping for {provider}:{resource}", "ERROR")
            sys.exit(1)
        path = os.path.join(SCRIPT_DIR, INFRA_MAP[provider][resource])
        deployments.append((provider, resource, role, path))
    return deployments

def prepare_env_and_vars(provider, resource, args, env_vars):
    # Prepare env_vars copy and extra_vars for terraform based on provider/resource and args
    # Returns (env_vars_copy, extra_vars_dict)
    local_env = env_vars.copy()
    extra_vars = {}

    # Set environment variables for providers
    if provider == "aws":
        if args.aws_access_key and args.aws_secret_key:
            local_env.update({
                "AWS_ACCESS_KEY_ID": args.aws_access_key,
                "AWS_SECRET_ACCESS_KEY": args.aws_secret_key
            })
        extra_vars = {
            "aws_access_key": args.aws_access_key or "",
            "aws_secret_key": args.aws_secret_key or ""
        }
        if resource == "lambda":
            extra_vars["redirector_target"] = args.redirector_target or local_env.get("REDIRECT_TARGET", "")
        else:
            extra_vars["pvt_key"] = args.ssh_key or ""

    elif provider == "digitalocean":
        if args.do_token:
            local_env["DIGITALOCEAN_TOKEN"] = args.do_token
        extra_vars = {
            "do_token": args.do_token or "",
            "pvt_key": args.ssh_key or ""
        }

    elif provider == "azure":
        extra_vars = {}
        if resource == "cdn":
            extra_vars = {
                "origin_hostname": args.redirector_target,
                "origin_host_header": args.redirector_target,
                "custom_domain_name": args.redirector_domain,
                "cdn_endpoint_name": args.cdn_endpoint_name or "defaultcdn"
            }

    return local_env, extra_vars

def validate_credentials_for_deployment(provider, resource, args, env):
    if provider == "aws":
        if not (args.aws_access_key or env.get("AWS_ACCESS_KEY_ID")):
            log(f"--aws-access-key is required for {provider}:{resource}", "ERROR")
            sys.exit(1)
        if not (args.aws_secret_key or env.get("AWS_SECRET_ACCESS_KEY")):
            log(f"--aws-secret-key is required for {provider}:{resource}", "ERROR")
            sys.exit(1)

    elif provider == "digitalocean":
        if not (args.do_token or env.get("DIGITALOCEAN_TOKEN")):
            log(f"--do-token is required for {provider}:{resource}", "ERROR")
            sys.exit(1)

def main():
    global ACTION_TYPE
    redirector_resources = []
    phishserver_resources = []

    for provider, resources in INFRA_MAP.items():
        for resource, path in resources.items():
            if "redirector" in path:
                redirector_resources.append(f"{provider}:{resource}")
            elif "phishserver" in path or "phish" in path:
                phishserver_resources.append(f"{provider}:{resource}")

    infra_mapping_help = "Available resources\n"
    infra_mapping_help += "-----------------------------\n"
    infra_mapping_help += "[Redirectors]\n"
    infra_mapping_help += "\n".join(ROLE_MAP.get("redirector", [])) or "None"
    infra_mapping_help += "\n\n[Phishserver]\n"
    infra_mapping_help += "\n".join(ROLE_MAP.get("phishserver", [])) or "None"
    infra_mapping_help += "\n "

    parser = argparse.ArgumentParser(
        description="Deploy and configure cloud resources",
        epilog=infra_mapping_help,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--deploy", nargs="+", metavar="provider:resource:role")
    parser.add_argument("--destroy", nargs="+", metavar="provider:resource:role")
    parser.add_argument("--redirector-domain", help="Domain to point at redirector (e.g. not-malicious.com). Use CNAME record for Azure CDN (e.g. www.not-malicious.com). Not needed for AWS Lambda.")
    parser.add_argument("--redirector-target", help="Domain to forward traffic to (e.g. totally-benign.com)")
    parser.add_argument("--cdn-endpoint-name", help="Name for Azure CDN endpoint. Requires CNAME pointed to <cdn-endpoint-name>.azureedge.net before successful deployment")
    parser.add_argument("--aws-access-key")
    parser.add_argument("--aws-secret-key")
    parser.add_argument("--ssh-key")
    parser.add_argument("--do-token")
    parser.add_argument("--dry-run", action="store_true", help="Detail what would happen")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    ACTION_TYPE = "destroy" if args.destroy else "deploy"
    init_log_file(ACTION_TYPE)

    def is_valid_cdn_name(name):
        return re.fullmatch(r'^[a-z][a-z0-9-]{2,62}$', name) is not None

    # Validate required args for redirector deployments
    if args.deploy:
        for item in args.deploy:
            try:
                provider, resource, role = item.split(":")
            except ValueError:
                continue  # Already validated elsewhere

            if role == "redirector":
                if provider == "azure" and resource == "cdn":
                    if not args.redirector_domain:
                        log("--redirector-domain is required for azure:cdn redirector.", "ERROR")
                        sys.exit(1)                
                    if not args.redirector_target:
                        log("--redirector-target is required for azure:cdn redirector.", "ERROR")
                        sys.exit(1)
                    if not args.cdn_endpoint_name:
                        log("--cdn-endpoint-name is required for azure:cdn redirector.", "ERROR")
                        sys.exit(1)
                    if not is_valid_cdn_name(args.cdn_endpoint_name):
                        log("--cdn-endpoint-name must be 3–63 chars, lowercase alphanumeric or dashes, and start with a letter.", "ERROR")
                        sys.exit(1)
                elif provider == "aws" and resource == "lambda":
                    if not args.redirector_target:
                        log("--redirector-target is required for aws:lambda redirector.", "ERROR")
                        sys.exit(1)
                else:
                    # For other redirectors, require both redirector-domain and redirector-target
                    if not args.redirector_domain or not args.redirector_target:
                        log("--redirector-domain and --redirector-target are required for redirector deployments except aws:lambda.", "ERROR")
                        sys.exit(1)

    base_env_vars = os.environ.copy()
    if args.aws_access_key and args.aws_secret_key:
        base_env_vars.update({
            "AWS_ACCESS_KEY_ID": args.aws_access_key,
            "AWS_SECRET_ACCESS_KEY": args.aws_secret_key
        })
    if args.do_token:
        base_env_vars["DIGITALOCEAN_TOKEN"] = args.do_token
    if args.redirector_target:
        base_env_vars["REDIRECT_TARGET"] = args.redirector_target

    outputs_by_deployment = {}
    hosts_by_role = {}

    deployed_redirector = False  # Track if any redirector was deployed

    if args.deploy:
        required_ssh_key_pairs = [("aws", "ec2"), ("azure", "vm"), ("digitalocean", "droplet")]
        for item in args.deploy:
            try:
                provider, resource, role = item.split(":")
            except ValueError:
                continue  # Already validated elsewhere

            if (provider, resource) in required_ssh_key_pairs and not args.ssh_key:
                log(f"--ssh-key is required for {provider}:{resource}:{role}", "ERROR")
                sys.exit(1)

        deployments = parse_deploy_argument(args.deploy)

        for provider, resource, role, path in deployments:
            validate_credentials_for_deployment(provider, resource, args, base_env_vars)
            env_vars, extra_vars = prepare_env_and_vars(provider, resource, args, base_env_vars)
            try:
                if args.dry_run:
                    log(f"Would deploy {provider}:{resource} as role '{role}'")

                    if role == "redirector":
                        if provider == "azure" and resource == "cdn":
                            log(f"{args.redirector_domain} will be a CNAME pointing to {args.cdn_endpoint_name}.azureedge.net, which will push traffic to {args.redirector_target}")
                        elif provider == "aws" and resource == "lambda":
                            log(f"AWS Lambda will forward to {args.redirector_target}")
                        else:
                            log(f"{args.redirector_domain} should point to deployed IP, which will push traffic to {args.redirector_target}")
                            log("certbot + apache2 config will be applied via Ansible")

                else:
                    run_terraform(path, env_vars, destroy=False, extra_vars=extra_vars, verbose=args.verbose)
                    outputs = extract_outputs(path)
                    outputs_by_deployment[f"{provider}:{resource}:{role}"] = outputs
                    ip = extract_ip_from_output(outputs)
                    if role not in hosts_by_role:
                        hosts_by_role[role] = []
                    if ip:
                        hosts_by_role[role].append((ip, provider, args.ssh_key or ""))

                    if role == "redirector":
                        deployed_redirector = True  # Mark that a redirector was deployed
            except subprocess.CalledProcessError:
                log(f"Terraform failed for {provider}:{resource}:{role}", "ERROR")
                sys.exit(1)

    if args.destroy:
        deployments = parse_deploy_argument(args.destroy)
        for provider, resource, role, path in deployments:
            validate_credentials_for_deployment(provider, resource, args, base_env_vars)
            env_vars, extra_vars = prepare_env_and_vars(provider, resource, args, base_env_vars)
            try:
                if args.dry_run:
                    log(f"Would destroy {provider}:{resource}:{role} in {path}")
                else:
                    run_terraform(path, env_vars, destroy=True, extra_vars=extra_vars, verbose=args.verbose)
            except subprocess.CalledProcessError:
                log(f"Terraform destroy failed for {provider}:{resource}:{role}", "ERROR")
                sys.exit(1)

    # Wait 30 seconds before running Ansible if a redirector was deployed and not dry-run
    if (deployed_redirector or hosts_by_role) and not args.dry_run:        
        log("Waiting 30 seconds before running Ansible...")
        time.sleep(30)

    if hosts_by_role:
        build_inventory(hosts_by_role)

    if not args.dry_run and not args.destroy and hosts_by_role:
        if args.redirector_domain and args.redirector_target:
            set_redirector_group_vars(args.redirector_domain, args.redirector_target)
        run_ansible(verbose=args.verbose)


    if outputs_by_deployment and not args.dry_run:
        log("Deployment complete", "SUCCESS")
        print("\n====== Deployed Resources Summary ======")
        for name, output in outputs_by_deployment.items():
            provider, resource, role = name.split(":")
            ip = extract_ip_from_output(output)
            lambda_url = extract_lambda_url(output) if (provider == "aws" and resource == "lambda") else None

            access_command = None
            for key, val in output.items():
                if key.lower().startswith("access"):
                    access_command = val.get("value") if isinstance(val, dict) else val
                    break

            if lambda_url:
                print(f"{name}: {lambda_url}\n")
            else:
                print(f"{name}: {ip}\n")

            show_followup(
                provider=provider,
                resource=resource,
                role=role,
                domain=args.redirector_domain,
                target=args.redirector_target,
                ip=ip,
                cdn_endpoint_name=args.cdn_endpoint_name,
                lambda_url=lambda_url,
                access_command=access_command,
                ssh_key=args.ssh_key  # pass ssh_key as well for fallback if needed
            )

    if log_file:
        log_file.close()

if __name__ == "__main__":
    main()
