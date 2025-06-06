# infra-deploy
Dynamically deploy redirector or phishserver

## Features
This script is designed (i.e. written by ChatGPT) to deploy infrastructure and configure them according to the specified role, either redirector or phishserver. Available options are AWS EC2 instances and Lambda functions, Azure VMs and CDNs, and DigitalOcean Droplets. Applicable follow on commands are provided according to the specific resource deployed. All deployments and destructions are timestamped and logged into the logs directory.

### Redirector
* AWS EC2 / Azure VM / DigitalOcean Droplet: Stands up an Apache server that forwards traffic to a specified target. Also installs Tmux, Zsh, and Certbot for HTTPS after Ansible. The Ansible users role will be executed on this deployment.
* AWS Lambda: Creates an public API gateway that forwards traffic according to a specified target.
* Azure CDN: Creates a CDN that is configured for an Azure custom domain to forward traffic to a specified target. Requires a CNAME for your domain to be set before execution or the Azure custom domain will fail. NOTE: Deployment and destruction will take a hot minute.

### Phishserver
* AWS EC2 / Azure VM / DigitalOcean Droplet: Installs GoPhish and Evilginx for phishing purposes. Also installs Tmux, Zsh, and Go. Extra configuration required before use. The Ansible users role will be executed on this deployment.

## Warnings/Assumptions
* This script is designed to dynamically add another redirector to protect the initial domain. There should be another domain pointing to a redirector on the edge of your enclave pushing traffic to the teamserver. 
* Access to a provider is needed before execution. AWS will need the access and secret keys. DigitalOcean will need the token. Azure will require that you're logged in before execution.
* Placeholders are found throughout these files, denoted by `<>`. Edit them for applicable IP spaces, users, public SSH keys and more.

## Execution
```
usage: script.py [-h] [--deploy provider:resource:role [provider:resource:role ...]] [--destroy provider:resource:role [provider:resource:role ...]]
                 [--redirector-domain REDIRECTOR_DOMAIN] [--redirector-target REDIRECTOR_TARGET] [--cdn-endpoint-name CDN_ENDPOINT_NAME] [--aws-access-key AWS_ACCESS_KEY]
                 [--aws-secret-key AWS_SECRET_KEY] [--ssh-key SSH_KEY] [--do-token DO_TOKEN] [--dry-run] [-v]

Deploy and configure cloud resources

options:
  -h, --help            show this help message and exit
  --deploy provider:resource:role [provider:resource:role ...]
  --destroy provider:resource:role [provider:resource:role ...]
  --redirector-domain REDIRECTOR_DOMAIN
                        Domain to point at redirector (e.g. not-malicious.com). Use CNAME record for Azure CDN (e.g. www.not-malicious.com). Not needed for AWS Lambda.
  --redirector-target REDIRECTOR_TARGET
                        Domain to forward traffic to (e.g. totally-benign.com)
  --cdn-endpoint-name CDN_ENDPOINT_NAME
                        Name for Azure CDN endpoint. Requires CNAME pointed to <cdn-endpoint-name>.azureedge.net before successful deployment
  --aws-access-key AWS_ACCESS_KEY
  --aws-secret-key AWS_SECRET_KEY
  --ssh-key SSH_KEY
  --do-token DO_TOKEN
  --dry-run             Detail what would happen
  -v, --verbose

Available resources
-----------------------------
[Redirectors]
aws:ec2
aws:lambda
azure:cdn
azure:vm
digitalocean:droplet

[Phishserver]
aws:ec2
azure:vm
digitalocean:droplet
```

### Examples
Deploy an AWS EC2 instance that will have first-domain.com point to it and forward to second-domain.com:
```bash
python3 ./script.py --deploy aws:ec2:redirector --aws-access-key <AWS_ACCESS_KEY> --aws-secret-key <AWS_SECRET_KEY> --redirector-domain first-domain.com --redirector-target second-domain.com
```

Deploy an Azure CDN that will have a custom domain of www.first-domain.com pointing to an Azure edge my-edge and forward to second-domain.com and print all Terraform and Ansible output:
```bash
python3 ./script.py --deploy azure:cdn:redirector --redirector-domain first-domain.com --cdn-endpoint-name my-edge --redirector-target second-domain.com -v
```
