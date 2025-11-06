# infra-deploy
Dynamically deploy a redirector or phishserver.

## Features
This script is designed (i.e. vibe coded) to deploy infrastructure and configure it according to the specified role, either (smart/dumb) redirector or phishserver. Available options:
* AWS EC2 instance
* AWS API Gateway with Lambda function
* AWS CloudFront distribution
* Azure VM
* Azure App Service
* DigitalOcean Droplet

Applicable follow-on commands are provided according to the specific resource deployed. All deployments and destructions are timestamped and logged into the logs directory.

### Redirector
##### Smart Redirectors 
* AWS EC2 | Azure VM | DigitalOcean Droplet: Stands up a hardened Apache server to proxy traffic to a specified target. Requires a domain, custom header and GET & POST paths. Also installs Tmux, Zsh, and Certbot for HTTPS after Ansible. The Ansible users role will be executed on this deployment.

##### Dumb Redirectors 
* AWS API Gateway: Creates an public API gateway using a Lambda function to proxy all traffic to a specified target. Name is randomly generated.
* AWS CloudFront: Creates a CDN that is configured to proxy all traffic to a specified target. Name is randomly generated.
* Azure App Service: Creates an app using Flask and Gunicorn to proxy all traffic to a specified target. Default region is westus2 due to current capacity issues. Name is randomly generated.

### Phishserver
* AWS EC2 | Azure VM | DigitalOcean Droplet: Installs GoPhish and Evilginx for phishing purposes. Also installs Tmux, Zsh, and Go. Extra configuration required before use. The Ansible users role will be executed on this deployment.

## Warnings/Assumptions
* This script is designed to dynamically add another redirector to protect the initial domain, which points to a redirector on the edge of your enclave pushing C2 traffic to the teamserver internally. 
* Access to a provider is needed before execution. AWS will need the access key and secret key. DigitalOcean will need the token. Azure will require that you're logged in before execution.
* Placeholders are found throughout these files, denoted by `<>`. Edit them for applicable IP spaces, users, public SSH keys and more.

## Execution
```
usage: script.py [-h] [--deploy provider:resource:role [provider:resource:role ...]] [--destroy provider:resource:role [provider:resource:role ...]]
                 [--resource-domain RESOURCE_DOMAIN] --redirect-to REDIRECT_TO [--get-path GET_PATH] [--post-path POST_PATH]
                 [--custom-header CUSTOM_HEADER] [--aws-access-key AWS_ACCESS_KEY] [--aws-secret-key AWS_SECRET_KEY] [--ssh-key SSH_KEY]
                 [--do-token DO_TOKEN] [--dry-run] [-v]

Deploy cloud-based infrastructure

options:
  -h, --help            show this help message and exit
  --deploy provider:resource:role [provider:resource:role ...]
  --destroy provider:resource:role [provider:resource:role ...]
  --resource-domain RESOURCE_DOMAIN
                        Domain to point at the resource (not-malicious.com). Not required for dumb redirectors.
  --redirect-to REDIRECT_TO
                        Domain to forward traffic to (totally-legit.com)
  --get-path GET_PATH   Path for GET requests ("/api")
  --post-path POST_PATH
                        Path for POST requests ("/form")
  --custom-header CUSTOM_HEADER
                        Custom header for additional hardening ("Access-X-Control: True")
  --aws-access-key AWS_ACCESS_KEY
  --aws-secret-key AWS_SECRET_KEY
  --ssh-key SSH_KEY
  --do-token DO_TOKEN
  --dry-run             Detail what would happen
  -v, --verbose

[Redirectors]
  [Smart (OPSEC focused)]
   aws:ec2
   azure:vm
   digitalocean:droplet

  [Dumb (Proxy everything)]
   aws:api_gateway
   aws:cloudfront
   azure:app

[Phishservers]
 aws:ec2
 azure:vm
 digitalocean:droplet
```

### Examples
Deploy a smart redirector on an AWS EC2 instance that will have temporary.org point to it and proxy to fake.com if the custom header, GET & POST paths are validated and print all Terraform and Ansible output:
```bash
python3 ./script.py --deploy aws:ec2:redirector --aws-access-key <access_key> --aws-secret-key <secret_key> --resource-domain temporary.org --redirect-to fake.com --custom-header "Access-X: True" --get-path "/jquery/user/preferences" --post-path "/api/v2/jquery/settings/update" --ssh-key <private_ssh_key_path> -v
```

Deploy a dumb redirector on a randomly-named Azure App Service that will proxy all traffic to notC2.com:
```bash
python3 ./script.py --deploy azure:app:redirector --redirect-to notC2.com -v
```

### Requirements
Python3
Terraform
Ansible
AWS/Azure/DigitalOcean access

### To do
* Clean up dumb redirectors to remove GET & POST paths
* Add naming functionality for dumb redirectors
