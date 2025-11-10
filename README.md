# infra-deploy
Dynamically deploy a redirector or phishserver.

## Features
This script is designed (i.e. vibe coded) to deploy infrastructure and configure it according to the specified YAML, supporting either a (smart/dumb) redirector or phishserver. Available options are:
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
usage: script.py [-h] -f FILE [-d] [-v]

Deploy / destroy from a YAML file

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to config file
  -d, --dry-run         Show what would happen
  -v, --verbose         Show Terraform/Ansible output

[Redirectors]
   [Smart] (OPSEC focused)
    aws:ec2
    azure:vm
    digitalocean:droplet

   [Dumb] (Proxy everything)
    aws:api_gateway
    aws:cloudfront
    azure:app

[Phishservers]
 aws:ec2
 azure:vm
 digitalocean:droplet
```

### Examples
Deploy a smart redirector on an AWS EC2 instance that will have temporary.org point to it and proxy to fake.com if the custom header, GET & POST paths are validated:
```yaml
action: deploy
provider: aws
resource: ec2
role: redirector
redirect_to: "https://fake.com"

resource_domain: "temporary.org"
get_path: "/api"
post_path: "/submit"
custom_header: "Access-X: true"
ssh_key: "~/.ssh/id_ed25519"

aws_access_key: "AKIA..."
aws_secret_key: "wJal..."
```

### Requirements
* Python3
* Terraform
* Ansible
* AWS/Azure/DigitalOcean access

### To do
* Clean up dumb redirectors to remove GET & POST paths
* Add naming functionality for dumb redirectors
