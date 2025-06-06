terraform {
  required_providers {
    digitalocean = {
      source = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

#passing the DO PAT & private SSH key at execution
variable "do_token" {}
variable "pvt_key" {}

provider "digitalocean" {
  token = var.do_token
}

#have terraform add SSH keys to droplet given to it, pub key specified should be added to digitalocean
data "digitalocean_ssh_key" "<ssh pubkey name>" {
  name = "<ssh_pubkey_in_digitalocean>"
}