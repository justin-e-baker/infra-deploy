output "Access_Droplet" {
  description = "Public IP of the Digital Ocean Droplet. Access with your private SSH key"
  value = "ssh root@${digitalocean_droplet.Droplet.ipv4_address} -i $HOME/.ssh/id_ed25519"
}