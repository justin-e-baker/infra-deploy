#create a droplet resource
resource "digitalocean_droplet" "Droplet" {
    image = "ubuntu-24-10-x64"
    name = "Droplet"
    region = "nyc3"
    size = "s-2vcpu-4gb"
    
    #specify which public SSH keys to add to droplet, ensure they match what's in provider.tf
    ssh_keys = [data.digitalocean_ssh_key.<ssh pubkey name>.id]
}

resource "digitalocean_firewall" "SSH-and-Web" {
  name = "ssh-and-web"
  
  droplet_ids = [digitalocean_droplet.Droplet.id]
  
  #digitalocean firewall to allow 22, 80 & 443 in
  inbound_rule {
    protocol = "tcp"
    port_range = "22"
    source_addresses = ["<IP/space>"]
  }
  
  inbound_rule {
    protocol = "tcp"
    port_range = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  inbound_rule {
    protocol = "tcp"
    port_range = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  outbound_rule {
    protocol = "tcp"
    port_range = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  outbound_rule {
    protocol = "udp"
    port_range = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}