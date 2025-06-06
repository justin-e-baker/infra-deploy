# Output the VM's public IP so you can SSH into it
output "Access_VM" {
  description = "Public IP address of the Linux VM"
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.public_ip.ip_address} -i $HOME/.ssh/id_ed25519"
}