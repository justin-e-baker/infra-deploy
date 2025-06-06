output "Access_EC2" {
  description = "Public IP of the EC2 instance. Access with your private SSH key"
  value = "ssh ubuntu@${aws_instance.ec2-server.public_ip} -i $HOME/.ssh/id_ed25519"
}
