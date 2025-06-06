#provide SSH public key
resource "aws_key_pair" "deployer" {
  key_name = "deployer-key"
  public_key = "<ssh pub key>"
}

#create security group to restrict traffic to specified IP space
resource "aws_security_group" "ec2-group" {
  name = "ec2"
  description = "Allow traffic from specified IP space"

  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["<IP/space>"]
    description = "EC2 SSH Access"
  }
  
  egress {
	from_port   = 0
	to_port     = 0
	protocol    = -1
	cidr_blocks = ["0.0.0.0/0"]
	description = "Internet Access"
  }

  #adding 80 & 443 access for eventual script checking traffic flow
  ingress {
	from_port   = 443
	to_port     = 443
	protocol    = "tcp"
	cidr_blocks = ["0.0.0.0/0"]
	description = "EC2 HTTPS Access"
	ipv6_cidr_blocks    = []
	prefix_list_ids     = []
	security_groups     = []
  }

  ingress {
	from_port   = 80
	to_port     = 80
	protocol    = "tcp"
	cidr_blocks = ["0.0.0.0/0"]
	description = "EC2 HTTP Access"
	ipv6_cidr_blocks    = []
	prefix_list_ids     = []
	security_groups     = []
  }
}

resource "aws_instance" "ec2-server" {
    #
    ami = "ami-0b529f3487c2c0e7f"
    #double check type needed
    instance_type = "t2.medium"
    key_name = aws_key_pair.deployer.key_name
	vpc_security_group_ids = [aws_security_group.ec2-group.id]
    tags = {
      Name = "AWS EC2 Server"
    }
}