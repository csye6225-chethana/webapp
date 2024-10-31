packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.0.0, <2.0.0"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "source_ami" {
  type    = string
  default = "ami-0866a3c8686eaeeba" # Ubuntu 24.04 LTS image us-east-1
}

variable "ssh_username" {
  type    = string
  default = "ubuntu"
}

variable "subnet_id" {
  type    = string
  default = "subnet-0ba49ba3bce33fcd8" # picked from default vpc subnet us-east-1a
}

source "amazon-ebs" "my-ami" {
  region          = "${var.aws_region}"
  source_ami      = "${var.source_ami}"
  instance_type   = "t2.small"
  ssh_username    = "${var.ssh_username}"
  subnet_id       = "${var.subnet_id}"
  ami_name        = "csye6225_webapp_${formatdate("YYYY_MM_DD_HH_mm_ss", timestamp())}"
  ami_description = "CSYE6225 Assignment-4 image creation"

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 8
    volume_type           = "gp2"
    delete_on_termination = true
  }
}

build {
  sources = ["source.amazon-ebs.my-ami"]

  provisioner "file" {
    source      = "../webapp.zip"
    destination = "/tmp/webapp.zip"
  }

  provisioner "shell" {
    script = "setup_webapp.sh"
  }

  # Install CloudWatch Agent
  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y wget",

      # Download and install the CloudWatch Agent
      "wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb",
      "sudo dpkg -i -E ./amazon-cloudwatch-agent.deb",

      # Enable CloudWatch Agent to start on boot
      "sudo systemctl enable amazon-cloudwatch-agent",

      # Clean up installation files
      "rm -f amazon-cloudwatch-agent.deb"
    ]
  }

  # Cleanup provisioner to remove git and its dependencies
  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get remove -y git",
      "sudo apt-get autoremove -y",
      "sudo apt-get clean",
      "sudo rm -rf /usr/bin/git*",
      "sudo rm -rf /usr/lib/git-core"
    ]
  }
}