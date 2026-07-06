
terraform {

  required_version = "~> 1.15"

  required_providers {

    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"

    }

  }

  backend "s3" {

    bucket         = "cloud-lab-tfstate-random"
    key            = "oidc/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}

provider "aws" {

  region  = "us-east-1"
  profile = "lab-deploy"
}
