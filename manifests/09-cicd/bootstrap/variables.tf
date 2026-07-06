provider "aws" {
	region 	= var.region
	profile = var.aws_profile
}

variable "region" {
	type = string
	default = "us-east-1"
}

variable "aws_profile" {
	type = string
	default = "lab-deploy"
}

variable "state_bucket_name" {
	description = "S3 bucket for terraform state"
	type = string
}

variable "lock_table_name" {
	description = "DynamoDB name for state locking"
	type	    =  string
	default	    =  "terraform-locks"
}

