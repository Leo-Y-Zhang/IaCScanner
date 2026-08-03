# INTENTIONALLY INSECURE EXAMPLE - for education only. Never deploy this.
# All values are synthetic: account 123456789012, fake hostnames, and
# obviously fake secrets. This file exists so IaCScanner rules have
# something realistic to detect.

variable "db_password" {
  description = "Database password (hardcoded default is the anti-pattern)"
  type        = string
  default     = "SuperSecret123-example"
}

resource "aws_s3_bucket" "example_data" {
  bucket = "example-data-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  name        = "example-admin-sg"
  description = "Admin access (world-open, the anti-pattern)"

  ingress {
    description = "SSH open to the world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP open to the world"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

resource "aws_db_instance" "app" {
  identifier        = "example-app-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username            = "appuser"
  password            = "hunter2-example-password"
  storage_encrypted   = false
  publicly_accessible = true
}

resource "aws_cloudtrail" "main" {
  name           = "example-trail"
  s3_bucket_name = "example-trail-bucket"
  enable_logging = false
}

resource "aws_iam_policy" "admin" {
  name   = "example-admin-policy"
  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "*", "Resource": "*"}
  ]
}
EOT
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = "example-data-bucket"
  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-data-bucket/*"
    }
  ]
}
EOT
}

# --- curated expansion (TL020-TL025): each is an explicit misconfiguration ---

resource "aws_kms_key" "example" {
  description         = "example key"
  enable_key_rotation = false
}

resource "aws_ecr_repository" "example" {
  name = "example-app"
  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_efs_file_system" "example" {
  encrypted = false
}

resource "aws_instance" "example" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_dynamodb_table" "example" {
  name     = "example-table"
  hash_key = "id"
  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_db_instance" "backups" {
  identifier              = "example-backups-db"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 0
}
