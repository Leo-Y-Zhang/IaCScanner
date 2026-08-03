# Secure counterpart to examples/vulnerable/main.tf.
# All values are synthetic: account 123456789012 and example hostnames.

variable "db_password" {
  description = "Database password, supplied at deploy time"
  type        = string
  sensitive   = true
}

resource "aws_s3_bucket" "example_data" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "example_data" {
  bucket                  = "example-data-bucket"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example_data" {
  bucket = "example-data-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "example_data" {
  bucket = "example-data-bucket"

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "example_data" {
  bucket        = "example-data-bucket"
  target_bucket = "example-log-bucket"
  target_prefix = "s3-access/"
}

resource "aws_security_group" "admin" {
  name        = "example-admin-sg"
  description = "Admin access from the private network only"

  ingress {
    description = "SSH from the corporate range"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}

resource "aws_db_instance" "app" {
  identifier        = "example-app-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username            = "appuser"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
}

resource "aws_cloudtrail" "main" {
  name           = "example-trail"
  s3_bucket_name = "example-trail-bucket"
  enable_logging = true
}

resource "aws_iam_policy" "readonly" {
  name   = "example-readonly-policy"
  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::example-data-bucket/*"
    }
  ]
}
EOT
}

# --- curated expansion (TL020-TL025): each is the secure counterpart ---

resource "aws_kms_key" "example" {
  description         = "example key"
  enable_key_rotation = true
}

resource "aws_ecr_repository" "example" {
  name = "example-app"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_efs_file_system" "example" {
  encrypted  = true
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/example"
}

resource "aws_instance" "example" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}

resource "aws_dynamodb_table" "example" {
  name     = "example-table"
  hash_key = "id"
  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_db_instance" "backups" {
  identifier              = "example-backups-db"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 7
}
