provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "safe_bucket" {
  bucket = "my-secure-bucket"
  acl    = "private"  # 안전한 설정
  
  # 암호화 활성화
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # 로깅 활성화
  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-secure-log-bucket"
  acl    = "private"
}

resource "aws_instance" "secure_web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  # 보안 그룹 설정
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  
  # IMDSv2 활성화
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"  # IMDSv2 강제
  }
}

resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Allow web traffic"
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}