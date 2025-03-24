provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-unsecure-bucket"
  acl    = "public-read"  # 취약점: 공개 액세스 허용
  
  # 암호화 없음
}

resource "aws_instance" "vulnerable_web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  # 보안 그룹 없음
  
  # IMDSv2 설정 없음
}

resource "aws_iam_role" "admin_role" {
  name = "admin-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "admin_policy" {
  name = "admin-policy"
  role = aws_iam_role.admin_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "*"  # 취약점: 과도한 권한
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}