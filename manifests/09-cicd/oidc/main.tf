
data "tls_certificate" "github" {

  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "github_actions_deploy" {
  name = "github-actions-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }

        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }

          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:Naveed6300/cloud-security-homelab:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "github_actions_deploy" {

  role       = aws_iam_role.github_actions_deploy.name
  policy_arn = aws_iam_policy.github_actions_permissions.arn
}

resource "aws_iam_policy" "github_actions_permissions" {

  name = "github-actions-deploy-permissions"

  policy = jsonencode({

    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3StateAndLab"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::cloud-lab-tfstate-random/*",
          "arn:aws:s3:::cloud-lab-tfstate-random"
        ]
      },
      {
        Sid    = "DynamoDBLocking"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:us-east-1:${data.aws_caller_identity.current.account_id}:table/terraform-locks"
      },

      {

        Sid    = "AppBucketManage"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:PutBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:CreateBucket",
          "s3:DeleteBucket"
        ]

        Resource = [

          "arn:aws:s3:::cloud-lab-cicd-demo-githubactions",
          "arn:aws:s3:::cloud-lab-cicd-demo-githubactions/*"
        ]
      }
    ]
  })
}
