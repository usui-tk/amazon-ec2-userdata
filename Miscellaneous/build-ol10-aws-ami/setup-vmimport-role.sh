#!/usr/bin/env bash
#==============================================================================
# setup-vmimport-role.sh
#
# Creates the "vmimport" IAM service role required by AWS VM Import/Export.
#
# Reference:
#   https://docs.aws.amazon.com/vm-import/latest/userguide/required-permissions.html
#
# Usage:
#   ./setup-vmimport-role.sh <S3_BUCKET> [ROLE_NAME]
#
#   S3_BUCKET : The S3 bucket where the VMDK is staged. Must match the value
#               configured in env.properties.
#   ROLE_NAME : Name of the role to create (default: vmimport).
#==============================================================================

set -euo pipefail

S3_BUCKET="${1:-}"
ROLE_NAME="${2:-vmimport}"

[[ -z "${S3_BUCKET}" ]] && { echo "Usage: $0 <S3_BUCKET> [ROLE_NAME]" >&2; exit 1; }

WORKDIR=$(mktemp -d)
trap 'rm -rf "${WORKDIR}"' EXIT

#------------------------------------------------------------------------------
# 1) Trust policy (allow vmie.amazonaws.com to assume the role)
#------------------------------------------------------------------------------
cat > "${WORKDIR}/trust-policy.json" <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "vmie.amazonaws.com" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:Externalid": "vmimport" }
      }
    }
  ]
}
EOF

#------------------------------------------------------------------------------
# 2) Role policy (permissions on S3 / EC2 / KMS)
#------------------------------------------------------------------------------
cat > "${WORKDIR}/role-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}",
        "arn:aws:s3:::${S3_BUCKET}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject",
        "s3:GetBucketAcl"
      ],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}",
        "arn:aws:s3:::${S3_BUCKET}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:ModifySnapshotAttribute",
        "ec2:CopySnapshot",
        "ec2:RegisterImage",
        "ec2:Describe*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:CreateGrant",
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

#------------------------------------------------------------------------------
# 3) Create the role and attach the policy
#------------------------------------------------------------------------------
if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  echo "[INFO] Role ${ROLE_NAME} already exists. Updating its trust policy."
  aws iam update-assume-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-document "file://${WORKDIR}/trust-policy.json"
else
  echo "[INFO] Creating new role: ${ROLE_NAME}"
  aws iam create-role \
    --role-name "${ROLE_NAME}" \
    --assume-role-policy-document "file://${WORKDIR}/trust-policy.json" \
    --description "AWS VM Import/Export service role for oracle-linux-image-tools"
fi

aws iam put-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-name "vmimport-policy" \
  --policy-document "file://${WORKDIR}/role-policy.json"

echo
echo "[OK] vmimport role is ready"
echo "     Role Name : ${ROLE_NAME}"
echo "     S3 Bucket : ${S3_BUCKET}"
