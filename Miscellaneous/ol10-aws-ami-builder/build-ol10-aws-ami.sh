#!/usr/bin/env bash
#==============================================================================
# build-ol10-aws-ami.sh
#
# Wrapper script that builds an AWS AMI for Oracle Linux 10 Update 1 (x86_64)
# using the official Oracle oracle-linux-image-tools project.
#
# Reference:
#   https://github.com/oracle/oracle-linux/tree/main/oracle-linux-image-tools
#
# Pipeline phases:
#   Phase 0: Preflight checks (KVM support, required commands, free disk)
#   Phase 1: Provision the build host (KVM/libvirt/virt-install/libguestfs)
#   Phase 2: Clone the oracle/oracle-linux repository
#   Phase 3: Resolve ISO checksum and generate env.properties
#   Phase 4: Run oracle-linux-image-tools to produce a VMDK
#   Phase 5: Upload the VMDK to S3
#   Phase 6: Convert the VMDK to an EBS snapshot via import-snapshot
#   Phase 7: Register the snapshot as an AMI
#
# Usage:
#   1) Edit env.properties.aws-ol10 (WORKSPACE / S3_BUCKET / AWS_REGION, etc.)
#   2) ./build-ol10-aws-ami.sh --env env.properties.aws-ol10
#
# Options:
#   --env <file>          : Path to the environment properties file (required)
#   --skip-prereq         : Skip Phase 1 when build host packages are present
#   --skip-aws-import     : Skip Phases 5-7 (build VMDK only)
#   --build-only          : Run Phase 4 only
#   -h | --help           : Show this help
#==============================================================================

set -euo pipefail

readonly PGM=$(basename "$0")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
readonly OL_REPO_URL="https://github.com/oracle/oracle-linux.git"
readonly OL_TOOLS_SUBDIR="oracle-linux-image-tools"

# Default ISO information (Oracle Linux 10 Update 1, x86_64)
readonly DEFAULT_ISO_URL="https://yum.oracle.com/ISOS/OracleLinux/OL10/u1/x86_64/OracleLinux-R10-U1-x86_64-dvd.iso"
readonly DEFAULT_ISO_CHECKSUM_URL="${DEFAULT_ISO_URL}.sha256sum"

# Execution mode flags
SKIP_PREREQ=0
SKIP_AWS_IMPORT=0
BUILD_ONLY=0
ENV_FILE=""

#------------------------------------------------------------------------------
# Logging helpers
#------------------------------------------------------------------------------
log_info()  { echo -e "\033[1;34m[INFO]\033[0m  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m  $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }
log_error() { echo -e "\033[1;31m[ERROR]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }
log_step()  { echo -e "\n\033[1;32m========== $* ==========\033[0m\n"; }

die() { log_error "$*"; exit 1; }

#------------------------------------------------------------------------------
# Argument parsing
#------------------------------------------------------------------------------
usage() {
  sed -n '/^# build-ol10-aws-ami.sh/,/^#==============/p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env)              ENV_FILE="$2";       shift 2 ;;
      --skip-prereq)      SKIP_PREREQ=1;       shift ;;
      --skip-aws-import)  SKIP_AWS_IMPORT=1;   shift ;;
      --build-only)       BUILD_ONLY=1;        shift ;;
      -h|--help)          usage 0 ;;
      *)                  log_error "Unknown option: $1"; usage 1 ;;
    esac
  done

  [[ -z "${ENV_FILE}" ]] && die "--env option is required"
  [[ ! -f "${ENV_FILE}" ]] && die "Environment properties file not found: ${ENV_FILE}"
}

#------------------------------------------------------------------------------
# Load environment properties and validate required keys
#------------------------------------------------------------------------------
load_env() {
  log_step "Loading environment properties: ${ENV_FILE}"

  # shellcheck source=/dev/null
  source "${ENV_FILE}"

  # Required parameters (build)
  : "${WORKSPACE:?WORKSPACE is not defined}"
  : "${DISTR:=ol10-slim}"
  : "${ISO_URL:=${DEFAULT_ISO_URL}}"
  : "${CLOUD:=aws}"

  # Resolve workspace to an absolute path
  WORKSPACE=$(realpath -m "${WORKSPACE}")
  mkdir -p "${WORKSPACE}"

  # Required parameters for AWS import (unless skipped)
  if [[ ${SKIP_AWS_IMPORT} -eq 0 && ${BUILD_ONLY} -eq 0 ]]; then
    : "${S3_BUCKET:?S3_BUCKET is not defined}"
    : "${AWS_REGION:?AWS_REGION is not defined}"
    : "${AMI_NAME:=OracleLinux-10-U1-x86_64-$(date +%Y%m%d-%H%M)}"
    : "${AMI_DESCRIPTION:=Oracle Linux 10 Update 1 (x86_64) custom AMI built via oracle-linux-image-tools}"
    : "${BOOT_MODE:=uefi-preferred}"
    : "${VMIMPORT_ROLE_NAME:=vmimport}"
  fi

  # Defaults for optional parameters
  : "${WORK_REPO_DIR:=${WORKSPACE}/oracle-linux}"
  : "${BUILD_NUMBER:=0}"
  : "${SETUP_SWAP:=No}"
  : "${SELINUX:=enforcing}"
  : "${ROOT_FS:=xfs}"
  : "${DISK_SIZE_GB:=10}"
  : "${SERIAL_CONSOLE_RUNTIME:=Yes}"
  : "${BOOT_MODE_BUILD:=uefi}"

  log_info "WORKSPACE          = ${WORKSPACE}"
  log_info "DISTR              = ${DISTR}"
  log_info "CLOUD              = ${CLOUD}"
  log_info "ISO_URL            = ${ISO_URL}"
  log_info "WORK_REPO_DIR      = ${WORK_REPO_DIR}"
  if [[ ${SKIP_AWS_IMPORT} -eq 0 && ${BUILD_ONLY} -eq 0 ]]; then
    log_info "AWS_REGION         = ${AWS_REGION}"
    log_info "S3_BUCKET          = ${S3_BUCKET}"
    log_info "AMI_NAME           = ${AMI_NAME}"
    log_info "BOOT_MODE          = ${BOOT_MODE}"
  fi
}

#------------------------------------------------------------------------------
# Detect the runtime environment (EC2 instance type, ID, region)
#
# Uses IMDSv2 to query EC2 metadata. Returns silently when not on EC2.
# Globals (set):
#   IS_EC2 (0/1), EC2_INSTANCE_TYPE, EC2_INSTANCE_ID, EC2_REGION
#------------------------------------------------------------------------------
detect_ec2_environment() {
  IS_EC2=0
  EC2_INSTANCE_TYPE=""
  EC2_INSTANCE_ID=""
  EC2_REGION=""

  local token
  token=$(curl -fsS --max-time 2 \
    -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)

  [[ -z "${token}" ]] && return 0   # Not running on EC2

  IS_EC2=1
  EC2_INSTANCE_TYPE=$(curl -fsS --max-time 2 \
    -H "X-aws-ec2-metadata-token: ${token}" \
    http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "")
  EC2_INSTANCE_ID=$(curl -fsS --max-time 2 \
    -H "X-aws-ec2-metadata-token: ${token}" \
    http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "")
  EC2_REGION=$(curl -fsS --max-time 2 \
    -H "X-aws-ec2-metadata-token: ${token}" \
    http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "")
}

#------------------------------------------------------------------------------
# Print detailed guidance when KVM is unavailable on an EC2 host, then exit.
#
# Three scenarios are handled:
#   (A) C8i / M8i / R8i family -> nested virtualization just needs to be enabled
#   (B) Other (legacy) Nitro family -> switch to C8i/M8i/R8i or use .metal
#   (C) .metal family -> likely a configuration issue (kvm module not loaded)
#------------------------------------------------------------------------------
guide_ec2_kvm_issue() {
  local instance_type="$1"

  echo
  log_error "=========================================="
  log_error "  CPU virtualization extensions are NOT exposed on this EC2 host"
  log_error "=========================================="
  log_info "  Detected instance type: ${instance_type:-unknown}"
  log_info "  Detected region:        ${EC2_REGION:-unknown}"
  echo

  # Resolve the instance family
  # e.g. m8i.xlarge -> m8i, c8i-flex.large -> c8i-flex
  local family
  family=$(echo "${instance_type}" | sed -E 's/\.[^.]+$//')

  case "${family}" in
    c8i|c8i-flex|c8id|m8i|m8i-flex|m8id|r8i|r8i-flex|r8id)
      log_warn "[Case A] ${family} supports nested virtualization, but the feature is currently disabled."
      echo
      log_info "Action: enable nested virtualization on this instance."
      log_info ""
      log_info "  # 1) Stop the instance"
      log_info "  aws ec2 stop-instances --instance-ids ${EC2_INSTANCE_ID} --region ${EC2_REGION}"
      log_info "  aws ec2 wait instance-stopped --instance-ids ${EC2_INSTANCE_ID} --region ${EC2_REGION}"
      log_info ""
      log_info "  # 2) Enable nested virtualization"
      log_info "  aws ec2 modify-instance-cpu-options \\"
      log_info "    --instance-id ${EC2_INSTANCE_ID} --region ${EC2_REGION} \\"
      log_info "    --nested-virtualization enabled"
      log_info ""
      log_info "  # 3) Start the instance and re-run this script"
      log_info "  aws ec2 start-instances --instance-ids ${EC2_INSTANCE_ID} --region ${EC2_REGION}"
      log_info ""
      log_info "  Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html"
      ;;
    *.metal|*-metal|*metal*)
      log_warn "[Case C] ${instance_type} is bare metal but /dev/kvm is unavailable."
      echo
      log_info "Action:"
      log_info "  1) Check whether the kvm module is loaded"
      log_info "       lsmod | grep kvm"
      log_info "  2) If not loaded, load it manually"
      log_info "       sudo modprobe kvm-intel    # for Intel CPUs"
      log_info "       sudo modprobe kvm-amd      # for AMD CPUs"
      log_info "  3) Verify /dev/kvm permissions"
      log_info "       ls -l /dev/kvm"
      ;;
    *)
      log_warn "[Case B] ${family} does NOT support nested virtualization."
      echo
      log_info "Action: switch to one of the following options."
      log_info ""
      log_info "  Option 1 (recommended): Use a nested-virtualization-capable C8i / M8i / R8i instance"
      log_info "    - Example: m8i.xlarge (4 vCPU / 16 GB / approx \$0.30/h)"
      log_info "    - Same price as the standard instance; no extra charge"
      log_info "    - Sufficient spec to host the build VM"
      log_info ""
      log_info "  Option 2: Switch to a bare-metal instance"
      log_info "    - Example: c5n.metal (approx \$5/h; acceptable for short builds)"
      log_info ""
      log_info "  List of nested-virt-capable instance types in this region:"
      log_info "    aws ec2 describe-instance-types \\"
      log_info "      --filters \"Name=processor-info.supported-features,Values=nested-virtualization\" \\"
      log_info "      --query \"sort(InstanceTypes[].InstanceType)\" \\"
      log_info "      --region ${EC2_REGION:-ap-northeast-1}"
      ;;
  esac

  echo
  log_error "Build cannot proceed. Apply the action above and re-run this script."
  exit 1
}

#------------------------------------------------------------------------------
# Phase 0: Preflight checks
#------------------------------------------------------------------------------
phase0_preflight() {
  log_step "Phase 0: Preflight checks"

  # Forbid running directly as root (oracle-linux-image-tools must run unprivileged)
  [[ $EUID -eq 0 ]] && die "Do not run as root. Run as a regular user with sudo privileges."

  # Detect EC2 vs. on-prem
  detect_ec2_environment
  if [[ ${IS_EC2} -eq 1 ]]; then
    log_info "EC2 environment detected: ${EC2_INSTANCE_TYPE} (${EC2_INSTANCE_ID}) in ${EC2_REGION}"
  else
    log_info "Non-EC2 environment (assuming on-premises KVM host or similar)"
  fi

  # Check for CPU virtualization extensions
  if ! grep -E -q '(vmx|svm)' /proc/cpuinfo; then
    if [[ ${IS_EC2} -eq 1 ]]; then
      # On EC2, give targeted guidance based on the instance type
      guide_ec2_kvm_issue "${EC2_INSTANCE_TYPE}"
    else
      die "CPU virtualization extensions (Intel VT-x / AMD-V) are not available. Run on a bare-metal host or an environment with nested virtualization enabled."
    fi
  fi
  log_info "CPU virtualization extensions: enabled (vmx/svm detected)"

  # Check /dev/kvm
  if [[ ! -e /dev/kvm ]]; then
    log_warn "/dev/kvm is missing. It is expected to be loaded by Phase 1."
    log_warn "  If it is still missing afterwards, run:"
    log_warn "    sudo modprobe kvm-intel    # for Intel CPUs"
    log_warn "    sudo modprobe kvm-amd      # for AMD CPUs"
  else
    log_info "/dev/kvm: available"
  fi

  # Check required commands (those installed in Phase 1 are excluded)
  local required_cmds=("git" "curl" "sudo" "realpath")
  for cmd in "${required_cmds[@]}"; do
    command -v "${cmd}" >/dev/null 2>&1 || die "Required command not found: ${cmd}"
  done

  # Check AWS CLI (skipped if --skip-aws-import)
  if [[ ${SKIP_AWS_IMPORT} -eq 0 && ${BUILD_ONLY} -eq 0 ]]; then
    command -v aws >/dev/null 2>&1 || die "aws CLI not found. Install AWS CLI v2."
    aws sts get-caller-identity >/dev/null 2>&1 || die "AWS CLI authentication failed. Verify 'aws configure'."
  fi

  # Check workspace free space (30GB+ recommended)
  local avail_gb
  avail_gb=$(df -BG "${WORKSPACE}" | awk 'NR==2 {print $4}' | tr -d 'G')
  if [[ ${avail_gb} -lt 30 ]]; then
    log_warn "Workspace has only ${avail_gb}GB free. 30GB or more is recommended."
  else
    log_info "Workspace free space: ${avail_gb}GB"
  fi

  log_info "Preflight checks completed"
}

#------------------------------------------------------------------------------
# Phase 1: Provision the build host
#------------------------------------------------------------------------------
phase1_install_prereqs() {
  if [[ ${SKIP_PREREQ} -eq 1 ]]; then
    log_step "Phase 1: Skipping prerequisite package installation"
    return 0
  fi

  log_step "Phase 1: Provisioning build host (KVM / libvirt / virt-install / libguestfs)"

  # Detect OS family
  local os_id=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    os_id=$(. /etc/os-release && echo "${ID_LIKE:-${ID}}")
  fi

  case "${os_id}" in
    *rhel*|*fedora*|*ol*|*"oracle linux"*)
      log_info "RHEL/OL family detected. Installing packages via dnf."
      sudo dnf install -y \
        libvirt qemu-kvm libguestfs guestfs-tools virt-install \
        libvirt-client libvirt-daemon-config-network \
        libvirt-daemon-driver-qemu \
        edk2-ovmf \
        || die "Failed to install RHEL/OL packages"
      ;;
    *debian*|*ubuntu*)
      log_info "Debian/Ubuntu family detected. Installing packages via apt."
      sudo apt-get update -y
      sudo apt-get install -y \
        qemu-kvm libvirt-daemon-system libvirt-clients \
        virtinst libguestfs-tools \
        ovmf \
        || die "Failed to install Debian/Ubuntu packages"
      ;;
    *)
      die "Unsupported OS (ID_LIKE=${os_id}). Use RHEL/OL 9-family or Ubuntu/Debian."
      ;;
  esac

  # Enable and start libvirtd
  sudo systemctl enable --now libvirtd

  # Add the running user to libvirt and kvm groups (re-login may be required)
  if getent group libvirt >/dev/null 2>&1; then
    sudo usermod -aG libvirt "${USER}" || true
  fi
  if getent group kvm >/dev/null 2>&1; then
    sudo usermod -aG kvm "${USER}" || true
  fi

  log_info "Build host provisioning completed"
  log_warn "If you were just added to the libvirt group, log out and back in for it to take effect."
}

#------------------------------------------------------------------------------
# Phase 2: Clone the oracle/oracle-linux repository
#------------------------------------------------------------------------------
phase2_clone_repo() {
  log_step "Phase 2: Cloning oracle/oracle-linux repository"

  if [[ -d "${WORK_REPO_DIR}/.git" ]]; then
    log_info "Updating existing clone: ${WORK_REPO_DIR}"
    git -C "${WORK_REPO_DIR}" fetch --depth=1 origin main
    git -C "${WORK_REPO_DIR}" reset --hard origin/main
  else
    log_info "Cloning repository: ${OL_REPO_URL}"
    git clone --depth=1 "${OL_REPO_URL}" "${WORK_REPO_DIR}"
  fi

  [[ -d "${WORK_REPO_DIR}/${OL_TOOLS_SUBDIR}" ]] \
    || die "Directory ${OL_TOOLS_SUBDIR} not found in the clone"

  log_info "Repository ready"
}

#------------------------------------------------------------------------------
# Phase 3: Resolve ISO checksum and generate the build-time env.properties
#------------------------------------------------------------------------------
phase3_prepare_env_properties() {
  log_step "Phase 3: Resolving ISO checksum and generating env.properties"

  # If ISO_CHECKSUM is empty, fetch it from the .sha256sum file
  if [[ -z "${ISO_CHECKSUM:-}" ]]; then
    local checksum_url="${ISO_CHECKSUM_URL:-${ISO_URL}.sha256sum}"
    log_info "ISO_CHECKSUM not set; fetching from: ${checksum_url}"

    local raw_sum
    raw_sum=$(curl -fsSL "${checksum_url}" || true)
    if [[ -z "${raw_sum}" ]]; then
      die "Failed to fetch ISO checksum. Set ISO_CHECKSUM explicitly in your env.properties."
    fi
    # Expected format: "<sha256>  <filename>"
    ISO_CHECKSUM=$(echo "${raw_sum}" | awk '{print $1}')
    log_info "ISO_CHECKSUM = ${ISO_CHECKSUM}"
  fi

  # Generate the env.properties file consumed by the build tool
  local tool_env="${WORK_REPO_DIR}/${OL_TOOLS_SUBDIR}/env.properties.local"
  cat > "${tool_env}" <<EOF
# Auto-generated: $(date)
# Source: ${ENV_FILE}

WORKSPACE=${WORKSPACE}
DISTR=${DISTR}
CLOUD=${CLOUD}
ISO_URL=${ISO_URL}
ISO_CHECKSUM=${ISO_CHECKSUM}

BUILD_NUMBER=${BUILD_NUMBER}
SETUP_SWAP=${SETUP_SWAP}
SELINUX=${SELINUX}
ROOT_FS=${ROOT_FS}
DISK_SIZE_GB=${DISK_SIZE_GB}
SERIAL_CONSOLE_RUNTIME=${SERIAL_CONSOLE_RUNTIME}
BOOT_MODE=${BOOT_MODE_BUILD}

# Kernel selection (uek or rhck) - falls back to distr default if unset
${KERNEL:+KERNEL=${KERNEL}}

# linux-firmware retention - "No" recommended for cloud VMs (smaller image)
${LINUX_FIRMWARE:+LINUX_FIRMWARE=${LINUX_FIRMWARE}}

# Root password / SSH key (prefer cloud-init for production use)
${ROOT_PASSWORD:+ROOT_PASSWORD=${ROOT_PASSWORD}}
${ROOT_SSH_KEY:+ROOT_SSH_KEY=${ROOT_SSH_KEY}}

# cloud-init configuration
${CLOUD_INIT:+CLOUD_INIT=${CLOUD_INIT}}
${CLOUD_USER:+CLOUD_USER=${CLOUD_USER}}
EOF

  log_info "Generated env.properties.local: ${tool_env}"
  echo "----- env.properties.local -----"
  grep -v '^#' "${tool_env}" | grep -v '^$'
  echo "--------------------------------"
}

#------------------------------------------------------------------------------
# Phase 4: Run oracle-linux-image-tools to produce the VMDK
#------------------------------------------------------------------------------
phase4_run_build() {
  log_step "Phase 4: Running oracle-linux-image-tools to build the VMDK"

  local tool_dir="${WORK_REPO_DIR}/${OL_TOOLS_SUBDIR}"
  local tool_env="${tool_dir}/env.properties.local"

  log_info "Starting build (this typically takes 20-60 minutes)"
  ( cd "${tool_dir}" && ./bin/build-image.sh --env "${tool_env}" ) \
    || die "build-image.sh failed"

  # Locate the produced VMDK file
  # Naming convention: OL10U1_x86_64-aws-b<BUILD_NUMBER>.vmdk
  VMDK_PATH=$(find "${WORKSPACE}" -maxdepth 3 -name '*.vmdk' -newer "${tool_env}" 2>/dev/null | head -n 1)

  [[ -z "${VMDK_PATH}" || ! -f "${VMDK_PATH}" ]] \
    && die "Built VMDK file was not found"

  log_info "VMDK file: ${VMDK_PATH}"
  log_info "Size:      $(du -h "${VMDK_PATH}" | awk '{print $1}')"
}

#------------------------------------------------------------------------------
# Phase 5: Upload the VMDK to S3
#------------------------------------------------------------------------------
phase5_upload_to_s3() {
  log_step "Phase 5: Uploading VMDK to S3"

  local vmdk_filename
  vmdk_filename=$(basename "${VMDK_PATH}")
  S3_KEY="${S3_KEY_PREFIX:-ol10-ami-import}/${vmdk_filename}"

  # Create the S3 bucket if it does not exist
  if ! aws s3api head-bucket --bucket "${S3_BUCKET}" --region "${AWS_REGION}" 2>/dev/null; then
    log_info "S3 bucket ${S3_BUCKET} does not exist; creating it"
    if [[ "${AWS_REGION}" == "us-east-1" ]]; then
      aws s3api create-bucket --bucket "${S3_BUCKET}" --region "${AWS_REGION}"
    else
      aws s3api create-bucket --bucket "${S3_BUCKET}" --region "${AWS_REGION}" \
        --create-bucket-configuration LocationConstraint="${AWS_REGION}"
    fi
    # Block all public access on the new bucket
    aws s3api put-public-access-block --bucket "${S3_BUCKET}" \
      --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  fi

  log_info "Uploading: s3://${S3_BUCKET}/${S3_KEY}"
  aws s3 cp "${VMDK_PATH}" "s3://${S3_BUCKET}/${S3_KEY}" --region "${AWS_REGION}"
  log_info "Upload completed"
}

#------------------------------------------------------------------------------
# Phase 6: Convert the VMDK to an EBS snapshot via import-snapshot
#------------------------------------------------------------------------------
phase6_import_snapshot() {
  log_step "Phase 6: Creating EBS snapshot via import-snapshot"

  # Confirm that the vmimport role exists
  if ! aws iam get-role --role-name "${VMIMPORT_ROLE_NAME}" >/dev/null 2>&1; then
    die "IAM role '${VMIMPORT_ROLE_NAME}' does not exist. Run setup-vmimport-role.sh first."
  fi

  local import_task
  import_task=$(aws ec2 import-snapshot \
    --region "${AWS_REGION}" \
    --description "${AMI_NAME} - import" \
    --disk-container "Format=VMDK,UserBucket={S3Bucket=${S3_BUCKET},S3Key=${S3_KEY}}" \
    --role-name "${VMIMPORT_ROLE_NAME}" \
    --query 'ImportTaskId' --output text)

  log_info "import-snapshot task ID: ${import_task}"
  log_info "Polling until completion (typically 10-30 minutes)"

  while :; do
    local status progress
    read -r status progress <<< "$(aws ec2 describe-import-snapshot-tasks \
      --region "${AWS_REGION}" \
      --import-task-ids "${import_task}" \
      --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.[Status,Progress]' \
      --output text)"

    log_info "  Status: ${status} (${progress:-0}%)"

    case "${status}" in
      completed) break ;;
      deleted|cancelled|deleting)
        die "import-snapshot task failed: ${status}"
        ;;
    esac
    sleep 60
  done

  SNAPSHOT_ID=$(aws ec2 describe-import-snapshot-tasks \
    --region "${AWS_REGION}" \
    --import-task-ids "${import_task}" \
    --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId' \
    --output text)

  log_info "Snapshot ready: ${SNAPSHOT_ID}"

  # Tag the snapshot
  aws ec2 create-tags \
    --region "${AWS_REGION}" \
    --resources "${SNAPSHOT_ID}" \
    --tags "Key=Name,Value=${AMI_NAME}" \
           "Key=BuiltBy,Value=oracle-linux-image-tools" \
           "Key=Distr,Value=${DISTR}"
}

#------------------------------------------------------------------------------
# Phase 7: Register the snapshot as an AMI
#------------------------------------------------------------------------------
phase7_register_ami() {
  log_step "Phase 7: Registering AMI via register-image"

  local ami_id
  ami_id=$(aws ec2 register-image \
    --region "${AWS_REGION}" \
    --name "${AMI_NAME}" \
    --description "${AMI_DESCRIPTION}" \
    --architecture x86_64 \
    --root-device-name /dev/sda1 \
    --virtualization-type hvm \
    --ena-support \
    --boot-mode "${BOOT_MODE}" \
    --tpm-support v2.0 \
    --imds-support v2.0 \
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={SnapshotId=${SNAPSHOT_ID},VolumeSize=${DISK_SIZE_GB},VolumeType=gp3,DeleteOnTermination=true}" \
    --query 'ImageId' --output text) \
    || die "register-image failed"

  log_info "AMI registered: ${ami_id}"

  # Tag the AMI
  aws ec2 create-tags \
    --region "${AWS_REGION}" \
    --resources "${ami_id}" \
    --tags "Key=Name,Value=${AMI_NAME}" \
           "Key=OS,Value=OracleLinux10U1" \
           "Key=Architecture,Value=x86_64" \
           "Key=BuiltBy,Value=oracle-linux-image-tools" \
           "Key=BuildDate,Value=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo
  log_info "=========================================="
  log_info "  AMI build completed successfully"
  log_info "=========================================="
  log_info "  AMI ID:       ${ami_id}"
  log_info "  AMI Name:     ${AMI_NAME}"
  log_info "  Region:       ${AWS_REGION}"
  log_info "  Snapshot ID:  ${SNAPSHOT_ID}"
  log_info "  Boot Mode:    ${BOOT_MODE}"
  log_info "  ENA Support:  enabled"
  log_info "=========================================="
}

#------------------------------------------------------------------------------
# Main entrypoint
#------------------------------------------------------------------------------
main() {
  parse_args "$@"
  load_env

  phase0_preflight
  phase1_install_prereqs
  phase2_clone_repo
  phase3_prepare_env_properties
  phase4_run_build

  if [[ ${BUILD_ONLY} -eq 1 || ${SKIP_AWS_IMPORT} -eq 1 ]]; then
    log_info "Build-only mode. Skipping AWS import phases."
    log_info "VMDK file: ${VMDK_PATH}"
    exit 0
  fi

  phase5_upload_to_s3
  phase6_import_snapshot
  phase7_register_ami
}

main "$@"
