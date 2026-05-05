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
#   Phase 0:   Preflight checks (KVM support, required commands, free disk)
#   Phase 1:   Provision the build host (KVM/libvirt/virt-install/libguestfs)
#   Phase 2:   Grant the qemu user traverse access to WORKSPACE (ACL)
#   Phase 3:   Clone the oracle/oracle-linux repository
#   Phase 4:   Resolve ISO checksum and generate env.properties
#   Phase 5:   Run oracle-linux-image-tools to produce a VMDK
#   Phase 6:   Upload the VMDK to S3
#   Phase 7:   Convert the VMDK to an EBS snapshot via import-snapshot
#   Phase 8:   Register the snapshot as an AMI
#
# Usage:
#   1) Edit env.properties.aws-ol10 (WORKSPACE / S3_BUCKET / AWS_REGION, etc.)
#   2) ./build-ol10-aws-ami.sh --env env.properties.aws-ol10
#
# Options:
#   --env <file>          : Path to the environment properties file (required)
#   --skip-prereq         : Skip Phase 1 when build host packages are present
#   --skip-aws-import     : Skip Phases 5-7 (build VMDK only)
#   --build-only          : Run Phase 5 only
#   -h | --help           : Show this help
#==============================================================================

set -euo pipefail

readonly OL_REPO_URL="https://github.com/oracle/oracle-linux.git"
readonly OL_TOOLS_SUBDIR="oracle-linux-image-tools"

# Default ISO information (Oracle Linux 10 Update 1, x86_64)
# DEFAULT_ISO_URL is consumed in load_env() as the fallback when the user
# has not set ISO_URL in their env.properties.
readonly DEFAULT_ISO_URL="https://yum.oracle.com/ISOS/OracleLinux/OL10/u1/x86_64/OracleLinux-R10-U1-x86_64-dvd.iso"

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

  # Explicit return 0 to avoid the "&& die" pattern leaking a non-zero exit
  # status when both checks pass. With set -e in the caller, returning a
  # non-zero status from this function would silently abort the script.
  return 0
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
    # AMI registration boot mode.
    # IMPORTANT: oracle-linux-image-tools currently produces BIOS-only images
    # for the AWS target (BOOT_MODE_BUILD must be 'bios'), so the AMI must
    # be registered as legacy-bios. uefi-preferred would require an ESP in
    # the disk image, which the upstream tool does not generate for AWS.
    : "${BOOT_MODE:=legacy-bios}"
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
  # Build-time boot mode.
  # IMPORTANT: Oracle's build-image.sh enforces BOOT_MODE=bios for AWS.
  # See cloud/aws/image-scripts.sh in oracle-linux-image-tools.
  : "${BOOT_MODE_BUILD:=bios}"

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

  # Validate BOOT_MODE_BUILD: oracle-linux-image-tools restricts AWS to bios.
  if [[ "${CLOUD,,}" == "aws" && "${BOOT_MODE_BUILD,,}" != "bios" ]]; then
    log_error "BOOT_MODE_BUILD='${BOOT_MODE_BUILD}' is not supported for CLOUD=aws."
    log_error "  oracle-linux-image-tools only accepts BOOT_MODE=bios for AWS targets."
    log_error "  Set BOOT_MODE_BUILD=\"bios\" in env.properties.local (or remove the line"
    log_error "  to use the default)."
    die "Invalid BOOT_MODE_BUILD for AWS"
  fi

  # Cross-check the AMI registration boot mode.
  # When the build produces a BIOS-only image, registering with uefi or
  # uefi-preferred would fail at boot on UEFI-capable instances.
  if [[ ${SKIP_AWS_IMPORT} -eq 0 && ${BUILD_ONLY} -eq 0 ]]; then
    if [[ "${BOOT_MODE_BUILD,,}" == "bios" && "${BOOT_MODE,,}" != "legacy-bios" ]]; then
      log_warn "BOOT_MODE_BUILD=bios produces a BIOS-only image, but AMI BOOT_MODE='${BOOT_MODE}'."
      log_warn "  This will likely fail to boot on UEFI-capable instances."
      log_warn "  Recommended setting: BOOT_MODE=\"legacy-bios\""
    fi
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

  # IMPORTANT: detect bare-metal instances against the FULL instance_type,
  # not against `family` — the family extraction strips the trailing
  # ".metal" suffix, so 'c5n.metal' becomes 'c5n' and would otherwise match
  # the catch-all "*) Case B" branch incorrectly.
  if [[ "${instance_type}" == *.metal || "${instance_type}" == *.metal-* ]]; then
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
  else
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
  fi

  echo
  log_error "Build cannot proceed. Apply the action above and re-run this script."
  exit 1
}

#------------------------------------------------------------------------------
# Phase 0: Preflight checks
#------------------------------------------------------------------------------
phase0_preflight_checks() {
  log_step "Phase 0: Preflight checks"

  # Warn (but do not abort) if running as root.
  # The upstream oracle-linux-image-tools project recommends running as a
  # non-privileged user, but in environments such as freshly-launched EC2
  # instances where only root is available, allow execution to continue.
  if [[ $EUID -eq 0 ]]; then
    log_warn "Running as root. oracle-linux-image-tools is designed to run as an unprivileged user."
    log_warn "  Continuing anyway because the user explicitly opted in."
    log_warn "  If KVM or libvirt permission errors occur in later phases, switch to a regular user with sudo."
  fi

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
  local required_cmds=("git" "curl" "sudo" "realpath" "findmnt" "df")
  for cmd in "${required_cmds[@]}"; do
    command -v "${cmd}" >/dev/null 2>&1 || die "Required command not found: ${cmd}"
  done

  # Check AWS CLI (skipped if --skip-aws-import)
  if [[ ${SKIP_AWS_IMPORT} -eq 0 && ${BUILD_ONLY} -eq 0 ]]; then
    command -v aws >/dev/null 2>&1 || die "aws CLI not found. Install AWS CLI v2."
    aws sts get-caller-identity >/dev/null 2>&1 || die "AWS CLI authentication failed. Verify 'aws configure'."
  fi

  # Check workspace free space and underlying filesystem characteristics.
  # We read these via stat/findmnt because the WORKSPACE may live on tmpfs
  # (typical for /tmp on modern Linux) which has size and persistence
  # implications worth surfacing before the build starts.
  local avail_gb fstype mount_opts
  avail_gb=$(df -BG "${WORKSPACE}" | awk 'NR==2 {print $4}' | tr -d 'G')
  fstype=$(findmnt -n -o FSTYPE --target "${WORKSPACE}" 2>/dev/null || echo "unknown")
  mount_opts=$(findmnt -n -o OPTIONS --target "${WORKSPACE}" 2>/dev/null || echo "")

  log_info "Workspace path:       ${WORKSPACE}"
  log_info "Workspace filesystem: ${fstype}"
  log_info "Workspace free space: ${avail_gb}GB"

  # Warn about insufficient free space (build needs ~20GB; 30GB recommended).
  if [[ ${avail_gb} -lt 20 ]]; then
    log_error "Workspace has only ${avail_gb}GB free. The build needs at least 20GB."
    log_error "  Move WORKSPACE to a larger location, e.g. /var/tmp/ol10-build-ws"
    log_error "  (which is typically disk-backed and persistent across reboots)."
    die "Insufficient free space at WORKSPACE."
  elif [[ ${avail_gb} -lt 30 ]]; then
    log_warn "Workspace has only ${avail_gb}GB free. 30GB or more is recommended."
  fi

  # tmpfs caveats: RAM-backed, size-capped, cleared on reboot.
  if [[ "${fstype}" == "tmpfs" ]]; then
    log_warn "Workspace is on tmpfs (RAM-backed):"
    log_warn "  * Size is typically capped at 50% of system RAM. Verify ${avail_gb}GB is enough."
    log_warn "  * Contents are cleared on reboot. A reboot mid-build will lose all progress."
    log_warn "  * If you encounter ENOSPC errors during Phase 5, switch to /var/tmp:"
    log_warn "      WORKSPACE=\"/var/tmp/ol10-build-ws\""
  fi

  # noexec is fatal: oracle-linux-image-tools runs scripts inside WORKSPACE.
  if [[ ",${mount_opts}," == *",noexec,"* ]]; then
    log_error "The filesystem hosting ${WORKSPACE} is mounted with 'noexec'."
    log_error "  oracle-linux-image-tools executes scripts in the workspace; this will fail."
    log_error "  Move WORKSPACE to a filesystem without noexec, e.g. /var/tmp/ol10-build-ws"
    log_error "  Current mount options: ${mount_opts}"
    die "WORKSPACE filesystem has noexec; cannot proceed."
  fi

  log_info "Preflight checks completed"
}

#------------------------------------------------------------------------------
# Phase 1: Provision the build host
#------------------------------------------------------------------------------
phase1_install_prerequisites() {
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
        libosinfo osinfo-db osinfo-db-tools \
        acl \
        || die "Failed to install RHEL/OL packages"
      ;;
    *debian*|*ubuntu*)
      log_info "Debian/Ubuntu family detected. Installing packages via apt."
      sudo apt-get update -y
      sudo apt-get install -y \
        qemu-kvm libvirt-daemon-system libvirt-clients \
        virtinst libguestfs-tools \
        ovmf \
        libosinfo-bin osinfo-db osinfo-db-tools \
        acl \
        || die "Failed to install Debian/Ubuntu packages"
      ;;
    *)
      die "Unsupported OS (ID_LIKE=${os_id}). Use RHEL/OL 9-family or Ubuntu/Debian."
      ;;
  esac

  # Enable and start the libvirt daemon.
  # Modern RHEL 9+ / Fedora 35+ / Debian 12+ ship modular libvirt daemons
  # (virtqemud, virtnetworkd, virtstoraged, ...) instead of monolithic
  # libvirtd. We try the legacy unit first (still present on most distros
  # as a compatibility wrapper), then fall back to modular daemons.
  if systemctl list-unit-files libvirtd.service >/dev/null 2>&1 \
     && systemctl list-unit-files libvirtd.service 2>/dev/null | grep -q '^libvirtd\.service'; then
    sudo systemctl enable --now libvirtd
    log_info "Enabled monolithic libvirtd.service"
  elif systemctl list-unit-files virtqemud.service 2>/dev/null | grep -q '^virtqemud\.service'; then
    sudo systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket 2>/dev/null \
      || log_warn "Some modular libvirt sockets could not be enabled (may not exist on this distro)"
    log_info "Enabled modular libvirt daemons (virtqemud / virtnetworkd / virtstoraged)"
  else
    log_warn "Neither libvirtd.service nor virtqemud.service was found."
    log_warn "  You may need to start the libvirt daemon manually before Phase 5."
  fi

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
# Detect the system's qemu/libvirt run-as username.
#
# When libvirt runs in system mode (qemu:///system, the default that Oracle's
# image-tools relies on), the spawned qemu process runs as a non-root user.
# Different distros use different names:
#   * RHEL / Fedora / Oracle Linux : "qemu"
#   * Debian / Ubuntu              : "libvirt-qemu"
#
# Returns the username on stdout, or 1 if neither user exists.
#------------------------------------------------------------------------------
detect_qemu_user() {
  local candidates=("qemu" "libvirt-qemu")
  local user
  for user in "${candidates[@]}"; do
    if id "${user}" >/dev/null 2>&1; then
      echo "${user}"
      return 0
    fi
  done
  return 1
}

#------------------------------------------------------------------------------
# Phase 2: Ensure the workspace path is reachable by the qemu user.
#
# libvirt in system mode launches QEMU as a non-root user. When WORKSPACE
# lives under /root (or any directory without world-execute bit), the qemu
# user cannot traverse the path and virt-install fails with:
#   "Cannot access storage file ... (as uid:107, gid:107): Permission denied"
#
# Fix: walk every parent directory from WORKSPACE up to '/' and grant the
# qemu user a traverse-only ACL (u:qemu:x). This is more granular and safer
# than chmod o+x on /root.
#------------------------------------------------------------------------------
phase2_grant_qemu_access() {
  log_step "Phase 2: Ensuring qemu user can access the workspace"

  local qemu_user
  qemu_user=$(detect_qemu_user) || {
    log_warn "Could not detect a qemu/libvirt-qemu user."
    log_warn "  Phase 1 may not have completed successfully, or libvirt is not installed."
    log_warn "  Skipping ACL setup. Phase 5 will likely fail."
    return 0
  }
  log_info "Detected qemu user: ${qemu_user}"

  if ! command -v setfacl >/dev/null 2>&1; then
    log_warn "setfacl not found. Install the 'acl' package:"
    log_warn "  sudo dnf install acl       # RHEL/OL/Fedora"
    log_warn "  sudo apt-get install acl   # Debian/Ubuntu"
    log_warn "Continuing without ACL setup; Phase 5 may fail."
    return 0
  fi

  log_info "Granting traverse-only ACL (u:${qemu_user}:x) to each parent of WORKSPACE."
  log_info "  This allows qemu to reach files under ${WORKSPACE} without exposing"
  log_info "  contents to the world. Existing permissions are preserved."

  # Walk up the path, applying setfacl to each existing directory.
  local path="${WORKSPACE}"
  local fixed_count=0
  local skipped_count=0
  while [[ "${path}" != "/" && -n "${path}" ]]; do
    if [[ -d "${path}" ]]; then
      # Test whether the qemu user can already traverse it
      if sudo -u "${qemu_user}" test -x "${path}" 2>/dev/null; then
        skipped_count=$((skipped_count + 1))
      else
        log_info "  -> setfacl -m u:${qemu_user}:x ${path}"
        if sudo setfacl -m "u:${qemu_user}:x" "${path}" 2>/dev/null; then
          fixed_count=$((fixed_count + 1))
        else
          log_warn "    failed (filesystem may not support ACLs)"
        fi
      fi
    fi
    path=$(dirname "${path}")
  done

  log_info "ACL setup: ${fixed_count} directories updated, ${skipped_count} already accessible"

  # Final verification: can the qemu user actually read a file in WORKSPACE?
  local probe="${WORKSPACE}/.qemu-access-probe"
  : > "${probe}"
  if sudo -u "${qemu_user}" test -r "${probe}" 2>/dev/null; then
    log_info "Verified: qemu user '${qemu_user}' can access ${WORKSPACE}"
    rm -f "${probe}"
  else
    rm -f "${probe}"
    log_error "Verification failed: qemu user '${qemu_user}' still cannot read ${WORKSPACE}"
    log_error "  Possible reasons:"
    log_error "    * The filesystem does not support POSIX ACLs (e.g. tmpfs without acl mount option)"
    log_error "    * SELinux is blocking access (check: sudo ausearch -m avc -ts recent)"
    log_error "  Workaround: relocate WORKSPACE to a path under /var/lib or /var/tmp:"
    log_error "    WORKSPACE=\"/var/lib/ol10-build-ws\""
    die "Workspace is not accessible by the qemu user."
  fi
}

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
phase3_clone_repository() {
  log_step "Phase 3: Cloning oracle/oracle-linux repository"

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
# Derive the official Oracle checksum file URL from an ISO URL.
#
# Oracle publishes per-release checksum files at
#   https://linux.oracle.com/security/gpg/checksum/
# with names of the form:
#   OracleLinux-R{major}-U{minor}-Server-{arch}.checksum
#
# Returns 0 with the URL on stdout when the ISO URL matches the expected
# Oracle naming convention, or 1 otherwise.
#------------------------------------------------------------------------------
derive_oracle_checksum_url() {
  local iso_url="$1"
  local iso_filename
  iso_filename=$(basename "${iso_url}")

  # Match patterns like:
  #   OracleLinux-R10-U1-x86_64-dvd.iso
  #   OracleLinux-R9-U7-x86_64-dvd.iso
  #   OracleLinux-R8-U1-Server-x86_64-dvd.iso  (older naming)
  if [[ "${iso_filename}" =~ ^OracleLinux-R([0-9]+)-U([0-9]+)-(Server-)?([^-]+)-(dvd|boot)(-uek)?\.iso$ ]]; then
    local release="R${BASH_REMATCH[1]}"
    local update="U${BASH_REMATCH[2]}"
    local arch="${BASH_REMATCH[4]}"
    echo "https://linux.oracle.com/security/gpg/checksum/OracleLinux-${release}-${update}-Server-${arch}.checksum"
    return 0
  fi
  return 1
}

#------------------------------------------------------------------------------
# Find a valid OS_VARIANT short-id available in the local osinfo-db.
#
# Oracle's build-image.sh validates OS_VARIANT against the local osinfo
# database via:
#   osinfo-query os --fields=short-id short-id="${OS_VARIANT}"
#
# When the host's osinfo-db package is older than Oracle Linux 10's release,
# auto-detection fails with:
#   "can't determine OS_VARIANT; you must define it in your environment file"
#
# This function tries a list of candidate short-ids in priority order and
# returns the first one that is actually present in the local database.
# If oraclelinux10 entries exist they are preferred; otherwise we fall back
# to RHEL 10 (binary compatible), then a generic Linux variant. virt-install
# accepts these and the OL10 installer still runs from the ISO regardless.
#------------------------------------------------------------------------------
detect_os_variant() {
  local -a candidates=(
    # Most specific match for Oracle Linux 10 update 1
    "oraclelinux10.1"
    "oraclelinux10.0"
    "oraclelinux10"
    # RHEL 10 is binary-compatible with OL10 and a safe stand-in
    "rhel10.1"
    "rhel10.0"
    "rhel10-unknown"
    "rhel10"
    # CentOS Stream 10 is also a close match
    "centos-stream10"
    "centos-stream-10"
    # Last-known Oracle Linux entries (still close enough to OL10 for virt-install)
    "oraclelinux9.7"
    "oraclelinux9.6"
    "oraclelinux9.5"
    "oraclelinux9.4"
    "oraclelinux9.3"
    "oraclelinux9.2"
    "oraclelinux9.1"
    "oraclelinux9.0"
    "oraclelinux9"
    # Generic Linux fallbacks
    "linux2024"
    "linux2023"
    "linux2022"
  )

  if ! command -v osinfo-query >/dev/null 2>&1; then
    return 1
  fi

  # Build a single list of all known short-ids on the host (skip header rows)
  local available
  available=$(osinfo-query os --fields=short-id 2>/dev/null \
    | tail -n +3 | awk '{print $1}' | grep -v '^$')

  if [[ -z "${available}" ]]; then
    return 1
  fi

  local variant
  for variant in "${candidates[@]}"; do
    if echo "${available}" | grep -qx "${variant}"; then
      echo "${variant}"
      return 0
    fi
  done

  return 1
}

#------------------------------------------------------------------------------
# Phase 4: Resolve ISO checksum and OS_VARIANT, then generate
#          oracle-linux-image-tools' env.properties.local
#------------------------------------------------------------------------------
phase4_prepare_env_properties() {
  log_step "Phase 4: Resolving ISO checksum and generating env.properties"

  # If ISO_CHECKSUM is empty, fetch it from the published checksum file.
  if [[ -z "${ISO_CHECKSUM:-}" ]]; then
    local iso_filename
    iso_filename=$(basename "${ISO_URL}")
    local raw_sum=""
    local checksum_url=""

    # Build the list of candidate URLs in priority order:
    #   1. User-supplied ISO_CHECKSUM_URL (if any)
    #   2. Legacy "<iso_url>.sha256sum" (works for OL7/OL8 on some mirrors)
    #   3. Modern linux.oracle.com signed checksum file (OL9+)
    local -a candidate_urls=()
    [[ -n "${ISO_CHECKSUM_URL:-}" ]] && candidate_urls+=("${ISO_CHECKSUM_URL}")
    candidate_urls+=("${ISO_URL}.sha256sum")
    local oracle_url
    if oracle_url=$(derive_oracle_checksum_url "${ISO_URL}"); then
      candidate_urls+=("${oracle_url}")
    fi

    for checksum_url in "${candidate_urls[@]}"; do
      log_info "Attempting checksum fetch from: ${checksum_url}"
      raw_sum=$(curl -fsSL "${checksum_url}" 2>/dev/null || true)
      if [[ -n "${raw_sum}" ]]; then
        log_info "  -> success"
        break
      fi
      log_warn "  -> failed (HTTP error or empty response)"
    done

    if [[ -z "${raw_sum}" ]]; then
      log_error "Failed to fetch the ISO checksum from any of the candidate URLs."
      log_error "Manual workaround:"
      log_error "  1) Open the official checksum directory in a browser:"
      log_error "       https://linux.oracle.com/security/gpg/"
      log_error "  2) Locate the entry for your release (e.g. 'Oracle Linux 10.1 x86_64 checksum file')."
      log_error "  3) Open the file and find the line for ${iso_filename}."
      log_error "  4) Set ISO_CHECKSUM=<sha256_hash> in your env.properties.local and re-run."
      die "Checksum auto-resolution failed."
    fi

    # Extract the SHA256 hash for our specific ISO filename.
    # The checksum file may be a plain ".sha256sum" (single line) or a
    # GPG clear-signed file with multiple hash entries; in both cases the
    # pattern "<hash>  <filename>" lets us grep+awk the right value.
    ISO_CHECKSUM=$(echo "${raw_sum}" | grep -F "${iso_filename}" | awk '{print $1}' | head -n 1)

    if [[ -z "${ISO_CHECKSUM}" ]]; then
      log_error "Checksum file was retrieved, but no entry was found for ${iso_filename}."
      log_error "Inspect the file at: ${checksum_url}"
      log_error "Then set ISO_CHECKSUM=<sha256_hash> in your env.properties.local and re-run."
      die "Could not extract a checksum entry for ${iso_filename}."
    fi

    # Sanity-check the result looks like a SHA-256 hex string (64 chars).
    if [[ ! "${ISO_CHECKSUM}" =~ ^[0-9a-fA-F]{64}$ ]]; then
      die "Extracted value does not look like a SHA-256 hash: '${ISO_CHECKSUM}'"
    fi

    log_info "ISO_CHECKSUM = ${ISO_CHECKSUM}"
    log_info "  (source: ${checksum_url})"
  fi

  # Resolve OS_VARIANT for virt-install / Oracle build-image.sh.
  # When the user did not provide it, try to find a working short-id in the
  # local osinfo-db. If nothing matches, fail with actionable guidance.
  if [[ -z "${OS_VARIANT:-}" ]]; then
    log_info "OS_VARIANT not set; auto-detecting from the local osinfo-db"
    if ! command -v osinfo-query >/dev/null 2>&1; then
      die "osinfo-query command not found. Install libosinfo / osinfo-db (Phase 1 should have done this)."
    fi

    OS_VARIANT=$(detect_os_variant) || true

    if [[ -z "${OS_VARIANT}" ]]; then
      log_error "No suitable OS_VARIANT short-id was found in the local osinfo-db."
      log_error "Workarounds:"
      log_error "  1) Update the database:"
      log_error "       sudo dnf upgrade osinfo-db libosinfo                 # RHEL/OL"
      log_error "       sudo apt-get install --only-upgrade osinfo-db        # Debian/Ubuntu"
      log_error "  2) Install the latest osinfo-db tarball from upstream:"
      log_error "       https://releases.pagure.org/libosinfo/"
      log_error "       (then 'sudo osinfo-db-import --system osinfo-db-XXXXXX.tar.xz')"
      log_error "  3) Set OS_VARIANT manually in env.properties.local, e.g."
      log_error "       OS_VARIANT=\"linux2022\""
      die "OS_VARIANT auto-detection failed."
    fi

    log_info "  -> selected: ${OS_VARIANT}"

    # Categorize the chosen variant and emit an appropriate notice.
    # OL10 is binary-compatible with RHEL 10 / CentOS Stream 10, so when one
    # of those is selected the build is effectively equivalent. Older or
    # generic fallbacks deserve a stronger warning.
    case "${OS_VARIANT}" in
      oraclelinux10*)
        log_info "  Native Oracle Linux 10 profile. Optimal."
        ;;
      rhel10*|centos-stream10*|centos-stream-10*)
        log_info "  Note: '${OS_VARIANT}' is binary-compatible with Oracle Linux 10."
        log_info "  This is an excellent stand-in and produces an equivalent build."
        log_info "  (To get a native 'oraclelinux10' entry, update osinfo-db from upstream:"
        log_info "   https://releases.pagure.org/libosinfo/)"
        ;;
      oraclelinux9*)
        log_warn "  Note: the chosen variant is from the OL9 family, not OL10."
        log_warn "  The build will still produce a working OL10 image, but virt-install"
        log_warn "  may apply OL9-era hardware defaults. Consider updating osinfo-db:"
        log_warn "    sudo dnf upgrade osinfo-db libosinfo                 # RHEL/OL"
        log_warn "    sudo apt-get install --only-upgrade osinfo-db        # Debian/Ubuntu"
        ;;
      linux*)
        log_warn "  Note: a generic Linux profile was selected."
        log_warn "  The build will work, but virt-install will use minimal defaults."
        log_warn "  For a more accurate profile, update osinfo-db (see commands above)"
        log_warn "  or install the latest tarball from https://releases.pagure.org/libosinfo/"
        ;;
      *)
        log_warn "  Selected variant '${OS_VARIANT}' is unusual. Verify the build VM behavior."
        ;;
    esac
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
OS_VARIANT=${OS_VARIANT}

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
# Phase 5: Run oracle-linux-image-tools to produce the VMDK
#------------------------------------------------------------------------------
phase5_run_build() {
  log_step "Phase 5: Running oracle-linux-image-tools to build the VMDK"

  local tool_dir="${WORK_REPO_DIR}/${OL_TOOLS_SUBDIR}"
  local tool_env="${tool_dir}/env.properties.local"

  # Force libguestfs to run qemu directly instead of via libvirt.
  #
  # Why: virt-sparsify (called by oracle-linux-image-tools at the very end
  # of the build) creates a temporary overlay subdirectory under the disk's
  # own directory using mkdtemp(3), which always sets mode 0700. That mode
  # cannot be relaxed by POSIX default ACLs (the auto-computed mask masks
  # the qemu user's permission bits to 0). The libvirt 'qemu' user (uid
  # 107) therefore fails to traverse the temp dir and the build aborts:
  #
  #   virt-sparsify: error: libguestfs error: could not create appliance
  #     through libvirt. Cannot access storage file '...tmp.XXXX/...qcow2'
  #     (as uid:107, gid:107): Permission denied
  #
  # The "direct" backend bypasses libvirt entirely and runs qemu as the
  # current user, which (when the script runs as root) can access every
  # directory regardless of mode.
  #
  # This affects ONLY libguestfs-based tools (virt-customize, virt-sysprep,
  # virt-sparsify). virt-install in this phase still goes through libvirt,
  # which is why Phase 2 grants the qemu user traverse ACLs on the parent
  # path of WORKSPACE — both fixes are needed.
  #
  # User can override by setting LIBGUESTFS_BACKEND in env.properties.local.
  export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"
  log_info "LIBGUESTFS_BACKEND = ${LIBGUESTFS_BACKEND}"

  log_info "Starting build (this typically takes 20-60 minutes)"
  ( cd "${tool_dir}" && ./bin/build-image.sh --env "${tool_env}" ) \
    || die "build-image.sh failed"

  # Locate the produced VMDK file
  # Naming convention: OL10U1_x86_64-aws-b<BUILD_NUMBER>.vmdk
  VMDK_PATH=$(find "${WORKSPACE}" -maxdepth 3 -name '*.vmdk' -newer "${tool_env}" 2>/dev/null | head -n 1)

  if [[ -z "${VMDK_PATH}" || ! -f "${VMDK_PATH}" ]]; then
    die "Built VMDK file was not found under ${WORKSPACE}"
  fi

  log_info "VMDK file: ${VMDK_PATH}"
  log_info "Size:      $(du -h "${VMDK_PATH}" | awk '{print $1}')"
}

#------------------------------------------------------------------------------
# Phase 6: Upload the VMDK to S3
#------------------------------------------------------------------------------
phase6_upload_to_s3() {
  log_step "Phase 6: Uploading VMDK to S3"

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
# Phase 7: Convert the VMDK to an EBS snapshot via import-snapshot
#------------------------------------------------------------------------------
phase7_import_snapshot() {
  log_step "Phase 7: Creating EBS snapshot via import-snapshot"

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

  # Poll loop with hard timeout (90 minutes) and graceful handling of
  # transient AWS API failures (network blips, throttling). A failed
  # describe-import-snapshot-tasks call should not abort the build —
  # we retry on the next iteration.
  local -i poll_interval=60
  local -i max_iterations=$((90 * 60 / poll_interval))   # 90 minutes
  local -i iteration=0
  local status="" progress="" query_output=""

  while :; do
    iteration=$((iteration + 1))
    if (( iteration > max_iterations )); then
      die "import-snapshot did not complete within $((max_iterations * poll_interval / 60)) minutes (task: ${import_task})"
    fi

    if ! query_output=$(aws ec2 describe-import-snapshot-tasks \
        --region "${AWS_REGION}" \
        --import-task-ids "${import_task}" \
        --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.[Status,Progress]' \
        --output text 2>/dev/null); then
      log_warn "  describe-import-snapshot-tasks API call failed (transient); retrying in ${poll_interval}s"
      sleep "${poll_interval}"
      continue
    fi

    read -r status progress <<< "${query_output}"

    # Empty status means the API returned successfully but with no data
    # for our task (extremely unlikely; treat as transient and retry).
    if [[ -z "${status}" ]]; then
      log_warn "  Empty status returned by AWS API; retrying"
      sleep "${poll_interval}"
      continue
    fi

    log_info "  Status: ${status} (${progress:-0}%)"

    case "${status}" in
      completed)
        break
        ;;
      deleted|cancelled|deleting)
        die "import-snapshot task failed: ${status}"
        ;;
      active|pending)
        # in progress — keep polling
        ;;
      *)
        # Unknown status code — log and continue (AWS may add new states)
        log_warn "  Unrecognized status '${status}'; continuing to poll"
        ;;
    esac
    sleep "${poll_interval}"
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
# Phase 8: Register the snapshot as an AMI
#------------------------------------------------------------------------------
phase8_register_ami() {
  log_step "Phase 8: Registering AMI via register-image"

  # Build the register-image argument list.
  # NitroTPM (--tpm-support) requires UEFI boot; it is incompatible with
  # legacy-bios AMIs and must be omitted in that case.
  local -a register_args=(
    --region "${AWS_REGION}"
    --name "${AMI_NAME}"
    --description "${AMI_DESCRIPTION}"
    --architecture x86_64
    --root-device-name /dev/sda1
    --virtualization-type hvm
    --ena-support
    --boot-mode "${BOOT_MODE}"
    --imds-support v2.0
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={SnapshotId=${SNAPSHOT_ID},VolumeSize=${DISK_SIZE_GB},VolumeType=gp3,DeleteOnTermination=true}"
  )

  # NitroTPM is only valid for UEFI-bootable AMIs
  if [[ "${BOOT_MODE,,}" == "uefi" || "${BOOT_MODE,,}" == "uefi-preferred" ]]; then
    register_args+=(--tpm-support v2.0)
    log_info "Boot mode supports UEFI; enabling NitroTPM (--tpm-support v2.0)"
  else
    log_info "Boot mode is legacy-bios; NitroTPM (--tpm-support) is omitted (UEFI-only feature)"
  fi

  local ami_id
  ami_id=$(aws ec2 register-image "${register_args[@]}" --query 'ImageId' --output text) \
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

  phase0_preflight_checks
  phase1_install_prerequisites
  phase2_grant_qemu_access
  phase3_clone_repository
  phase4_prepare_env_properties
  phase5_run_build

  if [[ ${BUILD_ONLY} -eq 1 || ${SKIP_AWS_IMPORT} -eq 1 ]]; then
    log_info "Build-only mode. Skipping AWS import phases."
    log_info "VMDK file: ${VMDK_PATH}"
    exit 0
  fi

  phase6_upload_to_s3
  phase7_import_snapshot
  phase8_register_ami
}

main "$@"
