# Oracle Linux 10 AWS AMI Builder

English | [日本語](./README.ja.md)

A set of wrapper scripts that build an AWS AMI for Oracle Linux 10 Update 1 (x86_64) using the official Oracle [`oracle-linux-image-tools`](https://github.com/oracle/oracle-linux/tree/main/oracle-linux-image-tools) project.

Created in response to the discontinuation of Oracle's official AMI offerings (owner ID `131827586825`) on the AWS Marketplace, with the goal of establishing an independent build and operations workflow for Oracle Linux AMIs.

> **Aligned with the AWS feature released in February 2026**
> Now that AWS supports nested virtualization on C8i / M8i / R8i instances, this guide **recommends building on M8i-class instances as the primary path**. This removes the need for bare-metal instances (`.metal`) and brings the cost down to **approximately 1/15 of the previous approach**.

---

## 1. Repository Layout

| File | Purpose |
|------|---------|
| `build-ol10-aws-ami.sh` | Main build orchestrator. Runs the entire pipeline (prep through AMI registration) in seven phases. |
| `env.properties.aws-ol10` | Parameter file for the build (ISO URL, S3 bucket, region, etc.). |
| `setup-vmimport-role.sh` | One-time setup script that creates the `vmimport` IAM service role for AWS VM Import/Export. |
| `README.md` | This document (English). |
| `README.ja.md` | Japanese version of this document. |

---

## 2. End-to-End Flow

```
[Builder EC2 (M8i family, nested-virt enabled)]    [AWS]
      │                                              │
      │ (1) Download ISO                             │
      │ (2) Install OS via virt-install              │
      │     (run OL10 as L2 inside KVM L1)           │
      │ (3) Provision via virt-customize             │
      │ (4) Produce VMDK                             │
      │                                              │
      ├─── (5) aws s3 cp ─────────────────────►   S3 Bucket
      │                                              │
      ├─── (6) import-snapshot ───────────────►   EBS Snapshot
      │                                              │
      └─── (7) register-image ────────────────►   AMI ready
```

---

## 3. Choosing a Builder Environment

`oracle-linux-image-tools` relies on KVM/libvirt, so the build host must expose CPU virtualization extensions (Intel VT-x / AMD-V). You have **three options**.

### 3.1 Recommended: AWS EC2 M8i / C8i / R8i family (nested virtualization enabled)

Since February 2026, AWS supports **nested virtualization** on regular (non-bare-metal) EC2 instances. This lets you run the builder on inexpensive instances like `m8i.xlarge`.

| Item | Detail |
|------|--------|
| Supported instances | C8i, C8i-flex, C8id / M8i, M8i-flex, M8id / R8i, R8i-flex, R8id |
| Sizes | `.large` through `.96xlarge` (all sizes supported) |
| Architecture | x86_64 (Intel Xeon 6, Sapphire Rapids generation) |
| Regions | All commercial regions (including Tokyo `ap-northeast-1`) |
| Extra cost | **None** — same price as the regular instance |
| Recommended size | `m8i.xlarge` (4 vCPU / 16 GB) — meets `oracle-linux-image-tools` defaults |

**Launch example:**
```bash
aws ec2 run-instances \
  --image-id <Oracle Linux 9-based AMI ID> \
  --instance-type m8i.xlarge \
  --cpu-options "NestedVirtualization=enabled" \
  --key-name your-keypair \
  --security-group-ids sg-xxxxx \
  --subnet-id subnet-xxxxx \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":60,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ol10-builder}]' \
  --region ap-northeast-1
```

> Important: You must specify `--cpu-options "NestedVirtualization=enabled"` **at launch time**, or stop the instance later and enable it via `modify-instance-cpu-options`.

### 3.2 Alternative 1: AWS EC2 `.metal` instances

The legacy approach without using nested virtualization. More expensive than M8i but a reliable fallback.

| Item | Detail |
|------|--------|
| Supported instances | `c5n.metal`, `m5.metal`, `c6i.metal`, `m6i.metal`, `i3.metal`, etc. |
| Price | Roughly $4–$5 / hour (Tokyo region, on-demand) |
| Pros | KVM works out of the box, no configuration needed |
| Cons | Expensive, unsuitable for frequent builds |

### 3.3 Alternative 2: On-premises KVM host

If you already have a KVM-capable Linux host on premises, the build runs there with no AWS compute cost. Be mindful of bandwidth when uploading the resulting VMDK to AWS.

### 3.4 Common Requirements

| Item | Requirement |
|------|-------------|
| OS | **Oracle Linux 9 / RHEL 9 / Ubuntu 22.04 or newer** recommended |
| Architecture | **x86_64** (must match the target AMI architecture) |
| Memory | 8 GB or more (allocated to the build VM) |
| Disk | At least **30 GB free** in the workspace |
| Network | HTTPS reachability to `yum.oracle.com` and `github.com` |
| Privileges | A regular user with sudo. Direct execution as `root` is not allowed. |

---

## 4. Enabling Nested Virtualization (M8i family only)

### 4.1 Enable at launch

```bash
aws ec2 run-instances \
  --instance-type m8i.xlarge \
  --cpu-options "NestedVirtualization=enabled" \
  ...(other options)
```

### 4.2 Enable on an existing (stopped) instance

```bash
INSTANCE_ID=i-xxxxxxxxxxxxx
REGION=ap-northeast-1

# Stop the instance
aws ec2 stop-instances --instance-ids ${INSTANCE_ID} --region ${REGION}
aws ec2 wait instance-stopped --instance-ids ${INSTANCE_ID} --region ${REGION}

# Enable nested virtualization
aws ec2 modify-instance-cpu-options \
  --instance-id ${INSTANCE_ID} \
  --region ${REGION} \
  --nested-virtualization enabled

# Start the instance
aws ec2 start-instances --instance-ids ${INSTANCE_ID} --region ${REGION}
```

### 4.3 Verify nested virtualization

After SSH'ing into the builder EC2 instance:

```bash
# Check CPU virtualization flags (should include "vmx")
grep -E '(vmx|svm)' /proc/cpuinfo | head -n 1

# Confirm /dev/kvm exists
ls -l /dev/kvm

# Verify from the AWS side (requires ec2:DescribeInstances)
aws ec2 describe-instances --instance-ids ${INSTANCE_ID} --region ${REGION} \
  --query 'Reservations[0].Instances[0].CpuOptions.NestedVirtualization'
# -> Returns "enabled" if successfully configured
```

### 4.4 List supported instance types in your region

```bash
aws ec2 describe-instance-types \
  --filters "Name=processor-info.supported-features,Values=nested-virtualization" \
  --query "sort(InstanceTypes[].InstanceType)" \
  --region ap-northeast-1
```

---

## 5. Initial Setup

### 5.1 Obtain the repository

```bash
git clone <your repository hosting these scripts> ol10-aws-ami-builder
cd ol10-aws-ami-builder
chmod +x build-ol10-aws-ami.sh setup-vmimport-role.sh
```

### 5.2 Configure the AWS CLI

```bash
aws configure
aws sts get-caller-identity
```

Minimum IAM permissions required:
- `s3:CreateBucket`, `s3:PutObject`, `s3:GetObject`, `s3:HeadBucket`
- `iam:CreateRole`, `iam:PutRolePolicy`, `iam:GetRole`
- `ec2:ImportSnapshot`, `ec2:DescribeImportSnapshotTasks`, `ec2:RegisterImage`
- `ec2:CreateTags`, `ec2:DescribeImages`, `ec2:DescribeSnapshots`

### 5.3 Create the vmimport IAM role (one-time)

```bash
./setup-vmimport-role.sh my-ol10-ami-import-bucket
```

This role is required by AWS VM Import/Export to read the staged VMDK from S3. Run this **only once per AWS account**.

### 5.4 Edit the environment file

```bash
cp env.properties.aws-ol10 env.properties.local
vi env.properties.local
```

**Minimum settings to update:**

| Parameter | Example |
|-----------|---------|
| `WORKSPACE` | `/tmp/ol10-build-ws` (default — universally accessible by the qemu user; switch to `/var/tmp/ol10-build-ws` if `/tmp` is tmpfs and too small) |
| `S3_BUCKET` | `my-ol10-ami-import-bucket` (must match `setup-vmimport-role.sh`) |
| `AWS_REGION` | `ap-northeast-1` |
| `AMI_NAME` | Optional; auto-generates with timestamp if unset |

---

## 6. Running a Build

### 6.1 Standard run (full pipeline)

```bash
./build-ol10-aws-ami.sh --env env.properties.local
```

Expected total time: **40–90 minutes** (depends on bandwidth and instance performance).

| Phase | Description | Approximate time |
|-------|-------------|------------------|
| 0 | Preflight checks | A few seconds |
| 1 | Install KVM and other prerequisites | 2–5 min (first run only) |
| 2 | Grant qemu user traverse ACL on the workspace path | A few seconds |
| 3 | Clone the repository | A few seconds |
| 4 | Resolve ISO checksum / generate env file | A few seconds |
| 5 | Build the VMDK (`virt-install` runs the OS installer) | **20–40 min** |
| 6 | Upload to S3 | 2–10 min |
| 7 | `import-snapshot` (creates EBS snapshot) | **10–30 min** |
| 8 | `register-image` (registers the AMI) | Less than 1 min |

### 6.2 Execution modes

| Option | Use case |
|--------|----------|
| `--skip-prereq` | Skip KVM package installation (Phase 1). Useful for re-runs. |
| `--build-only` | Stop after VMDK is built (Phase 5). Run the AWS import separately. |
| `--skip-aws-import` | Skip Phases 6–8 (equivalent to `--build-only`). |

### 6.3 Phase 0 self-diagnosis

Phase 0 inspects the runtime environment and emits targeted guidance when something is wrong.

**Case A: An M8i-family instance with nested virtualization currently disabled**
```
[ERROR] CPU virtualization extensions are NOT exposed on this EC2 host
[INFO]  Detected instance type: m8i.xlarge
[WARN]  [Case A] m8i supports nested virtualization, but the feature is currently disabled.
[INFO]  Action: enable nested virtualization on this instance.
[INFO]    aws ec2 stop-instances --instance-ids i-xxxxx --region ap-northeast-1
[INFO]    aws ec2 modify-instance-cpu-options ...
```

**Case B: Running on an instance family that does not support nested virtualization**
```
[WARN]  [Case B] m5 does NOT support nested virtualization.
[INFO]  Option 1 (recommended): Use a nested-virtualization-capable C8i / M8i / R8i instance
[INFO]  Option 2: Switch to a bare-metal instance
```

**Case C: A bare-metal instance that has /dev/kvm missing**
```
[WARN]  [Case C] m5.metal is bare metal but /dev/kvm is unavailable.
[INFO]  Action:
[INFO]    1) Check whether the kvm module is loaded: lsmod | grep kvm
[INFO]    2) If not loaded, load it manually: sudo modprobe kvm-intel
```

This automation **minimizes the trial-and-error of first-time setup**.

---

## 7. Cost Comparison

Tokyo region pricing, assuming roughly one hour per build.

| Approach | Builder | Hourly | Per build | 4 builds/mo | 30 builds/mo |
|----------|---------|--------|-----------|-------------|--------------|
| **Recommended: M8i + nested virt** | `m8i.xlarge` | $0.30/h | **$0.30** | $1.20 | **$9.00** |
| Recommended: C8i (compute-heavy) | `c8i.2xlarge` | $0.50/h | $0.50 | $2.00 | $15.00 |
| Legacy: bare metal | `c5n.metal` | $4.50/h | $4.50 | $18.00 | $135.00 |
| Legacy: bare metal | `m5.metal` | $5.50/h | $5.50 | $22.00 | $165.00 |

**At 30 builds per month, you save approximately $126/month** compared to the bare-metal approach. The pricing easily supports CI/CD pipeline integration.

---

## 8. Verifying the AMI

### 8.1 List your AMIs

```bash
aws ec2 describe-images \
  --owners self \
  --filters "Name=tag:OS,Values=OracleLinux10U1" \
  --query 'Images[*].[ImageId,Name,CreationDate,BootMode]' \
  --output table
```

### 8.2 Smoke test by launching an instance

```bash
AMI_ID=ami-xxxxxxxxxxxxx
KEY_PAIR=your-keypair
SG_ID=sg-xxxxxxxx
SUBNET_ID=subnet-xxxxxxxx

aws ec2 run-instances \
  --image-id "${AMI_ID}" \
  --instance-type t3.small \
  --key-name "${KEY_PAIR}" \
  --security-group-ids "${SG_ID}" \
  --subnet-id "${SUBNET_ID}" \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ol10-test}]'
```

SSH login:
```bash
ssh -i your-keypair.pem ec2-user@<public-ip>
```

cloud-init deploys your public key under the `ec2-user` account on first boot.

---

## 9. Key Design Decisions

### 9.1 Using `import-snapshot` + `register-image` instead of `import-image`

AWS VM Import/Export offers two import flows:

| Approach | Characteristics |
|----------|-----------------|
| `import-image` | AWS auto-detects the OS and registers the AMI directly. Convenient, but OL10 is likely missing from the supported-OS list. |
| `import-snapshot` + `register-image` | Creates only the snapshot, then **explicitly controls AMI attributes** (BootMode / ENA / TPM / IMDS) on our side. |

For newer distributions like OL10, the second approach is safer and more reliable, so this script uses it. It allows us to set:

- `--ena-support`: enable ENA (Elastic Network Adapter)
- `--boot-mode uefi-preferred`: boot via UEFI on UEFI-capable instances, fall back to BIOS otherwise
- `--tpm-support v2.0`: enable NitroTPM
- `--imds-support v2.0`: enforce IMDSv2

### 9.2 ENA / NVMe drivers

The `cloud=aws` target of `oracle-linux-image-tools` packages the Amazon ENA driver and cloud-init in (as the upstream README notes). The OL10 kernel (UEK 7-series or RHCK 6.x) ships with the `ena` and `nvme` modules natively, so no extra driver injection is required.

### 9.3 `BOOT_MODE_BUILD = "hybrid"`

Building with hybrid creates an image with **GPT + ESP (EFI System Partition) + BIOS Boot Partition**, which can boot in both modes. Combined with the AMI-side `--boot-mode uefi-preferred`, this lets the AMI run on both UEFI-capable and legacy-BIOS-only instance types.

### 9.4 cloud-init / ec2-user

Setting `CLOUD_INIT="Yes"` and `CLOUD_USER="ec2-user"` aligns with the AWS convention of logging in as `ec2-user` with key-pair authentication.

### 9.5 Why nested virtualization is the primary recommendation

Now that AWS officially supports nested virtualization on C8i/M8i/R8i (since February 2026), this approach delivers:

1. **Compatibility with the official Oracle tooling** at a **dramatically lower cost**
2. **Realistic CI/CD integration** thanks to the pricing
3. Faster end-to-end time, since you avoid the multi-minute startup latency typical of bare-metal instances
4. Compatibility with Spot Instances and Auto Scaling for further cost optimization

---

## 10. Known Limitations and Caveats

1. **aarch64 (Graviton) AMIs are not supported.**
   `oracle-linux-image-tools` only targets x86_64 for AWS, and AWS nested virtualization is not available on Graviton. Building aarch64 AMIs requires a separate path.

2. **Build host architecture must match the target.**
   You need an x86_64 host to build x86_64 AMIs. Cross-architecture builds via libguestfs/virt-install are impractical.

3. **AWS service quotas.**
   `import-snapshot` is rate-limited per AWS account (default: 5 concurrent tasks). If you build at high volume, check AWS Service Quotas.

4. **Official VM Import support for OL10.**
   As of May 2026, OL10 may not appear in the AWS VM Import/Export supported-OS matrix. Using `import-snapshot` + `register-image` (as this script does) sidesteps that limitation.

5. **License and support.**
   If you need an Oracle Linux support contract, purchase Oracle Linux Premier Support separately.

6. **Performance of nested virtualization.**
   AWS still recommends bare-metal for workloads with strict performance/latency requirements. The build process here is I/O bound, so the overhead of nested virtualization is not a practical concern.

---

## 11. Troubleshooting

### Phase 0 reports "CPU virtualization extensions are NOT exposed"

→ Follow the targeted guidance from the Phase 0 self-diagnosis. In most cases, nested virtualization simply has not been enabled. See section 4.2 to apply `modify-instance-cpu-options`.

### Phase 1: `qemu-kvm` install fails

→ EPEL or CodeReady Builder repositories may need to be enabled.
```bash
sudo dnf config-manager --set-enabled crb  # Oracle Linux 9 / RHEL 9
sudo dnf install -y epel-release
```

### Phase 5: `KVM acceleration not available, using 'qemu'` warning

→ Either nested virtualization is off, or `/dev/kvm` permissions are wrong.
```bash
ls -l /dev/kvm
sudo modprobe kvm-intel
sudo usermod -aG kvm,libvirt $USER
# Log out and back in for the new groups to take effect
```

### Phase 7: `ClientError: Unsupported kernel version`

→ AWS VM Import does not recognize the OL10 kernel. This is the typical failure with `import-image`, but **should not occur** with this script since it uses `import-snapshot`. If it does occur, file a support request asking AWS to extend OL10 support.

### cloud-init hangs on first boot of the new AMI

→ Confirm `SERIAL_CONSOLE_RUNTIME="Yes"` is set. You can inspect the boot log via the EC2 Serial Console:
```bash
aws ec2 get-console-output --instance-id i-xxxxx --region <region>
```

---

## 12. References

- [oracle/oracle-linux/oracle-linux-image-tools](https://github.com/oracle/oracle-linux/tree/main/oracle-linux-image-tools) — The Oracle official tool used internally
- [Use nested virtualization to run hypervisors in Amazon EC2 instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html) — AWS nested virtualization documentation
- [Amazon EC2 supports nested virtualization on virtual Amazon EC2 instances (What's New)](https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-ec2-nested-virtualization-on-virtual/) — February 2026 release announcement
- [Oracle Linux ISOs](https://yum.oracle.com/oracle-linux-isos.html) — ISO downloads and checksums
- [AWS VM Import/Export User Guide](https://docs.aws.amazon.com/vm-import/latest/userguide/) — Detailed documentation for `import-snapshot` / `register-image`
- [Boot modes in EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-boot.html) — Behavior of `uefi-preferred` and friends
