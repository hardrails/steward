locals {
  source_lock = jsondecode(file("${path.module}/source-lock.json"))

  steward_version = coalesce(var.steward_release_version, local.source_lock.steward.version)
  installer_sha   = coalesce(var.steward_installer_sha256, local.source_lock.steward.installer_sha256)
  installer_url   = "${trimsuffix(var.steward_release_origin, "/")}/download/${local.steward_version}/install-steward.sh"

  gvisor_lock    = local.source_lock.gvisor.archives[var.architecture]
  gvisor_version = local.source_lock.gvisor.version
  gvisor_url     = "https://storage.googleapis.com/gvisor/releases/release/${local.gvisor_version}/${local.gvisor_lock.upstream_arch}/gvisor.tar.bz2"

  ami_architecture = var.architecture == "amd64" ? "x86_64" : "arm64"
  instance_type    = coalesce(var.instance_type, var.architecture == "amd64" ? "m7i.large" : "m7g.large")

  kms_arn_parts        = split(":", var.kms_key_arn)
  aws_partition        = local.kms_arn_parts[1]
  aws_region           = local.kms_arn_parts[3]
  aws_account_id       = local.kms_arn_parts[4]
  token_parameter_name = "/steward/${var.name}/bootstrap/rke2-server-token"
  token_parameter_arn  = "arn:${local.aws_partition}:ssm:${local.aws_region}:${local.aws_account_id}:parameter/${trimprefix(local.token_parameter_name, "/")}"

  common_tags = merge(var.tags, {
    "steward.io/cluster" = var.name
    "steward.io/release" = local.steward_version
    "steward.io/role"    = "management-cluster"
  })

  bootstrap_script = templatefile("${path.module}/bootstrap.sh.tftpl", {
    operation_b64            = base64encode("init")
    cluster_name_b64         = base64encode(var.name)
    node_name_b64            = base64encode("${var.name}-server-1")
    server_url_b64           = ""
    aws_region_b64           = base64encode(local.aws_region)
    token_parameter_name_b64 = base64encode(local.token_parameter_name)
    kms_key_arn_b64          = base64encode(var.kms_key_arn)
    installer_url_b64        = base64encode(local.installer_url)
    installer_sha256         = local.installer_sha
    steward_version          = local.steward_version
    gvisor_url_b64           = base64encode(local.gvisor_url)
    gvisor_sha512            = local.gvisor_lock.sha512
    gvisor_size              = local.gvisor_lock.size
    gvisor_version           = local.gvisor_version
    timeout_seconds          = var.bootstrap_timeout_minutes * 60
    rendezvous_ttl_hours     = var.rendezvous_ttl_hours
    expected_server_count    = var.server_count
    publish_token            = "true"
  })

  bootstrap_cloud_init = <<-CLOUD
    #cloud-config
    package_update: false
    write_files:
      - path: /usr/local/sbin/steward-cluster-bootstrap
        owner: root:root
        permissions: '0700'
        encoding: b64
        content: ${base64encode(local.bootstrap_script)}
    runcmd:
      - [ /usr/local/sbin/steward-cluster-bootstrap ]
  CLOUD
}

data "aws_ami" "amazon_linux_2023" {
  count       = var.ami_id == null ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-${local.ami_architecture}"]
  }

  filter {
    name   = "architecture"
    values = [local.ami_architecture]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  ami_id = coalesce(var.ami_id, try(data.aws_ami.amazon_linux_2023[0].id, null))
}

resource "aws_security_group" "cluster" {
  name_prefix = "${var.name}-cluster-"
  description = "Private RKE2 traffic for the Steward management cluster"
  vpc_id      = var.vpc_id

  tags = merge(local.common_tags, {
    Name = "${var.name}-cluster"
  })

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  cluster_tcp_ports = {
    supervisor = [9345, 9345]
    api        = [6443, 6443]
    kubelet    = [10250, 10250]
    etcd       = [2379, 2381]
    canal      = [9099, 9099]
    nodeport   = [30000, 32767]
  }
}

resource "aws_vpc_security_group_ingress_rule" "cluster_tcp" {
  for_each = local.cluster_tcp_ports

  security_group_id            = aws_security_group.cluster.id
  referenced_security_group_id = aws_security_group.cluster.id
  description                  = "RKE2 ${each.key} traffic inside the cluster"
  ip_protocol                  = "tcp"
  from_port                    = each.value[0]
  to_port                      = each.value[1]
}

resource "aws_vpc_security_group_ingress_rule" "canal_vxlan" {
  security_group_id            = aws_security_group.cluster.id
  referenced_security_group_id = aws_security_group.cluster.id
  description                  = "Canal VXLAN inside the cluster"
  ip_protocol                  = "udp"
  from_port                    = 8472
  to_port                      = 8472
}

resource "aws_vpc_security_group_egress_rule" "connected_bootstrap" {
  for_each = var.egress_ipv4_cidrs

  security_group_id = aws_security_group.cluster.id
  description       = "Reviewed connected-bootstrap egress"
  ip_protocol       = "-1"
  cidr_ipv4         = each.value
}

resource "aws_iam_role" "bootstrap" {
  name_prefix          = "${var.name}-cluster-bootstrap-"
  permissions_boundary = var.permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role" "join" {
  name_prefix          = "${var.name}-cluster-join-"
  permissions_boundary = var.permissions_boundary_arn
  assume_role_policy   = aws_iam_role.bootstrap.assume_role_policy
  tags                 = local.common_tags
}

resource "aws_iam_role_policy" "bootstrap_rendezvous" {
  name = "publish-expiring-rke2-token"
  role = aws_iam_role.bootstrap.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishExactParameter"
        Effect   = "Allow"
        Action   = ["ssm:PutParameter"]
        Resource = local.token_parameter_arn
      },
      {
        Sid      = "EncryptRendezvous"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource = var.kms_key_arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "join_rendezvous" {
  name = "read-expiring-rke2-token"
  role = aws_iam_role.join.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadExactParameter"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = local.token_parameter_arn
      },
      {
        Sid      = "DecryptRendezvous"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bootstrap_session_manager" {
  count      = var.enable_session_manager ? 1 : 0
  role       = aws_iam_role.bootstrap.name
  policy_arn = "arn:${local.aws_partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "join_session_manager" {
  count      = var.enable_session_manager ? 1 : 0
  role       = aws_iam_role.join.name
  policy_arn = "arn:${local.aws_partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "bootstrap" {
  name_prefix = "${var.name}-cluster-bootstrap-"
  role        = aws_iam_role.bootstrap.name
  tags        = local.common_tags
}

resource "aws_iam_instance_profile" "join" {
  name_prefix = "${var.name}-cluster-join-"
  role        = aws_iam_role.join.name
  tags        = local.common_tags
}

resource "aws_instance" "bootstrap" {
  ami                         = local.ami_id
  instance_type               = local.instance_type
  subnet_id                   = var.subnet_ids[0]
  associate_public_ip_address = var.associate_public_ip_address
  vpc_security_group_ids      = concat([aws_security_group.cluster.id], sort(tolist(var.additional_security_group_ids)))
  iam_instance_profile        = aws_iam_instance_profile.bootstrap.name
  user_data                   = local.bootstrap_cloud_init
  user_data_replace_on_change = false
  monitoring                  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    volume_size           = var.root_volume_gib
    volume_type           = "gp3"
  }

  tags = merge(local.common_tags, {
    Name                  = "${var.name}-server-1"
    "steward.io/node"     = "${var.name}-server-1"
    "steward.io/sequence" = "1"
  })

  lifecycle {
    ignore_changes = [user_data]

    precondition {
      condition     = length(var.subnet_ids) >= var.server_count
      error_message = "server_count requires at least that many subnet_ids."
    }

    precondition {
      condition     = (var.steward_release_version == null) == (var.steward_installer_sha256 == null)
      error_message = "override steward_release_version and steward_installer_sha256 together."
    }

    precondition {
      condition     = length(local.bootstrap_cloud_init) <= 16384
      error_message = "rendered bootstrap user data exceeds EC2's 16 KiB limit."
    }
  }
}

locals {
  joining_cloud_init = [
    for index in range(var.server_count - 1) : <<-CLOUD
      #cloud-config
      package_update: false
      write_files:
        - path: /usr/local/sbin/steward-cluster-bootstrap
          owner: root:root
          permissions: '0700'
          encoding: b64
          content: ${base64encode(templatefile("${path.module}/bootstrap.sh.tftpl", {
    operation_b64            = base64encode("join-server")
    cluster_name_b64         = base64encode(var.name)
    node_name_b64            = base64encode("${var.name}-server-${index + 2}")
    server_url_b64           = base64encode("https://${aws_instance.bootstrap.private_ip}:9345")
    aws_region_b64           = base64encode(local.aws_region)
    token_parameter_name_b64 = base64encode(local.token_parameter_name)
    kms_key_arn_b64          = base64encode(var.kms_key_arn)
    installer_url_b64        = base64encode(local.installer_url)
    installer_sha256         = local.installer_sha
    steward_version          = local.steward_version
    gvisor_url_b64           = base64encode(local.gvisor_url)
    gvisor_sha512            = local.gvisor_lock.sha512
    gvisor_size              = local.gvisor_lock.size
    gvisor_version           = local.gvisor_version
    timeout_seconds          = var.bootstrap_timeout_minutes * 60
    rendezvous_ttl_hours     = var.rendezvous_ttl_hours
    expected_server_count    = var.server_count
    publish_token            = "false"
}))}
      runcmd:
        - [ /usr/local/sbin/steward-cluster-bootstrap ]
    CLOUD
]
}

resource "aws_instance" "joining" {
  count = var.server_count - 1

  ami                         = local.ami_id
  instance_type               = local.instance_type
  subnet_id                   = var.subnet_ids[count.index + 1]
  associate_public_ip_address = var.associate_public_ip_address
  vpc_security_group_ids      = concat([aws_security_group.cluster.id], sort(tolist(var.additional_security_group_ids)))
  iam_instance_profile        = aws_iam_instance_profile.join.name
  user_data_replace_on_change = false
  monitoring                  = true
  user_data                   = local.joining_cloud_init[count.index]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    volume_size           = var.root_volume_gib
    volume_type           = "gp3"
  }

  tags = merge(local.common_tags, {
    Name                  = "${var.name}-server-${count.index + 2}"
    "steward.io/node"     = "${var.name}-server-${count.index + 2}"
    "steward.io/sequence" = tostring(count.index + 2)
  })

  depends_on = [
    aws_iam_role_policy.bootstrap_rendezvous,
    aws_iam_role_policy.join_rendezvous,
  ]

  lifecycle {
    ignore_changes = [user_data]

    precondition {
      condition     = length(local.joining_cloud_init[count.index]) <= 16384
      error_message = "rendered joining-server user data exceeds EC2's 16 KiB limit."
    }
  }
}
