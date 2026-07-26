data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}

locals {
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 3)
  common_tags = merge(var.tags, {
    "steward.io/cluster" = var.name
  })
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${var.name}-quickstart"
  })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${var.name}-quickstart"
  })
}

resource "aws_subnet" "cluster" {
  count = 3

  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.availability_zones[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 1)
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${var.name}-cluster-${count.index + 1}"
  })
}

resource "aws_route_table" "egress" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = merge(local.common_tags, {
    Name = "${var.name}-connected-bootstrap"
  })
}

resource "aws_route_table_association" "cluster" {
  count = 3

  subnet_id      = aws_subnet.cluster[count.index].id
  route_table_id = aws_route_table.egress.id
}

resource "aws_kms_key" "cluster" {
  description             = "Steward ${var.name} cluster bootstrap and root-volume key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = local.common_tags
}

resource "aws_kms_alias" "cluster" {
  name          = "alias/${var.name}-steward-cluster"
  target_key_id = aws_kms_key.cluster.key_id
}

module "steward_cluster" {
  source = "../../modules/aws-steward-cluster"

  name                        = var.name
  vpc_id                      = aws_vpc.this.id
  subnet_ids                  = aws_subnet.cluster[*].id
  server_count                = var.server_count
  architecture                = var.architecture
  instance_type               = var.instance_type
  kms_key_arn                 = aws_kms_key.cluster.arn
  associate_public_ip_address = true
  steward_release_version     = var.steward_release_version
  steward_installer_sha256    = var.steward_installer_sha256
  tags                        = local.common_tags
}
