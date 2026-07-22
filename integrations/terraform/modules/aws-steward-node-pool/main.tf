module "bootstrap" {
  source = "../steward-node"

  release_version  = var.release_version
  installer_url    = var.installer_url
  installer_sha256 = var.installer_sha256
  release_mirror   = var.release_mirror
  bootstrap_mode   = "stage"
}

locals {
  tags = merge(var.tags, {
    Name                 = var.name
    "steward.io/role"    = "node"
    "steward.io/release" = var.release_version
  })
}

resource "aws_launch_template" "this" {
  name_prefix   = "${var.name}-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  user_data     = base64encode(module.bootstrap.cloud_init)

  vpc_security_group_ids = sort(tolist(var.security_group_ids))

  dynamic "iam_instance_profile" {
    for_each = var.instance_profile_name == null ? [] : [var.instance_profile_name]
    content {
      name = iam_instance_profile.value
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = var.kms_key_arn
      volume_size           = var.root_volume_gib
      volume_type           = "gp3"
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = local.tags
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.tags
  }

  update_default_version = true

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "this" {
  name                      = var.name
  min_size                  = var.capacity.min
  desired_capacity          = var.capacity.desired
  max_size                  = var.capacity.max
  vpc_zone_identifier       = sort(tolist(var.subnet_ids))
  health_check_type         = "EC2"
  health_check_grace_period = var.instance_warmup_seconds
  capacity_rebalance        = true
  termination_policies      = ["OldestLaunchTemplate"]
  wait_for_capacity_timeout = "30m"

  launch_template {
    id      = aws_launch_template.this.id
    version = aws_launch_template.this.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      auto_rollback          = true
      instance_warmup        = var.instance_warmup_seconds
      min_healthy_percentage = var.min_healthy_percentage
      skip_matching          = true
    }
  }

  dynamic "tag" {
    for_each = local.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    precondition {
      condition     = var.capacity.min > 0
      error_message = "the hardened pool requires at least one retained node; use an explicit break-glass change to remove the pool instead of scaling it to zero."
    }
  }
}
