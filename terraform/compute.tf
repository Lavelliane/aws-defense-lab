resource "aws_instance" "manager" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.xlarge"
  subnet_id                   = aws_subnet.lab.id
  vpc_security_group_ids      = [aws_security_group.manager.id]
  iam_instance_profile        = aws_iam_instance_profile.manager.name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/cloud-init.sh.tftpl", {
    component    = "manager", region = var.aws_region, artifact_bucket = aws_s3_bucket.lab["assets"].id,
    artifact_key = aws_s3_object.bundle.key, artifact_sha = local.bundle_sha,
    settings     = "AWS_REGION=${var.aws_region}\nLOG_BUCKET=${aws_s3_bucket.lab["audit"].id}\nDATA_BUCKET=${aws_s3_bucket.lab["data"].id}\nAWS_ACCOUNT_ID=${data.aws_caller_identity.current.account_id}\nLAB_NAME=${var.lab_name}\n"
    }
  )
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 50
    tags        = { Project = "aws-defense-lab", Lab = var.lab_name }
  }
  tags = {
    Name = "${var.lab_name}-manager", Component = "manager"
  }
  depends_on = [aws_route_table_association.lab, aws_vpc_security_group_egress_rule.outbound, aws_iam_role_policy.manager, aws_iam_role_policy_attachment.ssm, aws_cloudtrail.lab]
}
resource "aws_instance" "app" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.lab.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  iam_instance_profile        = aws_iam_instance_profile.app.name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/cloud-init.sh.tftpl", {
    component    = "app", region = var.aws_region, artifact_bucket = aws_s3_bucket.lab["assets"].id,
    artifact_key = aws_s3_object.bundle.key, artifact_sha = local.bundle_sha,
    settings     = "AWS_REGION=${var.aws_region}\nDATA_BUCKET=${aws_s3_bucket.lab["data"].id}\nAPP_MODE=${var.app_mode}\nMANAGER_IP=${aws_instance.manager.private_ip}\nLAB_NAME=${var.lab_name}\n"
    }
  )
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 12
    tags        = { Project = "aws-defense-lab", Lab = var.lab_name }
  }
  tags = {
    Name = "${var.lab_name}-app", Component = "app"
  }
  depends_on = [aws_route_table_association.lab, aws_vpc_security_group_egress_rule.outbound, aws_iam_role_policy.app, aws_iam_role_policy_attachment.ssm, aws_s3_object.dummy]
}
