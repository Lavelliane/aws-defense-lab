resource "aws_vpc" "lab" {
  cidr_block           = "10.77.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = var.lab_name
  }
}
resource "aws_subnet" "lab" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.77.1.0/24"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.lab_name}-public"
  }
}
resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
}
resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
}
resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab.id
}
resource "aws_security_group" "app" {
  name_prefix = "${var.lab_name}-app-"
  description = "Lab app; no SSH"
  vpc_id      = aws_vpc.lab.id
}
resource "aws_security_group" "manager" {
  name_prefix = "${var.lab_name}-manager-"
  description = "Wazuh dashboard and private agents; no public API or indexer"
  vpc_id      = aws_vpc.lab.id
}
resource "aws_vpc_security_group_ingress_rule" "app_operator" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = var.allowed_cidr
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
}
resource "aws_vpc_security_group_ingress_rule" "app_scenario" {
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.manager.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}
resource "aws_vpc_security_group_ingress_rule" "dashboard" {
  security_group_id = aws_security_group.manager.id
  cidr_ipv4         = var.allowed_cidr
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}
resource "aws_vpc_security_group_ingress_rule" "agent" {
  for_each                     = toset(["1514", "1515"])
  security_group_id            = aws_security_group.manager.id
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = tonumber(each.key)
  to_port                      = tonumber(each.key)
}
resource "aws_vpc_security_group_egress_rule" "outbound" {
  for_each = {
    app = aws_security_group.app.id, manager = aws_security_group.manager.id
  }
  security_group_id = each.value
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Lab package installation, AWS APIs, agent and scenario traffic"
}
