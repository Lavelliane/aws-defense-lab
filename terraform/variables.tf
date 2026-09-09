variable "aws_region" {
  type    = string
  default = "ap-southeast-1"
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "Use an AWS commercial region, e.g. ap-southeast-1."
  }
}
variable "lab_name" {
  type    = string
  default = "defense-lab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,19}$", var.lab_name))
    error_message = "Lab name must be 3-20 lowercase letters, numbers or hyphens, starting with a letter."
  }
}
variable "allowed_cidr" {
  type        = string
  description = "Operator public IPv4 /32. No shared networks or world-open access."
  validation {
    condition     = can(cidrnetmask(var.allowed_cidr)) && can(regex("/32$", var.allowed_cidr))
    error_message = "Supply your public IPv4 address as a /32."
  }
}
variable "app_mode" {
  type    = string
  default = "vulnerable"
  validation {
    condition     = contains(["vulnerable", "hardened"], var.app_mode)
    error_message = "Mode must be vulnerable or hardened."
  }
}
variable "permissions_boundary_arn" {
  type        = string
  description = "Boundary ARN emitted by bootstrap. Required on every lab role."
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:policy/aws-defense-lab/[a-z0-9-]+-boundary$", var.permissions_boundary_arn))
    error_message = "Use the lab boundary ARN from bootstrap."
  }
}
variable "purge_on_destroy" {
  type        = bool
  default     = false
  description = "Explicit opt-in to purge lab data, logs and artifact versions on destroy. Bootstrap state remains."
}
