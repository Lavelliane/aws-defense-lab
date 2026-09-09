variable "aws_region" {
  type    = string
  default = "ap-southeast-1"
}
variable "lab_name" {
  type    = string
  default = "defense-lab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,19}$", var.lab_name))
    error_message = "Lab name must be 3-20 lowercase letters, numbers or hyphens, starting with a letter."
  }
}
variable "github_repository" {
  type        = string
  description = "Exact GitHub OIDC repository segment, including immutable IDs when GitHub uses them. Only main is trusted."
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+(@[0-9]+)?/[A-Za-z0-9_.-]+(@[0-9]+)?$", var.github_repository))
    error_message = "Use OWNER/REPOSITORY or OWNER@OWNER_ID/REPOSITORY@REPOSITORY_ID."
  }
}
variable "existing_oidc_provider_arn" {
  type        = string
  default     = ""
  description = "If GitHub OIDC already exists in the account, supply its ARN to avoid duplicate creation."
}
