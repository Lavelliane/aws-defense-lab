mock_provider "aws" {}

variables {
  github_repository = "octo-org@123456/octo-repo@456789"
  aws_region        = "ap-southeast-1"
  lab_name          = "defense-lab"
}

run "immutable_github_subject" {
  command = plan

  assert {
    condition     = local.github_subject == "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main"
    error_message = "The deploy role must trust GitHub's immutable repository subject on main."
  }
}
