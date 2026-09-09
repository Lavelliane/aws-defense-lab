output "app_instance_id" {
  value = aws_instance.app.id
}
output "manager_instance_id" {
  value = aws_instance.manager.id
}
output "app_private_url" {
  value = "http://${aws_instance.app.private_ip}:8080"
}
output "app_url" {
  value = "http://${aws_instance.app.public_ip}:8080"
}
output "dashboard_url" {
  value = "https://${aws_instance.manager.public_ip}"
}
output "data_bucket" {
  value = aws_s3_bucket.lab["data"].id
}
output "log_bucket" {
  value = aws_s3_bucket.lab["audit"].id
}
output "app_mode" {
  value = var.app_mode
}
output "lab_name" {
  value = var.lab_name
}
