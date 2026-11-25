variable "project" {
  type = string
}
variable "region" {
  type    = string
  default = "us-central1"
}
variable "zone" {
  type    = string
  default = "us-central1-a"
}
variable "name" {
  type    = string
  default = "mail-platform"
}
variable "machine_type" {
  type    = string
  default = "e2-small"
}
variable "disk_gb" {
  type    = number
  default = 50
}
variable "admin_cidrs" {
  description = "Addresses allowed to SSH in. No default on purpose."
  type        = list(string)
}
variable "snapshot_retention_days" {
  type    = number
  default = 14
}
