######################### Provider Settings #########################

variable "provider_auth_url" {
  type      = string
  sensitive = true
  default   = "https://auth.pscloud.io/v3/"
}

variable "provider_region" {
  type      = string
  sensitive = true
  default   = "kz-1"
}

variable "provider_connect_username" {
  type      = string
  sensitive = true
  default   = ""
}

variable "provider_connect_password" {
  type      = string
  sensitive = true
  default   = ""
}

variable "provider_connect_tenant_name" {
  type      = string
  sensitive = true
  default   = ""
}

variable "access_key" {
  description = "Access key for S3"
  type        = string
  default     = ""
  sensitive   = true
}

variable "tested_map" {
  type = map(string)
  default = {
    "key" = "str0ngPa@ssw0rd"
    "key2" = "str0ngPa@ssw0rd"
    "key3" = "str0ngPa@ssw0rd"
  }
}
