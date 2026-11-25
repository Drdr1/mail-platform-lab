output "public_ip" {
  description = "Use for the MX host A record, SPF, the PTR request and the Workspace relay IP allowlist."
  value       = google_compute_address.mail.address
}
