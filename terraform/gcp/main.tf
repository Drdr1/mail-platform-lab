terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project
  region  = var.region
}

resource "google_compute_address" "mail" {
  name   = "${var.name}-ip"
  region = var.region
}

resource "google_compute_instance" "mail" {
  name         = var.name
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["mail-server"]

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = var.disk_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.mail.address
    }
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  shielded_instance_config {
    enable_secure_boot = true
  }

  service_account {
    scopes = ["logging-write", "monitoring-write"]
  }
}

# Google Cloud blocks outbound TCP 25 from every VM. Inbound 25 works, so this
# host receives mail directly but must send through a relay on 587/465
# (Google Workspace SMTP relay or a sending provider). See docs/workspace-relay.md.
resource "google_compute_firewall" "mail_in" {
  name          = "${var.name}-mail-in"
  network       = "default"
  target_tags   = ["mail-server"]
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["25", "465", "587", "993"]
  }
}

resource "google_compute_firewall" "ssh_admin" {
  name          = "${var.name}-ssh-admin"
  network       = "default"
  target_tags   = ["mail-server"]
  source_ranges = var.admin_cidrs
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_resource_policy" "daily_snapshot" {
  name   = "${var.name}-daily-snapshot"
  region = var.region
  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "03:00"
      }
    }
    retention_policy {
      max_retention_days = var.snapshot_retention_days
    }
  }
}

resource "google_compute_disk_resource_policy_attachment" "boot" {
  name = google_compute_resource_policy.daily_snapshot.name
  disk = google_compute_instance.mail.name
  zone = var.zone
}
