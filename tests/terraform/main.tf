// Copyright (c) 2017, 2023, Oracle and/or its affiliates. All rights reserved.
// Licensed under the Mozilla Public License v2.0

variable "region" {
  type    = string
  default = "us-sanjose-1"
}

variable "tenancy_ocid" {
  type = string
}

variable "user_ocid" {
  type = string
}

variable "fingerprint" {
  type = string
}

variable "private_key_path" {
  type = string
}

variable "instance_shape" {
  default = "VM.Standard1.1"
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

data "oci_identity_availability_domain" "ad" {
  compartment_id = var.tenancy_ocid
  ad_number      = 1
}

# make SSH key
resource "tls_private_key" "main" {
  algorithm = "RSA"
}

resource "null_resource" "main" {
  triggers = {
    key = tls_private_key.main.public_key_openssh
  }
  provisioner "local-exec" {
    command = "echo \"${tls_private_key.main.private_key_pem}\" > private.key"
  }

  provisioner "local-exec" {
    command = "chmod 600 private.key"
  }
}

variable "instance_image_ocid" {
  type = map(string)

  default = {
    # See https://docs.oracle.com/en-us/iaas/images/
    # Ubuntu 22.04
    us-sanjose-1 = "ocid1.image.oc1.us-sanjose-1.aaaaaaaarvcih66qkcvp5da7vhaggw2kgmgnwv3gnqxdlf4zhgwirlpa2yna"
    us-phoenix-1 = "ocid1.image.oc1.phx.aaaaaaaajsoferqpz5bf6xagdw4hwh4whlq2lpqexap2d5hjnmbskxygg7va"
  }
}

resource "oci_core_vcn" "test_vcn" {
  cidr_block     = "10.1.0.0/16"
  compartment_id = var.tenancy_ocid
  display_name   = "TestVcn"
  dns_label      = "testvcn"
}


resource "oci_core_internet_gateway" "test_internet_gateway" {
  compartment_id = var.tenancy_ocid
  display_name   = "TestInternetGateway"
  vcn_id         = oci_core_vcn.test_vcn.id
}

resource "oci_core_default_route_table" "default_route_table" {
  manage_default_resource_id = oci_core_vcn.test_vcn.default_route_table_id
  display_name               = "DefaultRouteTable"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.test_internet_gateway.id
  }
}

resource "oci_core_subnet" "test_subnet" {
  availability_domain = data.oci_identity_availability_domain.ad.name
  cidr_block          = "10.1.20.0/24"
  display_name        = "TestSubnet"
  dns_label           = "testsubnet"
  security_list_ids   = [oci_core_vcn.test_vcn.default_security_list_id]
  compartment_id      = var.tenancy_ocid
  vcn_id              = oci_core_vcn.test_vcn.id
  route_table_id      = oci_core_vcn.test_vcn.default_route_table_id
  dhcp_options_id     = oci_core_vcn.test_vcn.default_dhcp_options_id
}


resource "oci_core_instance" "test_instance" {
  availability_domain = data.oci_identity_availability_domain.ad.name
  compartment_id      = var.tenancy_ocid
  display_name        = "TestInstance"
  shape               = var.instance_shape

  source_details {
    source_type = "image"
    source_id   = var.instance_image_ocid[var.region]
  }

  create_vnic_details {
    subnet_id = oci_core_subnet.test_subnet.id
  }

  metadata = {
    ssh_authorized_keys = tls_private_key.main.public_key_openssh
    user_data = base64encode(join("\n", [
      "#!/bin/bash",
      "apt-get update",
      "NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",
      "touch /tmp/user-data-completed",
    ]))
  }

  timeouts {
    create = "60m"
  }

  provisioner "remote-exec" {
    inline = [
      "while [ ! -f /tmp/user-data-completed ]; do sleep 2; done",
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      host        = oci_core_instance.test_instance.public_ip
      private_key = tls_private_key.main.private_key_pem
    }
  }
}

resource "oci_identity_dynamic_group" "test_dynamic_group" {
  compartment_id = var.tenancy_ocid
  description    = "test dynamic group"
  matching_rule  = "Any {instance.id = '${oci_core_instance.test_instance.id}', resource.id = '${var.user_ocid}'}"
  name           = "VaultDynamicGroup"
}

resource "oci_identity_group" "test_group" {
  compartment_id = var.tenancy_ocid
  description    = "test group"
  name           = "VaultTestGroup"
}

resource "oci_identity_user_group_membership" "test_user_group_membership" {
  group_id = oci_identity_group.test_group.id
  user_id  = var.user_ocid
}

resource "oci_identity_policy" "test_policy" {
  compartment_id = var.tenancy_ocid
  description    = "allow dynamic group to auth and group membership"
  name           = "VaultDynamicGroupInspectPolicy"
  statements = [
    "allow dynamic-group ${oci_identity_dynamic_group.test_dynamic_group.name} to {AUTHENTICATION_INSPECT} in tenancy",
    "allow dynamic-group ${oci_identity_dynamic_group.test_dynamic_group.name} to {GROUP_MEMBERSHIP_INSPECT} in tenancy",
  ]
}

resource "null_resource" "oci_config" {
  triggers = {
    instance = oci_core_instance.test_instance.id
  }
  depends_on = [oci_core_instance.test_instance]
  provisioner "remote-exec" {
    inline = [
      "mkdir /home/ubuntu/.oci",
      "echo '[DEFAULT]' > /home/ubuntu/.oci/config",
      "echo 'user=${var.user_ocid}' >> /home/ubuntu/.oci/config",
      "echo 'fingerprint=${var.fingerprint}' >> /home/ubuntu/.oci/config",
      "echo 'tenancy=${var.tenancy_ocid}' >> /home/ubuntu/.oci/config",
      "echo 'region=${var.region}' >> /home/ubuntu/.oci/config",
      "echo 'key_file=/home/ubuntu/.oci/oci-private.key' >> /home/ubuntu/.oci/config",
    ]
    connection {
      type        = "ssh"
      user        = "ubuntu"
      host        = oci_core_instance.test_instance.public_ip
      private_key = tls_private_key.main.private_key_pem
    }
  }
}

resource "null_resource" "oci_private_key" {
  triggers = {
    instance = oci_core_instance.test_instance.id
  }
  depends_on = [null_resource.oci_config]

  provisioner "local-exec" {
    command = "scp -i private.key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${var.private_key_path} ubuntu@${oci_core_instance.test_instance.public_ip}:/home/ubuntu/.oci/oci-private.key"
  }
}

resource "null_resource" "plugin_test" {
  triggers = {
    instance = oci_core_instance.test_instance.id
  }
  depends_on = [null_resource.oci_private_key]
  provisioner "remote-exec" {
    inline = [
      "NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive sudo -E apt-get install -y git golang make",
      "git clone https://github.com/hashicorp/vault-plugin-auth-oci",
      "cd vault-plugin-auth-oci && make testacc HOME_TENANCY_ID=${var.tenancy_ocid} ROLE_OCID_LIST=${oci_identity_group.test_group.id},${oci_identity_dynamic_group.test_dynamic_group.id} OCI_GO_SDK_DEBUG=info VAULT_LOG_LEVEL=debug",
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      host        = oci_core_instance.test_instance.public_ip
      private_key = tls_private_key.main.private_key_pem
    }
  }
}

output "rerun_acceptance_tests" {
  value = join("\n", [
    "# to rerun acceptance tests, SSH to the instance:",
    "ssh -i private.key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@${oci_core_instance.test_instance.public_ip}",
    "# and run:",
    "cd vault-plugin-auth-oci",
    "make testacc HOME_TENANCY_ID=${var.tenancy_ocid} ROLE_OCID_LIST=${oci_identity_group.test_group.id},${oci_identity_dynamic_group.test_dynamic_group.id} OCI_GO_SDK_DEBUG=info VAULT_LOG_LEVEL=debug",
  ])
}
