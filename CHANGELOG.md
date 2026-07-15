## v0.20.2
### July 15, 2026

* fix OCI auth endpoint resolution for non-oc1 realms (e.g. `me-dcc-doha-1`) to use the correct realm-specific domain instead of always using `oraclecloud.com` (#106)

### Dependency updates:
   * go 1.25.1 => 1.25.11
   * cloud.google.com/go/auth v0.14.1 => v0.18.2
   * cloud.google.com/go/auth/oauth2adapt v0.2.7 => v0.2.8
   * cloud.google.com/go/cloudsqlconn v1.4.3 => v1.20.2
   * cloud.google.com/go/compute/metadata v0.6.0 => v0.9.0
   * github.com/docker/go-connections v0.5.0 => v0.6.0
   * github.com/fatih/color v1.18.0 => v1.19.0
   * github.com/go-jose/go-jose/v4 v4.1.1 => v4.1.4
   * github.com/go-logr/logr v1.4.2 => v1.4.3
   * github.com/googleapis/enterprise-certificate-proxy v0.3.4 => v0.3.14
   * github.com/googleapis/gax-go/v2 v2.14.1 => v2.18.0
   * github.com/hashicorp/go-plugin v1.6.1 => v1.7.0
   * github.com/hashicorp/go-secure-stdlib/plugincontainer v0.4.2 => v0.5.0
   * github.com/hashicorp/vault/api v1.21.0 => v1.22.0
   * github.com/hashicorp/vault/sdk v0.19.0 => v0.21.0
   * github.com/jackc/pgtype v1.14.3 => v1.14.4
   * github.com/oklog/run v1.1.0 => v1.2.0
   * github.com/opencontainers/image-spec v1.1.0 => v1.1.1
   * github.com/stretchr/testify v1.10.0 => v1.11.1
   * go.opentelemetry.io/auto/sdk v1.1.0 => v1.2.1
   * go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.58.0 => v0.67.0
   * go.opentelemetry.io/otel v1.35.0 => v1.42.0
   * go.opentelemetry.io/otel/metric v1.35.0 => v1.42.0
   * go.opentelemetry.io/otel/trace v1.35.0 => v1.42.0
   * golang.org/x/crypto v0.46.0 => v0.53.0
   * golang.org/x/net v0.47.0 => v0.56.0
   * golang.org/x/oauth2 v0.28.0 => v0.36.0
   * golang.org/x/sys v0.39.0 => v0.46.0
   * golang.org/x/text v0.32.0 => v0.38.0
   * golang.org/x/time v0.12.0 => v0.15.0
   * google.golang.org/api v0.221.0 => v0.271.0
   * google.golang.org/genproto/googleapis/rpc v0.0.0-20250207221924-e9438ea467c6 => v0.0.0-20260330182312-d5a96adf58d8
   * google.golang.org/grpc v1.70.0 => v1.79.3
   * google.golang.org/protobuf v1.36.5 => v1.36.11

## v0.20.0
### October 3, 2025

* Upgrade Go Version (#85)
* Automated dependency upgrades (#78)
* init changie (#83)
* Add backport assistant workflow (#81)
* Add backport assistant workflow (#80)
* [Compliance] - PR Template Changes Required (#79)

## 0.19.0
### May 30, 2025

### Build:
* Build with go 1.24.3

### Dependency updates:
* `github.com/hashicorp/vault/sdk` v0.15.0 -> v0.17.0

## 0.18.0
### February 12, 2025

### Build:
* Build with go 1.23.6

### Dependency updates:
* `github.com/hashicorp/vault/api` v1.14.0 -> v1.16.0
* `github.com/hashicorp/vault/sdk` v0.13.0 -> v0.15.0

## 0.17.0
### Sept 5, 2024


### Build:
* Build with go 1.22.6


### Dependency updates:
* `github.com/hashicorp/vault/api` v1.12.2 -> v1.14.0
* `github.com/hashicorp/vault/sdk` v0.11.1 -> v0.13.0


## 0.16.0
### May 20, 2024

IMPROVEMENTS:
* Updated dependencies [PR-52](https://github.com/hashicorp/vault-plugin-auth-oci/pull/52)
* Updated dependencies:
  * `github.com/hashicorp/go-plugin` v1.5.2 -> v1.6.0 to enable running the plugin in containers

## 0.15.1
### February 6, 2024

CHANGES:
* Downgrades github.com/oracle/oci-go-sdk to v59.0.0 due to an incompatibility with Vault

## 0.15.0
### February 6, 2024

IMPROVEMENTS:
* Update go.mod version to 1.21
* Update dependencies:
  * github.com/oracle/oci-go-sdk v24.3.0 -> v65.57.0
  * github.com/hashicorp/go-hclog v1.5.0 -> v1.6.2
  * github.com/hashicorp/vault/api v1.10.0 -> v1.11.0
  * github.com/hashicorp/vault/sdk v0.10.0 -> v0.10.2

## 0.14.2
### September 5, 2023

IMPROVEMENTS:
* Update dependencies:
  * golang.org/x/net v0.9.0 -> v0.15.0

## 0.14.1
### September 5, 2023

IMPROVEMENTS:
* Update dependencies:
  * github.com/hashicorp/vault/api v1.9.1 -> v1.9.2
  * github.com/hashicorp/vault/sdk v0.9.0 -> v0.9.2

## 0.14.0

* Add display attributes for OpenAPI OperationID's [GH-29](https://github.com/hashicorp/vault-plugin-auth-oci/pull/29)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.1 [GH-31](https://github.com/hashicorp/vault-plugin-auth-oci/pull/31)

## 0.13.1

CHANGES:
* Repond with a 400 instead of 401 to login errors. [GH-27](https://github.com/hashicorp/vault-plugin-auth-oci/pull/27)

IMPROVEMENTS:

* Return success message when writing role [GH-27](https://github.com/hashicorp/vault-plugin-auth-oci/pull/27)
* Return error messages when failing to login [GH-27](https://github.com/hashicorp/vault-plugin-auth-oci/pull/27)
* enable plugin multiplexing [GH-25](https://github.com/hashicorp/vault-plugin-auth-oci/pull/25)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.0
  * `github.com/hashicorp/vault/sdk` v0.8.1
