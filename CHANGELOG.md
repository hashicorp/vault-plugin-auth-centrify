## Unreleased

SECURITY

* Upgrade dependencies to address multiple security vulnerabilities (SECVULN-40751)

IMPROVEMENTS

* Updated dependencies:
   * go 1.24 => 1.26.3
   * github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d => v0.1.2
   * golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 => v0.15.0
   * github.com/hashicorp/go-secure-stdlib/mlock v0.1.1 => v0.1.3
   * github.com/hashicorp/go-secure-stdlib/password v0.1.1 => v0.1.4
   * github.com/mattn/go-colorable v0.1.13 => v0.1.14
   * github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6 => v0.2.0
   * golang.org/x/text v0.23.0 => v0.37.0
   * github.com/armon/go-metrics v0.3.9 => v0.4.1
   * golang.org/x/term v0.30.0 => v0.43.0
   * golang.org/x/sys v0.31.0 => v0.45.0
   * golang.org/x/crypto v0.36.0 => v0.52.0
   * golang.org/x/net v0.38.0 => v0.55.0
   * github.com/hashicorp/golang-lru v0.5.4 => v1.0.2
   * github.com/hashicorp/go-retryablehttp v0.7.7 => v0.7.8
   * github.com/hashicorp/vault/sdk v0.9.0 => v0.25.1
   * github.com/hashicorp/hcl v1.0.0 => v1.0.1-vault-7
   * github.com/mitchellh/reflectwalk v1.0.0 => v1.0.2
   * github.com/mitchellh/copystructure v1.0.0 => v1.2.0
   * github.com/oklog/run v1.0.0 => v1.2.0
   * github.com/hashicorp/go-uuid v1.0.2 => v1.0.3
   * github.com/hashicorp/go-sockaddr v1.0.2 => v1.0.7
   * github.com/fatih/color v1.16.0 => v1.19.0
   * github.com/hashicorp/go-version v1.2.0 => v1.7.0
   * google.golang.org/protobuf v1.33.0 => v1.36.11
   * github.com/hashicorp/go-plugin v1.4.5 => v1.7.0
   * github.com/golang/protobuf v1.5.3 => v1.5.4
   * google.golang.org/grpc v1.56.3 => v1.79.3
   * go.uber.org/atomic v1.9.0 => v1.11.0
   * github.com/hashicorp/vault/api v1.9.0 => v1.16.0
   * github.com/hashicorp/go-kms-wrapping/entropy/v2 v2.0.0 => v2.0.1
   * github.com/hashicorp/go-kms-wrapping/v2 v2.0.8 => v2.0.18
   * github.com/pierrec/lz4 v2.5.2+incompatible => v2.6.1+incompatible
   * github.com/evanphx/json-patch/v5 v5.5.0 => v5.6.0

## v0.15.0

IMPROVEMENTS

* enable plugin multiplexing [GH-17](https://github.com/hashicorp/vault-plugin-auth-centrify/pull/17)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.0
  * `github.com/hashicorp/vault/sdk` v0.8.1
