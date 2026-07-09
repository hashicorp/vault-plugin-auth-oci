// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

type testConfigurationProvider struct {
	privateKey *rsa.PrivateKey
	region     string
}

func newTestConfigurationProvider(t *testing.T, region string) testConfigurationProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return testConfigurationProvider{
		privateKey: privateKey,
		region:     region,
	}
}

func (provider testConfigurationProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return provider.privateKey, nil
}

func (provider testConfigurationProvider) KeyID() (string, error) {
	return "ocid1.tenancy.oc1..test/ocid1.user.oc1..test/test:fingerprint", nil
}

func (provider testConfigurationProvider) TenancyOCID() (string, error) {
	return "ocid1.tenancy.oc1..test", nil
}

func (provider testConfigurationProvider) UserOCID() (string, error) {
	return "ocid1.user.oc1..test", nil
}

func (provider testConfigurationProvider) KeyFingerprint() (string, error) {
	return "test:fingerprint", nil
}

func (provider testConfigurationProvider) Region() (string, error) {
	return provider.region, nil
}

func (provider testConfigurationProvider) AuthType() (common.AuthConfig, error) {
	return common.AuthConfig{AuthType: common.UnknownAuthenticationType}, nil
}

// TestAuthenticationClientSetRegion verifies that SetRegion produces the correct
// auth endpoint URL for both a standard oc1 region and the non-oc1 region that
// triggered VAULT-39812.
//
// The original bug used DefaultHostURLTemplate which hardcodes ".oraclecloud.com",
// causing failures for realms with a different domain suffix (e.g. Doha = oc21,
// which requires ".oraclecloud21.com"). The fix delegates to EndpointForTemplate,
// which is realm-aware. Full realm-to-domain mapping is tested by the OCI SDK itself.
func TestAuthenticationClientSetRegionAllRealms(t *testing.T) {
	tests := []struct {
		realm        string
		region       string
		expectedHost string
	}{
		// oc1 — standard commercial: must still resolve to oraclecloud.com
		{"oc1", "us-ashburn-1", "https://auth.us-ashburn-1.oraclecloud.com"},
		// oc21 — Doha DCC: regression case for VAULT-39812
		{"oc21", "me-dcc-doha-1", "https://auth.me-dcc-doha-1.oraclecloud21.com"},
	}

	for _, tc := range tests {
		t.Run(tc.region, func(t *testing.T) {
			client := AuthenticationClient{}
			client.SetRegion(tc.region)
			if client.Host != tc.expectedHost {
				t.Errorf("realm %s: SetRegion(%q)\n  got:  %q\n  want: %q",
					tc.realm, tc.region, client.Host, tc.expectedHost)
			}
		})
	}
}

func TestAuthenticationClientSetConfigurationProviderUsesRegionEndpoint(t *testing.T) {
	provider := newTestConfigurationProvider(t, "me-dcc-doha-1")

	client, err := NewAuthenticationClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatalf("expected client construction to succeed, got error: %v", err)
	}

	if client.Host != "https://auth.me-dcc-doha-1.oraclecloud21.com" {
		t.Fatalf("expected provider-based Doha host %q, got %q", "https://auth.me-dcc-doha-1.oraclecloud21.com", client.Host)
	}
}

func TestAuthenticationClientSetConfigurationProviderHonorsEnvOverride(t *testing.T) {
	t.Setenv("OCI_SDK_AUTH_CLIENT_REGION_URL", "https://custom-auth.example.com")
	provider := newTestConfigurationProvider(t, "me-dcc-doha-1")

	client, err := NewAuthenticationClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatalf("expected client construction to succeed, got error: %v", err)
	}

	if client.Host != "https://custom-auth.example.com" {
		t.Fatalf("expected env override host %q, got %q", "https://custom-auth.example.com", client.Host)
	}
}
