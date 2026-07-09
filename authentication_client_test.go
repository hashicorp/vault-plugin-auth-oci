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

// TestAuthenticationClientSetRegionAllRealms verifies that SetRegion produces the correct
// auth endpoint URL across known OCI realms.
//
// The original bug (VAULT-39812) used DefaultHostURLTemplate which hardcodes ".oraclecloud.com"
// and omits the "https://" scheme, causing failures for any non-oc1 realm (e.g. Doha = oc21
// which requires ".oraclecloud21.com"). The fix uses EndpointForTemplate which is realm-aware.
func TestAuthenticationClientSetRegionAllRealms(t *testing.T) {
	tests := []struct {
		realm        string
		region       string
		expectedHost string
	}{
		// oc1 — standard commercial
		{"oc1", "us-ashburn-1", "https://auth.us-ashburn-1.oraclecloud.com"},
		// oc3 — US Government
		{"oc3", "us-gov-ashburn-1", "https://auth.us-gov-ashburn-1.oraclegovcloud.com"},
		// oc4 — UK Government
		{"oc4", "uk-gov-london-1", "https://auth.uk-gov-london-1.oraclegovcloud.uk"},
		// oc8 — Japan Government
		{"oc8", "ap-chiyoda-1", "https://auth.ap-chiyoda-1.oraclecloud8.com"},
		// oc9 — Muscat DCC
		{"oc9", "me-dcc-muscat-1", "https://auth.me-dcc-muscat-1.oraclecloud9.com"},
		// oc10 — Canberra DCC
		{"oc10", "ap-dcc-canberra-1", "https://auth.ap-dcc-canberra-1.oraclecloud10.com"},
		// oc14 — EU DCC
		{"oc14", "eu-dcc-milan-1", "https://auth.eu-dcc-milan-1.oraclecloud14.com"},
		{"oc14", "eu-dcc-rating-1", "https://auth.eu-dcc-rating-1.oraclecloud14.com"},
		{"oc14", "eu-dcc-dublin-1", "https://auth.eu-dcc-dublin-1.oraclecloud14.com"},
		// oc15 — Gazipur DCC
		{"oc15", "ap-dcc-gazipur-1", "https://auth.ap-dcc-gazipur-1.oraclecloud15.com"},
		// oc21 — Doha DCC
		{"oc21", "me-dcc-doha-1", "https://auth.me-dcc-doha-1.oraclecloud21.com"},
		// oc24 — Zurich DCC
		{"oc24", "eu-dcc-zurich-1", "https://auth.eu-dcc-zurich-1.oraclecloud24.com"},
		// oc26 — Abu Dhabi 3
		{"oc26", "me-abudhabi-3", "https://auth.me-abudhabi-3.oraclecloud26.com"},
		// oc29 — Abu Dhabi 2
		{"oc29", "me-abudhabi-2", "https://auth.me-abudhabi-2.oraclecloud29.com"},
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
