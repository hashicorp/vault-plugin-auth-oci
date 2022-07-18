// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestResolveRole(t *testing.T) {
	role := "testrole"
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	roleData := map[string]interface{}{
		"description":    "My dev role",
		"ocid_list":      "ocid1,ocid2",
		"token_policies": "policy1,policy2",
		"token_ttl":      1500,
	}

	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Storage:   config.StorageView,
		Data:      roleData,
		Path:      "role/" + role,
	}

	resp, err := b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Role creation failed. resp:%#v\n err:%v", resp, err)
	}

	loginData := map[string]interface{}{
		"role": role,
	}
	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   config.StorageView,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["role"] != role {
		t.Fatalf("Role was not as expected. Expected %s, received %s", role, resp.Data["role"])
	}
}
