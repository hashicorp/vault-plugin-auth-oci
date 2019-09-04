// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"testing"

	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"os"
)

func TestBackend_PathConfig(t *testing.T) {

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	configPath := "config"

	configData := map[string]interface{}{
		HomeTenancyIdConfigName: "ocid1.tenancy.oc1..dummy",
	}

	configReq := &logical.Request{
		Operation: logical.CreateOperation,
		Storage:   config.StorageView,
		Data:      configData,
	}

	configReq.Path = configPath
	resp, err = b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Config creation failed. resp:%#v\n err:%v", resp, err)
	}

	// now read the config
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configReq.Path,
		Storage:   config.StorageView,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Read config failed. resp:%#v\n err:%v", resp, err)
	}

	// now try to update the config (should pass)
	configUpdate := map[string]interface{}{
		HomeTenancyIdConfigName: "ocid1.tenancy.oc2..dummy",
	}

	configReqUpdate := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Data:      configUpdate,
	}

	configReqUpdate.Path = configPath
	resp, err = b.HandleRequest(context.Background(), configReqUpdate)
	if err != nil {
		t.Fatalf("bad: config update failed. resp:%#v\n err:%v", resp, err)
	}

	if resp != nil && resp.IsError() == true {
		t.Fatalf("Config update failed.")
	}

	// now try to delete the config
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configPath,
		Storage:   config.StorageView,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Config delete failed. resp:%#v\n err:%v", resp, err)
	}

	fmt.Println("All tests completed successfully")
}
