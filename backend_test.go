// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"os"
	"reflect"
	"testing"
	"time"
)

const (
	DevRole             = "devrole"
	OpsRole             = "opsrole"
	KnowledgeWorkerRole = "kwrole"
	NonExistentRole     = "nonrole"
)

func createHomeTenancy(t *testing.T, backendConfig *logical.BackendConfig, backend logical.Backend) {
	var resp *logical.Response
	var err error
	configPath := "config"

	homeTenancyId := os.Getenv("HOME_TENANCY_ID")

	configData := map[string]interface{}{
		HomeTenancyIdConfigName: homeTenancyId,
	}

	configReq := &logical.Request{
		Operation: logical.CreateOperation,
		Storage:   backendConfig.StorageView,
		Data:      configData,
	}

	configReq.Path = configPath
	resp, err = backend.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: config creation failed. resp:%#v\n err:%v", resp, err)
	}
}

func initTest(t *testing.T) (backend logical.Backend, config *logical.BackendConfig, err error) {

	defaultLeaseTTLVal := time.Hour * 24
	maxLeaseTTLVal := time.Hour * 24 * 2

	config = &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}

	backend, err = Factory(context.Background(), config)

	if err != nil {
		return
	}

	createHomeTenancy(t, config, backend)

	roleOcidList := os.Getenv("ROLE_OCID_LIST")
	if roleOcidList == "" {
		return nil, nil, fmt.Errorf("ROLE_OCID_LIST environment variable is empty")
	}
	//Create the devRole
	devRoleData := map[string]interface{}{
		"role":           DevRole,
		"description":    DevRole + " description",
		"ocid_list":      roleOcidList,
		"token_policies": "policy1,policy2",
		"token_ttl":      1500,
	}

	err = createRole(devRoleData, DevRole, backend, config)
	if err != nil {
		return
	}

	//Create the opsRole
	opsRoleData := map[string]interface{}{
		"role":           OpsRole,
		"description":    OpsRole + " description",
		"ocid_list":      "",
		"token_policies": "policy3",
		"token_ttl":      1000,
	}

	err = createRole(opsRoleData, OpsRole, backend, config)
	if err != nil {
		return
	}

	//Create the knowledgeWorkerRole
	knowledgeWorkerRole := map[string]interface{}{
		"role":           KnowledgeWorkerRole,
		"description":    KnowledgeWorkerRole + " description",
		"ocid_list":      roleOcidList,
		"token_policies": "policy1,policy5",
		"token_ttl":      1000,
	}

	err = createRole(knowledgeWorkerRole, KnowledgeWorkerRole, backend, config)
	if err != nil {
		return
	}

	return
}

func createRole(roleData map[string]interface{}, roleName string, backend logical.Backend, config *logical.BackendConfig) error {
	roleRequest := &logical.Request{
		Operation: logical.CreateOperation,
		Storage:   config.StorageView,
		Data:      roleData,
	}

	roleRequest.Path = "role/" + roleName
	response, err := backend.HandleRequest(context.Background(), roleRequest)
	if err != nil || (response != nil && response.IsError()) {
		return fmt.Errorf("bad: role creation failed. resp:%#v\n err:%v", response, err)
	}

	return nil
}

func TestBackEnd_ValidateUserApiKeyLogin(t *testing.T) {

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	cmdMap := map[string]string{
		"auth_type": "apikey",
		"role":     DevRole,
	}
	makeRequestAndValidateResponse(t, cmdMap, false, 1500*time.Second, []string{"policy1", "policy2"})

	cmdMap = map[string]string{
		"auth_type": "apikey",
		"role":     KnowledgeWorkerRole,
	}
	makeRequestAndValidateResponse(t, cmdMap, false, 1000*time.Second, []string{"policy1", "policy5"})
}

func TestBackEnd_ValidateUserApiKeyLoginNotInRole(t *testing.T) {

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	cmdMap := map[string]string{
		"auth_type": "apikey",
		"role":     OpsRole,
	}
	makeRequestAndValidateResponse(t, cmdMap, true, 1500*time.Second, []string{})
}

func TestBackEnd_ValidateUserApiKeyLoginNonExistentRole(t *testing.T) {

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	cmdMap := map[string]string{
		"auth_type": "apikey",
		"role":     NonExistentRole,
	}
	makeRequestAndValidateResponse(t, cmdMap, true, 1500*time.Second, []string{})
}

func TestBackEnd_ValidateInstancePrincipalLogin(t *testing.T) {

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	cmdMap := map[string]string{
		"auth_type": "ip",
		"role":     DevRole,
	}
	makeRequestAndValidateResponse(t, cmdMap, false, 1500*time.Second, []string{"policy1", "policy2"})

	cmdMap = map[string]string{
		"auth_type": "ip",
		"role":     KnowledgeWorkerRole,
	}
	makeRequestAndValidateResponse(t, cmdMap, false, 1000*time.Second, []string{"policy1", "policy5"})
}

func TestBackEnd_ValidateInstancePrincipalLoginNotInRole(t *testing.T) {

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	cmdMap := map[string]string{
		"auth_type": "ip",
		"role":     OpsRole,
	}
	makeRequestAndValidateResponse(t, cmdMap, true, 1500*time.Second, []string{})
}

func TestBackEnd_ValidateInstancePrincipalLoginNonExistentRole(t *testing.T) {

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	cmdMap := map[string]string{
		"auth_type": "ip",
		"role":     NonExistentRole,
	}
	makeRequestAndValidateResponse(t, cmdMap, true, 1500*time.Second, []string{})
}

func makeRequestAndValidateResponse(t *testing.T, cmdMap map[string]string, expectFailure bool, expectedTTL time.Duration, expectedPolicies []string) {

	role := cmdMap["role"]
	path := fmt.Sprintf(PathBaseFormat, role)
	signingPath := PathVersionBase + path

	backend, config, err := initTest(t)
	if err != nil {
		t.Fatalf("initTest failed: %s", err)
	}

	loginData, err := CreateLoginData("http://127.0.0.1", cmdMap, signingPath)
	if err != nil {
		t.Fatalf("CreateLoginData failed: %s", err)
	}

	loginRequest := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login/" + role,
		Storage:   config.StorageView,
		Data:      loginData,
	}

	response, err := backend.HandleRequest(context.Background(), loginRequest)

	if err != nil {
		t.Fatalf("Test failed, got error: resp:%#v\n err:%v", response, err)
	}

	if response == nil || (response != nil && response.IsError()) {
		if expectFailure {
			return
		} else {
			t.Fatalf("Test failure: unexpected response: %#v\n", response)
		}
	} else {
		if expectFailure {
			if response.Data["http_status_code"] != 401 {
				t.Fatalf("Expected failure, but the request succeeded. Test Failed. Response: %#v\n", response)
			}
			return
		}
	}

	if response == nil || response.Auth == nil {
		t.Fatalf("Failed response is nil")
	}

	if response.Auth.TTL != expectedTTL {
		t.Fatalf("Failed! Expected TTL: %#v Got TTL: %#v resp: %#v\n", response.Auth.TTL, expectedTTL, response)
	}

	if len(expectedPolicies) != len(response.Auth.Policies) {
		t.Fatalf("Failed! Expected Policies: %#v Got Policies: %#v resp: %#v\n", expectedPolicies, response.Auth.Policies, response)
	}

	expectedPolicyMap := sliceToMap(expectedPolicies)
	responsePolicyMap := sliceToMap(response.Auth.Policies)

	if !reflect.DeepEqual(responsePolicyMap, expectedPolicyMap) {
		t.Fatalf("Failed Policy Comparison! Expected Policies: %#v Got Policies: %#v resp: %#v\n", expectedPolicies, response.Auth.Policies, response)
	}
}
