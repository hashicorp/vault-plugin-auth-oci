// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

//These constants store the configuration keys
const (
	HomeTenancyIdConfigName = "homeTenancyId"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			HomeTenancyIdConfigName: {
				Type:        framework.TypeString,
				Description: "The tenancy id of the account.",
			},
		},

		ExistenceCheck: b.pathConfigExistenceCheck,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigCreate,
			logical.UpdateOperation: b.pathConfigUpdate,
			logical.DeleteOperation: b.pathConfigDelete,
			logical.ReadOperation:   b.pathConfigRead,
		},

		HelpSynopsis:    pathConfigSyn,
		HelpDescription: pathConfigDesc,
	}
}

// Establishes dichotomy of request operation between CreateOperation and UpdateOperation.
// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.lockedOCIConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

// lockedOCIConfig returns the properties set on the given config. This method
// acquires the read lock before reading the config from the storage.
func (b *backend) lockedOCIConfig(ctx context.Context, s logical.Storage) (*OCIConfigEntry, error) {
	b.configMutex.RLock()
	configEntry, err := b.nonLockedOCIConfig(ctx, s)
	// we manually unlock rather than defer the unlock because we might need to grab
	// a read/write lock in the upgrade path
	b.configMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	if configEntry == nil {
		return nil, nil
	}
	return configEntry, nil
}

// lockedSetOCIConfig creates or updates a config in the storage. This method
// acquires the write lock before creating or updating the config at the storage.
func (b *backend) lockedSetOCIConfig(ctx context.Context, s logical.Storage, configEntry *OCIConfigEntry) error {
	if configEntry == nil {
		return fmt.Errorf("config is not found")
	}

	b.configMutex.Lock()
	defer b.configMutex.Unlock()

	return b.nonLockedSetOCIConfig(ctx, s, configEntry)
}

// nonLockedSetOCIConfig creates or updates a config in the storage. This method
// does not acquire the write lock before writing the config to the storage. If
// locking is desired, use lockedSetOCIConfig instead.
func (b *backend) nonLockedSetOCIConfig(ctx context.Context, s logical.Storage, configEntry *OCIConfigEntry) error {
	if configEntry == nil {
		return fmt.Errorf("config is not found")
	}

	entry, err := logical.StorageEntryJSON("config", configEntry)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// nonLockedOCIConfig returns the properties set on the given config. This method
// does not acquire the read lock before reading the config from the storage. If
// locking is desired, use lockedOCIConfig instead.
// This method also does NOT check to see if a config upgrade is required. It is
// the responsibility of the caller to check if a config upgrade is required and,
// if so, to upgrade the config
func (b *backend) nonLockedOCIConfig(ctx context.Context, s logical.Storage) (*OCIConfigEntry, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result OCIConfigEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configEntry, err := b.lockedOCIConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if configEntry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: configEntry.ToResponseData(),
	}, nil
}

// create a Config
func (b *backend) pathConfigCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	homeTenancyId := data.Get(HomeTenancyIdConfigName).(string)
	if strings.TrimSpace(homeTenancyId) == "" {
		return logical.ErrorResponse("missing homeTenancyId"), nil
	}

	b.configMutex.Lock()
	defer b.configMutex.Unlock()

	configEntry, err := b.nonLockedOCIConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if configEntry != nil {
		return logical.ErrorResponse("The specified config already exists"), nil
	}

	configEntry = &OCIConfigEntry{
		HomeTenancyId: homeTenancyId,
	}

	if err := b.nonLockedSetOCIConfig(ctx, req.Storage, configEntry); err != nil {
		return nil, err
	}

	var resp logical.Response

	return &resp, nil
}

// update a Config
func (b *backend) pathConfigUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	homeTenancyId := data.Get(HomeTenancyIdConfigName).(string)
	if strings.TrimSpace(homeTenancyId) == "" {
		return logical.ErrorResponse("missing homeTenancyId"), nil
	}

	b.configMutex.Lock()
	defer b.configMutex.Unlock()

	configEntry, err := b.nonLockedOCIConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if configEntry == nil {
		return logical.ErrorResponse("The specified config does not exist"), nil
	}

	configEntry.HomeTenancyId = homeTenancyId

	if err := b.nonLockedSetOCIConfig(ctx, req.Storage, configEntry); err != nil {
		return nil, err
	}

	var resp logical.Response
	return &resp, nil
}

// delete a Config
func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.configMutex.Lock()
	defer b.configMutex.Unlock()

	return nil, req.Storage.Delete(ctx, "config")
}

// Struct to hold the information associated with an OCI config
type OCIConfigEntry struct {
	HomeTenancyId string `json:"homeTenancyId" `
}

func (r *OCIConfigEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		"homeTenancyId": r.HomeTenancyId,
	}

	return responseData
}

const pathConfigSyn = `
Manages the configuration for the Vault Auth Plugin.
`

const pathConfigDesc = `
The homeTenancyId configuration is the Tenant OCID of your OCI Account. Only login requests from entities present in this tenant id are accepted.

Example:

vault write /auth/oci/config homeTenancyId=myocid
`
