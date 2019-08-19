// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// Constants for role specific data
const (
	// Increasing this above this limit might require implementing
	// client-side paging in the filterGroupMembership API
	MaxOCIDsPerRole = 100
)

func pathRole(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
			},
			"ocid_list": {
				Type:        framework.TypeCommaStringSlice,
				Description: `A comma separated list of Group or Dynamic Group OCIDs that are allowed to take this role.`,
			},
		},

		ExistenceCheck: b.pathRoleExistenceCheck,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathRoleCreateUpdate,
			logical.UpdateOperation: b.pathRoleCreateUpdate,
			logical.ReadOperation:   b.pathRoleRead,
			logical.DeleteOperation: b.pathRoleDelete,
		},

		HelpSynopsis:    pathRoleSyn,
		HelpDescription: pathRoleDesc,
	}

	tokenutil.AddTokenFields(p.Fields)

	return p
}

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

// Establishes dichotomy of request operation between CreateOperation and UpdateOperation.
// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.lockedOCIRole(ctx, req.Storage, data.Get("role").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

// lockedOCIRole returns the properties set on the given role. This method
// acquires the read lock before reading the role from the storage.
func (b *backend) lockedOCIRole(ctx context.Context, s logical.Storage, roleName string) (*OCIRoleEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}

	b.roleMutex.RLock()
	roleEntry, err := b.nonLockedOCIRole(ctx, s, roleName)
	// we manually unlock rather than defer the unlock because we might need to grab
	// a read/write lock in the upgrade path
	b.roleMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return nil, nil
	}
	return roleEntry, nil
}

// lockedSetOCIRole creates or updates a role in the storage. This method
// acquires the write lock before creating or updating the role at the storage.
func (b *backend) lockedSetOCIRole(ctx context.Context, s logical.Storage, roleName string, roleEntry *OCIRoleEntry) error {
	if roleName == "" {
		return fmt.Errorf("missing role name")
	}

	if roleEntry == nil {
		return fmt.Errorf("nil role entry")
	}

	b.roleMutex.Lock()
	defer b.roleMutex.Unlock()

	return b.nonLockedSetOCIRole(ctx, s, roleName, roleEntry)
}

// nonLockedSetOCIRole creates or updates a role in the storage. This method
// does not acquire the write lock before reading the role from the storage. If
// locking is desired, use lockedSetOCIRole instead.
func (b *backend) nonLockedSetOCIRole(ctx context.Context, s logical.Storage, roleName string,
	roleEntry *OCIRoleEntry) error {
	if roleName == "" {
		return fmt.Errorf("missing role name")
	}

	if roleEntry == nil {
		return fmt.Errorf("nil role entry")
	}

	entry, err := logical.StorageEntryJSON("role/"+roleName, roleEntry)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// nonLockedOCIRole returns the properties set on the given role. This method
// does not acquire the read lock before reading the role from the storage. If
// locking is desired, use lockedOCIRole instead.
// This method also does NOT check to see if a role upgrade is required. It is
// the responsibility of the caller to check if a role upgrade is required and,
// if so, to upgrade the role
func (b *backend) nonLockedOCIRole(ctx context.Context, s logical.Storage, roleName string) (*OCIRoleEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result OCIRoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	return nil, req.Storage.Delete(ctx, "role/"+roleName)
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleEntry, err := b.lockedOCIRole(ctx, req.Storage, data.Get("role").(string))
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return nil, nil
	}

	responseData := map[string]interface{}{
		"role":      roleEntry.Role,
		"ocid_list": roleEntry.OcidList,
	}

	convertNilToEmptySlice := func(data map[string]interface{}, field string) {
		if data[field] == nil || len(data[field].([]string)) == 0 {
			data[field] = []string{}
		}
	}

	convertNilToEmptySlice(responseData, "ocid_list")

	roleEntry.PopulateTokenData(responseData)

	return &logical.Response{
		Data: responseData,
	}, nil
}

// create a Role
func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("role").(string)

	b.roleMutex.Lock()
	defer b.roleMutex.Unlock()

	roleEntry, err := b.nonLockedOCIRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if roleEntry == nil && req.Operation == logical.CreateOperation {
		roleEntry = &OCIRoleEntry{
			Role: roleName,
		}
	} else if roleEntry == nil {
		return logical.ErrorResponse("The specified role does not exist"), nil
	}

	if ocidList, ok := data.GetOk("ocid_list"); ok {
		roleEntry.OcidList = ocidList.([]string)
		if len(roleEntry.OcidList) > MaxOCIDsPerRole {
			return logical.ErrorResponse("Number of OCIDs for this role exceeds the limit"), nil
		}
	}

	if err := roleEntry.ParseTokenFields(req, data); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	var resp logical.Response

	if err := b.nonLockedSetOCIRole(ctx, req.Storage, roleName, roleEntry); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Struct to hold the information associated with an OCI role
type OCIRoleEntry struct {
	tokenutil.TokenParams

	Role     string   `json:"role" `
	OcidList []string `json:"ocid_list"`
}

const pathRoleSyn = `
Create a role and associate policies to it.
`

const pathRoleDesc = `
Create a role and associate policies to it.
`

const pathListRolesHelpSyn = `
Lists all the roles that are registered with Vault.
`

const pathListRolesHelpDesc = `
Roles will be listed by their respective role names.
`
