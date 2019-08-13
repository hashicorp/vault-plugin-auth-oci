// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import "github.com/oracle/oci-go-sdk/common"

// Do not edit this file. This is based on standard OCI GO SDK format

type FilterGroupMembershipDetails struct {
	Principal Principal `json:"principal"`
	GroupIds  []string  `json:"groupIds"`
}

func (m FilterGroupMembershipDetails) String() string {
	return common.PointerString(m)
}
