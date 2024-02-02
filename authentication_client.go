// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// Do not edit this file. This is based on standard OCI GO SDK format

// AuthenticationClient stores the client and configuration details for authenticating
type AuthenticationClient struct {
	common.BaseClient
	config *common.ConfigurationProvider
}

// NewAuthenticationClientWithConfigurationProvider Creates a new default Authentication client with the given configuration provider.
// the configuration provider will be used for the default signer as well as reading the region
func NewAuthenticationClientWithConfigurationProvider(configProvider common.ConfigurationProvider) (client AuthenticationClient, err error) {
	baseClient, err := common.NewClientWithConfig(configProvider)
	if err != nil {
		return
	}

	client = AuthenticationClient{BaseClient: baseClient}
	client.BasePath = ""
	err = client.setConfigurationProvider(configProvider)
	return
}

// SetRegion overrides the region of this client.
func (client *AuthenticationClient) SetHost(host string) {
	client.Host = host
}

// SetConfigurationProvider sets the configuration provider including the region, returns an error if is not valid
func (client *AuthenticationClient) setConfigurationProvider(configProvider common.ConfigurationProvider) error {
	if ok, err := common.IsConfigurationProviderValid(configProvider); !ok {
		return err
	}

	// Error has been checked already
	region, _ := configProvider.Region()
	client.config = &configProvider
	if regionURL, ok := os.LookupEnv("OCI_SDK_AUTH_CLIENT_REGION_URL"); ok {
		client.Host = regionURL
	} else {
		client.Host = fmt.Sprintf(common.DefaultHostURLTemplate, "auth", string(region))
	}
	client.BasePath = "/v1"
	return nil
}

// SetRegion overrides the region of this client.
func (client *AuthenticationClient) SetRegion(region string) {
	client.Host = fmt.Sprintf(common.DefaultHostURLTemplate, "auth", region)
}

// AuthenticateClient takes in a request to authenticate a client, makes the API request to OCI Identity and returns the Response.
// If the authentication is successful, the AuthenticateClientResult member of the response will contain the Principal of the authenticated entity.
func (client AuthenticationClient) AuthenticateClient(ctx context.Context, request AuthenticateClientRequest) (response AuthenticateClientResponse, err error) {
	var ociResponse common.OCIResponse
	policy := common.NoRetryPolicy()
	if request.RetryPolicy() != nil {
		policy = *request.RetryPolicy()
	}

	if !(request.OpcRetryToken != nil && *request.OpcRetryToken != "") {
		request.OpcRetryToken = common.String(common.RetryToken())
	}

	ociResponse, err = common.Retry(ctx, request, client.authenticateClient, policy)
	if err != nil {
		if ociResponse != nil {
			response = AuthenticateClientResponse{RawResponse: ociResponse.HTTPResponse()}
		}
		return
	}
	if convertedResponse, ok := ociResponse.(AuthenticateClientResponse); ok {
		response = convertedResponse
	} else {
		err = fmt.Errorf("failed to convert OCIResponse into AuthenticateClientResponse")
	}
	return
}

func (client AuthenticationClient) authenticateClient(ctx context.Context, request common.OCIRequest, binaryRequestBody *common.OCIReadSeekCloser, extraHeaders map[string]string) (common.OCIResponse, error) {
	httpRequest, err := request.HTTPRequest(http.MethodPost, "/authentication/authenticateClient", binaryRequestBody, extraHeaders)
	if err != nil {
		return nil, err
	}

	var response AuthenticateClientResponse
	var httpResponse *http.Response
	httpResponse, err = client.Call(ctx, &httpRequest)
	defer common.CloseBodyIfValid(httpResponse)
	response.RawResponse = httpResponse
	if err != nil {
		return response, err
	}

	err = common.UnmarshalResponse(httpResponse, &response)

	return response, err
}

// FilterGroupMembership takes in a list of Group or Dynamic Group IDs and a Principal context and makes an API request to OCI Identity.
// If the request is successful, it returns the subset of the request groups that the entity corresponding to the Principal is a part of.
func (client AuthenticationClient) FilterGroupMembership(ctx context.Context, request FilterGroupMembershipRequest) (response FilterGroupMembershipResponse, err error) {
	var ociResponse common.OCIResponse
	policy := common.NoRetryPolicy()
	if request.RetryPolicy() != nil {
		policy = *request.RetryPolicy()
	}

	if !(request.OpcRetryToken != nil && *request.OpcRetryToken != "") {
		request.OpcRetryToken = common.String(common.RetryToken())
	}

	ociResponse, err = common.Retry(ctx, request, client.filterGroupMembership, policy)
	if err != nil {
		if ociResponse != nil {
			response = FilterGroupMembershipResponse{RawResponse: ociResponse.HTTPResponse()}
		}
		return
	}
	if convertedResponse, ok := ociResponse.(FilterGroupMembershipResponse); ok {
		response = convertedResponse
	} else {
		err = fmt.Errorf("failed to convert OCIResponse into FilterGroupMembershipResponse")
	}
	return
}

func (client AuthenticationClient) filterGroupMembership(ctx context.Context, request common.OCIRequest, binaryRequestBody *common.OCIReadSeekCloser, extraHeaders map[string]string) (common.OCIResponse, error) {
	httpRequest, err := request.HTTPRequest(http.MethodPost, "/filterGroupMembership", binaryRequestBody, extraHeaders)
	if err != nil {
		return nil, err
	}

	var response FilterGroupMembershipResponse
	var httpResponse *http.Response
	httpResponse, err = client.Call(ctx, &httpRequest)
	defer common.CloseBodyIfValid(httpResponse)
	response.RawResponse = httpResponse
	if err != nil {
		return response, err
	}

	err = common.UnmarshalResponse(httpResponse, &response)

	return response, err
}
