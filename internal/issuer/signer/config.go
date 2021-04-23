/*
Copyright 2021 Anish Ramasekar.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"fmt"
	"strconv"
)

const (
	cloudKey                  = "cloud"
	tenantIDKey               = "tenantID"
	aadClientIDKey            = "aadClientID"
	aadClientSecretKey        = "aadClientSecret"
	useManagedIdentityKey     = "useManagedIdentity"
	userAssignedIdentityIDKey = "userAssignedIdentity"
)

// authConfig holds auth related part of cloud config
type authConfig struct {
	// The cloud environment identifier. Takes values from https://github.com/Azure/go-autorest/blob/ec5f4903f77ed9927ac95b19ab8e44ada64c1356/autorest/azure/environments.go#L13
	cloud string
	// The AAD Tenant ID for the Subscription that the keyvault is in
	tenantID string
	// The ClientID for an AAD application with RBAC access to keyvault
	aadClientID string
	// The ClientSecret for an AAD application with RBAC access to keyvault
	aadClientSecret string
	// Use managed service identity to access keyvault instance
	useManagedIdentity bool
	// UserAssignedIdentityID contains the Client ID of the user assigned MSI which is assigned to the underlying VMs. If empty the user assigned identity is not used.
	// More details of the user assigned identity can be found at: https://docs.microsoft.com/en-us/azure/active-directory/managed-service-identity/overview
	// For the user assigned identity specified here to be used, the UseManagedIdentityExtension has to be set to true.
	userAssignedIdentityID string
}

// getConfigFromSecretData returns authConfig based on the credentials provided in the secret data
func getConfigFromSecretData(data map[string][]byte) (*authConfig, error) {
	var err error

	config := new(authConfig)
	config.cloud = string(data[cloudKey])
	config.tenantID = string(data[tenantIDKey])
	config.aadClientID = string(data[aadClientIDKey])
	config.aadClientSecret = string(data[aadClientSecretKey])
	config.userAssignedIdentityID = string(data[userAssignedIdentityIDKey])

	config.useManagedIdentity = false
	if string(data[useManagedIdentityKey]) != "" {
		if config.useManagedIdentity, err = strconv.ParseBool(string(data[useManagedIdentityKey])); err != nil {
			return nil, fmt.Errorf("failed to parse auth config: %+v", err)
		}
	}

	return config, nil
}
