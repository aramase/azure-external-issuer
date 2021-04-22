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

	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
)

// Signer is an abstraction of the certificate authority
type Signer interface {
	Sign([]byte) ([]byte, error)
}

type caSigner struct {
	baseClient kv.BaseClient
}

func NewSigner(creds map[string][]byte, vaultName string) (Signer, error) {
	kvClient := kv.New()
	err := kvClient.AddToUserAgent("cert-manager-issuer")
	if err != nil {
		return nil, fmt.Errorf("failed to add user agent to keyvault client, error: %+v", err)
	}
	// get azure cloud environment name
	cloudName := cloudEnvironment(creds)
	_, err = parseCloudEnvironment(cloudName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cloud environment %s, error: %+v", cloudName, err)
	}
	return &caSigner{
		baseClient: kvClient,
	}, nil
}

func (s *caSigner) Sign([]byte) ([]byte, error) {
	return nil, nil
}

func cloudEnvironment(creds map[string][]byte) string {
	return string(creds["cloud"])
}

// parseCloudEnvironment returns azure environment by name
func parseCloudEnvironment(cloudName string) (*azure.Environment, error) {
	var env azure.Environment
	var err error
	if cloudName == "" {
		env = azure.PublicCloud
	} else {
		env, err = azure.EnvironmentFromName(cloudName)
	}
	return &env, err
}
