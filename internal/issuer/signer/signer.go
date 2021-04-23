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
	"context"
	"fmt"
	"regexp"

	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// Signer is an abstraction of the certificate authority
type Signer interface {
	Sign(context.Context, []byte, string, string) ([]byte, error)
	CheckIssuer(context.Context, string) error
}

type caSigner struct {
	baseClient kv.BaseClient
	vaultURL   string
}

func NewSigner(creds map[string][]byte, vaultName string) (Signer, error) {
	kvClient := kv.New()
	err := kvClient.AddToUserAgent("cert-manager-issuer")
	if err != nil {
		return nil, fmt.Errorf("failed to add user agent to keyvault client, error: %+v", err)
	}
	// get auth config
	config, err := getConfigFromSecretData(creds)
	if err != nil {
		return nil, err
	}
	// get azure cloud environment name
	env, err := parseCloudEnvironment(config.cloud)
	if err != nil {
		return nil, err
	}
	// get keyvault url
	vaultURL, err := getVaultURL(env, vaultName)
	if err != nil {
		return nil, err
	}
	authorizer, err := getKeyvaultToken(config, env)
	if err != nil {
		return nil, err
	}
	kvClient.Authorizer = authorizer

	return &caSigner{
		baseClient: kvClient,
		vaultURL:   *vaultURL,
	}, nil
}

// CheckIssuer gets the issuer name provided in the Issuer/ClusterIssuer custom resource
// use to validate the credentials have permissions to access the issuer and issuer exists
func (s *caSigner) CheckIssuer(ctx context.Context, issuerName string) error {
	_, err := s.baseClient.GetCertificateIssuer(ctx, s.vaultURL, issuerName)
	return err
}

func (s *caSigner) Sign(ctx context.Context, certificateSigningRequest []byte, name, issuerName string) ([]byte, error) {
	csr, err := pki.DecodeX509CertificateRequestBytes(certificateSigningRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CSR: %+v", err)
	}

	params := kv.CertificateCreateParameters{
		CertificatePolicy: &kv.CertificatePolicy{
			X509CertificateProperties: &kv.X509CertificateProperties{
				Subject:                 to.StringPtr(string(csr.RawSubject)),
				SubjectAlternativeNames: &kv.SubjectAlternativeNames{DNSNames: &csr.DNSNames},
			},
			IssuerParameters: &kv.IssuerParameters{
				Name: to.StringPtr(issuerName),
			},
		},
		CertificateAttributes: &kv.CertificateAttributes{},
	}
	_, err = s.baseClient.CreateCertificate(ctx, s.vaultURL, name, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate %s: %v", name, err)
	}
	return nil, nil
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

func getVaultURL(azureEnvironment *azure.Environment, vaultName string) (vaultURL *string, err error) {
	// Key Vault name must be a 3-24 character string
	if len(vaultName) < 3 || len(vaultName) > 24 {
		return nil, fmt.Errorf("invalid vault name: %q, must be between 3 and 24 chars", vaultName)
	}
	// See docs for validation spec: https://docs.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates#objects-identifiers-and-versioning
	isValid := regexp.MustCompile(`^[-A-Za-z0-9]+$`).MatchString
	if !isValid(vaultName) {
		return nil, fmt.Errorf("invalid vault name: %q, must match [-a-zA-Z0-9]{3,24}", vaultName)
	}

	vaultDNSSuffixValue := azureEnvironment.KeyVaultDNSSuffix
	vaultURI := "https://" + vaultName + "." + vaultDNSSuffixValue + "/"
	return &vaultURI, nil
}

// getKeyvaultToken returns token for Keyvault endpoint
func getKeyvaultToken(config *authConfig, env *azure.Environment) (authorizer autorest.Authorizer, err error) {
	kvEndPoint := env.KeyVaultEndpoint
	if '/' == kvEndPoint[len(kvEndPoint)-1] {
		kvEndPoint = kvEndPoint[:len(kvEndPoint)-1]
	}
	servicePrincipalToken, err := getServicePrincipalToken(config, env, kvEndPoint)
	if err != nil {
		return nil, err
	}
	authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	return authorizer, nil
}

// getServicePrincipalToken creates a new service principal token based on the configuration
func getServicePrincipalToken(config *authConfig, env *azure.Environment, resource string) (adal.OAuthTokenProvider, error) {
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, config.tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth config, error: %v", err)
	}

	if config.useManagedIdentity {
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, fmt.Errorf("failed to get managed service identity endpoint, error: %v", err)
		}
		// using user-assigned managed identity to access keyvault
		if len(config.userAssignedIdentityID) > 0 {
			return adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, env.ServiceManagementEndpoint, config.userAssignedIdentityID)
		}
		// using system-assigned managed identity to access keyvault
		return adal.NewServicePrincipalTokenFromMSI(msiEndpoint, resource)
	}
	// using service-principal to access the keyvault instance
	if len(config.aadClientID) > 0 && len(config.aadClientSecret) > 0 {
		return adal.NewServicePrincipalToken(*oauthConfig, config.aadClientID, config.aadClientSecret, resource)
	}
	return nil, fmt.Errorf("no credentials provided for accessing keyvault")
}
