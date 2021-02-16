// Copyright 2021 SumUp Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package provider

import (
	"context"
	"crypto/rand"
	stdRsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	stdOs "os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/go-tfe"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func getTFEworkspaceID() string {
	return stdOs.Getenv("TFE_TEST_WORKSPACE_ID")
}

func testAccVariableCheckUpdate(
	t *testing.T,
	provider *schema.Provider,
	sensitive bool,
	value string,
) func(state *terraform.State) error {
	return func(state *terraform.State) error {
		resourceState := state.Modules[0].Resources["vaultedtfe_variable.secret"]
		instanceState := resourceState.Primary

		meta := provider.Meta()
		client, ok := meta.(*MetaClient)
		require.True(t, ok, "unexpected provider meta")

		variable, err := client.TfeClient.Variables.Read(context.Background(), getTFEworkspaceID(), instanceState.ID)
		require.Nil(t, err, "failed to find TFE variable")

		// NOTE: Only possible to check if it's a sensitive.
		require.Equal(t, sensitive, variable.Sensitive)
		require.Equal(t, value, variable.Value)

		return nil
	}
}

func TestResourceVariable(t *testing.T) {
	t.Run(
		"it has schema version of 1",
		func(t *testing.T) {
			actual := resourceVariable()
			assert.Equal(t, 1, actual.SchemaVersion)
		},
	)
}

func TestResourceVariableIntegration_with_VAULTED_PRIVATE_KEY_PATH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	t.Run(
		"with no pre-existing state, it is applied and destroyed successfully",
		func(t *testing.T) {
			osExecutor := &os.RealOsExecutor{}
			rsaSvc := rsa.NewRsaService(osExecutor)

			tmpDir := testutils.TestDir(t, "provider-vaultedtfe")
			testutils.TestChdir(t, tmpDir)

			privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
				t,
				tmpDir,
				"priv.key",
			)

			err := stdOs.Setenv("VAULTED_PRIVATE_KEY_PATH", privkeyPath)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()
			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
			require.Nil(t, err, "failed to generate passphrase")

			encPayloadSvc := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				content.NewV1EncryptedContentService(
					b64Svc,
					aes.NewAesService(pkcs7.NewPkcs7Service()),
				),
			)

			contentArg := "supersecret"

			payload := payload.NewPayload(
				header.NewHeader(),
				passphraseArg,
				content.NewContent([]byte(contentArg)),
			)
			key := acctest.RandomWithPrefix("vaultedtfe")

			encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
			require.Nil(t, err)

			serializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
			require.Nil(t, err)

			category := "terraform"
			sensitive := false
			// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
			// but still run it as an integration test.
			resource.UnitTest(
				t,
				resource.TestCase{
					PreCheck:          func() { testAccPreCheck(t) },
					ProviderFactories: providerFactories,
					Steps: []resource.TestStep{
						{
							Config: testResourceVariableConfig(
								key,
								string(serializedEncPayload),
								category,
								sensitive,
							),
							Check: resource.ComposeTestCheckFunc(
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"key",
									key,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"value",
									string(serializedEncPayload),
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"category",
									category,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"sensitive",
									strconv.FormatBool(sensitive),
								),
							),
						},
					},
				})

			cfg := tfe.DefaultConfig()
			tfeClient, err := tfe.NewClient(cfg)
			require.Nil(t, err, "failed to create TFE client")
			actualVar, err := tfeClient.Variables.Read(
				context.Background(),
				getTFEworkspaceID(),
				key,
			)
			require.Nil(t, actualVar)
			require.True(
				t,
				strings.Contains(err.Error(), "resource not found"),
				"resource must not exist in TFE",
			)
		},
	)

	t.Run(
		"with existing non-sensitive resource that has actually different encrypted content (inside payload), "+
			"it is applied (updated)",
		func(t *testing.T) {
			osExecutor := &os.RealOsExecutor{}
			rsaSvc := rsa.NewRsaService(osExecutor)

			tmpDir := testutils.TestDir(t, "provider-vaultedtfe")
			testutils.TestChdir(t, tmpDir)

			privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
				t,
				tmpDir,
				"priv.key",
			)

			err := stdOs.Setenv("VAULTED_PRIVATE_KEY_PATH", privkeyPath)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()
			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
			if err != nil {
				log.Fatal(err)
			}

			encPayloadSvc := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				content.NewV1EncryptedContentService(
					b64Svc,
					aes.NewAesService(pkcs7.NewPkcs7Service()),
				),
			)

			oldContentArg := "oldsecret"

			payloadInstance := payload.NewPayload(
				header.NewHeader(),
				passphraseArg,
				content.NewContent([]byte(oldContentArg)),
			)
			key := acctest.RandomWithPrefix("encrypted_test")

			encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
			require.Nil(t, err)

			oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
			require.Nil(t, err)

			newContentArg := "newsecret"
			payloadInstance.Content = content.NewContent([]byte(newContentArg))

			encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
			require.Nil(t, err)

			newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
			require.Nil(t, err)

			category := "terraform"
			sensitive := false

			providerInstance := New("dev")()
			providerFactoriesWithSpy := map[string]func() (*schema.Provider, error){
				"vaultedtfe": func() (*schema.Provider, error) {
					return providerInstance, nil
				},
			}

			// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
			// but still run it as an integration test.
			resource.UnitTest(
				t,
				resource.TestCase{
					PreCheck:          func() { testAccPreCheck(t) },
					ProviderFactories: providerFactoriesWithSpy,
					Steps: []resource.TestStep{
						{
							Config: testResourceVariableConfig(
								key,
								string(oldSerializedEncPayload),
								category,
								sensitive,
							),
							Check: resource.ComposeTestCheckFunc(
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"key",
									key,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"value",
									string(oldSerializedEncPayload),
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"category",
									category,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"sensitive",
									strconv.FormatBool(sensitive),
								),
							),
						},
						{
							Config: testResourceVariableConfig(
								key,
								string(newSerializedEncPayload),
								category,
								sensitive,
							),
							Check: testAccVariableCheckUpdate(
								t,
								providerInstance,
								sensitive,
								newContentArg,
							),
						},
					},
				},
			)

			meta := providerInstance.Meta().(*MetaClient)
			require.Nil(t, err, "failed to create TFE client")
			actualVar, err := meta.TfeClient.Variables.Read(
				context.Background(),
				getTFEworkspaceID(),
				key,
			)
			require.Nil(t, actualVar)
			require.True(
				t,
				strings.Contains(err.Error(), "resource not found"),
				"resource must not exist in TFE",
			)
		},
	)

	t.Run(
		"with existing non-sensitive resource that has actually the same encrypted content (inside payload), "+
			"it has no diff during plan, hence nothing is applied",
		func(t *testing.T) {
			osExecutor := &os.RealOsExecutor{}
			rsaSvc := rsa.NewRsaService(osExecutor)

			tmpDir := testutils.TestDir(t, "provider-vaultedtfe")
			testutils.TestChdir(t, tmpDir)

			privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
				t,
				tmpDir,
				"priv.key",
			)

			err := stdOs.Setenv("VAULTED_PRIVATE_KEY_PATH", privkeyPath)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()
			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
			if err != nil {
				log.Fatal(err)
			}

			encPayloadSvc := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				content.NewV1EncryptedContentService(
					b64Svc,
					aes.NewAesService(pkcs7.NewPkcs7Service()),
				),
			)

			oldContentArg := "oldsecret"

			payloadInstance := payload.NewPayload(
				header.NewHeader(),
				passphraseArg,
				content.NewContent([]byte(oldContentArg)),
			)
			key := acctest.RandomWithPrefix("encrypted_test")

			encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
			require.Nil(t, err)

			oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
			require.Nil(t, err)

			encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
			require.Nil(t, err)

			newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
			require.Nil(t, err)

			category := "terraform"
			sensitive := false

			providerInstance := New("dev")()
			providerFactoriesWithSpy := map[string]func() (*schema.Provider, error){
				"vaultedtfe": func() (*schema.Provider, error) {
					return providerInstance, nil
				},
			}

			// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
			// but still run it as an integration test.
			resource.UnitTest(
				t,
				resource.TestCase{
					PreCheck:          func() { testAccPreCheck(t) },
					ProviderFactories: providerFactoriesWithSpy,
					Steps: []resource.TestStep{
						{
							Config: testResourceVariableConfig(
								key,
								string(oldSerializedEncPayload),
								category,
								sensitive,
							),
							ExpectNonEmptyPlan: false,
							Check: resource.ComposeTestCheckFunc(
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"key",
									key,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"value",
									string(oldSerializedEncPayload),
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"category",
									category,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"sensitive",
									strconv.FormatBool(sensitive),
								),
							),
						},
						{
							Config: testResourceVariableConfig(
								key,
								string(newSerializedEncPayload),
								category,
								sensitive,
							),
							Check: testAccVariableCheckUpdate(
								t,
								providerInstance,
								sensitive,
								// NOTE: No changes
								oldContentArg,
							),
						},
					},
				},
			)

			meta := providerInstance.Meta().(*MetaClient)
			require.Nil(t, err, "failed to create TFE client")
			actualVar, err := meta.TfeClient.Variables.Read(
				context.Background(),
				getTFEworkspaceID(),
				key,
			)
			require.Nil(t, actualVar)
			require.True(
				t,
				strings.Contains(err.Error(), "resource not found"),
				"resource must not exist in TFE",
			)
		},
	)

	t.Run(
		"with applied resource, but deleted externally (via TFE Cloud API directly)"+
			" that has actually the same encrypted content (inside payload), "+
			"it is applied and created, destroyed again",
		func(t *testing.T) {
			osExecutor := &os.RealOsExecutor{}
			rsaSvc := rsa.NewRsaService(osExecutor)

			tmpDir := testutils.TestDir(t, "provider-vaultedtfe")
			testutils.TestChdir(t, tmpDir)

			privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
				t,
				tmpDir,
				"priv.key",
			)

			err := stdOs.Setenv("VAULTED_PRIVATE_KEY_PATH", privkeyPath)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()
			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
			if err != nil {
				log.Fatal(err)
			}

			encPayloadSvc := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				content.NewV1EncryptedContentService(
					b64Svc,
					aes.NewAesService(pkcs7.NewPkcs7Service()),
				),
			)

			contentArg := "mysecret"

			payloadInstance := payload.NewPayload(
				header.NewHeader(),
				passphraseArg,
				content.NewContent([]byte(contentArg)),
			)
			key := acctest.RandomWithPrefix("encrypted_test")

			encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
			require.Nil(t, err)

			serializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
			require.Nil(t, err)

			encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
			require.Nil(t, err)

			category := "terraform"
			sensitive := false

			providerInstance := New("dev")()
			providerFactoriesWithSpy := map[string]func() (*schema.Provider, error){
				"vaultedtfe": func() (*schema.Provider, error) {
					return providerInstance, nil
				},
			}

			var existingVariableResourceID string
			// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
			// but still run it as an integration test.
			resource.UnitTest(
				t,
				resource.TestCase{
					PreCheck:          func() { testAccPreCheck(t) },
					ProviderFactories: providerFactoriesWithSpy,
					Steps: []resource.TestStep{
						{
							Config: testResourceVariableConfig(
								key,
								string(serializedEncPayload),
								category,
								sensitive,
							),
							Destroy: false,
							Check: resource.ComposeTestCheckFunc(
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"key",
									key,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"value",
									string(serializedEncPayload),
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"category",
									category,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"sensitive",
									strconv.FormatBool(sensitive),
								),
								func(state *terraform.State) error {
									resourceState := state.Modules[0].Resources["vaultedtfe_variable.secret"]
									instanceState := resourceState.Primary

									existingVariableResourceID = instanceState.ID
									return nil
								},
							),
						},
						{
							PreConfig: func() {
								meta := providerInstance.Meta().(*MetaClient)
								require.Nil(t, err, "failed to read TFE var")

								err = meta.TfeClient.Variables.Delete(
									context.Background(),
									getTFEworkspaceID(),
									existingVariableResourceID,
								)
								require.Nil(t, err, "failed to delete TFE variable")
							},
							Config: testResourceVariableConfig(
								key,
								string(serializedEncPayload),
								category,
								sensitive,
							),
							Check: resource.ComposeTestCheckFunc(
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"key",
									key,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"value",
									string(serializedEncPayload),
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"category",
									category,
								),
								resource.TestCheckResourceAttr(
									"vaultedtfe_variable.secret",
									"sensitive",
									strconv.FormatBool(sensitive),
								),
							),
						},
					},
				},
			)

			meta := providerInstance.Meta().(*MetaClient)
			require.Nil(t, err, "failed to create TFE client")
			actualVar, err := meta.TfeClient.Variables.Read(
				context.Background(),
				getTFEworkspaceID(),
				key,
			)
			require.Nil(t, actualVar)
			require.True(
				t,
				strings.Contains(err.Error(), "resource not found"),
				"resource must not exist in TFE",
			)
		},
	)
}

func generateRSAprivateKey(t *testing.T) ([]byte, *stdRsa.PrivateKey) {
	privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	), privKey
}

func testResourceVariableConfig(key, value string, category string, sensitive bool) string {
	res := fmt.Sprintf(
		`resource vaultedtfe_variable secret {
	key          = "%s"
	value        = "%s"
	category     = "%s"
	workspace_id = "%s"
	sensitive    = "%t"
}`,
		key,
		value,
		category,
		getTFEworkspaceID(),
		sensitive,
	)
	return res
}
