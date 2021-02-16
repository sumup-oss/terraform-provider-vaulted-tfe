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
	stdRsa "crypto/rsa"
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/go-tfe"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

const (
	defaultDescription = "Managed by github.com/sumup-oss/terraform-provider-vaulted-tfe"
)

func resourceVariable() *schema.Resource {
	return &schema.Resource{
		Description: "Creates/updates/destroys TFE Cloud variables. To read variables or provision non-sensitive ones, " +
			"use the official TFE provider https://registry.terraform.io/providers/hashicorp/tfe/latest",
		CreateContext: resourceVariableCreate,
		ReadContext:   resourceVariableRead,
		UpdateContext: resourceVariableUpdate,
		DeleteContext: resourceVariableDelete,
		SchemaVersion: 1,
		Schema: map[string]*schema.Schema{
			"key": {
				Type:     schema.TypeString,
				Required: true,
			},
			"value": {
				Type: schema.TypeString,
				// NOTE: It's impractical for this provider to be used w/o values.
				// If users want to create place-holders, it's better to use the official `tfe_variable`.
				Required:    true,
				Sensitive:   true,
				Description: "Encrypted value by github.com/sumup-oss/vaulted",
				ForceNew:    true,
			},
			"sensitive": {
				Type:     schema.TypeBool,
				Optional: true,
				// NOTE: By default it's a good idea to have your encrypted variables committed in SCM as `sensitive=true`.
				// However if you want you can make them non-sensitive so that you can detect drift (or debug) between
				// manual changes in TFE UI and local infrastructure as code Terraform.
				Default: true,
			},
			"category": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice(
					[]string{
						string(tfe.CategoryEnv),
						string(tfe.CategoryTerraform),
					},
					false,
				),
				Description: "Terraform environment variable or environment variable to be provisioned in TFE. " +
					"Valid values are either `terraform` or `env`.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     defaultDescription,
				Description: "Description of the variable that'll be provisioned in TFE",
			},
			// NOTE: Is supporting HCL very practical for this provider?
			// We will encrypt the plaintext HCL and store it encrypted in state.
			"hcl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to evaluate the value of the variable as a string of HCL code. Has no effect for environment variables.",
			},
			"workspace_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the workspace that owns the variable.",
			},
		},
		CustomizeDiff: customdiff.ForceNewIf(
			"key",
			func(_ context.Context, d *schema.ResourceDiff, m interface{}) bool {
				return d.Get("sensitive").(bool)
			},
		),
	}
}

func resourceVariableCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// nolint:forcetypeassert
	metaClient := meta.(*MetaClient)
	key := d.Get("key").(string)
	category := d.Get("category").(string)

	ws, err := getWorkspace(ctx, metaClient.TfeClient, d)
	if err != nil {
		return diag.FromErr(err)
	}

	encryptedValue, ok := d.Get("value").(string)
	if !ok {
		// nolint:goerr113
		err = fmt.Errorf(
			"non-string value for `value` at %s. Actual: %#v",
			key,
			d.Get("value"),
		)

		return diag.FromErr(err)
	}

	plaintextValue, err := decryptValue(metaClient.VaultedPrivateKey, key, encryptedValue)
	if err != nil {
		return diag.FromErr(err)
	}

	options := tfe.VariableCreateOptions{
		Key:         tfe.String(key),
		Value:       tfe.String(plaintextValue),
		Category:    tfe.Category(tfe.CategoryType(category)),
		HCL:         tfe.Bool(d.Get("hcl").(bool)),
		Sensitive:   tfe.Bool(d.Get("sensitive").(bool)),
		Description: tfe.String(d.Get("description").(string)),
	}

	log.Printf("[DEBUG] Create %s variable: %s", category, key)

	variable, err := metaClient.TfeClient.Variables.Create(ctx, ws.ID, options)
	if err != nil {
		err = fmt.Errorf("error creating %s variable %s: %w", category, key, err)
		return diag.FromErr(err)
	}

	d.SetId(variable.ID)

	return resourceVariableRead(ctx, d, meta)
}

func resourceVariableRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	metaClient := meta.(*MetaClient)

	encryptedValue, ok := d.Get("value").(string)
	if !ok {
		// nolint:goerr113
		err := fmt.Errorf(
			"non-string value for `value` at %s. Actual: %#v",
			d.Id(),
			d.Get("value"),
		)

		return diag.FromErr(err)
	}

	key := d.Get("key").(string)

	plaintextValue, err := decryptValue(metaClient.VaultedPrivateKey, key, encryptedValue)
	if err != nil {
		return diag.FromErr(err)
	}

	ws, err := getWorkspace(ctx, metaClient.TfeClient, d)
	if err != nil {
		if errors.Is(err, tfe.ErrResourceNotFound) {
			log.Printf("[DEBUG] Workspace %s no longer exists", d.Get("workspace_id"))
			d.SetId("")

			return nil
		}

		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Read variable: %s", d.Id())

	variable, err := metaClient.TfeClient.Variables.Read(ctx, ws.ID, d.Id())
	if err != nil {
		if errors.Is(err, tfe.ErrResourceNotFound) {
			log.Printf("[DEBUG] Variable %s does no longer exist", d.Id())
			d.SetId("")

			return nil
		}

		err = fmt.Errorf("error reading variable %s: %w", d.Id(), err)

		return diag.FromErr(err)
	}

	_ = d.Set("key", variable.Key)
	_ = d.Set("category", string(variable.Category))
	_ = d.Set("description", variable.Description)
	_ = d.Set("hcl", variable.HCL)

	if !variable.Sensitive {
		if plaintextValue != variable.Value {
			log.Printf("[DEBUG] plaintext `value` difference for variable: %s", d.Id())
			_ = d.Set("value", "")

			return nil
		}
	}

	return nil
}

func resourceVariableUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	metaClient := meta.(*MetaClient)

	encryptedValue, ok := d.Get("value").(string)
	if !ok {
		// nolint:goerr113
		err := fmt.Errorf(
			"non-string value for `value` at %s. Actual: %#v",
			d.Id(),
			d.Get("value"),
		)

		return diag.FromErr(err)
	}

	key := d.Get("key").(string)

	plaintextValue, err := decryptValue(metaClient.VaultedPrivateKey, key, encryptedValue)
	if err != nil {
		return diag.FromErr(err)
	}

	ws, err := getWorkspace(ctx, metaClient.TfeClient, d)
	if err != nil {
		return diag.FromErr(err)
	}

	options := tfe.VariableUpdateOptions{
		Key:   tfe.String(d.Get("key").(string)),
		Value: tfe.String(plaintextValue),
		HCL:   tfe.Bool(d.Get("hcl").(bool)),
		// NOTE: Since this resource is about encrypting values and not storing them plaintext in state,
		// avoid having the values in plaintext web UI.
		Sensitive:   tfe.Bool(true),
		Description: tfe.String(d.Get("description").(string)),
	}

	log.Printf("[DEBUG] Update variable: %s", d.Id())

	_, err = metaClient.TfeClient.Variables.Update(ctx, ws.ID, d.Id(), options)
	if err != nil {
		err = fmt.Errorf("error updating variable %s: %w", d.Id(), err)
		return diag.FromErr(err)
	}

	return resourceVariableRead(ctx, d, meta)
}

func resourceVariableDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	metaClient := meta.(*MetaClient)

	ws, err := getWorkspace(ctx, metaClient.TfeClient, d)
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Delete variable: %s", d.Id())

	err = metaClient.TfeClient.Variables.Delete(ctx, ws.ID, d.Id())
	if err != nil {
		if errors.Is(err, tfe.ErrResourceNotFound) {
			log.Printf("[DEBUG] Variable %s does no longer exist", d.Id())
			return nil
		}

		err = fmt.Errorf("error deleting variable%s: %w", d.Id(), err)

		return diag.FromErr(err)
	}

	return nil
}

func getWorkspace(ctx context.Context, tfeClient *tfe.Client, d *schema.ResourceData) (*tfe.Workspace, error) {
	workspaceID := d.Get("workspace_id").(string)

	ws, err := tfeClient.Workspaces.ReadByID(ctx, workspaceID)
	if err != nil {
		err = fmt.Errorf("error retrieving workspace %s: %w", workspaceID, err)
		return nil, err
	}

	return ws, nil
}

func decryptValue(privateKey *stdRsa.PrivateKey, key, encryptedValue string) (string, error) {
	osExecutor := &os.RealOsExecutor{}
	b64Svc := base64.NewBase64Service()
	rsaSvc := rsa.NewRsaService(osExecutor)
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

	encPayloadSvc := payload.NewEncryptedPayloadService(
		header.NewHeaderService(),
		passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc),
		content.NewV1EncryptedContentService(b64Svc, aesSvc),
	)

	deserializedValue, err := encPayloadSvc.Deserialize([]byte(encryptedValue))
	if err != nil {
		return "", fmt.Errorf("unable to deserialize `value` at %s. Err: %w", key, err)
	}

	decryptedValue, err := encPayloadSvc.Decrypt(privateKey, deserializedValue)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt `value` at %s. Err: %w", key, err)
	}

	return string(decryptedValue.Content.Plaintext), nil
}
