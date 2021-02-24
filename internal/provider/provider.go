package provider

import (
	"context"
	stdRsa "crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-tfe"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

type MetaClient struct {
	TfeClient         *tfe.Client
	VaultedPrivateKey *stdRsa.PrivateKey
}

func init() {
	// Set descriptions to support markdown syntax, this will be used in document generation
	// and the language server.
	schema.DescriptionKind = schema.StringMarkdown

	// Customize the content of descriptions when output. For example you can add defaults on
	// to the exported descriptions if present.
	// schema.SchemaDescriptionBuilder = func(s *schema.Schema) string {
	// 	desc := s.Description
	// 	if s.Default != nil {
	// 		desc += fmt.Sprintf(" Defaults to `%v`.", s.Default)
	// 	}
	// 	return strings.TrimSpace(desc)
	// }
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"protocol": {
					Type:     schema.TypeString,
					Optional: true,
					Description: "Protocol to use when connecting to specified `hostname` Terraform Enterprise. " +
						"Defaults to https",
					DefaultFunc: schema.EnvDefaultFunc("TFE_PROTOCOL", "https"),
				},
				"hostname": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "The Terraform Enterprise hostname to connect to. Defaults to app.terraform.io.",
					DefaultFunc: schema.EnvDefaultFunc("TFE_HOSTNAME", "app.terraform.io"),
				},
				"token": {
					Type:        schema.TypeString,
					Required:    true,
					Description: "The token used to authenticate with Terraform Cloud/Enterprise.",
					DefaultFunc: schema.EnvDefaultFunc("TFE_TOKEN", nil),
				},
				"ssl_skip_verify": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "Whether or not to skip certificate verifications.",
					DefaultFunc: schema.EnvDefaultFunc("TFE_SSL_SKIP_VERIFY", false),
				},
				"private_key_content": {
					Type:        schema.TypeString,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("VAULTED_PRIVATE_KEY_CONTENT", ""),
					Description: "Content of private key used to decrypt `vaultedtfe_variable` resources. " +
						"This setting has higher priority than `private_key_path`.",
				},
				"private_key_path": {
					Type:        schema.TypeString,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("VAULTED_PRIVATE_KEY_PATH", ""),
					Description: "Path to private key used to decrypt `vaultedtfe_variable` resources. " +
						"This setting has lower priority than `private_key_content`.",
				},
			},
			ResourcesMap: map[string]*schema.Resource{
				// NOTE: Ideally would be called `vaultedtfe_variable`,
				// but try to skip to TFE terminology,
				// since HashiCorp might introduce their version of secrets at some point.
				"vaultedtfe_variable": resourceVariable(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

func configure(
	version string,
	p *schema.Provider,
) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		osExecutor := &os.RealOsExecutor{}
		rsaSvc := rsa.NewRsaService(osExecutor)

		privateKey, err := readPrivateKey(d, osExecutor, rsaSvc)
		if err != nil {
			return nil, diag.FromErr(err)
		}

		cfg := tfe.DefaultConfig()
		cfg.Address = d.Get("hostname").(string)
		protocol := d.Get("protocol").(string)
		cfg.Address = fmt.Sprintf("%s://%s", protocol, cfg.Address)
		cfg.Token = d.Get("token").(string)
		httpClient := cfg.HTTPClient
		transport := httpClient.Transport.(*http.Transport)
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = d.Get("ssl_skip_verify").(bool)

		httpHeaders := http.Header{}
		httpHeaders.Add("User-Agent", p.UserAgent("terraform-provider-vaultedtfe", version))
		cfg.Headers = httpHeaders

		client, err := tfe.NewClient(cfg)
		if err != nil {
			return nil, diag.FromErr(err)
		}

		client.RetryServerErrors(false)

		return &MetaClient{
			TfeClient:         client,
			VaultedPrivateKey: privateKey,
		}, nil
	}
}

func readPrivateKey(
	d *schema.ResourceData,
	osExecutor os.OsExecutor,
	rsaSvc *rsa.Service,
) (*stdRsa.PrivateKey, error) {
	var privateKey *stdRsa.PrivateKey

	privateKeyContentTypeless := d.Get("private_key_content")
	switch privateKeyContent := privateKeyContentTypeless.(type) {
	case string:
		if privateKeyContent != "" {
			fd, nestedErr := osExecutor.TempFile("", "vaulted-private-key-from-content")
			if nestedErr != nil {
				return nil, fmt.Errorf("failed to create temporary file for vaulted private key from content: %s", nestedErr)
			}

			_, nestedErr = fd.WriteString(privateKeyContent)
			if nestedErr != nil {
				return nil, fmt.Errorf(
					"failed to write private key content to temporary file for vaulted private key: %s",
					nestedErr,
				)
			}

			nestedErr = fd.Sync()
			if nestedErr != nil {
				return nil, fmt.Errorf(
					"failed to sync private key content to temporary file for vaulted private key: %s",
					nestedErr,
				)
			}

			nestedErr = fd.Close()
			if nestedErr != nil {
				return nil, fmt.Errorf("failed to close temporary file for vaulted private key from content: %s", nestedErr)
			}

			key, readErr := rsaSvc.ReadPrivateKeyFromPath(fd.Name())
			if readErr != nil {
				return nil, readErr
			}

			privateKey = key

			// NOTE: Clean up the private key from the disk
			nestedErr = osExecutor.Remove(fd.Name())
			if nestedErr != nil {
				return nil, fmt.Errorf("failed to remove temporary file for vaulted private key from content: %s", nestedErr)
			}
		}
	default: // NOTE: Do nothing, try with `private_key_path`.
	}

	if privateKey == nil {
		privateKeyPathTypeless := d.Get("private_key_path")
		switch privateKeyPath := privateKeyPathTypeless.(type) {
		case string:
			if privateKeyPath != "" {
				key, readErr := rsaSvc.ReadPrivateKeyFromPath(privateKeyPath)
				if readErr != nil {
					return nil, fmt.Errorf("failed to read private key from path %s, err: %s", privateKeyPath, readErr)
				}

				privateKey = key
			}
		default:
			return nil, fmt.Errorf("non-string private_key_path. actual: %#v", privateKeyPath)
		}
	}

	if privateKey == nil {
		return nil, errors.New(
			"failed to read RSA private key from either `private_key_content` or" +
				" `private_key_path` provider attributes",
		)
	}

	return privateKey, nil
}
