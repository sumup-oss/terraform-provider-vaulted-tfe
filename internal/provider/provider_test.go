package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var providerFactories = map[string]func() (*schema.Provider, error){
	"vaultedtfe": func() (*schema.Provider, error) {
		return New("dev")(), nil
	},
}

func TestNew(t *testing.T) {
	err := New("dev")().InternalValidate()
	require.Nil(t, err)
}

func TestProvider(t *testing.T) {
	t.Run(
		"it has resource `vaultedtfe_variable",
		func(t *testing.T) {
			t.Parallel()
			providerInstance := New("dev")()

			actual := providerInstance.Resources()
			assert.Equal(t, 1, len(actual))
			assert.Equal(t, "vaultedtfe_variable", actual[0].Name)
			assert.True(t, actual[0].SchemaAvailable)
		},
	)
}

func testAccPreCheck(t *testing.T) {
	for _, v := range []string{"TFE_TEST_WORKSPACE_ID", "TFE_TOKEN"} {
		envVar := os.Getenv(v)
		if envVar == "" {
			t.Fatalf("%s must be set for acceptance tests\n", v)
		}
	}
}
