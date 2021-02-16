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
