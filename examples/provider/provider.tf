provider "vaulted-tfe" {
  # Preferably set via `TFE_TOKEN` environment variable
  # token = ""
  # Generate using `github.com/sumup-oss/vaulted`
  private_key_path = "./vaultedtfe.key"
}
