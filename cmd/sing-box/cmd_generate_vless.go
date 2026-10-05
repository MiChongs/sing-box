package main

import (
	"os"
	"strings"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/vless/encryption"

	"github.com/spf13/cobra"
)

var commandGenerateVLESSEncryption = &cobra.Command{
	Use:   "vless-encryption",
	Short: "Generate VLESS Encryption decryption/encryption pair",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := generateVLESSEncryption()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGenerate.AddCommand(commandGenerateVLESSEncryption)
}

func generateVLESSEncryption() error {
	privateKey, password, err := encryption.GenerateX25519("")
	if err != nil {
		return err
	}
	seed, client, err := encryption.GenerateMLKEM768("")
	if err != nil {
		return err
	}
	os.Stdout.WriteString("Choose one authentication to use, do not mix them. The ephemeral key exchange is post-quantum safe anyway.\n\n")
	os.Stdout.WriteString("Authentication: X25519, not post-quantum\n")
	os.Stdout.WriteString("\"decryption\": \"" + vlessEncryptionValue("600s", privateKey) + "\"\n")
	os.Stdout.WriteString("\"encryption\": \"" + vlessEncryptionValue("0rtt", password) + "\"\n\n")
	os.Stdout.WriteString("Authentication: ML-KEM-768, post-quantum\n")
	os.Stdout.WriteString("\"decryption\": \"" + vlessEncryptionValue("600s", seed) + "\"\n")
	os.Stdout.WriteString("\"encryption\": \"" + vlessEncryptionValue("0rtt", client) + "\"\n")
	return nil
}

func vlessEncryptionValue(rtt string, key string) string {
	return strings.Join([]string{"mlkem768x25519plus", "native", rtt, key}, ".")
}
