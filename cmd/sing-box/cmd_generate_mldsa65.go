package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/spf13/cobra"
)

var commandGenerateMLDSA65Seed string

func init() {
	commandGenerateMLDSA65.Flags().StringVarP(&commandGenerateMLDSA65Seed, "input", "i", "", "derive the verify key from an existing seed")
	commandGenerate.AddCommand(commandGenerateMLDSA65)
}

var commandGenerateMLDSA65 = &cobra.Command{
	Use:   "mldsa65",
	Short: "Generate ML-DSA-65 seed and verify key for REALITY",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := generateMLDSA65(commandGenerateMLDSA65Seed)
		if err != nil {
			log.Fatal(err)
		}
	},
}

// generateMLDSA65 输出与 xray mldsa65 相同格式的 Seed（服务端 mldsa65_seed）与
// Verify（客户端 mldsa65_verify）。
func generateMLDSA65(input string) error {
	var seed [mldsa65.SeedSize]byte
	if input != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(input)
		if err != nil {
			return E.Cause(err, "decode seed")
		}
		if len(decoded) != mldsa65.SeedSize {
			return E.New("invalid seed length: expected ", mldsa65.SeedSize, " bytes, got ", len(decoded))
		}
		copy(seed[:], decoded)
	} else {
		_, err := rand.Read(seed[:])
		if err != nil {
			return err
		}
	}
	publicKey, _ := mldsa65.NewKeyFromSeed(&seed)
	verify, err := publicKey.MarshalBinary()
	if err != nil {
		return err
	}
	os.Stdout.WriteString("Seed: " + base64.RawURLEncoding.EncodeToString(seed[:]) + "\n")
	os.Stdout.WriteString("Verify: " + base64.RawURLEncoding.EncodeToString(verify) + "\n")
	return nil
}
