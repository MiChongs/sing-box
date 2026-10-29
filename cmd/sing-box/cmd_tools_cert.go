package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/ptls"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/spf13/cobra"
)

var (
	toolsCertSNI     string
	toolsCertTimeout time.Duration
	toolsCertMode    string
)

var commandToolsCert = &cobra.Command{
	Use:     "inspect-cert <host[:port]> [sni]",
	Aliases: []string{"fetch-cert"},
	Short:   "Fetch remote TLS/QUIC certificate chain and output DER/PEM sizes and Shannon entropy",
	Args:    cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		var sni string
		if len(args) > 1 {
			sni = args[1]
		}
		err := runInspectCert(args[0], sni)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandToolsCert.Flags().StringVarP(&toolsCertSNI, "sni", "s", "", "Server Name Indication (defaults to target host)")
	commandToolsCert.Flags().DurationVar(&toolsCertTimeout, "timeout", 10*time.Second, "Handshake timeout")
	commandToolsCert.Flags().StringVarP(&toolsCertMode, "mode", "m", "tcp", "Transport mode: tcp (TLS) or udp (QUIC)")

	commandTools.AddCommand(commandToolsCert)
}

func runInspectCert(target string, customSNI string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = strings.Trim(target, "[]")
		portStr = "443"
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return E.Cause(err, "parse port")
	}

	sni := customSNI
	if sni == "" {
		sni = toolsCertSNI
	}
	if sni == "" {
		sni = host
	}

	ctx, cancel := context.WithTimeout(globalCtx, toolsCertTimeout)
	defer cancel()

	var (
		certs      []*x509.Certificate
		versionStr string
	)

	mode := strings.ToLower(toolsCertMode)
	switch mode {
	case "tcp", "":
		certs, versionStr, err = inspectCertTCP(ctx, host, portStr, port, sni)
	case "udp", "quic":
		certs, versionStr, err = inspectCertQUIC(ctx, host, portStr, port, sni)
	default:
		return E.New("unsupported mode: ", toolsCertMode, " (expected tcp or udp)")
	}
	if err != nil {
		return err
	}

	if len(certs) == 0 {
		return E.New("no peer certificates returned")
	}

	// 1. 统计单张叶子证书尺寸与信息熵
	leafRaw := certs[0].Raw
	leafDERSize := len(leafRaw)
	leafPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafRaw})
	leafPEMSize := len(leafPEMBytes)
	leafEntropy := ptls.CalculateEntropy(leafRaw)

	// 2. 统计整条证书链尺寸与信息熵
	var totalDERBytes []byte
	chainDERSize := 0
	chainPEMSize := 0

	for _, cert := range certs {
		chainDERSize += len(cert.Raw)
		totalDERBytes = append(totalDERBytes, cert.Raw...)
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		chainPEMSize += len(pemBlock)
	}
	chainEntropy := ptls.CalculateEntropy(totalDERBytes)

	// 3. 提取证书元数据与公钥类型合规检查
	subjectCN := certs[0].Subject.CommonName
	issuerCN := certs[0].Issuer.CommonName
	sanList := certs[0].DNSNames
	sanStr := "N/A"
	if len(sanList) > 0 {
		sanStr = strings.Join(sanList, ", ")
	}

	var (
		keyTypeStr         string
		leafTypeConfig     string
		unsupportedWarning string
	)
	switch pub := certs[0].PublicKey.(type) {
	case *ecdsa.PublicKey:
		curveName := pub.Curve.Params().Name
		keyTypeStr = fmt.Sprintf("ECDSA (%s)", curveName)
		if curveName == "P-256" {
			leafTypeConfig = "ecdsa"
		} else {
			unsupportedWarning = fmt.Sprintf("Target certificate uses %s. PTLS only supports ECDSA (P-256) and RSA (2048-bit) for zero-byte wire mimicry. Please switch to another camouflage target.", keyTypeStr)
		}
	case *rsa.PublicKey:
		bits := pub.Size() * 8
		keyTypeStr = fmt.Sprintf("RSA (%d-bit)", bits)
		if bits == 2048 {
			leafTypeConfig = "rsa"
		} else {
			unsupportedWarning = fmt.Sprintf("Target certificate uses %s. PTLS only supports RSA (2048-bit) and ECDSA (P-256) for zero-byte wire mimicry. Please switch to another camouflage target.", keyTypeStr)
		}
	default:
		keyTypeStr = "Unknown"
		unsupportedWarning = "Target certificate uses an unsupported public key algorithm. PTLS only supports ECDSA (P-256) and RSA (2048-bit) for zero-byte wire mimicry. Please switch to another camouflage target."
	}

	// 4. 格式化输出审计报告与 PTLS 配置片段
	var out strings.Builder
	out.WriteString("\n================================================================================\n")
	out.WriteString(fmt.Sprintf(" Target Endpoint:    %s:%d [%s]\n", host, port, strings.ToUpper(mode)))
	out.WriteString(fmt.Sprintf(" Handshake SNI:      %s\n", sni))
	out.WriteString(fmt.Sprintf(" Negotiated Version: %s\n", versionStr))
	out.WriteString(fmt.Sprintf(" Certificate Chain:  %d certificate(s)\n", len(certs)))
	out.WriteString("================================================================================\n\n")

	out.WriteString("[Leaf Certificate (certs[0])]\n")
	out.WriteString(fmt.Sprintf("  CommonName (CN):   %s\n", subjectCN))
	out.WriteString(fmt.Sprintf("  Issuer:            %s\n", issuerCN))
	out.WriteString(fmt.Sprintf("  Public Key:        %s\n", keyTypeStr))
	out.WriteString(fmt.Sprintf("  DNS Names (SAN):   %s\n", sanStr))
	out.WriteString(fmt.Sprintf("  DER Physical Size: %d bytes\n", leafDERSize))
	out.WriteString(fmt.Sprintf("  PEM Encoded Size:  %d bytes\n", leafPEMSize))
	out.WriteString(fmt.Sprintf("  Shannon Entropy:   %.4f bit/byte\n\n", leafEntropy))

	for i := 1; i < len(certs); i++ {
		cRaw := certs[i].Raw
		cDERSize := len(cRaw)
		cPEMSize := len(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cRaw}))
		cEntropy := ptls.CalculateEntropy(cRaw)
		out.WriteString(fmt.Sprintf("[Certificate [%d]]\n", i))
		out.WriteString(fmt.Sprintf("  CommonName (CN):   %s\n", certs[i].Subject.CommonName))
		out.WriteString(fmt.Sprintf("  Issuer:            %s\n", certs[i].Issuer.CommonName))
		out.WriteString(fmt.Sprintf("  DER Physical Size: %d bytes\n", cDERSize))
		out.WriteString(fmt.Sprintf("  PEM Encoded Size:  %d bytes\n", cPEMSize))
		out.WriteString(fmt.Sprintf("  Shannon Entropy:   %.4f bit/byte\n\n", cEntropy))
	}

	out.WriteString("[Full Certificate Chain Summary]\n")
	out.WriteString(fmt.Sprintf("  Total DER Size:    %d bytes\n", chainDERSize))
	out.WriteString(fmt.Sprintf("  Total PEM Size:    %d bytes\n", chainPEMSize))
	out.WriteString(fmt.Sprintf("  Combined Entropy:  %.4f bit/byte\n\n", chainEntropy))

	if unsupportedWarning != "" {
		out.WriteString("================================================================================\n")
		out.WriteString("[WARNING: INCOMPATIBLE TARGET CERTIFICATE ALGORITHM]\n")
		out.WriteString("================================================================================\n")
		out.WriteString(fmt.Sprintf("  %s\n", unsupportedWarning))
		out.WriteString("================================================================================\n\n")
	}

	out.WriteString("================================================================================\n")
	out.WriteString("[Recommended PTLS Configuration Snippet]\n")
	out.WriteString("================================================================================\n")
	if leafTypeConfig != "" {
		out.WriteString(fmt.Sprintf("  \"leaf_type\":       \"%s\",\n", leafTypeConfig))
	} else {
		out.WriteString("  // WARNING: Incompatible target algorithm. Please switch to a P-256 or RSA-2048 target.\n")
	}
	out.WriteString(fmt.Sprintf("  \"leaf_der_size\":   %d,\n", leafDERSize))
	out.WriteString(fmt.Sprintf("  \"chain_der_size\":  %d,\n", chainDERSize))
	out.WriteString(fmt.Sprintf("  \"target_entropy\":  %.2f\n", chainEntropy))
	out.WriteString("================================================================================\n\n")

	_, err = os.Stdout.WriteString(out.String())
	return err
}

func inspectCertTCP(ctx context.Context, host string, portStr string, port uint64, sni string) ([]*x509.Certificate, string, error) {
	var (
		rawConn net.Conn
		err     error
	)
	if commandToolsFlagOutbound != "" {
		instance, err := createPreStartedClient()
		if err != nil {
			return nil, "", err
		}
		defer instance.Close()
		dialer, err := createDialer(instance, commandToolsFlagOutbound)
		if err != nil {
			return nil, "", err
		}
		rawConn, err = dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort(host, uint16(port)))
		if err != nil {
			return nil, "", E.Cause(err, "dial outbound ", commandToolsFlagOutbound)
		}
	} else {
		instance, err := createPreStartedClient()
		if err == nil {
			defer instance.Close()
			dialer, err := createDialer(instance, "")
			if err == nil {
				rawConn, _ = dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort(host, uint16(port)))
			}
		}
		if rawConn == nil {
			dialer := &net.Dialer{Timeout: toolsCertTimeout}
			rawConn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, portStr))
			if err != nil {
				return nil, "", E.Cause(err, "dial tcp")
			}
		}
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()

	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return nil, "", E.Cause(err, "tls handshake")
	}

	state := tlsConn.ConnectionState()
	versionStr := "TLS 1.2"
	if state.Version == tls.VersionTLS13 {
		versionStr = "TLS 1.3"
	}
	return state.PeerCertificates, versionStr, nil
}