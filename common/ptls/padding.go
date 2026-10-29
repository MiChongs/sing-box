package ptls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math"
	"math/big"
	"time"
)

var paddingOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// MinAttachedCertSize 声明一张合法合规的 X.509 ECDSA-P256 证书的物理 DER 字节下限
const MinAttachedCertSize = 510

// lowEntropyCorpus 包含标准 X.509 拓展与权威机构策略的低熵语料，自身香农信息熵约为 4.4~4.6 bit/byte
var lowEntropyCorpus = []byte(
	"http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1.crl" +
		"http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1.crl" +
		"http://ocsp.digicert.com" +
		"http://www.digicert.com/CPS" +
		"DigiCert Assured ID Root CA" +
		"2.16.840.1.114412.1.1" +
		"http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1.crt" +
		"Copyright (c) 2026 Certificate Authority Inc. All Rights Reserved." +
		"Organizational Certificate Policy and Compliance Verification Statement.",
)

type fixedLenECDSASigner struct {
	priv      *ecdsa.PrivateKey
	targetLen int
}

func (s *fixedLenECDSASigner) Public() crypto.PublicKey {
	return s.priv.Public()
}

func (s *fixedLenECDSASigner) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	for i := 0; i < 64; i++ {
		sig, err := ecdsa.SignASN1(randReader, s.priv, digest)
		if err != nil {
			return nil, err
		}
		if len(sig) == s.targetLen {
			return sig, nil
		}
	}
	return s.priv.Sign(randReader, digest, opts)
}

func wrapFixedLenSigner(priv any, targetLen int) any {
	if ecKey, ok := priv.(*ecdsa.PrivateKey); ok {
		if ecKey.Curve != elliptic.P256() {
			return priv
		}
		return &fixedLenECDSASigner{priv: ecKey, targetLen: targetLen}
	}
	return priv
}

// CalculateCombinedEntropy 计算多个字节切片拼接后的联合香农信息熵 (0.0 ~ 8.0 bit/byte)
func CalculateCombinedEntropy(slices ...[]byte) float64 {
	var counts [256]int
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
		for _, b := range s {
			counts[b]++
		}
	}
	if totalLen == 0 {
		return 0
	}
	total := float64(totalLen)
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// CalculateEntropy 计算给定字节切片的香农信息熵 (0.0 ~ 8.0 bit/byte)
func CalculateEntropy(data []byte) float64 {
	return CalculateCombinedEntropy(data)
}

func generateMixedPayload(padLen int, ratio float64) []byte {
	if padLen <= 0 {
		return nil
	}
	payload := make([]byte, padLen)
	if ratio <= 0 {
		for i := 0; i < padLen; i++ {
			payload[i] = lowEntropyCorpus[i%len(lowEntropyCorpus)]
		}
		return payload
	}
	if ratio >= 1.0 {
		_, _ = rand.Read(payload)
		return payload
	}

	randCount := int(float64(padLen) * ratio)
	if randCount > padLen {
		randCount = padLen
	}
	corpusCount := padLen - randCount

	if randCount > 0 {
		_, _ = rand.Read(payload[:randCount])
	}
	for i := 0; i < corpusCount; i++ {
		payload[randCount+i] = lowEntropyCorpus[i%len(lowEntropyCorpus)]
	}
	return payload
}

// PadCertificateDER 采用高低熵双源混合算法对证书进行精确尺寸微调与信息熵调节
func PadCertificateDER(template, parent *x509.Certificate, pub, priv any, targetSize int, targetEntropy float64) ([]byte, error) {
	return padCertificateDERInternal(template, parent, pub, priv, targetSize, targetEntropy, nil)
}

func padCertificateDERInternal(template, parent *x509.Certificate, pub, priv any, targetSize int, targetEntropy float64, prefixDER []byte) ([]byte, error) {
	if template == nil {
		return x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	}

	// 限制在 X.509 ASN.1 物理有效熵区间内，避免二分搜索空转
	if targetEntropy <= 0 {
		targetEntropy = 7.40
	} else if targetEntropy < 5.50 {
		targetEntropy = 5.50
	} else if targetEntropy > 7.85 {
		targetEntropy = 7.85
	}

	// 锁定 ECDSA 签名中位数长度 (71 字节)，消除非对称加密大整数抖动 (非 P-256 原样透传)
	signingPriv := wrapFixedLenSigner(priv, 71)

	// 深度拷贝模板，防止原地修改污染入参指针或引起并发数据竞态
	tpl := *template
	if len(template.ExtraExtensions) > 0 {
		tpl.ExtraExtensions = make([]pkix.Extension, len(template.ExtraExtensions))
		copy(tpl.ExtraExtensions, template.ExtraExtensions)
	} else {
		tpl.ExtraExtensions = nil
	}

	// 测量基准证书精确长度
	baseDER, err := x509.CreateCertificate(rand.Reader, &tpl, parent, pub, signingPriv)
	if err != nil {
		return nil, err
	}

	currentLen := len(baseDER)
	if targetSize <= 0 || currentLen >= targetSize {
		return baseDER, nil
	}

	const padOverhead = 21
	diff := targetSize - currentLen
	if diff < padOverhead {
		return baseDER, nil
	}

	padLen := diff - padOverhead
	baseExtCount := len(template.ExtraExtensions)

	// 1. 闭环反馈微调锁定目标物理尺寸 (带轨迹检测防止 ASN.1 进位阶跃死循环)
	var finalDER []byte
	bestSizeDiff := math.MaxInt
	bestPadLen := padLen
	seenPadLen := make(map[int]bool)

	for attempt := 0; attempt < 10; attempt++ {
		if seenPadLen[padLen] {
			// 检测到 padLen 陷入跨边界往复震荡环路，跳出循环保留离目标最近的解
			break
		}
		seenPadLen[padLen] = true

		payload := generateMixedPayload(padLen, 0.75)
		ext := pkix.Extension{
			Id:       paddingOID,
			Critical: false,
			Value:    payload,
		}
		tpl.ExtraExtensions = append(tpl.ExtraExtensions[:baseExtCount], ext)
		der, err := x509.CreateCertificate(rand.Reader, &tpl, parent, pub, signingPriv)
		if err != nil {
			return nil, err
		}

		sizeDiff := targetSize - len(der)
		absDiff := sizeDiff
		if absDiff < 0 {
			absDiff = -absDiff
		}
		if absDiff < bestSizeDiff {
			bestSizeDiff = absDiff
			bestPadLen = padLen
			finalDER = der
		}

		if sizeDiff == 0 {
			break
		}

		padLen += sizeDiff
		if padLen < 0 {
			padLen = 0
		}
	}

	// 2. 在已锁定的目标尺寸 (bestPadLen) 下，二分搜索寻找最匹配 targetEntropy 的高低熵混合比率
	low := 0.0
	high := 1.0
	bestEntropyDiff := math.MaxFloat64

	for i := 0; i < 8; i++ {
		mid := (low + high) / 2
		payload := generateMixedPayload(bestPadLen, mid)
		ext := pkix.Extension{
			Id:       paddingOID,
			Critical: false,
			Value:    payload,
		}
		tpl.ExtraExtensions = append(tpl.ExtraExtensions[:baseExtCount], ext)
		testDER, err := x509.CreateCertificate(rand.Reader, &tpl, parent, pub, signingPriv)
		if err != nil {
			break
		}
		ent := CalculateCombinedEntropy(prefixDER, testDER)
		entDiff := math.Abs(ent - targetEntropy)

		sizeDiff := targetSize - len(testDER)
		if sizeDiff < 0 {
			sizeDiff = -sizeDiff
		}
		if sizeDiff <= bestSizeDiff && entDiff < bestEntropyDiff {
			bestEntropyDiff = entDiff
			finalDER = testDER
			bestSizeDiff = sizeDiff
		}

		if ent < targetEntropy {
			low = mid
		} else {
			high = mid
		}
	}

	return finalDER, nil
}

// GenerateAttachedCertificate 生成作为尺寸与信息熵补偿垫片的独立附加证书
func GenerateAttachedCertificate(parent *x509.Certificate, parentPriv any, targetSize int, targetEntropy float64, prefixDER ...[]byte) ([]byte, error) {
	if targetSize < MinAttachedCertSize {
		targetSize = MinAttachedCertSize
	}

	attachedPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	commonName := "Internal Authority Intermediate CA"
	if parent != nil && parent.Subject.CommonName != "" {
		commonName = parent.Subject.CommonName + " G2"
	}
	var org []string
	if parent != nil && len(parent.Subject.Organization) > 0 {
		org = parent.Subject.Organization
	} else {
		org = []string{"Private Trust Infrastructure"}
	}

	notAfter := time.Now().Add(365 * 24 * time.Hour)
	if parent != nil && !parent.NotAfter.IsZero() {
		notAfter = parent.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: org,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	signingParent := parent
	signingPriv := parentPriv
	if signingParent == nil || signingPriv == nil {
		signingParent = tmpl
		signingPriv = attachedPriv
	}

	var prefix []byte
	if len(prefixDER) == 1 {
		prefix = prefixDER[0]
	} else if len(prefixDER) > 1 {
		for _, p := range prefixDER {
			prefix = append(prefix, p...)
		}
	}

	return padCertificateDERInternal(tmpl, signingParent, &attachedPriv.PublicKey, signingPriv, targetSize, targetEntropy, prefix)
}