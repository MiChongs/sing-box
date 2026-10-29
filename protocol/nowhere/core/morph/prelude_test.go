package morph

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/chacha20"
)

func TestFixedPreludeVectors(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	for _, tc := range []struct {
		name, prefix, nonce, high, tail string
		identity, counter               uint64
	}{
		{
			name:     "reference",
			prefix:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			nonce:    "000102030405060708090a0b",
			high:     "f00faa55",
			identity: 0x0123456789abcdef,
			counter:  1,
			tail:     "898f9c840e570537225e187fb7e4c990df489547d61b9e515bad2a8f4dd84d86",
		},
		{
			name:     "all-ff",
			prefix:   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			nonce:    "ffffffffffffffffffffffff",
			high:     "ffffffff",
			identity: 0xffffffffffffffff,
			counter:  maxCounter,
			tail:     "b2eac9c5c3fcb0e5a3f3a7c8febed9bca7aec3a1c4b0a3a5cf879c8edf8ffce8",
		},
		{
			name:     "all-zero",
			prefix:   "0000000000000000000000000000000000000000000000000000000000000000",
			nonce:    "000000000000000000000000",
			high:     "00000000",
			identity: 0,
			counter:  0,
			tail:     "245b016f7d7e2b4c125f3e33445f0d2a103f225860664d0c7465093120367212",
		},
		{
			name:     "mixed-boundary",
			prefix:   "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
			nonce:    "0b0a09080706050403020100",
			high:     "80000001",
			identity: 0x8000000000000001,
			counter:  0x800000000001,
			tail:     "b57508160f6c2d312c50315572780903206a301662675c472f676d701b032ab8",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prelude := preludeWithHighBits(t, tc.prefix, tc.high)
			nonce := decodeHex(t, tc.nonce)
			if err := EncodeTCPPrelude(keys, prelude, nonce, tc.identity, tc.counter); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(prelude[32:]) != tc.tail {
				t.Fatalf("tail %x", prelude[32:])
			}
			gotID, gotCounter, ok := DecodeTCPPrelude(keys, prelude, nonce)
			if !ok || gotID != tc.identity || gotCounter != tc.counter {
				t.Fatalf("decode id=%x counter=%d ok=%v", gotID, gotCounter, ok)
			}
			wrong := Derive([]byte("0123456789abcdef0123456789abcdee"))
			if _, _, ok := DecodeTCPPrelude(wrong, prelude, nonce); ok {
				t.Fatal("wrong shared key matched")
			}
		})
	}
}

func TestPreludeRoundTripPreservesHighBits(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	for _, policy := range []preludePolicy{preludeFade, preludeFull8, preludeLow7} {
		original, err := generatePrelude(policy)
		if err != nil {
			t.Fatal(err)
		}
		prelude := append([]byte(nil), original[:]...)
		var nonce [nonceLen]byte
		if err := readEntropy(nonce[:]); err != nil {
			t.Fatal(err)
		}
		if err := EncodeTCPPrelude(keys, prelude, nonce[:], 0x1122334455667788, 0x010203040506); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(prelude[:32], original[:32]) {
			t.Fatal("prefix changed")
		}
		for i := range prelude {
			if prelude[i]&0x80 != original[i]&0x80 {
				t.Fatalf("policy %d high bit %d changed", policy, i)
			}
		}
		id, counter, ok := DecodeTCPPrelude(keys, prelude, nonce[:])
		if !ok || id != 0x1122334455667788 || counter != 0x010203040506 {
			t.Fatalf("policy %d decode id=%x counter=%d ok=%v", policy, id, counter, ok)
		}
	}
}

func TestEveryPreludeAndNonceBitIsAuthenticated(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	prelude := preludeWithHighBits(t,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"f00faa55")
	nonce := decodeHex(t, "000102030405060708090a0b")
	if err := EncodeTCPPrelude(keys, prelude, nonce, 0x0123456789abcdef, 1); err != nil {
		t.Fatal(err)
	}
	originalPrelude := append([]byte(nil), prelude...)
	originalNonce := append([]byte(nil), nonce...)
	for i := range originalPrelude {
		for bit := 0; bit < 8; bit++ {
			mutated := append([]byte(nil), originalPrelude...)
			mutated[i] ^= 1 << bit
			if _, _, ok := DecodeTCPPrelude(keys, mutated, originalNonce); ok {
				t.Fatalf("prelude byte %d bit %d still verified", i, bit)
			}
		}
	}
	for i := range originalNonce {
		for bit := 0; bit < 8; bit++ {
			mutated := append([]byte(nil), originalNonce...)
			mutated[i] ^= 1 << bit
			if _, _, ok := DecodeTCPPrelude(keys, originalPrelude, mutated); ok {
				t.Fatalf("nonce byte %d bit %d still verified", i, bit)
			}
		}
	}
}

func TestWrappedConnectionsShareIdentity(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	first := capturePrelude(t, keys)
	second := capturePrelude(t, keys)
	id1, c1, ok := DecodeTCPPrelude(keys, first.prelude, first.nonce)
	id2, c2, ok2 := DecodeTCPPrelude(keys, second.prelude, second.nonce)
	if !ok || !ok2 || id1 != id2 || c1 != 1 || c2 != 2 {
		t.Fatalf("id %x/%x counters %d/%d ok %v/%v", id1, id2, c1, c2, ok, ok2)
	}
	other := Derive([]byte("0123456789abcdef0123456789abcdef"))
	third := capturePrelude(t, other)
	id3, c3, ok := DecodeTCPPrelude(other, third.prelude, third.nonce)
	if !ok || id3 == id1 || c3 != 1 {
		t.Fatalf("second vector id=%x counter=%d ok=%v", id3, c3, ok)
	}
}

func TestCounterExhaustionAndFailedUse(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	keys.state.ctr.Store(maxCounter - 1)
	one := capturePrelude(t, keys)
	if _, counter, ok := DecodeTCPPrelude(keys, one.prelude, one.nonce); !ok || counter != maxCounter {
		t.Fatalf("last counter %d ok %v", counter, ok)
	}
	if _, err := WrapTCPClient(nil, keys); !errors.Is(err, errCounterExhausted) {
		t.Fatalf("exhaustion: %v", err)
	}
	if keys.state.ctr.Load() != maxCounter {
		t.Fatalf("counter changed after exhaustion: %d", keys.state.ctr.Load())
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	keys.state.ctr.Store(maxCounter - 1)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := keys.state.allocate(); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("last allocation winners = %d", wins.Load())
	}

	fresh := Derive([]byte("0123456789abcdef0123456789abcdef"))
	if _, _, err := fresh.state.allocate(); err != nil {
		t.Fatal(err)
	}
	entropyMu.Lock()
	previous := entropy
	entropy = failEntropy{}
	entropyMu.Unlock()
	_, err := WrapTCPClient(nil, fresh)
	entropyMu.Lock()
	entropy = previous
	entropyMu.Unlock()
	if err == nil {
		t.Fatal("expected entropy failure")
	}
	if fresh.state.ctr.Load() != 2 {
		t.Fatalf("failed bootstrap consumed counter %d, want 2", fresh.state.ctr.Load())
	}
	if _, counter, err := fresh.state.allocate(); err != nil || counter != 3 {
		t.Fatalf("next counter %d err %v", counter, err)
	}

	blocked := Derive([]byte("fedcba9876543210fedcba9876543210"))
	entropyMu.Lock()
	entropy = failEntropy{}
	entropyMu.Unlock()
	_, err = WrapTCPClient(nil, blocked)
	_, errAgain := WrapTCPClient(nil, blocked)
	entropyMu.Lock()
	entropy = previous
	entropyMu.Unlock()
	if !errors.Is(err, errIdentityRandom) || !errors.Is(errAgain, errIdentityRandom) {
		t.Fatalf("identity errors %v %v", err, errAgain)
	}
	if blocked.state.ctr.Load() != 0 {
		t.Fatalf("failed identity consumed counter %d", blocked.state.ctr.Load())
	}
}

func TestReplayWindowAndFIFO(t *testing.T) {
	replay := newReplayRegistry()
	if !replay.precheck(9, 1) || replay.count != 0 {
		t.Fatal("precheck inserted an identity")
	}
	if replay.precheck(9, 0) || replay.commit(9, 0) || replay.commit(9, maxCounter+1) {
		t.Fatal("invalid counter accepted")
	}
	if !replay.commit(9, 10) || replay.commit(9, 10) {
		t.Fatal("highest counter was not one-shot")
	}
	if !replay.commit(9, 8) || !replay.commit(9, 9) || replay.commit(9, 8) {
		t.Fatal("in-window counters were not admitted once")
	}
	high := uint64(2000)
	if !replay.commit(9, high) {
		t.Fatal("window advance rejected")
	}
	if replay.commit(9, high-replayWindow) || !replay.commit(9, high-replayWindow+1) {
		t.Fatal("window edge mismatch")
	}
	if !replay.commit(9, high+replayWindow) || replay.commit(9, high) {
		t.Fatal("advancing by the window did not retire old counters")
	}
	advanced := high + replayWindow
	if replay.commit(9, advanced-replayWindow) || !replay.commit(9, advanced-replayWindow+1) {
		t.Fatal("post-advance window edge mismatch")
	}

	filled := newReplayRegistry()
	for id := uint64(1); id <= replayCapacity; id++ {
		if !filled.commit(id, 1) {
			t.Fatalf("insert %d failed", id)
		}
	}
	if !filled.commit(1, 2) {
		t.Fatal("updating the oldest identity failed")
	}
	if !filled.commit(replayCapacity+1, 1) {
		t.Fatal("fifo insert failed")
	}
	if _, ok := filled.entries[1]; ok {
		t.Fatal("oldest identity survived an update")
	}
	if _, ok := filled.entries[2]; !ok {
		t.Fatal("second identity was evicted")
	}
	if !filled.commit(1, 1) {
		t.Fatal("evicted identity could not be registered again")
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	shared := newReplayRegistry()
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if shared.commit(42, 7) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || shared.count != 1 {
		t.Fatalf("concurrent winners=%d entries=%d", wins.Load(), shared.count)
	}
}

func TestPortalPreludeAdmission(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	hello := minimalClientHello()
	if !acceptOnce(t, keys, sealPrelude(keys, 77, 1, hello), hello) {
		t.Fatal("fresh counter rejected")
	}
	if keys.state.replay == nil || keys.state.replay.count != 1 {
		t.Fatal("accepted prelude was not committed")
	}
	if acceptOnce(t, keys, sealPrelude(keys, 77, 1, hello), hello) {
		t.Fatal("duplicate counter fell through")
	}
	if keys.state.replay.count != 1 {
		t.Fatal("duplicate changed registry size")
	}

	zero := Derive([]byte("00112233445566778899aabbccddeeff"))
	if acceptBlocking(t, zero, sealHead(zero, 5, 0)) {
		t.Fatal("counter 0 was accepted")
	}
	if zero.state.replay != nil {
		t.Fatal("counter 0 consulted or created the registry")
	}

	legacyKeys := Derive([]byte("ffeeddccbbaa99887766554433221100"))
	if acceptBlocking(t, legacyKeys, legacyPrelude(t, legacyKeys, hello)) {
		t.Fatal("3.0 prelude accepted")
	}
	if legacyKeys.state.replay != nil {
		t.Fatal("tag mismatch touched the registry")
	}

	badHello := bytes.Repeat([]byte{0xff}, 32)
	fresh := Derive([]byte("abc123abc123abc123abc123abc123ab"))
	if acceptOnce(t, fresh, sealPrelude(fresh, 9, 4, badHello), badHello) {
		t.Fatal("malformed client hello accepted")
	}
	if fresh.state.replay != nil && fresh.state.replay.count != 0 {
		t.Fatal("malformed client hello committed replay state")
	}
	if !acceptOnce(t, fresh, sealPrelude(fresh, 9, 4, hello), hello) {
		t.Fatal("counter was consumed by the malformed hello")
	}

	fragmented := splitRecords(hello)
	if !acceptOnce(t, fresh, sealPrelude(fresh, 9, 5, fragmented), fragmented) {
		t.Fatal("fragmented client hello rejected")
	}
}

func TestDuplicateCounterIsSilent(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	hello := minimalClientHello()
	wire := sealPrelude(keys, 99, 3, hello)
	leftClient, leftServer := net.Pipe()
	rightClient, rightServer := net.Pipe()
	defer leftClient.Close()
	defer rightClient.Close()
	errCh := make(chan error, 2)
	go func() { errCh <- readServerPayload(leftServer, keys, hello) }()
	go func() { errCh <- readServerPayload(rightServer, keys, hello) }()
	go func() { _, _ = leftClient.Write(wire) }()
	go func() { _, _ = rightClient.Write(append([]byte(nil), wire...)) }()
	var rejected int
	timeout := time.After(3 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				if !errors.Is(err, ErrPreludeRejected) {
					t.Fatal(err)
				}
				rejected++
			}
		case <-timeout:
			t.Fatal("duplicate admission timed out")
		}
	}
	if rejected != 1 {
		t.Fatalf("rejected %d duplicates", rejected)
	}
}

func TestMalformedHelloWritesNoTLSAlert(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	hello := bytes.Repeat([]byte{0x61}, 24)
	wire := sealPrelude(keys, 12, 1, hello)
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		tlsConn := tls.Server(WrapTCPServer(serverSide, keys), &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		})
		done <- tlsConn.Handshake()
	}()
	go func() { _, _ = clientSide.Write(wire) }()
	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := clientSide.Read(buf)
	if n != 0 || (err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, osDeadline(err))) {
		if n != 0 {
			t.Fatalf("server wrote %d alert bytes: %x", n, buf[:n])
		}
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not finish")
	}
	if keys.state.replay != nil && keys.state.replay.count != 0 {
		t.Fatal("rejected hello committed replay state")
	}
}

func TestRejectedPreludeDoesNotReadClientHello(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	hello := minimalClientHello()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	wire := legacyPrelude(t, keys, hello)
	var read atomic.Int64
	limited := &budgetConn{Conn: serverSide, left: &read, budget: int64(preludeLen + nonceLen)}
	errCh := make(chan error, 1)
	go func() {
		server := WrapTCPServer(limited, keys)
		_, err := server.Read(make([]byte, 8))
		errCh <- err
	}()
	go func() { _, _ = clientSide.Write(wire) }()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrPreludeRejected) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("rejected prelude did not return")
	}
	if read.Load() != int64(preludeLen+nonceLen) {
		t.Fatalf("server read %d bytes, want %d", read.Load(), preludeLen+nonceLen)
	}
	if keys.state.replay != nil {
		t.Fatal("rejected prelude created the registry")
	}
}

// budgetConn fails the read that would pass budget. It proves a rejected
// prelude stops before the following ClientHello.
type budgetConn struct {
	net.Conn
	left   *atomic.Int64
	budget int64
}

func (c *budgetConn) Read(p []byte) (int, error) {
	used := c.left.Load()
	if used >= c.budget {
		return 0, errors.New("read past prelude")
	}
	if int64(len(p)) > c.budget-used {
		p = p[:c.budget-used]
	}
	n, err := c.Conn.Read(p)
	c.left.Add(int64(n))
	return n, err
}

func TestReleaseAuthenticatedRestoresLingerOnlyBeforeDeadline(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	server := WrapTCPServer(serverSide, keys)
	if err := ReleaseAuthenticated(server, time.Now().Add(-time.Second)); !errors.Is(err, ErrHandshakeDeadline) {
		t.Fatalf("expired deadline: %v", err)
	}
	if err := ReleaseAuthenticated(clientSide, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := WrapTCPClient(clientSide, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReleaseAuthenticated(client, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyReceiverConsumesAuthenticatedPrelude(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	hello := minimalClientHello()
	errCh := make(chan error, 1)
	go func() {
		var head [preludeLen + nonceLen]byte
		if _, err := io.ReadFull(serverSide, head[:]); err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, len(hello))
		if _, err := io.ReadFull(serverSide, buf); err != nil {
			errCh <- err
			return
		}
		var nonce [nonceLen]byte
		copy(nonce[:], head[preludeLen:])
		chacha20.XORKeyStreamAt(buf, buf, &keys.TCPC2S, &nonce, 0)
		if !bytes.Equal(buf, hello) {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- nil
	}()
	client, err := WrapTCPClient(clientSide, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

type capturedPrelude struct {
	prelude []byte
	nonce   []byte
}

func capturePrelude(t *testing.T, keys Keys) capturedPrelude {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	client, err := WrapTCPClient(clientSide, keys)
	if err != nil {
		t.Fatal(err)
	}
	payload := minimalClientHello()
	errCh := make(chan error, 1)
	var got capturedPrelude
	go func() {
		buf := make([]byte, preludeLen+nonceLen+len(payload))
		_, err := io.ReadFull(serverSide, buf)
		if err == nil {
			got.prelude = append([]byte(nil), buf[:preludeLen]...)
			got.nonce = append([]byte(nil), buf[preludeLen:preludeLen+nonceLen]...)
		}
		errCh <- err
	}()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	_ = clientSide.Close()
	return got
}

func acceptOnce(t *testing.T, keys Keys, wire, want []byte) bool {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	errCh := make(chan error, 1)
	go func() { errCh <- readServerPayload(serverSide, keys, want) }()
	go func() { _, _ = clientSide.Write(wire) }()
	select {
	case err := <-errCh:
		return err == nil
	case <-time.After(3 * time.Second):
		t.Fatal("admission timed out")
		return false
	}
}

func readServerPayload(conn net.Conn, keys Keys, want []byte) error {
	defer conn.Close()
	server := WrapTCPServer(conn, keys)
	buf := make([]byte, len(want))
	_, err := io.ReadFull(server, buf)
	if err == nil && !bytes.Equal(buf, want) {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func acceptBlocking(t *testing.T, keys Keys, wire []byte) bool {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	errCh := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		server := WrapTCPServer(serverSide, keys)
		_, err := server.Read(make([]byte, 8))
		errCh <- err
	}()
	go func() { _, _ = clientSide.Write(wire) }()
	select {
	case err := <-errCh:
		return err == nil
	case <-time.After(time.Second):
		t.Fatal("portal blocked on a rejected prelude")
		return false
	}
}

func sealPrelude(keys Keys, identity, counter uint64, hello []byte) []byte {
	return append(sealHead(keys, identity, counter), encryptHello(keys, nonceFor(counter), hello)...)
}

func sealHead(keys Keys, identity, counter uint64) []byte {
	prelude := make([]byte, preludeLen)
	for i := range prelude[:32] {
		prelude[i] = byte(i)
	}
	nonce := nonceFor(counter)
	if err := EncodeTCPPrelude(keys, prelude, nonce[:], identity, counter); err != nil {
		panic(err)
	}
	return append(prelude, nonce[:]...)
}

func nonceFor(counter uint64) [nonceLen]byte {
	var nonce [nonceLen]byte
	binary.BigEndian.PutUint64(nonce[4:], counter+1)
	return nonce
}

func encryptHello(keys Keys, nonce [nonceLen]byte, hello []byte) []byte {
	out := append([]byte(nil), hello...)
	chacha20.XORKeyStreamAt(out, out, &keys.TCPC2S, &nonce, 0)
	return out
}

func legacyPrelude(t *testing.T, keys Keys, hello []byte) []byte {
	t.Helper()
	prelude, err := generatePrelude(preludeFull8)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [nonceLen]byte
	if err := readEntropy(nonce[:]); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, _, ok := DecodeTCPPrelude(keys, prelude[:], nonce[:]); !ok {
			return append(append(prelude[:], nonce[:]...), encryptHello(keys, nonce, hello)...)
		}
		prelude[0] ^= 1 << i
	}
	t.Fatal("could not build a tag mismatch")
	return nil
}

func splitRecords(hello []byte) []byte {
	body := hello[tlsRecordHeader:]
	mid := len(body) / 2
	return append(oneRecord(body[:mid]), oneRecord(body[mid:])...)
}

func oneRecord(fragment []byte) []byte {
	record := []byte{tlsHandshake, 0x03, 0x01, byte(len(fragment) >> 8), byte(len(fragment))}
	return append(record, fragment...)
}

func minimalClientHello() []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0x00, 0x02, 0x13, 0x01, 1, 0)
	ext := []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	message := []byte{tlsClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	message = append(message, body...)
	return oneRecord(message)
}

func preludeWithHighBits(t *testing.T, prefix, high string) []byte {
	t.Helper()
	out := make([]byte, preludeLen)
	copy(out, decodeHex(t, prefix))
	packed := decodeHex(t, high)
	for i := 0; i < 32; i++ {
		bit := (packed[i/8] >> (7 - i%8)) & 1
		out[32+i] = bit << 7
	}
	return out
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type failEntropy struct{}

func (failEntropy) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func osDeadline(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return err
	}
	return io.EOF
}
