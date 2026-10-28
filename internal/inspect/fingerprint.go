package inspect

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
)

const (
	tlsRecordTypeHandshake    = 22
	tlsHandshakeClientHello   = 1
	maxClientHelloRecordBytes = 1 << 20
)

type observedListener struct {
	net.Listener
}

type prefixConn struct {
	net.Conn
	once   sync.Once
	reader io.Reader
	state  *connectionStateData
}

func (c *prefixConn) NetConn() net.Conn {
	return c.Conn
}

type parsedClientHello struct {
	legacyVersion     uint16
	serverName        string
	cipherSuites      []uint16
	extensions        []uint16
	supportedCurves   []uint16
	supportedPoints   []uint8
	supportedVersions []uint16
	signatureSchemes  []uint16
	supportedProtos   []string
}

func newObservedListener(ln net.Listener) net.Listener {
	return &observedListener{Listener: ln}
}

func newPrefixConn(conn net.Conn, prefix []byte, state *connectionStateData) net.Conn {
	return &prefixConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(prefix), conn),
		state:  state,
	}
}

func (l *observedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &prefixConn{
		Conn:  conn,
		state: &connectionStateData{},
	}, nil
}

func (c *prefixConn) Read(p []byte) (int, error) {
	c.once.Do(c.initReader)
	return c.reader.Read(p)
}

func (c *prefixConn) initReader() {
	if c.reader != nil {
		return
	}
	wrapped, hello, _ := captureClientHello(c.Conn, c.state)
	if hello != nil && c.state != nil {
		c.state.mu.Lock()
		c.state.fingerprint = buildFingerprintInfo(hello)
		c.state.mu.Unlock()
	}
	if pc, ok := wrapped.(*prefixConn); ok {
		c.reader = pc.reader
	} else {
		c.reader = wrapped
	}
}

func captureClientHello(conn net.Conn, state *connectionStateData) (net.Conn, *parsedClientHello, error) {
	var raw bytes.Buffer
	var handshake bytes.Buffer

	for raw.Len() < maxClientHelloRecordBytes {
		header := make([]byte, 5)
		n, err := io.ReadFull(conn, header)
		raw.Write(header[:n])
		if err != nil {
			rawConn := newPrefixConn(conn, raw.Bytes(), state)
			return rawConn, nil, err
		}

		if header[0] != tlsRecordTypeHandshake {
			rawConn := newPrefixConn(conn, raw.Bytes(), state)
			return rawConn, nil, fmt.Errorf("unexpected TLS record type %d", header[0])
		}

		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		payload := make([]byte, recordLen)
		n, err = io.ReadFull(conn, payload)
		raw.Write(payload[:n])
		if err != nil {
			rawConn := newPrefixConn(conn, raw.Bytes(), state)
			return rawConn, nil, err
		}

		handshake.Write(payload)
		buf := handshake.Bytes()
		if len(buf) < 4 {
			continue
		}
		if buf[0] != tlsHandshakeClientHello {
			rawConn := newPrefixConn(conn, raw.Bytes(), state)
			return rawConn, nil, fmt.Errorf("unexpected handshake type %d", buf[0])
		}

		helloLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if len(buf) < 4+helloLen {
			continue
		}

		hello, err := parseClientHello(buf[4 : 4+helloLen])
		rawConn := newPrefixConn(conn, raw.Bytes(), state)
		return rawConn, hello, err
	}

	rawConn := newPrefixConn(conn, raw.Bytes(), state)
	return rawConn, nil, fmt.Errorf("client hello exceeded %d bytes", maxClientHelloRecordBytes)
}

func parseClientHello(data []byte) (*parsedClientHello, error) {
	if len(data) < 34 {
		return nil, fmt.Errorf("client hello too short")
	}

	out := &parsedClientHello{
		legacyVersion: binary.BigEndian.Uint16(data[:2]),
	}

	pos := 2 + 32
	if pos >= len(data) {
		return nil, fmt.Errorf("missing session id length")
	}

	sessionIDLen := int(data[pos])
	pos++
	if pos+sessionIDLen > len(data) {
		return nil, fmt.Errorf("invalid session id")
	}
	pos += sessionIDLen

	if pos+2 > len(data) {
		return nil, fmt.Errorf("missing cipher suites length")
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if cipherLen%2 != 0 || pos+cipherLen > len(data) {
		return nil, fmt.Errorf("invalid cipher suites")
	}
	out.cipherSuites = make([]uint16, 0, cipherLen/2)
	for i := 0; i < cipherLen; i += 2 {
		out.cipherSuites = append(out.cipherSuites, binary.BigEndian.Uint16(data[pos+i:pos+i+2]))
	}
	pos += cipherLen

	if pos >= len(data) {
		return out, nil
	}
	compressionLen := int(data[pos])
	pos++
	if pos+compressionLen > len(data) {
		return nil, fmt.Errorf("invalid compression methods")
	}
	pos += compressionLen

	if pos == len(data) {
		return out, nil
	}
	if pos+2 > len(data) {
		return nil, fmt.Errorf("missing extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+extLen > len(data) {
		return nil, fmt.Errorf("invalid extensions")
	}
	extEnd := pos + extLen

	for pos+4 <= extEnd {
		extID := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > extEnd {
			return nil, fmt.Errorf("invalid extension payload")
		}

		extData := data[pos : pos+extDataLen]
		out.extensions = append(out.extensions, extID)
		switch extID {
		case 0:
			name, err := parseServerNameExtension(extData)
			if err == nil {
				out.serverName = name
			}
		case 10:
			out.supportedCurves = parseUint16Vector(extData, 2)
		case 11:
			out.supportedPoints = parseUint8Vector(extData, 1)
		case 13:
			out.signatureSchemes = parseUint16Vector(extData, 2)
		case 16:
			out.supportedProtos = parseALPNExtension(extData)
		case 43:
			out.supportedVersions = parseSupportedVersionsExtension(extData)
		}
		pos += extDataLen
	}

	return out, nil
}

func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("server name extension too short")
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if 2+listLen > len(data) {
		return "", fmt.Errorf("invalid server name list")
	}

	pos := 2
	for pos+3 <= 2+listLen {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > len(data) {
			return "", fmt.Errorf("invalid server name")
		}
		if nameType == 0 && nameLen > 0 {
			return string(data[pos : pos+nameLen]), nil
		}
		pos += nameLen
	}
	return "", nil
}

func parseSupportedVersionsExtension(data []byte) []uint16 {
	return parseUint16Vector(data, 1)
}

func parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if 2+listLen > len(data) {
		return nil
	}

	var out []string
	for pos := 2; pos < 2+listLen; {
		if pos >= len(data) {
			return out
		}
		nameLen := int(data[pos])
		pos++
		if pos+nameLen > len(data) {
			return out
		}
		out = append(out, string(data[pos:pos+nameLen]))
		pos += nameLen
	}
	return out
}

func parseUint16Vector(data []byte, prefixSize int) []uint16 {
	if len(data) < prefixSize {
		return nil
	}

	var listLen int
	switch prefixSize {
	case 0:
		listLen = len(data)
	case 1:
		listLen = int(data[0])
	case 2:
		listLen = int(binary.BigEndian.Uint16(data[:2]))
	default:
		return nil
	}
	if prefixSize+listLen > len(data) || listLen%2 != 0 {
		return nil
	}

	out := make([]uint16, 0, listLen/2)
	for i := prefixSize; i < prefixSize+listLen; i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return out
}

func parseUint8Vector(data []byte, prefixSize int) []uint8 {
	if len(data) < prefixSize {
		return nil
	}

	var listLen int
	switch prefixSize {
	case 0:
		listLen = len(data)
	case 1:
		listLen = int(data[0])
	case 2:
		listLen = int(binary.BigEndian.Uint16(data[:2]))
	default:
		return nil
	}
	if prefixSize+listLen > len(data) {
		return nil
	}
	return append([]uint8(nil), data[prefixSize:prefixSize+listLen]...)
}

func buildFingerprintInfo(hello *parsedClientHello) fingerprintInfo {
	ja3Raw := buildJA3Raw(hello)
	return fingerprintInfo{
		JA3:    md5Hex(ja3Raw),
		JA3Raw: ja3Raw,
		JA4:    buildJA4(hello),
		JA4Raw: buildJA4Raw(hello),
	}
}

func buildJA3Raw(hello *parsedClientHello) string {
	return strings.Join([]string{
		fmt.Sprintf("%d", hello.legacyVersion),
		joinUint16Decimal(filterNonGREASE(hello.cipherSuites), "-"),
		joinUint16Decimal(filterNonGREASE(hello.extensions), "-"),
		joinUint16Decimal(filterNonGREASE(hello.supportedCurves), "-"),
		joinUint8Decimal(hello.supportedPoints, "-"),
	}, ",")
}

func buildJA4(hello *parsedClientHello) string {
	a := buildJA4A(hello)
	bRaw := joinUint16Hex(sortDistinct(filterNonGREASE(hello.cipherSuites)), ",")

	exts := sortDistinct(filterExcludedExtensions(hello.extensions))
	sigs := sortDistinct(filterNonGREASE(hello.signatureSchemes))
	cRaw := joinUint16Hex(exts, ",") + "_" + joinUint16Hex(sigs, ",")

	return a + "_" + sha256PrefixHex(bRaw) + "_" + sha256PrefixHex(cRaw)
}

func buildJA4Raw(hello *parsedClientHello) string {
	a := buildJA4A(hello)
	bRaw := joinUint16Hex(sortDistinct(filterNonGREASE(hello.cipherSuites)), ",")

	exts := sortDistinct(filterExcludedExtensions(hello.extensions))
	sigs := sortDistinct(filterNonGREASE(hello.signatureSchemes))
	cRaw := joinUint16Hex(exts, ",") + "_" + joinUint16Hex(sigs, ",")

	return a + "_" + bRaw + "_" + cRaw
}

func buildJA4A(hello *parsedClientHello) string {
	version := ja4VersionString(hello.supportedVersions, hello.legacyVersion)
	sniFlag := "i"
	if hello.serverName != "" {
		sniFlag = "d"
	}

	cipherCount := fmt.Sprintf("%02d", min(len(sortDistinct(filterNonGREASE(hello.cipherSuites))), 99))
	extCount := fmt.Sprintf("%02d", min(len(sortDistinct(filterNonGREASE(hello.extensions))), 99))

	return "t" + version + sniFlag + cipherCount + extCount + ja4ALPN(hello.supportedProtos)
}

func ja4VersionString(versions []uint16, legacyVersion uint16) string {
	highest := legacyVersion
	for _, v := range versions {
		if isGREASE(v) {
			continue
		}
		if v > highest {
			highest = v
		}
	}

	switch highest {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

func ja4ALPN(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}

	proto := strings.ToLower(protos[0])
	first := proto[0]
	last := proto[len(proto)-1]
	if isJA4AlphaNum(first) && isJA4AlphaNum(last) {
		return string([]byte{first, last})
	}
	return "00"
}

func isJA4AlphaNum(b byte) bool {
	return ('a' <= b && b <= 'z') || ('0' <= b && b <= '9')
}

func filterNonGREASE(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, v := range values {
		if isGREASE(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func filterExcludedExtensions(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, v := range values {
		if isGREASE(v) || v == 0 || v == 16 {
			continue
		}
		out = append(out, v)
	}
	return out
}

func sortDistinct(values []uint16) []uint16 {
	if len(values) == 0 {
		return nil
	}

	out := append([]uint16(nil), values...)
	slices.Sort(out)
	return slices.Compact(out)
}

func joinUint16Decimal(values []uint16, sep string) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func joinUint8Decimal(values []uint8, sep string) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func joinUint16Hex(values []uint16, sep string) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, sep)
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256PrefixHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
