package telemetry

import (
	"encoding/binary"
	"strings"
)

// ParseClientHelloSNI extracts the first host_name from a TLS ClientHello in one contiguous buffer.
// The buffer may be truncated (e.g. BPF captures only the first N bytes of a larger record); the
// function parses as far as it can and returns false only when the SNI extension is unreachable.
func ParseClientHelloSNI(b []byte) (sni string, ok bool) {
	if len(b) < 43 {
		return "", false
	}
	if b[0] != 0x16 {
		return "", false
	}
	ver := binary.BigEndian.Uint16(b[1:3])
	if ver < 0x0301 || ver > 0x0304 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 38 {
		return "", false
	}
	// Use whatever bytes are available; a BPF capture may be shorter than the full record.
	hsEnd := 5 + recLen
	if hsEnd > len(b) {
		hsEnd = len(b)
	}
	hs := b[5:hsEnd]
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", false
	}
	chLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if chLen < 34 {
		return "", false
	}
	// ClientHello body may also be truncated; use available bytes.
	chEnd := 4 + chLen
	if chEnd > len(hs) {
		chEnd = len(hs)
	}
	ch := hs[4:chEnd]
	i := 34 // after version + random
	if i >= len(ch) {
		return "", false
	}
	sidLen := int(ch[i])
	i++
	if i+sidLen > len(ch) {
		return "", false
	}
	i += sidLen
	if i+2 > len(ch) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(ch[i : i+2]))
	i += 2
	if i+csLen > len(ch) {
		return "", false
	}
	i += csLen
	if i >= len(ch) {
		return "", false
	}
	compLen := int(ch[i])
	i++
	if i+compLen > len(ch) {
		return "", false
	}
	i += compLen
	if i+2 > len(ch) {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(ch[i : i+2]))
	i += 2
	if extLen == 0 {
		return "", false
	}
	// The extensions block may also be truncated; scan whatever bytes are available.
	extEnd := i + extLen
	if extEnd > len(ch) {
		extEnd = len(ch)
	}
	return scanServerNameList(ch[i:extEnd])
}

func scanServerNameList(ext []byte) (string, bool) {
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext[0:2])
		ln := int(binary.BigEndian.Uint16(ext[2:4]))
		if 4+ln > len(ext) {
			return "", false
		}
		block := ext[4 : 4+ln]
		ext = ext[4+ln:]
		if typ != 0 {
			continue
		}
		if len(block) < 2 {
			return "", false
		}
		listLen := int(binary.BigEndian.Uint16(block[0:2]))
		if listLen < 3 || 2+listLen > len(block) {
			return "", false
		}
		list := block[2 : 2+listLen]
		if len(list) < 3 || list[0] != 0 {
			return "", false
		}
		nameLen := int(binary.BigEndian.Uint16(list[1:3]))
		if nameLen <= 0 || 3+nameLen > len(list) {
			return "", false
		}
		raw := strings.ToLower(strings.TrimSpace(string(list[3 : 3+nameLen])))
		if raw == "" || len(raw) > 255 {
			return "", false
		}
		return raw, true
	}
	return "", false
}
