//go:build linux

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

// execHashMaxBytes bounds the content-hash cost: binaries larger than this are
// not hashed (exe_sha256 left empty) so a pathological exec of a huge file
// cannot stall the exec reader. 16 MiB comfortably covers ordinary CI tool
// binaries while keeping the per-exec I/O bounded.
const execHashMaxBytes int64 = 16 << 20

// bestEffortExeSHA256 returns the lowercase-hex SHA-256 of the file at path, or
// "" when it cannot be computed cheaply and unambiguously. It is a supplemental
// tamper hint layered on the robust in-kernel exe_ino/exe_dev identity, not a
// guarantee that the hashed bytes are the ones the kernel exec'd:
//
//   - The BPF exe_path is capped at 256 bytes and may be relative or truncated;
//     only absolute paths are hashed (a relative path resolves against the
//     agent's cwd, not the target process's, so it would be wrong).
//   - TOCTOU: the file may have been replaced between exec and this read. A
//     differing hash for the same exe_ino is itself a tamper signal.
//   - Non-regular files and over-cap files are skipped.
//
// Any error returns "" — never fatal.
func bestEffortExeSHA256(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > execHashMaxBytes {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	// LimitReader as a belt-and-suspenders bound in case the file grew between
	// the stat and the open; the stat already gated on execHashMaxBytes.
	if _, err := io.Copy(h, io.LimitReader(f, execHashMaxBytes)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
