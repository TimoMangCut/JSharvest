package replay

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// BogusID makes an identifier of the kind of id that names nothing: an id
// the server has no object for, far from the one it is made from (never
// id +- k, never 0, negative or past the type's top), of the same shape so
// that a parser takes it (docs/gd7-bola-design.md 4.3). avoid says which
// values are taken (ids the run has seen); "" when none could be made.
func BogusID(id ParsedID, avoid func(string) bool) string {
	for range 40 {
		v := bogusOnce(id)
		if v == "" || v == id.Value || (avoid != nil && avoid(v)) {
			continue
		}
		return v
	}
	return ""
}

func randBetween(lo, hi int64) int64 { // lo <= n <= hi
	n, err := rand.Int(rand.Reader, big.NewInt(hi-lo+1))
	if err != nil {
		return lo
	}
	return lo + n.Int64()
}

func randFrom(alphabet string, n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(alphabet[randBetween(0, int64(len(alphabet)-1))])
	}
	return b.String()
}

func bogusOnce(id ParsedID) string {
	switch id.Kind {
	case IDRelay:
		inner := bogusKind(id.InnerKind, id.RelayInner)
		if inner == "" {
			return ""
		}
		return EncodeRelay(id.RelayType, inner, id.relayEnc)
	}
	return bogusKind(id.Kind, id.Value)
}

func bogusKind(kind IDKind, v string) string {
	switch kind {
	case IDIntSmall:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return ""
		}
		if n >= 1_800_000_000 {
			return strconv.FormatInt(randBetween(1_400_000_000, 1_700_000_000), 10)
		}
		return strconv.FormatInt(randBetween(1_900_000_000, 2_147_483_000), 10)
	case IDInt64:
		return bogusInt64(v)
	case IDUUID:
		return bogusUUID(v)
	case IDULID:
		if len(v) != 26 {
			return ""
		}
		return v[:10] + randFrom("0123456789ABCDEFGHJKMNPQRSTVWXYZ", 16)
	case IDObjectID:
		if len(v) != 24 {
			return ""
		}
		alphabet := "0123456789abcdef"
		if v != strings.ToLower(v) {
			alphabet = "0123456789ABCDEF"
		}
		return v[:8] + randFrom(alphabet, 16)
	case IDSlug:
		return bogusSlug(v)
	}
	return ""
}

// bogusInt64 keeps the digit count and the first two digits (a plausible
// epoch part) and stays at or under MaxInt64, farther than 10^9 from v.
func bogusInt64(v string) string {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || len(v) < 10 {
		return ""
	}
	prefix := v[:2]
	if len(v) == 19 && prefix >= "92" {
		prefix = "91"
	}
	for range 20 {
		s := prefix + randFrom("0123456789", len(v)-2)
		f, err := strconv.ParseInt(s, 10, 64)
		if err != nil || f <= math.MaxInt32 {
			continue
		}
		if d := f - n; d > 1_000_000_000 || d < -1_000_000_000 {
			return s
		}
	}
	// A number of 10 digits has no other with its first two digits that far
	// away: any number of the same length then.
	for range 40 {
		s := randFrom("123456789", 1) + randFrom("0123456789", len(v)-1)
		f, err := strconv.ParseInt(s, 10, 64)
		if err != nil || f <= math.MaxInt32 {
			continue
		}
		if d := f - n; d > 1_000_000_000 || d < -1_000_000_000 {
			return s
		}
	}
	return ""
}

func bogusUUID(v string) string {
	if len(v) != 36 {
		return ""
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	ver := byte(4)
	if c, err := strconv.ParseUint(v[14:15], 16, 8); err == nil && c >= 1 && c <= 8 {
		ver = byte(c)
	}
	if ver == 7 {
		// 48 bits of milliseconds since the epoch, not past now.
		ms := uint64(time.Now().UnixMilli()) - uint64(randBetween(1, 365*24*3600*1000))
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], ms)
		copy(b[:6], t[2:])
	}
	b[6] = b[6]&0x0f | ver<<4
	b[8] = b[8]&0x3f | 0x80
	s := hex.EncodeToString(b[:])
	out := s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
	if v != strings.ToLower(v) {
		out = strings.ToUpper(out)
	}
	return out
}

// bogusSlug keeps a short prefix and its separator (usr_, proj-, doc-) and
// every separator and character class after it; a slug with no prefix
// becomes z- and random characters, at least 12.
func bogusSlug(v string) string {
	i := strings.IndexAny(v, "-_")
	if i >= 2 && i <= 10 && len(v)-i-1 >= 2 {
		var b strings.Builder
		b.WriteString(v[:i+1])
		for _, r := range v[i+1:] {
			switch {
			case r >= '0' && r <= '9':
				b.WriteByte(randFrom("0123456789", 1)[0])
			case r >= 'a' && r <= 'z':
				b.WriteByte(randFrom("abcdefghijklmnopqrstuvwxyz", 1)[0])
			case r >= 'A' && r <= 'Z':
				b.WriteByte(randFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1)[0])
			default:
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return "z-" + randFrom("abcdefghijklmnopqrstuvwxyz0123456789", max(12, len(v)))
}
