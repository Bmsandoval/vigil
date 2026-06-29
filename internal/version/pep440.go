package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// pep440Comparator implements a practical subset of PEP 440 version ordering:
// epoch, release segments, pre-release (a/b/rc), post-release, and dev-release.
// Local versions ("+local") are ignored for ordering, as the spec allows when
// comparing public releases. This covers the forms that appear in OSV PyPI
// advisory ranges and pinned requirements.
type pep440Comparator struct{}

var pep440Re = regexp.MustCompile(`^\s*v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?` +
	`(?P<post>(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*)|(?:-[0-9]+))?` +
	`(?P<dev>[-_.]?dev[-_.]?[0-9]*)?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?` +
	`\s*$`)

type pep440Version struct {
	epoch   int
	release []int
	preKind int // -1 none; 0 a; 1 b; 2 rc
	preNum  int
	hasPost bool
	postNum int
	hasDev  bool
	devNum  int
}

func (pep440Comparator) Valid(v string) bool {
	_, err := parsePEP440(strings.ToLower(strings.TrimSpace(v)))
	return err == nil
}

func (pep440Comparator) Compare(a, b string) (int, error) {
	va, err := parsePEP440(strings.ToLower(strings.TrimSpace(a)))
	if err != nil {
		return 0, err
	}
	vb, err := parsePEP440(strings.ToLower(strings.TrimSpace(b)))
	if err != nil {
		return 0, err
	}
	return va.compare(vb), nil
}

func parsePEP440(s string) (pep440Version, error) {
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pep440Version{}, fmt.Errorf("invalid PEP 440 version %q", s)
	}
	idx := func(name string) string { return m[pep440Re.SubexpIndex(name)] }

	var v pep440Version
	if e := idx("epoch"); e != "" {
		v.epoch, _ = strconv.Atoi(e)
	}
	for _, seg := range strings.Split(idx("release"), ".") {
		n, _ := strconv.Atoi(seg)
		v.release = append(v.release, n)
	}

	v.preKind = -1
	if pre := idx("pre"); pre != "" {
		kind, num := splitLabel(pre, map[string]int{
			"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2,
		})
		v.preKind, v.preNum = kind, num
	}
	if post := idx("post"); post != "" {
		v.hasPost = true
		// A bare "-N" implicit post-release, or "postN"/"revN".
		v.postNum = trailingNumber(post)
	}
	if dev := idx("dev"); dev != "" {
		v.hasDev = true
		v.devNum = trailingNumber(dev)
	}
	return v, nil
}

// splitLabel maps a textual pre-release label to its kind rank and number.
func splitLabel(s string, kinds map[string]int) (int, int) {
	s = strings.Trim(s, "-_.")
	letters := strings.TrimRight(s, "0123456789")
	num := trailingNumber(s)
	letters = strings.Trim(letters, "-_.")
	if k, ok := kinds[letters]; ok {
		return k, num
	}
	return 2, num // default unknown labels to rc rank
}

func trailingNumber(s string) int {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return 0
	}
	n, _ := strconv.Atoi(s[i:])
	return n
}

func (a pep440Version) compare(b pep440Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := cmpRelease(a.release, b.release); c != 0 {
		return c
	}
	// Pre-release ordering: a version WITH a pre-release sorts BEFORE the same
	// version without one. dev sorts before pre; post sorts after the release.
	if c := cmpPre(a, b); c != 0 {
		return c
	}
	if c := cmpPost(a, b); c != 0 {
		return c
	}
	return cmpDev(a, b)
}

func cmpRelease(a, b []int) int {
	n := max(len(a), len(b))
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// preRank yields a sortable key for the pre-release phase of a version.
// dev-only (no pre) < pre-release < final/post.
func cmpPre(a, b pep440Version) int {
	ra := preOrder(a)
	rb := preOrder(b)
	if ra != rb {
		return cmpInt(ra, rb)
	}
	if a.preKind >= 0 && b.preKind >= 0 {
		if c := cmpInt(a.preKind, b.preKind); c != 0 {
			return c
		}
		return cmpInt(a.preNum, b.preNum)
	}
	return 0
}

// preOrder: a pure dev release (1.0.dev1) is below a pre-release (1.0a1) which
// is below the final release (1.0). 0=dev-only, 1=pre, 2=final-or-post.
func preOrder(v pep440Version) int {
	switch {
	case v.preKind >= 0:
		return 1
	case v.hasDev && !v.hasPost:
		return 0
	default:
		return 2
	}
}

func cmpPost(a, b pep440Version) int {
	av, bv := -1, -1
	if a.hasPost {
		av = a.postNum
	}
	if b.hasPost {
		bv = b.postNum
	}
	return cmpInt(av, bv)
}

func cmpDev(a, b pep440Version) int {
	// Among otherwise-equal versions, a dev release sorts before a non-dev one.
	av, bv := int(^uint(0)>>1), int(^uint(0)>>1) // no dev → "infinity"
	if a.hasDev {
		av = a.devNum
	}
	if b.hasDev {
		bv = b.devNum
	}
	return cmpInt(av, bv)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
