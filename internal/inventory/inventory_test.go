package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// byName indexes parsed packages for assertions.
func byName(pkgs []Package) map[string]Package {
	m := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		m[p.Name] = p
	}
	return m
}

func TestGoParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", `module example.com/app

go 1.22

require (
	github.com/spf13/cobra v1.9.1
	golang.org/x/sys v0.44.0 // indirect
)
`)
	ms, err := Scan(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Ecosystem != "Go" {
		t.Fatalf("expected one Go manifest, got %+v", ms)
	}
	idx := byName(ms[0].Packages)
	if c := idx["github.com/spf13/cobra"]; c.Version != "v1.9.1" || !c.Direct {
		t.Errorf("cobra = %+v, want v1.9.1 direct", c)
	}
	if s := idx["golang.org/x/sys"]; s.Direct {
		t.Errorf("x/sys should be indirect: %+v", s)
	}
	if c := idx["github.com/spf13/cobra"]; c.Purl != "pkg:golang/github.com/spf13/cobra@v1.9.1" {
		t.Errorf("bad purl: %q", c.Purl)
	}
}

func TestNpmParserV3(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "package-lock.json", `{
	  "name": "app",
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "dependencies": { "lodash": "^4.17.0" } },
	    "node_modules/lodash": { "version": "4.17.20" },
	    "node_modules/lodash/node_modules/transitive": { "version": "1.0.0" },
	    "node_modules/@scope/pkg": { "version": "2.1.0" }
	  }
	}`)
	ms, err := Scan(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	idx := byName(ms[0].Packages)
	if l := idx["lodash"]; l.Version != "4.17.20" || !l.Direct {
		t.Errorf("lodash = %+v, want 4.17.20 direct", l)
	}
	if tr := idx["transitive"]; tr.Version != "1.0.0" || tr.Direct {
		t.Errorf("transitive = %+v, want 1.0.0 indirect", tr)
	}
	if s := idx["@scope/pkg"]; s.Version != "2.1.0" {
		t.Errorf("scoped pkg = %+v", s)
	}
}

func TestPnpmParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pnpm-lock.yaml", `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.21

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-x}
  '@scope/pkg@2.0.0':
    resolution: {integrity: sha512-y}
  debug@4.3.4(supports-color@8.1.1):
    resolution: {integrity: sha512-z}
`)
	ms, err := Scan(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	idx := byName(ms[0].Packages)
	if l := idx["lodash"]; l.Version != "4.17.21" || !l.Direct {
		t.Errorf("lodash = %+v, want 4.17.21 direct", l)
	}
	if s := idx["@scope/pkg"]; s.Version != "2.0.0" {
		t.Errorf("scoped = %+v, want 2.0.0", s)
	}
	if d := idx["debug"]; d.Version != "4.3.4" { // peer suffix stripped
		t.Errorf("debug = %+v, want 4.3.4 (peer stripped)", d)
	}
}

func TestRequirementsParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", `# comment
Django==4.2.1
requests[security]==2.31.0  # inline comment
urllib3==2.0.0 ; python_version < "3.9"
unpinned-package>=1.0
-r other.txt
`)
	ms, err := Scan(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	idx := byName(ms[0].Packages)
	if len(idx) != 3 {
		t.Fatalf("expected 3 pinned packages, got %d: %v", len(idx), idx)
	}
	if d := idx["django"]; d.Version != "4.2.1" || d.Ecosystem != "PyPI" { // normalized lowercase
		t.Errorf("django = %+v", d)
	}
	if r := idx["requests"]; r.Version != "2.31.0" { // extras stripped
		t.Errorf("requests = %+v", r)
	}
	if u := idx["urllib3"]; u.Version != "2.0.0" { // marker stripped
		t.Errorf("urllib3 = %+v", u)
	}
}

func TestPoetryParserDirectCrossRef(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pyproject.toml", `[tool.poetry]
name = "app"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
`)
	write(t, dir, "poetry.lock", `[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "charset-normalizer"
version = "3.2.0"
`)
	ms, err := Scan(dir, []string{"PyPI"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Both poetry.lock and pyproject could match; only poetry.lock parses here.
	var lock Manifest
	for _, m := range ms {
		if m.RelPath == "poetry.lock" {
			lock = m
		}
	}
	idx := byName(lock.Packages)
	if r := idx["requests"]; !r.Direct {
		t.Errorf("requests should be direct (in pyproject): %+v", r)
	}
	if c := idx["charset-normalizer"]; c.Direct {
		t.Errorf("charset-normalizer should be transitive: %+v", c)
	}
}

func TestScanRespectsEcosystemFilterAndSkipDirs(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module x\n\ngo 1.22\n\nrequire github.com/a/b v1.0.0\n")
	write(t, dir, "requirements.txt", "flask==3.0.0\n")
	write(t, dir, "node_modules/dep/package-lock.json", `{"lockfileVersion":3,"packages":{}}`)

	ms, err := Scan(dir, []string{"Go"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Ecosystem != "Go" {
		t.Fatalf("ecosystem filter failed: %+v", ms)
	}

	// Without filter, node_modules must still be skipped.
	all, _ := Scan(dir, nil, nil)
	for _, m := range all {
		if filepath.Dir(m.RelPath) == "node_modules/dep" {
			t.Errorf("node_modules should be skipped: %s", m.RelPath)
		}
	}
}

func TestNormalizePyPI(t *testing.T) {
	cases := map[string]string{
		"Django":             "django",
		"charset_normalizer": "charset-normalizer",
		"Foo.Bar__Baz":       "foo-bar-baz",
	}
	for in, want := range cases {
		if got := normalizePyPI(in); got != want {
			t.Errorf("normalizePyPI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCargoParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Cargo.toml", `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"

[dev-dependencies]
mockito = "1.2"
`)
	write(t, dir, "Cargo.lock", `version = 3

[[package]]
name = "myapp"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde_derive"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "mockito"
version = "1.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
	ms, err := Scan(dir, []string{"crates.io"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var lock Manifest
	for _, m := range ms {
		if m.RelPath == "Cargo.lock" {
			lock = m
		}
	}
	idx := byName(lock.Packages)
	// Local workspace member "myapp" (no source) must be excluded.
	if _, ok := idx["myapp"]; ok {
		t.Error("local crate myapp should not be inventoried")
	}
	if s := idx["serde"]; s.Version != "1.0.190" || !s.Direct || s.Ecosystem != "crates.io" {
		t.Errorf("serde = %+v, want 1.0.190 direct crates.io", s)
	}
	if d := idx["serde_derive"]; d.Direct {
		t.Errorf("serde_derive should be transitive: %+v", d)
	}
	if m := idx["mockito"]; !m.Direct { // dev-dependency counts as direct
		t.Errorf("mockito (dev-dep) should be direct: %+v", m)
	}
	if s := idx["serde"]; s.Purl != "pkg:cargo/serde@1.0.190" {
		t.Errorf("bad purl: %q", s.Purl)
	}
}

func TestComposerParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "composer.json", `{
	  "require": { "php": "^8.2", "laravel/framework": "^11.0", "firebase/php-jwt": "^6.0" },
	  "require-dev": { "phpunit/phpunit": "^11.0" }
	}`)
	write(t, dir, "composer.lock", `{
	  "_readme": ["ignore"],
	  "packages": [
	    { "name": "laravel/framework", "version": "v11.9.2" },
	    { "name": "firebase/php-jwt", "version": "v6.10.0" },
	    { "name": "brick/math", "version": "0.12.1" }
	  ],
	  "packages-dev": [
	    { "name": "phpunit/phpunit", "version": "11.2.5" }
	  ]
	}`)
	ms, err := Scan(dir, []string{"Packagist"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var lock Manifest
	for _, m := range ms {
		if m.RelPath == "composer.lock" {
			lock = m
		}
	}
	idx := byName(lock.Packages)
	if l := idx["laravel/framework"]; l.Version != "11.9.2" || !l.Direct || l.Ecosystem != "Packagist" { // v stripped
		t.Errorf("laravel/framework = %+v, want 11.9.2 direct Packagist", l)
	}
	if b := idx["brick/math"]; b.Direct { // transitive, not in composer.json
		t.Errorf("brick/math should be transitive: %+v", b)
	}
	if p := idx["phpunit/phpunit"]; !p.Direct { // dev-dep counts as direct
		t.Errorf("phpunit (dev) should be direct: %+v", p)
	}
	if l := idx["laravel/framework"]; l.Purl != "pkg:composer/laravel/framework@v11.9.2" {
		t.Errorf("bad purl: %q", l.Purl)
	}
}
