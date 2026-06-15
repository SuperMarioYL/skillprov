// Package scan statically inspects a skill directory. It pulls declared
// capabilities out of SKILL.md frontmatter and detects observed capability
// signals (network / fs-write / exec / env) across the skill's scripts and
// source files using lightweight, language-agnostic heuristics.
//
// The heuristics are deliberately conservative: they over-detect rather than
// under-detect, because a missed signal in the scanner becomes an undeclared
// capability that slips past verification. False positives are the author's to
// declare away; false negatives would defeat the whole point.
package scan

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/SuperMarioYL/skillsig/internal/manifest"
)

// Capability is one of the four capability classes skillsig tracks.
type Capability string

const (
	CapNet      Capability = "net"
	CapFSWrite  Capability = "fs-write"
	CapExec     Capability = "exec"
	CapEnv      Capability = "env"
)

// Evidence records a single observed capability hit: where it was seen and the
// matched snippet. This is what makes a REJECTED message human-readable.
type Evidence struct {
	Capability Capability
	File       string
	Line       int
	Snippet    string
}

// Result is the full output of scanning a skill directory.
type Result struct {
	SkillName    string
	SkillVersion string
	Entry        string

	// Declared is the capability set parsed from SKILL.md frontmatter.
	Declared map[Capability]bool
	// DeclaredHosts / DeclaredEnv carry the finer-grained declarations when the
	// author listed specific hosts or environment variables.
	DeclaredHosts []string
	DeclaredEnv   []string

	// Observed is the capability set the static scan actually found, with the
	// evidence that triggered each.
	Observed map[Capability][]Evidence

	// Files is the relative path of every scanned source/script file.
	Files []string

	// observedHosts accumulates hostnames seen in network evidence.
	observedHosts []string
}

// skillFrontmatter is the subset of SKILL.md frontmatter skillsig reads.
type skillFrontmatter struct {
	Name         string `yaml:"name"`
	Version      string `yaml:"version"`
	Entry        string `yaml:"entry"`
	AllowedTools string `yaml:"allowed-tools"`
	// Capabilities is skillsig's optional explicit declaration block. Authors
	// who want precise control over the manifest use this rather than relying on
	// allowed-tools inference.
	Capabilities *declaredCaps `yaml:"capabilities"`
}

type declaredCaps struct {
	Net     *bool    `yaml:"net"`
	FSWrite *bool    `yaml:"fs-write"`
	Exec    *bool    `yaml:"exec"`
	Env     *bool    `yaml:"env"`
	Hosts   []string `yaml:"hosts"`
	EnvVars []string `yaml:"env-vars"`
}

// scannable file extensions. SKILL.md itself is scanned for inline code too.
var scanExt = map[string]bool{
	".sh": true, ".bash": true, ".zsh": true,
	".py": true, ".js": true, ".ts": true, ".mjs": true, ".cjs": true,
	".go": true, ".rb": true, ".pl": true, ".php": true,
	".md": true, "": true, // "" covers extensionless scripts (e.g. ./run)
}

// signature is one capability detector.
type signature struct {
	cap Capability
	re  *regexp.Regexp
}

// signatures are the static heuristics. Kept intentionally broad.
var signatures = []signature{
	// network
	{CapNet, regexp.MustCompile(`(?i)\bhttps?://`)},
	{CapNet, regexp.MustCompile(`(?i)\b(curl|wget)\b`)},
	{CapNet, regexp.MustCompile(`(?i)\b(requests|urllib|httplib|http\.client|httpx|aiohttp)\b`)},
	{CapNet, regexp.MustCompile(`(?i)\bfetch\s*\(`)},
	{CapNet, regexp.MustCompile(`(?i)\b(net/http|http\.Get|http\.Post|http\.NewRequest)\b`)},
	{CapNet, regexp.MustCompile(`(?i)\bsocket\.(socket|create_connection)\b`)},
	{CapNet, regexp.MustCompile(`(?i)\bnet\.Dial\b`)},
	// fs-write
	{CapFSWrite, regexp.MustCompile(`(?i)\bopen\s*\([^)]*['"][wa]\+?['"]`)},
	{CapFSWrite, regexp.MustCompile(`(?i)\b(os\.Create|os\.WriteFile|ioutil\.WriteFile)\b`)},
	{CapFSWrite, regexp.MustCompile(`(?i)\bWriteFile\b`)},
	{CapFSWrite, regexp.MustCompile(`(?i)\bfs\.(write|writeFile|appendFile|createWriteStream)\b`)},
	{CapFSWrite, regexp.MustCompile(`(?i)\bFile\.(write|open)\b`)},
	{CapFSWrite, regexp.MustCompile(`>>?\s*['"]?/`)},      // shell redirect to an absolute path
	{CapFSWrite, regexp.MustCompile(`>>?\s*['"]?\$[A-Za-z_{]`)}, // redirect into a $VAR-rooted path (e.g. > "$HOME/x")
	{CapFSWrite, regexp.MustCompile(`(?i)\btee\b`)},
	// exec
	{CapExec, regexp.MustCompile(`(?i)\b(subprocess|os\.system|popen|check_output|check_call)\b`)},
	{CapExec, regexp.MustCompile(`(?i)\bexec(\.Command|Sync|File)?\b`)},
	{CapExec, regexp.MustCompile(`(?i)\bsystem\s*\(`)},
	{CapExec, regexp.MustCompile(`(?i)\b(child_process|spawn|execFile)\b`)},
	{CapExec, regexp.MustCompile("`[^`]+`")}, // shell backtick command substitution
	{CapExec, regexp.MustCompile(`\$\([^)]+\)`)}, // shell $(...) command substitution
	// env
	{CapEnv, regexp.MustCompile(`(?i)\b(getenv|os\.environ|process\.env|ENV\[)`)},
	{CapEnv, regexp.MustCompile(`(?i)\bos\.Getenv\b`)},
	{CapEnv, regexp.MustCompile(`\$\{?[A-Z_][A-Z0-9_]*\}?`)}, // $VAR / ${VAR} in shell
}

// hostRe extracts hostnames from URLs to enrich network evidence.
var hostRe = regexp.MustCompile(`(?i)https?://([a-z0-9.\-]+)`)

// Scan walks dir, parses SKILL.md, and detects observed capabilities.
func Scan(dir string) (*Result, error) {
	r := &Result{
		Declared: map[Capability]bool{},
		Observed: map[Capability][]Evidence{},
	}

	if err := r.parseSkillMD(dir); err != nil {
		return nil, err
	}

	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// Never scan skillsig's own emitted artifacts.
		switch rel {
		case manifest.ManifestFile, manifest.SBOMFile, "bundle.sig":
			return nil
		}
		if !scanExt[strings.ToLower(filepath.Ext(rel))] {
			return nil
		}
		r.Files = append(r.Files, rel)
		return r.scanFile(path, rel)
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(r.Files)
	return r, nil
}

// parseSkillMD reads SKILL.md frontmatter into the declared capability set.
func (r *Result) parseSkillMD(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		return err
	}
	fm := extractFrontmatter(b)
	var f skillFrontmatter
	if len(fm) > 0 {
		_ = yaml.Unmarshal(fm, &f) // a malformed frontmatter just means nothing declared
	}
	r.SkillName = f.Name
	r.SkillVersion = f.Version
	if r.SkillVersion == "" {
		r.SkillVersion = "0.0.0"
	}
	r.Entry = f.Entry
	if r.Entry == "" {
		r.Entry = "SKILL.md"
	}

	// 1) Explicit capabilities block wins when present. A class set explicitly
	//    (to true OR false) is "locked": the coarse allowed-tools inference in
	//    step 2 must not override an author's deliberate `false` declaration —
	//    that is exactly the negative declaration verify needs to catch a lie.
	locked := map[Capability]bool{}
	if c := f.Capabilities; c != nil {
		lockExplicit(r.Declared, locked, CapNet, c.Net)
		lockExplicit(r.Declared, locked, CapFSWrite, c.FSWrite)
		lockExplicit(r.Declared, locked, CapExec, c.Exec)
		lockExplicit(r.Declared, locked, CapEnv, c.Env)
		r.DeclaredHosts = manifest.SortStrings(c.Hosts)
		r.DeclaredEnv = manifest.SortStrings(c.EnvVars)
		if len(c.Hosts) > 0 {
			r.Declared[CapNet] = true
			locked[CapNet] = true
		}
		if len(c.EnvVars) > 0 {
			r.Declared[CapEnv] = true
			locked[CapEnv] = true
		}
	}

	// 2) allowed-tools is inferred as a coarse capability hint for classes the
	//    author did NOT pin explicitly. A skill that lists Bash-style tools is
	//    declaring exec; WebFetch declares net; Write/Edit declares fs-write.
	inferFromAllowedTools(r.Declared, locked, f.AllowedTools)
	return nil
}

// lockExplicit records an explicit (true or false) declaration and marks the
// class as locked so inference can't change it.
func lockExplicit(decl map[Capability]bool, locked map[Capability]bool, c Capability, v *bool) {
	if v == nil {
		return
	}
	decl[c] = *v
	locked[c] = true
}

// inferFromAllowedTools maps harness tool names to capability classes, but never
// touches a class the author locked with an explicit capabilities declaration.
func inferFromAllowedTools(decl map[Capability]bool, locked map[Capability]bool, allowed string) {
	a := strings.ToLower(allowed)
	if a == "" {
		return
	}
	set := func(c Capability) {
		if !locked[c] {
			decl[c] = true
		}
	}
	if strings.Contains(a, "bash") || strings.Contains(a, "shell") || strings.Contains(a, "exec") {
		set(CapExec)
	}
	if strings.Contains(a, "webfetch") || strings.Contains(a, "websearch") ||
		strings.Contains(a, "fetch") || strings.Contains(a, "http") {
		set(CapNet)
	}
	if strings.Contains(a, "write") || strings.Contains(a, "edit") {
		set(CapFSWrite)
	}
}

// scanFile applies every signature to each line of a file, recording evidence.
//
// Markdown is handled specially: a SKILL.md (or any .md) is mostly prose plus a
// YAML frontmatter declaration block, neither of which is executable. Matching
// capability signals against prose would produce misleading evidence (e.g. the
// word "curl" in a sentence). For Markdown we therefore scan ONLY the lines
// inside fenced ``` code blocks, and skip the leading --- frontmatter entirely.
func (r *Result) scanFile(path, rel string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	isMarkdown := strings.EqualFold(filepath.Ext(rel), ".md")

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	inFrontmatter := false
	frontmatterDone := false
	inCodeFence := false

	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		if isMarkdown {
			// Detect and skip a leading YAML frontmatter block.
			if lineNo == 1 && trimmed == "---" {
				inFrontmatter = true
				continue
			}
			if inFrontmatter {
				if trimmed == "---" {
					inFrontmatter = false
					frontmatterDone = true
				}
				continue
			}
			_ = frontmatterDone
			// Toggle on fenced code blocks; only scan lines inside one.
			if strings.HasPrefix(trimmed, "```") {
				inCodeFence = !inCodeFence
				continue
			}
			if !inCodeFence {
				continue
			}
		}

		// Skip obvious full-line comments to cut false positives, but keep
		// scanning shell `#!` shebangs and inline code.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "* ") {
			continue
		}
		for _, sig := range signatures {
			loc := sig.re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			snippet := strings.TrimSpace(line)
			if len(snippet) > 120 {
				snippet = snippet[:117] + "..."
			}
			r.Observed[sig.cap] = append(r.Observed[sig.cap], Evidence{
				Capability: sig.cap,
				File:       rel,
				Line:       lineNo,
				Snippet:    snippet,
			})
			if sig.cap == CapNet {
				for _, h := range hostRe.FindAllStringSubmatch(line, -1) {
					r.observedHost(h[1])
				}
			}
		}
	}
	return sc.Err()
}

func (r *Result) observedHost(h string) {
	r.observedHosts = appendUnique(r.observedHosts, h)
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// ObservedHosts returns the network hosts found during the scan.
func (r *Result) ObservedHosts() []string {
	return manifest.SortStrings(r.observedHosts)
}

// DeclaredCapabilities builds a manifest.Capabilities block from what the skill
// DECLARED in its SKILL.md frontmatter. This is what `skillsig manifest` writes:
// the author's stated permission set, which `verify` later diffs against the
// observed scan. When the author left a class undeclared, the corresponding
// field is empty (and network resolves to "none").
func (r *Result) DeclaredCapabilities() manifest.Capabilities {
	// exec/env are initialized to empty (non-nil) slices so the emitted JSON is
	// always a [] for those required schema fields, never a null.
	c := manifest.Capabilities{Exec: []string{}, Env: []string{}}

	if r.Declared[CapFSWrite] {
		c.Filesystem.Write = []string{"**"}
	}
	c.Filesystem.Read = []string{"**"} // reads are not a tracked risk class

	if r.Declared[CapNet] {
		hosts := r.DeclaredHosts
		if len(hosts) == 0 {
			hosts = []string{"*"}
		}
		c.Network = manifest.Network{Hosts: hosts}
	} else {
		c.Network = manifest.Network{None: true}
	}

	if r.Declared[CapExec] {
		c.Exec = []string{"*"}
	}
	if r.Declared[CapEnv] {
		env := r.DeclaredEnv
		if len(env) == 0 {
			env = []string{"*"}
		}
		c.Env = env
	}
	return c
}

// ObservedCapabilities builds a manifest.Capabilities block reflecting what the
// static scan actually FOUND. `skillsig manifest` shows this to the author so
// they can confirm/declare it.
func (r *Result) ObservedCapabilities() manifest.Capabilities {
	c := manifest.Capabilities{}
	if len(r.Observed[CapFSWrite]) > 0 {
		c.Filesystem.Write = []string{"**"}
	}
	if len(r.Observed[CapNet]) > 0 {
		hosts := r.ObservedHosts()
		if len(hosts) == 0 {
			hosts = []string{"*"}
		}
		c.Network = manifest.Network{Hosts: hosts}
	} else {
		c.Network = manifest.Network{None: true}
	}
	if len(r.Observed[CapExec]) > 0 {
		c.Exec = []string{"*"}
	}
	if len(r.Observed[CapEnv]) > 0 {
		c.Env = []string{"*"}
	}
	return c
}

// ObservedCaps returns the set of capability classes that fired, sorted.
func (r *Result) ObservedCaps() []Capability {
	var out []Capability
	for _, c := range []Capability{CapNet, CapFSWrite, CapExec, CapEnv} {
		if len(r.Observed[c]) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// extractFrontmatter returns the bytes between the leading --- fences, or nil.
func extractFrontmatter(b []byte) []byte {
	s := string(b)
	s = strings.TrimPrefix(s, "\uFEFF") // strip UTF-8 BOM if present
	if !strings.HasPrefix(s, "---") {
		return nil
	}
	rest := s[3:]
	// Find the closing fence at the start of a line.
	idx := strings.Index(rest, "\n---")
	if idx < 0 {
		return nil
	}
	return []byte(rest[:idx])
}
