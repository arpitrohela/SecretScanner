package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	patterns = map[string]*regexp.Regexp{
		"AWS":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"GitHub":  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		"Google":  regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"API":     regexp.MustCompile(`(?i)api[_-]?key['":\s=]+[a-zA-Z0-9\-_]{20,}`),
		"DB":      regexp.MustCompile(`(?i)(mongodb|postgresql|mysql)://[^\s'"]+`),
		"Private": regexp.MustCompile(`-----BEGIN.*PRIVATE KEY-----`),
		"Bearer":  regexp.MustCompile(`Bearer\s+[a-zA-Z0-9\-._~+/]+=*`),
		"CC":      regexp.MustCompile(`\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b`),
	}
	contextRe   = regexp.MustCompile(`(?i)(password|token|key|secret|auth|credential)`)
	b64Re       = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	hexRe       = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	excludeRe   = regexp.MustCompile(`(?i)(example|test|dummy|fake|sample|placeholder)`)
	whitelist   = map[string]bool{}
	found       = map[string]bool{}
)

func entropy(s string) float64 {
	m := make(map[rune]float64)
	for _, r := range s {
		m[r]++
	}
	l := float64(len(s))
	e := 0.0
	for _, c := range m {
		p := c / l
		e -= p * math.Log2(p)
	}
	return e
}

func luhn(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		n := int(s[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n = n%10 + n/10
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func validate(secret, stype string) bool {
	switch stype {
	case "AWS":
		return len(secret) == 20 && strings.HasPrefix(secret, "AKIA")
	case "GitHub":
		client := &http.Client{Timeout: 2 * time.Second}
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("Authorization", "token "+secret)
		resp, err := client.Do(req)
		return err == nil && resp.StatusCode != 401
	case "CC":
		return luhn(secret)
	}
	return true
}

func preFilter(content string) string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(strings.TrimSpace(line), "//") &&
			!strings.HasPrefix(strings.TrimSpace(line), "#") &&
			!strings.Contains(line, "<!--") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func contextScore(line string, pos int) float64 {
	score := 0.0
	before := line[:pos]
	after := line[pos:]
	
	if contextRe.MatchString(before) {
		score += 5.0
	}
	if strings.Contains(before, "=") || strings.Contains(before, ":") {
		score += 3.0
	}
	if strings.Contains(after, "\n") || strings.Contains(after, ";") {
		score += 1.0
	}
	// Entropy boost for validated secrets
	return score
}

func entropyFilter(content string) []string {
	var suspects []string
	words := strings.Fields(content)
	
	for _, word := range words {
		if len(word) >= 20 && entropy(word) >= 4.5 {
			if b64Re.MatchString(word) || hexRe.MatchString(word) {
				suspects = append(suspects, word)
			}
		}
	}
	return suspects
}

func scan(content, file string) {
	lines := strings.Split(content, "\n")
	
	// Layer 1: Basic pattern matching
	for name, re := range patterns {
		matches := re.FindAllStringIndex(content, -1)
		for _, match := range matches {
			secret := content[match[0]:match[1]]
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte(secret)))[:8]
			
			if found[hash] || whitelist[hash] {
				continue
			}
			
			// Layer 2: Multi-layer validation
			if secondLayerValidate(secret, name, content, match, lines, file) {
				found[hash] = true
			}
		}
	}
}

func secondLayerValidate(secret, stype, content string, match []int, lines []string, file string) bool {
	// Pre-filtering
	filteredContent := preFilter(content)
	if !strings.Contains(filteredContent, secret) {
		return false
	}
	
	// Exclude obvious test data
	if excludeRe.MatchString(secret) {
		return false
	}
	
	// Find line and context
	lineNum := 1
	charCount := 0
	var currentLine string
	for _, line := range lines {
		if charCount+len(line) >= match[0] {
			currentLine = line
			break
		}
		charCount += len(line) + 1
		lineNum++
	}
	
	// Context analysis
	score := contextScore(currentLine, match[0]-charCount)
	
	// Entropy analysis
	if entropy(secret) >= 4.5 {
		score += 2.0
	}
	
	// Context score threshold
	if score < 8.5 {
		return false
	}
	
	// Validation layer
	if !validate(secret, stype) {
		return false
	}
	
	fmt.Printf("%s: %s in %s:%d (score:%.1f)\n", stype, secret, file, lineNum, score)
	return true
}

func isText(path string, forceAll bool) bool {
	if forceAll {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".txt" || ext == ".log" || ext == ".json" || ext == ".xml" || 
		ext == ".yaml" || ext == ".yml" || ext == ".conf" || ext == ".cfg" || 
		ext == ".go" || ext == ".rs" || ext == ".py" || ext == ".js" || 
		ext == ".java" || ext == ".c" || ext == ".cpp" || ext == ".sh" || 
		ext == ".sql" || ext == ".md" || ext == ".html" || ext == ".css"
}

func main() {
	root := "."
	forceAll := false
	
	args := os.Args[1:]
	for _, arg := range args {
		if arg == "--all" {
			forceAll = true
		} else if arg == "--whitelist" {
			fmt.Print("Enter hash to whitelist: ")
			var hash string
			fmt.Scanln(&hash)
			whitelist[hash] = true
		} else {
			root = arg
		}
	}

	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isText(path, forceAll) {
			return nil
		}
		if content, err := os.ReadFile(path); err == nil {
			scan(string(content), path)
		}
		return nil
	})
}
