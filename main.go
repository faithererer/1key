package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// =========================
// ====== CONFIG ===========
const (
	defaultEncryptionKey = "0DWb9ZMkN0s9Ks9EBsXExYUtPYr6YTAB" // 32 bytes
	serverPort           = "80"

	programID      = "67c8c14f5f17a83b745e3f82"
	sheerIDBaseURL = "https://services.sheerid.com"
	mySheerIDURL   = "https://my.sheerid.com"

	defaultHCaptchaSecret = ""
	hCaptchaVerifyURL     = "https://hcaptcha.com/siteverify"

	// 代理（直连请设 PROXY_URL=direct 或留空）
	defaultProxyURL = "http://127.0.0.1:33300"

	// Linux Do OAuth
	linuxDoAuthURL         = "https://connect.linux.do/oauth2/authorize"
	linuxDoTokenURL        = "https://connect.linux.do/oauth2/token"
	linuxDoUserInfoURL     = "https://connect.linux.do/api/user"
	defaultLDOClientID     = "SJptqzeDMkogEThaYDyJIrdmF47DN9LT"
	defaultLDOClientSecret = ""
)

func getRandomUserAgentDynamic() string {
	mathrand.Seed(time.Now().UnixNano())

	browsers := []struct {
		name     string
		versions []int
		os       []string
		template string
	}{
		{
			name:     "chrome",
			versions: []int{128, 129, 130, 131},
			os:       []string{"Windows NT 10.0", "Windows NT 11.0", "Macintosh; Intel Mac OS X 10_15_7", "X11; Linux x86_64"},
			template: "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36",
		},
		{
			name:     "firefox",
			versions: []int{130, 131, 132, 133},
			os:       []string{"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10.15", "X11; Linux x86_64"},
			template: "Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0",
		},
		{
			name:     "edge",
			versions: []int{128, 129, 130, 131},
			os:       []string{"Windows NT 10.0; Win64; x64", "Windows NT 11.0; Win64; x64"},
			template: "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 Edg/%d.0.0.0",
		},
	}

	// 随机选择浏览器
	browser := browsers[mathrand.Intn(len(browsers))]

	// 随机选择版本和操作系统
	version := browser.versions[mathrand.Intn(len(browser.versions))]
	os := browser.os[mathrand.Intn(len(browser.os))]

	// 根据浏览器类型生成UA
	switch browser.name {
	case "chrome":
		return fmt.Sprintf(browser.template, os, version)
	case "firefox":
		return fmt.Sprintf(browser.template, os, version, version)
	case "edge":
		return fmt.Sprintf(browser.template, os, version, version)
	default:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	}
}

type SchoolConfig struct {
	ID         string
	IDExtended string
	Name       string
	IDPOrigin  string
	IDPReferer string
	Username   string
	Password   string
}

// School configurations
var schoolConfigs = map[string]SchoolConfig{
	"utexas": {
		ID:         "3696",
		IDExtended: "3696",
		Name:       "The University of Texas at Austin (Austin, TX)",
		IDPOrigin:  "https://enterprise.login.utexas.edu",
		IDPReferer: "https://enterprise.login.utexas.edu/",
		Username:   "",
		Password:   "",
	},
	"utexas1": {
		ID:         "5819067",
		IDExtended: "5819067",
		Name:       "University of Texas System (Austin, TX)",
		IDPOrigin:  "https://enterprise.login.utexas.edu",
		IDPReferer: "https://enterprise.login.utexas.edu/",
		Username:   "",
		Password:   "",
	},
}

// School rotation state
var (
	schoolRotator struct {
		mu      sync.Mutex
		current int
		schools []string
	}
)

func initSchoolRotator() {
	schoolRotator.schools = []string{"utexas", "utexas1"}
	schoolRotator.current = 0
}

func getNextSchool() string {
	schoolRotator.mu.Lock()
	defer schoolRotator.mu.Unlock()

	school := schoolRotator.schools[schoolRotator.current]
	schoolRotator.current = (schoolRotator.current + 1) % len(schoolRotator.schools)
	return school
}

// 队列/心跳/复验相关参数
const (
	queueStartInterval      = 5 * time.Second   // 每 2 分钟启动 1 个任务（可按需调整）
	pingMinInterval         = 5 * time.Second   // 小于该间隔的连续 ping => 立刻移除
	pingMaxInterval         = 10 * time.Second  // 推荐客户端 <10s ；后端实际宽限见 pingGrace
	pingGrace               = 12 * time.Second  // 超过该时长没 ping => 移除
	metricsPushInterval     = 10 * time.Second  // SSE metrics 推送间隔
	reaperTick              = 3 * time.Second   // 清理检查周期
	captchaInitialDelay     = 60 * time.Second  // 约 1 分钟后开始复验
	captchaInterval         = 120 * time.Second // 此后每 120 秒请求一次
	captchaResponseDeadline = 60 * time.Second  // 发起复验后最晚 60s 内回传，否则移除

	// 新增：作业保留时间和最大并发工作者数
	jobRetentionTime = 1 * time.Hour
	maxWorkers       = 10
)

// 允许用环境变量覆盖
func cfg(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func proxyFromConfig() func(*http.Request) (*url.URL, error) {
	raw := cfg("PROXY_URL", defaultProxyURL)
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "direct") || strings.EqualFold(raw, "none") {
		return nil // 不使用代理
	}
	u, err := url.Parse(raw)
	if err != nil {
		log.Printf("WARN: invalid PROXY_URL %q, fallback to DIRECT: %v", raw, err)
		return nil
	}
	return http.ProxyURL(u)
}

// =========================
// ====== DATA =============
type CompleteVerificationRequest struct {
	VerificationID string `json:"verificationId"`
	HCaptchaToken  string `json:"hcaptchaToken"`
	// Optional fields
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Email     string `json:"email,omitempty"`
	BirthDate string `json:"birthDate,omitempty"`
	SchoolID  string `json:"schoolId,omitempty"`
}

type CompleteVerificationResponse struct {
	Success        bool                   `json:"success"`
	Message        string                 `json:"message"`
	VerificationID string                 `json:"verificationId"`
	PersonalInfo   PersonalInfo           `json:"personalInfo"`
	FinalStatus    map[string]interface{} `json:"finalStatus,omitempty"`
	RedirectURL    string                 `json:"redirectUrl,omitempty"`
	Cookies        string                 `json:"cookies,omitempty"`
	Logs           []string               `json:"logs"`
	Error          string                 `json:"error,omitempty"`
	SchoolUsed     string                 `json:"schoolUsed,omitempty"`
}

type PersonalInfo struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	BirthDate string `json:"birthDate"`
}

// ===== Linux Do OAuth user =====
type LinuxDoUser struct {
	ID             int64             `json:"id"`
	Sub            string            `json:"sub"`
	Username       string            `json:"username"`
	Login          string            `json:"login"`
	Name           string            `json:"name"`
	Email          string            `json:"email"`
	AvatarTemplate string            `json:"avatar_template"`
	AvatarURL      string            `json:"avatar_url"`
	Active         bool              `json:"active"`
	TrustLevel     int               `json:"trust_level"`
	Silenced       bool              `json:"silenced"`
	ExternalIDs    map[string]string `json:"external_ids"`
	APIKey         string            `json:"api_key"`
}

// ===== OAuth state tracking =====
var oauthStates = struct {
	mu sync.Mutex
	m  map[string]time.Time
}{m: map[string]time.Time{}}

func makeState(n int) string {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}

// ===== Session storage (in-memory) =====
type sessionData struct {
	User    LinuxDoUser
	CSRF    string
	Expires time.Time
}

var sessStore = struct {
	mu sync.Mutex
	m  map[string]sessionData
}{m: map[string]sessionData{}}

func isHTTPS(r *http.Request) bool {
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		return xf == "https"
	}
	return r.TLS != nil
}

func newSession(u LinuxDoUser, ttl time.Duration) (sid, csrf string) {
	b1 := make([]byte, 32)
	b2 := make([]byte, 16)
	_, _ = crand.Read(b1)
	_, _ = crand.Read(b2)
	sid = hex.EncodeToString(b1)
	csrf = hex.EncodeToString(b2)
	sessStore.mu.Lock()
	sessStore.m[sid] = sessionData{User: u, CSRF: csrf, Expires: time.Now().Add(ttl)}
	sessStore.mu.Unlock()
	return
}

func getSession(r *http.Request) (LinuxDoUser, sessionData, bool) {
	c, err := r.Cookie("ldo_sess")
	if err != nil || c.Value == "" {
		return LinuxDoUser{}, sessionData{}, false
	}
	sessStore.mu.Lock()
	sd, ok := sessStore.m[c.Value]
	if ok && time.Now().After(sd.Expires) {
		ok = false
		delete(sessStore.m, c.Value)
	}
	sessStore.mu.Unlock()
	if !ok {
		return LinuxDoUser{}, sessionData{}, false
	}
	return sd.User, sd, true
}

func sessionGC(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			sessStore.mu.Lock()
			for k, v := range sessStore.m {
				if now.After(v.Expires) {
					delete(sessStore.m, k)
				}
			}
			sessStore.mu.Unlock()
		}
	}
}

func deriveRedirectURI(r *http.Request) string {
	scheme := "http"
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		scheme = xf
	} else if r.TLS != nil {
		scheme = ""
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host + "/api/oauth/callback"
}

// ===== LinuxDo rate limiter =====
type LinuxDoLimiter struct {
	mu     sync.Mutex
	counts map[int64]int
}

func (l *LinuxDoLimiter) Allow(id int64) bool {
	if id <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts == nil {
		l.counts = map[int64]int{}
	}
	if l.counts[id] >= 1 {
		return false
	}
	l.counts[id]++
	return true
}

func (l *LinuxDoLimiter) ResetLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.mu.Lock()
			l.counts = map[int64]int{}
			l.mu.Unlock()
		}
	}
}

var ldLimiter LinuxDoLimiter

type SheerIDPersonalInfoRequest struct {
	FirstName             string                 `json:"firstName"`
	LastName              string                 `json:"lastName"`
	BirthDate             string                 `json:"birthDate"`
	Email                 string                 `json:"email"`
	PhoneNumber           string                 `json:"phoneNumber"`
	Organization          Organization           `json:"organization"`
	DeviceFingerprintHash string                 `json:"deviceFingerprintHash"`
	Locale                string                 `json:"locale"`
	Metadata              map[string]interface{} `json:"metadata"`
}

type Organization struct {
	ID         int    `json:"id"`
	IDExtended string `json:"idExtended"`
	Name       string `json:"name"`
}

type hCaptchaVerifyResp struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Credit      bool     `json:"credit"`
	ErrorCodes  []string `json:"error-codes"`
}

// =========================
// ====== TEST DATA ========
type TestDataGenerator struct{ rng *mathrand.Rand }

func NewTestDataGenerator() *TestDataGenerator {
	return &TestDataGenerator{rng: mathrand.New(mathrand.NewSource(time.Now().UnixNano()))}
}
func (g *TestDataGenerator) GenerateDeviceFingerprint() string {
	b := make([]byte, 16)
	g.rng.Read(b)
	return hex.EncodeToString(b)
}
func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
func (g *TestDataGenerator) GenerateName() (string, string) {
	firstStarts := []string{"Jo", "Ja", "Mi", "Sa", "Da", "Em", "Ol", "Wil", "Be", "Lu"}
	firstMiddles := []string{"na", "cha", "ri", "so", "li", "ma", "ro", "vi", "be", "la"}
	firstEnds := []string{"n", "ah", "el", "ra", "id", "us", "as", "ie", "ta", "es"}
	lastStarts := []string{"Sm", "John", "Wil", "Brow", "Jon", "Gar", "Mill", "Dav", "Rod", "Mart"}
	lastMiddles := []string{"ith", "son", "lia", "vic", "mar", "dez", "sen", "lin", "nor", "car"}
	lastEnds := []string{"ez", "er", "son", "ton", "ley", "man", "ski"}

	first := firstStarts[g.rng.Intn(len(firstStarts))]
	for i := 0; i < g.rng.Intn(3); i++ {
		first += firstMiddles[g.rng.Intn(len(firstMiddles))]
	}
	first += firstEnds[g.rng.Intn(len(firstEnds))]

	last := lastStarts[g.rng.Intn(len(lastStarts))]
	for i := 0; i < g.rng.Intn(3); i++ {
		last += lastMiddles[g.rng.Intn(len(lastMiddles))]
	}
	last += lastEnds[g.rng.Intn(len(lastEnds))]

	return capitalize(first), capitalize(last)
}
func (g *TestDataGenerator) GenerateEmail(firstName, lastName string) string {
	domains := []string{"yahoo.com", "outlook.com", "hotmail.com"}
	suffix := fmt.Sprintf("%04d", g.rng.Intn(1000000))
	suffix1 := fmt.Sprintf("%04d", g.rng.Intn(1000000))
	domain := domains[g.rng.Intn(len(domains))]
	return fmt.Sprintf("%s.%s%s%s@%s", strings.ToLower(firstName), strings.ToLower(lastName), suffix, suffix1, domain)
}
func (g *TestDataGenerator) GenerateBirthDate() string {
	now := time.Now()
	age := 18 + g.rng.Intn(8)
	return fmt.Sprintf("%04d-%02d-%02d", now.Year()-age, 1+g.rng.Intn(12), 1+g.rng.Intn(28))
}

// =========================
// ====== SSO ==============
type SSORequest struct {
	VerificationID string `json:"verificationId"`
	SchoolID       string `json:"schoolId"`
	InitialCookies string `json:"initialCookies,omitempty"`
}
type SSOResponse struct {
	Success     bool     `json:"success"`
	Message     string   `json:"message"`
	Cookies     string   `json:"cookies,omitempty"`
	RedirectURL string   `json:"redirectUrl,omitempty"`
	Logs        []string `json:"logs"`
	Error       string   `json:"error,omitempty"`
}

// =========================
// ====== HELPERS ==========
func userIP(r *http.Request) string {
	if cip := r.Header.Get("CF-Connecting-IP"); cip != "" {
		return cip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func cookiesForURLString(jar http.CookieJar, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	cookies := jar.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}
	var pairs []string
	for _, c := range cookies {
		pairs = append(pairs, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	return strings.Join(pairs, "; ")
}
func decrypt(encodedString string, keyString string) ([]byte, error) {
	key := []byte(keyString)
	ciphertext, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
func newHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		Proxy:               proxyFromConfig(),
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// =========================
// ===== hCaptcha ==========
func verifyHCaptcha(token, remoteIP string) (bool, string, error) {
	secret := cfg("HCAPTCHA_SECRET", defaultHCaptchaSecret)
	if token == "" {
		return false, "missing-token", errors.New("empty hcaptcha token")
	}
	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequest("POST", hCaptchaVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, "request-build-failed", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", getRandomUserAgentDynamic())
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, "request-failed", err
	}
	defer resp.Body.Close()
	var vr hCaptchaVerifyResp
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		return false, "bad-response", err
	}
	if !vr.Success {
		reason := "verification-failed"
		if len(vr.ErrorCodes) > 0 {
			reason = strings.Join(vr.ErrorCodes, ",")
		}
		return false, reason, nil
	}
	return true, "", nil
}

// =========================
// ====== CORE FLOW ========
func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func performCompleteVerification(ctx context.Context, req CompleteVerificationRequest, client *http.Client, logs *[]string, logFn func(string)) CompleteVerificationResponse {
	var defaultUserAgent = getRandomUserAgentDynamic()
	addLog := func(msg string) {
		line := fmt.Sprintf("[%s] %s", nowUTC(), msg)
		log.Println(msg)
		*logs = append(*logs, line)
		if logFn != nil {
			logFn(line)
		}
	}
	generator := NewTestDataGenerator()

	addLog("SheerID Verifier Turbo V1.1.1003")

	// 填充缺省数据
	if req.FirstName == "" || req.LastName == "" {
		req.FirstName, req.LastName = generator.GenerateName()
		addLog(fmt.Sprintf("Generated name: %s %s", req.FirstName, req.LastName))
	}
	if req.Email == "" {
		req.Email = generator.GenerateEmail(req.FirstName, req.LastName)
		addLog(fmt.Sprintf("Generated email: %s", req.Email))
	}
	if req.BirthDate == "" {
		req.BirthDate = generator.GenerateBirthDate()
		addLog(fmt.Sprintf("Generated birth date: %s", req.BirthDate))
	}

	// Get next school in rotation
	schoolKey := getNextSchool()
	schoolConfig := schoolConfigs[schoolKey]
	req.SchoolID = schoolConfig.ID
	// addLog(fmt.Sprintf("Using school: %s", schoolConfig.Name))

	personalInfo := PersonalInfo{FirstName: req.FirstName, LastName: req.LastName, Email: req.Email, BirthDate: req.BirthDate}

	addLog(fmt.Sprintf("Starting complete verification for %s %s", req.FirstName, req.LastName))

	// Step 0
	addLog("Step 0: Checking verification ID status...")
	statusURL := fmt.Sprintf("%s/rest/v2/verification/%s", mySheerIDURL, req.VerificationID)
	statusReq, _ := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	statusReq.Header.Set("User-Agent", defaultUserAgent)
	statusReq.Header.Set("Accept", "application/json")
	statusResp, err := client.Do(statusReq)
	if err != nil {
		return createCompleteErrorResponse(*logs, "Failed to check verification status", err, personalInfo, schoolKey)
	}
	defer statusResp.Body.Close()
	var statusData map[string]interface{}
	if err := json.NewDecoder(statusResp.Body).Decode(&statusData); err != nil {
		return createCompleteErrorResponse(*logs, "Failed to parse status response", err, personalInfo, schoolKey)
	}
	currentStep, _ := statusData["currentStep"].(string)
	if currentStep == "error" {
		errorMsg := "Verification not found"
		if msg, ok := statusData["systemErrorMessage"].(string); ok {
			errorMsg = msg
		}
		return createCompleteErrorResponse(*logs, fmt.Sprintf("Verification error: %s, Try again 3 hours later.", errorMsg), nil, personalInfo, schoolKey)
	}
	if currentStep != "collectStudentPersonalInfo" {
		return createCompleteErrorResponse(*logs, fmt.Sprintf("Unexpected verification step: %s, Try again 3 hours later.", currentStep), nil, personalInfo, schoolKey)
	}
	addLog("Verification ID valid.")

	// Step 1
	addLog("Step 1: Submitting personal information to SheerID...")
	deviceFingerprint := generator.GenerateDeviceFingerprint()

	// Convert string ID to int for organization ID
	orgID := 686 // default
	switch schoolKey {
	case "utexas":
		orgID = 3696
	case "utexas1":
		orgID = 5819067
	}

	personalInfoReq := SheerIDPersonalInfoRequest{
		FirstName: req.FirstName, LastName: req.LastName, BirthDate: req.BirthDate, Email: req.Email,
		Organization:          Organization{ID: orgID, IDExtended: schoolConfig.IDExtended, Name: schoolConfig.Name},
		DeviceFingerprintHash: deviceFingerprint,
		Locale:                "en-US",
		Metadata: map[string]interface{}{
			"marketConsentValue": false,
			"refererUrl":         fmt.Sprintf("%s/verify/%s/?verificationId=%s", sheerIDBaseURL, programID, req.VerificationID),
			"verificationId":     req.VerificationID,
		},
	}
	personalInfoJSON, _ := json.Marshal(personalInfoReq)
	personalInfoURL := fmt.Sprintf("%s/rest/v2/verification/%s/step/collectStudentPersonalInfo", sheerIDBaseURL, req.VerificationID)
	personalInfoHTTPReq, _ := http.NewRequestWithContext(ctx, "POST", personalInfoURL, bytes.NewBuffer(personalInfoJSON))
	personalInfoHTTPReq.Header.Set("Content-Type", "application/json")
	personalInfoHTTPReq.Header.Set("User-Agent", defaultUserAgent)
	personalInfoHTTPReq.Header.Set("Accept", "application/json")
	personalInfoResp, err := client.Do(personalInfoHTTPReq)
	if err != nil {
		return createCompleteErrorResponse(*logs, "Failed to submit personal information", err, personalInfo, schoolKey)
	}
	defer personalInfoResp.Body.Close()
	if personalInfoResp.StatusCode != 200 {
		body, _ := io.ReadAll(personalInfoResp.Body)
		return createCompleteErrorResponse(*logs, fmt.Sprintf("Step 1 failed: %s", string(body)), nil, personalInfo, schoolKey)
	}
	var step1Data map[string]interface{}
	if err := json.NewDecoder(personalInfoResp.Body).Decode(&step1Data); err != nil {
		return createCompleteErrorResponse(*logs, "Failed to parse Step 1 response", err, personalInfo, schoolKey)
	}
	addLog("Step 1 completed.")
	if step1Data["currentStep"] == "error" {
		return createCompleteErrorResponse(*logs, "Please use *USA* IP to create your verify link from goo.gle/freepro. Try again 3 hours later.", nil, personalInfo, schoolKey)
	}

	// Step 2
	addLog("Step 2: Starting SSO authentication flow...")
	ssoResult := performSSOFlowInternal(ctx, ctx, req.VerificationID, req.SchoolID, schoolKey, client, logs, defaultUserAgent)
	if !ssoResult.Success {
		return createCompleteErrorResponse(*logs, ssoResult.Message, errors.New(ssoResult.Error), personalInfo, schoolKey)
	}
	addLog("Step 2 completed: SSO authentication successful")

	// Step 3
	addLog("Step 3: Checking final verification status...")
	var finalStatus map[string]interface{}
	success := false
	maxAttempts := 4
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return createCompleteErrorResponse(*logs, "Context cancelled", ctx.Err(), personalInfo, schoolKey)
		case <-time.After(2 * time.Second):
		}
		finalStatusReq, _ := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
		finalStatusReq.Header.Set("User-Agent", defaultUserAgent)
		finalStatusReq.Header.Set("Accept", "application/json")
		finalStatusResp, err := client.Do(finalStatusReq)
		if err != nil {
			continue
		}
		if err := json.NewDecoder(finalStatusResp.Body).Decode(&finalStatus); err != nil {
			finalStatusResp.Body.Close()
			continue
		}
		finalStatusResp.Body.Close()
		cs, _ := finalStatus["currentStep"].(string)
		addLog(fmt.Sprintf("Status check %d/%d: %s", attempt, maxAttempts, cs))
		if cs == "success" {
			success = true
			addLog("✅ Verification successful!")
			if redirectURL, ok := finalStatus["redirectUrl"].(string); ok {
				addLog(fmt.Sprintf("Redirect URL: %s", redirectURL))
			}
			break
		} else if cs == "rejected" || cs == "error" {
			break
		}
	}
	if !success {
		addLog("⏱️ Verification timeout - max attempts reached")
	}
	cookiesString := cookiesForURLString(client.Jar, sheerIDBaseURL)
	response := CompleteVerificationResponse{
		Success:        success,
		VerificationID: req.VerificationID,
		PersonalInfo:   personalInfo,
		FinalStatus:    finalStatus,
		Cookies:        cookiesString,
		Logs:           *logs,
		SchoolUsed:     schoolConfig.Name,
	}
	if success {
		response.Message = "Verification completed successfully!"
		if redirectURL, ok := finalStatus["redirectUrl"].(string); ok {
			response.RedirectURL = redirectURL
		}
	} else {
		response.Message = "Verification failed or timed out"
		if cs, ok := finalStatus["currentStep"].(string); ok {
			response.Message = fmt.Sprintf("Verification failed at step: %s", cs)
		}
	}
	return response
}
func performSSOFlowInternal(xctx context.Context, ctx context.Context, verificationID, schoolID, schoolKey string, client *http.Client, logs *[]string, defaultUserAgent string) SSOResponse {
	addLog := func(msg string) {
		line := fmt.Sprintf("[%s] %s", nowUTC(), msg)
		log.Println(msg)
		*logs = append(*logs, line)
	}

	schoolConfig, ok := schoolConfigs[schoolKey]
	if !ok {
		return SSOResponse{Success: false, Message: fmt.Sprintf("No configuration for school %s", schoolKey), Logs: *logs}
	}

	// Step 1-3: Initial redirects (same for all schools)
	addLog("Step 1: Getting redirect URL...")
	ssoStepURL := fmt.Sprintf("%s/rest/v2/verification/%s/step/sso", sheerIDBaseURL, verificationID)
	initialReferer := fmt.Sprintf("%s/verify/%s/?verificationId=%s", sheerIDBaseURL, programID, verificationID)
	req, _ := http.NewRequestWithContext(ctx, "GET", ssoStepURL, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Referer", initialReferer)
	resp, err := client.Do(req)
	if err != nil {
		return createErrorResponse(*logs, "Step 1 request failed", err, nil, nil)
	}
	defer resp.Body.Close()
	shibbolethUrl, err := getRedirectURL(resp, sheerIDBaseURL)
	if err != nil {
		return createErrorResponse(*logs, "Step 1: Did not receive a redirect.", err, resp, nil)
	}
	addLog("Step 1 successful")

	req, _ = http.NewRequestWithContext(ctx, "GET", shibbolethUrl, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Referer", initialReferer)
	resp, err = client.Do(req)
	if err != nil {
		return createErrorResponse(*logs, "Step 2 failed", err, nil, nil)
	}
	defer resp.Body.Close()
	idpUrl, err := getRedirectURL(resp, shibbolethUrl)
	if err != nil {
		return createErrorResponse(*logs, "Step 2: No redirect URL found", err, nil, nil)
	}
	addLog("Step 2 successful")

	req, _ = http.NewRequestWithContext(ctx, "GET", idpUrl, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Referer", sheerIDBaseURL+"/")
	resp, err = client.Do(req)
	if err != nil {
		return createErrorResponse(*logs, "Step 3 failed", err, nil, nil)
	}
	defer resp.Body.Close()
	loginPageUrl, err := getRedirectURL(resp, idpUrl)
	if err != nil {
		return createErrorResponse(*logs, "Step 3: No redirect found", err, nil, nil)
	}
	addLog("Step 3 successful")

	// School-specific login handling
	var samlHtml string

	switch schoolKey {
	case "utexas", "utexas1":
		// UT Austin has a multi-step flow with localStorage handling
		samlHtml, err = handleUTAustinLogin(ctx, client, loginPageUrl, schoolConfig, addLog, defaultUserAgent)
		if err != nil {
			return createErrorResponse(*logs, fmt.Sprintf("SSO 1 login failed: %v", err), err, nil, nil)
		}
	default:
		return createErrorResponse(*logs, "Unsupported school", nil, nil, nil)
	}

	// Extract SAML response and relay state
	samlResponseRegex := regexp.MustCompile(`name="SAMLResponse"\s+value="([^"]+)"`)
	relayStateRegex := regexp.MustCompile(`name="RelayState"\s+value="([^"]+)"`)
	samlMatches := samlResponseRegex.FindStringSubmatch(samlHtml)
	if len(samlMatches) < 2 {
		return createErrorResponse(*logs, "SAML Response not found. Login likely failed.", nil, nil, nil)
	}
	samlResponse := html.UnescapeString(samlMatches[1])
	addLog("SAML Response found.")
	relayState := ""
	if relayMatches := relayStateRegex.FindStringSubmatch(samlHtml); len(relayMatches) > 1 {
		relayState = html.UnescapeString(relayMatches[1])
	}

	// Submit SAML response to SheerID
	samlData := url.Values{}
	samlData.Set("SAMLResponse", samlResponse)
	samlData.Set("RelayState", relayState)
	samlSubmitURL := fmt.Sprintf("%s/Shibboleth.sso/SAML2/POST", sheerIDBaseURL)
	req, _ = http.NewRequestWithContext(ctx, "POST", samlSubmitURL, strings.NewReader(samlData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Origin", schoolConfig.IDPOrigin)
	req.Header.Set("Referer", schoolConfig.IDPReferer)
	resp, err = client.Do(req)
	if err != nil {
		return createErrorResponse(*logs, "Failed to submit SAML", nil, nil, nil)
	}
	defer resp.Body.Close()
	finalHandshakeURL, err := getRedirectURL(resp, sheerIDBaseURL)
	if err != nil {
		return createErrorResponse(*logs, "Did not receive final redirect after SAML POST.", nil, nil, nil)
	}
	addLog("SAML submitted successfully. Received redirect.")

	// Final handshake
	req, _ = http.NewRequestWithContext(ctx, "GET", finalHandshakeURL, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Referer", schoolConfig.IDPReferer)
	resp, err = client.Do(req)
	if err != nil {
		return createErrorResponse(*logs, "Final handshake failed", nil, nil, nil)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		addLog(fmt.Sprintf("WARN: Final handshake returned status %d, but proceeding anyway.", resp.StatusCode))
	} else {
		addLog("SSO flow completed successfully.")
	}
	return SSOResponse{Success: true, Message: "Flow Completed Successfully", Logs: *logs}
}

func handleUTAustinLogin(ctx context.Context, client *http.Client, loginPageUrl string, config SchoolConfig, addLog func(string), defaultUserAgent string) (string, error) {
	// Step 4a: GET the initial login page (execution=e1s1)
	addLog("SSO x2 Step4a: Getting initial login page...")
	req, _ := http.NewRequestWithContext(ctx, "GET", loginPageUrl, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Referer", sheerIDBaseURL+"/")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get initial login page: %v", err)
	}
	var bodyBytes []byte
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// Step 4b: Submit localStorage information (mimics JavaScript behavior)
	addLog("SSO x2 Step4b: Submitting localStorage data...")
	localStorageData := url.Values{}
	localStorageData.Set("shib_idp_ls_exception.shib_idp_session_ss", "")
	localStorageData.Set("shib_idp_ls_success.shib_idp_session_ss", "true")
	localStorageData.Set("shib_idp_ls_value.shib_idp_session_ss", "")
	localStorageData.Set("shib_idp_ls_exception.shib_idp_persistent_ss", "")
	localStorageData.Set("shib_idp_ls_success.shib_idp_persistent_ss", "true")
	localStorageData.Set("shib_idp_ls_value.shib_idp_persistent_ss", "")
	localStorageData.Set("shib_idp_ls_supported", "true")
	localStorageData.Set("_eventId_proceed", "")

	req, _ = http.NewRequestWithContext(ctx, "POST", loginPageUrl, strings.NewReader(localStorageData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Origin", config.IDPOrigin)
	req.Header.Set("Referer", loginPageUrl)
	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit localStorage: %v", err)
	}

	// Should redirect to execution=e1s2
	loginFormUrl, err := getRedirectURL(resp, loginPageUrl)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("no redirect after localStorage submission: %v", err)
	}

	// Step 5a: GET the actual login form (execution=e1s2)
	addLog("SSO x2 Step5a: Getting login form...")
	req, _ = http.NewRequestWithContext(ctx, "GET", loginFormUrl, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Referer", loginPageUrl)
	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get login form: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// Step 5b: Submit credentials
	addLog("SSO x2 Step5b: Submitting credentials...")
	loginData := url.Values{}
	loginData.Set("j_username", config.Username)
	loginData.Set("j_password", config.Password)
	loginData.Set("_eventId_proceed", "Sign in")

	req, _ = http.NewRequestWithContext(ctx, "POST", loginFormUrl, strings.NewReader(loginData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Origin", config.IDPOrigin)
	req.Header.Set("Referer", loginFormUrl)
	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit credentials: %v", err)
	}

	// Should redirect to execution=e1s3
	sessionPageUrl, err := getRedirectURL(resp, loginFormUrl)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("no redirect after login: %v", err)
	}

	// Step 6a: GET the session saving page (execution=e1s3)
	addLog("SSO x2 Step6a: Getting session page...")
	req, _ = http.NewRequestWithContext(ctx, "GET", sessionPageUrl, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Referer", loginFormUrl)
	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get session page: %v", err)
	}
	bodyBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	sessionPageHtml := string(bodyBytes)

	// Extract the session value from JavaScript (if present)
	// Look for writeLocalStorage("shib_idp_session_ss", "...")
	sessionValue := ""
	sessionRegex := regexp.MustCompile(`writeLocalStorage\("shib_idp_session_ss",\s*"([^"]+)"`)
	if matches := sessionRegex.FindStringSubmatch(sessionPageHtml); len(matches) > 1 {
		sessionValue = matches[1]
	}

	// Step 6b: Submit session data
	addLog("SSO x2 Step6b: Submitting session data...")
	sessionData := url.Values{}
	sessionData.Set("shib_idp_ls_exception.shib_idp_session_ss", "")
	sessionData.Set("shib_idp_ls_success.shib_idp_session_ss", "true")
	if sessionValue != "" {
		// Note: In real scenario, this would be stored in localStorage
		// But since we're server-side, we just acknowledge it
	}
	sessionData.Set("_eventId_proceed", "")

	req, _ = http.NewRequestWithContext(ctx, "POST", sessionPageUrl, strings.NewReader(sessionData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Origin", config.IDPOrigin)
	req.Header.Set("Referer", sessionPageUrl)
	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit session data: %v", err)
	}

	// This should return the SAML response
	bodyBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	samlHtml := string(bodyBytes)

	addLog("SSO 1 login flow completed")
	return samlHtml, nil
}

func getRedirectURL(resp *http.Response, baseURL string) (string, error) {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			// Handle relative URLs
			if !strings.HasPrefix(location, "http") {
				base, err := url.Parse(baseURL)
				if err != nil {
					return "", err
				}
				rel, err := url.Parse(location)
				if err != nil {
					return "", err
				}
				location = base.ResolveReference(rel).String()
			}
			return location, nil
		}
	}
	return "", fmt.Errorf("no redirect found, status: %d", resp.StatusCode)
}

// =========================
// ====== QUEUE + SSE ======
type JobStatus string

const (
	JobQueued  JobStatus = "queued"
	JobRunning JobStatus = "running"
	JobDone    JobStatus = "done"
	JobFailed  JobStatus = "failed"
	JobRemoved JobStatus = "removed" // 被踢出队列/超时/违规
)

type Job struct {
	ID        string
	Req       CompleteVerificationRequest
	Created   time.Time
	Completed time.Time // 新增：完成时间

	status JobStatus
	result *CompleteVerificationResponse

	subscribers map[chan string]struct{}

	lastPing time.Time

	ctx    context.Context
	cancel context.CancelFunc

	// captcha 复验
	nextCaptchaAt     time.Time
	challengeID       string
	challengePending  bool
	challengeDeadline time.Time
}

type JobManager struct {
	mu         sync.RWMutex
	jobs       map[string]*Job
	activeJobs map[string]*Job // 新增：仅活跃作业
	queueChan  chan *Job

	lastStart time.Time
	interval  time.Duration

	addSubCh chan struct {
		id string
		ch chan string
	}
	delSubCh chan struct {
		id string
		ch chan string
	}
	broadcast chan struct {
		id   string
		line string
	}
}

var JM *JobManager

func NewJobManager() *JobManager {
	return &JobManager{
		jobs:       make(map[string]*Job),
		activeJobs: make(map[string]*Job), // 初始化活跃作业映射
		queueChan:  make(chan *Job, 2000),
		interval:   queueStartInterval,

		addSubCh: make(chan struct {
			id string
			ch chan string
		}),
		delSubCh: make(chan struct {
			id string
			ch chan string
		}),
		broadcast: make(chan struct {
			id   string
			line string
		}, 4000),
	}
}

// 新增：清理作业函数
func (jm *JobManager) cleanupJob(jobID string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if job, ok := jm.jobs[jobID]; ok {
		// 清理订阅者
		for ch := range job.subscribers {
			close(ch)
		}
		job.subscribers = nil

		// 确保取消context
		if job.cancel != nil {
			job.cancel()
		}

		// 从映射中删除
		delete(jm.jobs, jobID)
		delete(jm.activeJobs, jobID)

		log.Printf("Cleaned up job %s", jobID)
	}
}

func (jm *JobManager) send(id, typ, data string) {
	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", typ, data)
	select {
	case jm.broadcast <- struct{ id, line string }{id, msg}:
	default:
	}
}

func (jm *JobManager) setStatus(job *Job, s JobStatus) {
	jm.mu.Lock()
	job.status = s

	// 更新活跃作业映射
	if s == JobDone || s == JobFailed || s == JobRemoved {
		job.Completed = time.Now()
		delete(jm.activeJobs, job.ID)
	}
	jm.mu.Unlock()

	jm.send(job.ID, "status", string(s))
}

func (jm *JobManager) Enqueue(job *Job) {
	jm.mu.Lock()
	jm.jobs[job.ID] = job
	jm.activeJobs[job.ID] = job // 添加到活跃作业
	job.status = JobQueued
	job.lastPing = time.Now()
	jm.mu.Unlock()
	jm.send(job.ID, "status", string(JobQueued))
	jm.queueChan <- job
}

func (jm *JobManager) CancelJob(job *Job, reason string) {
	jm.mu.Lock()
	if job.status == JobDone || job.status == JobFailed || job.status == JobRemoved {
		jm.mu.Unlock()
		return
	}

	// 如果任务还在排队或刚开始运行就被取消，考虑回退 lastStart
	if job.status == JobQueued || job.status == JobRunning {
		// 如果 lastStart 在未来，将其拉回到现在
		now := time.Now()
		if jm.lastStart.After(now) {
			jm.lastStart = now
		}
	}

	job.status = JobRemoved
	job.Completed = time.Now()
	delete(jm.activeJobs, job.ID)
	if job.cancel != nil {
		job.cancel()
	}
	jm.mu.Unlock()
	jm.send(job.ID, "error", reason)
	jm.send(job.ID, "status", string(JobRemoved))
	jm.send(job.ID, "end", "EOF")
}

func isTimeoutError(result CompleteVerificationResponse) bool {
	return strings.Contains(result.Message, "Verification timeout - max attempts reached") ||
		strings.Contains(result.Message, "⏱️ Verification timeout")
}

func (jm *JobManager) execute(job *Job) {
	// Check if job is already canceled before starting
	jm.mu.RLock()
	if job.status != JobQueued {
		jm.mu.RUnlock()
		return
	}
	jm.mu.RUnlock()

	// Create context with timeout
	jm.mu.Lock()
	job.ctx, job.cancel = context.WithTimeout(context.Background(), 15*time.Minute)
	jm.mu.Unlock()

	// Ensure cleanup happens no matter what
	defer func() {
		if job.cancel != nil {
			job.cancel()
		}
		// Ensure job is marked as complete even if there's a panic
		if r := recover(); r != nil {
			log.Printf("Panic in execute for job %s: %v", job.ID, r)
			jm.mu.Lock()
			if job.status == JobRunning {
				job.status = JobFailed
				job.Completed = time.Now()
				delete(jm.activeJobs, job.ID)
			}
			jm.mu.Unlock()
			jm.send(job.ID, "error", fmt.Sprintf("Internal error: %v", r))
			jm.send(job.ID, "status", string(JobFailed))
			jm.send(job.ID, "end", "EOF")
		}
	}()

	// Check if context is already canceled
	select {
	case <-job.ctx.Done():
		log.Printf("Job %s context already canceled before execution", job.ID)
		jm.setStatus(job, JobRemoved)
		jm.send(job.ID, "error", "Job canceled before execution")
		jm.send(job.ID, "end", "EOF")
		return
	default:
	}

	jm.setStatus(job, JobRunning)
	jm.send(job.ID, "log", fmt.Sprintf("[%s] Queue: task started", nowUTC()))

	client := newHTTPClient()
	logs := []string{}
	logFn := func(line string) {
		// Check if context is still valid before sending
		select {
		case <-job.ctx.Done():
			return
		default:
			jm.send(job.ID, "log", line)
		}
	}

	// Perform the verification with context checking
	result := performCompleteVerification(job.ctx, job.Req, client, &logs, logFn)

	// Check if job was canceled during execution
	jm.mu.RLock()
	currentStatus := job.status
	jm.mu.RUnlock()

	if currentStatus == JobRemoved {
		// Job was canceled, don't process results
		log.Printf("Job %s was canceled during execution, skipping result processing", job.ID)
		jm.send(job.ID, "end", "EOF")
		return
	}

	// Store result
	jm.mu.Lock()
	job.result = &result
	jm.mu.Unlock()

	client.CloseIdleConnections()

	// Handle results
	if result.Success {
		jm.setStatus(job, JobDone)
		if result.RedirectURL != "" {
			jm.send(job.ID, "result", result.RedirectURL)
		}
		jm.send(job.ID, "end", "EOF")
	} else {
		// Check if it was a context cancellation error
		if strings.Contains(result.Error, "context canceled") || strings.Contains(result.Error, "context deadline exceeded") {
			log.Printf("Job %s failed due to context cancellation/timeout", job.ID)
			jm.setStatus(job, JobRemoved)
			jm.send(job.ID, "error", "Job timed out or was canceled")
			jm.send(job.ID, "end", "EOF")
			// Don't apply delays for context cancellation
			return
		}

		jm.setStatus(job, JobFailed)
		msg := result.Message
		if result.Error != "" {
			msg += " | " + result.Error
		}
		jm.send(job.ID, "error", msg)

		// Check if it's a timeout error and apply delay
		if isTimeoutError(result) {
			log.Printf("Timeout error detected, waiting 5 minutes before next job")
			jm.mu.Lock()
			jm.lastStart = time.Now().Add(5 * time.Minute)
			jm.mu.Unlock()
		} else {
			log.Printf("Non-timeout error, proceeding immediately to next job")
			jm.mu.Lock()
			jm.lastStart = time.Now().Add(-jm.interval)
			jm.mu.Unlock()
		}
		jm.send(job.ID, "end", "EOF")
	}
}

func (jm *JobManager) computeMetrics(jobID string) (queueLen int, ahead int, estWait time.Duration) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	// 使用activeJobs而不是所有jobs（修复4：Inefficient Reaper Loop）
	for _, j := range jm.activeJobs {
		if j.status == JobQueued {
			queueLen++
		}
	}

	target, ok := jm.jobs[jobID]
	if !ok {
		return queueLen, 0, 0
	}
	if target.status == JobDone || target.status == JobFailed || target.status == JobRemoved {
		return queueLen, 0, 0
	}

	// 按创建时间统计在前的待处理数
	type pair struct{ t time.Time }
	var earlier []pair
	for _, j := range jm.activeJobs {
		if j.status == JobQueued && j.Created.Before(target.Created) {
			earlier = append(earlier, pair{j.Created})
		}
	}
	ahead = len(earlier)

	// 估算等待：距离下一可启动时刻 + ahead * interval
	nextStart := jm.lastStart.Add(jm.interval)
	base := time.Until(nextStart)
	if base < 0 {
		base = 0
	}
	estWait = base + time.Duration(ahead)*jm.interval
	return
}

func (jm *JobManager) issueCaptcha(job *Job) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	if job.status != JobQueued && job.status != JobRunning {
		return
	}
	if job.challengePending {
		return
	}
	// 生成 challenge
	job.challengeID = fmt.Sprintf("%x", mathrand.Uint64())
	job.challengePending = true
	job.challengeDeadline = time.Now().Add(captchaResponseDeadline)
	jm.send(job.ID, "captcha", fmt.Sprintf(`{"challengeId":"%s"}`, job.challengeID))
	jm.send(job.ID, "log", fmt.Sprintf("[%s] captcha challenge issued", nowUTC()))
}

func (jm *JobManager) Run(ctx context.Context) {
	// 修复2：使用工作池模式
	workerChan := make(chan *Job, maxWorkers)

	// 启动固定数量的工作者
	for i := 0; i < maxWorkers; i++ {
		go func(workerID int) {
			log.Printf("Worker %d started", workerID)
			for job := range workerChan {
				// Reserve slot here, after job is picked from queue
				sleep := jm.reserveLaunchSlot()
				if sleep > 0 {
					time.Sleep(sleep)
				}
				jm.execute(job)
			}
			log.Printf("Worker %d stopped", workerID)
		}(i)
	}

	// 队列调度器
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(workerChan)
				return
			case job := <-jm.queueChan:
				select {
				case workerChan <- job:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// 订阅/广播循环
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case sub := <-jm.addSubCh:
				jm.mu.Lock()
				if job, ok := jm.jobs[sub.id]; ok {
					if job.subscribers == nil {
						job.subscribers = map[chan string]struct{}{}
					}
					job.subscribers[sub.ch] = struct{}{}
				}
				jm.mu.Unlock()
			case unsub := <-jm.delSubCh:
				jm.mu.Lock()
				if job, ok := jm.jobs[unsub.id]; ok && job.subscribers != nil {
					delete(job.subscribers, unsub.ch)
					close(unsub.ch)
				}
				jm.mu.Unlock()
			case b := <-jm.broadcast:
				jm.mu.RLock()
				if job, ok := jm.jobs[b.id]; ok && job.subscribers != nil {
					for ch := range job.subscribers {
						select {
						case ch <- b.line:
						default:
						}
					}
				}
				jm.mu.RUnlock()
			}
		}
	}()

	// 清理 + 复验调度器
	ticker := time.NewTicker(reaperTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()

			// 修复4：仅遍历活跃作业进行心跳和captcha检查
			jm.mu.RLock()
			activeIDs := make([]string, 0, len(jm.activeJobs))
			for id := range jm.activeJobs {
				activeIDs = append(activeIDs, id)
			}
			jm.mu.RUnlock()

			for _, id := range activeIDs {
				jm.mu.RLock()
				job := jm.activeJobs[id]
				jm.mu.RUnlock()
				if job == nil {
					continue
				}

				// 过期心跳
				if job.status == JobQueued || job.status == JobRunning {
					if now.Sub(job.lastPing) > pingGrace {
						jm.CancelJob(job, "keepalive timeout (no ping)")
						continue
					}
				}
				// 首次复验调度
				if (job.status == JobQueued || job.status == JobRunning) && job.nextCaptchaAt.IsZero() && now.Sub(job.Created) >= captchaInitialDelay {
					jm.mu.Lock()
					job.nextCaptchaAt = now
					jm.mu.Unlock()
				}
				// 发起复验
				if (job.status == JobQueued || job.status == JobRunning) && !job.nextCaptchaAt.IsZero() && now.After(job.nextCaptchaAt) && !job.challengePending {
					jm.issueCaptcha(job)
					jm.mu.Lock()
					job.nextCaptchaAt = now.Add(captchaInterval)
					jm.mu.Unlock()
				}
				// 复验超时
				if job.challengePending && now.After(job.challengeDeadline) {
					jm.CancelJob(job, "captcha timeout")
					continue
				}
			}

			// 修复6：作业过期清理（针对已完成的作业）
			jm.mu.RLock()
			allIDs := make([]string, 0, len(jm.jobs))
			for id := range jm.jobs {
				allIDs = append(allIDs, id)
			}
			jm.mu.RUnlock()

			for _, id := range allIDs {
				jm.mu.RLock()
				job := jm.jobs[id]
				jm.mu.RUnlock()
				if job == nil {
					continue
				}

				// 清理已完成且超过保留时间的作业
				if (job.status == JobDone || job.status == JobFailed || job.status == JobRemoved) &&
					!job.Completed.IsZero() && now.Sub(job.Completed) > jobRetentionTime {
					jm.cleanupJob(job.ID)
				}
			}
		}
	}
}

func (jm *JobManager) reserveLaunchSlot() time.Duration {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	now := time.Now()
	if jm.lastStart.IsZero() {
		// 让第一个任务立即开始
		jm.lastStart = now
		return 0
	}
	next := jm.lastStart.Add(jm.interval)
	if now.After(next) {
		// 已过间隔，立即开始，并把 lastStart 设为现在
		jm.lastStart = now
		return 0
	}
	// 预占下一个启动时间点，并返回需要睡多久
	jm.lastStart = next
	return time.Until(next)
}

func (jm *JobManager) AddSubscriber(id string, ch chan string) {
	jm.addSubCh <- struct {
		id string
		ch chan string
	}{id: id, ch: ch}
}
func (jm *JobManager) RemoveSubscriber(id string, ch chan string) {
	jm.delSubCh <- struct {
		id string
		ch chan string
	}{id: id, ch: ch}
}

// =========================
// ====== HTTP =============

func writeCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func quickPrecheck(ctx context.Context, client *http.Client, verificationID string, defaultUserAgent string) (ok bool, step string, err error) {
	statusURL := fmt.Sprintf("%s/rest/v2/verification/%s", mySheerIDURL, verificationID)
	req, _ := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	var statusData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&statusData); err != nil {
		return false, "", err
	}
	step, _ = statusData["currentStep"].(string)
	if step == "collectStudentPersonalInfo" {
		return true, step, nil
	}
	return false, step, nil
}

func queueSubmitHandler(w http.ResponseWriter, r *http.Request) {
	writeCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// OAuth session & CSRF
	user, sd, ok := getSession(r)
	if !ok {
		respondWithError(w, "OAuth required", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-CSRF") != sd.CSRF {
		respondWithError(w, "CSRF mismatch", http.StatusForbidden)
		return
	}
	if !ldLimiter.Allow(user.ID) {
		respondWithError(w, "Rate limit: this linuxDoId can submit only 1 time per 5 minutes", http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req CompleteVerificationRequest
	if dec, derr := decrypt(string(body), cfg("ENCRYPTION_KEY", defaultEncryptionKey)); derr == nil {
		if err := json.Unmarshal(dec, &req); err != nil {
			respondWithError(w, "Invalid JSON in decrypted payload", http.StatusBadRequest)
			return
		}
	} else {
		if err := json.Unmarshal(body, &req); err != nil {
			respondWithError(w, "Invalid request format", http.StatusBadRequest)
			return
		}
	}
	if req.VerificationID == "" {
		respondWithError(w, "Missing verificationId", http.StatusBadRequest)
		return
	}
	if req.HCaptchaToken != "" {
		ok, reason, verr := verifyHCaptcha(req.HCaptchaToken, userIP(r))
		if verr != nil {
			respondWithError(w, "hCaptcha verification error: "+reason, http.StatusBadGateway)
			return
		}
		if !ok {
			respondWithError(w, "hCaptcha verification failed: "+reason, http.StatusForbidden)
			return
		}
	}

	client := newHTTPClient()
	ctx := r.Context()
	ok, step, err := quickPrecheck(ctx, client, req.VerificationID, getRandomUserAgentDynamic())
	if err != nil {
		respondWithError(w, "Precheck failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if !ok {
		respondWithError(w, fmt.Sprintf("Precheck not passed, currentStep=%s. Try again later.", step), http.StatusConflict)
		return
	}

	log.Printf("[%s] %s from %s", nowUTC(), req.VerificationID, userIP(r))
	jobID := fmt.Sprintf("%s-%d", req.VerificationID, time.Now().UnixNano())
	job := &Job{
		ID:          jobID,
		Req:         req,
		Created:     time.Now(),
		status:      JobQueued,
		subscribers: make(map[chan string]struct{}),
	}
	JM.Enqueue(job)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"jobId": jobID, "status": string(JobQueued)})
}

func queueStreamHandler(w http.ResponseWriter, r *http.Request) {
	writeCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	JM.mu.RLock()
	job, ok := JM.jobs[id]
	JM.mu.RUnlock()
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream not supported", http.StatusInternalServerError)
		return
	}

	ch := make(chan string, 128)
	JM.AddSubscriber(id, ch)
	defer JM.RemoveSubscriber(id, ch)

	// 初始状态
	fmt.Fprintf(w, "event: status\ndata: %s\n\n", job.status)
	flusher.Flush()

	heartbeat := time.NewTicker(25 * time.Second)
	metricsTicker := time.NewTicker(metricsPushInterval)
	defer heartbeat.Stop()
	defer metricsTicker.Stop()

	notify := r.Context().Done()
	for {
		select {
		case line := <-ch:
			_, _ = io.WriteString(w, line)
			flusher.Flush()
		case <-metricsTicker.C:
			qLen, ahead, est := JM.computeMetrics(id)
			_, _ = io.WriteString(w, fmt.Sprintf("event: metrics\ndata: {\"queueLen\":%d,\"ahead\":%d,\"estWaitSec\":%d}\n\n", qLen, ahead, int(est.Seconds())))
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = io.WriteString(w, "event: ping\ndata: ok\n\n")
			flusher.Flush()
		case <-notify:
			return
		}
	}
}

// 客户端 keepalive ping
func queuePingHandler(w http.ResponseWriter, r *http.Request) {
	writeCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		respondWithError(w, "missing id", http.StatusBadRequest)
		return
	}

	JM.mu.Lock()
	job, ok := JM.jobs[id]
	if !ok {
		JM.mu.Unlock()
		respondWithError(w, "job not found", http.StatusNotFound)
		return
	}
	now := time.Now()
	if !job.lastPing.IsZero() {
		dt := now.Sub(job.lastPing)
		if dt < pingMinInterval {
			JM.mu.Unlock()
			JM.CancelJob(job, "ping too frequent (<5s)")
			respondWithError(w, "ping too frequent", http.StatusTooManyRequests)
			return
		}
	}
	job.lastPing = now
	JM.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// 客户端提交 captcha token
func queueCaptchaHandler(w http.ResponseWriter, r *http.Request) {
	writeCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	chID := r.URL.Query().Get("challenge")
	if id == "" || chID == "" {
		respondWithError(w, "missing id or challenge", http.StatusBadRequest)
		return
	}

	JM.mu.RLock()
	job, ok := JM.jobs[id]
	JM.mu.RUnlock()
	if !ok {
		respondWithError(w, "job not found", http.StatusNotFound)
		return
	}

	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		respondWithError(w, "bad json", http.StatusBadRequest)
		return
	}
	if payload.Token == "" {
		respondWithError(w, "missing token", http.StatusBadRequest)
		return
	}

	// 验证 hCaptcha
	ok2, reason, verr := verifyHCaptcha(payload.Token, userIP(r))
	if verr != nil {
		respondWithError(w, "captcha verify error: "+verr.Error(), http.StatusBadGateway)
		return
	}
	if !ok2 {
		JM.CancelJob(job, "captcha failed: "+reason)
		respondWithError(w, "captcha failed: "+reason, http.StatusForbidden)
		return
	}

	// 校验 challengeId
	JM.mu.Lock()
	if !job.challengePending || job.challengeID != chID {
		JM.mu.Unlock()
		respondWithError(w, "invalid challenge", http.StatusConflict)
		return
	}
	job.challengePending = false
	job.challengeID = ""
	job.challengeDeadline = time.Time{}
	JM.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// =========================
// ====== BOOT ============

// GET /api/oauth/start -> returns authUrl and state
func oauthStartHandler(w http.ResponseWriter, r *http.Request) {
	writeCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	redirect := deriveRedirectURI(r)
	state := makeState(16)

	oauthStates.mu.Lock()
	oauthStates.m[state] = time.Now()
	oauthStates.mu.Unlock()

	u, _ := url.Parse(linuxDoAuthURL)
	q := u.Query()
	q.Set("client_id", cfg("LDO_CLIENT_ID", defaultLDOClientID))
	q.Set("redirect_uri", redirect)
	q.Set("response_type", "code")
	q.Set("scope", "user")
	q.Set("state", state)
	u.RawQuery = q.Encode()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"authUrl": u.String(),
		"state":   state,
	})
}

// GET /api/oauth/callback -> exchange token, fetch userinfo, set HttpOnly cookie
func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	writeCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		respondWithError(w, "missing code/state", http.StatusBadRequest)
		return
	}
	// validate state within 10 minutes
	oauthStates.mu.Lock()
	ts, ok := oauthStates.m[state]
	if ok && time.Since(ts) > 10*time.Minute {
		ok = false
	}
	if ok {
		delete(oauthStates.m, state)
	}
	oauthStates.mu.Unlock()
	if !ok {
		respondWithError(w, "invalid state", http.StatusBadRequest)
		return
	}

	redirect := deriveRedirectURI(r)
	form := url.Values{
		"client_id":     {cfg("LDO_CLIENT_ID", defaultLDOClientID)},
		"client_secret": {cfg("LDO_CLIENT_SECRET", defaultLDOClientSecret)},
		"code":          {code},
		"redirect_uri":  {redirect},
		"grant_type":    {"authorization_code"},
	}
	tokReq, _ := http.NewRequest("POST", linuxDoTokenURL, strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil {
		respondWithError(w, "token request failed", http.StatusBadGateway)
		return
	}
	defer tokResp.Body.Close()
	var tok map[string]interface{}
	if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
		respondWithError(w, "bad token response", http.StatusBadGateway)
		return
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		respondWithError(w, "missing access_token", http.StatusBadGateway)
		return
	}

	uiReq, _ := http.NewRequest("GET", linuxDoUserInfoURL, nil)
	uiReq.Header.Set("Authorization", "Bearer "+access)
	uiResp, err := http.DefaultClient.Do(uiReq)
	if err != nil {
		respondWithError(w, "userinfo request failed", http.StatusBadGateway)
		return
	}
	defer uiResp.Body.Close()
	bodyBytes, err := io.ReadAll(uiResp.Body)
	if err != nil {
		respondWithError(w, "failed to read userinfo", http.StatusBadGateway)
		return
	}
	fmt.Printf("userinfo raw response: %s\n", string(bodyBytes))
	var user LinuxDoUser
	if err := json.Unmarshal(bodyBytes, &user); err != nil {
		respondWithError(w, "bad userinfo", http.StatusForbidden)
		return
	}

	// create 30-min session
	sid, _ := newSession(user, 30*time.Minute)
	http.SetCookie(w, &http.Cookie{
		Name:     "ldo_sess",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 60,
	})

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<script>
  (function(){
    try { if (window.opener && !window.opener.closed) {
      window.opener.postMessage({type:"linuxdo_oauth", ok:true}, "*");
    } } catch(e) {}
    window.close();
  })();
</script>
<body style="font:14px system-ui">Login successful. You can close this window.</body>`)
}

// GET /api/oauth/me -> return user & csrf if logged in
func oauthMeHandler(w http.ResponseWriter, r *http.Request) {
	writeCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, sd, ok := getSession(r)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		_ = json.NewEncoder(w).Encode(map[string]any{"loggedIn": false})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"loggedIn": true,
		"user":     user,
		"csrf":     sd.CSRF,
	})
}

func main() {
	// Initialize school rotator
	initSchoolRotator()

	encKey := cfg("ENCRYPTION_KEY", defaultEncryptionKey)
	if len(encKey) != 32 {
		log.Fatal("FATAL: ENCRYPTION_KEY must be exactly 32 bytes long.")
	}
	if cfg("HCAPTCHA_SECRET", defaultHCaptchaSecret) == defaultHCaptchaSecret {
		log.Println("WARN: HCAPTCHA_SECRET uses default placeholder.")
	}

	// 启动队列
	JM = NewJobManager()
	go JM.Run(context.Background())

	go ldLimiter.ResetLoop(context.Background())
	go sessionGC(context.Background())

	// 路由

	http.HandleFunc("/api/oauth/start", oauthStartHandler)
	http.HandleFunc("/api/oauth/callback", oauthCallbackHandler)
	http.HandleFunc("/api/oauth/me", oauthMeHandler)
	http.HandleFunc("/api/queue/submit", queueSubmitHandler)
	http.HandleFunc("/api/queue/stream", queueStreamHandler)
	http.HandleFunc("/api/queue/ping", queuePingHandler)
	http.HandleFunc("/api/queue/captcha", queueCaptchaHandler)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeCORS(w, r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok","endpoints":["/api/queue/submit","/api/queue/stream","/api/queue/ping","/api/queue/captcha","/api/complete-verification"]}`)
	})

	log.Printf("Starting server on :%s with school rotation (Colorado State, UT Austin)...", serverPort)
	if err := http.ListenAndServe(":"+serverPort, nil); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// =========================
// ====== ERRORS ==========
func respondWithError(w http.ResponseWriter, message string, code int) {
	log.Printf("Responding with error [%d]: %s", code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func createCompleteErrorResponse(logs []string, message string, err error, personalInfo PersonalInfo, schoolUsed string) CompleteVerificationResponse {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	log.Printf("ERROR: %s - %s", message, errMsg)
	return CompleteVerificationResponse{Success: false, Message: message, PersonalInfo: personalInfo, Logs: logs, Error: errMsg, SchoolUsed: schoolConfigs[schoolUsed].Name}
}
func createErrorResponse(logs []string, message string, err error, resp *http.Response, _ interface{}) SSOResponse {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	line := fmt.Sprintf("[%s] ERROR: %s - %s", nowUTC(), message, errMsg)
	log.Println(line)
	logs = append(logs, line)
	return SSOResponse{Success: false, Message: message, Logs: logs, Error: errMsg}
}
