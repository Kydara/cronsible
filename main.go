package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bcampbell/fuzzytime"
	_ "github.com/mattn/go-sqlite3"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "cronsible_session"
	maxOutputBytes    = 64 * 1024
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var hostInputRe = regexp.MustCompile(`^[A-Za-z0-9.:-]+$`)

type Config struct {
	Addr                string
	DataDir             string
	DBPath              string
	InventoryPath       string
	KnownHostsPath      string
	KeysDir             string
	AnsiblePath         string
	AnsiblePlaybookPath string
}

type App struct {
	cfg        Config
	db         *sql.DB
	templates  *template.Template
	cron       *cron.Cron
	runner     *Runner
	jobEntries map[int64]cron.EntryID
	mu         sync.Mutex
}

type Runner struct {
	cfg   Config
	db    *sql.DB
	queue chan int64
	stop  chan struct{}
	wg    sync.WaitGroup
}

type User struct {
	ID       int64
	Username string
}

type Host struct {
	ID                 int64
	Name               string
	Address            string
	Port               int
	User               string
	HostKey            string
	StrictHostChecking bool
	GroupNames         string
}

type Group struct {
	ID          int64
	Name        string
	Description string
	HostCount   int
}

type Job struct {
	ID         int64
	Name       string
	TargetType string
	TargetID   int64
	Schedule   string
	Command    string
	Format     string
	Enabled    bool
}

type JobView struct {
	Job
	TargetName string
	NextRun    string
}

type Key struct {
	ID             int64
	Name           string
	PrivateKeyPath string
	PublicKeyPath  string
	PublicKey      string
	CreatedAt      int64
}

type JobRun struct {
	ID         int64
	JobID      int64
	JobName    string
	StartedAt  int64
	FinishedAt int64
	Status     string
	ExitCode   int
	Output     string
}

type TemplateData struct {
	Title            string
	HideNav          bool
	User             *User
	Error            string
	Info             string
	ContentTemplate  string
	CurrentPath      string
	Hosts            []Host
	Groups           []Group
	Jobs             []JobView
	Keys             []Key
	Runs             []JobRun
	ActiveKeyID      int64
	InventoryPath    string
	InventoryContent string
	SelectedHost     *Host
	SelectedGroup    *Group
	SelectedJob      *Job
	SelectedTarget   string
	SelectedGroupIDs map[int64]bool
	ScheduleHint     string
	JobFormat        string
	Setup            bool
}

func main() {
	cfg := loadConfig()
	if err := ensureDirs(cfg); err != nil {
		log.Fatalf("init dirs: %v", err)
	}

	db, err := openDB(cfg.DBPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := migrate(db); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	tmpl, err := parseTemplates()
	if err != nil {
		log.Fatalf("templates: %v", err)
	}

	app := &App{
		cfg:        cfg,
		db:         db,
		templates:  tmpl,
		cron:       cron.New(),
		jobEntries: make(map[int64]cron.EntryID),
	}
	app.runner = &Runner{
		cfg:   cfg,
		db:    db,
		queue: make(chan int64, 100),
		stop:  make(chan struct{}),
	}
	app.runner.Start()
	if err := app.ReloadAllJobs(); err != nil {
		log.Printf("scheduler init: %v", err)
	}
	app.cron.Start()

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: app.routes(),
	}

	log.Printf("cronsible listening on %s", cfg.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}

func loadConfig() Config {
	dataDir := os.Getenv("CRONSIBLE_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	ansiblePath := os.Getenv("CRONSIBLE_ANSIBLE_PATH")
	if ansiblePath == "" {
		ansiblePath = "ansible"
	}
	ansiblePlaybookPath := os.Getenv("CRONSIBLE_ANSIBLE_PLAYBOOK_PATH")
	if ansiblePlaybookPath == "" {
		ansiblePlaybookPath = "ansible-playbook"
	}
	addr := os.Getenv("CRONSIBLE_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	return Config{
		Addr:                addr,
		DataDir:             dataDir,
		DBPath:              filepath.Join(dataDir, "cronsible.db"),
		InventoryPath:       filepath.Join(dataDir, "inventory.ini"),
		KnownHostsPath:      filepath.Join(dataDir, "known_hosts"),
		KeysDir:             filepath.Join(dataDir, "keys"),
		AnsiblePath:         ansiblePath,
		AnsiblePlaybookPath: ansiblePlaybookPath,
	}
}

func ensureDirs(cfg Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.KeysDir, 0o700); err != nil {
		return err
	}
	return nil
}

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			private_key_path TEXT NOT NULL,
			public_key_path TEXT,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			address TEXT NOT NULL,
			port INTEGER NOT NULL,
			user TEXT NOT NULL,
			host_key TEXT,
			strict_host_checking INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS host_groups (
			host_id INTEGER NOT NULL,
			group_id INTEGER NOT NULL,
			PRIMARY KEY(host_id, group_id),
			FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
			FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			target_type TEXT NOT NULL,
			target_id INTEGER NOT NULL,
			schedule TEXT NOT NULL,
			command TEXT NOT NULL,
			job_format TEXT NOT NULL DEFAULT 'shell',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS job_runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER NOT NULL,
			started_at INTEGER NOT NULL,
			finished_at INTEGER NOT NULL,
			status TEXT NOT NULL,
			exit_code INTEGER NOT NULL,
			output TEXT NOT NULL,
			FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	if err := ensureColumn(db, "hosts", "host_key", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "hosts", "strict_host_checking", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "jobs", "job_format", "TEXT NOT NULL DEFAULT 'shell'"); err != nil {
		return err
	}
	return nil
}

func ensureColumn(db *sql.DB, table, column, def string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, def))
	return err
}

func parseTemplates() (*template.Template, error) {
	var tmpl *template.Template
	funcs := template.FuncMap{
		"formatTime": func(ts int64) string {
			if ts == 0 {
				return "-"
			}
			return time.Unix(ts, 0).Local().Format("2006-01-02 15:04:05")
		},
		"isActive": func(path, current string) bool {
			if current == "" {
				return false
			}
			return current == path || strings.HasPrefix(current, path+"/")
		},
		"nowUnix": func() int64 {
			return time.Now().Unix()
		},
		"yesno": func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		},
		"render": func(name string, data any) (template.HTML, error) {
			if tmpl == nil {
				return "", nil
			}
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
				return "", err
			}
			return template.HTML(buf.String()), nil
		},
	}
	tmpl = template.New("base.html").Funcs(funcs)
	return tmpl.ParseGlob("templates/*.html")
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", a.requireAuth(a.handleHome))
	mux.HandleFunc("/setup", a.handleSetup)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/logout", a.requireAuth(a.handleLogout))

	mux.HandleFunc("/hosts", a.requireAuth(a.handleHosts))
	mux.HandleFunc("/hosts/new", a.requireAuth(a.handleHostNew))
	mux.HandleFunc("/hosts/create", a.requireAuth(a.handleHostCreate))
	mux.HandleFunc("/hosts/scan-key", a.requireAuth(a.handleHostScanKey))
	mux.HandleFunc("/hosts/edit", a.requireAuth(a.handleHostEdit))
	mux.HandleFunc("/hosts/update", a.requireAuth(a.handleHostUpdate))
	mux.HandleFunc("/hosts/delete", a.requireAuth(a.handleHostDelete))

	mux.HandleFunc("/groups", a.requireAuth(a.handleGroups))
	mux.HandleFunc("/groups/new", a.requireAuth(a.handleGroupNew))
	mux.HandleFunc("/groups/create", a.requireAuth(a.handleGroupCreate))
	mux.HandleFunc("/groups/edit", a.requireAuth(a.handleGroupEdit))
	mux.HandleFunc("/groups/update", a.requireAuth(a.handleGroupUpdate))
	mux.HandleFunc("/groups/delete", a.requireAuth(a.handleGroupDelete))

	mux.HandleFunc("/jobs", a.requireAuth(a.handleJobs))
	mux.HandleFunc("/jobs/new", a.requireAuth(a.handleJobNew))
	mux.HandleFunc("/jobs/create", a.requireAuth(a.handleJobCreate))
	mux.HandleFunc("/jobs/suggest", a.requireAuth(a.handleJobSuggest))
	mux.HandleFunc("/jobs/edit", a.requireAuth(a.handleJobEdit))
	mux.HandleFunc("/jobs/update", a.requireAuth(a.handleJobUpdate))
	mux.HandleFunc("/jobs/delete", a.requireAuth(a.handleJobDelete))
	mux.HandleFunc("/jobs/run", a.requireAuth(a.handleJobRun))

	mux.HandleFunc("/keys", a.requireAuth(a.handleKeys))
	mux.HandleFunc("/keys/upload", a.requireAuth(a.handleKeyUpload))
	mux.HandleFunc("/keys/generate", a.requireAuth(a.handleKeyGenerate))
	mux.HandleFunc("/keys/activate", a.requireAuth(a.handleKeyActivate))
	mux.HandleFunc("/keys/delete", a.requireAuth(a.handleKeyDelete))

	mux.HandleFunc("/inventory", a.requireAuth(a.handleInventory))
	mux.HandleFunc("/inventory/generate", a.requireAuth(a.handleInventoryGenerate))
	mux.HandleFunc("/inventory/download", a.requireAuth(a.handleInventoryDownload))

	mux.HandleFunc("/runs", a.requireAuth(a.handleRuns))

	return mux
}

func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.needsSetup() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		user, err := a.currentUser(r)
		if err != nil || user == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), "user", user))
		next(w, r)
	}
}

func (a *App) currentUser(r *http.Request) (*User, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	var userID int64
	var expiresAt int64
	row := a.db.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE token = ?`, cookie.Value)
	if err := row.Scan(&userID, &expiresAt); err != nil {
		return nil, err
	}
	if time.Now().Unix() > expiresAt {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE token = ?`, cookie.Value)
		return nil, errors.New("session expired")
	}
	var user User
	row = a.db.QueryRow(`SELECT id, username FROM users WHERE id = ?`, userID)
	if err := row.Scan(&user.ID, &user.Username); err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *App) needsSetup() bool {
	var count int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false
	}
	return count == 0
}

func (a *App) render(w http.ResponseWriter, r *http.Request, name string, data *TemplateData) {
	if data == nil {
		data = &TemplateData{}
	}
	if data.ContentTemplate == "" {
		data.ContentTemplate = name
	}
	if data.CurrentPath == "" && r != nil {
		data.CurrentPath = r.URL.Path
	}
	if user, ok := r.Context().Value("user").(*User); ok {
		data.User = user
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/jobs", http.StatusSeeOther)
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !a.needsSetup() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	data := &TemplateData{Title: "Setup", HideNav: true, Setup: true}
	if r.Method == http.MethodGet {
		a.render(w, r, "setup", data)
		return
	}
	if err := r.ParseForm(); err != nil {
		data.Error = "invalid form"
		a.render(w, r, "setup", data)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		data.Error = "username and password required"
		a.render(w, r, "setup", data)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		data.Error = "failed to create user"
		a.render(w, r, "setup", data)
		return
	}
	_, err = a.db.Exec(`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`, username, string(hash), time.Now().Unix())
	if err != nil {
		data.Error = "failed to create user"
		a.render(w, r, "setup", data)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if a.needsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	data := &TemplateData{Title: "Login", HideNav: true}
	if r.Method == http.MethodGet {
		a.render(w, r, "login", data)
		return
	}
	if err := r.ParseForm(); err != nil {
		data.Error = "invalid form"
		a.render(w, r, "login", data)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	var userID int64
	var hash string
	row := a.db.QueryRow(`SELECT id, password_hash FROM users WHERE username = ?`, username)
	if err := row.Scan(&userID, &hash); err != nil {
		data.Error = "invalid credentials"
		a.render(w, r, "login", data)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		data.Error = "invalid credentials"
		a.render(w, r, "login", data)
		return
	}
	sessionToken, err := randomToken(32)
	if err != nil {
		data.Error = "login failed"
		a.render(w, r, "login", data)
		return
	}
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	_, err = a.db.Exec(`INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`, sessionToken, userID, expiresAt, time.Now().Unix())
	if err != nil {
		data.Error = "login failed"
		a.render(w, r, "login", data)
		return
	}
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE token = ?`, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.listHosts()
	if err != nil {
		a.render(w, r, "hosts", &TemplateData{Title: "Hosts", Error: "failed to load hosts"})
		return
	}
	data := &TemplateData{Title: "Hosts", Hosts: hosts}
	data.Groups, _ = a.listGroups()
	a.render(w, r, "hosts", data)
}

func (a *App) handleHostNew(w http.ResponseWriter, r *http.Request) {
	groups, _ := a.listGroups()
	data := &TemplateData{Title: "New Host", Groups: groups}
	a.render(w, r, "host_form", data)
}

func (a *App) handleHostCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	address := strings.TrimSpace(r.FormValue("address"))
	user := strings.TrimSpace(r.FormValue("user"))
	hostKey := strings.TrimSpace(r.FormValue("host_key"))
	strict := r.FormValue("strict_host_checking") == "on"
	portStr := strings.TrimSpace(r.FormValue("port"))
	port := 22
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	if !validName(name) || address == "" || user == "" || (strict && hostKey == "") {
		groups, _ := a.listGroups()
		host := &Host{
			Name:               name,
			Address:            address,
			User:               user,
			Port:               port,
			HostKey:            hostKey,
			StrictHostChecking: strict,
		}
		data := &TemplateData{Title: "New Host", Error: "invalid host data", Groups: groups, SelectedGroupIDs: idsToSet(parseIDs(r.Form["group_ids"])), SelectedHost: host}
		a.render(w, r, "host_form", data)
		return
	}
	res, err := a.db.Exec(`INSERT INTO hosts (name, address, port, user, host_key, strict_host_checking) VALUES (?, ?, ?, ?, ?, ?)`, name, address, port, user, hostKey, boolToInt(strict))
	if err != nil {
		groups, _ := a.listGroups()
		data := &TemplateData{Title: "New Host", Error: "failed to create host", Groups: groups, SelectedHost: &Host{Name: name, Address: address, User: user, Port: port, HostKey: hostKey, StrictHostChecking: strict}}
		a.render(w, r, "host_form", data)
		return
	}
	id, _ := res.LastInsertId()
	groupIDs := parseIDs(r.Form["group_ids"])
	if err := a.setHostGroups(id, groupIDs); err != nil {
		log.Printf("set host groups: %v", err)
	}
	_ = a.GenerateInventory()
	http.Redirect(w, r, "/hosts", http.StatusSeeOther)
}

func (a *App) handleHostScanKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.writeScanKeyError(w)
		return
	}
	address := strings.TrimSpace(r.FormValue("address"))
	portStr := strings.TrimSpace(r.FormValue("port"))
	port := 22
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}
	if !validHostInput(address) {
		a.writeScanKeyError(w)
		return
	}
	key, err := scanHostKey(address, port)
	if err != nil {
		log.Printf("host key scan failed for %s:%d: %v", address, port, err)
		a.writeScanKeyError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": key})
}

func (a *App) handleHostEdit(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
		return
	}
	host, err := a.getHost(id)
	if err != nil {
		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
		return
	}
	groups, _ := a.listGroups()
	selected, _ := a.getHostGroupIDs(id)
	data := &TemplateData{Title: "Edit Host", SelectedHost: host, Groups: groups, SelectedGroupIDs: idsToSet(selected)}
	a.render(w, r, "host_form", data)
}

func (a *App) handleHostUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	id, err := parseIDParam(r, "id")
	if err != nil {
		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	address := strings.TrimSpace(r.FormValue("address"))
	user := strings.TrimSpace(r.FormValue("user"))
	hostKey := strings.TrimSpace(r.FormValue("host_key"))
	strict := r.FormValue("strict_host_checking") == "on"
	portStr := strings.TrimSpace(r.FormValue("port"))
	port := 22
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	if !validName(name) || address == "" || user == "" || (strict && hostKey == "") {
		groups, _ := a.listGroups()
		host := &Host{
			ID:                 id,
			Name:               name,
			Address:            address,
			User:               user,
			Port:               port,
			HostKey:            hostKey,
			StrictHostChecking: strict,
		}
		data := &TemplateData{Title: "Edit Host", Error: "invalid host data", SelectedHost: host, Groups: groups, SelectedGroupIDs: idsToSet(parseIDs(r.Form["group_ids"]))}
		a.render(w, r, "host_form", data)
		return
	}
	_, err = a.db.Exec(`UPDATE hosts SET name = ?, address = ?, port = ?, user = ?, host_key = ?, strict_host_checking = ? WHERE id = ?`, name, address, port, user, hostKey, boolToInt(strict), id)
	if err != nil {
		groups, _ := a.listGroups()
		host := &Host{
			ID:                 id,
			Name:               name,
			Address:            address,
			User:               user,
			Port:               port,
			HostKey:            hostKey,
			StrictHostChecking: strict,
		}
		data := &TemplateData{Title: "Edit Host", Error: "failed to update host", SelectedHost: host, Groups: groups}
		a.render(w, r, "host_form", data)
		return
	}
	groupIDs := parseIDs(r.Form["group_ids"])
	if err := a.setHostGroups(id, groupIDs); err != nil {
		log.Printf("set host groups: %v", err)
	}
	_ = a.GenerateInventory()
	http.Redirect(w, r, "/hosts", http.StatusSeeOther)
}

func (a *App) handleHostDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
		return
	}
	id, err := parseIDParam(r, "id")
	if err == nil {
		_, _ = a.db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	}
	_ = a.GenerateInventory()
	http.Redirect(w, r, "/hosts", http.StatusSeeOther)
}

func (a *App) handleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := a.listGroups()
	if err != nil {
		a.render(w, r, "groups", &TemplateData{Title: "Groups", Error: "failed to load groups"})
		return
	}
	data := &TemplateData{Title: "Groups", Groups: groups}
	a.render(w, r, "groups", data)
}

func (a *App) handleGroupNew(w http.ResponseWriter, r *http.Request) {
	data := &TemplateData{Title: "New Group"}
	a.render(w, r, "group_form", data)
}

func (a *App) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))
	if !validName(name) {
		data := &TemplateData{Title: "New Group", Error: "invalid group name"}
		a.render(w, r, "group_form", data)
		return
	}
	_, err := a.db.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, name, description)
	if err != nil {
		data := &TemplateData{Title: "New Group", Error: "failed to create group"}
		a.render(w, r, "group_form", data)
		return
	}
	_ = a.GenerateInventory()
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (a *App) handleGroupEdit(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	group, err := a.getGroup(id)
	if err != nil {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	data := &TemplateData{Title: "Edit Group", SelectedGroup: group}
	a.render(w, r, "group_form", data)
}

func (a *App) handleGroupUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	id, err := parseIDParam(r, "id")
	if err != nil {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))
	if !validName(name) {
		data := &TemplateData{Title: "Edit Group", Error: "invalid group name", SelectedGroup: &Group{ID: id, Name: name, Description: description}}
		a.render(w, r, "group_form", data)
		return
	}
	_, err = a.db.Exec(`UPDATE groups SET name = ?, description = ? WHERE id = ?`, name, description, id)
	if err != nil {
		data := &TemplateData{Title: "Edit Group", Error: "failed to update group", SelectedGroup: &Group{ID: id, Name: name, Description: description}}
		a.render(w, r, "group_form", data)
		return
	}
	_ = a.GenerateInventory()
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (a *App) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	id, err := parseIDParam(r, "id")
	if err == nil {
		_, _ = a.db.Exec(`DELETE FROM groups WHERE id = ?`, id)
	}
	_ = a.GenerateInventory()
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (a *App) handleJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.listJobs()
	if err != nil {
		a.render(w, r, "jobs", &TemplateData{Title: "Jobs", Error: "failed to load jobs"})
		return
	}
	data := &TemplateData{Title: "Jobs", Jobs: jobs}
	a.render(w, r, "jobs", data)
}

func (a *App) handleJobNew(w http.ResponseWriter, r *http.Request) {
	groups, _ := a.listGroups()
	hosts, _ := a.listHosts()
	data := &TemplateData{Title: "New Job", Groups: groups, Hosts: hosts, JobFormat: "shell"}
	a.render(w, r, "job_form", data)
}

func (a *App) handleJobCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	schedule := strings.TrimSpace(r.FormValue("schedule"))
	command := strings.TrimSpace(r.FormValue("command"))
	format := strings.TrimSpace(r.FormValue("job_format"))
	if format == "" {
		format = "shell"
	}
	enabled := r.FormValue("enabled") == "on"
	targetType, targetID, err := parseTarget(r.FormValue("target"))
	if err != nil {
		a.render(w, r, "job_form", &TemplateData{Title: "New Job", Error: "invalid target"})
		return
	}
	if !validName(name) || schedule == "" || command == "" || !validJobFormat(format) {
		groups, _ := a.listGroups()
		hosts, _ := a.listHosts()
		data := &TemplateData{Title: "New Job", Error: "invalid job data", Groups: groups, Hosts: hosts, SelectedTarget: r.FormValue("target"), JobFormat: format, SelectedJob: &Job{Name: name, Schedule: schedule, Command: command, Enabled: enabled, TargetType: targetType, TargetID: targetID, Format: format}}
		a.render(w, r, "job_form", data)
		return
	}
	if _, err := cron.ParseStandard(schedule); err != nil {
		groups, _ := a.listGroups()
		hosts, _ := a.listHosts()
		data := &TemplateData{Title: "New Job", Error: "invalid cron schedule", Groups: groups, Hosts: hosts, SelectedTarget: r.FormValue("target"), JobFormat: format, SelectedJob: &Job{Name: name, Schedule: schedule, Command: command, Enabled: enabled, TargetType: targetType, TargetID: targetID, Format: format}}
		a.render(w, r, "job_form", data)
		return
	}
	now := time.Now().Unix()
	_, err = a.db.Exec(`INSERT INTO jobs (name, target_type, target_id, schedule, command, job_format, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, name, targetType, targetID, schedule, command, format, boolToInt(enabled), now, now)
	if err != nil {
		groups, _ := a.listGroups()
		hosts, _ := a.listHosts()
		data := &TemplateData{Title: "New Job", Error: "failed to create job", Groups: groups, Hosts: hosts}
		a.render(w, r, "job_form", data)
		return
	}
	_ = a.ReloadAllJobs()
	http.Redirect(w, r, "/jobs", http.StatusSeeOther)
}

func (a *App) handleJobSuggest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/jobs/new", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	schedule := strings.TrimSpace(r.FormValue("schedule"))
	command := strings.TrimSpace(r.FormValue("command"))
	format := strings.TrimSpace(r.FormValue("job_format"))
	if format == "" {
		format = "shell"
	}
	enabled := r.FormValue("enabled") == "on"
	targetVal := r.FormValue("target")
	targetType, targetID, _ := parseTarget(targetVal)
	hint := strings.TrimSpace(r.FormValue("schedule_hint"))
	info := ""
	if hint == "" {
		info = "Add a hint like \"every 5 minutes\" or \"daily at 03:30\"."
	} else {
		suggested, reason := suggestCron(hint)
		if suggested == "" {
			info = "Could not infer a cron schedule from the hint. Try a simpler phrase."
		} else {
			schedule = suggested
			info = fmt.Sprintf("Suggested cron: %s (%s).", suggested, reason)
		}
	}
	groups, _ := a.listGroups()
	hosts, _ := a.listHosts()
	data := &TemplateData{
		Title:          "New Job",
		Info:           info,
		Groups:         groups,
		Hosts:          hosts,
		SelectedTarget: targetVal,
		ScheduleHint:   hint,
		JobFormat:      format,
		SelectedJob: &Job{
			Name:       name,
			Schedule:   schedule,
			Command:    command,
			Enabled:    enabled,
			TargetType: targetType,
			TargetID:   targetID,
			Format:     format,
		},
	}
	a.render(w, r, "job_form", data)
}

func (a *App) handleJobEdit(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}
	job, err := a.getJob(id)
	if err != nil {
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}
	groups, _ := a.listGroups()
	hosts, _ := a.listHosts()
	data := &TemplateData{Title: "Edit Job", SelectedJob: job, Groups: groups, Hosts: hosts, JobFormat: job.Format}
	data.SelectedTarget = fmt.Sprintf("%s:%d", job.TargetType, job.TargetID)
	a.render(w, r, "job_form", data)
}

func (a *App) handleJobUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	id, err := parseIDParam(r, "id")
	if err != nil {
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	schedule := strings.TrimSpace(r.FormValue("schedule"))
	command := strings.TrimSpace(r.FormValue("command"))
	format := strings.TrimSpace(r.FormValue("job_format"))
	if format == "" {
		format = "shell"
	}
	enabled := r.FormValue("enabled") == "on"
	targetType, targetID, err := parseTarget(r.FormValue("target"))
	if err != nil {
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}
	if !validName(name) || schedule == "" || command == "" || !validJobFormat(format) {
		groups, _ := a.listGroups()
		hosts, _ := a.listHosts()
		data := &TemplateData{Title: "Edit Job", Error: "invalid job data", Groups: groups, Hosts: hosts, JobFormat: format, SelectedJob: &Job{ID: id, Name: name, Schedule: schedule, Command: command, Enabled: enabled, TargetType: targetType, TargetID: targetID, Format: format}, SelectedTarget: fmt.Sprintf("%s:%d", targetType, targetID)}
		a.render(w, r, "job_form", data)
		return
	}
	if _, err := cron.ParseStandard(schedule); err != nil {
		groups, _ := a.listGroups()
		hosts, _ := a.listHosts()
		data := &TemplateData{Title: "Edit Job", Error: "invalid cron schedule", Groups: groups, Hosts: hosts, JobFormat: format, SelectedJob: &Job{ID: id, Name: name, Schedule: schedule, Command: command, Enabled: enabled, TargetType: targetType, TargetID: targetID, Format: format}, SelectedTarget: fmt.Sprintf("%s:%d", targetType, targetID)}
		a.render(w, r, "job_form", data)
		return
	}
	_, err = a.db.Exec(`UPDATE jobs SET name = ?, target_type = ?, target_id = ?, schedule = ?, command = ?, job_format = ?, enabled = ?, updated_at = ? WHERE id = ?`, name, targetType, targetID, schedule, command, format, boolToInt(enabled), time.Now().Unix(), id)
	if err != nil {
		groups, _ := a.listGroups()
		hosts, _ := a.listHosts()
		data := &TemplateData{Title: "Edit Job", Error: "failed to update job", Groups: groups, Hosts: hosts, SelectedJob: &Job{ID: id, Name: name, Schedule: schedule, Command: command, Enabled: enabled, TargetType: targetType, TargetID: targetID}}
		a.render(w, r, "job_form", data)
		return
	}
	_ = a.ReloadAllJobs()
	http.Redirect(w, r, "/jobs", http.StatusSeeOther)
}

func (a *App) handleJobDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}
	id, err := parseIDParam(r, "id")
	if err == nil {
		_, _ = a.db.Exec(`DELETE FROM jobs WHERE id = ?`, id)
	}
	_ = a.ReloadAllJobs()
	http.Redirect(w, r, "/jobs", http.StatusSeeOther)
}

func (a *App) handleJobRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}
	id, err := parseIDParam(r, "id")
	if err == nil {
		a.runner.Enqueue(id)
	}
	http.Redirect(w, r, "/jobs", http.StatusSeeOther)
}

func (a *App) handleKeys(w http.ResponseWriter, r *http.Request) {
	keys, _ := a.listKeys()
	activeKeyID, _ := a.activeKeyID()
	data := &TemplateData{Title: "Keys", Keys: keys, ActiveKeyID: activeKeyID}
	a.render(w, r, "keys", data)
}

func (a *App) renderKeysError(w http.ResponseWriter, r *http.Request, msg string) {
	keys, _ := a.listKeys()
	activeKeyID, _ := a.activeKeyID()
	data := &TemplateData{Title: "Keys", Keys: keys, ActiveKeyID: activeKeyID, Error: msg}
	a.render(w, r, "keys", data)
}

func (a *App) handleKeyUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		a.renderKeysError(w, r, "invalid upload form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	file, header, err := r.FormFile("private_key")
	if err != nil {
		a.renderKeysError(w, r, "private key file required")
		return
	}
	defer file.Close()
	if name == "" {
		name = strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
	}
	keyID, err := randomToken(6)
	if err != nil {
		a.renderKeysError(w, r, "failed to create key")
		return
	}
	privatePath := filepath.Join(a.cfg.KeysDir, fmt.Sprintf("%s_%s", sanitizeName(name), keyID))
	if err := writeFile(privatePath, file, 0o600); err != nil {
		a.renderKeysError(w, r, "failed to save private key")
		return
	}
	pubKey, err := derivePublicKey(privatePath)
	if err != nil {
		_ = os.Remove(privatePath)
		a.renderKeysError(w, r, "invalid private key or passphrase-protected")
		return
	}
	publicPath := privatePath + ".pub"
	if err := os.WriteFile(publicPath, []byte(pubKey+"\n"), 0o644); err != nil {
		_ = os.Remove(privatePath)
		a.renderKeysError(w, r, "failed to write public key")
		return
	}

	_, _ = a.db.Exec(`INSERT INTO ssh_keys (name, private_key_path, public_key_path, created_at) VALUES (?, ?, ?, ?)`, name, privatePath, publicPath, time.Now().Unix())
	a.ensureSingleKeyActive()
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (a *App) handleKeyGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		a.renderKeysError(w, r, "key name is required")
		return
	}
	slug := sanitizeName(name)
	keyID, _ := randomToken(6)
	privatePath := filepath.Join(a.cfg.KeysDir, fmt.Sprintf("%s_%s", slug, keyID))
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", privatePath, "-N", "", "-C", "cronsible")
	if err := cmd.Run(); err != nil {
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	publicPath := privatePath + ".pub"
	_, _ = a.db.Exec(`INSERT INTO ssh_keys (name, private_key_path, public_key_path, created_at) VALUES (?, ?, ?, ?)`, name, privatePath, publicPath, time.Now().Unix())
	a.ensureSingleKeyActive()
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (a *App) handleKeyActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	id, err := parseIDParam(r, "id")
	if err == nil {
		_, _ = a.db.Exec(`INSERT INTO settings (key, value) VALUES ('active_key_id', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprintf("%d", id))
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (a *App) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	id, err := parseIDParam(r, "id")
	if err != nil {
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	var privatePath, publicPath string
	row := a.db.QueryRow(`SELECT private_key_path, public_key_path FROM ssh_keys WHERE id = ?`, id)
	_ = row.Scan(&privatePath, &publicPath)
	_, _ = a.db.Exec(`DELETE FROM ssh_keys WHERE id = ?`, id)
	activeID, _ := a.activeKeyID()
	if activeID == id {
		_, _ = a.db.Exec(`DELETE FROM settings WHERE key = 'active_key_id'`)
	}
	if privatePath != "" {
		_ = os.Remove(privatePath)
	}
	if publicPath != "" {
		_ = os.Remove(publicPath)
	}
	a.ensureSingleKeyActive()
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (a *App) handleInventory(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile(a.cfg.InventoryPath)
	inventoryText := ""
	if err == nil {
		inventoryText = string(content)
	}
	data := &TemplateData{Title: "Inventory", InventoryPath: a.cfg.InventoryPath, InventoryContent: inventoryText}
	a.render(w, r, "inventory", data)
}

func (a *App) handleInventoryGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/inventory", http.StatusSeeOther)
		return
	}
	_ = a.GenerateInventory()
	http.Redirect(w, r, "/inventory", http.StatusSeeOther)
}

func (a *App) handleInventoryDownload(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile(a.cfg.InventoryPath)
	if err != nil {
		http.Error(w, "inventory not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"inventory.ini\"")
	w.Write(content)
}

func (a *App) handleRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := a.listRuns()
	if err != nil {
		a.render(w, r, "runs", &TemplateData{Title: "Runs", Error: "failed to load runs"})
		return
	}
	a.render(w, r, "runs", &TemplateData{Title: "Runs", Runs: runs})
}

func (a *App) listHosts() ([]Host, error) {
	rows, err := a.db.Query(`SELECT h.id, h.name, h.address, h.port, h.user, IFNULL(GROUP_CONCAT(g.name, ', '), '')
		FROM hosts h
		LEFT JOIN host_groups hg ON h.id = hg.host_id
		LEFT JOIN groups g ON hg.group_id = g.id
		GROUP BY h.id
		ORDER BY h.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.Name, &h.Address, &h.Port, &h.User, &h.GroupNames); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

func (a *App) getHost(id int64) (*Host, error) {
	var h Host
	var strict int
	row := a.db.QueryRow(`SELECT id, name, address, port, user, host_key, strict_host_checking FROM hosts WHERE id = ?`, id)
	if err := row.Scan(&h.ID, &h.Name, &h.Address, &h.Port, &h.User, &h.HostKey, &strict); err != nil {
		return nil, err
	}
	h.StrictHostChecking = strict == 1
	return &h, nil
}

func (a *App) listGroups() ([]Group, error) {
	rows, err := a.db.Query(`SELECT g.id, g.name, g.description, COUNT(hg.host_id)
		FROM groups g
		LEFT JOIN host_groups hg ON g.id = hg.group_id
		GROUP BY g.id
		ORDER BY g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.HostCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, nil
}

func (a *App) getGroup(id int64) (*Group, error) {
	var g Group
	row := a.db.QueryRow(`SELECT id, name, description FROM groups WHERE id = ?`, id)
	if err := row.Scan(&g.ID, &g.Name, &g.Description); err != nil {
		return nil, err
	}
	return &g, nil
}

func (a *App) listJobs() ([]JobView, error) {
	rows, err := a.db.Query(`SELECT j.id, j.name, j.target_type, j.target_id, j.schedule, j.command, j.job_format, j.enabled,
		CASE WHEN j.target_type = 'host' THEN h.name ELSE g.name END AS target_name
		FROM jobs j
		LEFT JOIN hosts h ON j.target_type = 'host' AND j.target_id = h.id
		LEFT JOIN groups g ON j.target_type = 'group' AND j.target_id = g.id
		ORDER BY j.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []JobView
	for rows.Next() {
		var j JobView
		var enabled int
		if err := rows.Scan(&j.ID, &j.Name, &j.TargetType, &j.TargetID, &j.Schedule, &j.Command, &j.Format, &enabled, &j.TargetName); err != nil {
			return nil, err
		}
		if j.Format == "" {
			j.Format = "shell"
		}
		j.Enabled = enabled == 1
		j.NextRun = a.nextRunForJob(j.ID)
		jobs = append(jobs, j)
	}
	return jobs, nil
}

func (a *App) getJob(id int64) (*Job, error) {
	var j Job
	var enabled int
	row := a.db.QueryRow(`SELECT id, name, target_type, target_id, schedule, command, job_format, enabled FROM jobs WHERE id = ?`, id)
	if err := row.Scan(&j.ID, &j.Name, &j.TargetType, &j.TargetID, &j.Schedule, &j.Command, &j.Format, &enabled); err != nil {
		return nil, err
	}
	if j.Format == "" {
		j.Format = "shell"
	}
	j.Enabled = enabled == 1
	return &j, nil
}

func (a *App) listKeys() ([]Key, error) {
	rows, err := a.db.Query(`SELECT id, name, private_key_path, public_key_path, created_at FROM ssh_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.ID, &k.Name, &k.PrivateKeyPath, &k.PublicKeyPath, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.PublicKey = readPublicKey(k.PublicKeyPath, k.PrivateKeyPath)
		keys = append(keys, k)
	}
	return keys, nil
}

func (a *App) listRuns() ([]JobRun, error) {
	rows, err := a.db.Query(`SELECT r.id, r.job_id, j.name, r.started_at, r.finished_at, r.status, r.exit_code, r.output
		FROM job_runs r
		JOIN jobs j ON r.job_id = j.id
		ORDER BY r.started_at DESC
		LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []JobRun
	for rows.Next() {
		var r JobRun
		if err := rows.Scan(&r.ID, &r.JobID, &r.JobName, &r.StartedAt, &r.FinishedAt, &r.Status, &r.ExitCode, &r.Output); err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, nil
}

func (a *App) setHostGroups(hostID int64, groupIDs []int64) error {
	_, err := a.db.Exec(`DELETE FROM host_groups WHERE host_id = ?`, hostID)
	if err != nil {
		return err
	}
	for _, gid := range groupIDs {
		_, _ = a.db.Exec(`INSERT INTO host_groups (host_id, group_id) VALUES (?, ?)`, hostID, gid)
	}
	return nil
}

func (a *App) getHostGroupIDs(hostID int64) ([]int64, error) {
	rows, err := a.db.Query(`SELECT group_id FROM host_groups WHERE host_id = ?`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (a *App) GenerateInventory() error {
	rows, err := a.db.Query(`SELECT h.id, h.name, h.address, h.port, h.user, h.host_key, h.strict_host_checking, g.name
		FROM hosts h
		LEFT JOIN host_groups hg ON h.id = hg.host_id
		LEFT JOIN groups g ON hg.group_id = g.id
		ORDER BY h.name`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type invHost struct {
		ID                 int64
		Name               string
		Address            string
		Port               int
		User               string
		HostKey            string
		StrictHostChecking bool
		Groups             map[string]bool
	}

	hostsByID := make(map[int64]*invHost)
	groupsSet := make(map[string]bool)
	for rows.Next() {
		var hostID int64
		var name, address, user, hostKey, groupName sql.NullString
		var port int
		var strict int
		if err := rows.Scan(&hostID, &name, &address, &port, &user, &hostKey, &strict, &groupName); err != nil {
			return err
		}
		h, ok := hostsByID[hostID]
		if !ok {
			h = &invHost{
				ID:                 hostID,
				Name:               name.String,
				Address:            address.String,
				Port:               port,
				User:               user.String,
				HostKey:            hostKey.String,
				StrictHostChecking: strict == 1,
				Groups:             make(map[string]bool),
			}
			hostsByID[hostID] = h
		}
		if groupName.Valid && groupName.String != "" {
			h.Groups[groupName.String] = true
			groupsSet[groupName.String] = true
		}
	}

	var hosts []*invHost
	for _, h := range hostsByID {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })

	var groupNames []string
	for g := range groupsSet {
		groupNames = append(groupNames, g)
	}
	sort.Strings(groupNames)

	var knownHosts []string
	for _, h := range hosts {
		if h.StrictHostChecking && strings.TrimSpace(h.HostKey) != "" {
			knownHosts = append(knownHosts, strings.TrimSpace(h.HostKey))
		}
	}
	if len(knownHosts) > 0 {
		knownContent := strings.Join(knownHosts, "\n") + "\n"
		tmpKnown, err := os.CreateTemp(filepath.Dir(a.cfg.KnownHostsPath), "known_hosts-*.tmp")
		if err != nil {
			return err
		}
		if _, err := tmpKnown.WriteString(knownContent); err != nil {
			_ = tmpKnown.Close()
			return err
		}
		if err := tmpKnown.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmpKnown.Name(), a.cfg.KnownHostsPath); err != nil {
			return err
		}
	} else {
		_ = os.Remove(a.cfg.KnownHostsPath)
	}

	var b strings.Builder
	b.WriteString("[all]\n")
	for _, h := range hosts {
		if h.Name == "" {
			continue
		}
		fmt.Fprintf(&b, "%s ansible_host=%s", h.Name, h.Address)
		if h.User != "" {
			fmt.Fprintf(&b, " ansible_user=%s", h.User)
		}
		if h.Port != 0 {
			fmt.Fprintf(&b, " ansible_port=%d", h.Port)
		}
		if h.StrictHostChecking && strings.TrimSpace(h.HostKey) != "" {
			fmt.Fprintf(&b, " ansible_ssh_common_args='-o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s'", a.cfg.KnownHostsPath)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	for _, g := range groupNames {
		b.WriteString("[")
		b.WriteString(g)
		b.WriteString("]\n")
		for _, h := range hosts {
			if h.Groups[g] {
				b.WriteString(h.Name)
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(a.cfg.InventoryPath), "inventory-*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmpFile.WriteString(b.String()); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpFile.Name(), a.cfg.InventoryPath)
}

func (a *App) activeKeyID() (int64, error) {
	var idStr string
	row := a.db.QueryRow(`SELECT value FROM settings WHERE key = 'active_key_id'`)
	if err := row.Scan(&idStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return strconv.ParseInt(idStr, 10, 64)
}

func (a *App) getActiveKey() (*Key, error) {
	id, err := a.activeKeyID()
	if err != nil {
		return nil, err
	}
	if id == 0 {
		return nil, nil
	}
	var k Key
	row := a.db.QueryRow(`SELECT id, name, private_key_path, public_key_path, created_at FROM ssh_keys WHERE id = ?`, id)
	if err := row.Scan(&k.ID, &k.Name, &k.PrivateKeyPath, &k.PublicKeyPath, &k.CreatedAt); err != nil {
		return nil, err
	}
	return &k, nil
}

func (a *App) ensureSingleKeyActive() {
	var count int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM ssh_keys`).Scan(&count); err != nil {
		return
	}
	if count != 1 {
		return
	}
	var id int64
	if err := a.db.QueryRow(`SELECT id FROM ssh_keys LIMIT 1`).Scan(&id); err != nil {
		return
	}
	_, _ = a.db.Exec(`INSERT INTO settings (key, value) VALUES ('active_key_id', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprintf("%d", id))
}

func (a *App) ReloadAllJobs() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, entryID := range a.jobEntries {
		a.cron.Remove(entryID)
	}
	a.jobEntries = make(map[int64]cron.EntryID)

	rows, err := a.db.Query(`SELECT id, schedule FROM jobs WHERE enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var schedule string
		if err := rows.Scan(&id, &schedule); err != nil {
			return err
		}
		jobID := id
		entryID, err := a.cron.AddFunc(schedule, func() {
			a.runner.Enqueue(jobID)
		})
		if err != nil {
			log.Printf("invalid schedule for job %d: %v", jobID, err)
			continue
		}
		a.jobEntries[jobID] = entryID
	}
	return nil
}

func (a *App) nextRunForJob(jobID int64) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	entryID, ok := a.jobEntries[jobID]
	if !ok {
		return "-"
	}
	entry := a.cron.Entry(entryID)
	if entry.Next.IsZero() {
		return "-"
	}
	return entry.Next.Local().Format("2006-01-02 15:04:05")
}

func (r *Runner) Start() {
	r.wg.Add(1)
	go r.loop()
}

func (r *Runner) Enqueue(jobID int64) {
	select {
	case r.queue <- jobID:
	default:
		log.Printf("job queue full, dropping job %d", jobID)
	}
}

func (r *Runner) loop() {
	defer r.wg.Done()
	for {
		select {
		case jobID := <-r.queue:
			r.runJob(jobID)
		case <-r.stop:
			return
		}
	}
}

func (r *Runner) runJob(jobID int64) {
	var job Job
	var enabled int
	row := r.db.QueryRow(`SELECT id, name, target_type, target_id, schedule, command, job_format, enabled FROM jobs WHERE id = ?`, jobID)
	if err := row.Scan(&job.ID, &job.Name, &job.TargetType, &job.TargetID, &job.Schedule, &job.Command, &job.Format, &enabled); err != nil {
		return
	}
	if enabled != 1 {
		return
	}

	targetName, err := r.resolveTargetName(job.TargetType, job.TargetID)
	if err != nil || targetName == "" {
		r.recordRun(job.ID, "failed", 1, "invalid target")
		return
	}

	app := &App{db: r.db, cfg: r.cfg}
	if err := app.GenerateInventory(); err != nil {
		r.recordRun(job.ID, "failed", 1, "failed to generate inventory")
		return
	}
	key, err := app.getActiveKey()
	if err != nil || key == nil {
		r.recordRun(job.ID, "failed", 1, "no active ssh key")
		return
	}

	started := time.Now().Unix()
	format := strings.TrimSpace(strings.ToLower(job.Format))
	if format == "" {
		format = "shell"
	}
	playbook := ""
	switch format {
	case "shell":
		playbook = buildShellPlaybook(job.Command)
	case "playbook":
		playbook = strings.TrimSpace(job.Command)
		if playbook == "" {
			r.recordRun(job.ID, "failed", 1, "empty playbook")
			return
		}
	default:
		r.recordRun(job.ID, "failed", 1, "invalid job format")
		return
	}
	if !strings.HasSuffix(playbook, "\n") {
		playbook += "\n"
	}
	tmpFile, err := os.CreateTemp(r.cfg.DataDir, fmt.Sprintf("job-%d-*.yml", job.ID))
	if err != nil {
		r.recordRun(job.ID, "failed", 1, "failed to create playbook file")
		return
	}
	if _, err := tmpFile.WriteString(playbook); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		r.recordRun(job.ID, "failed", 1, "failed to write playbook file")
		return
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		r.recordRun(job.ID, "failed", 1, "failed to save playbook file")
		return
	}
	defer os.Remove(tmpFile.Name())

	cmd := exec.Command(r.cfg.AnsiblePlaybookPath, "-i", r.cfg.InventoryPath, "--private-key", key.PrivateKeyPath, "--limit", targetName, tmpFile.Name())
	outputBytes, err := cmd.CombinedOutput()
	finished := time.Now().Unix()
	status := "success"
	exitCode := 0
	if err != nil {
		status = "failed"
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	output := string(outputBytes)
	if len(output) > maxOutputBytes {
		output = output[:maxOutputBytes] + "\n(truncated)"
	}
	_, _ = r.db.Exec(`INSERT INTO job_runs (job_id, started_at, finished_at, status, exit_code, output) VALUES (?, ?, ?, ?, ?, ?)`, job.ID, started, finished, status, exitCode, output)
}

func (r *Runner) recordRun(jobID int64, status string, exitCode int, output string) {
	started := time.Now().Unix()
	finished := started
	if len(output) > maxOutputBytes {
		output = output[:maxOutputBytes]
	}
	_, _ = r.db.Exec(`INSERT INTO job_runs (job_id, started_at, finished_at, status, exit_code, output) VALUES (?, ?, ?, ?, ?, ?)`, jobID, started, finished, status, exitCode, output)
}

func (r *Runner) resolveTargetName(targetType string, targetID int64) (string, error) {
	if targetType == "host" {
		var name string
		row := r.db.QueryRow(`SELECT name FROM hosts WHERE id = ?`, targetID)
		if err := row.Scan(&name); err != nil {
			return "", err
		}
		return name, nil
	}
	if targetType == "group" {
		var name string
		row := r.db.QueryRow(`SELECT name FROM groups WHERE id = ?`, targetID)
		if err := row.Scan(&name); err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("unknown target type")
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validName(name string) bool {
	return name != "" && nameRe.MatchString(name)
}

func sanitizeName(name string) string {
	if validName(name) {
		return name
	}
	clean := make([]rune, 0, len(name))
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			clean = append(clean, r)
		}
	}
	if len(clean) == 0 {
		return "key"
	}
	return string(clean)
}

func parseIDParam(r *http.Request, key string) (int64, error) {
	idStr := r.FormValue(key)
	if idStr == "" {
		idStr = r.URL.Query().Get(key)
	}
	return strconv.ParseInt(idStr, 10, 64)
}

func parseIDs(values []string) []int64 {
	var ids []int64
	for _, v := range values {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func idsToSet(ids []int64) map[int64]bool {
	set := make(map[int64]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

func parseTarget(value string) (string, int64, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, errors.New("invalid target")
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, err
	}
	typeVal := parts[0]
	if typeVal != "host" && typeVal != "group" {
		return "", 0, errors.New("invalid target type")
	}
	return typeVal, id, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func validJobFormat(value string) bool {
	switch value {
	case "shell", "playbook":
		return true
	default:
		return false
	}
}

func validHostInput(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	return hostInputRe.MatchString(value)
}

func writeFile(path string, src io.Reader, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return err
}

func buildShellPlaybook(command string) string {
	var b strings.Builder
	b.WriteString("- hosts: all\n")
	b.WriteString("  gather_facts: false\n")
	b.WriteString("  tasks:\n")
	b.WriteString("    - name: Run command\n")
	b.WriteString("      ansible.builtin.shell:\n")
	b.WriteString("        cmd: |\n")
	lines := strings.Split(command, "\n")
	if len(lines) == 0 {
		lines = []string{""}
	}
	for _, line := range lines {
		b.WriteString("          ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func readPublicKey(publicPath, privatePath string) string {
	if publicPath != "" {
		if b, err := os.ReadFile(publicPath); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	if privatePath != "" {
		if out, err := derivePublicKey(privatePath); err == nil {
			return strings.TrimSpace(out)
		}
	}
	return ""
}

func derivePublicKey(privatePath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-y", "-f", privatePath)
	cmd.Stdin = strings.NewReader("\n")
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", errors.New("ssh-keygen timeout")
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func scanHostKey(address string, port int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-keyscan", "-T", "5", "-p", strconv.Itoa(port), address)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", errors.New("ssh-keyscan timeout")
	}
	if err != nil {
		return "", fmt.Errorf("ssh-keyscan failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	for _, line := range strings.Split(string(out), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		return trim, nil
	}
	return "", errors.New("no host key found")
}

func (a *App) writeScanKeyError(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func suggestCron(input string) (string, string) {
	raw := strings.TrimSpace(input)
	s := strings.ToLower(raw)
	if s == "" {
		return "", ""
	}

	if m := regexp.MustCompile(`every\s+(\d+)\s+minutes?`).FindStringSubmatch(s); len(m) == 2 {
		n, _ := strconv.Atoi(m[1])
		if n > 0 && n <= 60 {
			return fmt.Sprintf("*/%d * * * *", n), fmt.Sprintf("every %d minutes", n)
		}
	}
	if strings.Contains(s, "every minute") || strings.Contains(s, "each minute") {
		return "* * * * *", "every minute"
	}
	if m := regexp.MustCompile(`every\s+(\d+)\s+hours?`).FindStringSubmatch(s); len(m) == 2 {
		n, _ := strconv.Atoi(m[1])
		if n > 0 && n <= 24 {
			return fmt.Sprintf("0 */%d * * *", n), fmt.Sprintf("every %d hours", n)
		}
	}
	if strings.Contains(s, "hourly") {
		return "0 * * * *", "hourly"
	}

	timeMatch := regexp.MustCompile(`\b(\d{1,2}):(\d{2})\b`).FindStringSubmatch(s)
	if len(timeMatch) == 3 {
		hour, _ := strconv.Atoi(timeMatch[1])
		minute, _ := strconv.Atoi(timeMatch[2])
		if hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59 {
			if strings.Contains(s, "weekday") {
				return fmt.Sprintf("%d %d * * 1-5", minute, hour), "weekdays"
			}
			if dow, ok := dayOfWeekFromText(s); ok {
				return fmt.Sprintf("%d %d * * %d", minute, hour, dow), "weekly"
			}
			if strings.Contains(s, "daily") || strings.Contains(s, "every day") || strings.Contains(s, "each day") {
				return fmt.Sprintf("%d %d * * *", minute, hour), "daily"
			}
			if strings.Contains(s, "weekly") || strings.Contains(s, "every week") {
				return fmt.Sprintf("%d %d * * 0", minute, hour), "weekly"
			}
			if strings.Contains(s, "monthly") || strings.Contains(s, "every month") {
				return fmt.Sprintf("%d %d 1 * *", minute, hour), "monthly"
			}
		}
	}

	if strings.Contains(s, "daily") || strings.Contains(s, "every day") {
		return "0 0 * * *", "daily at midnight"
	}
	if strings.Contains(s, "weekly") || strings.Contains(s, "every week") {
		return "0 0 * * 0", "weekly on Sunday"
	}
	if strings.Contains(s, "monthly") || strings.Contains(s, "every month") {
		return "0 0 1 * *", "monthly on the 1st"
	}

	if cron, reason := suggestCronFromFuzzy(raw); cron != "" {
		return cron, reason
	}

	return "", ""
}

func dayOfWeekFromText(s string) (int, bool) {
	weekdays := map[string]int{
		"sunday":    0,
		"monday":    1,
		"tuesday":   2,
		"wednesday": 3,
		"thursday":  4,
		"friday":    5,
		"saturday":  6,
	}
	for name, val := range weekdays {
		if strings.Contains(s, name) {
			return val, true
		}
	}
	return 0, false
}

func suggestCronFromFuzzy(input string) (string, string) {
	dt, _, err := fuzzytime.USContext.Extract(input)
	if err != nil || dt.Empty() {
		return "", ""
	}

	hasHour := dt.Time.HasHour()
	hasMinute := dt.Time.HasMinute()
	hasTime := hasHour || hasMinute
	hour := 0
	minute := 0
	if hasHour {
		hour = dt.Time.Hour()
	}
	if hasMinute {
		minute = dt.Time.Minute()
	}

	hasDay := dt.Date.HasDay()
	hasMonth := dt.Date.HasMonth()
	hasYear := dt.Date.HasYear()

	if hasTime {
		if hasMonth && hasDay {
			reason := "date/time hint"
			if hasYear {
				reason = "date/time hint (year ignored)"
			}
			return fmt.Sprintf("%d %d %d %d *", minute, hour, dt.Date.Day(), dt.Date.Month()), reason
		}
		if hasDay {
			return fmt.Sprintf("%d %d %d * *", minute, hour, dt.Date.Day()), "monthly at time from hint"
		}
		return fmt.Sprintf("%d %d * * *", minute, hour), "daily at time from hint"
	}

	if hasMonth && hasDay {
		reason := "date hint at midnight"
		if hasYear {
			reason = "date hint at midnight (year ignored)"
		}
		return fmt.Sprintf("0 0 %d %d *", dt.Date.Day(), dt.Date.Month()), reason
	}
	if hasDay {
		return fmt.Sprintf("0 0 %d * *", dt.Date.Day()), "monthly at midnight from hint"
	}

	return "", ""
}
