// main.go
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "forum_session"
	sessionTTL        = 24 * time.Hour
)

var db *sql.DB
var templates = template.Must(template.ParseGlob("templates/*.html"))

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db?_foreign_keys=on")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatalf("init db: %v", err)
	}

	// static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/post/create", requireAuth(handleCreatePost))
	http.HandleFunc("/post/", handleViewPost) // view single post and comments
	http.HandleFunc("/comment/create", requireAuth(handleCreateComment))
	http.HandleFunc("/like", requireAuth(handleLike)) // endpoint to like/dislike
	http.HandleFunc("/filter", handleFilter)

	addr := ":8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

/* DB init function: executes the CREATE statements */
func initDB(db *sql.DB) error {
	sqlStmt := `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS post_categories (
    post_id INTEGER NOT NULL,
    category_id INTEGER NOT NULL,
    PRIMARY KEY(post_id, category_id),
    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER NOT NULL,
    value INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, target_type, target_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`
	_, err := db.Exec(sqlStmt)
	if err != nil {
		return err
	}

	// insert some example categories if not exist
	_, err = db.Exec(`INSERT OR IGNORE INTO categories (name) VALUES ('general'), ('golang'), ('docker')`)
	return err
}

/* -- Auth helpers -- */
type User struct {
	ID       int
	Email    string
	Username string
}

func createUser(email, username, password string) error {
	// password hashing
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)`, email, username, string(hash))
	if err != nil {
		return err
	}
	return nil
}

func authenticate(email, password string) (*User, error) {
	var id int
	var username string
	var hash string
	row := db.QueryRow(`SELECT id, username, password_hash FROM users WHERE email = ?`, email)
	err := row.Scan(&id, &username, &hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid credentials")
		}
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	return &User{ID: id, Email: email, Username: username}, nil
}

/* session management */
func createSession(w http.ResponseWriter, userID int) error {
	sid := uuid.New().String()
	exp := time.Now().Add(sessionTTL)

	// optional: delete existing sessions for user to enforce single active session
	_, _ = db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)

	_, err := db.Exec(`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`, sid, userID, exp)
	if err != nil {
		return err
	}
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		// Secure: true, // set when using HTTPS
	}
	http.SetCookie(w, c)
	return nil
}

func getUserFromRequest(r *http.Request) (*User, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	var userID int
	var expiresAt time.Time
	row := db.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE id = ?`, c.Value)
	if err := row.Scan(&userID, &expiresAt); err != nil {
		return nil, err
	}
	if time.Now().After(expiresAt) {
		// expired: delete session
		_, _ = db.Exec(`DELETE FROM sessions WHERE id = ?`, c.Value)
		return nil, errors.New("session expired")
	}
	// fetch user
	u := &User{}
	row2 := db.QueryRow(`SELECT id, email, username FROM users WHERE id = ?`, userID)
	if err := row2.Scan(&u.ID, &u.Email, &u.Username); err != nil {
		return nil, err
	}
	return u, nil
}

func requireAuth(next func(http.ResponseWriter, *http.Request, *User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := getUserFromRequest(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, u)
	}
}

/* -- Handlers -- */

func handleIndex(w http.ResponseWriter, r *http.Request) {
	// show recent posts
	rows, err := db.Query(`SELECT p.id, p.title, p.body, p.created_at, u.username
		FROM posts p JOIN users u ON p.author_id = u.id
		ORDER BY p.created_at DESC LIMIT 50`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type PostView struct {
		ID        int
		Title     string
		Body      string
		Author    string
		CreatedAt string
	}
	posts := []PostView{}
	for rows.Next() {
		var p PostView
		var created string
		if err := rows.Scan(&p.ID, &p.Title, &p.Body, &created, &p.Author); err != nil {
			http.Error(w, "db scan error", http.StatusInternalServerError)
			return
		}
		p.CreatedAt = created
		posts = append(posts, p)
	}

	// load categories
	cats := []struct {
		ID   int
		Name string
	}{}
	crows, _ := db.Query(`SELECT id, name FROM categories ORDER BY name`)
	defer func() {
		if crows != nil {
			crows.Close()
		}
	}()
	if crows != nil {
		for crows.Next() {
			var id int
			var name string
			_ = crows.Scan(&id, &name)
			cats = append(cats, struct {
				ID   int
				Name string
			}{ID: id, Name: name})
		}
	}

	var user *User
	if u, err := getUserFromRequest(r); err == nil {
		user = u
	}

	data := map[string]interface{}{
		"Posts":      posts,
		"Categories": cats,
		"User":       user,
	}
	if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "register.html", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")
	if email == "" || username == "" || password == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}
	// check existing
	var exists int
	_ = db.QueryRow(`SELECT COUNT(1) FROM users WHERE email = ?`, email).Scan(&exists)
	if exists > 0 {
		http.Error(w, "email already taken", http.StatusConflict)
		return
	}
	if err := createUser(email, username, password); err != nil {
		http.Error(w, "create user failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// auto-login: fetch userID and create session
	var uid int
	_ = db.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&uid)
	_ = createSession(w, uid)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	user, err := authenticate(email, password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if err := createSession(w, user.ID); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err == nil {
		_, _ = db.Exec(`DELETE FROM sessions WHERE id = ?`, c.Value)
		// expire cookie
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
		})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

/* create post: expects form: title, body, categories=comma-separated ids */
func handleCreatePost(w http.ResponseWriter, r *http.Request, user *User) {
	if r.Method == http.MethodGet {
		// show create post with categories
		rows, _ := db.Query(`SELECT id, name FROM categories ORDER BY name`)
		defer rows.Close()
		var cats []struct {
			ID   int
			Name string
		}
		for rows.Next() {
			var id int
			var name string
			_ = rows.Scan(&id, &name)
			cats = append(cats, struct {
				ID   int
				Name string
			}{ID: id, Name: name})
		}
		templates.ExecuteTemplate(w, "create_post.html", cats)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	title := r.FormValue("title")
	body := r.FormValue("body")
	catIDs := r.Form["category"] // multiple checkboxes named "category"

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "tx err", 500)
		return
	}
	res, err := tx.Exec(`INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)`, user.ID, title, body)
	if err != nil {
		tx.Rollback()
		http.Error(w, "insert post", 500)
		return
	}
	postID64, _ := res.LastInsertId()
	postID := int(postID64)
	for _, cid := range catIDs {
		ci, _ := strconv.Atoi(cid)
		_, _ = tx.Exec(`INSERT OR IGNORE INTO post_categories (post_id, category_id) VALUES (?, ?)`, postID, ci)
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "commit", 500)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/post/%d", postID), http.StatusSeeOther)
}

func handleViewPost(w http.ResponseWriter, r *http.Request) {
	// URL: /post/{id}
	idStr := r.URL.Path[len("/post/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// fetch post
	var title, body, author string
	var created string
	row := db.QueryRow(`SELECT p.title, p.body, u.username, p.created_at
		FROM posts p JOIN users u ON p.author_id=u.id WHERE p.id = ?`, id)
	if err := row.Scan(&title, &body, &author, &created); err != nil {
		http.NotFound(w, r)
		return
	}
	// categories
	catRows, _ := db.Query(`SELECT c.id, c.name FROM categories c JOIN post_categories pc ON c.id=pc.category_id WHERE pc.post_id=?`, id)
	defer catRows.Close()
	var cats []struct {
		ID   int
		Name string
	}
	for catRows.Next() {
		var cid int
		var cname string
		_ = catRows.Scan(&cid, &cname)
		cats = append(cats, struct {
			ID   int
			Name string
		}{ID: cid, Name: cname})
	}
	// comments
	cRows, _ := db.Query(`SELECT c.id, c.body, u.username, c.created_at FROM comments c JOIN users u ON c.author_id=u.id WHERE c.post_id=? ORDER BY c.created_at ASC`, id)
	defer cRows.Close()
	type CommentView struct {
		ID       int
		Body     string
		Author   string
		Created  string
		Likes    int
		Dislikes int
	}
	var comments []CommentView
	for cRows.Next() {
		var cv CommentView
		_ = cRows.Scan(&cv.ID, &cv.Body, &cv.Author, &cv.Created)
		// count likes/dislikes
		_ = db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN value=1 THEN 1 ELSE 0 END),0) FROM likes WHERE target_type='comment' AND target_id=?`, cv.ID).Scan(&cv.Likes)
		_ = db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN value=-1 THEN 1 ELSE 0 END),0) FROM likes WHERE target_type='comment' AND target_id=?`, cv.ID).Scan(&cv.Dislikes)
		comments = append(comments, cv)
	}
	// post likes/dislikes
	var likes, dislikes int
	_ = db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN value=1 THEN 1 ELSE 0 END),0) FROM likes WHERE target_type='post' AND target_id=?`, id).Scan(&likes)
	_ = db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN value=-1 THEN 1 ELSE 0 END),0) FROM likes WHERE target_type='post' AND target_id=?`, id).Scan(&dislikes)

	var user *User
	if u, err := getUserFromRequest(r); err == nil {
		user = u
	}

	data := map[string]interface{}{
		"Post": map[string]interface{}{
			"ID": id, "Title": title, "Body": body, "Author": author, "Created": created, "Likes": likes, "Dislikes": dislikes,
		},
		"Categories": cats,
		"Comments":   comments,
		"User":       user,
	}
	_ = templates.ExecuteTemplate(w, "post.html", data)
}

func handleCreateComment(w http.ResponseWriter, r *http.Request, user *User) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	postIDStr := r.FormValue("post_id")
	body := r.FormValue("body")
	pid, _ := strconv.Atoi(postIDStr)
	if pid == 0 || body == "" {
		http.Error(w, "missing data", http.StatusBadRequest)
		return
	}
	_, err := db.Exec(`INSERT INTO comments (post_id, author_id, body) VALUES (?, ?, ?)`, pid, user.ID, body)
	if err != nil {
		http.Error(w, "db error insert comment", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/post/%d", pid), http.StatusSeeOther)
}

/* handleLike expects POST form: target_type (post/comment), target_id, value (1 or -1) */
func handleLike(w http.ResponseWriter, r *http.Request, user *User) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	targetType := r.FormValue("target_type")
	targetID, _ := strconv.Atoi(r.FormValue("target_id"))
	val, _ := strconv.Atoi(r.FormValue("value"))
	if targetType == "" || targetID == 0 || (val != 1 && val != -1) {
		http.Error(w, "bad params", 400)
		return
	}
	// upsert: insert or replace existing value
	_, err := db.Exec(`
INSERT INTO likes (user_id, target_type, target_id, value)
VALUES (?, ?, ?, ?)
ON CONFLICT(user_id, target_type, target_id) DO UPDATE SET value=excluded.value, created_at=CURRENT_TIMESTAMP
`, user.ID, targetType, targetID, val)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	// redirect back
	ref := r.Referer()
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

/* handleFilter: query params: ?category=ID OR ?mine=1 OR ?liked=1 (mine & liked only for logged in) */
func handleFilter(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if cid := q.Get("category"); cid != "" {
		// show posts in category
		cidInt, _ := strconv.Atoi(cid)
		rows, _ := db.Query(`
SELECT p.id, p.title, p.body, u.username, p.created_at
FROM posts p
JOIN post_categories pc ON pc.post_id=p.id
JOIN users u ON u.id=p.author_id
WHERE pc.category_id=?
ORDER BY p.created_at DESC
`, cidInt)
		defer rows.Close()
		type PostView struct {
			ID                           int
			Title, Body, Author, Created string
		}
		posts := []PostView{}
		for rows.Next() {
			var p PostView
			_ = rows.Scan(&p.ID, &p.Title, &p.Body, &p.Created, &p.Author)
			posts = append(posts, p)
		}
		templates.ExecuteTemplate(w, "filter_category.html", posts)
		return
	}
	if q.Get("mine") == "1" {
		user, err := getUserFromRequest(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		rows, _ := db.Query(`SELECT id, title, body, created_at FROM posts WHERE author_id = ? ORDER BY created_at DESC`, user.ID)
		defer rows.Close()
		type P struct {
			ID                   int
			Title, Body, Created string
		}
		var posts []P
		for rows.Next() {
			var p P
			_ = rows.Scan(&p.ID, &p.Title, &p.Body, &p.Created)
			posts = append(posts, p)
		}
		templates.ExecuteTemplate(w, "filter_mine.html", posts)
		return
	}
	if q.Get("liked") == "1" {
		user, err := getUserFromRequest(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// get liked posts ids
		rows, _ := db.Query(`SELECT target_id FROM likes WHERE user_id=? AND target_type='post' AND value=1`, user.ID)
		defer rows.Close()
		var ids []int
		for rows.Next() {
			var id int
			_ = rows.Scan(&id)
			ids = append(ids, id)
		}
		posts := []struct {
			ID          int
			Title, Body string
		}{}
		for _, pid := range ids {
			var t, b string
			_ = db.QueryRow(`SELECT title, body FROM posts WHERE id=?`, pid).Scan(&t, &b)
			posts = append(posts, struct {
				ID          int
				Title, Body string
			}{ID: pid, Title: t, Body: b})
		}
		templates.ExecuteTemplate(w, "filter_liked.html", posts)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
