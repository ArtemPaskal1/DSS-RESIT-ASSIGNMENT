package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/gorilla/mux"
	_ "github.com/jackc/pgx/v4/stdlib"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type Comment struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

func main() {

	connStr := "postgres://postgres:Gafentiy@localhost/socialmedia?sslmode=disable"
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatal(err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		log.Fatal(err)
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		log.Fatal(err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/register", registerHandler(db)).Methods("POST")
	router.HandleFunc("/login", loginHandler(db)).Methods("POST")
	router.HandleFunc("/comments", createCommentHandler(db)).Methods("POST")
	router.HandleFunc("/comments/{id}", getCommentHandler(db)).Methods("GET")
	router.HandleFunc("/comments/{id}", updateCommentHandler(db)).Methods("PUT")
	router.HandleFunc("/comments/{id}", deleteCommentHandler(db)).Methods("DELETE")
	router.HandleFunc("/admin/login", adminLoginHandler).Methods("POST")

	router.Use(adminAuthMiddleware)

	log.Println("Server started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func registerHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user.Password = string(hashedPassword)

		_, err = db.Exec("INSERT INTO users (username, password, created_at) VALUES ($1, $2, $3)", user.Username, user.Password, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

func loginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var storedUser User
		err = db.QueryRow("SELECT id, username, password, created_at FROM users WHERE username = $1", user.Username).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password, &storedUser.CreatedAt)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func createCommentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var comment Comment
		err := json.NewDecoder(r.Body).Decode(&comment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_, err = db.Exec("INSERT INTO comments (user_id, content, created_at) VALUES ($1, $2, $3)", comment.UserID, comment.Content, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

func getCommentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		params := mux.Vars(r)
		commentID := params["id"]

		var comment Comment
		err := db.QueryRow("SELECT id, user_id, content, created_at FROM comments WHERE id = $1", commentID).Scan(&comment.ID, &comment.UserID, &comment.Content, &comment.CreatedAt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(comment)
	}
}

func updateCommentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		params := mux.Vars(r)
		commentID := params["id"]

		var updatedComment Comment
		err := json.NewDecoder(r.Body).Decode(&updatedComment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_, err = db.Exec("UPDATE comments SET content = $1 WHERE id = $2", updatedComment.Content, commentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func deleteCommentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		params := mux.Vars(r)
		commentID := params["id"]

		_, err := db.Exec("DELETE FROM comments WHERE id = $1", commentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {

	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authorization failed", http.StatusUnauthorized)
		return
	}

	if username != "admin" || password != "adminpassword" {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if !isAuthenticatedAdmin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isAuthenticatedAdmin(r *http.Request) bool {

	return true
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	var html string

	switch tmpl {
	case "register":
		html = `
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Register</title>
			</head>
			<body>
				<h2>Register</h2>
				<form action="/register" method="post">
					<label for="username">Username:</label><br>
					<input type="text" id="username" name="username"><br>
					<label for="password">Password:</label><br>
					<input type="password" id="password" name="password"><br><br>
					<input type="submit" value="Register">
				</form>
			</body>
			</html>
		`
	case "login":
		html = `
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Login</title>
			</head>
			<body>
				<h2>Login</h2>
				<form action="/login" method="post">
					<label for="username">Username:</label><br>
					<input type="text" id="username" name="username"><br>
					<label for="password">Password:</label><br>
					<input type="password" id="password" name="password"><br><br>
					<input type="submit" value="Login">
				</form>
			</body>
			</html>
		`
	default:
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if _, err := fmt.Fprint(w, html); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
