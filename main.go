package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"cloud.google.com/go/bigquery"
	"github.com/joho/godotenv"
	"github.com/pkg/profile"
	"google.golang.org/api/iterator"
)

// EnvLoad ...
func EnvLoad() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

// UserInfo ...
type UserInfo struct {
	Password string `json:"password"`
}

// Request ...
type Request struct {
	Username   string `json:"username"`
	RequestPWD string `json:"password"`
}

// Iterator ...
type Iterator interface {
	Next(interface{}) error
}

func getPasswordIter(ctx context.Context, username string) (Iterator, error) {
	projectID := os.Getenv("GCP_PROJECT_ID")
	dataset := os.Getenv("BQ_DATASET_NAME")
	table := os.Getenv("BQ_AUTH_TABLE_NAME")

	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		log.Println("[Error]: ", err)
		return nil, err
	}
	defer client.Close()

	query := fmt.Sprintf(
		"SELECT password FROM `%s.%s.%s` WHERE user_id='%s'",
		projectID,
		dataset,
		table,
		username,
	)

	q := client.Query(query)
	job, err := q.Run(ctx)
	if err != nil {
		log.Println("[Query Error]: ", err)
		return nil, err
	}
	status, err := job.Wait(ctx)
	if err != nil {
		log.Println("[Job Error]: ", err)
		return nil, err
	}
	if err := status.Err(); err != nil {
		log.Println("[Status Error]: ", err)
		return nil, err
	}

	it, err := job.Read(ctx)
	if err != nil {
		log.Println("[Read Error]: ", err)
		return nil, err
	}

	return it, nil
}

// GetHashedPWD ...
func GetHashedPWD(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", os.Getenv("ALLOW_ORIGIN"))
	w.Header().Set(
		"Access-Control-Allow-Headers",
		"Origin, X-Requested-With, Content-Type, Accept, Authorization",
	)
	if r.Method == "OPTIONS" {
		w.WriteHeader(200)
		return
	}

	var req = new(Request)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println("[Request Error]: ", err)
		return
	}

	if req.RequestPWD != os.Getenv("REQUEST_PWD") {
		log.Println("[Permission Error] Status Code 400")
		fmt.Fprintf(w, "Permission denied\n")
		return
	}

	username := req.Username

	ctx := context.Background()
	it, err := getPasswordIter(ctx, username)

	if err != nil {
		return
	}

	for {
		var row []bigquery.Value
		err := it.Next(&row)
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Println("[Iterator Error]: ", err)
			return
		}

		if password, ok := row[0].(string); ok {
			hashedPwd := sha256.Sum256([]byte(password))
			hashedPwdStr := hex.EncodeToString(hashedPwd[:])

			resp := UserInfo{hashedPwdStr}
			jresp, err := json.Marshal(resp)

			if err != nil {
				log.Println("[JSON Error]: ", err)
				return
			}

			w.Write(jresp)
			break
		}

	}

	log.Println("[Request]: Status Code 200")
}

func main() {
	defer profile.Start(profile.MemProfile, profile.ProfilePath(".")).Stop()
	EnvLoad()

	http.HandleFunc("/login", GetHashedPWD)
	http.ListenAndServe(":8080", nil)
}
