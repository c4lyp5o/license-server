// +build !dev

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/time/rate"
)

var secretKey = []byte("your-secret-key")
var client *mongo.Client
var store = sessions.NewCookieStore([]byte("your-secret-key"))

type User struct {
	ID            primitive.ObjectID `bson:"_id,omitempty"`
	Name          string             `bson:"name,omitempty"`
	Email         string             `bson:"email,omitempty" unique:"true"`
	APIKey        string             `bson:"apikey,omitempty"`
	PurchaseDate  time.Time          `bson:"purchase_date,omitempty"`
	ExpiryDate    time.Time          `bson:"expiry_date,omitempty"`
	Products      []string           `bson:"products,omitempty"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
		fmt.Println("[LS-GO] Could not load environment variables from .env file")
		fmt.Println("[LS-GO] Stopped application")
		os.Exit(1)
	} else {
		fmt.Println("[LS-GO] Loaded environment variables from .env file")
	}

	serverPort := os.Getenv("SERVER_PORT")
	devEnv := os.Getenv("DEV_ENV")

    databaseName := os.Getenv("MONGO_DATABASE")
    collectionName := os.Getenv("MONGO_COLLECTION")
    collection := client.Database(databaseName).Collection(collectionName)

	connectToMongoDB()

	router := mux.NewRouter()

	router.Use(rateLimiter)

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "[LS-GO] This is License Server v1.0")
	})
	router.HandleFunc("/api/v1/generate-token", generateToken)
	router.HandleFunc("/api/v1/verify-token", verifyToken)
	router.HandleFunc("/api/v1/set-session", setSession)
	router.HandleFunc("/api/v1/get-session", getSession)
	router.HandleFunc("/api/v1/protected-route", jwtMiddleware(protectedRouteHandler))
	router.HandleFunc("/api/v1/get-all-users", getAllUsersHandler)
	router.HandleFunc("/api/v1/get-user", getUserHandler)
	router.HandleFunc("/api/v1/insert-user", insertUserHandler)

	fmt.Println("[LS-GO] Starting server on port:", strings.Trim(serverPort, ":"))
	fmt.Println("[LS-GO] Running in environment:", devEnv)
	fmt.Println("[LS-GO] This is License Server v1.0")
		
	log.Fatal(http.ListenAndServe(serverPort, router))
}

func connectToMongoDB() error {
    mongoURI := os.Getenv("MONGO_URI")

    clientOptions := options.Client().ApplyURI(mongoURI)

    var err error
    client, err = mongo.Connect(context.Background(), clientOptions)
    if err != nil {
        return err
    }

    err = client.Ping(context.Background(), nil)
    if err != nil {
        return err
    }

    return nil
}

func generateToken(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query()
    apikey := query.Get("apikey")

    filter := bson.M{"apikey": apikey}
    var result bson.M
    err := collection.FindOne(context.Background(), filter).Decode(&result)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    token := jwt.New(jwt.SigningMethodHS256)
    claims := token.Claims.(jwt.MapClaims)
    claims["expiry_date"] = result["expiry_date"]
    claims["products"] = result["products"]
    
    signedToken, err := token.SignedString(secretKey)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    w.Write([]byte(signedToken))
}

func verifyToken(w http.ResponseWriter, r *http.Request) {
    tokenString := r.Header.Get("Authorization")
    if tokenString == "" {
        http.Error(w, "Token missing", http.StatusUnauthorized)
        return
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return secretKey, nil
    })

    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    if !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    w.Write([]byte("Token is valid"))
}

func insertUser(user *User) error {
    _, err := collection.InsertOne(context.Background(), user)
    if err != nil {
        return err
    }

    return nil
}

func insertUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Printf("Request body: %+v\n", user)

	err = insertUser(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

    w.WriteHeader(http.StatusCreated)
    w.Write([]byte("User created"))
}

func getAllUsers() ([]*User, error) {
	databaseName := os.Getenv("MONGO_DATABASE")
    collectionName := os.Getenv("MONGO_COLLECTION")
    collection := client.Database(databaseName).Collection(collectionName)

	cursor, err := collection.Find(context.Background(), bson.M{})
	if err != nil {
		return nil, err
	}

	// Iterate through the returned cursor
	var users []*User
	for cursor.Next(context.Background()) {
		// Declare a user struct to decode each document into
		var user User

		// Decode the document into the user struct
		err := cursor.Decode(&user)
		if err != nil {
			return nil, err
		}

		// Append the user struct to the users slice
		users = append(users, &user)
	}

	return users, nil
}

func getAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	users, err := getAllUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("User documents: %+v\n", users)

	json.NewEncoder(w).Encode(users)
}

func getUser(userID string) (*User, error) {
    objID, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return nil, err
    }

    filter := bson.M{"_id": objID}

    var user User
    err = collection.FindOne(context.Background(), filter).Decode(&user)
    if err != nil {
        return nil, err
    }

    return &user, nil
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
    userID := mux.Vars(r)["id"]

    user, err := getUser(userID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    if user == nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    fmt.Printf("User document: %+v\n", user)

    json.NewEncoder(w).Encode(user)
}

func setSession(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")
    session.Values["username"] = "example_user"
    session.Save(r, w)
}

func getSession(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")
    username := session.Values["username"]
    w.Write([]byte(username.(string)))
}

func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Token missing", http.StatusUnauthorized)
            return
        }

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return secretKey, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    }
}

func rateLimiter(next http.Handler) http.Handler {
    limiter := rate.NewLimiter(rate.Every(time.Second), 10)

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            http.Error(w, "Too many requests", http.StatusTooManyRequests)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func protectedRouteHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Protected route"))
}