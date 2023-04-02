package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtSecretKey = []byte("jwt_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type LoginDto struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var customers = map[string]string{
	"test": "pass1",
}

func Login(response http.ResponseWriter, request *http.Request) {

	var loginDto LoginDto

	err := json.NewDecoder(request.Body).Decode(&loginDto)
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := customers[loginDto.Username]

	if !ok || expectedPassword != loginDto.Password {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationJwtTokenTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: loginDto.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationJwtTokenTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(response, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationJwtTokenTime,
	})

}

func RefreshToken(response http.ResponseWriter, request *http.Request) {

	tokenObjectFetchFromCookie, err := request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenStringFetchFromCookie := tokenObjectFetchFromCookie.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStringFetchFromCookie, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}

	if time.Until(claims.ExpiresAt.Time) > (60 * time.Second) {
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	expirationJwtTokenTime := time.Now().Add(10 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationJwtTokenTime)
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := newToken.SignedString(jwtSecretKey)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(response, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationJwtTokenTime,
	})

}

func Info(response http.ResponseWriter, request *http.Request) {

	tokenObjectFetchFromCookie, err := request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}

		response.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStringFetchFromCookie := tokenObjectFetchFromCookie.Value

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStringFetchFromCookie, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}

	response.Write([]byte(fmt.Sprintf("Your username: %s!", claims.Username)))

}

func Exit(response http.ResponseWriter, request *http.Request) {

	http.SetCookie(response, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})

}

func main() {

	http.HandleFunc("/login", Login)
	http.HandleFunc("/refresh-token", RefreshToken)
	http.HandleFunc("/info", Info)
	http.HandleFunc("/exit", Exit)

	log.Fatal(http.ListenAndServe(":8080", nil))

}
