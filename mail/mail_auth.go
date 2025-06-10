package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/smtp"
	"time"
)

func GenerateConfirmationToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

func StoreConfirmationToken(rdb *redis.Client, email, token string) error {
	ctx := context.Background()
	return rdb.Set(ctx, "confirm:"+email, token, 24*time.Hour).Err()
}

func SendConfirmationEmail(email, token string) error {
	smtpHost := ""
	smtpPort := ""
	smtpUser := ""
	smtpPass := ""

	confirmationURL := "http://localhost:8080/confirm?token=" + token + "&email=" + email

	subject := "Confirm your email"
	body := "For confirmation, please click on the link:\n" + confirmationURL

	msg := "From: " + smtpUser + "\n" +
		"To: " + email + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	tslConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         smtpHost,
	}

	conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tslConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return err
	}
	defer client.Close()

	if err = client.Auth(auth); err != nil {
		return err
	}

	if err = client.Mail(smtpUser); err != nil {
		return err
	}

	if err = client.Rcpt(email); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = w.Write([]byte(msg))
	return err

}

func VerifyConfirmationToken(rdb *redis.Client, email, token string) (bool, error) {
	ctx := context.Background()
	storedToken, err := rdb.Get(ctx, "confirm:"+email).Result()

	if err == redis.Nil {
		return false, nil // Токен не найден
	} else if err != nil {
		return false, err // Ошибка Redis
	}

	return storedToken == token, nil
}

func HandleEmailConfirmationRequest(w http.ResponseWriter, r *http.Request) {
	// Получаем email из запроса
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Генерация токена
	token, err := GenerateConfirmationToken()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Сохранение токена
	if err := StoreConfirmationToken(redisClient, req.Email, token); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Отправка email
	if err := SendConfirmationEmail(req.Email, token); err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "confirmation email sent"})
}
