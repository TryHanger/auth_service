package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"time"

	"github.com/redis/go-redis/v9"
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
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	smtpUser := "berkenov.a.2006@gmail.com"
	smtpPass := "ezbi lqpl tifg qvyq"

	confirmationURL := "http://localhost:8080/confirm?token=" + token + "&email=" + email

	subject := "Confirm your email"
	body := "For confirmation, please click on the link:\n" + confirmationURL

	msg := "From: " + smtpUser + "\n" +
		"To: " + email + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	conn, err := net.Dial("tcp", smtpHost+":"+smtpPort)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	if err = client.StartTLS(&tls.Config{
		InsecureSkipVerify: false,
		ServerName:         smtpHost,
	}); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}

	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	if err = client.Mail(smtpUser); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	if err = client.Rcpt(email); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer w.Close()

	_, err = w.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	return nil
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
