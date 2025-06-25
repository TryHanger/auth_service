package mail

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
)

func SendConfirmationEmail(toEmail, token string) error {
	smtpHost := os.Getenv("SMTP_HOST") // напр. smtp.gmail.com
	smtpPort := os.Getenv("SMTP_PORT") // напр. 587
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	appURL := os.Getenv("APP_URL")

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	confirmationURL := fmt.Sprintf("%s/confirm?token=%s&email=%s", appURL, token, toEmail)
	subject := "Confirm your email"
	body := "Click to confirm:\n" + confirmationURL

	msg := []byte("To: " + toEmail + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body)

	// Подключаемся без шифрования
	client, err := smtp.Dial(smtpHost + ":" + smtpPort)
	if err != nil {
		return err
	}
	defer client.Close()

	// Используем TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         smtpHost,
	}
	if err = client.StartTLS(tlsConfig); err != nil {
		return err
	}

	// Аутентификация
	if err = client.Auth(auth); err != nil {
		return err
	}

	// Отправка письма
	if err = client.Mail(smtpUser); err != nil {
		return err
	}
	if err = client.Rcpt(toEmail); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	defer w.Close()

	if _, err = w.Write(msg); err != nil {
		return err
	}

	return nil
}
