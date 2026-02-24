package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net/mail"
	"net/smtp"
	"strings"

	"biliticket/userhub/internal/config"
)

type MailSender interface {
	Send(ctx context.Context, to string, subject string, body string) error
}

type smtpSender struct {
	cfg config.SMTPConfig
}

func NewSMTPSender(cfg config.SMTPConfig) (MailSender, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("smtp host is required")
	}
	if cfg.Port <= 0 {
		return nil, fmt.Errorf("smtp port must be greater than 0")
	}
	if strings.TrimSpace(cfg.FromEmail) == "" {
		return nil, fmt.Errorf("smtp from_email is required")
	}
	if _, err := mail.ParseAddress(cfg.FromEmail); err != nil {
		return nil, fmt.Errorf("invalid smtp from_email: %w", err)
	}
	return &smtpSender{cfg: cfg}, nil
}

func (s *smtpSender) Send(_ context.Context, to string, subject string, body string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("recipient email is required")
	}
	if _, err := mail.ParseAddress(to); err != nil {
		return fmt.Errorf("invalid recipient email: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("dial smtp server: %w", err)
	}
	defer client.Close()

	if s.cfg.UseSTARTTLS {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return fmt.Errorf("smtp server does not support STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{
			ServerName:         s.cfg.Host,
			InsecureSkipVerify: s.cfg.SkipTLSVerify,
		}); err != nil {
			return fmt.Errorf("starttls failed: %w", err)
		}
	}

	if strings.TrimSpace(s.cfg.Username) != "" {
		ok, _ := client.Extension("AUTH")
		if !ok {
			return fmt.Errorf("smtp server does not support AUTH")
		}
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth failed: %w", err)
		}
	}

	if err := client.Mail(s.cfg.FromEmail); err != nil {
		return fmt.Errorf("smtp MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO failed: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA failed: %w", err)
	}

	fromHeader := s.cfg.FromEmail
	if strings.TrimSpace(s.cfg.FromName) != "" {
		fromHeader = (&mail.Address{
			Name:    s.cfg.FromName,
			Address: s.cfg.FromEmail,
		}).String()
	}
	subjectHeader := mime.QEncoding.Encode("UTF-8", subject)
	msg := strings.Builder{}
	msg.WriteString("From: " + fromHeader + "\r\n")
	msg.WriteString("To: " + to + "\r\n")
	msg.WriteString("Subject: " + subjectHeader + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	if _, err := writer.Write([]byte(msg.String())); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write smtp body failed: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close smtp writer failed: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("smtp quit failed: %w", err)
	}
	return nil
}
