// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// EmailConfig configures an SMTP email channel.
type EmailConfig struct {
	base
	SMTPHost string
	From     string
	To       []string
	Username string
	Password string
}

// emailSender is injectable for tests.
type emailSender func(ctx context.Context, cfg EmailConfig, subject, body string) error

type emailChannel struct {
	cfg  EmailConfig
	send emailSender
}

// NewEmailChannel validates and returns an SMTP email Channel.
func NewEmailChannel(cfg EmailConfig) (Channel, error) {
	cfg.base.applyDefaults()
	if cfg.name == "" {
		return nil, errors.New("email: name is required")
	}
	if strings.TrimSpace(cfg.SMTPHost) == "" {
		return nil, errors.New("email: smtpHost is required")
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, errors.New("email: from is required")
	}
	if len(cfg.To) == 0 {
		return nil, errors.New("email: at least one to address is required")
	}
	return &emailChannel{cfg: cfg, send: smtpSend}, nil
}

func (c *emailChannel) Name() string           { return c.cfg.name }
func (c *emailChannel) MinSeverity() string    { return c.cfg.minSeverity }
func (c *emailChannel) Timeout() time.Duration { return c.cfg.timeout }
func (c *emailChannel) MaxAttempts() int       { return c.cfg.maxAttempts }

func (c *emailChannel) Send(ctx context.Context, ev Event) error {
	if !c.cfg.accepts(ev.Severity) {
		return nil
	}
	return c.send(ctx, c.cfg, Title(ev), Plain(ev))
}

func smtpSend(ctx context.Context, cfg EmailConfig, subject, body string) error {
	host, port, err := net.SplitHostPort(cfg.SMTPHost)
	if err != nil {
		host = cfg.SMTPHost
		port = "587"
	}
	addr := net.JoinHostPort(host, port)

	var msg strings.Builder
	fmt.Fprintf(&msg, "From: %s\r\n", cfg.From)
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(cfg.To, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("email %s: dial: %w", cfg.name, err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("email %s: smtp: %w", cfg.name, err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("email %s: starttls: %w", cfg.name, err)
		}
	}
	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email %s: auth: %w", cfg.name, err)
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("email %s: mail: %w", cfg.name, err)
	}
	for _, to := range cfg.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("email %s: rcpt %s: %w", cfg.name, to, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email %s: data: %w", cfg.name, err)
	}
	if _, err := w.Write([]byte(msg.String())); err != nil {
		_ = w.Close()
		return fmt.Errorf("email %s: write: %w", cfg.name, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email %s: close: %w", cfg.name, err)
	}
	return client.Quit()
}
