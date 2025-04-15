package main

// ... imports (context, log, os, signal, time, certifytheweb, gomail)
import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/certifytheweb/certifytheweb"
	"gopkg.in/gomail.v2"
)

const (
	// How often to poll the Certify The Web instance
	checkInterval = 8 * time.Hour
	// Alert if certificate expires within this duration (safety net)
	criticalExpiryThreshold = 10 * 24 * time.Hour
	// Optional: Log warning if certificate expires within this duration
	warningExpiryThreshold = 21 * 24 * time.Hour
)

// Struct to hold configuration (loaded from file/env)
type Config struct {
	CertifyConfigPath string
	SMTPServer        string
	SMTPPort          int
	SMTPUser          string
	SMTPPass          string
	AdminEmail        string
}

func main() {
	// Load config (replace hardcoded values)
	cfg := loadConfiguration() // Implement this function

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	certManager := certifytheweb.NewCertManager()
	if err := certManager.Configure(cfg.CertifyConfigPath); err != nil {
		log.Fatalf("Failed to configure CertifyTheWeb connection: %v\n", err)
		// Ensure config path points to connection details for the Azure VM instance
	}

	// Verify initial connection (optional but recommended)
	if _, err := certManager.GetCertificates(); err != nil {
		log.Fatalf("Failed to connect or get initial certificates from CertifyTheWeb instance: %v\n", err)
	}
	log.Println("Successfully connected to CertifyTheWeb instance.")

	monitorCertificates := func() {
		log.Println("Checking certificate status...")
		certs, err := certManager.GetCertificates()
		if err != nil {
			log.Printf("Error getting certificates from Certify instance: %v\n", err)
			// Maybe send an alert if connection fails repeatedly?
			return
		}

		now := time.Now()
		for _, cert := range certs {
			timeUntilExpiry := cert.ExpiryDate.Sub(now)
			log.Printf("  Domain: %s, Expires: %s (in %v)\n", cert.Domain, cert.ExpiryDate.Format(time.RFC3339), timeUntilExpiry.Round(time.Hour))

			// Check for critical expiry (Certify auto-renewal might have failed)
			if timeUntilExpiry < criticalExpiryThreshold {
				subject := fmt.Sprintf("CRITICAL: Certificate for %s expires soon!", cert.Domain)
				body := fmt.Sprintf("Certificate for %s expires on %s (%v remaining).\nAutomatic renewal may have failed. Please investigate the Certify The Web instance on the Azure VM immediately.",
					cert.Domain, cert.ExpiryDate.Format(time.RFC3339), timeUntilExpiry.Round(time.Hour))
				sendAlert(subject, body, cfg)
			} else if timeUntilExpiry < warningExpiryThreshold {
				log.Printf("  WARNING: Certificate for %s entering renewal window soon.\n", cert.Domain)
			}

			// --- DO NOT TRIGGER RENEWAL HERE ---
			// Let the Certify The Web instance handle its own scheduled renewals.
			// The RenewCertificate call should be removed/commented.
			/*
			   if timeUntilExpiry < renewalThreshold { // Old logic
			       log.Printf("Certificate for %s expiring in %s. Renewing...\n", cert.Domain, timeUntilExpiry)
			       if err := certManager.RenewCertificate(cert); err != nil { // DON'T DO THIS
			           // ... old alerting ...
			       }
			   }
			*/
		}
		log.Println("Certificate status check complete.")
	}

	// Initial check
	monitorCertificates()

	// Periodic check
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Gracefully shutting down monitor...")
			return
		case <-ticker.C:
			monitorCertificates()
		}
	}
}

// Implement loadConfiguration() to load from JSON/env

// Refactor alertRenewalFailure to sendAlert
func sendAlert(subject, body string, cfg Config) {
	log.Printf("ALERT: %s\nBody: %s\n", subject, body) // Log the alert

	// Log to file (optional)
	// ... file logging ...

	// Send email notification
	m := gomail.NewMessage()
	m.SetHeader("From", cfg.SMTPUser) // Use config
	m.SetHeader("To", cfg.AdminEmail) // Use config
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	d := gomail.NewDialer(cfg.SMTPServer, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass) // Use config

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Error sending alert email: %v\n", err)
	} else {
		log.Println("Alert email sent successfully")
	}
}
