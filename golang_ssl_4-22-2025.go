package main

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
	// Number of consecutive connection failures before sending an alert
	maxConnectionFailures = 3 // NEW CONSTANT
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

// Implement loadConfiguration() to load from JSON/env/etc.
// Example placeholder:
func loadConfiguration() Config {
	// In a real scenario, load from a file (e.g., config.json) or environment variables
	log.Println("WARN: Using placeholder configuration. Implement loadConfiguration()")
	return Config{
		CertifyConfigPath: "path/to/your/certify/connection/config.json", // Needs valid path
		SMTPServer:        "smtp.example.com",
		SMTPPort:          587,
		SMTPUser:          "user@example.com",
		SMTPPass:          "your_password",
		AdminEmail:        "admin@yourdomain.com",
	}
}

func main() {
	// Load config
	cfg := loadConfiguration() // Implement this properly!

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	certManager := certifytheweb.NewCertManager()
	// Ensure config path points to connection details for the Azure VM instance
	// This file typically contains the API endpoint and access token/key
	if err := certManager.Configure(cfg.CertifyConfigPath); err != nil {
		// Configuration error is fatal, as we don't know where to connect
		log.Fatalf("Failed to configure CertifyTheWeb connection using path '%s': %v\n", cfg.CertifyConfigPath, err)
	}

	// Verify initial connection (optional but recommended)
	if _, err := certManager.GetCertificates(); err != nil {
		// Log warning but allow startup, maybe the service is just starting?
		// The loop below will handle persistent failures.
		log.Printf("WARN: Failed to get initial certificates from CertifyTheWeb instance: %v\n", err)
		log.Printf("WARN: Will attempt connection periodically. Ensure CertifyTheWeb service is running and accessible.")
	} else {
		log.Println("Successfully connected to CertifyTheWeb instance initially.")
	}

	// State for tracking connection issues
	connectionFailureCount := 0 // NEW STATE VARIABLE

	monitorCertificates := func() {
		// This function now assumes the connection was successful just before it was called
		// OR handles errors internally gracefully. Let's keep the GetCertificates call here
		// for simplicity of the monitoring logic itself.

		log.Println("Checking certificate status...")
		certs, err := certManager.GetCertificates()
		if err != nil {
			// This specific error is now handled by the loop logic outside this func
			// We log it here for context during the check, but don't alert yet.
			log.Printf("Error getting certificates during scheduled check: %v\n", err)
			// We need to signal failure to the main loop
			// Returning an error is one way, but modifies the signature.
			// For minimal change, we rely on the check *before* calling this in the loop.
			// Let's adjust this slightly: move GetCertificates *outside* this func
			// and pass the certs list in.
			// --- See revised structure below ---
			return // Exit if we couldn't get certs
		}

		// If we reached here, GetCertificates succeeded in *this* attempt.
		// The counter reset happens outside this func.

		now := time.Now()
		foundCritical := false // Track if critical issues found in this run

		for _, cert := range certs {
			timeUntilExpiry := cert.ExpiryDate.Sub(now)
			log.Printf("  Domain: %s, Expires: %s (in %v)\n", cert.Domain, cert.ExpiryDate.Format(time.RFC3339), timeUntilExpiry.Round(time.Hour))

			// Check for critical expiry (Certify auto-renewal might have failed)
			if timeUntilExpiry < criticalExpiryThreshold {
				foundCritical = true
				subject := fmt.Sprintf("CRITICAL: Certificate for %s expires soon!", cert.Domain)
				body := fmt.Sprintf("Certificate for %s expires on %s (%v remaining).\nAutomatic renewal may have failed. Please investigate the Certify The Web instance on the Azure VM immediately.",
					cert.Domain, cert.ExpiryDate.Format(time.RFC3339), timeUntilExpiry.Round(time.Hour))
				sendAlert(subject, body, cfg) // Alert immediately for critical expiry
			} else if timeUntilExpiry < warningExpiryThreshold {
				log.Printf("  WARNING: Certificate for %s entering renewal window soon.\n", cert.Domain)
			}
			// --- Renewal logic correctly commented out ---
		}
		log.Println("Certificate status check complete.")
		if foundCritical {
			log.Println("CRITICAL EXPIRY DETECTED. Alerts sent.")
		}
	}

	// ---- Revised Ticker Loop ----
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	// Perform an initial check immediately
	log.Println("Performing initial certificate check...")
	certs, err := certManager.GetCertificates()
	if err != nil {
		log.Printf("Error during initial check: %v\n", err)
		connectionFailureCount++ // Increment on initial failure too
		// Optional: Send immediate alert on initial failure? Depends on requirements.
		// For now, we just increment and wait for the threshold.
	} else {
		connectionFailureCount = 0              // Reset if initial check works
		monitorCertificatesInternal(certs, cfg) // Call internal logic
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Gracefully shutting down monitor...")
			return
		case <-ticker.C:
			log.Println("Periodic check triggered.")
			certs, err := certManager.GetCertificates() // Check connection first
			if err != nil {
				// Connection failed
				connectionFailureCount++
				log.Printf("Failed to connect/get certificates (%d/%d consecutive failures): %v\n",
					connectionFailureCount, maxConnectionFailures, err)

				if connectionFailureCount >= maxConnectionFailures {
					log.Printf("Connection failure threshold reached (%d). Sending alert.\n", maxConnectionFailures)
					subject := "CRITICAL: Cannot connect to Certify The Web instance"
					body := fmt.Sprintf("Failed to connect to the Certify The Web instance and retrieve certificates for %d consecutive checks.\nLast error: %v\nPlease check the Certify The Web service on the Azure VM and network connectivity.",
						connectionFailureCount, err)
					sendAlert(subject, body, cfg)
					// Optional: Reset counter after alerting to avoid spamming?
					// Or keep it high until success? Let's reset to prevent spamming.
					// connectionFailureCount = 0
					// Let's actually *not* reset here - keep alerting until connection restored.
					// Administrator should fix the issue causing the alert.
				}
			} else {
				// Connection succeeded
				if connectionFailureCount > 0 {
					log.Printf("Connection to Certify The Web instance restored after %d failure(s).\n", connectionFailureCount)
					// Optional: Send a "resolved" notification?
					/*
						subject := "RESOLVED: Connection to Certify The Web instance restored"
						body := fmt.Sprintf("Successfully re-established connection to the Certify The Web instance after %d failed check(s).", connectionFailureCount)
						sendAlert(subject, body, cfg)
					*/
				}
				connectionFailureCount = 0              // Reset counter on success
				monitorCertificatesInternal(certs, cfg) // Run the actual checks only if connection works
			}
		}
	}
}

// Renamed internal function to avoid confusion
func monitorCertificatesInternal(certs []certifytheweb.CertificateInfo, cfg Config) {
	log.Println("Processing certificate status...")
	now := time.Now()
	foundCritical := false

	for _, cert := range certs {
		timeUntilExpiry := cert.ExpiryDate.Sub(now)
		log.Printf("  Domain: %s, Expires: %s (in %v)\n", cert.Domain, cert.ExpiryDate.Format(time.RFC3339), timeUntilExpiry.Round(time.Hour))

		if timeUntilExpiry < criticalExpiryThreshold {
			foundCritical = true
			subject := fmt.Sprintf("CRITICAL: Certificate for %s expires soon!", cert.Domain)
			body := fmt.Sprintf("Certificate for %s expires on %s (%v remaining).\nAutomatic renewal may have failed. Please investigate the Certify The Web instance on the Azure VM immediately.",
				cert.Domain, cert.ExpiryDate.Format(time.RFC3339), timeUntilExpiry.Round(time.Hour))
			sendAlert(subject, body, cfg)
		} else if timeUntilExpiry < warningExpiryThreshold {
			log.Printf("  WARNING: Certificate for %s entering renewal window soon.\n", cert.Domain)
		}
	}
	log.Println("Certificate status processing complete.")
	if foundCritical {
		log.Println("CRITICAL EXPIRY DETECTED during processing. Alerts sent.")
	}
}

// sendAlert function remains the same
func sendAlert(subject, body string, cfg Config) {
	log.Printf("ALERT: %s\nBody: %s\n", subject, body) // Log the alert

	// Optional: Log to file
	// ... file logging ...

	// Send email notification
	if cfg.AdminEmail == "" || cfg.SMTPServer == "" {
		log.Println("Email configuration missing, cannot send alert email.")
		return
	}

	m := gomail.NewMessage()
	m.SetHeader("From", cfg.SMTPUser) // Use config (often same as user)
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
