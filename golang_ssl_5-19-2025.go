package main

import (
	"context"     // For managing cancellation and shutdown signals
	"crypto/x509" // For handling X.509 certificates
	// For TLS configuration and handling
	"fmt"           // For formatted string operations (alerts and logs)
	"log"           // For logging messages	to the console
	"net/http"      // For HTTP server and request handling
	"os"            // For OS-level operations (environment variables, file handling)
	"os/signal"     // For handling OS signals like Ctrl+C
	"path/filepath" // For file path manipulations
	"syscall"       // For handling specific signal constants (like SIGTERM)
	"time"          // For time calculations and scheduling

	"golang.org/x/crypto/acme/autocert" // For automatic certificate management
	"gopkg.in/gomail.v2"                // For sending email alerts via SMTP
)

// How often to check the instance for certificate status
const (
	checkInterval           = 8 * time.Hour
	criticalExpiryThreshold = 10 * 24 * time.Hour
	warningExpiryThreshold  = 21 * 24 * time.Hour
	maxConnectionFailures   = 3
	certCacheDir            = "./cert_cache"
)

// Configuration structure to hold domain names, SMTP settings, and admin email
type Config struct {
	Domains          []string
	SMTPServer       string
	SMTPPort         int
	SMTPUser         string
	SMTPPass         string
	AdminEmail       string
	LetsEncryptEmail string
}

func loadConfiguration() Config {
	return Config{
		Domains:          []string{"yourdomain.com", "www.yourdomain.com"},
		LetsEncryptEmail: "admin@yourdomain.com",
		SMTPServer:       os.Getenv("SMTP_SERVER"),
		SMTPPort:         587,
		SMTPUser:         os.Getenv("SMTP_USER"),
		SMTPPass:         os.Getenv("SMTP_PASS"),
		AdminEmail:       os.Getenv("ADMIN_EMAIL"),
	}
}

func main() {
	cfg := loadConfiguration()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      cfg.LetsEncryptEmail,
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Cache:      autocert.DirCache(certCacheDir),
	}

	// Setup HTTPS server
	server := &http.Server{
		Addr:      ":443",
		Handler:   http.HandlerFunc(handleRequest),
		TLSConfig: certManager.TLSConfig(),
	}

	// Start certificate monitoring
	go monitorCertificates(ctx, &certManager, cfg)

	// Start HTTPS server
	go func() {
		log.Println("Starting HTTPS server on :443")
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	// Start HTTP server for ACME challenges
	go func() {
		log.Println("Starting HTTP server on :80")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down servers...")
	server.Shutdown(context.Background())
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello Secure World! Your connection is secured with a certificate from %s", r.TLS.PeerCertificates[0].Issuer)
}

func monitorCertificates(ctx context.Context, mgr *autocert.Manager, cfg Config) {
	connectionFailureCount := 0
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			certs, err := loadCertificatesFromCache(mgr)
			if err != nil {
				connectionFailureCount++
				log.Printf("Certificate check failed (%d/%d): %v", connectionFailureCount, maxConnectionFailures, err)

				if connectionFailureCount >= maxConnectionFailures {
					sendAlert("CRITICAL: Certificate Monitoring Failure",
						fmt.Sprintf("Failed to check certificates %d times: %v", connectionFailureCount, err), cfg)
				}
				continue
			}

			connectionFailureCount = 0
			checkExpirations(certs, cfg)
		}
	}
}

func loadCertificatesFromCache(mgr *autocert.Manager) ([]*x509.Certificate, error) {
	cache, ok := mgr.Cache.(autocert.DirCache)
	if !ok {
		return nil, fmt.Errorf("unsupported cache type")
	}

	var certs []*x509.Certificate
	err := filepath.Walk(string(cache), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".crt" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		cert, err := x509.ParseCertificate(data)
		if err == nil {
			certs = append(certs, cert)
		}
		return nil
	})

	return certs, err
}

func checkExpirations(certs []*x509.Certificate, cfg Config) {
	now := time.Now()
	for _, cert := range certs {
		expiry := cert.NotAfter
		remaining := expiry.Sub(now)

		log.Printf("Certificate %s expires in %v", cert.DNSNames, remaining.Round(time.Hour))

		if remaining < criticalExpiryThreshold {
			subject := fmt.Sprintf("CRITICAL: Certificate %s Expiring Soon", cert.DNSNames)
			body := fmt.Sprintf("Certificate for %s expires on %s (%v remaining)",
				cert.DNSNames, expiry.Format(time.RFC3339), remaining.Round(time.Hour))
			sendAlert(subject, body, cfg)
		} else if remaining < warningExpiryThreshold {
			log.Printf("WARNING: Certificate %s entering renewal window", cert.DNSNames)
		}
	}
}

func sendAlert(subject, body string, cfg Config) {
	log.Printf("ALERT: %s - %s", subject, body)

	if cfg.AdminEmail == "" || cfg.SMTPServer == "" {
		return
	}

	m := gomail.NewMessage()
	m.SetHeader("From", cfg.SMTPUser)
	m.SetHeader("To", cfg.AdminEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	d := gomail.NewDialer(cfg.SMTPServer, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass)
	if err := d.DialAndSend(m); err != nil {
		log.Printf("Failed to send alert email: %v", err)
	}
}
