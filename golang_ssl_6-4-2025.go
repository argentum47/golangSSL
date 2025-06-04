package main

import (
	"context" // For managing cancellation and shutdown signals
	"crypto/tls"
	"crypto/x509" // For handling X.509 certificates
	"fmt"         // For formatted string operations (alerts and logs)
	"log"         // For logging messages	to the console
	"net/http"    // For HTTP server and request handling
	"os"          // For OS-level operations (environment variables, file handling)
	"os/signal"   // For handling OS signals like Ctrl+C
	"strings"

	// For file path manipulations
	"syscall" // For handling specific signal constants (like SIGTERM)
	"time"    // For time calculations and scheduling

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

func loadConfiguration() (Config, error) {
	cfg := Config{
		SMTPServer:       os.Getenv("SMTP_SERVER"),
		SMTPUser:         os.Getenv("SMTP_USER"),
		SMTPPass:         os.Getenv("SMTP_PASS"),
		AdminEmail:       os.Getenv("ADMIN_EMAIL"),
		LetsEncryptEmail: os.Getenv("LETSENCRYPT_EMAIL"),
		SMTPPort:         587,
	}

	// Load domains from environment or config file
	domains := os.Getenv("DOMAINS")
	if domains == "" {
		return cfg, fmt.Errorf("DOMAINS environment variable required")
	}
	cfg.Domains = strings.Split(domains, ",")

	// Validate required fields
	if cfg.AdminEmail == "" || cfg.LetsEncryptEmail == "" {
		return cfg, fmt.Errorf("email configuration required")
	}

	return cfg, nil
}

func main() {
	cfg, err := loadConfiguration()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// ... setup code ...

	// Wait for shutdown signal
	<-ctx.Done()
	log.Println("Shutdown signal received...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	} else {
		log.Println("Server shutdown complete")
	}

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
	if r.TLS == nil {
		fmt.Fprintf(w, "Hello World! (HTTP)")
		return
	}

	if len(r.TLS.PeerCertificates) > 0 {
		fmt.Fprintf(w, "Hello Secure World! Certificate issuer: %s",
			r.TLS.PeerCertificates[0].Issuer)
	} else {
		fmt.Fprintf(w, "Hello Secure World! TLS connection established")
	}
}

func monitorCertificates(ctx context.Context, mgr *autocert.Manager, cfg Config) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	consecutiveFailures := make(map[string]int)

	for {
		select {
		case <-ctx.Done():
			log.Println("Certificate monitoring stopped")
			return
		case <-ticker.C:
			for _, domain := range cfg.Domains {
				cert, err := getCertificateFromManager(mgr, domain)
				if err != nil {
					consecutiveFailures[domain]++
					log.Printf("Failed to get certificate for %s: %v", domain, err)

					if consecutiveFailures[domain] >= maxConnectionFailures {
						sendAlert(fmt.Sprintf("CRITICAL: Cannot access certificate for %s", domain),
							fmt.Sprintf("Failed %d consecutive times: %v", consecutiveFailures[domain], err), cfg)
					}
					continue
				}

				consecutiveFailures[domain] = 0 // Reset on success
				checkCertificateExpiration(cert, domain, cfg)
			}
		}
	}
}

// retrieves the certificate for a given domain from the autocert manager
func getCertificateFromManager(mgr *autocert.Manager, domain string) (*x509.Certificate, error) {
	hello := &tls.ClientHelloInfo{ServerName: domain}
	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate data")
	}

	return x509.ParseCertificate(cert.Certificate[0])
}

// checks the expiration of a certificate and sends alerts if necessary
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

// sends an email alert to the admin about certificate issues
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

// health check endpoint to verify server status
func setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRequest)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})
	return mux
}
