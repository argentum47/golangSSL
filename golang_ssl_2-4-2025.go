// golang script to discover, renew and monitor certificates using CertifyTheWeb API

package main

import (
	"log"
	"os"
	"time"

	"github.com/certifytheweb/certifytheweb"
)

func main() {
	// Configure CertifyTheWeb
	certManager := certifytheweb.NewCertManager()
	if err := certManager.Configure("my-config.json"); err != nil {
		log.Fatalf("Failed to configure CertifyTheWeb: %v\n", err)
	}

	// Function to check and renew certificates as needed
	checkAndRenewCertificates := func() {
		certs, err := certManager.GetCertificates()
		if err != nil {
			log.Printf("Error getting certificates: %v\n", err)
			return
		}

		for _, cert := range certs {
			// Check if the certificate is expiring within 72 hours
			if cert.ExpiryDate.Sub(time.Now()).Hours() < 72 {
				log.Printf("Renewing certificate for %s...\n", cert.Domain)
				if err := certManager.RenewCertificate(cert); err != nil {
					log.Printf("Error renewing certificate for %s: %v\n", cert.Domain, err)
					// Implement your alerting mechanism here (send SMTP email message to admin mailbox)
					alertRenewalFailure(cert.Domain, err)
				} else {
					log.Printf("Certificate for %s renewed successfully\n", cert.Domain)
				}
			}
		}
	}

	// Run the check once every eight hours
	ticker := time.NewTicker(8 * time.Hour)
	go func() {
		for range ticker.C {
			checkAndRenewCertificates()
		}
	}()

	log.Println("Certificate Monitoring and Renewal Tool started")
	select {}
}

// Function to alert on certificate renewal failure
func alertRenewalFailure(domain string, err error) {
	// Example: Log to a file
	f, fileErr := os.OpenFile("renewal_failures.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if fileErr != nil {
		log.Printf("Error opening log file: %v\n", fileErr)
		return
	}
	defer f.Close()

	logger := log.New(f, "", log.LstdFlags)
	logger.Printf("Failed to renew certificate for %s: %v\n", domain, err)

	// Add additional alerting mechanisms as needed (example: send an email or Slack notification)
}
