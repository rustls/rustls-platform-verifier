// Generates the test data files used in the tests in verification_mock.rs.
//
// After re-generating mock certificates be sure to also update the fixed
// verification timestamp in `mod.rs`'s `verification_time` fn to match
// the current time.
//
// The primary point of this program is to fully automate the creation of the
// test data, with minimal tool dependencies (e.g. no OpenSSL), with low effort.
//
// This program isn't run as part of the build. Instead, it generates data files
// that are valid for a long time, so they don't need to be regenerated to avoid
// expiration.
//
// Files generated by this program are named "A-B-ee_C[-D].{crt, ocsp}" where
// A is the (subject) name the root certificate, B is the (subject) name of the
// intermediate certificate, C is the (subjectAltName DNS name) name of the
// end-entity certificate, and D is some distinguishing feature (e.g. "revoked").
//
// When this program was first written, it was thought that such conventions,
// and the structure of the program, would make it easy to create certificates
// that are similar but slightly different, e.g. same hostname, same issuer
// name, but different roots. It's still to be determined if this structure
// actually facilitates that.
//
// The other goal of this program is to serve as a model for the `webpki`
// crate's planned self-contained all-Rust test suite. In particular, this
// program was originally developed to accelerate the Rust test data generator
// for the `webpki` crate.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	OneDay  = time.Hour * 24
	OneYear = OneDay * 365
)

func main() {
	err := doIt()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func doIt() error {
	now := time.Now().Truncate(time.Minute).UTC()

	// "ee_1" -> "::1" is IPv6 localhost, omitting ":" characters b/c invalid for file paths on Windows
	end_entities := [3]string{"ee_example.com", "ee_127.0.0.1", "ee_1"}

	var err error = nil

	root1_key, err := generateRoot("root1", now)
	if err != nil {
		return err
	}

	root1_int1_key, err := generateInt("root1-int1", 2, now, root1_key)
	if err != nil {
		return err
	}

	for _, ee := range end_entities {
		err = generateEndEntity("root1-int1-"+ee+"-good", 1, now, root1_int1_key)
		if err != nil {
			return err
		}

		err = generateEndEntity("root1-int1-"+ee+"-revoked", 2, now, root1_int1_key)
		if err != nil {
			return err
		}

		err = generateEndEntity("root1-int1-"+ee+"-wrong_eku", 3, now, root1_int1_key)
		if err != nil {
			return err
		}
	}

	return nil
}

// Generates a binary DER X.509 file with name `eeName` + ".crt". The certificate will have
// the given serial number (which should be unique per issuer), OCSP status (ocsp.Good,
// ocsp.Revoked, etc.), signed by the given key.
func generateEndEntity(eeName string, serial int64, now time.Time, caKey crypto.Signer) error {
	nameParts := strings.Split(eeName, "-")
	caName := nameParts[0] + "-" + nameParts[1]
	eeBaseName := nameParts[2]
	label := nameParts[3]

	caCert, err := readCert(caName)
	if err != nil {
		return err
	}
	eePubKey, err := generatePubKey()
	if err != nil {
		return err
	}

	// macOS requirements reference: https://support.apple.com/en-us/HT210176
	template := x509.Certificate{
		NotBefore: now.Add(-OneDay),
		// macOS >=10.15 requires that certificates must have a
		// validity period of 825 days or fewer.
		NotAfter: now.Add(2 * OneYear),
		// macOS >=10.15 requires that server certificates must have the
		// id-kp-serverAuth OID present in the EKU.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	switch eeBaseName {
	case "ee_example.com":
		template.SerialNumber = big.NewInt(serial)
		template.DNSNames = []string{"example.com"}
	case "ee_127.0.0.1": // IPv4 localhost
		template.SerialNumber = big.NewInt(serial)
		template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	case "ee_1": // IPv6 localhost, e.g. "::1"
		template.SerialNumber = big.NewInt(serial)
		template.IPAddresses = []net.IP{net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	default:
		return errors.New("Unrecognized end entity certificate:" + eeName)
	}

	ocspStatus := ocsp.Unknown // Don't generate an OCSP response.

	switch label {
	case "good":
		ocspStatus = ocsp.Good
	case "revoked":
		ocspStatus = ocsp.Revoked
	case "wrong_eku":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, caCert, eePubKey, caKey)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(eeName+".crt", cert, 0666)
	if err != nil {
		return err
	}

	if ocspStatus != ocsp.Unknown {
		err = generateOCSPResponse(eeName, ocspStatus, now, caKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// Generates a binary DER X.509 file with name `intName` + ".crt".
func generateInt(intName string, serial int64, now time.Time, caKey crypto.Signer) (crypto.Signer, error) {
	nameParts := strings.Split(intName, "-")
	caName := nameParts[0]

	caCert, err := readCert(caName)
	if err != nil {
		return nil, err
	}
	intKey, err := generateKey()
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{intName},
		},
		NotBefore:             now.Add(-OneDay),
		NotAfter:              now.Add(OneYear),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(serial),
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, caCert, intKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(intName+".crt", cert, 0666)
	if err != nil {
		return nil, err
	}

	return intKey, nil
}

func generateRoot(name string, now time.Time) (crypto.Signer, error) {
	caKey, err := generateKey()
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{name},
		},
		NotBefore:             now.Add(-OneDay),
		NotAfter:              now.Add(OneYear),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	return caKey, ioutil.WriteFile(name+".crt", cert, 0666)
}

func generateOCSPResponse(name string, status int, now time.Time, caKey crypto.Signer) error {
	nameParts := strings.Split(name, "-")
	caName := nameParts[0] + "-" + nameParts[1]

	caCert, err := readCert(caName)
	if err != nil {
		return err
	}
	eeCert, err := readCert(name)
	if err != nil {
		return err
	}

	// It seems we must have `thisUpdate >= eeCert.NotBefore` or else
	// Windows won't trust the OCSP response. In particular, if the
	// response is `revoked` but this date is too early, then it will
	// not consider the response revoked!
	thisUpdate := eeCert.NotBefore.Add(1)

	template := ocsp.Response{
		Status:       status,
		SerialNumber: eeCert.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   thisUpdate.Add(1 * OneYear),
	}

	if status == ocsp.Revoked {
		template.RevokedAt = thisUpdate
	}

	response, err := ocsp.CreateResponse(caCert, caCert, template, caKey)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(name+".ocsp", response, 0666)
}

func generateKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func generatePubKey() (*ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

func readCert(name string) (*x509.Certificate, error) {
	der, err := ioutil.ReadFile(name + ".crt")
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func readKey(name string) (*ecdsa.PrivateKey, error) {
	pkcs8, err := ioutil.ReadFile(name + ".p8")
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return nil, errors.New("Unexpected private key type")
	}
}
