package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/shiftleftcyber/secure-sbom-verifier/application"
	digestsigning "github.com/shiftleftcyber/secure-sbom-verifier/services/digest"
	sbomService "github.com/shiftleftcyber/secure-sbom-verifier/services/sbom"
	"github.com/shiftleftcyber/secure-sbom-verifier/verificationkey"

	sbomValidator "github.com/shiftleftcyber/sbom-validator/v2"
)

type fileLoader func(string) ([]byte, error)

type command struct {
	stdout   io.Writer
	stderr   io.Writer
	loadFile fileLoader
	newApp   func() *application.VerifierApp
}

func newCommand(stdout, stderr io.Writer) *command {
	return &command{
		stdout:   stdout,
		stderr:   stderr,
		loadFile: os.ReadFile,
		newApp:   application.NewVerifierApp,
	}
}

type options struct {
	sbomPath            string
	digestValue         string
	pubKeyPath          string
	signature           string
	hashAlgorithm       string
	signatureAlgorithm  string
	verificationVersion application.VerificationVersion
}

func (c *command) run(args []string) int {
	if err := c.execute(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	return 0
}

func (c *command) execute(args []string) error {
	opts, err := c.parseArgs(args)
	if err != nil {
		return err
	}

	public, err := c.loadTextFile(opts.pubKeyPath, "Failed to read public key")
	if err != nil {
		return err
	}

	if opts.digestValue != "" {
		return c.verifyDigest(opts, public)
	}

	sbom, err := c.loadFileWithLabel(opts.sbomPath, "Failed to read SBOM")
	if err != nil {
		return err
	}

	app := c.newApp()
	result, sbomType, err := c.verifySBOM(app, sbom, public, opts)
	if err != nil {
		return err
	}

	printResult(c.stdout, true, "SBOM", "SBOM Type", strings.ToLower(sbomType), result.Algorithm, result.Message, nil)
	return nil
}

func (c *command) parseArgs(args []string) (options, error) {
	fs := flag.NewFlagSet("sbom-offline-verification", flag.ContinueOnError)
	fs.SetOutput(c.stderr)

	sbomPath := fs.String("sbom", "", "Path to the signed SBOM file")
	digestValue := fs.String("digest", "", "Base64-encoded digest to verify")
	pubKeyPath := fs.String("pubkey", "", "Path to the public key PEM file (required)")
	signature := fs.String("signature", "", "Detached signature for SPDX or for digest verification")
	hashAlgorithm := fs.String("hash-algorithm", "sha256", "Hash algorithm for digest verification (default: sha256)")
	signatureAlgorithm := fs.String("signature-algorithm", "ES256", "Signature algorithm for digest verification (default: ES256)")
	verificationVersionParam := fs.String("verification-version", "v2", "Verification version to use: v1 or v2 (default: v2)")

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}

	if strings.TrimSpace(*pubKeyPath) == "" {
		fmt.Fprintln(c.stderr, "Error: -pubkey is required")
		fs.Usage()
		return options{}, errors.New("missing required -pubkey")
	}

	if strings.TrimSpace(*digestValue) == "" && strings.TrimSpace(*sbomPath) == "" {
		fmt.Fprintln(c.stderr, "Error: either -sbom or -digest is required")
		fs.Usage()
		return options{}, errors.New("either -sbom or -digest is required")
	}

	verificationVersion, err := parseVerificationVersion(*verificationVersionParam)
	if err != nil {
		fmt.Fprintf(c.stderr, "Invalid -verification-version (expected v1 or v2): %v\n", err)
		return options{}, err
	}

	return options{
		sbomPath:            strings.TrimSpace(*sbomPath),
		digestValue:         strings.TrimSpace(*digestValue),
		pubKeyPath:          strings.TrimSpace(*pubKeyPath),
		signature:           strings.TrimSpace(*signature),
		hashAlgorithm:       strings.TrimSpace(*hashAlgorithm),
		signatureAlgorithm:  strings.TrimSpace(*signatureAlgorithm),
		verificationVersion: verificationVersion,
	}, nil
}

func parseVerificationVersion(value string) (application.VerificationVersion, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "v2":
		return application.VerificationV2, nil
	case "v1":
		return application.VerificationV1, nil
	default:
		return 0, fmt.Errorf("got: %q", value)
	}
}

func (c *command) loadTextFile(path string, label string) (string, error) {
	content, err := c.loadFileWithLabel(path, label)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (c *command) loadFileWithLabel(path string, label string) ([]byte, error) {
	content, err := c.loadFile(path)
	if err != nil {
		fmt.Fprintf(c.stderr, "%s: %v\n", label, err)
		return nil, err
	}
	return content, nil
}

func (c *command) verifySBOM(app *application.VerifierApp, sbom []byte, public string, opts options) (*application.VerificationResult, string, error) {
	result, err := sbomValidator.ValidateSBOMData(sbom)
	if err != nil {
		fmt.Fprintf(c.stderr, "SBOM validation failed: %v\n", err)
		return nil, "", err
	}
	if !result.IsValid {
		err := fmt.Errorf("%v", result.ValidationErrors)
		fmt.Fprintf(c.stderr, "Invalid SBOM: %v\n", err)
		return nil, "", err
	}

	switch strings.ToLower(result.SBOMType) {
	case "cyclonedx":
		return c.verifyCycloneDX(app, sbom, public, opts.verificationVersion)
	case "spdx":
		return c.verifySPDX(app, sbom, opts.signature, public, opts.verificationVersion)
	default:
		err := fmt.Errorf("sbom type: %s", result.SBOMType)
		fmt.Fprintf(c.stderr, "Unsupported SBOM type: %v\n", err)
		return nil, "", err
	}
}

func (c *command) verifyCycloneDX(
	app *application.VerifierApp,
	sbom []byte,
	public string,
	version application.VerificationVersion,
) (*application.VerificationResult, string, error) {
	result, err := app.VerifyCycloneDXEmbeddedVersioned(sbom, public, version)
	if err != nil {
		printResult(c.stdout, false, "SBOM", "SBOM Type", "CycloneDX", "", "", err)
		return nil, "", err
	}
	return result, "CycloneDX", nil
}

func (c *command) verifySPDX(
	app *application.VerifierApp,
	sbom []byte,
	signature string,
	public string,
	version application.VerificationVersion,
) (*application.VerificationResult, string, error) {
	if signature == "" {
		err := fmt.Errorf("SPDX verification requires --signature")
		fmt.Fprintf(c.stderr, "Error: %v\n", err)
		return nil, "", err
	}

	canonical, err := sbomService.CanonicalizeUnsignedSBOM(sbom)
	if err != nil {
		fmt.Fprintf(c.stderr, "Failed to canonicalize SPDX SBOM: %v\n", err)
		return nil, "", err
	}

	result, err := app.VerifySPDXDetachedVersioned(canonical, signature, public, version)
	if err != nil {
		printResult(c.stdout, false, "SBOM", "SBOM Type", "SPDX", "", "", err)
		return nil, "", err
	}
	return result, "SPDX", nil
}

func (c *command) verifyDigest(opts options, publicKeyPEM string) error {
	if opts.signature == "" {
		err := fmt.Errorf("digest verification requires -signature")
		fmt.Fprintf(c.stderr, "Error: %v\n", err)
		return err
	}

	validator := digestsigning.NewValidator()
	validated, err := validator.ValidateVerifyDigestRequest(digestsigning.VerifyDigestInput{
		KeyID:         "offline",
		HashAlgorithm: opts.hashAlgorithm,
		Digest:        opts.digestValue,
		Signature:     opts.signature,
	})
	if err != nil {
		printResult(c.stdout, false, "Digest", "Hash Algorithm", strings.ToLower(strings.TrimSpace(opts.hashAlgorithm)), opts.signatureAlgorithm, "", err)
		return err
	}

	verifier := digestsigning.NewCryptoVerifier()
	err = verifier.Verify(&verificationkey.KeyInfo{
		KeyID:     "offline",
		Algorithm: opts.signatureAlgorithm,
		PublicKey: publicKeyPEM,
	}, validated.Digest, validated.Signature)
	if err != nil {
		printResult(c.stdout, false, "Digest", "Hash Algorithm", validated.HashAlgorithm, opts.signatureAlgorithm, "", err)
		return err
	}

	printResult(c.stdout, true, "Digest", "Hash Algorithm", validated.HashAlgorithm, opts.signatureAlgorithm, "signature is valid", nil)
	return nil
}

func printResult(writer io.Writer, isSuccess bool, mode, subjectLabel, subjectValue, algorithm, message string, reason error) {
	divider := "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

	if isSuccess {
		fmt.Fprintln(writer, divider)
		fmt.Fprintln(writer, " ✅  VERIFICATION SUCCESSFUL")
		fmt.Fprintln(writer, divider)
		fmt.Fprintf(writer, " Verification Mode:    %s\n", mode)
		fmt.Fprintf(writer, " %-20s %s\n", subjectLabel+":", subjectValue)
		fmt.Fprintf(writer, " Algorithm:            %s\n", algorithm)
		fmt.Fprintf(writer, " Message:              %s\n", message)
		fmt.Fprintf(writer, " Public Key:           OK\n")
		fmt.Fprintln(writer, divider)
		return
	}

	fmt.Fprintln(writer, divider)
	fmt.Fprintln(writer, " ❌  VERIFICATION FAILED")
	fmt.Fprintln(writer, divider)
	fmt.Fprintf(writer, " Verification Mode:    %s\n", mode)
	fmt.Fprintf(writer, " Reason:               %v\n", reason)
	fmt.Fprintf(writer, " %-20s %s\n", subjectLabel+":", subjectValue)
	if algorithm != "" {
		fmt.Fprintf(writer, " Algorithm:            %s\n", algorithm)
	}
	fmt.Fprintln(writer, divider)
}
