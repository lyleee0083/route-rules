package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

const (
	cacheModeFile       = "connection-cache.mode"
	cacheReceiptFile    = "connection-cache-receipt.json"
	cacheProofFile      = "connection-cache-proof.json"
	cacheModeOff        = "off-v1"
	cacheModeCTMark     = "ctmark-v1"
	cacheModeLegacyOff  = "legacy-off"
	cacheStateFileLimit = 32 * 1024
	cacheManifestLimit  = 1024 * 1024
)

var cacheBootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var cacheDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type cachePackageIdentity struct {
	Owner          string
	Mode           string
	PackageVersion string
	PayloadSHA256  string
}

type connectionCacheReceipt struct {
	SchemaVersion  int    `json:"schema_version"`
	Mode           string `json:"mode"`
	PackageVersion string `json:"package_version"`
	Owner          string `json:"owner"`
	PayloadSHA256  string `json:"payload_sha256"`
	StagedBootID   string `json:"staged_boot_id"`
	Nonce          string `json:"nonce"`
	ConsumedBootID string `json:"consumed_boot_id,omitempty"`
}

type connectionCacheProof struct {
	SchemaVersion      int    `json:"schema_version"`
	Status             string `json:"status"`
	Mode               string `json:"mode"`
	PackageVersion     string `json:"package_version"`
	Owner              string `json:"owner"`
	PayloadSHA256      string `json:"payload_sha256"`
	ReceiptNonce       string `json:"receipt_nonce"`
	StagedBootID       string `json:"staged_boot_id"`
	ActivatedBootID    string `json:"activated_boot_id"`
	JournalFingerprint string `json:"journal_fingerprint"`
}

type cacheGateDecision struct {
	Mode  string
	State string
	Boot  string
	ID    cachePackageIdentity
	Nonce string
}

type cacheStopAuthorization struct {
	identity    cachePackageIdentity
	receipt     connectionCacheReceipt
	proof       connectionCacheProof
	boot        string
	fingerprint string
}

type rebootRequiredError struct{ message string }

func (err rebootRequiredError) Error() string { return "REBOOT_REQUIRED: " + err.message }

type recoveryOnlyError struct{ cause error }

func (err recoveryOnlyError) Error() string {
	return "RECOVERY_ONLY: " + err.cause.Error()
}

func (err recoveryOnlyError) Unwrap() error { return err.cause }

func cacheGuardError(format string, args ...any) error {
	return fmt.Errorf("CACHE_GUARD_FAILED: "+format, args...)
}

func readRegularStable(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid bounded file-read limit")
	}
	file, opened, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	checkErr := verifyOpenedRegularFile(path, file, opened)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if checkErr != nil {
		return nil, checkErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds bounded read limit: %s", filepath.Base(path))
	}
	return data, nil
}

func (c *controller) cacheModeMarker() (string, bool, error) {
	path := filepath.Join(c.root, cacheModeFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return cacheModeLegacyOff, false, nil
	} else if err != nil {
		return "", false, err
	}
	data, err := readRegularStable(path, 128)
	if err != nil {
		return "", true, fmt.Errorf("read cache mode marker: %w", err)
	}
	switch string(data) {
	case cacheModeOff + "\n":
		return cacheModeOff, true, nil
	case cacheModeCTMark + "\n":
		return cacheModeCTMark, true, nil
	default:
		return "", true, errors.New("cache mode marker is malformed or unsupported")
	}
}

func parsePayloadManifest(data []byte) (map[string]string, error) {
	if len(data) == 0 || len(data) > cacheManifestLimit || bytes.Contains(data, []byte{'\r'}) || !bytes.HasSuffix(data, []byte{'\n'}) || bytes.HasSuffix(data, []byte{'\n', '\n'}) {
		return nil, errors.New("invalid payload manifest bytes")
	}
	entries := make(map[string]string)
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	for _, line := range lines {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || !cacheDigestPattern.MatchString(parts[0]) || !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(parts[1]) || parts[1] == "SHA256SUMS" {
			return nil, errors.New("invalid payload manifest entry")
		}
		if _, exists := entries[parts[1]]; exists {
			return nil, errors.New("duplicate payload manifest name")
		}
		entries[parts[1]] = parts[0]
	}
	if len(entries) == 0 {
		return nil, errors.New("empty payload manifest")
	}
	return entries, nil
}

func (c *controller) readPackageManifest() ([]byte, map[string]string, error) {
	if err := directory(c.root); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(c.root, "SHA256SUMS")
	data, err := readRegularStable(path, cacheManifestLimit)
	if err != nil {
		return nil, nil, err
	}
	entries, err := parsePayloadManifest(data)
	if err != nil {
		return nil, nil, err
	}
	return data, entries, nil
}

func (c *controller) readStateDirectory() error {
	info, err := os.Lstat(c.state)
	if err != nil {
		return err
	}
	if err = directory(c.state); err != nil {
		return err
	}
	return validateCacheStateDirectory(c.state, info)
}

func readCacheStateFile(path string, limit int64) ([]byte, string, error) {
	if limit <= 0 {
		return nil, "", errors.New("invalid bounded state-file limit")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	if err = validateCacheStateFile(before); err != nil {
		return nil, "", err
	}
	file, opened, err := openRegularFile(path)
	if err != nil {
		return nil, "", err
	}
	if err = validateCacheStateFile(opened); err != nil {
		_ = file.Close()
		return nil, "", err
	}
	identity, identityErr := cacheFileIdentity(file, opened)
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	checkErr := verifyOpenedRegularFile(path, file, opened)
	closeErr := file.Close()
	if identityErr != nil {
		return nil, "", identityErr
	}
	if readErr != nil {
		return nil, "", readErr
	}
	if checkErr != nil {
		return nil, "", checkErr
	}
	if closeErr != nil {
		return nil, "", closeErr
	}
	if int64(len(data)) > limit {
		return nil, "", fmt.Errorf("state file exceeds bounded read limit: %s", filepath.Base(path))
	}
	return data, identity, nil
}

func writeCacheStateFile(state, name string, data []byte) error {
	if err := directory(state); err != nil {
		return err
	}
	info, err := os.Lstat(state)
	if err != nil {
		return err
	}
	if err = validateCacheStateDirectory(state, info); err != nil {
		return err
	}
	path := filepath.Join(state, name)
	if info, err = os.Lstat(path); err == nil {
		if err = validateCacheStateFile(info); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return atomicWrite(path, data)
}

func cacheWriteFragment(path string) error {
	fragment := path + ".write"
	if _, err := os.Lstat(fragment); err == nil {
		return fmt.Errorf("retained cache-state write fragment requires review: %s", filepath.Base(fragment))
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func marshalCacheJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, isString := keyToken.(string)
			if !isString || seen[key] {
				return errors.New("duplicate or invalid JSON object key")
			}
			seen[key] = true
			if err = scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object ending")
		}
	case '[':
		for decoder.More() {
			if err = scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array ending")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func decodeUniqueStrictJSON(data []byte, target any) error {
	unique := json.NewDecoder(bytes.NewReader(data))
	unique.UseNumber()
	if err := scanUniqueJSONValue(unique); err != nil {
		return err
	}
	if err := requireJSONEOF(unique); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("trailing JSON data")
}

func (c *controller) cacheOwner() (string, error) {
	if err := c.readStateDirectory(); err != nil {
		return "", err
	}
	data, _, err := readCacheStateFile(filepath.Join(c.state, "owner"), 256)
	if err != nil {
		return "", err
	}
	if string(data) != "sing-box-native-v1\n" {
		return "", errors.New("unknown integration owner")
	}
	return "sing-box-native-v1", nil
}

func (c *controller) verifiedCachePackageIdentity() (cachePackageIdentity, error) {
	var identity cachePackageIdentity
	modeBefore, markerBefore, err := c.cacheModeMarker()
	if err != nil {
		return identity, err
	}
	manifestBefore, entriesBefore, err := c.readPackageManifest()
	if err != nil {
		return identity, err
	}
	var modeBytesBefore []byte
	if markerBefore {
		modeBytesBefore, err = readRegularStable(filepath.Join(c.root, cacheModeFile), 128)
		if err != nil {
			return identity, err
		}
		if _, listed := entriesBefore[cacheModeFile]; !listed {
			return identity, errors.New("cache mode marker is not covered by SHA256SUMS")
		}
		digest := sha256.Sum256(modeBytesBefore)
		if entriesBefore[cacheModeFile] != hex.EncodeToString(digest[:]) {
			return identity, errors.New("cache mode marker digest does not match SHA256SUMS")
		}
	}
	if err = c.verified(); err != nil {
		return identity, err
	}
	modeAfter, markerAfter, err := c.cacheModeMarker()
	if err != nil {
		return identity, err
	}
	manifestAfter, entriesAfter, err := c.readPackageManifest()
	if err != nil {
		return identity, err
	}
	if modeBefore != modeAfter || markerBefore != markerAfter || !bytes.Equal(manifestBefore, manifestAfter) {
		return identity, errors.New("package identity changed during validation")
	}
	if markerBefore {
		modeBytesAfter, readErr := readRegularStable(filepath.Join(c.root, cacheModeFile), 128)
		if readErr != nil || !bytes.Equal(modeBytesBefore, modeBytesAfter) || entriesAfter[cacheModeFile] != entriesBefore[cacheModeFile] {
			return identity, errors.New("cache mode source changed during package validation")
		}
	}
	owner, err := c.cacheOwner()
	if err != nil {
		return identity, err
	}
	manifestDigest := sha256.Sum256(manifestAfter)
	identity = cachePackageIdentity{
		Owner:          owner,
		Mode:           modeAfter,
		PackageVersion: modeAfter,
		PayloadSHA256:  hex.EncodeToString(manifestDigest[:]),
	}
	if !markerAfter {
		identity.Mode = cacheModeLegacyOff
		identity.PackageVersion = cacheModeLegacyOff
	}
	return identity, nil
}

func validCacheNonce(value string) bool { return cacheDigestPattern.MatchString(value) }

func validCacheBootID(value string) bool { return cacheBootIDPattern.MatchString(value) }

func validateCacheReceipt(receipt connectionCacheReceipt) error {
	if receipt.SchemaVersion != 1 || receipt.Owner != "sing-box-native-v1" ||
		(receipt.Mode != cacheModeOff && receipt.Mode != cacheModeCTMark) || receipt.PackageVersion != receipt.Mode ||
		!cacheDigestPattern.MatchString(receipt.PayloadSHA256) || !validCacheBootID(receipt.StagedBootID) || !validCacheNonce(receipt.Nonce) {
		return errors.New("cache stage receipt is malformed")
	}
	if receipt.ConsumedBootID != "" && !validCacheBootID(receipt.ConsumedBootID) {
		return errors.New("cache stage receipt consumed boot ID is malformed")
	}
	return nil
}

func validateCacheProof(proof connectionCacheProof) error {
	if proof.SchemaVersion != 1 || (proof.Status != "preparing" && proof.Status != "active") ||
		proof.Owner != "sing-box-native-v1" || (proof.Mode != cacheModeOff && proof.Mode != cacheModeCTMark) ||
		proof.PackageVersion != proof.Mode || !cacheDigestPattern.MatchString(proof.PayloadSHA256) ||
		!validCacheNonce(proof.ReceiptNonce) || !validCacheBootID(proof.StagedBootID) ||
		!validCacheBootID(proof.ActivatedBootID) || proof.JournalFingerprint == "" {
		return errors.New("cache activation proof is malformed")
	}
	return nil
}

func (c *controller) loadCacheReceipt() (connectionCacheReceipt, bool, error) {
	var receipt connectionCacheReceipt
	path := filepath.Join(c.state, cacheReceiptFile)
	data, _, err := readCacheStateFile(path, cacheStateFileLimit)
	if os.IsNotExist(err) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, err
	}
	if err = decodeUniqueStrictJSON(data, &receipt); err != nil {
		return receipt, true, fmt.Errorf("decode cache stage receipt: %w", err)
	}
	if err = validateCacheReceipt(receipt); err != nil {
		return receipt, true, err
	}
	return receipt, true, nil
}

func (c *controller) loadCacheProof() (connectionCacheProof, bool, error) {
	var proof connectionCacheProof
	path := filepath.Join(c.state, cacheProofFile)
	data, _, err := readCacheStateFile(path, cacheStateFileLimit)
	if os.IsNotExist(err) {
		return proof, false, nil
	}
	if err != nil {
		return proof, false, err
	}
	if err = decodeUniqueStrictJSON(data, &proof); err != nil {
		return proof, true, fmt.Errorf("decode cache activation proof: %w", err)
	}
	if err = validateCacheProof(proof); err != nil {
		return proof, true, err
	}
	return proof, true, nil
}

func cacheReceiptMatchesIdentity(receipt connectionCacheReceipt, identity cachePackageIdentity) bool {
	return receipt.Owner == identity.Owner && receipt.Mode == identity.Mode &&
		receipt.PackageVersion == identity.PackageVersion && receipt.PayloadSHA256 == identity.PayloadSHA256
}

func cacheProofMatchesReceipt(proof connectionCacheProof, receipt connectionCacheReceipt) bool {
	return proof.Owner == receipt.Owner && proof.Mode == receipt.Mode && proof.PackageVersion == receipt.PackageVersion &&
		proof.PayloadSHA256 == receipt.PayloadSHA256 && proof.ReceiptNonce == receipt.Nonce && proof.StagedBootID == receipt.StagedBootID
}

func (c *controller) cacheJournalSnapshot() (*journal, string, error) {
	path := filepath.Join(c.state, "journal.json")
	if err := cacheWriteFragment(path); err != nil {
		return nil, "", err
	}
	data, identity, err := readCacheStateFile(path, 2*1024*1024)
	if err != nil {
		return nil, "", err
	}
	j, err := decodeJournalData(data)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(data)
	return j, hex.EncodeToString(digest[:]) + ":" + identity, nil
}

func (c *controller) checkCacheBoot() (cacheGateDecision, error) {
	mode, markerPresent, err := c.cacheModeMarker()
	if err != nil {
		return cacheGateDecision{}, cacheGuardError("%v", err)
	}
	if !markerPresent || mode == cacheModeOff || mode == cacheModeLegacyOff {
		return cacheGateDecision{Mode: mode, State: "off"}, nil
	}
	if mode != cacheModeCTMark {
		return cacheGateDecision{}, cacheGuardError("unsupported cache mode %q", mode)
	}
	identity, err := c.verifiedCachePackageIdentity()
	if err != nil {
		return cacheGateDecision{}, cacheGuardError("installed package validation failed: %v", err)
	}
	if identity.Mode != cacheModeCTMark {
		return cacheGateDecision{}, cacheGuardError("validated package is not in ctmark-v1 mode")
	}
	if c.boot == nil {
		return cacheGateDecision{}, cacheGuardError("boot identity provider is unavailable")
	}
	boot, err := c.boot()
	if err != nil {
		return cacheGateDecision{}, cacheGuardError("current boot ID is unavailable: %v", err)
	}
	if !validCacheBootID(strings.TrimSpace(boot)) {
		return cacheGateDecision{}, cacheGuardError("current boot ID is unavailable or invalid: %v", err)
	}
	boot = strings.TrimSpace(boot)
	for _, name := range []string{cacheReceiptFile, cacheProofFile, "journal.json"} {
		if err = cacheWriteFragment(filepath.Join(c.state, name)); err != nil {
			return cacheGateDecision{}, cacheGuardError("%v", err)
		}
	}
	receipt, exists, err := c.loadCacheReceipt()
	if err != nil {
		return cacheGateDecision{}, cacheGuardError("%v", err)
	}
	if !exists {
		return cacheGateDecision{}, cacheGuardError("cache stage receipt is missing")
	}
	if !cacheReceiptMatchesIdentity(receipt, identity) {
		return cacheGateDecision{}, cacheGuardError("stage receipt owner, mode, package version, or payload digest does not match installed source")
	}
	if receipt.StagedBootID == boot {
		return cacheGateDecision{}, rebootRequiredError{message: "cache package was staged during this boot; reboot before enabling the connection cache"}
	}
	proof, proofExists, err := c.loadCacheProof()
	if err != nil {
		return cacheGateDecision{}, cacheGuardError("%v", err)
	}
	if proofExists && !cacheProofMatchesReceipt(proof, receipt) {
		return cacheGateDecision{}, cacheGuardError("activation proof does not match the installed package receipt")
	}
	if receipt.ConsumedBootID == boot {
		if !proofExists || proof.Status != "active" || proof.ActivatedBootID != boot {
			return cacheGateDecision{}, rebootRequiredError{message: "same-boot cache activation was attempted but no committed proof remains; reboot before retry"}
		}
		j, fingerprint, journalErr := c.cacheJournalSnapshot()
		if journalErr != nil {
			return cacheGateDecision{}, cacheGuardError("same-boot journal is unavailable: %v", journalErr)
		}
		if j.Boot != boot || j.Phase != "restored" || proof.JournalFingerprint != fingerprint {
			return cacheGateDecision{}, rebootRequiredError{message: "same-boot journal lifecycle or source changed; reboot before reusing cached verdicts"}
		}
		return cacheGateDecision{Mode: mode, State: "same-boot-restart", Boot: boot, ID: identity, Nonce: receipt.Nonce}, nil
	}
	if proofExists && proof.ActivatedBootID == boot {
		return cacheGateDecision{}, rebootRequiredError{message: "current-boot activation proof is not linked to a consumed receipt"}
	}
	journalPath := filepath.Join(c.state, "journal.json")
	if _, statErr := os.Lstat(journalPath); statErr == nil {
		j, _, journalErr := c.cacheJournalSnapshot()
		if journalErr != nil {
			return cacheGateDecision{}, cacheGuardError("existing lifecycle journal is invalid: %v", journalErr)
		}
		if j.Boot == boot {
			return cacheGateDecision{}, rebootRequiredError{message: "a current-boot journal has no matching cache receipt proof; reboot before enabling cached verdict reuse"}
		}
	} else if !os.IsNotExist(statErr) {
		return cacheGateDecision{}, cacheGuardError("inspect lifecycle journal: %v", statErr)
	}
	if err = cacheWriteFragment(filepath.Join(c.state, cacheReceiptFile)); err != nil {
		return cacheGateDecision{}, cacheGuardError("%v", err)
	}
	if err = cacheWriteFragment(filepath.Join(c.state, cacheProofFile)); err != nil {
		return cacheGateDecision{}, cacheGuardError("%v", err)
	}
	if err = cacheWriteFragment(journalPath); err != nil {
		return cacheGateDecision{}, cacheGuardError("%v", err)
	}
	return cacheGateDecision{Mode: mode, State: "fresh-boot", Boot: boot, ID: identity, Nonce: receipt.Nonce}, nil
}

func (c *controller) cacheBootCheck() error {
	decision, err := c.checkCacheBoot()
	if err != nil {
		if c.priorBootRecoveryAvailable() {
			return recoveryOnlyError{cause: err}
		}
		return err
	}
	fmt.Printf("SING_BOX_CACHE_BOOT_CHECK_OK mode=%s state=%s\n", decision.Mode, decision.State)
	return nil
}

func (c *controller) priorBootRecoveryAvailable() bool {
	if c.readStateDirectory() != nil {
		return false
	}
	if _, err := c.cacheOwner(); err != nil {
		return false
	}
	if c.boot == nil {
		return false
	}
	boot, err := c.boot()
	if err != nil || !validCacheBootID(strings.TrimSpace(boot)) {
		return false
	}
	j, _, err := c.cacheJournalSnapshot()
	return err == nil && j.Boot != strings.TrimSpace(boot)
}

func (c *controller) requireGuardedCacheLifecycle() error {
	mode, _, err := c.cacheModeMarker()
	if err != nil {
		return cacheGuardError("%v", err)
	}
	if mode == cacheModeCTMark && !c.cacheLifecycleAuthorized {
		return errors.New("ctmark-v1 requires the guarded supervise lifecycle; direct prepare/apply is refused")
	}
	if mode == cacheModeCTMark && (c.cacheAuthorization == nil || c.cacheAuthorization.Mode != cacheModeCTMark) {
		return cacheGuardError("ctmark-v1 startup authorization is unavailable")
	}
	return nil
}

func (c *controller) refreshCacheAuthorization() error {
	decision, err := c.checkCacheBoot()
	if err != nil {
		return err
	}
	c.cacheAuthorization = &decision
	return nil
}

func (c *controller) validateCacheAuthorizationBeforeApply() error {
	decision := c.cacheAuthorization
	if decision == nil || decision.Mode != cacheModeCTMark {
		return nil
	}
	identity, err := c.verifiedCachePackageIdentity()
	if err != nil {
		return cacheGuardError("installed package validation failed before apply: %v", err)
	}
	if identity != decision.ID {
		return cacheGuardError("installed package identity changed after startup authorization")
	}
	if c.boot == nil {
		return cacheGuardError("boot identity provider is unavailable")
	}
	boot, err := c.boot()
	if err != nil || strings.TrimSpace(boot) != decision.Boot {
		return cacheGuardError("boot identity changed after startup authorization")
	}
	receipt, exists, err := c.loadCacheReceipt()
	if err != nil || !exists || !cacheReceiptMatchesIdentity(receipt, identity) || receipt.Nonce != decision.Nonce {
		return cacheGuardError("stage receipt changed after startup authorization: %v", err)
	}
	if receipt.StagedBootID == decision.Boot {
		return rebootRequiredError{message: "cache package was staged during this boot; reboot before enabling the connection cache"}
	}
	if decision.State == "same-boot-restart" {
		proof, proofExists, proofErr := c.loadCacheProof()
		if proofErr != nil || !proofExists || proof.Status != "active" || proof.ActivatedBootID != decision.Boot || !cacheProofMatchesReceipt(proof, receipt) {
			return rebootRequiredError{message: "same-boot active cache proof changed before apply; reboot before reusing cached verdicts"}
		}
		if receipt.ConsumedBootID != decision.Boot {
			return cacheGuardError("same-boot cache receipt consumption changed before apply")
		}
	} else if decision.State == "fresh-boot" {
		if receipt.ConsumedBootID == decision.Boot {
			return rebootRequiredError{message: "cache receipt was already consumed during this boot; reboot before retry"}
		}
	} else {
		return cacheGuardError("unknown cache startup authorization state %q", decision.State)
	}
	return nil
}

func (c *controller) invalidateCacheProofForOffMode() error {
	mode, _, err := c.cacheModeMarker()
	if err != nil {
		return err
	}
	if mode == cacheModeCTMark {
		return nil
	}
	if err = c.readStateDirectory(); err != nil {
		return err
	}
	path := filepath.Join(c.state, cacheProofFile)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		// Never follow or remove a suspicious object in off mode. A future cache
		// activation will reject it before any integration mutation.
		return nil
	}
	if err = validateCacheStateFile(info); err != nil {
		return nil
	}
	return os.Remove(path)
}

func (c *controller) removeCacheProofForStage() error {
	path := filepath.Join(c.state, cacheProofFile)
	if err := cacheWriteFragment(path); err != nil {
		return err
	}
	_, exists, err := c.loadCacheProof()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return os.Remove(path)
}

func (c *controller) stageCacheReceipt(payloadSHA256, owner, packageVersion string) error {
	identity, err := c.verifiedCachePackageIdentity()
	if err != nil {
		return fmt.Errorf("stage package validation failed: %w", err)
	}
	if identity.Mode != cacheModeCTMark && identity.Mode != cacheModeOff {
		return errors.New("legacy package cannot stage a cache receipt")
	}
	if !cacheDigestPattern.MatchString(payloadSHA256) || payloadSHA256 != identity.PayloadSHA256 {
		return errors.New("supplied payload digest does not match the validated installed SHA256SUMS")
	}
	if owner != identity.Owner || owner != "sing-box-native-v1" {
		return errors.New("supplied project owner does not match the owned state marker")
	}
	if packageVersion != identity.PackageVersion || packageVersion != identity.Mode {
		return errors.New("supplied package version does not match the validated mode marker")
	}
	if c.boot == nil {
		return errors.New("boot identity provider is unavailable")
	}
	boot, err := c.boot()
	if err != nil {
		return fmt.Errorf("current boot ID is unavailable: %w", err)
	}
	if !validCacheBootID(strings.TrimSpace(boot)) {
		return errors.New("current boot ID is invalid")
	}
	boot = strings.TrimSpace(boot)
	if err = c.readStateDirectory(); err != nil {
		return err
	}
	path := filepath.Join(c.state, cacheReceiptFile)
	if err = cacheWriteFragment(path); err != nil {
		return err
	}
	if err = cacheWriteFragment(filepath.Join(c.state, cacheProofFile)); err != nil {
		return err
	}
	previous, previousExists, err := c.loadCacheReceipt()
	if err != nil {
		return fmt.Errorf("existing cache receipt requires review: %w", err)
	}
	proof, proofExists, err := c.loadCacheProof()
	if err != nil {
		return fmt.Errorf("existing cache proof requires review: %w", err)
	}
	nonce, err := newCacheNonce(previous.Nonce, proof.ReceiptNonce)
	if err != nil {
		return err
	}
	if proofExists {
		if err = c.removeCacheProofForStage(); err != nil {
			return fmt.Errorf("invalidate prior cache proof: %w", err)
		}
	}
	receipt := connectionCacheReceipt{
		SchemaVersion:  1,
		Mode:           identity.Mode,
		PackageVersion: identity.PackageVersion,
		Owner:          identity.Owner,
		PayloadSHA256:  identity.PayloadSHA256,
		StagedBootID:   boot,
		Nonce:          nonce,
	}
	if previousExists && previous.Nonce == receipt.Nonce {
		return errors.New("stage nonce was reused")
	}
	data, err := marshalCacheJSON(receipt)
	if err != nil {
		return err
	}
	if err = writeCacheStateFile(c.state, cacheReceiptFile, data); err != nil {
		return fmt.Errorf("write owned cache stage receipt: %w", err)
	}
	fmt.Printf("SING_BOX_CACHE_RECEIPT_STAGED mode=%s payload_sha256=%s staged_boot_id=%s\n", receipt.Mode, receipt.PayloadSHA256, receipt.StagedBootID)
	return nil
}

func newCacheNonce(previous ...string) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("generate stage nonce: %w", err)
		}
		nonce := hex.EncodeToString(raw)
		unique := true
		for _, value := range previous {
			if value != "" && nonce == value {
				unique = false
			}
		}
		if unique {
			return nonce, nil
		}
	}
	return "", errors.New("could not generate a non-reused stage nonce")
}

func stageCacheReceiptCLI(c *controller, args []string) error {
	flags := flag.NewFlagSet("stage-cache-receipt", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	payload := flags.String("payload-sha256", "", "SHA-256 of exact installed SHA256SUMS bytes")
	owner := flags.String("owner", "", "project owner marker")
	version := flags.String("package-version", "", "exact connection-cache.mode marker")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *payload == "" || *owner == "" || *version == "" {
		return errors.New("stage-cache-receipt requires --payload-sha256, --owner, and --package-version")
	}
	if err := c.cacheOwnerBeforeStage(); err != nil {
		return err
	}
	unlock, err := lockFile(filepath.Join(c.state, "controller.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return c.stageCacheReceipt(*payload, *owner, *version)
}

func (c *controller) cacheOwnerBeforeStage() error {
	owner, err := c.cacheOwner()
	if err != nil {
		return err
	}
	if owner != "sing-box-native-v1" {
		return errors.New("unknown integration owner")
	}
	return nil
}

func (c *controller) prepareCacheProof() error {
	mode, _, modeErr := c.cacheModeMarker()
	if modeErr != nil {
		return cacheGuardError("%v", modeErr)
	}
	if mode != cacheModeCTMark {
		return nil
	}
	decision := c.cacheAuthorization
	if decision == nil || decision.Mode != cacheModeCTMark || (decision.State != "fresh-boot" && decision.State != "same-boot-restart") {
		return cacheGuardError("guarded activation authorization is unavailable")
	}
	current, err := c.verifiedCachePackageIdentity()
	if err != nil {
		return cacheGuardError("installed package changed before cached policy: %v", err)
	}
	if current != decision.ID {
		return cacheGuardError("installed package identity changed before cached policy")
	}
	if c.boot == nil {
		return cacheGuardError("boot identity provider is unavailable")
	}
	boot, err := c.boot()
	if err != nil || strings.TrimSpace(boot) != decision.Boot {
		return cacheGuardError("boot identity changed before cached policy")
	}
	receipt, exists, err := c.loadCacheReceipt()
	if err != nil || !exists || !cacheReceiptMatchesIdentity(receipt, current) || receipt.Nonce != decision.Nonce {
		return cacheGuardError("stage receipt changed before cached policy: %v", err)
	}
	if receipt.StagedBootID == decision.Boot {
		return rebootRequiredError{message: "cache package was staged during this boot; reboot before enabling the connection cache"}
	}
	if decision.State == "same-boot-restart" && receipt.ConsumedBootID != decision.Boot {
		return cacheGuardError("same-boot cache receipt consumption changed before cached policy")
	}
	if decision.State == "fresh-boot" && receipt.ConsumedBootID == decision.Boot {
		return rebootRequiredError{message: "cache receipt was already consumed during this boot; reboot before retry"}
	}
	if err = cacheWriteFragment(filepath.Join(c.state, cacheReceiptFile)); err != nil {
		return cacheGuardError("%v", err)
	}
	if err = cacheWriteFragment(filepath.Join(c.state, cacheProofFile)); err != nil {
		return cacheGuardError("%v", err)
	}
	j, fingerprint, err := c.cacheJournalSnapshot()
	if err != nil || j.Boot != decision.Boot || j.Phase != "dns" {
		return cacheGuardError("pre-policy journal cannot bind cache proof: %v", err)
	}
	receipt.ConsumedBootID = decision.Boot
	receiptData, err := marshalCacheJSON(receipt)
	if err != nil {
		return err
	}
	if err = writeCacheStateFile(c.state, cacheReceiptFile, receiptData); err != nil {
		return fmt.Errorf("consume stage receipt before cached policy: %w", err)
	}
	proof := connectionCacheProof{
		SchemaVersion:      1,
		Status:             "preparing",
		Mode:               current.Mode,
		PackageVersion:     current.PackageVersion,
		Owner:              current.Owner,
		PayloadSHA256:      current.PayloadSHA256,
		ReceiptNonce:       receipt.Nonce,
		StagedBootID:       receipt.StagedBootID,
		ActivatedBootID:    decision.Boot,
		JournalFingerprint: fingerprint,
	}
	proofData, err := marshalCacheJSON(proof)
	if err != nil {
		return err
	}
	if err = writeCacheStateFile(c.state, cacheProofFile, proofData); err != nil {
		return fmt.Errorf("write preparing cache proof before cached policy: %w", err)
	}
	return nil
}

func (c *controller) commitCacheProof() error {
	mode, _, modeErr := c.cacheModeMarker()
	if modeErr != nil {
		return cacheGuardError("%v", modeErr)
	}
	if mode != cacheModeCTMark {
		return nil
	}
	proof, exists, err := c.loadCacheProof()
	if err != nil || !exists || proof.Status != "preparing" {
		return cacheGuardError("preparing cache proof is missing or invalid: %v", err)
	}
	j, fingerprint, err := c.cacheJournalSnapshot()
	if err != nil || j.Phase != "active" || j.Boot != proof.ActivatedBootID {
		return cacheGuardError("active journal is unavailable for cache proof commit: %v", err)
	}
	proof.Status = "active"
	proof.JournalFingerprint = fingerprint
	data, err := marshalCacheJSON(proof)
	if err != nil {
		return err
	}
	return writeCacheStateFile(c.state, cacheProofFile, data)
}

func (c *controller) captureCacheStopAuthorization(j *journal) *cacheStopAuthorization {
	if j == nil || (j.Phase != "active" && j.Phase != "restored") || !c.cacheLifecycleAuthorized || c.cacheRecoveryOnly {
		return nil
	}
	decision := c.cacheAuthorization
	if decision == nil || decision.Mode != cacheModeCTMark || decision.Boot == "" {
		return nil
	}
	mode, _, err := c.cacheModeMarker()
	if err != nil || mode != cacheModeCTMark {
		return nil
	}
	identity, err := c.verifiedCachePackageIdentity()
	if err != nil || identity != decision.ID {
		return nil
	}
	if c.boot == nil {
		return nil
	}
	boot, err := c.boot()
	if err != nil {
		return nil
	}
	boot = strings.TrimSpace(boot)
	if boot != decision.Boot || j.Boot != boot {
		return nil
	}
	snapshot, fingerprint, err := c.cacheJournalSnapshot()
	if err != nil || !reflect.DeepEqual(snapshot, j) {
		return nil
	}
	receipt, exists, err := c.loadCacheReceipt()
	if err != nil || !exists || !cacheReceiptMatchesIdentity(receipt, identity) || receipt.Nonce != decision.Nonce || receipt.ConsumedBootID != boot {
		return nil
	}
	proof, exists, err := c.loadCacheProof()
	if err != nil || !exists || proof.Status != "active" || proof.ActivatedBootID != boot || !cacheProofMatchesReceipt(proof, receipt) || proof.JournalFingerprint != fingerprint {
		return nil
	}
	return &cacheStopAuthorization{identity: identity, receipt: receipt, proof: proof, boot: boot, fingerprint: fingerprint}
}

func (c *controller) refreshCacheProofAfterRestore(j *journal, authorization *cacheStopAuthorization) error {
	if j == nil || j.Phase != "restored" {
		return nil
	}
	if c.cacheRecoveryOnly {
		return nil
	}
	mode, _, err := c.cacheModeMarker()
	if err != nil {
		return nil
	}
	if mode != cacheModeCTMark {
		_ = c.invalidateCacheProofForOffMode()
		return nil
	}
	if authorization == nil || !c.cacheLifecycleAuthorized {
		return nil
	}
	proof, exists, err := c.loadCacheProof()
	if os.IsNotExist(err) || (!exists && err == nil) {
		return nil
	}
	if err != nil {
		return nil
	}
	if proof.Status != "active" {
		return nil
	}
	if c.boot == nil {
		return cacheGuardError("boot identity provider is unavailable")
	}
	boot, err := c.boot()
	if err != nil {
		return nil
	}
	if proof.ActivatedBootID != strings.TrimSpace(boot) || j.Boot != proof.ActivatedBootID || authorization.boot != proof.ActivatedBootID {
		return nil
	}
	identity, err := c.verifiedCachePackageIdentity()
	if err != nil || identity != authorization.identity {
		return nil
	}
	receipt, exists, err := c.loadCacheReceipt()
	if err != nil || !exists || !cacheReceiptMatchesIdentity(receipt, identity) || !cacheProofMatchesReceipt(proof, receipt) || receipt != authorization.receipt || receipt.ConsumedBootID != proof.ActivatedBootID {
		return nil
	}
	if proof != authorization.proof || proof.JournalFingerprint != authorization.fingerprint {
		return nil
	}
	snapshot, fingerprint, err := c.cacheJournalSnapshot()
	if err != nil || !reflect.DeepEqual(snapshot, j) {
		return nil
	}
	if fingerprint == authorization.fingerprint {
		return nil
	}
	proof.JournalFingerprint = fingerprint
	data, err := marshalCacheJSON(proof)
	if err != nil {
		return err
	}
	return writeCacheStateFile(c.state, cacheProofFile, data)
}

func (c *controller) validateActiveCacheProof(j *journal) error {
	mode, _, err := c.cacheModeMarker()
	if err != nil || mode != cacheModeCTMark {
		return cacheGuardError("active cache mode marker is invalid: %v", err)
	}
	decision, err := c.checkCacheBootForActive()
	if err != nil {
		return err
	}
	if decision.State != "active" || j == nil || j.Phase != "active" || j.Boot != decision.Boot {
		return cacheGuardError("active cache proof does not match lifecycle journal")
	}
	return nil
}

func (c *controller) checkCacheBootForActive() (cacheGateDecision, error) {
	identity, err := c.verifiedCachePackageIdentity()
	if err != nil {
		return cacheGateDecision{}, cacheGuardError("installed package validation failed: %v", err)
	}
	if c.boot == nil {
		return cacheGateDecision{}, cacheGuardError("boot identity provider is unavailable")
	}
	boot, err := c.boot()
	if err != nil {
		return cacheGateDecision{}, cacheGuardError("current boot ID is unavailable: %v", err)
	}
	if !validCacheBootID(strings.TrimSpace(boot)) {
		return cacheGateDecision{}, cacheGuardError("current boot ID is invalid")
	}
	boot = strings.TrimSpace(boot)
	receipt, exists, err := c.loadCacheReceipt()
	if err != nil || !exists || !cacheReceiptMatchesIdentity(receipt, identity) || receipt.ConsumedBootID != boot {
		return cacheGateDecision{}, cacheGuardError("active cache receipt is missing or mismatched: %v", err)
	}
	proof, exists, err := c.loadCacheProof()
	if err != nil || !exists || proof.Status != "active" || proof.ActivatedBootID != boot || !cacheProofMatchesReceipt(proof, receipt) {
		return cacheGateDecision{}, cacheGuardError("active cache proof is missing or mismatched: %v", err)
	}
	_, fingerprint, err := c.cacheJournalSnapshot()
	if err != nil || proof.JournalFingerprint != fingerprint {
		return cacheGateDecision{}, cacheGuardError("active journal fingerprint changed: %v", err)
	}
	return cacheGateDecision{Mode: cacheModeCTMark, State: "active", Boot: boot, ID: identity, Nonce: receipt.Nonce}, nil
}

func (c *controller) invalidateCacheProofForStage() error {
	path := filepath.Join(c.state, cacheProofFile)
	if err := cacheWriteFragment(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = validateCacheStateFile(info); err != nil {
		return err
	}
	return os.Remove(path)
}

func (c *controller) cacheRollbackClean() error {
	if err := c.readStateDirectory(); err != nil {
		return err
	}
	if _, err := c.cacheOwner(); err != nil {
		return err
	}
	if err := cacheWriteFragment(filepath.Join(c.state, "journal.json")); err != nil {
		return err
	}
	journalPath := filepath.Join(c.state, "journal.json")
	if _, err := os.Lstat(journalPath); err == nil {
		j, _, snapshotErr := c.cacheJournalSnapshot()
		if snapshotErr != nil {
			return fmt.Errorf("restoration journal cannot be verified before cache-state cleanup: %w", snapshotErr)
		}
		if j.Phase != "restored" {
			return errors.New("cache-state cleanup requires a restored lifecycle journal")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := c.noOwnedObjects(); err != nil {
		return fmt.Errorf("owned integration is not fully restored: %w", err)
	}
	paths := []string{filepath.Join(c.state, cacheReceiptFile), filepath.Join(c.state, cacheProofFile)}
	for _, path := range paths {
		if err := cacheWriteFragment(path); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err = validateCacheStateFile(info); err != nil {
			return fmt.Errorf("refuse to remove unowned cache state %s: %w", filepath.Base(path), err)
		}
		if filepath.Base(path) == cacheReceiptFile {
			if _, _, err = c.loadCacheReceipt(); err != nil {
				return err
			}
		} else if _, _, err = c.loadCacheProof(); err != nil {
			return err
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove owned cache state %s: %w", filepath.Base(path), err)
		}
	}
	fmt.Println("SING_BOX_CACHE_ROLLBACK_CLEAN_OK")
	return nil
}
