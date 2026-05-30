package attestix

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// jwtHeader is the decoded JOSE header of a UCAN delegation JWT.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Ucv string `json:"ucv"`
}

// DelegationClaims are the UCAN payload claims relevant to verification.
type DelegationClaims struct {
	Iss string   `json:"iss"`
	Aud string   `json:"aud"`
	Sub string   `json:"sub"`
	Iat int64    `json:"iat"`
	Exp int64    `json:"exp"`
	Nbf int64    `json:"nbf"`
	Jti string   `json:"jti"`
	Att []string `json:"att"`
	Prf []string `json:"prf"`
}

// DelegationResult is the structured outcome of verifying a delegation chain.
type DelegationResult struct {
	// ParentSignatureValid is the EdDSA signature verdict for the parent token.
	ParentSignatureValid bool
	// ChildSignatureValid is the EdDSA signature verdict for the child token.
	ChildSignatureValid bool
	// AttenuationIsSubset is true when the child att is a subset of parent att.
	AttenuationIsSubset bool
}

// Verify reports the overall delegation verdict: both signatures valid AND the
// child capabilities are a subset of the parent's.
func (r DelegationResult) Verify() bool {
	return r.ParentSignatureValid && r.ChildSignatureValid && r.AttenuationIsSubset
}

// VerifyDelegationChain verifies a two-link UCAN delegation (parent -> child).
// Each token is an EdDSA-signed compact JWT; the signed message is
// base64url(header)."."base64url(payload) (unpadded, per the JWT spec). Only
// alg=EdDSA is accepted; alg:none is rejected.
//
// Both tokens are verified against pub (in Attestix every token in a chain is
// signed by the single server key). The child att MUST be a subset of the
// parent att or the chain is rejected for privilege escalation.
//
// childAtt and parentAtt, when non-nil, are the authoritative capability lists
// to compare; when nil they are taken from the respective token payloads.
func VerifyDelegationChain(childToken, parentToken string, childAtt, parentAtt []string, pub ed25519.PublicKey) (DelegationResult, error) {
	return verifyDelegationChainAt(childToken, parentToken, childAtt, parentAtt, pub, time.Now())
}

func verifyDelegationChainAt(childToken, parentToken string, childAtt, parentAtt []string, pub ed25519.PublicKey, now time.Time) (DelegationResult, error) {
	var res DelegationResult

	childClaims, childSigOK, err := verifyJWT(childToken, pub)
	if err != nil {
		return res, err
	}
	res.ChildSignatureValid = childSigOK

	parentClaims, parentSigOK, err := verifyJWT(parentToken, pub)
	if err != nil {
		return res, err
	}
	res.ParentSignatureValid = parentSigOK

	if childAtt == nil {
		childAtt = childClaims.Att
	}
	if parentAtt == nil {
		parentAtt = parentClaims.Att
	}
	res.AttenuationIsSubset = isSubset(childAtt, parentAtt)

	return res, nil
}

// VerifyToken verifies a single UCAN JWT signature against pub, returning the
// decoded claims. It rejects any algorithm other than EdDSA. It does not walk
// the prf chain; use VerifyChainFull for recursive verification.
func VerifyToken(token string, pub ed25519.PublicKey) (DelegationClaims, bool, error) {
	return verifyJWT(token, pub)
}

func verifyJWT(token string, pub ed25519.PublicKey) (DelegationClaims, bool, error) {
	var claims DelegationClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, false, fmt.Errorf("attestix: malformed JWT (want 3 parts, got %d)", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, false, fmt.Errorf("attestix: decode JWT header: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return claims, false, fmt.Errorf("attestix: parse JWT header: %w", err)
	}
	// Reject alg:none and anything that is not EdDSA.
	if hdr.Alg != "EdDSA" {
		return claims, false, nil
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, false, fmt.Errorf("attestix: decode JWT payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return claims, false, fmt.Errorf("attestix: parse JWT payload: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims, false, fmt.Errorf("attestix: decode JWT signature: %w", err)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	ok := ed25519.Verify(pub, signingInput, sig)
	return claims, ok, nil
}

// VerifyChainFull recursively verifies a UCAN token and its entire prf ancestor
// chain against pub: every token's EdDSA signature must verify, none may be
// expired (exp claim, compared against now), and the chain must contain no
// cycles (a repeated jti). Capability attenuation is asserted at each link:
// each token's att must be a subset of every parent it references in prf.
func VerifyChainFull(token string, pub ed25519.PublicKey, now time.Time) (bool, error) {
	seen := map[string]bool{}
	return verifyChainRec(token, pub, now, seen)
}

func verifyChainRec(token string, pub ed25519.PublicKey, now time.Time, seen map[string]bool) (bool, error) {
	claims, sigOK, err := verifyJWT(token, pub)
	if err != nil {
		return false, err
	}
	if !sigOK {
		return false, nil
	}
	if claims.Jti != "" {
		if seen[claims.Jti] {
			return false, nil // cycle
		}
		seen[claims.Jti] = true
		defer delete(seen, claims.Jti)
	}
	if claims.Exp != 0 && now.Unix() >= claims.Exp {
		return false, nil // expired
	}
	for _, parentTok := range claims.Prf {
		parentClaims, parentSigOK, err := verifyJWT(parentTok, pub)
		if err != nil {
			return false, err
		}
		if !parentSigOK {
			return false, nil
		}
		// Attenuation: this token's att must be a subset of the parent's.
		if !isSubset(claims.Att, parentClaims.Att) {
			return false, nil
		}
		ok, err := verifyChainRec(parentTok, pub, now, seen)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func isSubset(child, parent []string) bool {
	set := make(map[string]struct{}, len(parent))
	for _, p := range parent {
		set[p] = struct{}{}
	}
	for _, c := range child {
		if _, ok := set[c]; !ok {
			return false
		}
	}
	return true
}
