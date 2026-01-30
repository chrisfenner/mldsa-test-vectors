// Package testvector includes helpers for generating ML-DSA test vectors.
package testvector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/nsmithuk/ml-dsa/options"
)

// HexBytes is a byte array that overrides UnmarshalJSON so it gets printed in hex.
type HexBytes []byte

// A TestVector is a single test vector in the output JSON.
type TestVector struct {
	// ML-DSA-44, ML-DSA-65, or ML-DSA-87
	ParameterSet string
	// The seed that derives the expanded keypair.
	Seed HexBytes
	// The public key.
	PublicKey HexBytes
	// The (expanded) secret key.
	SecretKey HexBytes
	// The randomness used during signing.
	Entropy HexBytes
	// The message that was signed.
	Message HexBytes
	// The context used with the signature.
	Context HexBytes
	// The µ value produced based on the public key, context, and message.
	Mu HexBytes
	// The signature.
	Signature HexBytes
}

// MarshalJSON implements the json.Marshaler interface.
func (data HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(data))
}

// A KATInput is a single test vector from github.com/post-quantum-cryptography/KAT's ML-DSA data.
type KATInput struct {
	// The seed as a hex string.
	Xi string
	// The randomness as a hex string.
	RNG string
	// The public key as a hex string.
	PK string
	// The secret key as a hex string.
	SK string
	// The message to be signed as a hex string.
	Msg string
	// The context as a hex string.
	Ctx string
	// The signature concatenated with the message, as a hex string.
	SM string
}

// ComputeTestVector expands the provided data from post-quantum-cryptography/KAT, computing µ along the way.
func ComputeTestVector(input KATInput) (*TestVector, error) {
	// Decode and validate all the things.
	seed, err := decodeHexAndCheckLength(input.Xi, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid xi: %v", err)
	}
	entropy, err := decodeHexAndCheckLength(input.RNG, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid rng: %v", err)
	}
	// Take the size of the public key as our indicator of what the parameter set.
	publicKey, err := hex.DecodeString(input.PK)
	if err != nil {
		return nil, fmt.Errorf("invalid pk: %v", err)
	}
	var params ParameterSet
	switch len(publicKey) {
	case ParameterSetMLDSA44.PublicKeySize():
		params = ParameterSetMLDSA44
	case ParameterSetMLDSA65.PublicKeySize():
		params = ParameterSetMLDSA65
	case ParameterSetMLDSA87.PublicKeySize():
		params = ParameterSetMLDSA87
	default:
		return nil, fmt.Errorf("invalid pk: %v did not conform to any known ML-DSA parameter set", input.PK)
	}

	secretKey, err := decodeHexAndCheckLength(input.SK, params.SecretKeySize())
	if err != nil {
		return nil, fmt.Errorf("invalid sk: %v", err)
	}
	// We don't check the length of message or context. They vary.
	msg, err := hex.DecodeString(input.Msg)
	if err != nil {
		return nil, fmt.Errorf("invalid msg: %v", err)
	}
	ctx, err := hex.DecodeString(input.Ctx)
	if err != nil {
		return nil, fmt.Errorf("invalid ctx: %v", err)
	}
	sigMessage, err := decodeHexAndCheckLength(input.SM, params.SignatureSize()+len(msg))
	if err != nil {
		return nil, fmt.Errorf("invalid sm: %v", err)
	}
	sig := sigMessage[:params.SignatureSize()]

	// Expand the key and check that it matches our expectations.
	sk := params.ExpandSeed(seed)
	if !bytes.Equal(secretKey, sk.EncodeExpanded()) {
		return nil, fmt.Errorf("unexpected secret key: KAT had %x, seed derives %x", secretKey, sk.EncodeExpanded())
	}
	pk := sk.PublicKey()
	if !bytes.Equal(publicKey, pk.Bytes()) {
		return nil, fmt.Errorf("unexpected public key: KAT had %x, seed derives %x", secretKey, pk.Bytes())
	}

	// Does the signature from the KAT verify?
	if !pk.VerifyWithOptions(msg, sig, &options.Options{
		Context: string(ctx),
	}) {
		return nil, fmt.Errorf("could not verify signature")
	}

	// Compute our mu.
	mu, err := computeExternalMu(publicKey, ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("computing mu: %v", err)
	}

	// Does the mu work?
	if !pk.VerifyWithExternalMU(mu, sig) {
		return nil, fmt.Errorf("could not verify mu")
	}

	return &TestVector{
		ParameterSet: params.String(),
		Seed:         seed,
		PublicKey:    pk.Bytes(),
		SecretKey:    sk.EncodeExpanded(),
		Entropy:      entropy,
		Message:      msg,
		Context:      ctx,
		Mu:           mu,
		Signature:    sig,
	}, nil
}
