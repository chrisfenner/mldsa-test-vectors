package testvector

import (
	"github.com/nsmithuk/ml-dsa/mldsa44"
	"github.com/nsmithuk/ml-dsa/mldsa65"
	"github.com/nsmithuk/ml-dsa/mldsa87"
	"github.com/nsmithuk/ml-dsa/types"
)

type ParameterSet int

const (
	ParameterSetUnspecified ParameterSet = iota
	ParameterSetMLDSA44
	ParameterSetMLDSA65
	ParameterSetMLDSA87
)

// String implements the stringer interface.
func (p ParameterSet) String() string {
	switch p {
	case ParameterSetMLDSA44:
		return "ML-DSA-44"
	case ParameterSetMLDSA65:
		return "ML-DSA-65"
	case ParameterSetMLDSA87:
		return "ML-DSA-87"
	}
	panic("invalid ParameterSet")
}

// PublicKeySize returns the size of the public key for this parameter set.
func (p ParameterSet) PublicKeySize() int {
	switch p {
	case ParameterSetMLDSA44:
		return 1312
	case ParameterSetMLDSA65:
		return 1952
	case ParameterSetMLDSA87:
		return 2592
	}
	panic("invalid ParameterSet")
}

// SecretKeySize returns the size of the secret key for this parameter set.
func (p ParameterSet) SecretKeySize() int {
	switch p {
	case ParameterSetMLDSA44:
		return 2560
	case ParameterSetMLDSA65:
		return 4032
	case ParameterSetMLDSA87:
		return 4896
	}
	panic("invalid ParameterSet")
}

// SignatureSize returns the size of the signature for this parameter set.
func (p ParameterSet) SignatureSize() int {
	switch p {
	case ParameterSetMLDSA44:
		return 2420
	case ParameterSetMLDSA65:
		return 3309
	case ParameterSetMLDSA87:
		return 4627
	}
	panic("invalid ParameterSet")
}

// ExpandSeed expands the seed, or panics because the seed is not 32 bytes.
func (p ParameterSet) ExpandSeed(seed []byte) types.PrivateKey {
	switch p {
	case ParameterSetMLDSA44:
		key, err := mldsa44.PrivateKeyFromSeed(seed)
		if err != nil {
			panic(err.Error())
		}
		return key
	case ParameterSetMLDSA65:
		key, err := mldsa65.PrivateKeyFromSeed(seed)
		if err != nil {
			panic(err.Error())
		}
		return key
	case ParameterSetMLDSA87:
		key, err := mldsa87.PrivateKeyFromSeed(seed)
		if err != nil {
			panic(err.Error())
		}
		return key
	}
	panic("invalid ParameterSet")
}
