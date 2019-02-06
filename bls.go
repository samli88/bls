package bls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"sort"
)

// Signature is a message signature.
type Signature struct {
	s *G1Projective
}

// Serialize serializes a signature in compressed form.
func (s *Signature) Serialize() []byte {
	return CompressG1(s.s.ToAffine()).Bytes()
}

// DeserializeSignature deserializes a signature from bytes.
func DeserializeSignature(b []byte) (*Signature, error) {
	a, err := DecompressG1(new(big.Int).SetBytes(b))
	if err != nil {
		return nil, err
	}

	return &Signature{s: a.ToProjective()}, nil
}

// Copy returns a copy of the signature.
func (s *Signature) Copy() *Signature {
	return &Signature{s.s.Copy()}
}

// PublicKey is a public key.
type PublicKey struct {
	p *G2Projective
}

func (p PublicKey) String() string {
	return p.p.String()
}

// Serialize serializes a public key to bytes.
func (p PublicKey) Serialize() []byte {
	return CompressG2(p.p.ToAffine()).Bytes()[:48]
}

// Equals checks if two public keys are equal
func (p PublicKey) Equals(other PublicKey) bool {
	return p.p.Equal(other.p)
}

// DeserializePublicKey deserializes a public key from
// bytes.
func DeserializePublicKey(b []byte) (*PublicKey, error) {
	a, err := DecompressG2(new(big.Int).SetBytes(b))
	if err != nil {
		return nil, err
	}

	return &PublicKey{p: a.ToProjective()}, nil
}

// SecretKey represents a BLS private key.
type SecretKey struct {
	f *FR
}

// SecretKeyFromSeed generates a secret key from a seed
func SecretKeyFromSeed(seed []byte) *SecretKey {
	// keyGen
	// Creates a public/private keypair, using a seed s. Private keys are 255 bit integers, and public keys are G1 elements.
	// input: random seed s
	// output: field element in Zq, G1 element
	// # Perform an HMAC using hash256, and the following string as the key
	// sk <- hmac256(s, b"BLS private key seed") mod n
	// pk <- g1 ^ sk

	// "BLS private key seed" in ascii
	hmacKey := []byte{
		0x42, 0x4c, 0x53, 0x20, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,
		0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x73, 0x65, 0x65, 0x64,
	}
	fmt.Println("hmackey = ", string(hmacKey))

	// securely allocate a buffer of PRIVATE_KEY_SIZE bytes
	//uint8_t* hash = Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);

	// fake it for now
	// var hash []byte

	// Hash the seed into sk
	// md_hmac(hash, seed, seedLen, hmacKey, sizeof(hmacKey));
	// func New(h func() hash.Hash, key []byte) hash.Hash
	//
	// New returns a new HMAC hash using the given hash.Hash type and key. Note
	// that unlike other hash implementations in the standard library, the
	// returned Hash does not implement encoding.BinaryMarshaler or
	// encoding.BinaryUnmarshaler.

	// Create a new HMAC by defining the hash type and the key (as byte array)
	hash := hmac.New(sha256.New, hmacKey)

	// Write data (which is the seed) to it
	hash.Write(seed)

	// Get the result
	// and encode as a hexadecimal string
	sha := hash.Sum(nil)

	sth := new(big.Int).Mod(
		new(big.Int).SetBytes(sha),
		RFieldModulus,
	)

	return &SecretKey{
		NewFR(sth),
	}
}

func (s SecretKey) String() string {
	return s.f.String()
}

// Serialize serializes a secret key to bytes.
func (s SecretKey) Serialize() []byte {
	return s.f.ToBig().Bytes()
}

// DeserializeSecretKey deserializes a secret key from
// bytes.
func DeserializeSecretKey(b []byte) *SecretKey {
	return &SecretKey{NewFR(new(big.Int).SetBytes(b))}
}

// Sign signs a message with a secret key.
func Sign(message []byte, key *SecretKey) *Signature {
	h := HashG1(message).Mul(key.f.n)
	return &Signature{s: h}
}

// PrivToPub converts the private key into a public key.
func PrivToPub(k *SecretKey) *PublicKey {
	return &PublicKey{p: G2AffineOne.Mul(k.f.n)}
}

// RandKey generates a random secret key.
func RandKey(r io.Reader) (*SecretKey, error) {
	k, err := RandFR(r)
	if err != nil {
		return nil, err
	}
	s := &SecretKey{f: k}
	return s, nil
}

// KeyFromBig returns a new key based on a big int in
// FR.
func KeyFromBig(i *big.Int) *SecretKey {
	return &SecretKey{f: NewFR(i)}
}

// Verify verifies a signature against a message and a public key.
func Verify(m []byte, pub *PublicKey, sig *Signature) bool {
	h := HashG1(m)
	lhs := Pairing(sig.s, G2ProjectiveOne)
	rhs := Pairing(h, pub.p)
	return lhs.Equals(rhs)
}

// AggregateSignatures adds up all of the signatures.
func AggregateSignatures(s []*Signature) *Signature {
	newSig := &Signature{s: G1ProjectiveZero.Copy()}
	for _, sig := range s {
		newSig.Aggregate(sig)
	}
	return newSig
}

// Aggregate adds one signature to another
func (s *Signature) Aggregate(other *Signature) {
	newS := s.s.Add(other.s)
	s.s = newS
}

// AggregatePublicKeys adds public keys together.
func AggregatePublicKeys(p []*PublicKey) *PublicKey {
	newPub := &PublicKey{p: G2ProjectiveZero.Copy()}
	for _, pub := range p {
		newPub.Aggregate(pub)
	}
	return newPub
}

// Aggregate adds two public keys together.
func (p *PublicKey) Aggregate(other *PublicKey) {
	newP := p.p.Add(other.p)
	p.p = newP
}

// Copy copies the public key and returns it.
func (p *PublicKey) Copy() *PublicKey {
	return &PublicKey{p: p.p.Copy()}
}

// NewAggregateSignature creates a blank aggregate signature.
func NewAggregateSignature() *Signature {
	return &Signature{s: G1ProjectiveZero.Copy()}
}

// NewAggregatePubkey creates a blank public key.
func NewAggregatePubkey() *PublicKey {
	return &PublicKey{p: G2ProjectiveZero.Copy()}
}

// implement `Interface` in sort package.
type sortableByteArray [][]byte

func (b sortableByteArray) Len() int {
	return len(b)
}

func (b sortableByteArray) Less(i, j int) bool {
	// bytes package already implements Comparable for []byte.
	switch bytes.Compare(b[i], b[j]) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		log.Panic("not fail-able with `bytes.Comparable` bounded [-1, 1].")
		return false
	}
}

func (b sortableByteArray) Swap(i, j int) {
	b[j], b[i] = b[i], b[j]
}

func sortByteArrays(src [][]byte) [][]byte {
	sorted := sortableByteArray(src)
	sort.Sort(sorted)
	return sorted
}

// VerifyAggregate verifies each public key against each message.
func (s *Signature) VerifyAggregate(pubKeys []*PublicKey, msgs [][]byte) bool {
	if len(pubKeys) != len(msgs) {
		return false
	}

	// messages must be distinct
	msgsSorted := sortByteArrays(msgs)
	lastMsg := []byte(nil)

	// check for duplicates
	for _, m := range msgsSorted {
		if bytes.Equal(m, lastMsg) {
			return false
		}
		lastMsg = m
	}

	lhs := Pairing(s.s, G2ProjectiveOne)
	rhs := FQ12One.Copy()
	for i := range pubKeys {
		h := HashG1(msgs[i])
		rhs.MulAssign(Pairing(h, pubKeys[i].p))
	}
	return lhs.Equals(rhs)
}

// VerifyAggregateCommon verifies each public key against a message.
// This is vulnerable to rogue public-key attack. Each user must
// provide a proof-of-knowledge of the public key.
func (s *Signature) VerifyAggregateCommon(pubKeys []*PublicKey, msg []byte) bool {
	h := HashG1(msg)
	lhs := Pairing(s.s, G2ProjectiveOne)
	rhs := FQ12One.Copy()
	for _, p := range pubKeys {
		rhs.MulAssign(Pairing(h, p.p))
	}
	return lhs.Equals(rhs)
}
