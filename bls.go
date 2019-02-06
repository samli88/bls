package bls

import (
	"bytes"
	"io"
	"log"
	"math/big"
	"sort"
)

// Signature is a message signature.
type Signature struct {
	s *G2Projective
}

// Serialize serializes a signature in compressed form.
func (s *Signature) Serialize() []byte {
	return CompressG2(s.s.ToAffine()).Bytes()
}

// DeserializeSignature deserializes a signature from bytes.
func DeserializeSignature(b []byte) (*Signature, error) {
	a, err := DecompressG2(new(big.Int).SetBytes(b))
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
	p *G1Projective
}

func (p PublicKey) String() string {
	return p.p.String()
}

// Serialize serializes a public key to bytes.
func (p PublicKey) Serialize() []byte {
	// Serialization
	// private key (32 bytes): Big endian integer.

	// pubkey (48 bytes): 381 bit affine x coordinate, encoded into 48
	// big-endian bytes. Since we have 3 bits left over in the beginning, the
	// first bit is set to 1 iff y coordinate is the lexicographically largest
	// of the two valid ys. The public key fingerprint is the first 4 bytes of
	// hash256(serialize(pubkey)).

	// signature (96 bytes): Two 381 bit integers (affine x coordinate),
	// encoded into two 48 big-endian byte arrays. Since we have 3 bits left
	// over in the beginning, the first bit is set to 1 iff the y coordinate is
	// the lexicographically largest of the two valid ys. (The term with the i
	// is compared first, i.e 3i + 1 > 2i + 7).

	return CompressG1(p.p.ToAffine()).Bytes()
}

// Fingerprint returns the public key fingerprint per the spec:
//
// The public key fingerprint is the first 4 bytes of hash256(serialize(pubkey))
func (p *PublicKey) Fingerprint() []byte {
	buf := Hash256(p.Serialize())
	return buf[:4]
}

// Equals checks if two public keys are equal
func (p PublicKey) Equals(other PublicKey) bool {
	return p.p.Equal(other.p)
}

// DeserializePublicKey deserializes a public key from
// bytes.
func DeserializePublicKey(b []byte) (*PublicKey, error) {
	a, err := DecompressG1(new(big.Int).SetBytes(b))
	if err != nil {
		return nil, err
	}

	return &PublicKey{p: a.ToProjective()}, nil
}

// SecretKey represents a BLS private key.
type SecretKey struct {
	f *FR
}

// SecretKeyFromSeed generates a private key from a seed, similar to HD key
// generation (hashes the seed), and reduces it mod the group order.
func SecretKeyFromSeed(seed []byte) *SecretKey {
	hmacKey := []byte("BLS private key seed")

	// TODO: Harden. memguard?
	// securely allocate a buffer of PRIVATE_KEY_SIZE bytes
	// uint8_t* hash = Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);

	hashed := Hmac256(seed, hmacKey)
	// Mod n (ensure value less than group order)
	return &SecretKey{
		NewFR(new(big.Int).Mod(new(big.Int).SetBytes(hashed), RFieldModulus)),
	}
}

// PublicKey returns the public key.
func (s *SecretKey) PublicKey() *PublicKey {
	return PrivToPub(s)
}

// String implements the Stringer interface.
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
	h := HashG2(message).Mul(key.f.n)
	return &Signature{s: h}
}

// PrivToPub converts the private key into a public key.
// pk <- g1 ^ sk
func PrivToPub(k *SecretKey) *PublicKey {
	return &PublicKey{p: G1AffineOne.Mul(k.f.n)}
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
	h := HashG2(m)
	lhs := Pairing(G1ProjectiveOne, sig.s)
	rhs := Pairing(pub.p, h)
	return lhs.Equals(rhs)
}

// AggregateSignatures adds up all of the signatures.
func AggregateSignatures(s []*Signature) *Signature {
	newSig := &Signature{s: G2ProjectiveZero.Copy()}
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
	newPub := &PublicKey{p: G1ProjectiveZero.Copy()}
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
	return &Signature{s: G2ProjectiveZero.Copy()}
}

// NewAggregatePubkey creates a blank public key.
func NewAggregatePubkey() *PublicKey {
	return &PublicKey{p: G1ProjectiveZero.Copy()}
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

	lhs := Pairing(G1ProjectiveOne, s.s)
	rhs := FQ12One.Copy()
	for i := range pubKeys {
		h := HashG2(msgs[i])
		rhs.MulAssign(Pairing(pubKeys[i].p, h))
	}
	return lhs.Equals(rhs)
}

// VerifyAggregateCommon verifies each public key against a message.
// This is vulnerable to rogue public-key attack. Each user must
// provide a proof-of-knowledge of the public key.
func (s *Signature) VerifyAggregateCommon(pubKeys []*PublicKey, msg []byte) bool {
	h := HashG2(msg)
	lhs := Pairing(G1ProjectiveOne, s.s)
	rhs := FQ12One.Copy()
	for _, p := range pubKeys {
		rhs.MulAssign(Pairing(p.p, h))
	}
	return lhs.Equals(rhs)
}
