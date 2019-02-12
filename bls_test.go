package bls_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/matryer/is"
	"github.com/samli88/bls"
)

func SignVerify(loopCount int) error {
	r := NewXORShift(1)
	for i := 0; i < loopCount; i++ {
		priv, _ := bls.RandKey(r)
		pub := bls.PrivToPub(priv)
		msg := []byte(fmt.Sprintf("Hello world! 16 characters %d", i))
		sig := bls.Sign(msg, priv, 0)
		if !bls.Verify(msg, pub, sig, 0) {
			return errors.New("sig did not verify")
		}
	}
	return nil
}

func SignVerifyAggregateCommonMessage(loopCount int) error {
	r := NewXORShift(2)
	pubkeys := make([]*bls.PublicKey, 0, 1000)
	sigs := make([]*bls.Signature, 0, 1000)
	msg := []byte(">16 character identical message")
	for i := 0; i < loopCount; i++ {
		priv, _ := bls.RandKey(r)
		pub := bls.PrivToPub(priv)
		sig := bls.Sign(msg, priv, 0)
		pubkeys = append(pubkeys, pub)
		sigs = append(sigs, sig)
		if i < 10 || i > (loopCount-5) {
			newSig := bls.AggregateSignatures(sigs)
			if !newSig.VerifyAggregateCommon(pubkeys, msg, 0) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func SignVerifyAggregateCommonMessageMissingSig(loopCount int) error {
	r := NewXORShift(3)
	skippedSig := loopCount / 2
	pubkeys := make([]*bls.PublicKey, 0, 1000)
	sigs := make([]*bls.Signature, 0, 1000)
	msg := []byte(">16 character identical message")
	for i := 0; i < loopCount; i++ {
		priv, _ := bls.RandKey(r)
		pub := bls.PrivToPub(priv)
		sig := bls.Sign(msg, priv, 0)
		pubkeys = append(pubkeys, pub)
		if i != skippedSig {
			sigs = append(sigs, sig)
		}
		if i < 10 || i > (loopCount-5) {
			newSig := bls.AggregateSignatures(sigs)
			if newSig.VerifyAggregateCommon(pubkeys, msg, 0) != (i < skippedSig) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func AggregateSignatures(loopCount int) error {
	r := NewXORShift(4)
	pubkeys := make([]*bls.PublicKey, 0, 1000)
	msgs := make([][]byte, 0, 1000)
	sigs := make([]*bls.Signature, 0, 1000)
	for i := 0; i < loopCount; i++ {
		priv, _ := bls.RandKey(r)
		pub := bls.PrivToPub(priv)
		msg := []byte(fmt.Sprintf(">16 character identical message %d", i))
		sig := bls.Sign(msg, priv, 0)
		pubkeys = append(pubkeys, pub)
		msgs = append(msgs, msg)
		sigs = append(sigs, sig)

		if i < 10 || i > (loopCount-5) {
			newSig := bls.AggregateSignatures(sigs)
			if !newSig.VerifyAggregate(pubkeys, msgs, 0) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func TestSignVerify(t *testing.T) {
	err := SignVerify(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyAggregateCommon(t *testing.T) {
	err := SignVerifyAggregateCommonMessage(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyAggregateCommonMissingSig(t *testing.T) {
	err := SignVerifyAggregateCommonMessageMissingSig(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignAggregateSigs(t *testing.T) {
	err := AggregateSignatures(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAggregateSignaturesDuplicatedMessages(t *testing.T) {
	r := NewXORShift(5)

	pubkeys := make([]*bls.PublicKey, 0, 1000)
	msgs := make([][]byte, 0, 1000)
	sigs := bls.NewAggregateSignature()

	key, _ := bls.RandKey(r)
	pub := bls.PrivToPub(key)
	message := []byte(">16 char first message")
	sig := bls.Sign(message, key, 0)
	pubkeys = append(pubkeys, pub)
	msgs = append(msgs, message)
	sigs.Aggregate(sig)

	if !sigs.VerifyAggregate(pubkeys, msgs, 0) {
		t.Fatal("signature does not verify")
	}

	key2, _ := bls.RandKey(r)
	pub2 := bls.PrivToPub(key2)
	message2 := []byte(">16 char second message")
	sig2 := bls.Sign(message2, key2, 0)
	pubkeys = append(pubkeys, pub2)
	msgs = append(msgs, message2)
	sigs.Aggregate(sig2)

	if !sigs.VerifyAggregate(pubkeys, msgs, 0) {
		t.Fatal("signature does not verify")
	}

	key3, _ := bls.RandKey(r)
	pub3 := bls.PrivToPub(key3)
	sig3 := bls.Sign(message2, key3, 0)
	pubkeys = append(pubkeys, pub3)
	msgs = append(msgs, message2)
	sigs.Aggregate(sig3)

	if sigs.VerifyAggregate(pubkeys, msgs, 0) {
		t.Fatal("signature verifies with duplicate message")
	}
}

func BenchmarkBLSAggregateSignature(b *testing.B) {
	r := NewXORShift(5)
	priv, _ := bls.RandKey(r)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	s := bls.NewAggregateSignature()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Aggregate(sig)
	}
}

func BenchmarkBLSSign(b *testing.B) {
	r := NewXORShift(5)
	privs := make([]*bls.SecretKey, b.N)
	for i := range privs {
		privs[i], _ = bls.RandKey(r)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		msg := []byte(fmt.Sprintf("Hello world! 16 characters %d", i))
		bls.Sign(msg, privs[i], 0)
		// if !bls.Verify(msg, pub, sig) {
		// 	return errors.New("sig did not verify")
		// }
	}
}

func BenchmarkBLSVerify(b *testing.B) {
	r := NewXORShift(5)
	priv, _ := bls.RandKey(r)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bls.Verify(msg, pub, sig, 0)
	}
}

func TestSignatureSerializeDeserialize(t *testing.T) {
	r := NewXORShift(1)
	priv, _ := bls.RandKey(r)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	if !bls.Verify(msg, pub, sig, 0) {
		t.Fatal("message did not verify before serialization/deserialization")
	}

	sigSer := sig.Serialize(true)
	sigDeser, err := bls.DeserializeSignature(sigSer)
	if err != nil {
		t.Fatal(err)
	}
	if !bls.Verify(msg, pub, sigDeser, 0) {
		t.Fatal("message did not verify after serialization/deserialization")
	}
}

func TestPubkeySerializeDeserialize(t *testing.T) {
	r := NewXORShift(1)
	priv, _ := bls.RandKey(r)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	if !bls.Verify(msg, pub, sig, 0) {
		t.Fatal("message did not verify before serialization/deserialization of pubkey")
	}

	pubSer := pub.Serialize(true)
	pubDeser, err := bls.DeserializePublicKey(pubSer)
	if err != nil {
		t.Fatal(err)
	}
	if !bls.Verify(msg, pubDeser, sig, 0) {
		t.Fatal("message did not verify after serialization/deserialization of pubkey")
	}
}

func TestPubkeySerializeDeserializeBig(t *testing.T) {
	r := NewXORShift(1)
	priv, _ := bls.RandKey(r)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	if !bls.Verify(msg, pub, sig, 0) {
		t.Fatal("message did not verify before serialization/deserialization of uncompressed pubkey")
	}

	pubSer := pub.Serialize(false)
	pubDeser, _ := bls.DeserializePublicKey(pubSer)
	if !bls.Verify(msg, pubDeser, sig, 0) {
		t.Fatal("message did not verify after serialization/deserialization of uncompressed pubkey")
	}
}

// TODO: Add tests for all test vectors here:
// https://github.com/Chia-Network/bls-signatures/blob/master/SPEC.md

func TestKeygen(t *testing.T) {
	tests := []struct {
		seed          []byte
		secretKey     []byte
		pkFingerprint []byte
	}{

		// keygen([1,2,3,4,5])
		// sk1: 0x022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e
		// pk1 fingerprint: 0x26d53247

		// keygen([1,2,3,4,5,6])
		//pk2 fingerprint: 0x289bb56e

		{
			seed: []byte{1, 2, 3, 4, 5},
			secretKey: []byte{
				0x02, 0x2f, 0xb4, 0x2c, 0x08, 0xc1, 0x2d, 0xe3,
				0xa6, 0xaf, 0x05, 0x38, 0x80, 0x19, 0x98, 0x06,
				0x53, 0x2e, 0x79, 0x51, 0x5f, 0x94, 0xe8, 0x34,
				0x61, 0x61, 0x21, 0x01, 0xf9, 0x41, 0x2f, 0x9e,
			},
			pkFingerprint: []byte{0x26, 0xd5, 0x32, 0x47},
		},
		{
			seed:          []byte{1, 2, 3, 4, 5, 6},
			secretKey:     []byte{},
			pkFingerprint: []byte{0x28, 0x9b, 0xb5, 0x6e},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)

			sk := bls.SecretKeyFromSeed(tt.seed)
			if len(tt.secretKey) > 0 {
				is.Equal(sk.Serialize(), tt.secretKey)
			}

			pk := sk.PublicKey()
			is.Equal(pk.Fingerprint(), tt.pkFingerprint)
		})
	}
}

// generated series of BLS keypairs on Dash v0.13 node for test compatibility
// secret and public keys should match (derive public from secret should work w/this lib)
func TestDashCoreBLSCompatibility(t *testing.T) {
	tests := []struct {
		secretKeyHex string
		publicKeyHex string
	}{
		{
			secretKeyHex: "563ce0062829910d8ef12cff8f47ea800832bc84cd3222d2bdfd1282cd362852",
			publicKeyHex: "8f5c05bdd0ee6fca063a49684c9f88fae01872f96d340db7d8ee1afee379d0031025e6e34d528a0fc6091c595d6ebc87",
		},
		{
			secretKeyHex: "5cdf4e6f00b65f8e8ed9815ee1df8852d5c76374cb9a281d377974affb6fde54",
			publicKeyHex: "181c4426ca49c6edeeae5f24f90791bbefc448bfcb7b58f8596f49a732c834538f4b65ad87465b7bdb57d517393a9be8",
		},
		{
			secretKeyHex: "2ac124c0aa1808e590ff1f94d67a53970ae982aa30bbe261ff1cb2ad15b7452a",
			publicKeyHex: "816782edc8f6815af5e256899d028c2dd2b6b243629262ea98da8df4b5755b24f85f78f5b124f2629b3fbdd2691cfb43",
		},
		{
			secretKeyHex: "149b7aafe55c94d1385304927c9943035812932477f660af44512a4f4a43bc2b",
			publicKeyHex: "01ae29b5718bafb22acc9ef7f77f3194452c9706b02e7ffee9a63228ae4bc9c908c9b49b9d2398829ffecd5ca150210b",
		},
		{
			secretKeyHex: "5e0c7856e7e31bb48a55678fec6d84151d5cd151fe9ed28cd97b580493e6fcd2",
			publicKeyHex: "17ef59b207a4dd5fba3f3bbe7549282a8ec53cb15e04d2fecd7c9812e1d383ac0f6dafe658346c53c4e50c9a092db586",
		},
		{
			secretKeyHex: "08e991bed779bc5a00ee613bd0fc3cd559670c3d6f18c534c06fe712b788e4c8",
			publicKeyHex: "956bb4e7316c21cf6cd535d32153e3fc570275a163241f6b63700aab9e103866c8922521e7a85182b61db03d180cd773",
		},
		{
			secretKeyHex: "21f47ee59dd75dc0d3b94843e44ccab3330d9e3fff13d072f5f2f1acbe3899da",
			publicKeyHex: "9429ea151b396f939bd06956513dab36474353f251a0b67eff04bbbdc91055ca4ccccb977a02dc42050960acc0db4ef6",
		},
		{
			secretKeyHex: "09cbaab1c0ab5a653b717d55eda537acf2c7879cb783486beae01612089e4174",
			publicKeyHex: "88181756209a9e9c3d2514c4e54a5d0646d6420a32094ca6baca3d0911d6aa542804c91bb5ade0fc277ab27d0d5c7608",
		},
		{
			secretKeyHex: "5ef06bb638002387bed416da8498b5c193978705c02d3160b4278e4d04aebbea",
			publicKeyHex: "93426e1bdf510fe35cf516087b1f9194d76f9160da6ecfd552a661dca2af1a368928da5acd38e61b7cb4ab789549d609",
		},
		{
			secretKeyHex: "57c4dd2086e26a05e43b94a8163e8714fb5bcc77ff60069d0919a9895ae9a7a8",
			publicKeyHex: "8a4b47215b573ef5c920097e02e33a3847f64a89645b8c77e7d5e0e3b68337d9b699cfd257e9bafaf2953f8cd9b3d3d8",
		},
		{
			secretKeyHex: "640ef47b97ebeb77277b945d455203a98c464412ae6cac3ddba3fbca90829b27",
			publicKeyHex: "09c2c2793d144ef3a9b751e49fd0f5203046713c80b7c1efca83cda5b03bb4fdec578e631558a87064554b1c63243e48",
		},
		{
			secretKeyHex: "4d172864f1345818cb388f0b30430e2eda878c467a7ba15abb428c81f4e07511",
			publicKeyHex: "84242993f3db405b033f04f013a61183a9a5c55e4ff29b5f431650c8e6bac4698ea3c8712bfb43c31b8fd9a313e271af",
		},
		{
			secretKeyHex: "62855030fec9b6da6a2e1c1bdce0b81684fad5af7d707e733a2a34373b0e154c",
			publicKeyHex: "0525a44f295d849096251a7a441edc51abb7371171e022ca98a47a47d1a3604d9a4503059cadca241d8086953c59ac89",
		},
		{
			secretKeyHex: "3d8009979132d9e031385f4a8905a905bf5583c193aeb62b6d430587bab86761",
			publicKeyHex: "8fc26e246f89547d691155b6a8acd5f87b3c064feccf6395cd49a5b34c2f2f03ca52ba54562b3492d9d982cecfdbf40d",
		},
		{
			secretKeyHex: "00296cfd1d88c9a38967099576cca92c2ffb1c9293fbac198a0bb83386df56d7",
			publicKeyHex: "158f7c42264beca75ea89489c328d9bbca1539b1b1e0a4dbd776643d0c1bd94a31f4d274fd2f0d9e97385e5334ce92a2",
		},
		{
			secretKeyHex: "29737bab11a7a60df9714f7b5b31c60273fff15f979764a7dd58e14b23470e56",
			publicKeyHex: "98ea685ab1c3b6021500a7e25c02ea82a6bcffea930a5ecbd5844b206e740260dc6284cc10c1323be109c28b75f38690",
		},
		{
			secretKeyHex: "416eb42cf78273eb45bae9b1395780cf8d90b2ebb1eae7888fd3eea044aca7d7",
			publicKeyHex: "87bad3c406efc9adc7aec55a01aedcc3c0d6e2b0b9d36501415ccb0309ac7989a69517442b20c1bb4f6c84d8b65ad0fb",
		},
		{
			secretKeyHex: "43275ccec25876e50bb67b19824a28df67a78f51cbc8d427d0c69ad19c2cb994",
			publicKeyHex: "8f37b249e91de490dd9ff625877140637976609b97140e13aa76e880053762f3c586129ca74171a6b9f8950e3858d2eb",
		},
		{
			secretKeyHex: "0c19430713a5ab50344333ef325a59de932da00dec8c8fa2eb6e8448171c69d3",
			publicKeyHex: "10d37ccd1a35dabf659d55a2814143356043267cbe37c232802a50a92246ca25ab1a62b72acbe8621a308833a5fd9af2",
		},
		{
			secretKeyHex: "661901051560977d339adba017205ed1590300a89f1a7e5f55a46c5a5146aed5",
			publicKeyHex: "003ace49fb8794199b6ecb6653290fb4dff5cde483fe48428bb1ec488e1f095b9500c247213d75c1c1b5c64a0bdd989b",
		},
		{
			secretKeyHex: "6530999e9b092cd6a868f049c45e39677fdfb57245c36ac84286510087f6a137",
			publicKeyHex: "17be5721e07331bb453558510f10f5fdc16bb5dbfa50dfd61731efbb82743881a88369694d5987d80f21478b133c4dec",
		},
		{
			secretKeyHex: "1ba7f8eb69b2c5cc750c9d65994e35447374978712cadae0865ce1d57b4e8399",
			publicKeyHex: "9175f960c2eda49be417dcc12da686ba799b275dc3446a60aad915f6f7ea9139ae06e10def75415e72c6fd3c4d3050e7",
		},
		{
			secretKeyHex: "273f5b9e234ee8f7c64bc0da917e4ebef1465be5c9f333348860fe76d67f8ba5",
			publicKeyHex: "9392b420e4a916bd9145d16004e34377529a95b79001fbfca311c48914a39cfd40cf45b4e4c101e831e8f22503b9cdd3",
		},
		{
			secretKeyHex: "39e31298f5a9887685849a36f3275c43c2bcdbfe78951840ea9999c3e0d2a247",
			publicKeyHex: "8f18513d6ac51febc63acb356d23178593524089a818f9d4a1490cedd7030e636867a315a8e2c2b63a9518a1f835a007",
		},
		{
			secretKeyHex: "53e030635a2720463c0d81a8a944022ae8299270bacca61e67ce61cabab2cf6e",
			publicKeyHex: "1746c79b95502b50ddfc4bdda1ad0e59d8784ff4f7cc5b1c602e3feabe8fcf12a5f14b2a15b369c2c93c96d5de9977ef",
		},
		{
			secretKeyHex: "5bf44880123eeb9fb906a171e49af2f4742fd6dd14380e62f8797ba7bf3d0c46",
			publicKeyHex: "0d0d71035b24f65620c52fe4a0afcbf9c9cae6d935e210dd690da548d6388f810902778d498ddd2103af3e07b9e90b8b",
		},
		{
			secretKeyHex: "050fbeb9e10ddef9eb0453884b13cfc7b917d5c8391cd42e8a7b87cc1cce6bdc",
			publicKeyHex: "880c07dfdf27e8ae05a286510f18b2ae312560ca54ec14833089dcea3b7132f9eedd865453b806bb9a76e7bf729c5384",
		},
		{
			secretKeyHex: "689b1e1b7c99aa4865be5c5bde640038c805105b293ac49d1ed3e57d3970e434",
			publicKeyHex: "17729a25a0df59730a391ef43860268497ae18d4196f92632cf08d0de28efebf7503c5eb77bcac8678b11640789c2cf9",
		},
		{
			secretKeyHex: "6755c73f60f6eede1f868612ec12f025ff4ffdb80c910c9633267eff8458d5ad",
			publicKeyHex: "0f2e9e8ddf16dd32120f55cce330ab69612852fa3401322d7baed956fdabdc315604aa3b3fa289b27ad5694985a8cf06",
		},
		{
			secretKeyHex: "5542ace97b8ee82e8add237f07f3d118e30283b85e233e75cad9511d738f3f58",
			publicKeyHex: "168fdd8ee67f7d33ce9aed94dfa8c6e61fd6a56625edbad23d16edefd535959b29aaedc9125418eb9c03a5c8c05ed4bf",
		},
		{
			secretKeyHex: "6e578eb7159f51e009258ac4547ea17cf1c21ca4a0297f4ba66fe905ac61d6af",
			publicKeyHex: "0d68087866b2c61b3b17d3070286b4207ffaa383eb953b395f3bdee3fbc67cb59bc9df820fe4016e18745231959e69c1",
		},
		{
			secretKeyHex: "4dd87fa6579823889067fbd9cb0fde68380ca9f84bb14fa40ea60f9ac0301711",
			publicKeyHex: "065e91758219d9928af26c6cf6d45f9246c00be096c170b6878d10b4d69c494b2a24315e0df97b8dcbe7836b79259dda",
		},
		{
			secretKeyHex: "5697c24cd2525b1647611bf85392618ce7585f327cbc9439e7011825fda6d887",
			publicKeyHex: "06f6e504766f0a2c8113fc2c72842c0caf4dab821fbea526f1dc5426aafc351913949fc3d5a253e88af5f63b8cb334d2",
		},
		{
			secretKeyHex: "465c9a492d240aa6d01c545cee86f2a515c3a45a8e5642323af6526fd092a595",
			publicKeyHex: "8d3e7ee2d400dba28a2d0f99a74634381112e641a470365fac3eb9235d153e80c54517fee51a8e3cba15fc08a0f5c1df",
		},
		{
			secretKeyHex: "1fbce36c48adfdead874dba965af6b7e36cf9f4184f44e8e09da947a78dc80e4",
			publicKeyHex: "94287d5cc784988d00ee898523ebd949a1b0bc3cdba32629b56f87cc4d14344ecc20f5b6bc2b25cd35b48cd2352fa017",
		},
		{
			secretKeyHex: "6628dab182e2147613c56684f217b7e81530d860e63b19d6297311118be88cd4",
			publicKeyHex: "8c309997e9f51e4e2df26372a59d2f557005820b59cd27686585fc86e5086ca3b7118a40173b4894dd2f3f476d71e45f",
		},
		{
			secretKeyHex: "35a0aa373d9ffed6b0cd54e6c98945ddd78be9c3f11ab88d317636526622ee67",
			publicKeyHex: "8ba3df1c152eff8a54297becbf4c3fb147ca7dff493a9e8faf389595536a877cffe621ff2c3dfc7e90119d3d7f92b34c",
		},
		{
			secretKeyHex: "2596ac714058286a8712c7e3f8e657950cfa5b620f8435e64674c2ba9620fff8",
			publicKeyHex: "0ebf55519e9d9f0692427c19a9b9dfd8a1bd4aa41c5605f111980f6c82872df3384ee47334d5b4a057449bb233612dea",
		},
		{
			secretKeyHex: "20f9b9a7d5770e2d007f965e690f490641d45747fef09e8a4f9588a11a3468c3",
			publicKeyHex: "001f5bba871503276ecebea4cca98f30ae11e4f4f5be6705b092f98ce3000d84392cecc90645dd57d16855726ff1356c",
		},
		{
			secretKeyHex: "37278c80a09d7abe8a68656efcea4bea04745943c87686d4c1121c351377c85d",
			publicKeyHex: "908ae7801d24fa9e7b73e2c85c6bf535965321429e20d6bec36af97cbf235f223cde3ec4c42d1706ca8adab2e46050c0",
		},
		{
			secretKeyHex: "59694c69a18b688a252d947d4d81ea66d85097cc0557c034037471a1944c836e",
			publicKeyHex: "08424e6d22262b386496a018471f29df3c2e027efe3d1752d1a2512d342a6c0b8eb52b7a349e6cfff1150fd09ce006e3",
		},
		{
			secretKeyHex: "6c1f452dd2e61a37600c6b670d143af615cea197e9999f1fe57624a5c5da6bee",
			publicKeyHex: "19f7bce8052170230e1c45251c68eaffb84396d471b451c4e16087477c9003b84a5ee7b5b8b310486f3ee7725fc77eae",
		},
		{
			secretKeyHex: "6eb587559a6a1cb7a1ad904e495aa99a6686a634289928171bf31c507a68dbc3",
			publicKeyHex: "8bdcdf8e5d53fe223e8bb77504f0021671a2a80c22d7cd46558b60b57f8880b916352977d3d38cc90fdbb8e4e07f46de",
		},
		{
			secretKeyHex: "5ed7112e6763b7c9a048e7570ec4b4136141300e3374fa72198509ed4d0f80c4",
			publicKeyHex: "155ef27234105d75f04538704fd4524ac4f0e9f9dcaa5286fa247e416305965c658463ea6dae1191254257190e1879b5",
		},
		{
			secretKeyHex: "388ce576e222a0adfd846660922504932640e506c5dc023f06f050cbc317c393",
			publicKeyHex: "023475b60141520fda45b01f20f0ce98cb47f3fa4f7243f8763c55689915346aad72154d8cf581ab50559c05b58e9ce3",
		},
		{
			secretKeyHex: "1cee519e3fa45870069ee3f7919896443dd3595b98000ce3eb842df5d593bcd1",
			publicKeyHex: "8cdd1560028d6e9c4018160183d143dee4081c2a75b00b6ab1c4095f6d9671e9855094fbbcb2258be3c4f993105f2f11",
		},
		{
			secretKeyHex: "3bf79edea9c970ce8ed511220fa86d34c209e141f4fe9e5928f0938cfdc70170",
			publicKeyHex: "9733a8dbdecc38dd37ed8bf83f1116f4a3c6fc44382fe5cadd6cb8c24f1c6ec348bc5f0920b2ee0f92a862345482073d",
		},
		{
			secretKeyHex: "269972701269eac95ab8a2e08ad123d901b4992229a933faeee8aba549cf6420",
			publicKeyHex: "160da6ff587052df9bb7654defccf9bc25dac325ce5938e7486502e00ab60ca3f973018c0a91db5df851babff0cf05a7",
		},
		{
			secretKeyHex: "01bcafd608e5c999563697c68c7b98f51ffd38a1610b48d32ed90789d6a48c8e",
			publicKeyHex: "04e1a4d118f8b1712990266cd937485e49b3f223033e480d924d41ff76c9e8a6d57c57418f773e5bc4fd9fba0893d4cb",
		},
		{
			secretKeyHex: "3a109d2699ec209b4fb3548b9af012421d7ff1ab63952b21060ffb5c52a5c66a",
			publicKeyHex: "0e5d52d2c45331250f80c426a55b37429f2caccddd550477534a45e5d0b2bd1f9e6fdc750cc20bc42656f308ab4b2c9f",
		},
		{
			secretKeyHex: "0134b62c8a463ca16363bd0ca804733b405399611c0e912df39a5a9a1af1210f",
			publicKeyHex: "94243b6b4af300c70b89b544b6892625ffdaeb59ef993084363497ed19bf5fbd76a95a3c1c1667f7432d6d0604e692c3",
		},
		{
			secretKeyHex: "1775dc37a30ed405ef794f5bc818b39d87a94c55e81eb04a6652205a6db46d7b",
			publicKeyHex: "88b573b34f36c0bf26c6d91e97fe87c109b0a25e9cb20fc778bf841d35f7be13d3023eff44823e394ca2471c25beacdd",
		},
		{
			secretKeyHex: "0bf7d83b409375e6d614f20261215092257323603cf7f5bbe47c85082d399976",
			publicKeyHex: "9578382c79ffa7bcbddcbf1b6da1b7d63ff941159eb9506019a2c4c0db2aeca9bf89f5b2d1fb2a20fc7fdfc2c7e38170",
		},
		{
			secretKeyHex: "5467201a04b95a25e200145daa10aea359956e0ef0674d0eafd81bb1ce6ee9dc",
			publicKeyHex: "04719ea0b11c80f72f4f90e9ae48c42d267e23417ca117eff0951be6c02277b332b264be793785b1384db3f554713491",
		},
		{
			secretKeyHex: "39ee9aba40854a2164243b1071f64d9b922d5b1a6214c88fa59763b3bb905f83",
			publicKeyHex: "0714db27fa6ed5b31a4311d0551bdde2420125ff59150ef9fa02dcc8160c19a22c8b6ac1a657aad0ce896b80405c675f",
		},
		{
			secretKeyHex: "4092e6e31e4354871835bbb8d49a163e5c1f5033aef781497274da9d2eed788b",
			publicKeyHex: "12970548f6cbf82df2b2a3ce083ca77a7ece25a815824766360c0c5232b67937c98fb80f1b0ffcc7c81606d57f017edc",
		},
		{
			secretKeyHex: "1a88fcb943375a1a2a5b4eeb307eed7662983e18a40075348715c9ad254d9c31",
			publicKeyHex: "1282593ccb55b4eaf36f780e3c7a4e94abf371c93aa9044a5e59a6b5b36f297abc2c0694bc37e3341055e26bcbc92fd6",
		},
		{
			secretKeyHex: "307afc079baf4cbfd74359c06d1b5da45ef3d573e315c59c9e2eec4ae3f77285",
			publicKeyHex: "04dc4b8ff0868da7a4db2d29f77b30ada024125fd70ae743eba4804c0511818b2257ed8a7ae1fcb217527ee50fe40fee",
		},
		{
			secretKeyHex: "31371e276a911f6ee7dd73f0afb025387c4f7ad1a5cfd84f85cd4168058bebc3",
			publicKeyHex: "18c189b0bea738c90770c3f9078405f1ce36c56a351eb4f56adee0b486992b69139ee132f5f2ec7d90068854827b4e90",
		},
		{
			secretKeyHex: "29d1c00090b04c59506e061cc715743027850105abbc713ed00134c11fc62e7b",
			publicKeyHex: "0012f5ddb0a5d076a192d7a9ff668fe615c12c4d2ce909ca9066ec2b8057699326ab27dc9056028ed812dfe8e52ae864",
		},
		{
			secretKeyHex: "47ae35de3a77210d178a6a0a2652505340629107218873827be032da5468368e",
			publicKeyHex: "17504bba19514de8d78b94a9a4a5c96ee700037885d87d0ac45c39da842ac353bec15f9c7b87b19b1f83e8668c91b53a",
		},
		{
			secretKeyHex: "068da3bfc03cc804bb5d1d52d5b8837633baf6ba993083a5920a260123518433",
			publicKeyHex: "00483624c3dccfae0d02fb59e1adb78ef6ac40c1c7b55171380b92c37cc0b878f19af2f911bdf8c16b49faca0369866c",
		},
		{
			secretKeyHex: "4615db51e7c8ff48d10400147d662618fd31f1b9409f6b7d023aa1c257078e6f",
			publicKeyHex: "900c5dad8be73ed2a9d321b72dff9eda58568f5ce990dac3e01d36a6724008b4266ee12776b625e36dc72f224c8b38df",
		},
		{
			secretKeyHex: "14a6a0e952216192e6da56408fadbeff7817269abdd7499d679ca63f07c346f2",
			publicKeyHex: "166b5a362c41d83f678de261015fdc12da78cbf9811d6ae10abb2c9897572014db19f72780a8b60d83d07ad48285866c",
		},
		{
			secretKeyHex: "3fde5906e234ee7d67a5c52663339e23b0e4a535a591b09143d8d21f0e629f02",
			publicKeyHex: "146b9df8f19449db62992c9b5376b89d387d82470134d3b450006c7ecbe620bc97df5b3eb22ba7795edd90f13027c2d4",
		},
		{
			secretKeyHex: "383e889a85b506c3d0506dbf7637073e7744b02596ffe2e5adcc698940de31ae",
			publicKeyHex: "971f554836bdade55811928ec12fcb6b75a28f87a3ad94ecd2abc22544ce8360186887dd1072f82530e92d9e5887d4dd",
		},
		{
			secretKeyHex: "1a6fa0a883bbdfdcbc352dde2ab06bd55e66aab32fecd4f5bf7ceb0361bc6fa6",
			publicKeyHex: "9587fb334fdfeded74a119692acd7b9677d7d36c459ff0e66d552bf6fa98262a6aca8181ae8e75e7db2dbc6902b1e759",
		},
		{
			secretKeyHex: "438043ad8827f9894b6cebbd4f89e3722bb60a3f6cda8b0b14475d5b94d80266",
			publicKeyHex: "831cc85a82a7dccc4d89b38023903d3e5cc29fe9488e953c481e2c74e9e37301f97409eb26d583ff6268c389f82d4cc6",
		},
		{
			secretKeyHex: "0226109657e8bc6c15d1030a45bea0f92a2b69dc640d31bf1374b2135d4e3648",
			publicKeyHex: "973aa29e8110e693413f2d7e405fc1b5787c5310b9f499b538d5df516d87e1afd2c96fb3093e8efa7759ec806a76c2c3",
		},
		{
			secretKeyHex: "2a877874fd42e7b7734ec88200325b722026e82038986502e91468479db71f2a",
			publicKeyHex: "8c9262c090218628cf28408a04d1caeb800e5dad78a2170de253b0cac97c6a0047d3161a141df5571345d349b1bfde07",
		},
		{
			secretKeyHex: "713d3ca8d7b75e2265ce520175c7740bf21d9842780afa8b18fcff60d4d6103d",
			publicKeyHex: "0d4c3acf0c4185febedaca11ccdb54b2e882c5ceb0fdf20af3ed312ef82a8c19bd4fee45ff1f814fba3d415910683db6",
		},
		{
			secretKeyHex: "1fca1fbe9954a4bd7d93252bfa181189b5447b7a0b4c6a038bd82690347ca86d",
			publicKeyHex: "01a7e4047b5513a22b45213b320887f39468697d4b99862c620fb237e946fe6a8589ae8b50b392c04f150f240d7ed815",
		},
		{
			secretKeyHex: "4a1e7275ab1cf080170ad70a9bb912f71bc4fd1a16cc1e75478c94409014bae3",
			publicKeyHex: "80bab9f49bd771f8d1b09768c3de2fabddb6dfe16818b712889d573d45e847d1ac544e2c23742660197081a8b7964619",
		},
		{
			secretKeyHex: "123a1425a11816ed2f178463d9ae086a4cee75487d0ebf8c5b0b9d6014536ac7",
			publicKeyHex: "172da861c2a438af0489a4ef203b0913818070bba7e4fe59f4c96a3d2f7bae6b66ccfa7b4c42603b0b264baf0919dd39",
		},
		{
			secretKeyHex: "3a7f6eea7df61b1b755fa9caa900fcff3e03de26e6b081f3e2393e6d3268b335",
			publicKeyHex: "02daca9b3c9ad96fd8fc9e893f52f7ab746e141e4268c8826ab21b12b25f49c538f664a80420e4d1553907e8163c53b7",
		},
		{
			secretKeyHex: "2240fb7571cb8a8f7f736eebe51ff4537a1be215e18fa0971d7c10d228921b97",
			publicKeyHex: "026c1feac94b5ecfe5facda422adf514c662c7d33d30b44396c6165de024784ec054a1ce7531f06e45738749f567de86",
		},
		{
			secretKeyHex: "48a13651f4142edb132e1f2f54649af2269111457ee1c1dd094f836903bc4e80",
			publicKeyHex: "971621db71e0d455137d2d91a069e63210dd7e74d6151bdeec1452f885f4ec79bf25fcada59057cf34155e0d8905c94c",
		},
		{
			secretKeyHex: "277cd03f1efe5320dd8925204ea812a1186e1863851d85eab7b14fba4227173b",
			publicKeyHex: "93c91b79716c1152e7783efbae9cd6a6dfe1d8caf5019cac47fe8f7002cdf3ef702732f73465b88a5eb9da7acc525a61",
		},
		{
			secretKeyHex: "1a9b66ab7083588a9dee54a3e43ed9b6892e27b18ee0da4fd647037ac2ccecb1",
			publicKeyHex: "96d3ffdc0b1a51cc069f8959b60190504d5f583fbeae9ac22de1ccaabeb6cd1fb0f1298ebdcf977414149fd1fd32d1d0",
		},
		{
			secretKeyHex: "0086aee367ad62ddc9331fcf67f9e138fbd5420cb73f71810790a76f58d2767e",
			publicKeyHex: "8c65fffa7ba8df70597eda77e33bdfb4da2d42d3822b3f2188529e0e4482d5aa406d137867c693ed167b44faf8e6fd4e",
		},
		{
			secretKeyHex: "6434238c13f107ae865eb42f5022726dfd9f0de74bfd70d780cade1b8e082424",
			publicKeyHex: "10cebee23ab620f8b27d59a1289d4df9b3c4ff76839d979354bf4f9e671155ee89a6a94cb03f925eba0da0676600be9b",
		},
		{
			secretKeyHex: "380c641ad54bd2e5d20e5da9075e6d336e02ad04e0e5d8a5a1f3ddb5f26c3ee1",
			publicKeyHex: "96b0fba81d153a1ef9d9498809287f9df0392ee7d15bb5f482f9e508c8549b684e2fc8b1b5ec87cfb1f294c30b28b1b8",
		},
		{
			secretKeyHex: "71b752380d1f9aa8f872f978a0a9f9948b749a0403df2f8dc69e32996c6d29ba",
			publicKeyHex: "061b810a9dffab1bafb04430a99587512a698a555b1afb1bf5db2774425ceacb34ceedaf7d35c812f891f26aba926b9f",
		},
		{
			secretKeyHex: "357975036260781d8dc6a4e44d54d3f6867aac2ba7d3ef4e53d28339e2d29de9",
			publicKeyHex: "06d67db2af39efb98eb9dd8777e5041406b8c42ed136d42951af314f87a127630c0f21ae114f4a1f78884c951fc4248a",
		},
		{
			secretKeyHex: "6056d5797da2ec712374047d22238300adfd84b690767cf7f719c99fe50cf832",
			publicKeyHex: "08b34a619e09bdd13580de3c96b3b028d8dfd5beed34a7b6cf3f00ac0c89018859ffb5122e4899b1375f256ed91d66be",
		},
		{
			secretKeyHex: "620e39edb10661bea99141695ddcc41490f7615fcc695b9c37713e8de8e54374",
			publicKeyHex: "96217b269dc6216e74e95b1d00fe65154b8ecab1c956c2df776701dc84dda4315c85bf02b78ec072b7d5737ba0d540ac",
		},
		{
			secretKeyHex: "041b44f81c8db1e686d7699275cb012b3beba53b2915a9eec62ab2584bc877aa",
			publicKeyHex: "88128e15d43f9dc711ab795b150ef978aaa17e31ceb336985fc9c9fa99871ca38a853fb425f12cf472d915fbde609f65",
		},
		{
			secretKeyHex: "10f5237675d04d0517c97e60c9706606bfd7e4bf7e4646284cd7b04d2c9694a0",
			publicKeyHex: "07a39dc0ae090e49d9bfa36d1aa9b27ec9a133db00947d45a756e948823ac54a1db8d64910f9d59a148dcfcea27ab6da",
		},
		{
			secretKeyHex: "6b2d3a50d4f0fe5db8dcf4d35cf2528c3ccfc79abd0649b8a49c4638387faea3",
			publicKeyHex: "87a1e34cfeb145bced82e56015a9ff4416b2c5fe92ef4143caf7b3ea02f1da2a53c2cbaad1a81ab2c0a7f224a7a47419",
		},
		{
			secretKeyHex: "1f7440bddb15c6805ff02f6f21e8044647e5f57c95558d0c98c7d34d5ed9a585",
			publicKeyHex: "850d40d0fba0ef99d97c1d00978240ebe076db2674aa53c8a43db62be520d70e67f978d8c41df5c0133ea54906acfba3",
		},
		{
			secretKeyHex: "01313ede858bdd6a4dbed2e7de66747dd761bfe5fc7322be9da3ed9a6d283e62",
			publicKeyHex: "995767792f6d040422860f4ff1fcfad892b18f7f40f06e36bbd82b53cb5cec2dd8741c93484c1529df1d8f3e0025ccb1",
		},
		{
			secretKeyHex: "58eb7ae3a7ec5149c616bffea5dec49ef12666a8093dca6dc6aa1ac3f575fea4",
			publicKeyHex: "0681001d631bc630ba05d2837593d83912b258b64c9e3798e57186642096e2a3063c5931e17657c70296e2a08548205e",
		},
		{
			secretKeyHex: "5e6ea412ab7fcb72e69960fdc96610408741b3e74d8cdc171755bd7d556cb696",
			publicKeyHex: "18f07ebd7ffaf057f09e7e250350517d0ecf11d5e6be4785f1c616c8673d28269aa0f7e2d1304875425e038c0401ed50",
		},
		{
			secretKeyHex: "6536e8a1aefed0177c2d19057190d7e7e781e264abeba1a5646df5375c622f60",
			publicKeyHex: "93bc96dd54fa7111bf68b1683f60d62a308f8830a58610de9bc22340384597058a599b23f211882200229dcafee8d744",
		},
		{
			secretKeyHex: "2efc0793be0ca38f4ff17ef8c9568d1621069f797e0912157bf63f026d507934",
			publicKeyHex: "9508d3de1ee4c058b54c44c271b83b6208717a9a7ffcf6786e61563e1a9981880ce9821b60f0303fed0b844c2a6245a6",
		},
		{
			secretKeyHex: "3a384777da358b36ba6855ac3ba36aceadc7498a919530b9dc256992e1066956",
			publicKeyHex: "94acea98641f16194d2b3ce8c15c1ac32fbe690bc5dc89817cb198ab454ca16d8e121ddd1ca9e70c1e23227c3010a176",
		},
		{
			secretKeyHex: "5b7721483d9157b1b71e37f255ab53add9ac0c664c38016f0884e24d73f7f389",
			publicKeyHex: "135c98567ac8462d7ebc2ada6ffb2d1b9ba60200488cfa8102d395ea0e9475edf42e0c7a18c0735f35dbc2cb4b1c1cb5",
		},
		{
			secretKeyHex: "5c7eaffb82a5e17dbf3e636b4b31e29c68003423c8ac845abdfaa3cfaf3c9242",
			publicKeyHex: "853d1f503db134a216af322ca293ace5bd4a059e9966d09f164790a9f6375b9b1f8d46b06ba9abf0b49a8c4c3a5d3b16",
		},
		{
			secretKeyHex: "4d4a75718a7037fb84ca44e003464a1258eec743386524114fc80db445770227",
			publicKeyHex: "14d042f2fa366c5f2ed20a42c1e5a574d2b5722e2bf2417eaa20afe8ccfc47682f9cd30858f70c67d32c32596e1ba4ee",
		},
		{
			secretKeyHex: "50b045ca4ac739ff35808bf123d3c7e469adf92cf6a682b129e5118189020946",
			publicKeyHex: "98de5b12a58bec6fbfcb1146e72267c7685d12d2c1831bec87f1733ae125ebd77f4b1ba8c8709d25785dcb6657ce5ff3",
		},
		{
			secretKeyHex: "63aa7c4b94e4eff3998e54aa76b7b2dcdb6f40e515f7e1e275debc01d9c3326a",
			publicKeyHex: "0a04c4cf179c2b6edf3c850a37130721a21e1f458d12c9ca1e0012c76c5cb0cbddf592b03f306f428891db0e4bc634cb",
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)

			skBytes, err := hex.DecodeString(tt.secretKeyHex)
			is.NoErr(err)

			sk := bls.DeserializeSecretKey(skBytes)

			pkExpected, err := hex.DecodeString(tt.publicKeyHex)
			is.NoErr(err)

			pk := sk.PublicKey()
			is.Equal(pk.Serialize(true), pkExpected)
		})
	}
}
