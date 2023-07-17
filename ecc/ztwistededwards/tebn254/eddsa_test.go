/*
 * Copyright © 2022 ZkBNB Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package tebn254

import (
	"bytes"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func TestA(t *testing.T) {
	// f82eb24bdb710bef0e04777da4b9a087adf8cf68bf500825dadd8c1c8fb241ac
	sk, err := GenerateEddsaPrivateKey("213123")
	if err != nil {
		//return err.Error()
	}
	var buf bytes.Buffer
	buf.Write(sk.PublicKey.Bytes())

	res := hex.EncodeToString(buf.Bytes())

	log.Println("res", res)
}

func TestB(t *testing.T) {

	as := assert.New(t)
	// read seed

	sk, err := GenerateEddsaPrivateKey("213123")
	if err != nil {
		//return err.Error()
	}

	signature, err := sk.Sign([]byte("fhbdgrsffds"), mimc.NewMiMC())
	if err != nil {
		//return err.Error()
	}
	res := hex.EncodeToString(signature)

	log.Println("res", res)

	as.Equal(res, "a6259e47658f3fca4ff7016d8625f596f5b9b16fe4f794f08d264c7940068516057103dd9996caa80f0e3860f69f3537d091e5a3ee44df309e8dfec193fe87e9")
}

func TestGenerateEddsaPrivateKey(t *testing.T) {
	sk, err := GenerateEddsaPrivateKey("testeeetgcxsaahsadcastzxbmjhgmgjhcarwewfseasdasdavacsafaewe")
	if err != nil {
		t.Fatal(err)
	}
	log.Println(new(big.Int).SetBytes(sk.Bytes()[32:64]).BitLen())
	hFunc := mimc.NewMiMC()
	hFunc.Write([]byte("sher"))
	msg := hFunc.Sum(nil)
	hFunc.Reset()
	signMsg, err := sk.Sign(msg, hFunc)
	if err != nil {
		t.Fatal(err)
	}
	hFunc.Reset()
	isValid, err := sk.PublicKey.Verify(signMsg, msg, hFunc)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(isValid)
}
