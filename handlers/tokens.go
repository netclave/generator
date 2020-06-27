/*
 * Copyright @ 2020 - present Blackvisor Ltd.
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
 */

package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/netclave/common/jsonutils"
	"github.com/netclave/generator/component"
)

func getTokensForWallet(walletID string) (map[string]string, error) {
	dataStorage := component.CreateDataStorage()

	tokenKeys, err := dataStorage.GetKeys(component.TOKENS, walletID+"/*")

	if err != nil {
		return nil, err
	}

	tokens := map[string]string{}
	for _, tokenKey := range tokenKeys {
		tokenKeySplit := strings.Split(tokenKey, "/")
		identityProviderID := tokenKeySplit[2]
		token := tokenKeySplit[3]

		tokens[identityProviderID] = token
	}

	return tokens, nil
}

func ListTokensForWallet(w http.ResponseWriter, r *http.Request) {
	request, err := jsonutils.ParseRequest(r)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot parse request", err.Error(), w)
		return
	}

	cryptoStorage := component.CreateCryptoStorage()

	_, walletID, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		fmt.Println(err)
		jsonutils.EncodeResponse("400", "Cannot verify or decrypt request", err, w)
		return
	}

	identityProviderTokenMap, err := getTokensForWallet(walletID)

	if err != nil {
		fmt.Println(err)
		jsonutils.EncodeResponse("400", "Cannot get tokens", err, w)
		return
	}

	generatorID := component.ComponentIdentificatorID
	generatorPriveteKey := component.ComponentPrivateKey
	generatorPublicKey := component.ComponentPublicKey

	walletPublicKey, err := cryptoStorage.RetrievePublicKey(walletID)

	if err != nil {
		fmt.Println(err)
		jsonutils.EncodeResponse("400", "Can not get public key", err, w)
		return
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(identityProviderTokenMap, generatorID,
		generatorPriveteKey, generatorPublicKey, walletPublicKey, false)

	if err != nil {
		log.Println(err)
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err, w)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w)
}
