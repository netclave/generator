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
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/netclave/common/jsonutils"
	"github.com/netclave/common/networkutils"
	"github.com/netclave/common/utils"
	"github.com/netclave/generator/component"
	"github.com/netclave/generator/config"
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

func saveRemoteIP(ip string, id string) error {
	dataStorage := component.CreateDataStorage()

	return dataStorage.SetKey(component.IP_TABLE, id+"/"+ip, ip, config.TokenTTL*time.Second)
}

func ListTokensForWallet(w http.ResponseWriter, r *http.Request) {
	request, err := jsonutils.ParseRequest(r)

	fail2banDataStorage := component.CreateFail2BanDataStorage()

	fail2BanData := &utils.Fail2BanData{
		DataStorage:   fail2banDataStorage,
		RemoteAddress: networkutils.GetRemoteAddress(r),
		TTL:           config.Fail2BanTTL,
	}

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot parse request", err.Error(), w, fail2BanData)
		return
	}

	cryptoStorage := component.CreateCryptoStorage()

	_, walletID, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		fmt.Println(err)
		jsonutils.EncodeResponse("400", "Cannot verify or decrypt request", err, w, fail2BanData)
		return
	}

	if config.SameNetwork == false {
		ipPort := networkutils.GetRemoteAddress(r)
		ipPortSplit := strings.Split(ipPort, ":")

		ip := ""

		for i := 0; i < len(ipPortSplit)-1; i++ {
			ip = ip + ipPortSplit[i]

			if i < len(ipPortSplit)-2 {
				ip = ip + ":"
			}
		}

		log.Println("Storing ip: " + ip)

		err := saveRemoteIP(ip, walletID)

		if err != nil {
			fmt.Println(err)
			jsonutils.EncodeResponse("400", "Can not store remote IP", err, w, fail2BanData)
			return
		}
	}

	identityProviderTokenMap, err := getTokensForWallet(walletID)

	if err != nil {
		fmt.Println(err)
		jsonutils.EncodeResponse("400", "Cannot get tokens", err, w, fail2BanData)
		return
	}

	generatorID := component.ComponentIdentificatorID
	generatorPriveteKey := component.ComponentPrivateKey
	generatorPublicKey := component.ComponentPublicKey

	walletPublicKey, err := cryptoStorage.RetrievePublicKey(walletID)

	if err != nil {
		fmt.Println(err)
		jsonutils.EncodeResponse("400", "Can not get public key", err, w, fail2BanData)
		return
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(identityProviderTokenMap, generatorID,
		generatorPriveteKey, generatorPublicKey, walletPublicKey, false)

	if err != nil {
		log.Println(err)
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err, w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}

type WalletPendingRequestForm struct {
	QRcode  string `json:"qrCode"`
	Comment string `json:"comment"`
}

type WalletPendingRequest struct {
	QRcode  string
	Comment string
}

func AddWalletPendingRequest(w http.ResponseWriter, r *http.Request) {
	fail2banDataStorage := component.CreateFail2BanDataStorage()

	fail2BanData := &utils.Fail2BanData{
		DataStorage:   fail2banDataStorage,
		RemoteAddress: networkutils.GetRemoteAddress(r),
		TTL:           config.Fail2BanTTL,
	}

	if config.SameNetwork == true {
		jsonutils.EncodeResponse("400", "Not activated", "Not activated", w, fail2BanData)
		return
	}

	request, err := jsonutils.ParseRequest(r)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot parse request", err.Error(), w, fail2BanData)
		return
	}

	cryptoStorage := component.CreateCryptoStorage()

	decryptedRequest, clientID, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot verify or decrypt request", err.Error(), w, fail2BanData)
		return
	}

	publicKey, err := cryptoStorage.RetrievePublicKey(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	qRRequestForm := &WalletPendingRequestForm{}

	err = json.Unmarshal([]byte(decryptedRequest), qRRequestForm)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot unmarshal request", err.Error(), w, fail2BanData)
		return
	}

	h := sha1.New()

	h.Write([]byte(qRRequestForm.QRcode + "/" + qRRequestForm.Comment))

	bs := h.Sum(nil)

	s := fmt.Sprintf("%x", bs)

	dataStorage := component.CreateDataStorage()

	err = dataStorage.AddToMap(component.PENDING_QR_CODES, "", s, &WalletPendingRequest{
		Comment: qRRequestForm.Comment,
		QRcode:  qRRequestForm.QRcode,
	})

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot add QR code to queue", err.Error(), w, fail2BanData)
		return
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse("Wallet QR code added to pending", component.ComponentIdentificatorID,
		component.ComponentPrivateKey, component.ComponentPublicKey, publicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}
