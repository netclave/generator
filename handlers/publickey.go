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
	"net/http"

	"github.com/netclave/common/networkutils"

	"github.com/netclave/common/jsonutils"
	"github.com/netclave/common/utils"
	"github.com/netclave/generator/component"
	"github.com/netclave/generator/config"
)

type GetPublicKeyForm struct {
}

func GetPublicKey(w http.ResponseWriter, r *http.Request) {
	generatorID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	fail2banDataStorage := component.CreateFail2BanDataStorage()

	fail2BanData := &utils.Fail2BanData{
		DataStorage:   fail2banDataStorage,
		RemoteAddress: networkutils.GetRemoteAddress(r),
		TTL:           config.Fail2BanTTL,
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse("", generatorID,
		privateKeyPEM, publicKeyPEM, "", true)

	if err != nil {
		jsonutils.EncodeResponse("400", "Can not sign response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}
