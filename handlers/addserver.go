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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	api "github.com/netclave/apis/generator/api"
	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/httputils"
	"github.com/netclave/common/jsonutils"
	"github.com/netclave/generator/component"
	"github.com/netclave/generator/flashkey"
)

var AccessDeniedMessage = "Access denied."

type GrpcServer struct {
}

type AddWalletForm struct {
	WalletID           string `json:"walletID"`
	IdentityProviderID string `json:"identityProviderID"`
	Signature          string `json:"signature"`
}

func (s *GrpcServer) AddIdentityProvider(ctx context.Context, in *api.AddIdentityProviderRequest) (*api.AddIdentityProviderResponse, error) {
	status, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.AddIdentityProviderResponse{}, err
	}

	if !status {
		return &api.AddIdentityProviderResponse{}, errors.New(AccessDeniedMessage)
	}

	identityProviderURL := in.IdentityProviderUrl
	emailOrPhone := in.EmailOrPhone

	cryptoStorage := component.CreateCryptoStorage()

	publicKey, remoteIdentityProviderID, err := httputils.RemoteGetPublicKey(identityProviderURL, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	err = cryptoStorage.StoreTempPublicKey(remoteIdentityProviderID, publicKey)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	fullURL := identityProviderURL + "/registerPublicKey"

	data := map[string]string{}

	data["identificator"] = emailOrPhone

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	request, err := jsonutils.SignAndEncryptResponse(data, identityProviderID,
		privateKeyPEM, publicKeyPEM, publicKey, true)

	response, remoteIdentityProviderID, _, err := httputils.MakePostRequest(fullURL, request, true, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	return &api.AddIdentityProviderResponse{
		Response:            response,
		IdentityProviderId:  remoteIdentityProviderID,
		IdentityProviderUrl: identityProviderURL,
	}, nil
}

func (s *GrpcServer) ListIdentityProviders(ctx context.Context, in *api.ListIdentityProvidersRequest) (*api.ListIdentityProvidersResponse, error) {
	status, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.ListIdentityProvidersResponse{}, err
	}

	if !status {
		return &api.ListIdentityProvidersResponse{}, errors.New(AccessDeniedMessage)
	}

	cryptoStorage := component.CreateCryptoStorage()

	identityProvidersMap, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.GeneratorIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ListIdentityProvidersResponse{}, err
	}

	identityProviders := []*api.IdentityProvider{}

	for _, identityProvider := range identityProvidersMap {
		identityProviderObj := &api.IdentityProvider{
			Url: identityProvider.IdentificatorURL,
			Id:  identityProvider.IdentificatorID,
		}

		identityProviders = append(identityProviders, identityProviderObj)
	}

	return &api.ListIdentityProvidersResponse{
		IdentityProviders: identityProviders,
	}, nil
}

func (s *GrpcServer) ConfirmIdentityProvider(ctx context.Context, in *api.ConfirmIdentityProviderRequest) (*api.ConfirmIdentityProviderResponse, error) {
	status, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	if !status {
		return &api.ConfirmIdentityProviderResponse{}, errors.New(AccessDeniedMessage)
	}

	identityProviderURL := in.IdentityProviderUrl
	identityProviderID := in.IdentityProviderId
	code := in.ConfirmationCode

	cryptoStorage := component.CreateCryptoStorage()

	publicKey, err := cryptoStorage.RetrieveTempPublicKey(identityProviderID)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	fullURL := identityProviderURL + "/confirmPublicKey"

	data := map[string]string{}

	data["confirmationCode"] = code
	data["identificatorType"] = cryptoutils.IDENTIFICATOR_TYPE_GENERATOR

	generatorID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	request, err := jsonutils.SignAndEncryptResponse(data, generatorID,
		privateKeyPEM, publicKeyPEM, publicKey, false)

	response, _, _, err := httputils.MakePostRequest(fullURL, request, true, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	log.Println("Response: " + response)

	if response != "\"Identificator confirmed\"" {
		log.Println("Do not add identificators")
		return &api.ConfirmIdentityProviderResponse{
			Response: response,
		}, nil
	}

	_, err = cryptoStorage.DeleteTempPublicKey(identityProviderID)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.StorePublicKey(identityProviderID, publicKey)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	identificatorObject := &cryptoutils.Identificator{}
	identificatorObject.IdentificatorID = identityProviderID
	identificatorObject.IdentificatorType = cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER
	identificatorObject.IdentificatorURL = identityProviderURL

	err = cryptoStorage.AddIdentificator(identificatorObject)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(identificatorObject, component.GeneratorIdentificator)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(component.GeneratorIdentificator, identificatorObject)

	if err != nil {
		log.Println(err.Error())
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	return &api.ConfirmIdentityProviderResponse{
		Response: response,
	}, nil
}

func (s *GrpcServer) ListNonRegisteredDevices(ctx context.Context, in *api.ListNonRegisteredDevicesRequest) (*api.ListNonRegisteredDevicesResponse, error) {
	validFlashKeyStatus, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		log.Println(err.Error())
		return &api.ListNonRegisteredDevicesResponse{}, err
	}

	anyFlashKeyStatus, err := flashkey.AnyRegisteredFlashkeys()

	if err != nil {
		log.Println(err.Error())
		return &api.ListNonRegisteredDevicesResponse{}, err
	}

	if anyFlashKeyStatus && !validFlashKeyStatus {
		return &api.ListNonRegisteredDevicesResponse{}, errors.New(AccessDeniedMessage)
	}

	fmt.Println("Listing all devices")

	devices, err := flashkey.ListNonRegisteredDevices()
	if err != nil {
		return nil, err
	}

	return &api.ListNonRegisteredDevicesResponse{
		Devices: devices,
	}, nil
}

func (s *GrpcServer) RegisterDevice(ctx context.Context, in *api.RegisterDeviceRequest) (*api.RegisterDeviceResponse, error) {
	validFlashKeyStatus, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.RegisterDeviceResponse{}, err
	}

	anyFlashKeyStatus, err := flashkey.AnyRegisteredFlashkeys()

	if err != nil {
		return &api.RegisterDeviceResponse{}, err
	}

	if anyFlashKeyStatus && !validFlashKeyStatus {
		return &api.RegisterDeviceResponse{}, errors.New(AccessDeniedMessage)
	}

	err = flashkey.RegisterDevice(in.DevID)
	if err != nil {
		return nil, err
	}

	return &api.RegisterDeviceResponse{}, nil
}

func SendQRCode(QR string) error {
	log.Println(QR)

	decodedQR, err := base64.StdEncoding.DecodeString(QR)
	if err != nil {
		log.Println("Error: " + err.Error())
		return err
	}

	objectQR := &AddWalletForm{}
	json.Unmarshal(decodedQR, objectQR)

	cryptoStorage := component.CreateCryptoStorage()

	identityProvidersMap, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.GeneratorIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)
	if err != nil {
		log.Println("Error: " + err.Error())
		return err
	}

	for _, identityProvider := range identityProvidersMap {
		if identityProvider.IdentificatorID != objectQR.IdentityProviderID {
			continue
		}

		url := identityProvider.IdentificatorURL

		identityProviderPublicKey, err := cryptoStorage.RetrievePublicKey(identityProvider.IdentificatorID)
		if err != nil {
			log.Println("Error: " + err.Error())
			return err
		}

		fullURL := url + "/exchangePublicKeys"

		data := map[string]string{}
		data["walletID"] = objectQR.WalletID
		data["IdentityProviderID"] = objectQR.IdentityProviderID
		data["signature"] = objectQR.Signature

		raspberryID := component.ComponentIdentificatorID
		privateKeyPEM := component.ComponentPrivateKey
		publicKeyPEM := component.ComponentPublicKey

		request, err := jsonutils.SignAndEncryptResponse(data, raspberryID,
			privateKeyPEM, publicKeyPEM, identityProviderPublicKey, false)

		if err != nil {
			log.Println("Error: " + err.Error())
			return err
		}

		_, _, _, err = httputils.MakePostRequest(fullURL, request, true, component.ComponentPrivateKey, cryptoStorage)

		if err != nil {
			log.Println("Error: " + err.Error())
			return err
		}

		return nil
	}

	return errors.New("Couldn't find IdentityProvider")
}

func (s *GrpcServer) AddWallet(ctx context.Context, in *api.AddWalletRequest) (*api.AddWalletResponse, error) {
	status, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.AddWalletResponse{}, err
	}

	if !status {
		return &api.AddWalletResponse{}, errors.New(AccessDeniedMessage)
	}

	QR := in.QRcode

	err = SendQRCode(QR)

	return &api.AddWalletResponse{}, err
}

func (s *GrpcServer) ListWallets(ctx context.Context, in *api.ListWalletsRequest) (*api.ListWalletsResponse, error) {
	status, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.ListWalletsResponse{}, err
	}

	if !status {
		return &api.ListWalletsResponse{}, errors.New(AccessDeniedMessage)
	}

	cryptoStorage := component.CreateCryptoStorage()

	wallets, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.GeneratorIdentificator, cryptoutils.IDENTIFICATOR_TYPE_WALLET)

	if err != nil {
		return &api.ListWalletsResponse{}, err
	}

	result := []string{}

	for _, wallet := range wallets {
		result = append(result, wallet.IdentificatorID)
	}

	return &api.ListWalletsResponse{
		Wallets: result,
	}, err
}

func (s *GrpcServer) ApproveWalletSharingRequest(ctx context.Context, in *api.ApproveWalletSharingRequestRequest) (*api.ApproveWalletSharingRequestResponse, error) {
	status, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.ApproveWalletSharingRequestResponse{}, err
	}

	if !status {
		return &api.ApproveWalletSharingRequestResponse{}, errors.New(AccessDeniedMessage)
	}

	dataStorage := component.CreateDataStorage()

	request := &WalletPendingRequest{}

	err = dataStorage.GetFromMap(component.PENDING_QR_CODES, "", in.RequestHash, request)

	if err != nil {
		return &api.ApproveWalletSharingRequestResponse{}, err
	}

	err = SendQRCode(request.QRcode)

	if err != nil {
		return &api.ApproveWalletSharingRequestResponse{}, err
	}

	err = dataStorage.DelFromMap(component.PENDING_QR_CODES, "", in.RequestHash)

	if err != nil {
		return &api.ApproveWalletSharingRequestResponse{}, err
	}

	return &api.ApproveWalletSharingRequestResponse{}, nil
}

func (s *GrpcServer) DeleteWalletSharingRequest(ctx context.Context, in *api.DeleteWalletSharingRequestRequest) (*api.DeleteWalletSharingRequestResponse, error) {
	status, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.DeleteWalletSharingRequestResponse{}, err
	}

	if !status {
		return &api.DeleteWalletSharingRequestResponse{}, errors.New(AccessDeniedMessage)
	}

	dataStorage := component.CreateDataStorage()

	err = dataStorage.DelFromMap(component.PENDING_QR_CODES, "", in.RequestHash)

	return &api.DeleteWalletSharingRequestResponse{}, err
}

func (s *GrpcServer) GetWalletSharingRequests(ctx context.Context, in *api.GetWalletSharingRequestsRequest) (*api.GetWalletSharingRequestsResponse, error) {
	status, err := flashkey.CheckForValidFlashkey()

	if err != nil {
		return &api.GetWalletSharingRequestsResponse{}, err
	}

	if !status {
		return &api.GetWalletSharingRequestsResponse{}, errors.New(AccessDeniedMessage)
	}

	response := &api.GetWalletSharingRequestsResponse{}

	dataStorage := component.CreateDataStorage()

	var requests map[string]*WalletPendingRequest

	err = dataStorage.GetMap(component.PENDING_QR_CODES, "", &requests)

	if err != nil {
		return response, err
	}

	for hash, walletRequest := range requests {
		log.Println(hash)
		sharingRequest := &api.WalletSharingRequest{
			Comment:     walletRequest.Comment,
			QRcode:      walletRequest.QRcode,
			RequestHash: hash,
		}

		response.Requests = append(response.Requests, sharingRequest)
	}

	return response, nil
}
