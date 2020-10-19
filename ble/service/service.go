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

package service

import (
	"context"
	"encoding/base64"
	"log"
	"time"

	"github.com/netclave/common/cryptoutils"

	"github.com/golang/protobuf/proto"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"google.golang.org/protobuf/runtime/protoiface"
	api "github.com/netclave/apis/generator/api"
	gatt "github.com/netclave/bluetooth-library"
	"github.com/netclave/generator/config"
	"github.com/netclave/generator/handlers"
)

var (
	attrGAPUUID = gatt.UUID16(0x1800)

	attrDeviceNameUUID        = gatt.UUID16(0x2A00)
	attrAppearanceUUID        = gatt.UUID16(0x2A01)
	attrPeripheralPrivacyUUID = gatt.UUID16(0x2A02)
	attrReconnectionAddrUUID  = gatt.UUID16(0x2A03)
	attrPeferredParamsUUID    = gatt.UUID16(0x2A04)

	attrGATTUUID           = gatt.UUID16(0x1801)
	attrServiceChangedUUID = gatt.UUID16(0x2A05)

	descCharUserDescUUID = gatt.UUID16(0x2901)
)

var gapCharAppearanceGenericComputer = []byte{0x00, 0x80}

// NewGapService : default GAP service
// NOTE: OS X provides GAP and GATT services, and they can't be customized.
// For Linux/Embedded, however, this is something we want to fully control.
func NewGapService(name string) *gatt.Service {
	s := gatt.NewService(attrGAPUUID)
	s.AddCharacteristic(attrDeviceNameUUID).SetValue([]byte(name))
	s.AddCharacteristic(attrAppearanceUUID).SetValue(gapCharAppearanceGenericComputer)
	s.AddCharacteristic(attrPeripheralPrivacyUUID).SetValue([]byte{0x00})
	s.AddCharacteristic(attrReconnectionAddrUUID).SetValue([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	s.AddCharacteristic(attrPeferredParamsUUID).SetValue([]byte{0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0xd0, 0x07})
	return s
}

// NewGattService : default GATT service
func NewGattService() *gatt.Service {
	s := gatt.NewService(attrGATTUUID)
	s.AddCharacteristic(attrServiceChangedUUID).HandleNotifyFunc(
		func(r gatt.Request, n gatt.Notifier) {
			go func() {
				log.Printf("Notify client when the services are changed")
			}()
		})
	return s
}

// NewGeneratorAdminService : relays requests to GeneratorAdmin via grps and sends responses back as notifications
func NewGeneratorAdminService(generatorAdminServer handlers.GrpcServer, configuration map[string]string) *gatt.Service {
	s := gatt.NewService(gatt.MustParseUUID(configuration[config.ServiceUUID]))
	ba := NewBleAdapter(s, generatorAdminServer, configuration)
	ba.addCharacteristics()
	return ba.GattService
}

// BleAdapter :
type BleAdapter struct {
	GattService          *gatt.Service
	GeneratorAdminServer handlers.GrpcServer
	Configuration        map[string]string
}

// NewBleAdapter :
func NewBleAdapter(GattService *gatt.Service, generatorAdminServer handlers.GrpcServer, configuration map[string]string) *BleAdapter {
	ba := new(BleAdapter)
	ba.GattService = GattService
	ba.GeneratorAdminServer = generatorAdminServer
	ba.Configuration = configuration

	return ba
}

func (ba BleAdapter) addCharacteristics() {

	endpoints := []GeneratorServiceEndpoint{
		GetEndPointsDescriptors{
			GeneratorServiceEndpointCommon{
				Name:                 "getEndPointsDescriptors",
				WriteHandlerUUID:     ba.Configuration[config.GetEndPointsDescriptorsWriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.GetEndPointsDescriptorsNotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		ListIdentityProviders{
			GeneratorServiceEndpointCommon{
				Name:                 config.ListIdentityProviders,
				WriteHandlerUUID:     ba.Configuration[config.ListIdentityProviders+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.ListIdentityProviders+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		AddIdentityProvider{
			GeneratorServiceEndpointCommon{
				Name:                 config.AddIdentityProvider,
				WriteHandlerUUID:     ba.Configuration[config.AddIdentityProvider+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.AddIdentityProvider+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		ConfirmIdentityProvider{
			GeneratorServiceEndpointCommon{
				Name:                 config.ConfirmIdentityProvider,
				WriteHandlerUUID:     ba.Configuration[config.ConfirmIdentityProvider+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.ConfirmIdentityProvider+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		RegisterDevice{
			GeneratorServiceEndpointCommon{
				Name:                 config.RegisterDevice,
				WriteHandlerUUID:     ba.Configuration[config.RegisterDevice+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.RegisterDevice+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		ListNonRegisteredDevices{
			GeneratorServiceEndpointCommon{
				Name:                 config.ListNonRegisteredDevices,
				WriteHandlerUUID:     ba.Configuration[config.ListNonRegisteredDevices+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.ListNonRegisteredDevices+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		AddWallet{
			GeneratorServiceEndpointCommon{
				Name:                 config.AddWallet,
				WriteHandlerUUID:     ba.Configuration[config.AddWallet+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.AddWallet+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		ListWallets{
			GeneratorServiceEndpointCommon{
				Name:                 config.ListWallets,
				WriteHandlerUUID:     ba.Configuration[config.ListWallets+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.ListWallets+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		GetWalletSharingRequests{
			GeneratorServiceEndpointCommon{
				Name:                 config.GetWalletSharingRequests,
				WriteHandlerUUID:     ba.Configuration[config.GetWalletSharingRequests+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.GetWalletSharingRequests+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		ApproveWalletSharingRequest{
			GeneratorServiceEndpointCommon{
				Name:                 config.ApproveWalletSharingRequest,
				WriteHandlerUUID:     ba.Configuration[config.ApproveWalletSharingRequest+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.ApproveWalletSharingRequest+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
		DeleteWalletSharingRequest{
			GeneratorServiceEndpointCommon{
				Name:                 config.DeleteWalletSharingRequest,
				WriteHandlerUUID:     ba.Configuration[config.DeleteWalletSharingRequest+config.WriteHandlerUUID],
				NotifyHandlerUUID:    ba.Configuration[config.DeleteWalletSharingRequest+config.NotifyHandlerUUID],
				GeneratorAdminServer: ba.GeneratorAdminServer,
				Configuration:        ba.Configuration,
			},
		},
	}

	for _, e := range endpoints {
		ba.addEndpointCharacteristics(e)
	}

}

func (ba BleAdapter) getPasscodes(t time.Time, skew int, period uint) (map[string]bool, error) {
	result := map[string]bool{}

	passcode, err := totp.GenerateCodeCustom(config.BluetoothOTPToken, t, totp.ValidateOpts{
		Period:    period,
		Digits:    4,
		Algorithm: otp.AlgorithmSHA512,
	})

	if err != nil {
		return nil, err
	}

	result[passcode] = true

	for i := 1; i <= skew; i++ {
		timeBehind := time.Unix(t.Unix()-int64(i)*int64(period), 0)
		timeAfter := time.Unix(t.Unix()+int64(i)*int64(period), 0)

		passcodeBefore, err := totp.GenerateCodeCustom(config.BluetoothOTPToken, timeBehind, totp.ValidateOpts{
			Period:    period,
			Digits:    4,
			Algorithm: otp.AlgorithmSHA512,
		})

		if err != nil {
			return nil, err
		}

		result[passcodeBefore] = true

		passcodeAfter, err := totp.GenerateCodeCustom(config.BluetoothOTPToken, timeAfter, totp.ValidateOpts{
			Period:    period,
			Digits:    4,
			Algorithm: otp.AlgorithmSHA512,
		})

		if err != nil {
			return nil, err
		}

		result[passcodeAfter] = true
	}

	return result, nil
}

func (ba BleAdapter) decryptBytes(bluetoothEncryptedContainerBytes []byte) ([]byte, error) {
	if config.BluetoothEncryption == false {
		return bluetoothEncryptedContainerBytes, nil
	}

	/*timeNow := time.Unix(1000000, 0)

	passcodes, err := ba.getPasscodes(timeNow, 5, 60)

	if err != nil {
		return nil, err
	}
	log.Println(timeNow)
	log.Println("aessecret: " + config.BluetoothAESSecret)
	log.Println("otpToken: " + config.BluetoothOTPToken)*/

	container := &api.BluetoothEncryptionContainer{}

	err := proto.Unmarshal(bluetoothEncryptedContainerBytes, container)

	if err != nil {
		return nil, err
	}

	/*for passcode := range passcodes {
		log.Println(passcode)

		base64EncodedKey := base64.StdEncoding.EncodeToString([]byte(config.BluetoothAESSecret + passcode))

		plainText, err := cryptoutils.DecryptAes(container.Ciphertext, container.Iv, base64EncodedKey)

		if err != nil {
			log.Println(err.Error())
			continue
		}

		return []byte(plainText), nil
	}

	return nil, errors.New("Can not decrypt container")*/

	base64EncodedKey := base64.StdEncoding.EncodeToString([]byte(config.BluetoothAESSecret))

	plainText, err := cryptoutils.DecryptAes(container.Ciphertext, container.Iv, base64EncodedKey)

	if err != nil {
		return nil, err
	}

	return []byte(plainText), nil
}

func (ba BleAdapter) encryptBytes(plainText []byte) ([]byte, error) {
	if config.BluetoothEncryption == false {
		return plainText, nil
	}

	/*timeNow := time.Unix(1000000, 0)

	passcode, err := totp.GenerateCodeCustom(config.BluetoothOTPToken, timeNow, totp.ValidateOpts{
		Period:    60,
		Digits:    4,
		Algorithm: otp.AlgorithmSHA512,
	})

	if err != nil {
		return nil, err
	}

	log.Println(timeNow)
	log.Println(passcode)
	log.Println("aessecret: " + config.BluetoothAESSecret)
	log.Println("otpToken: " + config.BluetoothOTPToken)*/

	base64EncodedKey := base64.StdEncoding.EncodeToString([]byte(config.BluetoothAESSecret /*+ passcode*/))

	cipherText, iv, err := cryptoutils.EncryptAES(string(plainText), base64EncodedKey)

	if err != nil {
		return nil, err
	}

	container := &api.BluetoothEncryptionContainer{
		Ciphertext: cipherText,
		Iv:         iv,
	}

	out, err := proto.Marshal(container)

	if err != nil {
		return nil, err
	}

	return out, nil
}

func splitIntoChunks(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

func (ba BleAdapter) addEndpointCharacteristics(endpoint GeneratorServiceEndpoint) {
	responseChannel := make(chan []byte)
	var dataBuffer []byte
	buffering := false

	log.Println(endpoint.getName())
	ba.GattService.AddCharacteristic(gatt.MustParseUUID(endpoint.getWriteHandlerUUID())).HandleWriteFunc(
		func(r gatt.Request, data []byte) (status byte) {
			log.Println(endpoint.getName(), "write called")
			log.Println(data)
			log.Println(len(data))

			if !buffering {
				if len(data) == 5 && string(data) == "START" {
					buffering = true
					return gatt.StatusSuccess
				}
				return gatt.StatusUnexpectedError
			} else {
				if len(data) == 4 && string(data) == "STOP" {
					buffering = false
					data = dataBuffer
					dataBuffer = []byte{}
				} else {
					dataBuffer = append(dataBuffer, data...)
					return gatt.StatusSuccess
				}
			}

			requestMsg := endpoint.getRequestMsg()

			decryptedData, err := ba.decryptBytes(data)

			log.Println(decryptedData)
			log.Println(len(decryptedData))
			log.Println(requestMsg)

			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			err = proto.Unmarshal(decryptedData, requestMsg)

			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			response, err := endpoint.call(context.Background(), requestMsg)
			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			responseData, err := proto.Marshal(response)

			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			log.Println(responseData)
			bluetoothEncryptedContainerBytes, err := ba.encryptBytes(responseData)
			log.Println(bluetoothEncryptedContainerBytes)

			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			go func() {
				log.Println(string(bluetoothEncryptedContainerBytes))
				responseChannel <- bluetoothEncryptedContainerBytes
			}()

			log.Println("not blocked after write to channel")

			return gatt.StatusSuccess
		})

	ba.GattService.AddCharacteristic(gatt.MustParseUUID(endpoint.getNotifyHandlerUUID())).HandleNotifyFunc(
		func(r gatt.Request, n gatt.Notifier) {
			log.Println(endpoint.getName(), "notify called")

			for !n.Done() {

				select {
				case responseData := <-responseChannel:
					log.Println(endpoint.getName(), "new data")
					log.Println(responseData)

					n.Write([]byte("START"))
					for _, chunk := range splitIntoChunks(responseData, 20) {
						n.Write(chunk)
					}
					n.Write([]byte("STOP"))
				default:
				}
			}
		})

}

// GeneratorServiceEndpoint :
type GeneratorServiceEndpoint interface {
	call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error)
	getRequestMsg() protoiface.MessageV1
	getName() string
	getWriteHandlerUUID() string
	getNotifyHandlerUUID() string
}

// GeneratorServiceEndpointCommon :
type GeneratorServiceEndpointCommon struct {
	Name                 string
	WriteHandlerUUID     string
	NotifyHandlerUUID    string
	GeneratorAdminServer handlers.GrpcServer
	Configuration        map[string]string
	GeneratorServiceEndpoint
}

func (e GeneratorServiceEndpointCommon) getName() string {
	return e.Name
}

func (e GeneratorServiceEndpointCommon) getWriteHandlerUUID() string {
	return e.WriteHandlerUUID
}

func (e GeneratorServiceEndpointCommon) getNotifyHandlerUUID() string {
	return e.NotifyHandlerUUID
}

//GetEndPointsDescriptors
type GetEndPointsDescriptors struct {
	GeneratorServiceEndpointCommon
}

func (e GetEndPointsDescriptors) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	response := &api.GetBluetoothEndpointsDescriptorsResponse{
		Endpoints: e.Configuration,
	}

	return response, nil
}

func (e GetEndPointsDescriptors) getRequestMsg() protoiface.MessageV1 {
	return &api.GetBluetoothEndpointsDescriptorsRequest{}
}

// ListIdentityProviders :
type ListIdentityProviders struct {
	GeneratorServiceEndpointCommon
}

func (e ListIdentityProviders) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.ListIdentityProvidersRequest)
	return e.GeneratorAdminServer.ListIdentityProviders(ctx, inTyped)
}

func (e ListIdentityProviders) getRequestMsg() protoiface.MessageV1 {
	return &api.ListIdentityProvidersRequest{}
}

// AddIdentityProvider :
type AddIdentityProvider struct {
	GeneratorServiceEndpointCommon
}

func (e AddIdentityProvider) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.AddIdentityProviderRequest)
	return e.GeneratorAdminServer.AddIdentityProvider(ctx, inTyped)
}

func (e AddIdentityProvider) getRequestMsg() protoiface.MessageV1 {
	return &api.AddIdentityProviderRequest{}
}

// ConfirmIdentityProvider :
type ConfirmIdentityProvider struct {
	GeneratorServiceEndpointCommon
}

func (e ConfirmIdentityProvider) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.ConfirmIdentityProviderRequest)
	return e.GeneratorAdminServer.ConfirmIdentityProvider(ctx, inTyped)
}

func (e ConfirmIdentityProvider) getRequestMsg() protoiface.MessageV1 {
	return &api.ConfirmIdentityProviderRequest{}
}

// RegisterDevice :
type RegisterDevice struct {
	GeneratorServiceEndpointCommon
}

func (e RegisterDevice) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.RegisterDeviceRequest)
	return e.GeneratorAdminServer.RegisterDevice(ctx, inTyped)
}

func (e RegisterDevice) getRequestMsg() protoiface.MessageV1 {
	return &api.RegisterDeviceRequest{}
}

// ListNonRegisteredDevices :
type ListNonRegisteredDevices struct {
	GeneratorServiceEndpointCommon
}

func (e ListNonRegisteredDevices) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.ListNonRegisteredDevicesRequest)
	return e.GeneratorAdminServer.ListNonRegisteredDevices(ctx, inTyped)
}

func (e ListNonRegisteredDevices) getRequestMsg() protoiface.MessageV1 {
	return &api.ListNonRegisteredDevicesRequest{}
}

// AddWallet :
type AddWallet struct {
	GeneratorServiceEndpointCommon
}

func (e AddWallet) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.AddWalletRequest)
	return e.GeneratorAdminServer.AddWallet(ctx, inTyped)
}

func (e AddWallet) getRequestMsg() protoiface.MessageV1 {
	return &api.AddWalletRequest{}
}

// ListWallets :
type ListWallets struct {
	GeneratorServiceEndpointCommon
}

func (e ListWallets) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.ListWalletsRequest)
	return e.GeneratorAdminServer.ListWallets(ctx, inTyped)
}

func (e ListWallets) getRequestMsg() protoiface.MessageV1 {
	return &api.ListWalletsRequest{}
}

// GetWalletSharingRequests :
type GetWalletSharingRequests struct {
	GeneratorServiceEndpointCommon
}

func (e GetWalletSharingRequests) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.GetWalletSharingRequestsRequest)
	return e.GeneratorAdminServer.GetWalletSharingRequests(ctx, inTyped)
}

func (e GetWalletSharingRequests) getRequestMsg() protoiface.MessageV1 {
	return &api.GetWalletSharingRequestsRequest{}
}

// ApproveWalletSharingRequest :
type ApproveWalletSharingRequest struct {
	GeneratorServiceEndpointCommon
}

func (e ApproveWalletSharingRequest) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.ApproveWalletSharingRequestRequest)
	return e.GeneratorAdminServer.ApproveWalletSharingRequest(ctx, inTyped)
}

func (e ApproveWalletSharingRequest) getRequestMsg() protoiface.MessageV1 {
	return &api.ApproveWalletSharingRequestRequest{}
}

// DeleteWalletSharingRequest :
type DeleteWalletSharingRequest struct {
	GeneratorServiceEndpointCommon
}

func (e DeleteWalletSharingRequest) call(ctx context.Context, in protoiface.MessageV1) (protoiface.MessageV1, error) {
	inTyped := in.(*api.DeleteWalletSharingRequestRequest)
	return e.GeneratorAdminServer.DeleteWalletSharingRequest(ctx, inTyped)
}

func (e DeleteWalletSharingRequest) getRequestMsg() protoiface.MessageV1 {
	return &api.DeleteWalletSharingRequestRequest{}
}
