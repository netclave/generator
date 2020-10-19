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

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
	api "github.com/netclave/apis/generator/api"
	"github.com/netclave/common/utils"

	"github.com/netclave/generator/handlers"

	"google.golang.org/grpc"

	qrcode "github.com/skip2/go-qrcode"
)

var RegisterSuccessfulMessage = "Device registered successfully"

func parseGrpcError(err error) error {
	s := err.Error()

	if strings.HasSuffix(s, handlers.AccessDeniedMessage) {
		return errors.New(handlers.AccessDeniedMessage)
	}

	//cuts out "rpc error: " from the beginning
	return errors.New(s[11:])
}

func addIdentityProviderRequest(conn *grpc.ClientConn, identityProviderURL, emailOrPhone string) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.AddIdentityProviderRequest{
		IdentityProviderUrl: identityProviderURL,
		EmailOrPhone:        emailOrPhone,
	}

	response, err := client.AddIdentityProvider(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}

	log.Println(response.Response + " " + response.IdentityProviderId)
}

func confirmIdentityProviderRequest(conn *grpc.ClientConn, identityProviderURL, identityProviderID, code string) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ConfirmIdentityProviderRequest{
		IdentityProviderUrl: identityProviderURL,
		IdentityProviderId:  identityProviderID,
		ConfirmationCode:    code,
	}

	response, err := client.ConfirmIdentityProvider(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}

	log.Println(response.Response)
}

func listIdentityProvidersRequest(conn *grpc.ClientConn) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListIdentityProvidersRequest{}

	response, err := client.ListIdentityProviders(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}

	identityProviders := response.IdentityProviders

	for _, identityProvider := range identityProviders {
		log.Println(identityProvider.Url + " " + identityProvider.Id)
	}
}

func listNonRegisteredDevices(conn *grpc.ClientConn) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListNonRegisteredDevicesRequest{}

	response, err := client.ListNonRegisteredDevices(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}

	devices := response.Devices

	for _, device := range devices {
		log.Println(device)
	}
}

func registerDevice(conn *grpc.ClientConn, devID string) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.RegisterDeviceRequest{
		DevID: devID,
	}

	_, err := client.RegisterDevice(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}

	log.Println(RegisterSuccessfulMessage)
}

func addWallet(conn *grpc.ClientConn, qrCode string) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.AddWalletRequest{
		QRcode: qrCode,
	}

	_, err := client.AddWallet(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}
}

func listWallets(conn *grpc.ClientConn) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListWalletsRequest{}

	res, err := client.ListWallets(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}

	for _, walletUUID := range res.Wallets {
		log.Println(walletUUID)
	}
}

func getWalletSharingRequests(conn *grpc.ClientConn) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.GetWalletSharingRequestsRequest{}

	response, err := client.GetWalletSharingRequests(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}

	for _, request := range response.Requests {
		log.Println(request.RequestHash + "," + request.Comment)
	}
}

func approveWalletSharingRequest(conn *grpc.ClientConn, requestHash string) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ApproveWalletSharingRequestRequest{
		RequestHash: requestHash,
	}

	_, err := client.ApproveWalletSharingRequest(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}
}

func deleteWalletSharingRequest(conn *grpc.ClientConn, requestHash string) {
	client := api.NewGeneratorAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.DeleteWalletSharingRequestRequest{
		RequestHash: requestHash,
	}

	_, err := client.DeleteWalletSharingRequest(ctx, in)

	if err != nil {
		log.Println(parseGrpcError(err))
		return
	}
}

type QRCodeData struct {
	AESSecret                       string
	OTPToken                        string
	ServiceUUID                     string
	BluetoothGetEndpointsWriteUUID  string
	BluetoothGetEndpointsNotifyUUID string
	MacAddress                      string
}

func getBluetoothMacAddress(bluetoothDevName string) (string, error) {
	line, err := utils.RunCommandGetOutput("hcitool dev | grep " + bluetoothDevName)

	if err != nil {
		return "", err
	}

	return strings.Trim(strings.ReplaceAll(line, bluetoothDevName, ""), " \n\t"), nil
}

func generateAuthenticationQRCode(configFile string, qrCodeFileDestination string, bluetoothDevName string) {
	file, err := os.Open(configFile)

	viper.SetConfigType("json")

	if err != nil {
		log.Println(err.Error())
		return
	} else {
		err = viper.ReadConfig(bufio.NewReader(file))

		if err != nil {
			log.Println(err.Error())
			return
		}
	}

	viper.SetDefault("bluetoothserviceuuid", "ec60d335-b78a-40eb-bd0b-4b48a39fe3f0")
	viper.SetDefault("bluetoothgetendpointswriteuuid", "5c27542d-62ea-4a1a-ab92-cdee7f62a0bb")
	viper.SetDefault("bluetoothgetendpointsnotifyuuid", "bf8d7d5a-e25b-4ed7-af64-773a7ad3a07e")
	viper.SetDefault("bluetoothotptoken", "otptoken")
	viper.SetDefault("bluetoothaessecret", "aessecret")

	macAddress, err := getBluetoothMacAddress(bluetoothDevName)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	qrCodeData := QRCodeData{}

	qrCodeData.ServiceUUID = viper.GetString("bluetoothserviceuuid")
	qrCodeData.BluetoothGetEndpointsWriteUUID = viper.GetString("bluetoothgetendpointswriteuuid")
	qrCodeData.BluetoothGetEndpointsNotifyUUID = viper.GetString("bluetoothgetendpointsnotifyuuid")

	qrCodeData.OTPToken = viper.GetString("bluetoothotptoken")
	qrCodeData.AESSecret = viper.GetString("bluetoothaessecret")
	qrCodeData.MacAddress = macAddress

	data, err := json.Marshal(qrCodeData)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = qrcode.WriteFile(string(data), qrcode.Low, 256, qrCodeFileDestination)

	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

func main() {
	if len(os.Args) == 1 || len(os.Args) == 2 {
		log.Println("client url addIdentityProvider identityProviderURL emailOrPhone")
		log.Println("client url confirmIdentityProvider identityProviderURL identityProviderId code")
		log.Println("client url listIdentityProviders")
		log.Println("client url listNonRegisteredDevices")
		log.Println("client url registerDevice devID")
		log.Println("client url addWallet qrCode")
		log.Println("client url listWallets")
		log.Println("client url getWalletSharingRequests")
		log.Println("client url approveWalletSharingRequest requestHash")
		log.Println("client url deleteWalletSharingRequest requestHash")
		log.Println("client url generateAuthenticationQRCode configFile qrCodeFileDestination bluetoothDevName")

		return
	}

	var conn *grpc.ClientConn

	conn, err := grpc.Dial(os.Args[1], grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	switch os.Args[2] {
	case "addIdentityProvider":
		{
			addIdentityProviderRequest(conn, os.Args[3], os.Args[4])
		}
	case "confirmIdentityProvider":
		{
			confirmIdentityProviderRequest(conn, os.Args[3], os.Args[4], os.Args[5])
		}
	case "listIdentityProviders":
		{
			listIdentityProvidersRequest(conn)
		}
	case "listNonRegisteredDevices":
		{
			listNonRegisteredDevices(conn)
		}
	case "registerDevice":
		{
			registerDevice(conn, os.Args[3])
		}
	case "addWallet":
		{
			addWallet(conn, os.Args[3])
		}
	case "listWallets":
		{
			listWallets(conn)
		}
	case "getWalletSharingRequests":
		{
			getWalletSharingRequests(conn)
		}
	case "approveWalletSharingRequest":
		{
			approveWalletSharingRequest(conn, os.Args[3])
		}
	case "deleteWalletSharingRequest":
		{
			deleteWalletSharingRequest(conn, os.Args[3])
		}
	case "generateAuthenticationQRCode":
		{
			generateAuthenticationQRCode(os.Args[3], os.Args[4], os.Args[5])
		}
	default:
		{
			log.Println("You have to choose program")
		}
	}
}
