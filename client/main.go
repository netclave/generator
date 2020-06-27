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
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	api "github.com/netclave/apis/generator/api"

	"github.com/netclave/generator/handlers"

	"google.golang.org/grpc"
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

func main() {
	if len(os.Args) == 1 || len(os.Args) == 2 {
		log.Println("client url addIdentityProvider identityProviderURL emailOrPhone")
		log.Println("client url confirmIdentityProvider identityProviderURL identityProviderId code")
		log.Println("client url listIdentityProviders")
		log.Println("client url listNonRegisteredDevices")
		log.Println("client url registerDevice devID")
		log.Println("client url addWallet qrCode")

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
	default:
		{
			log.Println("You have to choose program")
		}
	}
}
