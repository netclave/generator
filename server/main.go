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
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	api "github.com/netclave/apis/generator/api"
	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/httputils"
	"github.com/netclave/common/jsonutils"
	"github.com/netclave/generator/component"
	"github.com/netclave/generator/config"
	"github.com/netclave/generator/handlers"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func randStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func randString(length int) string {
	return randStringWithCharset(length, charset)
}

func startGRPCServer(address string) error {
	// create a listener on TCP port
	lis, err := net.Listen("tcp", address)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	// create a server instance
	s := handlers.GrpcServer{}

	ServerMaxReceiveMessageSize := math.MaxInt32

	opts := []grpc.ServerOption{grpc.MaxRecvMsgSize(ServerMaxReceiveMessageSize)}
	// create a gRPC server object
	grpcServer := grpc.NewServer(opts...)

	// attach the Ping service to the server
	api.RegisterGeneratorAdminServer(grpcServer, &s)

	// start the server
	log.Printf("starting HTTP/2 gRPC server on %s", address)
	reflection.Register(grpcServer)
	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %s", err)
	}

	return nil
}

// GetLocalIP returns the non loopback local IP of the host
func GetLocalIPs() ([]string, error) {
	ips := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	return ips, nil
}

type UpdateTokensRequest struct {
	WalletIDToTokenMap map[string]string `json:"walletIDToTokenMap"`
	LocalIps           []string          `json:"localIps"`
}

func updateAndSendTokens() error {
	cryptoStorage := component.CreateCryptoStorage()

	identityProvidersMap, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.GeneratorIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)
	if err != nil {
		return err
	}

	generatorID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	dataStorage := component.CreateDataStorage()

	for _, identityProvider := range identityProvidersMap {
		identityProviderPublicKey, err := cryptoStorage.RetrievePublicKey(identityProvider.IdentificatorID)
		if err != nil {
			log.Println(err.Error())
			return err
		}

		saveTokensURL := identityProvider.IdentificatorURL + "/saveTokens"

		wallets, err := cryptoStorage.GetIdentificatorToIdentificatorMap(identityProvider, cryptoutils.IDENTIFICATOR_TYPE_WALLET)
		if err != nil {
			log.Println(err.Error())
			return err
		}

		walletIDToTokenMap := map[string]string{}

		for _, wallet := range wallets {
			walletID := wallet.IdentificatorID

			token, err := dataStorage.GetKey(component.TOKENS, identityProvider.IdentificatorID+"/"+walletID+"/current")

			if err != nil {
				log.Println(err.Error())
				return err
			}

			if token != "" {
				walletIDToTokenMap[walletID] = token
				continue
			}

			token = randString(32)

			err = dataStorage.SetKey(component.TOKENS, identityProvider.IdentificatorID+"/"+walletID+"/"+token, token, config.TokenTTL*time.Second)
			if err != nil {
				log.Println(err.Error())
				return err
			}

			err = dataStorage.SetKey(component.TOKENS, walletID+"/"+identityProvider.IdentificatorID+"/"+token, token, config.TokenTTL*time.Second)
			if err != nil {
				log.Println(err.Error())
				return err
			}

			err = dataStorage.SetKey(component.TOKENS, identityProvider.IdentificatorID+"/"+walletID+"/current", token, 60*time.Second)
			if err != nil {
				log.Println(err.Error())
				return err
			}
			walletIDToTokenMap[walletID] = token
		}

		localIps, err := GetLocalIPs()

		if err != nil {
			log.Println(err.Error())
			continue
		}

		data := UpdateTokensRequest{
			WalletIDToTokenMap: walletIDToTokenMap,
			LocalIps:           localIps,
		}

		request, err := jsonutils.SignAndEncryptResponse(data, generatorID,
			privateKeyPEM, publicKeyPEM, identityProviderPublicKey, false)

		if err != nil {
			log.Println(err.Error())
			continue
		}

		_, _, _, err = httputils.MakePostRequest(saveTokensURL, request, true, component.ComponentPrivateKey, cryptoStorage)

		if err != nil {
			log.Println(err.Error())
			continue
		}
	}

	return nil
}

func updateRedisIdentificators() error {
	cryptoStorage := component.CreateCryptoStorage()

	identityProvidersMap, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.GeneratorIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)

	if err != nil {
		return err
	}

	generatorID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	for _, identityProvider := range identityProvidersMap {
		identityProviderPublicKey, err := cryptoStorage.RetrievePublicKey(identityProvider.IdentificatorID)

		if err != nil {
			log.Println(err)
			continue
		}

		request, err := jsonutils.SignAndEncryptResponse(map[string]string{}, generatorID,
			privateKeyPEM, publicKeyPEM, identityProviderPublicKey, false)

		if err != nil {
			log.Println(err)
			continue
		}

		response, _, _, err := httputils.MakePostRequest(identityProvider.IdentificatorURL+"/listPublicKeysForIdentificator", request, true, component.ComponentPrivateKey, cryptoStorage)

		if err != nil {
			log.Println(err)
			continue
		}

		log.Println(response)

		devices := make(map[string]string)
		err = json.Unmarshal([]byte(response), &devices)

		if err != nil {
			log.Println(err)
			continue
		}

		for deviceID, deviceTypeAndPublicKey := range devices {
			tokens := strings.Split(deviceTypeAndPublicKey, ",")
			identificatorType := tokens[1]
			publicKey := tokens[2]

			identificator := &cryptoutils.Identificator{
				IdentificatorID:   deviceID,
				IdentificatorType: identificatorType,
			}

			err := cryptoStorage.AddIdentificator(identificator)

			if err != nil {
				return err
			}

			err = cryptoStorage.StorePublicKey(deviceID, publicKey)

			if err != nil {
				return err
			}

			err = cryptoStorage.AddIdentificatorToIdentificator(identificator, identityProvider)

			if err != nil {
				return err
			}

			err = cryptoStorage.AddIdentificatorToIdentificator(identityProvider, identificator)

			if err != nil {
				return err
			}

			err = cryptoStorage.AddIdentificatorToIdentificator(identificator, component.GeneratorIdentificator)

			if err != nil {
				return err
			}

			err = cryptoStorage.AddIdentificatorToIdentificator(component.GeneratorIdentificator, identificator)

			if err != nil {
				return err
			}

		}
	}

	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	err := component.LoadComponent()
	if err != nil {
		log.Println(err.Error())
		return
	}

	go func() {
		log.Println("Starting grpc server")
		err = startGRPCServer(config.ListenGRPCAddress)
	}()

	go func() {
		for {
			err := updateAndSendTokens()

			if err != nil {
				log.Println(err)
			}

			time.Sleep(2 * time.Second)
		}
	}()

	go func() {
		for {
			err = updateRedisIdentificators()

			if err != nil {
				log.Println(err)
			}

			time.Sleep(2 * time.Second)
		}
	}()

	log.Println("Starting http server")

	http.HandleFunc("/getPublicKey", handlers.GetPublicKey)
	http.HandleFunc("/listTokensForWallet", handlers.ListTokensForWallet)

	if err := http.ListenAndServe(config.ListenHTTPAddress, nil); err != nil {
		panic(err)
	}

	if err != nil {
		panic(err)
	}
}
