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

package component

import (
	"fmt"
	"log"

	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/storage"
	"github.com/netclave/common/utils"
	"github.com/netclave/generator/config"
)

var COMPONENT_IDENTIFICATOR_ID = "component_generator"
var COMPONENT_REAL_ID = "componentrealid_generator"

var ComponentIdentificatorID = ""
var ComponentPublicKey = ""
var ComponentPrivateKey = ""

var GeneratorIdentificator = &cryptoutils.Identificator{}

func LoadComponent() error {
	err := config.Init()

	if err != nil {
		return err
	}

	err = InitDataStorage()

	if err != nil {
		return err
	}

	err = InitFail2BanDataStorage()

	if err != nil {
		return err
	}

	cryptoStorage := CreateCryptoStorage()

	dataStorage := CreateDataStorage()

	err = LoadBluetoothEndpoints(dataStorage)

	if err != nil {
		return err
	}

	privateKeyPem, err := cryptoStorage.RetrievePrivateKey(COMPONENT_IDENTIFICATOR_ID)
	if err != nil || privateKeyPem == "" {
		pair, err := cryptoutils.GenerateKeyPair()

		if err != nil {
			fmt.Println("Generate key pair error")
			return err
		}

		publicKeyPEM, err := cryptoutils.EncodePublicKeyPEM(pair)

		if err != nil {
			fmt.Println("Error encoding public key")
			return err
		}

		privateKeyPEM, err := cryptoutils.EncodePrivateKeyPEM(pair)

		if err != nil {
			fmt.Println("Error encoding private key")
			return err
		}

		err = cryptoStorage.StorePublicKey(COMPONENT_IDENTIFICATOR_ID, publicKeyPEM)
		if err != nil {
			fmt.Println("Error storing public key")
			return err
		}

		err = cryptoStorage.StorePrivateKey(COMPONENT_IDENTIFICATOR_ID, privateKeyPEM)

		if err != nil {
			fmt.Println("Error storing private key")
			return err
		}

		uuid, err := utils.GenerateUUID()

		fmt.Println("Generated ID: " + uuid)

		if err != nil || uuid == "" {
			fmt.Println("Error generating id")
			return err
		}

		err = dataStorage.SetKey(COMPONENT_REAL_ID, "", uuid, 0)

		if err != nil {
			fmt.Println("Error setting key")
			return err
		}

		GeneratorIdentificator = &cryptoutils.Identificator{}
		GeneratorIdentificator.IdentificatorID = uuid
		GeneratorIdentificator.IdentificatorType = cryptoutils.IDENTIFICATOR_TYPE_GENERATOR

		err = cryptoStorage.AddIdentificator(GeneratorIdentificator)

		if err != nil {
			fmt.Println("Error adding identificator")
			return err
		}
	}

	ComponentIdentificatorID, err = dataStorage.GetKey(COMPONENT_REAL_ID, "")

	if err != nil || ComponentIdentificatorID == "" {
		fmt.Println("Error getting ID")
		return err
	}

	ComponentPublicKey, err = cryptoStorage.RetrievePublicKey(COMPONENT_IDENTIFICATOR_ID)

	if err != nil || ComponentPublicKey == "" {
		fmt.Println("Error getting public key")
		return err
	}

	ComponentPrivateKey, err = cryptoStorage.RetrievePrivateKey(COMPONENT_IDENTIFICATOR_ID)

	if err != nil || ComponentPrivateKey == "" {
		fmt.Println("Error getting private key")
		return err
	}

	GeneratorIdentificator = &cryptoutils.Identificator{}
	GeneratorIdentificator.IdentificatorID = ComponentIdentificatorID
	GeneratorIdentificator.IdentificatorType = cryptoutils.IDENTIFICATOR_TYPE_GENERATOR

	return nil
}

func InitDataStorage() error {
	storage := &storage.GenericStorage{
		Credentials: config.DataStorageCredentials,
		StorageType: config.StorageType,
	}

	return storage.Init()
}

func CreateDataStorage() *storage.GenericStorage {
	storage := &storage.GenericStorage{
		Credentials: config.DataStorageCredentials,
		StorageType: config.StorageType,
	}

	return storage
}

func InitFail2BanDataStorage() error {
	storage := &storage.GenericStorage{
		Credentials: config.Fail2BanDataStorageCredentials,
		StorageType: config.Fail2BanStorageType,
	}

	return storage.Init()
}

func CreateFail2BanDataStorage() *storage.GenericStorage {
	storage := &storage.GenericStorage{
		Credentials: config.Fail2BanDataStorageCredentials,
		StorageType: config.Fail2BanStorageType,
	}

	return storage
}

func CreateCryptoStorage() *cryptoutils.CryptoStorage {
	cryptoStorage := &cryptoutils.CryptoStorage{
		Credentials: config.DataStorageCredentials,
		StorageType: config.StorageType,
	}

	return cryptoStorage
}

type BluetoothEndpoint struct {
	UUID string
}

func LoadBluetoothEndpoints(storage *storage.GenericStorage) error {
	var endPoints map[string]*BluetoothEndpoint

	err := storage.GetMap(BLUETOOTH_ENDPOINTS, "", &endPoints)

	if err != nil {
		return err
	}

	for _, keyName := range config.GRPCEndPoints {
		writerEndpointKey := keyName + config.WriteHandlerUUID

		writerEndpoint, ok := endPoints[writerEndpointKey]

		if ok == false {
			uuid, err := utils.GenerateUUID()

			if err != nil {
				return err
			}

			endpoint := BluetoothEndpoint{
				UUID: uuid,
			}

			err = storage.AddToMap(BLUETOOTH_ENDPOINTS, "", writerEndpointKey, endpoint)

			if err != nil {
				return err
			}

			writerEndpoint = &endpoint
		}

		notifierEndpointKey := keyName + config.NotifyHandlerUUID

		notifierEndpoint, ok := endPoints[notifierEndpointKey]

		if ok == false {
			uuid, err := utils.GenerateUUID()

			if err != nil {
				return err
			}

			endpoint := BluetoothEndpoint{
				UUID: uuid,
			}

			err = storage.AddToMap(BLUETOOTH_ENDPOINTS, "", notifierEndpointKey, endpoint)

			if err != nil {
				return err
			}

			notifierEndpoint = &endpoint
		}

		config.BluetoothEndpointsConfiguration[writerEndpointKey] = writerEndpoint.UUID
		config.BluetoothEndpointsConfiguration[notifierEndpointKey] = notifierEndpoint.UUID
	}

	for key, value := range config.BluetoothEndpointsConfiguration {
		log.Println(key + " ---> " + value)
	}

	return nil
}
