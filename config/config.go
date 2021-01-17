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

package config

import (
	"bufio"
	"flag"
	"log"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/netclave/common/storage"
)

var DataStorageCredentials map[string]string
var StorageType string

var Fail2BanDataStorageCredentials map[string]string
var Fail2BanStorageType string
var Fail2BanTTL int64

var TokenTTL = time.Duration(300)

var ListenHTTPAddress = ":8081"
var PublicPort = "8081"
var ListenGRPCAddress = "localhost:6666"
var DisableUSBSecurity = false
var EnableBluetooth = false
var SameNetwork = true
var ExternalUrls []string
var BluetoothEndpointsConfiguration = map[string]string{}
var BluetoothEncryption = false
var BluetoothOTPToken string
var BluetoothAESSecret string

func Init() error {
	flag.String("configFile", "/opt/config.json", "Provide full path to your config json file")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	filename := viper.GetString("configFile") // retrieve value from viper

	file, err := os.Open(filename)

	viper.SetConfigType("json")

	if err != nil {
		log.Println(err.Error())
	} else {
		err = viper.ReadConfig(bufio.NewReader(file))

		if err != nil {
			log.Println(err.Error())
			return err
		}
	}

	viper.SetDefault("host.httpaddress", ":8081")
	viper.SetDefault("host.publicport", "8081")
	viper.SetDefault("host.grpcaddress", "localhost:6666")

	viper.SetDefault("disableusbsecurity", false)
	viper.SetDefault("samenetwork", true)
	viper.SetDefault("externalurls", []string{})

	viper.SetDefault("datastorage.credentials", map[string]string{
		"host":     "localhost:6379",
		"db":       "2",
		"password": "",
	})
	viper.SetDefault("datastorage.type", storage.REDIS_STORAGE)

	viper.SetDefault("fail2bandatastorage.credentials", map[string]string{
		"host":     "localhost:6379",
		"db":       "5",
		"password": "",
	})
	viper.SetDefault("fail2bandatastorage.type", storage.REDIS_STORAGE)

	viper.SetDefault("fail2banttl", int64(300000))

	viper.SetDefault("enablebluetooth", false)
	viper.SetDefault("bluetoothserviceuuid", "ec60d335-b78a-40eb-bd0b-4b48a39fe3f0")
	viper.SetDefault("bluetoothgetendpointswriteuuid", "5c27542d-62ea-4a1a-ab92-cdee7f62a0bb")
	viper.SetDefault("bluetoothgetendpointsnotifyuuid", "bf8d7d5a-e25b-4ed7-af64-773a7ad3a07e")
	viper.SetDefault("bluetoothencryption", false)
	viper.SetDefault("bluetoothotptoken", "otptoken")
	viper.SetDefault("bluetoothaessecret", "aessecret")

	hostConfig := viper.Sub("host")

	ListenHTTPAddress = hostConfig.GetString("httpaddress")
	ListenGRPCAddress = hostConfig.GetString("grpcaddress")
	PublicPort = hostConfig.GetString("publicport")

	log.Println(ListenHTTPAddress)
	log.Println(ListenGRPCAddress)

	datastorageConfig := viper.Sub("datastorage")

	DataStorageCredentials = datastorageConfig.GetStringMapString("credentials")
	StorageType = datastorageConfig.GetString("type")

	fail2banDatastorageConfig := viper.Sub("fail2bandatastorage")

	Fail2BanDataStorageCredentials = fail2banDatastorageConfig.GetStringMapString("credentials")
	Fail2BanStorageType = fail2banDatastorageConfig.GetString("type")

	Fail2BanTTL = viper.GetInt64("fail2banttl")

	DisableUSBSecurity = viper.GetBool("disableusbsecurity")
	SameNetwork = viper.GetBool("samenetwork")
	ExternalUrls = viper.GetStringSlice("externalurls")

	EnableBluetooth = viper.GetBool("enablebluetooth")

	BluetoothEndpointsConfiguration[ServiceUUID] = viper.GetString("bluetoothserviceuuid")
	BluetoothEndpointsConfiguration[GetEndPointsDescriptorsWriteHandlerUUID] = viper.GetString("bluetoothgetendpointswriteuuid")
	BluetoothEndpointsConfiguration[GetEndPointsDescriptorsNotifyHandlerUUID] = viper.GetString("bluetoothgetendpointsnotifyuuid")

	BluetoothEncryption = viper.GetBool("bluetoothencryption")
	BluetoothOTPToken = viper.GetString("bluetoothotptoken")
	BluetoothAESSecret = viper.GetString("bluetoothaessecret")

	return err
}
