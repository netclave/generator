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

package flashkey

import (
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/utils"
	"github.com/netclave/generator/component"
	"github.com/netclave/generator/config"
)

var UUIDseparator = ": UUID=\""
var FindMnt = "findmnt "
var Blkid = "blkid -t TYPE=vfat -sUUID"
var EncryptedUUID = "encryptedUUID"

//createAndWriteFile tries to create a file filename and write value to it
func createAndWriteFile(filename string, value string) error {
	f, err := os.Create(filename)

	defer f.Close()

	valueByte := []byte(value)
	_, err = f.Write(valueByte)
	if err != nil {
		return err
	}

	return nil
}

//getMntPointAndDevID extracts mount point (mntPoint) and device ID (devID) from devInfo
func getMntPointAndDevID(devInfo string) (string, string, error) {
	devInfoSplit := strings.Split(devInfo, UUIDseparator)

	drive := devInfoSplit[0]
	devID := devInfoSplit[1][:len(devInfoSplit[1])-1]

	findmntOutput, err := utils.RunCommandGetOutput(FindMnt + drive)
	if err != nil {
		return "", "", err
	}
	findmntSecondLine := strings.Split(findmntOutput, "\n")[1]
	mntPoint := strings.Split(findmntSecondLine, " ")[0]

	return mntPoint, devID, nil
}

//listAllDevices returns a list of all inserted devices
func listAllDevices() ([]string, error) {
	//fmt.Println(Blkid)

	blkidOutput, err := utils.RunCommandGetOutput(Blkid)
	if err != nil {
		return nil, err
	}

	//fmt.Println(blkidOutput)

	blkidOutput = strings.TrimSpace(blkidOutput)

	blkidDevices := strings.Split(blkidOutput, "\n")

	return blkidDevices, nil
}

//decryptWithComponentKey decrypts data with the private key of the component
func decryptWithComponentKey(data string) (string, error) {
	privateKey, err := cryptoutils.ParseRSAPrivateKey(component.ComponentPrivateKey)
	if err != nil {
		return "", err
	}
	decryptedData, err := cryptoutils.DecryptData(data, privateKey)
	if err != nil {
		return "", err
	}

	return decryptedData, nil
}

//encryptWithComponentKey encrypts data with the public key of the component
func encryptWithComponentKey(data string) (string, error) {
	publicKey, err := cryptoutils.ParseRSAPublicKey(component.ComponentPublicKey)
	if err != nil {
		return "", err
	}
	encryptedData, err := cryptoutils.EncryptData(data, publicKey)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

//isValidFlashkey checks a particular device (devInfo) whether it is a valid flashkey
func isValidFlashkey(devInfo string) (bool, error) {
	//Extracting mount point and device's UUID from devInfo
	mntPoint, devID, err := getMntPointAndDevID(devInfo)
	if err != nil {
		return false, err
	}

	//Reading the encrypted UUID written on the flash drive
	b, err := ioutil.ReadFile(mntPoint + "/" + EncryptedUUID + "-" + component.ComponentIdentificatorID)
	if err != nil {
		return false, err
	}
	encryptedUUID := string(b)

	//Decrypting the UUID from the flash drive
	decryptedUUID, err := decryptWithComponentKey(encryptedUUID)
	if err != nil {
		return false, err
	}

	dataStorage := component.CreateDataStorage()

	//Retrieving from redis the actual UUID associated with this particular flash drive
	actualUUID, err := dataStorage.GetKey(component.FLASHKEYS, devID)
	if err != nil {
		return false, err
	}

	//The decrypted UUID from the flash drive should be the same as the actual UUID from redis
	return (decryptedUUID == actualUUID), nil
}

//CheckForValidFlashkey checks whether there is an inserted valid flashkey
func CheckForValidFlashkey() (bool, error) {
	if config.DisableUSBSecurity == true {
		return true, nil
	}

	devices, err := listAllDevices()
	if err != nil {
		return false, err
	}

	for _, devInfo := range devices {
		status, err := isValidFlashkey(devInfo)

		if err != nil {
			if strings.Contains(err.Error(), "no such file or directory") {
				continue
			}

			return false, err
		}

		if status {
			return status, nil
		}
	}

	return false, nil
}

//AnyRegisteredFlashkeys checks in redis whether there are any flashkeys registered for this raspberry
func AnyRegisteredFlashkeys() (bool, error) {
	dataStorage := component.CreateDataStorage()

	keys, err := dataStorage.GetKeys(component.FLASHKEYS, "*")

	if err != nil {
		return false, err
	}

	return (len(keys) > 0), nil
}

//ListNonRegisteredDevices returns a list of IDs and mount points of all devices that are not registered flashkeys for this particular raspberry
func ListNonRegisteredDevices() ([]string, error) {
	log.Println("List all devices")
	devices, err := listAllDevices()
	if err != nil {
		return nil, err
	}

	for _, devInfo := range devices {
		log.Println(devInfo)
	}

	nonRegisteredDevices := make([]string, 0)
	for _, devInfo := range devices {
		mntPoint, devID, err := getMntPointAndDevID(devInfo)
		if err != nil {
			log.Println(err.Error())
			continue
		}

		_, err = ioutil.ReadFile(mntPoint + "/" + EncryptedUUID)
		if err != nil {
			nonRegisteredDevices = append(nonRegisteredDevices, devID+" "+mntPoint)
		}
	}

	return nonRegisteredDevices, nil
}

//RegisterDevice registers the device with the given targetDevID as a flashkey.
func RegisterDevice(targetDevID string) error {
	devices, err := listAllDevices()
	if err != nil {
		return err
	}

	//Going through all devices to find the target one (where devID == targetDevID)
	for _, devInfo := range devices {
		mntPoint, devID, err := getMntPointAndDevID(devInfo)
		if devID != targetDevID || err != nil {
			continue
		}

		//Generating UUID
		UUID, err := utils.GenerateUUID()
		if err != nil {
			return err
		}

		//Encrypting UUID
		encryptedUUID, err := encryptWithComponentKey(UUID)
		if err != nil {
			return err
		}

		//Writing the encrypted UUID to the flashkey
		err = createAndWriteFile(mntPoint+"/"+EncryptedUUID+"-"+component.ComponentIdentificatorID, encryptedUUID)
		if err != nil {
			return err
		}

		//Writing in redis that this UUID belongs to this particular flashkey (by targetDevID)
		dataStorage := component.CreateDataStorage()

		err = dataStorage.SetKey(component.FLASHKEYS, targetDevID, UUID, 0)
		if err != nil {
			return err
		}
	}

	return nil
}
