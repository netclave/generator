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

package ble

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/netclave/generator/handlers"

	"syscall"

	gatt "github.com/netclave/bluetooth-library"
	cmd "github.com/netclave/bluetooth-library/linux/cmd"
	"github.com/netclave/common/utils"
	"github.com/netclave/generator/ble/service"
	"github.com/netclave/generator/config"

	"github.com/netclave/bluetooth-library/linux/socket"
)

var (
	mc    = flag.Int("mc", 1, "Maximum concurrent connections")
	id    = flag.Duration("id", 0, "ibeacon duration")
	ii    = flag.Duration("ii", 5*time.Second, "ibeacon interval")
	name  = flag.String("name", "NetClave Generator", "Device Name")
	chmap = flag.Int("chmap", 0x7, "Advertising channel map")
	dev   = flag.Int("dev", -1, "HCI device ID")
	chk   = flag.Bool("chk", true, "Check device LE support")
)

// DefaultServerOptions :
var DefaultServerOptions = []gatt.Option{
	gatt.LnxMaxConnections(1),
	gatt.LnxDeviceID(-1, true),
	gatt.LnxSetAdvertisingParameters(&cmd.LESetAdvertisingParameters{
		AdvertisingIntervalMin: 0x00f4,
		AdvertisingIntervalMax: 0x00f4,
		AdvertisingChannelMap:  0x7,
	}),
}

func StartBluetoothService() (string, error) {
	log.Println("Starting bluetooth service")
	return utils.RunCommandGetOutput("systemctl start bluetooth")
}

func StopBluetoothService() (string, error) {
	log.Println("Stopping bluetooth service")
	return utils.RunCommandGetOutput("systemctl stop bluetooth -f")
}

func ResetHCIInterface() (string, error) {
	log.Println("Resetting hci0 interface")
	return utils.RunCommandGetOutput("hciconfig hci0 reset")
}

func StopHCIInterface() (string, error) {
	log.Println("Stopping hci0 interface")
	return utils.RunCommandGetOutput("hciconfig hci0 down")
}

func RFKillBluetooth() (string, error) {
	log.Println("Rf killing the bluetooth adapter")
	return utils.RunCommandGetOutput("rfkill unblock bluetooth")
}

func closeSocket(fd int) error {
	log.Println("Closing of the socket")
	return syscall.Close(fd)
}

func createNewSocket() (int, error) {
	return socket.Socket(socket.AF_BLUETOOTH, syscall.SOCK_RAW, socket.BTPROTO_HCI)
}

func StartBLEServer(generatorAdminServer handlers.GrpcServer, channel chan bool, configuration map[string]string) error {
	log.Println("Starting BLE server")

	flag.Parse()

	fd, err := createNewSocket()

	d, err := gatt.NewDevice(fd, DefaultServerOptions...)

	if err != nil {
		log.Printf("Failed to open device, err: %s", err)
		return err
	}

	go func() {
		for {
			select {
			case _, ok := <-channel:
				if ok == false {
					d.CloseSocket()
					closeSocket(fd)
					return
				}
			default:
				time.Sleep(1 * time.Second)
			}
		}
	}()

	d.ResetDevice()

	// Register optional handlers.
	d.Handle(
		gatt.CentralConnected(func(c gatt.Central) { log.Println("Connect: ", c.ID()) }),
		gatt.CentralDisconnected(func(c gatt.Central) { log.Println("Disconnect: ", c.ID()) }),
	)

	// A mandatory handler for monitoring device state.
	onStateChanged := func(d gatt.Device, s gatt.State) {
		fmt.Printf("State: %s\n", s)
		switch s {
		case gatt.StatePoweredOn:

			// Setup GAP and GATT services.
			d.AddService(service.NewGapService(*name))
			d.AddService(service.NewGattService())

			generatorAdminService := service.NewGeneratorAdminService(generatorAdminServer, configuration)
			d.AddService(generatorAdminService)

			uuids := []gatt.UUID{generatorAdminService.UUID()}

			// If id is zero, advertise name and services statically.
			if *id == time.Duration(0) {
				d.AdvertiseNameAndServices(*name, uuids)
				break
			}

			// If id is non-zero, advertise name and services and iBeacon alternately.
			go func() {
				for {
					select {
					case _, ok := <-channel:
						if ok == false {
							d.StopAdvertising()
							log.Println("Receiving signal for Stopping advertising")
							return
						}
					default:
						// Advertise as a RedBear Labs iBeacon.

						d.AdvertiseIBeacon(gatt.MustParseUUID(config.IBeaconUUID), 1, 2, -59)
						time.Sleep(*id)

						// Advertise name and services.
						d.AdvertiseNameAndServices(*name, uuids)
						time.Sleep(*ii)
					}
				}
			}()

		default:
		}
	}

	d.Init(onStateChanged)

	return nil
}

func StopBLEServer(channel chan bool) {
	log.Println("Stopping BLE server")
	close(channel)
}
