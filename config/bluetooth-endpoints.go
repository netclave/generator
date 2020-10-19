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

const IBeaconUUID = "5AFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

const ServiceUUID = "serviceUUID"
const GetEndPointsDescriptorsWriteHandlerUUID = "getEndPointsDescriptorsWriteHandlerUUID"
const GetEndPointsDescriptorsNotifyHandlerUUID = "getEndPointsDescriptorsNotifyHandlerUUID"

const ListIdentityProviders = "listIdentityProviders"
const AddIdentityProvider = "addIdentityProvider"
const ConfirmIdentityProvider = "confirmIdentityProvider"
const RegisterDevice = "registerDevice"
const ListNonRegisteredDevices = "listNonRegisteredDevices"
const AddWallet = "addWallet"
const ListWallets = "listWallets"
const GetWalletSharingRequests = "getWalletSharingRequests"
const ApproveWalletSharingRequest = "approveWalletSharingRequest"
const DeleteWalletSharingRequest = "deleteWalletSharingRequest"

const WriteHandlerUUID = "WriteHandlerUUID"
const NotifyHandlerUUID = "NotifyHandlerUUID"

var GRPCEndPoints = map[string]string{
	"ListIdentityProviders":       ListIdentityProviders,
	"AddIdentityProvider":         AddIdentityProvider,
	"ConfirmIdentityProvider":     ConfirmIdentityProvider,
	"RegisterDevice":              RegisterDevice,
	"ListNonRegisteredDevices":    ListNonRegisteredDevices,
	"AddWallet":                   AddWallet,
	"ListWallets":                 ListWallets,
	"GetWalletSharingRequests":    GetWalletSharingRequests,
	"ApproveWalletSharingRequest": ApproveWalletSharingRequest,
	"DeleteWalletSharingRequest":  DeleteWalletSharingRequest,
}
