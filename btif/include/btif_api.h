/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/*******************************************************************************
 *
 *  Filename:      btif_api.h
 *
 *  Description:   Main API header file for all BTIF functions accessed
 *                 from main bluetooth HAL. All HAL extensions will not
 *                 require headerfiles as they would be accessed through
 *                 callout/callins.
 *
 *******************************************************************************/

#ifndef BTIF_API_H
#define BTIF_API_H

#include "btif_common.h"
#include "btif_dm.h"

/*******************************************************************************
**  BTIF CORE API
********************************************************************************/

/*******************************************************************************
**
** Function         btif_init_bluetooth
**
** Description      Creates BTIF task and prepares BT scheduler for startup
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_init_bluetooth(void);

/*******************************************************************************
**
** Function         btif_enable_bluetooth
**
** Description      Performs chip power on and kickstarts OS scheduler
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_enable_bluetooth(void);

/*******************************************************************************
**
** Function         btif_disable_bluetooth
**
** Description      Inititates shutdown of Bluetooth system.
**                  Any active links will be dropped and device entering
**                  non connectable/discoverable mode
**
** Returns          void
**
*******************************************************************************/
bt_status_t btif_disable_bluetooth(void);

/*******************************************************************************
**
** Function         btif_shutdown_bluetooth
**
** Description      Finalizes BT scheduler shutdown and terminates BTIF
**                  task.
**
**
** Returns          void
**
*******************************************************************************/
bt_status_t btif_shutdown_bluetooth(void);

/*******************************************************************************
**
** Function         btif_get_adapter_properties
**
** Description      Fetches all local adapter properties
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_get_adapter_properties(void);

/*******************************************************************************
**
** Function         btif_get_adapter_property
**
** Description      Fetches property value from local cache
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_get_adapter_property( bt_property_type_t type);

/*******************************************************************************
**
** Function         btif_set_adapter_property
**
** Description      Updates core stack with property value and stores it in
**                  local cache
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_set_adapter_property( const bt_property_t *property);

/*******************************************************************************
**
** Function         btif_get_remote_device_property
**
** Description      Fetches the remote device property from the NVRAM
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_get_remote_device_property( bt_bdaddr_t *remote_addr,
                                             bt_property_type_t type);

/*******************************************************************************
**
** Function         btif_get_remote_device_properties
**
** Description      Fetches all the remote device properties from NVRAM
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_get_remote_device_properties( bt_bdaddr_t *remote_addr);

/*******************************************************************************
**
** Function         btif_set_remote_device_property
**
** Description      Writes the remote device property to NVRAM.
**                  Currently, BT_PROPERTY_REMOTE_FRIENDLY_NAME is the only
**                  remote device property that can be set
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_set_remote_device_property( bt_bdaddr_t *remote_addr,
                                             const bt_property_t *property);

/*******************************************************************************
**
** Function         btif_get_remote_service_record
**
** Description      Looks up the service matching uuid on the remote device
**                  and fetches the SCN and service_name if the UUID is found
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_get_remote_service_record( bt_bdaddr_t *remote_addr,
                                            bt_uuid_t *uuid);


/*******************************************************************************
**  BTIF DM API
********************************************************************************/

/*******************************************************************************
**
** Function         btif_dm_start_discovery
**
** Description      Start device discovery/inquiry
**
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_start_discovery(void);

/*******************************************************************************
**
** Function         btif_dm_cancel_discovery
**
** Description      Cancels search
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_cancel_discovery(void);

/*******************************************************************************
**
** Function         btif_dm_create_bond
**
** Description      Initiate bonding with the specified device
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_create_bond(const bt_bdaddr_t *bd_addr, int transport);

/*******************************************************************************
**
** Function         btif_dm_cancel_bond
**
** Description      Initiate bonding with the specified device
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_cancel_bond(const bt_bdaddr_t *bd_addr);

/*******************************************************************************
**
** Function         btif_dm_remove_bond
**
** Description      Removes bonding with the specified device
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_remove_bond(const bt_bdaddr_t *bd_addr);

/*******************************************************************************
**
** Function         btif_dm_get_connection_state
**
** Description      Returns whether the remote device is currently connected
**
** Returns          0 if not connected
**
*******************************************************************************/
uint16_t btif_dm_get_connection_state(const bt_bdaddr_t *bd_addr);

/*******************************************************************************
**
** Function         btif_dm_pin_reply
**
** Description      BT legacy pairing - PIN code reply
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_pin_reply( const bt_bdaddr_t *bd_addr, uint8_t accept,
                               uint8_t pin_len, bt_pin_code_t *pin_code);

/*******************************************************************************
**
** Function         btif_dm_passkey_reply
**
** Description      BT SSP passkey reply
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_passkey_reply( const bt_bdaddr_t *bd_addr,
                                   uint8_t accept, uint32_t passkey);

/*******************************************************************************
**
** Function         btif_dm_ssp_reply
**
** Description      BT SSP Reply - Just Works, Numeric Comparison & Passkey Entry
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_ssp_reply( const bt_bdaddr_t *bd_addr,
                              bt_ssp_variant_t variant, uint8_t accept,
                              uint32_t passkey);

/*******************************************************************************
**
** Function         btif_dm_get_adapter_property
**
** Description      Queries the BTA for the adapter property
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_get_adapter_property(bt_property_t *prop);

/*******************************************************************************
**
** Function         btif_dm_get_remote_services
**
** Description      Start SDP to get remote services
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_get_remote_service_record(bt_bdaddr_t *remote_addr,
                                              bt_uuid_t *uuid);


/*******************************************************************************
**
** Function         btif_dm_get_remote_services
**
** Description      Start SDP to get remote services
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_dm_get_remote_services(bt_bdaddr_t *remote_addr);

/*******************************************************************************
**
** Function         btif_dut_mode_configure
**
** Description      Configure Test Mode - 'enable' to 1 puts the device in test mode and 0 exits
**                       test mode
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_dut_mode_configure(uint8_t enable);

/*******************************************************************************
**
** Function         btif_dut_mode_send
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_dut_mode_send(uint16_t opcode, uint8_t *buf, uint8_t len);

/*******************************************************************************
**
** Function         btif_le_test_mode
**
** Description     Sends a HCI BLE Test command to the Controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_le_test_mode(uint16_t opcode, uint8_t *buf, uint8_t len);

#if HCI_RAW_CMD_INCLUDED == TRUE
/*******************************************************************************
**
** Function         btif_hci_cmd_send
**
** Description      Sends a HCI Raw command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_hci_cmd_send(uint16_t opcode, uint8_t *buf, uint8_t len);
#endif

/*******************************************************************************
**
** Function         btif_dm_read_energy_info
**
** Description     Reads the energy info from controller
**
** Returns          void
**
*******************************************************************************/
void btif_dm_read_energy_info();

/*******************************************************************************
**
** Function         btif_read_version
**
** Description      Returns the BT chip firmware versoin
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_read_version(btif_fw_version_t *version);


/*******************************************************************************
**
** Function         btif_read_version_internal
**
** Description      Sends a HCI VSC to the controller to read the FW version
**
** Returns          Version of current firmware on the controller
**
*******************************************************************************/

bt_status_t btif_read_version_internal(void);

/*******************************************************************************
**
** Function         btif_hw_chip_firmware_update
**
** Description      Upgrades the BT Chip firmware
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_hw_chip_firmware_update(void);
bt_status_t btif_hw_chip_firmware_update_callback(void);
/*******************************************************************************
**
** Function         btif_config_hci_snoop_log
**
** Description     enable or disable HCI snoop log
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_config_hci_snoop_log(uint8_t enable);

bt_status_t btif_get_headless_device_list(void);
/*******************************************************************************
** Function         btif_enter_headless_mode
**
** Description     device_type: Bit0->Enable HOGP wakeup,Bit1->Enable BR/EDR wakeup
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_enter_headless_mode(uint8_t device_type);

/*******************************************************************************
**
** Function         btif_add_headless_mode_wakeup_device
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_add_headless_mode_wakeup_device(bt_bdaddr_t *remote_addr);

/*******************************************************************************
**
** Function         btif_hogp_read_link_key
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_hogp_read_link_key(void *str);

/*******************************************************************************
**
** Function         btif_hogp_set_scan_param
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_hogp_set_scan_param(hogp_le_scan_param_t *param);

/*******************************************************************************
**
** Function         btif_add_av_dev_to_headless_mode
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_add_av_dev_to_headless_mode(bt_bdaddr_t *remote_addr);

/*******************************************************************************
**
** Function         btif_delete_headless_mode_wakeup_device
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_delete_headless_mode_wakeup_device(bt_bdaddr_t *remote_addr);

/*******************************************************************************
**
** Function         btif_bt_wake_up_test
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_bt_wake_up_test(void);

/*******************************************************************************
**
** Function         btif_bt_erase_patch_nvm
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_bt_erase_patch_nvm(void);

/*******************************************************************************
**
** Function         btif_bt_read_flash_burning_status
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_bt_read_flash_burning_status(void);

/*******************************************************************************
**
** Function         btif_read_last_memory
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_read_last_memory(void);

/*******************************************************************************
**
** Function         btif_set_headless_le_adv_data
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_set_headless_le_adv_data(bt_le_headless_adv_data param);

/*******************************************************************************
**
** Function         btif_set_headless_scan_configure
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_set_headless_scan_configure(uint16_t pscan_interval, uint16_t pscan_window_size,uint8_t pscan_mode);


#endif /* BTIF_API_H */
