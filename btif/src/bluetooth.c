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

/************************************************************************************
 *
 *  Filename:      bluetooth.c
 *
 *  Description:   Bluetooth HAL implementation
 *
 ***********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hardware/bluetooth.h>
#include <hardware/bt_hf.h>
#include <hardware/bt_hf_client.h>
#include <hardware/bt_av.h>
#include <hardware/bt_sock.h>
#include <hardware/bt_hh.h>
#include <hardware/bt_hl.h>
#include <hardware/bt_pan.h>
#include <hardware/bt_mce.h>
#include <hardware/bt_gatt.h>
#include <hardware/bt_rc.h>
#include <hardware/bt_3d.h>

#define LOG_NDDEBUG 0
#define LOG_TAG "bluedroid"

#include "btif_api.h"
#include "bt_utils.h"

/************************************************************************************
**  Constants & Macros
************************************************************************************/

#define is_profile(profile, str) ((strlen(str) == strlen(profile)) && strncmp((const char *)profile, str, strlen(str)) == 0)

/************************************************************************************
**  Local type definitions
************************************************************************************/

/************************************************************************************
**  Static variables
************************************************************************************/

bt_callbacks_t *bt_hal_cbacks;

/** Operating System specific callouts for resource management */
bt_os_callouts_t *bt_os_callouts;

/************************************************************************************
**  Static functions
************************************************************************************/

/************************************************************************************
**  Externs
************************************************************************************/

/* list all extended interfaces here */

/* handsfree profile */
extern bthf_interface_t *btif_hf_get_interface();
/* handsfree profile - client */
extern bthf_client_interface_t *btif_hf_client_get_interface();
/* advanced audio profile */
extern btav_interface_t *btif_av_get_src_interface();
extern btav_interface_t *btif_av_get_sink_interface();
/*rfc l2cap*/
extern btsock_interface_t *btif_sock_get_interface();
/* hid host profile */
extern bthh_interface_t *btif_hh_get_interface();
/* health device profile */
extern bthl_interface_t *btif_hl_get_interface();
/*pan*/
extern btpan_interface_t *btif_pan_get_interface();
/*map client*/
extern btmce_interface_t *btif_mce_get_interface();
#if BLE_INCLUDED == TRUE
/* gatt */
extern btgatt_interface_t *btif_gatt_get_interface();
#endif
/* avrc target */
extern btrc_interface_t *btif_rc_get_interface();
/* 3d */
extern bt3d_interface_t *btif_3d_get_interface();

/* avrc controller */
extern btrc_interface_t *btif_rc_ctrl_get_interface();

/************************************************************************************
**  Functions
************************************************************************************/

static uint8_t interface_ready(void)
{
    /* add checks here that would prevent API calls other than init to be executed */
    if (bt_hal_cbacks == NULL)
        return FALSE;

    return TRUE;
}


/*****************************************************************************
**
**   BLUETOOTH HAL INTERFACE FUNCTIONS
**
*****************************************************************************/

static int init(bt_callbacks_t* callbacks )
{
    ALOGI("###init");

    /* sanity check */
    if (interface_ready() == TRUE)
        return BT_STATUS_DONE;

    /* store reference to user callbacks */
    bt_hal_cbacks = callbacks;

    /* add checks for individual callbacks ? */

    bt_utils_init();

    /* init btif */
    btif_init_bluetooth();

    return BT_STATUS_SUCCESS;
}

static int enable( void )
{
    ALOGI("enable");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_enable_bluetooth();
}

static int disable(void)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_disable_bluetooth();
}

static void cleanup( void )
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return;

    btif_shutdown_bluetooth();

    /* hal callbacks reset upon shutdown complete callback */

    return;
}

static int get_adapter_properties(void)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_get_adapter_properties();
}

static int get_adapter_property(bt_property_type_t type)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_get_adapter_property(type);
}

static int set_adapter_property(const bt_property_t *property)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_set_adapter_property(property);
}

int get_remote_device_properties(bt_bdaddr_t *remote_addr)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_get_remote_device_properties(remote_addr);
}

int get_remote_device_property(bt_bdaddr_t *remote_addr, bt_property_type_t type)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_get_remote_device_property(remote_addr, type);
}

int set_remote_device_property(bt_bdaddr_t *remote_addr, const bt_property_t *property)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_set_remote_device_property(remote_addr, property);
}

int get_remote_service_record(bt_bdaddr_t *remote_addr, bt_uuid_t *uuid)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_get_remote_service_record(remote_addr, uuid);
}

int get_remote_services(bt_bdaddr_t *remote_addr)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dm_get_remote_services(remote_addr);
}

static int start_discovery(void)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dm_start_discovery();
}

static int cancel_discovery(void)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dm_cancel_discovery();
}

static int create_bond(const bt_bdaddr_t *bd_addr, int transport)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dm_create_bond(bd_addr, transport);
}

static int cancel_bond(const bt_bdaddr_t *bd_addr)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dm_cancel_bond(bd_addr);
}

static int remove_bond(const bt_bdaddr_t *bd_addr)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dm_remove_bond(bd_addr);
}

static int get_connection_state(const bt_bdaddr_t *bd_addr)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return 0;

    return btif_dm_get_connection_state(bd_addr);
}

static int pin_reply(const bt_bdaddr_t *bd_addr, uint8_t accept,
                 uint8_t pin_len, bt_pin_code_t *pin_code)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dm_pin_reply(bd_addr, accept, pin_len, pin_code);
}

static int ssp_reply(const bt_bdaddr_t *bd_addr, bt_ssp_variant_t variant,
                       uint8_t accept, uint32_t passkey)
{
    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dm_ssp_reply(bd_addr, variant, accept, passkey);
}

static int read_energy_info()
{
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;
    btif_dm_read_energy_info();
    return BT_STATUS_SUCCESS;
}

static const void* get_profile_interface (const char *profile_id)
{
    ALOGI("get_profile_interface %s", profile_id);

    /* sanity check */
    if (interface_ready() == FALSE)
        return NULL;

    /* check for supported profile interfaces */
    if (is_profile(profile_id, BT_PROFILE_HANDSFREE_ID))
        return btif_hf_get_interface();

    if (is_profile(profile_id, BT_PROFILE_HANDSFREE_CLIENT_ID))
        return btif_hf_client_get_interface();

    if (is_profile(profile_id, BT_PROFILE_SOCKETS_ID))
        return btif_sock_get_interface();

    if (is_profile(profile_id, BT_PROFILE_PAN_ID))
        return btif_pan_get_interface();

    if (is_profile(profile_id, BT_PROFILE_ADVANCED_AUDIO_ID))
        return btif_av_get_src_interface();

    if (is_profile(profile_id, BT_PROFILE_ADVANCED_AUDIO_SINK_ID))
        return btif_av_get_sink_interface();

    if (is_profile(profile_id, BT_PROFILE_HIDHOST_ID))
        return btif_hh_get_interface();

    if (is_profile(profile_id, BT_PROFILE_HEALTH_ID))
        return btif_hl_get_interface();

    if (is_profile(profile_id, BT_PROFILE_MAP_CLIENT_ID))
        return btif_mce_get_interface();

#if ( BTA_GATT_INCLUDED == TRUE && BLE_INCLUDED == TRUE)
    if (is_profile(profile_id, BT_PROFILE_GATT_ID))
        return btif_gatt_get_interface();
#endif

    if (is_profile(profile_id, BT_PROFILE_AV_RC_ID))
        return btif_rc_get_interface();

    if (is_profile(profile_id, BT_PROFILE_3D_SYNC_ID))
        return btif_3d_get_interface();

    if (is_profile(profile_id, BT_PROFILE_AV_RC_CTRL_ID))
        return btif_rc_ctrl_get_interface();

    return NULL;
}

int dut_mode_configure(uint8_t enable)
{
    ALOGI("dut_mode_configure");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dut_mode_configure(enable);
}

int dut_mode_send(uint16_t opcode, uint8_t* buf, uint8_t len)
{
    ALOGI("dut_mode_send");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_dut_mode_send(opcode, buf, len);
}

#if BLE_INCLUDED == TRUE
int le_test_mode(uint16_t opcode, uint8_t* buf, uint8_t len)
{
    ALOGI("le_test_mode");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_le_test_mode(opcode, buf, len);
}
#endif

int config_hci_snoop_log(uint8_t enable)
{
    ALOGI("config_hci_snoop_log");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_config_hci_snoop_log(enable);
}

static int set_os_callouts(bt_os_callouts_t *callouts) {
    bt_os_callouts = callouts;
    return BT_STATUS_SUCCESS;
}

#if HCI_RAW_CMD_INCLUDED == TRUE
int hci_cmd_send(uint16_t opcode, uint8_t* buf, uint8_t len)
{
    ALOGI("hci_cmd_send");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_hci_cmd_send(opcode, buf, len);
}
#endif

/** Enter Headless mode. This API shall work only if Bluetooth is enabled.*/
/** Do not see a need for exit_headless_mode as 'enable' API will called to wake up
   * from headless mode */
/** Note that the behavior of Bluedroid is undefined after this API is invoked
   * and the application process needs to be killed and restarted for any
   * Bluedroid APIs to have any meaningful effect. */
static int get_headless_device_list(void)
{
    ALOGI("get_headless_device_list");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_get_headless_device_list();
}

static int enter_headless_mode(uint8_t device_type)
{
    ALOGI("enter_headless_mode");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_enter_headless_mode(device_type);
}

/** Add Headless mode wake-up remote device. Should be a paired device */
static int add_headless_mode_wakeup_device(bt_bdaddr_t *remote_addr)
{
    int i;
    uint8_t vnd_bd_addr[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ALOGI("add_headless_mode_wakeup_device");
    BTIF_TRACE_ERROR("BD Address before: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                                         *((uint8_t *)remote_addr + (0)),
                                         *((uint8_t *)remote_addr + (1)),
                                         *((uint8_t *)remote_addr + (2)),
                                         *((uint8_t *)remote_addr + (3)),
                                         *((uint8_t *)remote_addr + (4)),
                                         *((uint8_t *)remote_addr + (5)));

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;
     if(remote_addr)
         for(i=0;i<6;i++)
		vnd_bd_addr[i] = *((uint8_t *)remote_addr + (5-i));

         BTIF_TRACE_ERROR("BD Address in little endian: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                                         vnd_bd_addr[0],
                                         vnd_bd_addr[1],
                                         vnd_bd_addr[2],
                                         vnd_bd_addr[3],
                                         vnd_bd_addr[4],
                                         vnd_bd_addr[5]);
	return btif_add_headless_mode_wakeup_device((bt_bdaddr_t *)vnd_bd_addr);
}

/** Add AV device to Headless table */
static int add_av_dev_to_headless_mode(bt_bdaddr_t *remote_addr)
{
    int i;
    uint8_t vnd_bd_addr[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ALOGI("add_av_dev_to_headless_mode");
    BTIF_TRACE_ERROR("BD Address before: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                                         *((uint8_t *)remote_addr + (0)),
                                         *((uint8_t *)remote_addr + (1)),
                                         *((uint8_t *)remote_addr + (2)),
                                         *((uint8_t *)remote_addr + (3)),
                                         *((uint8_t *)remote_addr + (4)),
                                         *((uint8_t *)remote_addr + (5)));

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;
     if(remote_addr)
         for(i=0;i<6;i++)
                vnd_bd_addr[i] = *((uint8_t *)remote_addr + (5-i));
         BTIF_TRACE_ERROR("BD Address in little endian: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                                         vnd_bd_addr[0],
                                         vnd_bd_addr[1],
                                         vnd_bd_addr[2],
                                         vnd_bd_addr[3],
                                         vnd_bd_addr[4],
                                         vnd_bd_addr[5]);

    return btif_add_av_dev_to_headless_mode((bt_bdaddr_t *)vnd_bd_addr);
}

/** Remove Headless mode wake-up remote device */
static int delete_headless_mode_wakeup_device(bt_bdaddr_t *remote_addr)
{
    int i;
    uint8_t vnd_bd_addr[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ALOGI("delete_headless_mode_wakeup_device");
    BTIF_TRACE_ERROR("BD Address before: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                                         *((uint8_t *)remote_addr + (0)),
                                         *((uint8_t *)remote_addr + (1)),
                                         *((uint8_t *)remote_addr + (2)),
                                         *((uint8_t *)remote_addr + (3)),
                                         *((uint8_t *)remote_addr + (4)),
                                         *((uint8_t *)remote_addr + (5)));

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;
     if(remote_addr)
         for(i=0;i<6;i++)
                vnd_bd_addr[i] = *((uint8_t *)remote_addr + (5-i));
         //ALOGI("%s: BD Address in little endian: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", __FUNCTION__,
         BTIF_TRACE_ERROR("BD Address in little endian: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", 
                                         vnd_bd_addr[0],
                                         vnd_bd_addr[1],
                                         vnd_bd_addr[2],
                                         vnd_bd_addr[3],
                                         vnd_bd_addr[4],
                                         vnd_bd_addr[5]);

    return btif_delete_headless_mode_wakeup_device((bt_bdaddr_t *)vnd_bd_addr);
}

/** Set Remote LLR scan mode */
static int set_remote_llr_mode(bt_bdaddr_t *remote_addr, llr_scan_mode mode)
{
	ALOGE("[Qualcomm]%s: Need to implemented!!!", __FUNCTION__);
	return BT_STATUS_UNSUPPORTED;
}

/** Set LE advertising data for Headless mode */
static int set_headless_le_adv_data(bt_le_headless_adv_data param)
{
    ALOGI("set_headless_le_adv_data");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_set_headless_le_adv_data(param);
}

/** configure scan mode for Headless mode */
static int set_headless_scan_configure(uint16_t pscan_interval, uint16_t
		pscan_window_size,uint8_t pscan_mode)
{

    ALOGI("set_headless_scan_configure");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_set_headless_scan_configure(pscan_interval,pscan_window_size,pscan_mode);

}

/* Upgrade the BT Chip firmware */
int hw_chip_firmware_update(void)
{
    return btif_hw_chip_firmware_update();
}

/** Read version */
static int read_version(btif_fw_version_t *ver)
{
    ALOGI("Read BT-chip FW version");
    ver->build = 0;
    ver->config = 100;
    ver->minor= 0;
    ver->major= 0;

    return btif_read_version(ver);
}


/** Dummy API for BT wake up test */
static void bt_wake_up_test(void)
{
    ALOGI("bt_wake_up_test");

    /* sanity check */
    if (interface_ready() == FALSE)
        return ;

    btif_bt_wake_up_test();
    return;
}

static void bt_erase_patch_nvm(void)
{
    ALOGI("bt_erase_patch_nvm");

    /* sanity check */
    if (interface_ready() == FALSE)
        return ;

    btif_bt_erase_patch_nvm();
    return;
}

static void bt_read_flash_burning_status(void)
{
    ALOGI("bt_read_flash_burning_status");

    /* sanity check */
    if (interface_ready() == FALSE)
        return ;

    btif_bt_read_flash_burning_status();
    return;
}

/* Sets the vid/pid infor for the primary DID record and writes to EIR data */
static int set_local_did(bt_local_di_record_t *local_di_record)
{
    BTIF_TRACE_DEBUG("%s",__FUNCTION__);

    tBTA_DI_RECORD rec;
    UINT32 rec_num=0;
    rec.vendor = local_di_record->vendor;
    rec.vendor_id_source = local_di_record->vendor_id_source;
    rec.product = local_di_record->product;
    rec.version = local_di_record->version;
    rec.primary_record = TRUE;
    if (BTA_DmSetLocalDiRecord(&rec, &rec_num) != BTA_SUCCESS)
    {
        ALOGE("%s:SetLocalDiInfo failed", __FUNCTION__);
    }
    BTA_DMUpdateEir();
    return BT_STATUS_SUCCESS;
}

static void read_last_memory(void)
{
    ALOGI("read_last_memory");

    /* sanity check */
    if (interface_ready() == FALSE)
        return ;

    btif_read_last_memory();
    return;
}

static int hogp_read_link_key(void *str)
{
    ALOGI("hogp_read_link_key");

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

    return btif_hogp_read_link_key(str);
}

static int hogp_set_scan_param(uint8_t scan_type,uint16_t scan_interval,
		uint16_t scan_window,uint8_t addr_type,uint8_t filter_policy)
{
    ALOGI("hogp_set_scan_param");
	hogp_le_scan_param_t param;

    /* sanity check */
    if (interface_ready() == FALSE)
        return BT_STATUS_NOT_READY;

	param.scan_type = scan_type;
	param.scan_interval = scan_interval;
	param.scan_window = scan_window;
	param.addr_type =  addr_type;
	param.filter_policy = filter_policy;

    return btif_hogp_set_scan_param(&param);
}

/** Configure LLR param */
static int set_host_llr_param(uint16_t host_scan_interval)
{
	ALOGE("[Qualcomm]%s: Need to implemented!!!", __FUNCTION__);
	return BT_STATUS_UNSUPPORTED;
}

/** Configure parameters for page scan and inquiry scan*/
static int set_scan_param(uint16_t page_scan_interval, uint16_t page_scan_window,
                          uint16_t inquiry_scan_interval, uint16_t inquiry_scan_window)

{
	ALOGE("[Qualcomm]%s: Need to implemented!!!", __FUNCTION__);
	return BT_STATUS_UNSUPPORTED;
}

/** Configure AFH channel which will be disabled */
static int set_afh_channel(uint8_t first, uint8_t last)
{
	ALOGE("[Qualcomm]%s: Need to implemented!!!", __FUNCTION__);
	return BT_STATUS_UNSUPPORTED;
}

/** Enter antenna isolation measure mode */
static int enter_antenna_isolation_test_mode(void)
{
	ALOGE("[Qualcomm]%s: Need to implemented!!!", __FUNCTION__);
	return BT_STATUS_UNSUPPORTED;
}

static const bt_interface_t bluetoothInterface = {
    sizeof(bluetoothInterface),
    init,
    enable,
    disable,
    cleanup,
    get_adapter_properties,
    get_adapter_property,
    set_adapter_property,
    get_remote_device_properties,
    get_remote_device_property,
    set_remote_device_property,
    get_remote_service_record,
    get_remote_services,
    start_discovery,
    cancel_discovery,
    create_bond,
    remove_bond,
    cancel_bond,
    get_connection_state,
    pin_reply,
    ssp_reply,
    get_profile_interface,
    dut_mode_configure,
    dut_mode_send,
#if BLE_INCLUDED == TRUE
    le_test_mode,
#else
    NULL,
#endif
    #if HCI_RAW_CMD_INCLUDED == TRUE
    hci_cmd_send,
    #endif
    config_hci_snoop_log,
    set_os_callouts,
    read_energy_info,
    .get_headless_device_list = get_headless_device_list,
    .enter_headless_mode = enter_headless_mode,
    .add_headless_mode_wakeup_device = add_headless_mode_wakeup_device,
    .add_av_dev_to_headless_mode = add_av_dev_to_headless_mode,
    .delete_headless_mode_wakeup_device = delete_headless_mode_wakeup_device,
    .set_remote_llr_mode = set_remote_llr_mode,
    .set_headless_le_adv_data = set_headless_le_adv_data,
    .set_headless_scan_configure = set_headless_scan_configure,
    .read_version = read_version,
    .bt_wake_up_test = bt_wake_up_test,
    .bt_erase_patch_nvm = bt_erase_patch_nvm,
    .bt_read_flash_burning_status = bt_read_flash_burning_status,
    .set_local_did = set_local_did,
    .read_last_memory = read_last_memory,
    .hogp_read_link_key = hogp_read_link_key,
    .hogp_set_scan_param = hogp_set_scan_param,
    .hw_chip_firmware_update = hw_chip_firmware_update
};

const bt_interface_t* bluetooth__get_bluetooth_interface ()
{
    /* fixme -- add property to disable bt interface ? */

    return &bluetoothInterface;
}

static int close_bluetooth_stack(struct hw_device_t* device)
{
    UNUSED(device);
    cleanup();
    return 0;
}

static int open_bluetooth_stack (const struct hw_module_t* module, char const* name,
                                 struct hw_device_t** abstraction)
{
    UNUSED(name);

    bluetooth_device_t *stack = malloc(sizeof(bluetooth_device_t) );
    memset(stack, 0, sizeof(bluetooth_device_t) );
    stack->common.tag = HARDWARE_DEVICE_TAG;
    stack->common.version = 0;
    stack->common.module = (struct hw_module_t*)module;
    stack->common.close = close_bluetooth_stack;
    stack->get_bluetooth_interface = bluetooth__get_bluetooth_interface;
    *abstraction = (struct hw_device_t*)stack;
    return 0;
}


static struct hw_module_methods_t bt_stack_module_methods = {
    .open = open_bluetooth_stack,
};

struct hw_module_t HAL_MODULE_INFO_SYM = {
    .tag = HARDWARE_MODULE_TAG,
    .version_major = 1,
    .version_minor = 0,
    .id = BT_HARDWARE_MODULE_ID,
    .name = "Bluetooth Stack",
    .author = "The Android Open Source Project",
    .methods = &bt_stack_module_methods
};

