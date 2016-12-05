/******************************************************************************
 *
 *  Copyright (c) 2015 Qualcomm Atheros, Inc.
 *  All Rights Reserved.
 *  Qualcomm Atheros Confidential and Proprietary.
 *  NOT A CONTRIBUTION
 *
 *  Copyright (C) 2014 The Android Open Source Project
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
 *  Filename:      btif_core.c
 *
 *  Description:   Contains core functionality related to interfacing between
 *                 Bluetooth HAL and BTE core stack.
 *
 ***********************************************************************************/

#include <stdlib.h>
#include <hardware/bluetooth.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <cutils/properties.h>
#include <hw_rome.h>

#define LOG_TAG "BTIF_CORE"
#include "btif_api.h"
#include "bt_utils.h"
#include "bta_api.h"
#include "gki.h"
#include "btu.h"
#include "bte.h"
#include "bd.h"
#include "btif_av.h"
#include "btif_storage.h"
#include "btif_util.h"
#include "btif_sock.h"
#include "btif_pan.h"
#include "btif_mce.h"
#include "btif_profile_queue.h"
#include "btif_config.h"
#include "bta_sys.h"
/************************************************************************************
**  Constants & Macros
************************************************************************************/

#ifndef BTIF_TASK_STACK_SIZE
#define BTIF_TASK_STACK_SIZE       0x2000         /* In bytes */
#endif

#ifndef BTE_DID_CONF_FILE
#define BTE_DID_CONF_FILE "/etc/bluetooth/bt_did.conf"
#endif

#define BTIF_TASK_STR        ((INT8 *) "BTIF")


#define RAMPATCH_DEFAULT_PATH "/lib/firmware/ar3k/rampatch_tlv_usb_npl_1.0.tlv"
#define RAMPATCH_UPGRADE_PATH "/lib/firmware/ar3k/rampatch_tlv_usb_npl_1.0_upgrade.tlv"
#define RAMPATCH_BACKUP_PATH "/lib/firmware/ar3k/rampatch_tlv_usb_npl_1.0_backup.tlv"

#define NVM_DEFAULT_PATH "/lib/firmware/ar3k/nvm_tlv_usb_npl_1.0.bin"
#define NVM_UPGRADE_PATH "/lib/firmware/ar3k/nvm_tlv_usb_npl_1.0_upgrade.bin"
#define NVM_BACKUP_PATH "/lib/firmware/ar3k/nvm_tlv_usb_npl_1.0_backup.bin"

/************************************************************************************
**  Local type definitions
************************************************************************************/

static BOOLEAN enter_headless_mode = FALSE;
extern BOOLEAN enable_test_mode ;
/* Save the Rampatch version of controller */
UINT16 fw_patch_version;
UINT8  upgrade_initiated;
/* Retrieving the patch info from upgrade file */
FILE *file;
unsigned char *phdr_buffer;
unsigned char *pdata_buffer = NULL;
unsigned char gTlv_type;


/* These type definitions are used when passing data from the HAL to BTIF context
*  in the downstream path for the adapter and remote_device property APIs */

typedef struct {
  bt_bdaddr_t bd_addr;
  bt_property_type_t type;
} btif_storage_read_t;

typedef struct {
  bt_bdaddr_t bd_addr;
  bt_property_t prop;
} btif_storage_write_t;

typedef union {
  btif_storage_read_t read_req;
  btif_storage_write_t write_req;
} btif_storage_req_t;

typedef enum {
    BTIF_CORE_STATE_DISABLED = 0,
    BTIF_CORE_STATE_ENABLING,
    BTIF_CORE_STATE_ENABLED,
    BTIF_CORE_STATE_DISABLING
} btif_core_state_t;

/************************************************************************************
**  Static variables
************************************************************************************/

bt_bdaddr_t btif_local_bd_addr;

static UINT32 btif_task_stack[(BTIF_TASK_STACK_SIZE + 3) / 4];

/* holds main adapter state */
static btif_core_state_t btif_core_state = BTIF_CORE_STATE_DISABLED;

static int btif_shutdown_pending = 0;
static tBTA_SERVICE_MASK btif_enabled_services = 0;

/*
* This variable should be set to 1, if the Bluedroid+BTIF libraries are to
* function in DUT mode.
*
* To set this, the btif_init_bluetooth needs to be called with argument as 1
*/
static UINT8 btif_dut_mode = 0;

/************************************************************************************
**  Static functions
************************************************************************************/
static bt_status_t btif_associate_evt(void);
static bt_status_t btif_disassociate_evt(void);

/* sends message to btif task */
static void btif_sendmsg(void *p_msg);
void save_bt_firmware_version_cback(UINT8 evt_len, UINT8 *p);
/************************************************************************************
**  Externs
************************************************************************************/
extern void bte_load_did_conf(const char *p_path);
extern BOOLEAN unconditional_patch_upgrade;

/** TODO: Move these to _common.h */
void bte_main_boot_entry(void);
void bte_main_enable();
void bte_main_disable(void);
void bte_main_shutdown(void);
#if (defined(HCILP_INCLUDED) && HCILP_INCLUDED == TRUE)
void bte_main_enable_lpm(BOOLEAN enable);
#endif
void bte_main_postload_cfg(void);
void btif_dm_execute_service_request(UINT16 event, char *p_param);
#ifdef BTIF_DM_OOB_TEST
void btif_dm_load_local_oob(void);
#endif
void bte_main_config_hci_logging(BOOLEAN enable, BOOLEAN bt_disabled);

/************************************************************************************
**  Functions
************************************************************************************/


/*****************************************************************************
**   Context switching functions
*****************************************************************************/


/*******************************************************************************
**
** Function         btif_context_switched
**
** Description      Callback used to execute transferred context callback
**
**                  p_msg : message to be executed in btif context
**
** Returns          void
**
*******************************************************************************/

static void btif_context_switched(void *p_msg)
{
    tBTIF_CONTEXT_SWITCH_CBACK *p;

    BTIF_TRACE_VERBOSE("btif_context_switched");

    p = (tBTIF_CONTEXT_SWITCH_CBACK *) p_msg;

    /* each callback knows how to parse the data */
    if (p->p_cb)
        p->p_cb(p->event, p->p_param);
}


/*******************************************************************************
**
** Function         btif_transfer_context
**
** Description      This function switches context to btif task
**
**                  p_cback   : callback used to process message in btif context
**                  event     : event id of message
**                  p_params  : parameter area passed to callback (copied)
**                  param_len : length of parameter area
**                  p_copy_cback : If set this function will be invoked for deep copy
**
** Returns          void
**
*******************************************************************************/

bt_status_t btif_transfer_context (tBTIF_CBACK *p_cback, UINT16 event, char* p_params, int param_len, tBTIF_COPY_CBACK *p_copy_cback)
{
    tBTIF_CONTEXT_SWITCH_CBACK *p_msg;

    BTIF_TRACE_VERBOSE("btif_transfer_context event %d, len %d", event, param_len);

    /* allocate and send message that will be executed in btif context */
    if ((p_msg = (tBTIF_CONTEXT_SWITCH_CBACK *) GKI_getbuf(sizeof(tBTIF_CONTEXT_SWITCH_CBACK) + param_len)) != NULL)
    {
        p_msg->hdr.event = BT_EVT_CONTEXT_SWITCH_EVT; /* internal event */
        p_msg->p_cb = p_cback;

        p_msg->event = event;                         /* callback event */

        /* check if caller has provided a copy callback to do the deep copy */
        if (p_copy_cback)
        {
            p_copy_cback(event, p_msg->p_param, p_params);
        }
        else if (p_params)
        {
            memcpy(p_msg->p_param, p_params, param_len);  /* callback parameter data */
        }

        btif_sendmsg(p_msg);
        return BT_STATUS_SUCCESS;
    }
    else
    {
        /* let caller deal with a failed allocation */
        return BT_STATUS_NOMEM;
    }
}

/*******************************************************************************
**
** Function         btif_is_dut_mode
**
** Description      checks if BTIF is currently in DUT mode
**
** Returns          1 if test mode, otherwize 0
**
*******************************************************************************/

UINT8 btif_is_dut_mode(void)
{
    return (btif_dut_mode == 1);
}

/*******************************************************************************
**
** Function         btif_is_enabled
**
** Description      checks if main adapter is fully enabled
**
** Returns          1 if fully enabled, otherwize 0
**
*******************************************************************************/

int btif_is_enabled(void)
{
    return ((!btif_is_dut_mode()) && (btif_core_state == BTIF_CORE_STATE_ENABLED));
}

/*******************************************************************************
**
** Function         btif_task
**
** Description      BTIF task handler managing all messages being passed
**                  Bluetooth HAL and BTA.
**
** Returns          void
**
*******************************************************************************/

static void btif_task(UINT32 params)
{
    UINT16   event;
    BT_HDR   *p_msg;
    UNUSED(params);

    BTIF_TRACE_DEBUG("btif task starting");

    btif_associate_evt();

    for(;;)
    {
        /* wait for specified events */
        event = GKI_wait(0xFFFF, 0);

        /*
         * Wait for the trigger to init chip and stack. This trigger will
         * be received by btu_task once the UART is opened and ready
         */
        if (event == BT_EVT_TRIGGER_STACK_INIT)
        {
            BTIF_TRACE_DEBUG("btif_task: received trigger stack init event");
            #if (BLE_INCLUDED == TRUE)
            btif_dm_load_ble_local_keys();
            #endif
            BTA_EnableBluetooth(bte_dm_evt);
        }

        /*
         * Failed to initialize controller hardware, reset state and bring
         * down all threads
         */
        if (event == BT_EVT_HARDWARE_INIT_FAIL)
        {
            BTIF_TRACE_DEBUG("btif_task: hardware init failed");
            bte_main_disable();
            btif_queue_release();
            GKI_task_self_cleanup(BTIF_TASK);
            bte_main_shutdown();
            btif_dut_mode = 0;
            btif_core_state = BTIF_CORE_STATE_DISABLED;
            HAL_CBACK(bt_hal_cbacks,adapter_state_changed_cb,BT_STATE_OFF);
            break;
        }

        if (event & EVENT_MASK(GKI_SHUTDOWN_EVT))
            break;

        if(event & TASK_MBOX_1_EVT_MASK)
        {
            while((p_msg = GKI_read_mbox(BTU_BTIF_MBOX)) != NULL)
            {
                BTIF_TRACE_VERBOSE("btif task fetched event %x", p_msg->event);

                switch (p_msg->event)
                {
                    case BT_EVT_CONTEXT_SWITCH_EVT:
                        btif_context_switched(p_msg);
                        break;
                    default:
                        BTIF_TRACE_ERROR("unhandled btif event (%d)", p_msg->event & BT_EVT_MASK);
                        break;
                }

                GKI_freebuf(p_msg);
            }
        }
    }

    btif_disassociate_evt();

    BTIF_TRACE_DEBUG("btif task exiting");
}


/*******************************************************************************
**
** Function         btif_sendmsg
**
** Description      Sends msg to BTIF task
**
** Returns          void
**
*******************************************************************************/

void btif_sendmsg(void *p_msg)
{
    GKI_send_msg(BTIF_TASK, BTU_BTIF_MBOX, p_msg);
}

static void btif_fetch_local_bdaddr(bt_bdaddr_t *local_addr)
{
    char val[256];
    uint8_t valid_bda = FALSE;
    int val_size = 0;
    const uint8_t null_bdaddr[BD_ADDR_LEN] = {0,0,0,0,0,0};

    /* Get local bdaddr storage path from property */
    if (property_get(PROPERTY_BT_BDADDR_PATH, val, NULL))
    {
        int addr_fd;

        BTIF_TRACE_DEBUG("local bdaddr is stored in %s", val);
        ALOGI("local bdaddr is stored in %s", val);

        if ((addr_fd = open(val, O_RDONLY)) != -1)
        {
            memset(val, 0, sizeof(val));
            read(addr_fd, val, FACTORY_BT_BDADDR_STORAGE_LEN);
            str2bd(val, local_addr);
            /* If this is not a reserved/special bda, then use it */
            if (memcmp(local_addr->address, null_bdaddr, BD_ADDR_LEN) != 0)
            {
                valid_bda = TRUE;
                BTIF_TRACE_ERROR("Got Factory BDA %02X:%02X:%02X:%02X:%02X:%02X",
                    local_addr->address[0], local_addr->address[1], local_addr->address[2],
                    local_addr->address[3], local_addr->address[4], local_addr->address[5]);
            }

            close(addr_fd);
        }
    }

    if(!valid_bda)
    {
        val_size = sizeof(val);
        if(btif_config_get_str("Local", "Adapter", "Address", val, &val_size))
        {
            str2bd(val, local_addr);
            BTIF_TRACE_ERROR("local bdaddr from bt_config.xml is  %s", val);
            return;
        }
     }

    /* No factory BDADDR found. Look for previously generated random BDA */
    if ((!valid_bda) && \
        (property_get(PERSIST_BDADDR_PROPERTY, val, NULL)))
    {
        str2bd(val, local_addr);
        valid_bda = TRUE;
        BTIF_TRACE_ERROR("Got prior random BDA %02X:%02X:%02X:%02X:%02X:%02X",
            local_addr->address[0], local_addr->address[1], local_addr->address[2],
            local_addr->address[3], local_addr->address[4], local_addr->address[5]);
    }

    /* Generate new BDA if necessary */
    if (!valid_bda)
    {
        bdstr_t bdstr;
        /* Seed the random number generator */
        srand((unsigned int) (time(0)));

        /* No autogen BDA. Generate one now. */
        local_addr->address[0] = 0x22;
        local_addr->address[1] = 0x22;
        local_addr->address[2] = (uint8_t) ((rand() >> 8) & 0xFF);
        local_addr->address[3] = (uint8_t) ((rand() >> 8) & 0xFF);
        local_addr->address[4] = (uint8_t) ((rand() >> 8) & 0xFF);
        local_addr->address[5] = (uint8_t) ((rand() >> 8) & 0xFF);

        /* Convert to ascii, and store as a persistent property */
        bd2str(local_addr, &bdstr);

        BTIF_TRACE_ERROR("No preset BDA. Generating BDA: %s for prop %s",
             (char*)bdstr, PERSIST_BDADDR_PROPERTY);

        if (property_set(PERSIST_BDADDR_PROPERTY, (char*)bdstr) < 0)
            BTIF_TRACE_ERROR("Failed to set random BDA in prop %s",PERSIST_BDADDR_PROPERTY);
    }

    //save the bd address to config file
    bdstr_t bdstr;
    bd2str(local_addr, &bdstr);
    val_size = sizeof(val);
    if (btif_config_get_str("Local", "Adapter", "Address", val, &val_size))
    {
        if (strcmp(bdstr, val) ==0)
        {
            // BDA is already present in the config file.
            return;
        }
    }
    btif_config_set_str("Local", "Adapter", "Address", bdstr);
    btif_config_save();
}

void btif_read_last_memory_vse_cback(UINT8 len, UINT8 *p)
{
	lpm_last_memory_data data;
	if(len == 49)
	{
		BTIF_TRACE_ERROR("%s: read last memory specific event", __FUNCTION__);
		STREAM_TO_BDADDR (&data.wlist_addr[0], p);
		STREAM_TO_BDADDR (&data.av_addr[0], p);
		STREAM_TO_UINT16 (data.pscan_interval, p);
		STREAM_TO_UINT16 (data.pscan_window_size, p);
		STREAM_TO_UINT8 (data.pscan_mode, p);
		STREAM_TO_ARRAY(data.le_adv_data,p,31);
		STREAM_TO_UINT8 (data.le_adv_data_len, p);
		HAL_CBACK(bt_hal_cbacks, lpm_read_last_memory_data_cb, data);
	}

}

/*****************************************************************************
**
**   btif core api functions
**
*****************************************************************************/

/*******************************************************************************
**
** Function         btif_init_bluetooth
**
** Description      Creates BTIF task and prepares BT scheduler for startup
**
** Returns          bt_status_t
**
*******************************************************************************/

bt_status_t btif_init_bluetooth()
{
    UINT8 status;
    btif_config_init();
    bte_main_boot_entry();

    /* As part of the init, fetch the local BD ADDR */
    memset(&btif_local_bd_addr, 0, sizeof(bt_bdaddr_t));
    btif_fetch_local_bdaddr(&btif_local_bd_addr);

    /* start btif task */
    status = GKI_create_task(btif_task, BTIF_TASK, BTIF_TASK_STR,
                (UINT16 *) ((UINT8 *)btif_task_stack + BTIF_TASK_STACK_SIZE),
                sizeof(btif_task_stack));

    if (status != GKI_SUCCESS)
        return BT_STATUS_FAIL;

	BTM_RegisterForVSEvents(btif_read_last_memory_vse_cback,TRUE);
    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_associate_evt
**
** Description      Event indicating btif_task is up
**                  Attach btif_task to JVM
**
** Returns          void
**
*******************************************************************************/

static bt_status_t btif_associate_evt(void)
{
    BTIF_TRACE_DEBUG("%s: notify ASSOCIATE_JVM", __FUNCTION__);
    HAL_CBACK(bt_hal_cbacks, thread_evt_cb, ASSOCIATE_JVM);

    return BT_STATUS_SUCCESS;
}


/*******************************************************************************
**
** Function         btif_enable_bluetooth
**
** Description      Performs chip power on and kickstarts OS scheduler
**
** Returns          bt_status_t
**
*******************************************************************************/

bt_status_t btif_enable_bluetooth(void)
{
    BTIF_TRACE_DEBUG("BTIF ENABLE BLUETOOTH");

    if (btif_core_state != BTIF_CORE_STATE_DISABLED)
    {
        ALOGD("not disabled\n");
        return BT_STATUS_DONE;
    }

    btif_core_state = BTIF_CORE_STATE_ENABLING;

    /* Create the GKI tasks and run them */
    bte_main_enable();

    return BT_STATUS_SUCCESS;
}


/*******************************************************************************
**
** Function         btif_enable_bluetooth_evt
**
** Description      Event indicating bluetooth enable is completed
**                  Notifies HAL user with updated adapter state
**
** Returns          void
**
*******************************************************************************/

void btif_enable_bluetooth_evt(tBTA_STATUS status, BD_ADDR local_bd)
{
    bt_bdaddr_t bd_addr;
    bdstr_t bdstr;

    bdcpy(bd_addr.address, local_bd);
    BTIF_TRACE_DEBUG("%s: status %d, local bd [%s]", __FUNCTION__, status,
                                                     bd2str(&bd_addr, &bdstr));

    BTIF_TRACE_ERROR("%s: BTIF READ VERSION", __FUNCTION__);
    btif_read_version_internal();
    if (bdcmp(btif_local_bd_addr.address,local_bd))
    {
        bdstr_t buf;
        bt_property_t prop;

        /**
         * The Controller's BDADDR does not match to the BTIF's initial BDADDR!
         * This could be because the factory BDADDR was stored separatley in
         * the Controller's non-volatile memory rather than in device's file
         * system.
         **/
        BTIF_TRACE_WARNING("***********************************************");
        BTIF_TRACE_WARNING("BTIF init BDA was %02X:%02X:%02X:%02X:%02X:%02X",
            btif_local_bd_addr.address[0], btif_local_bd_addr.address[1],
            btif_local_bd_addr.address[2], btif_local_bd_addr.address[3],
            btif_local_bd_addr.address[4], btif_local_bd_addr.address[5]);
        BTIF_TRACE_WARNING("Controller BDA is %02X:%02X:%02X:%02X:%02X:%02X",
            local_bd[0], local_bd[1], local_bd[2],
            local_bd[3], local_bd[4], local_bd[5]);
        BTIF_TRACE_WARNING("***********************************************");

        bdcpy(btif_local_bd_addr.address, local_bd);

        //save the bd address to config file
        bd2str(&btif_local_bd_addr, &buf);
        btif_config_set_str("Local", "Adapter", "Address", buf);
        btif_config_save();

        //fire HAL callback for property change
        memcpy(buf, &btif_local_bd_addr, sizeof(bt_bdaddr_t));
        prop.type = BT_PROPERTY_BDADDR;
        prop.val = (void*)buf;
        prop.len = sizeof(bt_bdaddr_t);
        HAL_CBACK(bt_hal_cbacks, adapter_properties_cb, BT_STATUS_SUCCESS, 1, &prop);
    }

    bte_main_postload_cfg();
#if (defined(HCILP_INCLUDED) && HCILP_INCLUDED == TRUE)
    bte_main_enable_lpm(TRUE);
#endif
    /* add passing up bd address as well ? */

    /* callback to HAL */
    if (status == BTA_SUCCESS)
    {
        /* initialize a2dp service */
        btif_av_init();

        /* init rfcomm & l2cap api */
        btif_sock_init();

        /* init pan */
        btif_pan_init();

        /* load did configuration */
        bte_load_did_conf(BTE_DID_CONF_FILE);

#ifdef BTIF_DM_OOB_TEST
        btif_dm_load_local_oob();
#endif
        /* now fully enabled, update state */
        btif_core_state = BTIF_CORE_STATE_ENABLED;

        HAL_CBACK(bt_hal_cbacks, adapter_state_changed_cb, BT_STATE_ON);
    }
    else
    {
        /* cleanup rfcomm & l2cap api */
        btif_sock_cleanup();

        btif_pan_cleanup();

        /* we failed to enable, reset state */
        btif_core_state = BTIF_CORE_STATE_DISABLED;

        HAL_CBACK(bt_hal_cbacks, adapter_state_changed_cb, BT_STATE_OFF);
    }
}

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
bt_status_t btif_disable_bluetooth(void)
{
    tBTA_STATUS status;

    if (!btif_is_enabled())
    {
        BTIF_TRACE_ERROR("btif_disable_bluetooth : not yet enabled");
        return BT_STATUS_NOT_READY;
    }

    BTIF_TRACE_DEBUG("BTIF DISABLE BLUETOOTH");

    btif_dm_on_disable();
    btif_core_state = BTIF_CORE_STATE_DISABLING;

    /* cleanup rfcomm & l2cap api */
    btif_sock_cleanup();

    btif_pan_cleanup();

    status = BTA_DisableBluetooth();

    btif_config_flush();

    if (status != BTA_SUCCESS)
    {
        BTIF_TRACE_ERROR("disable bt failed (%d)", status);

        /* reset the original state to allow attempting disable again */
        btif_core_state = BTIF_CORE_STATE_ENABLED;

        return BT_STATUS_FAIL;
    }
    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_disable_bluetooth_evt
**
** Description      Event notifying BT disable is now complete.
**                  Terminates main stack tasks and notifies HAL
**                  user with updated BT state.
**
** Returns          void
**
*******************************************************************************/

void btif_disable_bluetooth_evt(void)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

#if (defined(HCILP_INCLUDED) && HCILP_INCLUDED == TRUE)
    bte_main_enable_lpm(FALSE);
#endif

#if (BLE_INCLUDED == TRUE)
     BTA_VendorCleanup();
#endif

     bte_main_disable();

    /* update local state */
    btif_core_state = BTIF_CORE_STATE_DISABLED;

    /* callback to HAL */
    HAL_CBACK(bt_hal_cbacks, adapter_state_changed_cb, BT_STATE_OFF);

    if (btif_shutdown_pending)
    {
        BTIF_TRACE_DEBUG("%s: calling btif_shutdown_bluetooth", __FUNCTION__);
        btif_shutdown_bluetooth();
    }
}


/*******************************************************************************
**
** Function         btif_shutdown_bluetooth
**
** Description      Finalizes BT scheduler shutdown and terminates BTIF
**                  task.
**
** Returns          void
**
*******************************************************************************/

bt_status_t btif_shutdown_bluetooth(void)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    if (btif_core_state == BTIF_CORE_STATE_DISABLING)
    {
        BTIF_TRACE_WARNING("shutdown during disabling");
        /* shutdown called before disabling is done */
        btif_shutdown_pending = 1;
        return BT_STATUS_NOT_READY;
    }

    if (btif_is_enabled())
    {
        BTIF_TRACE_WARNING("shutdown while still enabled, initiate disable");

        /* shutdown called prior to disabling, initiate disable */
        btif_disable_bluetooth();
        btif_shutdown_pending = 1;
        return BT_STATUS_NOT_READY;
    }

    btif_shutdown_pending = 0;

    if (btif_core_state == BTIF_CORE_STATE_ENABLING)
    {
        // Java layer abort BT ENABLING, could be due to ENABLE TIMEOUT
        // Direct call from cleanup()@bluetooth.c
        // bring down HCI/Vendor lib
        bte_main_disable();
        btif_core_state = BTIF_CORE_STATE_DISABLED;
        HAL_CBACK(bt_hal_cbacks, adapter_state_changed_cb, BT_STATE_OFF);
    }

    GKI_destroy_task(BTIF_TASK);
    btif_queue_release();
    bte_main_shutdown();

    btif_dut_mode = 0;

    bt_utils_cleanup();

    BTIF_TRACE_DEBUG("%s done", __FUNCTION__);

    return BT_STATUS_SUCCESS;
}


/*******************************************************************************
**
** Function         btif_disassociate_evt
**
** Description      Event indicating btif_task is going down
**                  Detach btif_task to JVM
**
** Returns          void
**
*******************************************************************************/

static bt_status_t btif_disassociate_evt(void)
{
    BTIF_TRACE_DEBUG("%s: notify DISASSOCIATE_JVM", __FUNCTION__);

    HAL_CBACK(bt_hal_cbacks, thread_evt_cb, DISASSOCIATE_JVM);

    /* shutdown complete, all events notified and we reset HAL callbacks */
    bt_hal_cbacks = NULL;

    return BT_STATUS_SUCCESS;
}

/****************************************************************************
**
**   BTIF Test Mode APIs
**
*****************************************************************************/
/*******************************************************************************
**
** Function         btif_dut_mode_cback
**
** Description     Callback invoked on completion of vendor specific test mode command
**
** Returns          None
**
*******************************************************************************/
static void btif_dut_mode_cback( tBTM_VSC_CMPL *p )
{
    UNUSED(p);
    /* For now nothing to be done. */
}

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
bt_status_t btif_dut_mode_configure(uint8_t enable)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    if (btif_core_state != BTIF_CORE_STATE_ENABLED) {
        BTIF_TRACE_ERROR("btif_dut_mode_configure : Bluetooth not enabled");
        return BT_STATUS_NOT_READY;
    }

    btif_dut_mode = enable;
    if (enable == 1) {
        BTA_EnableTestMode();
    } else {
        BTA_DisableTestMode();
    }
    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_dut_mode_send
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_dut_mode_send(uint16_t opcode, uint8_t *buf, uint8_t len)
{
    /* TODO: Check that opcode is a vendor command group */
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);
    if (!btif_is_dut_mode()) {
         BTIF_TRACE_ERROR("Bluedroid HAL needs to be init with test_mode set to 1.");
         return BT_STATUS_FAIL;
    }
    BTM_VendorSpecificCommand(opcode, len, buf, btif_dut_mode_cback);
    return BT_STATUS_SUCCESS;
}

/*****************************************************************************
**
**   btif api adapter property functions
**
*****************************************************************************/

static bt_status_t btif_in_get_adapter_properties(void)
{
    bt_property_t properties[6];
    uint32_t num_props;

    bt_bdaddr_t addr;
    bt_bdname_t name;
    bt_scan_mode_t mode;
    uint32_t disc_timeout;
    bt_bdaddr_t bonded_devices[BTM_SEC_MAX_DEVICE_RECORDS];
    bt_uuid_t local_uuids[BT_MAX_NUM_UUIDS];
    num_props = 0;

    /* BD_ADDR */
    BTIF_STORAGE_FILL_PROPERTY(&properties[num_props], BT_PROPERTY_BDADDR,
                               sizeof(addr), &addr);
    btif_storage_get_adapter_property(&properties[num_props]);
    num_props++;

    /* BD_NAME */
    BTIF_STORAGE_FILL_PROPERTY(&properties[num_props], BT_PROPERTY_BDNAME,
                               sizeof(name), &name);
    btif_storage_get_adapter_property(&properties[num_props]);
    num_props++;

    /* SCAN_MODE */
    BTIF_STORAGE_FILL_PROPERTY(&properties[num_props], BT_PROPERTY_ADAPTER_SCAN_MODE,
                               sizeof(mode), &mode);
    btif_storage_get_adapter_property(&properties[num_props]);
    num_props++;

    /* DISC_TIMEOUT */
    BTIF_STORAGE_FILL_PROPERTY(&properties[num_props], BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
                               sizeof(disc_timeout), &disc_timeout);
    btif_storage_get_adapter_property(&properties[num_props]);
    num_props++;

    /* BONDED_DEVICES */
    BTIF_STORAGE_FILL_PROPERTY(&properties[num_props], BT_PROPERTY_ADAPTER_BONDED_DEVICES,
                               sizeof(bonded_devices), bonded_devices);
    btif_storage_get_adapter_property(&properties[num_props]);
    num_props++;

    /* LOCAL UUIDs */
    BTIF_STORAGE_FILL_PROPERTY(&properties[num_props], BT_PROPERTY_UUIDS,
                               sizeof(local_uuids), local_uuids);
    btif_storage_get_adapter_property(&properties[num_props]);
    num_props++;

    HAL_CBACK(bt_hal_cbacks, adapter_properties_cb,
                     BT_STATUS_SUCCESS, num_props, properties);

    return BT_STATUS_SUCCESS;
}

static bt_status_t btif_in_get_remote_device_properties(bt_bdaddr_t *bd_addr)
{
    bt_property_t remote_properties[8];
    uint32_t num_props = 0;

    bt_bdname_t name, alias;
    uint32_t cod, devtype;
    bt_uuid_t remote_uuids[BT_MAX_NUM_UUIDS];

    memset(remote_properties, 0, sizeof(remote_properties));
    BTIF_STORAGE_FILL_PROPERTY(&remote_properties[num_props], BT_PROPERTY_BDNAME,
                               sizeof(name), &name);
    btif_storage_get_remote_device_property(bd_addr,
                                            &remote_properties[num_props]);
    num_props++;

    BTIF_STORAGE_FILL_PROPERTY(&remote_properties[num_props], BT_PROPERTY_REMOTE_FRIENDLY_NAME,
                               sizeof(alias), &alias);
    btif_storage_get_remote_device_property(bd_addr,
                                            &remote_properties[num_props]);
    num_props++;

    BTIF_STORAGE_FILL_PROPERTY(&remote_properties[num_props], BT_PROPERTY_CLASS_OF_DEVICE,
                               sizeof(cod), &cod);
    btif_storage_get_remote_device_property(bd_addr,
                                            &remote_properties[num_props]);
    num_props++;

    BTIF_STORAGE_FILL_PROPERTY(&remote_properties[num_props], BT_PROPERTY_TYPE_OF_DEVICE,
                               sizeof(devtype), &devtype);
    btif_storage_get_remote_device_property(bd_addr,
                                            &remote_properties[num_props]);
    num_props++;

    BTIF_STORAGE_FILL_PROPERTY(&remote_properties[num_props], BT_PROPERTY_UUIDS,
                               sizeof(remote_uuids), remote_uuids);
    btif_storage_get_remote_device_property(bd_addr,
                                            &remote_properties[num_props]);
    num_props++;

    HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb,
                     BT_STATUS_SUCCESS, bd_addr, num_props, remote_properties);

    return BT_STATUS_SUCCESS;
}


/*******************************************************************************
**
** Function         execute_storage_request
**
** Description      Executes adapter storage request in BTIF context
**
** Returns          bt_status_t
**
*******************************************************************************/

static void execute_storage_request(UINT16 event, char *p_param)
{
    uint8_t is_local;
    int num_entries = 0;
    bt_status_t status = BT_STATUS_SUCCESS;

    BTIF_TRACE_EVENT("execute storage request event : %d", event);

    switch(event)
    {
        case BTIF_CORE_STORAGE_ADAPTER_WRITE:
        {
            btif_storage_req_t *p_req = (btif_storage_req_t*)p_param;
            bt_property_t *p_prop = &(p_req->write_req.prop);
            BTIF_TRACE_EVENT("type: %d, len %d, 0x%x", p_prop->type,
                               p_prop->len, p_prop->val);

            status = btif_storage_set_adapter_property(p_prop);
            HAL_CBACK(bt_hal_cbacks, adapter_properties_cb, status, 1, p_prop);
        } break;

        case BTIF_CORE_STORAGE_ADAPTER_READ:
        {
            btif_storage_req_t *p_req = (btif_storage_req_t*)p_param;
            char buf[512];
            bt_property_t prop;
            prop.type = p_req->read_req.type;
            prop.val = (void*)buf;
            prop.len = sizeof(buf);
            if (prop.type == BT_PROPERTY_LOCAL_LE_FEATURES)
            {
                #if (BLE_INCLUDED == TRUE)
                tBTM_BLE_VSC_CB cmn_vsc_cb;
                bt_local_le_features_t local_le_features;

                /* LE features are not stored in storage. Should be retrived from stack */
                BTM_BleGetVendorCapabilities(&cmn_vsc_cb);
                local_le_features.local_privacy_enabled = BTM_BleLocalPrivacyEnabled();

                prop.len = sizeof (bt_local_le_features_t);
                if (cmn_vsc_cb.filter_support == 1)
                    local_le_features.max_adv_filter_supported = cmn_vsc_cb.max_filter;
                else
                    local_le_features.max_adv_filter_supported = 0;
                local_le_features.max_adv_instance = cmn_vsc_cb.adv_inst_max;
                local_le_features.max_irk_list_size = cmn_vsc_cb.max_irk_list_sz;
                local_le_features.rpa_offload_supported = cmn_vsc_cb.rpa_offloading;
                local_le_features.scan_result_storage_size_hibyte =
                    (cmn_vsc_cb.tot_scan_results_strg >> 8) & (0xFF);
                local_le_features.scan_result_storage_size_lobyte =
                    (cmn_vsc_cb.tot_scan_results_strg) & (0xFF);
                local_le_features.activity_energy_info_supported = cmn_vsc_cb.energy_support;
                memcpy(prop.val, &local_le_features, prop.len);
                #endif
            }
            else
            {
                status = btif_storage_get_adapter_property(&prop);
            }
            HAL_CBACK(bt_hal_cbacks, adapter_properties_cb, status, 1, &prop);
        } break;

        case BTIF_CORE_STORAGE_ADAPTER_READ_ALL:
        {
            status = btif_in_get_adapter_properties();
        } break;

        case BTIF_CORE_STORAGE_NOTIFY_STATUS:
        {
            HAL_CBACK(bt_hal_cbacks, adapter_properties_cb, status, 0, NULL);
        } break;

        default:
            BTIF_TRACE_ERROR("%s invalid event id (%d)", __FUNCTION__, event);
            break;
    }
}

static void execute_storage_remote_request(UINT16 event, char *p_param)
{
    bt_status_t status = BT_STATUS_FAIL;
    bt_property_t prop;

    BTIF_TRACE_EVENT("execute storage remote request event : %d", event);

    switch (event)
    {
        case BTIF_CORE_STORAGE_REMOTE_READ:
        {
            char buf[1024];
            btif_storage_req_t *p_req = (btif_storage_req_t*)p_param;
            prop.type = p_req->read_req.type;
            prop.val = (void*) buf;
            prop.len = sizeof(buf);

            status = btif_storage_get_remote_device_property(&(p_req->read_req.bd_addr),
                                                             &prop);
            HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb,
                            status, &(p_req->read_req.bd_addr), 1, &prop);
        }break;
        case BTIF_CORE_STORAGE_REMOTE_WRITE:
        {
           btif_storage_req_t *p_req = (btif_storage_req_t*)p_param;
           status = btif_storage_set_remote_device_property(&(p_req->write_req.bd_addr),
                                                            &(p_req->write_req.prop));
        }break;
        case BTIF_CORE_STORAGE_REMOTE_READ_ALL:
        {
           btif_storage_req_t *p_req = (btif_storage_req_t*)p_param;
           btif_in_get_remote_device_properties(&p_req->read_req.bd_addr);
        }break;
    }
}

void btif_adapter_properties_evt(bt_status_t status, uint32_t num_props,
                                    bt_property_t *p_props)
{
    HAL_CBACK(bt_hal_cbacks, adapter_properties_cb,
                     status, num_props, p_props);

}
void btif_remote_properties_evt(bt_status_t status, bt_bdaddr_t *remote_addr,
                                   uint32_t num_props, bt_property_t *p_props)
{
    HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb,
                     status, remote_addr, num_props, p_props);
}

/*******************************************************************************
**
** Function         btif_in_storage_request_copy_cb
**
** Description     Switch context callback function to perform the deep copy for
**                 both the adapter and remote_device property API
**
** Returns          None
**
*******************************************************************************/
static void btif_in_storage_request_copy_cb(UINT16 event,
                                                 char *p_new_buf, char *p_old_buf)
{
     btif_storage_req_t *new_req = (btif_storage_req_t*)p_new_buf;
     btif_storage_req_t *old_req = (btif_storage_req_t*)p_old_buf;

     BTIF_TRACE_EVENT("%s", __FUNCTION__);
     switch (event)
     {
         case BTIF_CORE_STORAGE_REMOTE_WRITE:
         case BTIF_CORE_STORAGE_ADAPTER_WRITE:
         {
             bdcpy(new_req->write_req.bd_addr.address, old_req->write_req.bd_addr.address);
             /* Copy the member variables one at a time */
             new_req->write_req.prop.type = old_req->write_req.prop.type;
             new_req->write_req.prop.len = old_req->write_req.prop.len;

             new_req->write_req.prop.val = (UINT8 *)(p_new_buf + sizeof(btif_storage_req_t));
             memcpy(new_req->write_req.prop.val, old_req->write_req.prop.val,
                    old_req->write_req.prop.len);
         }break;
     }
}

/*******************************************************************************
**
** Function         btif_get_adapter_properties
**
** Description      Fetch all available properties (local & remote)
**
** Returns          bt_status_t
**
*******************************************************************************/

bt_status_t btif_get_adapter_properties(void)
{
    BTIF_TRACE_EVENT("%s", __FUNCTION__);

    if (!btif_is_enabled())
        return BT_STATUS_NOT_READY;

    return btif_transfer_context(execute_storage_request,
                                 BTIF_CORE_STORAGE_ADAPTER_READ_ALL,
                                 NULL, 0, NULL);
}

/*******************************************************************************
**
** Function         btif_get_adapter_property
**
** Description      Fetches property value from local cache
**
** Returns          bt_status_t
**
*******************************************************************************/

bt_status_t btif_get_adapter_property(bt_property_type_t type)
{
    btif_storage_req_t req;

    BTIF_TRACE_EVENT("%s %d", __FUNCTION__, type);

    /* Allow get_adapter_property only for BDADDR and BDNAME if BT is disabled */
    if (!btif_is_enabled() && (type != BT_PROPERTY_BDADDR) && (type != BT_PROPERTY_BDNAME))
        return BT_STATUS_NOT_READY;

    memset(&(req.read_req.bd_addr), 0, sizeof(bt_bdaddr_t));
    req.read_req.type = type;

    return btif_transfer_context(execute_storage_request,
                                 BTIF_CORE_STORAGE_ADAPTER_READ,
                                (char*)&req, sizeof(btif_storage_req_t), NULL);
}

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

bt_status_t btif_set_adapter_property(const bt_property_t *property)
{
    btif_storage_req_t req;
    bt_status_t status = BT_STATUS_SUCCESS;
    int storage_req_id = BTIF_CORE_STORAGE_NOTIFY_STATUS; /* default */
    char bd_name[BTM_MAX_LOC_BD_NAME_LEN +1];
    UINT16  name_len = 0;

    BTIF_TRACE_EVENT("btif_set_adapter_property type: %d, len %d, 0x%x",
                      property->type, property->len, property->val);

    if (!btif_is_enabled())
        return BT_STATUS_NOT_READY;

    switch(property->type)
    {
        case BT_PROPERTY_BDNAME:
            {
                name_len = property->len > BTM_MAX_LOC_BD_NAME_LEN ? BTM_MAX_LOC_BD_NAME_LEN:
                                                                     property->len;
                memcpy(bd_name,property->val, name_len);
                bd_name[name_len] = '\0';

                BTIF_TRACE_EVENT("set property name : %s", (char *)bd_name);

                BTA_DmSetDeviceName((char *)bd_name);

                storage_req_id = BTIF_CORE_STORAGE_ADAPTER_WRITE;
            }
            break;

        case BT_PROPERTY_ADAPTER_SCAN_MODE:
            {
                bt_scan_mode_t mode = *(bt_scan_mode_t*)property->val;
                tBTA_DM_DISC disc_mode;
                tBTA_DM_CONN conn_mode;

                switch(mode)
                {
                    case BT_SCAN_MODE_NONE:
                        disc_mode = BTA_DM_NON_DISC;
                        conn_mode = BTA_DM_NON_CONN;
                        break;

                    case BT_SCAN_MODE_CONNECTABLE:
                        disc_mode = BTA_DM_NON_DISC;
                        conn_mode = BTA_DM_CONN;
                        break;

                    case BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE:
                        disc_mode = BTA_DM_GENERAL_DISC;
                        conn_mode = BTA_DM_CONN;
                        break;

                    default:
                        BTIF_TRACE_ERROR("invalid scan mode (0x%x)", mode);
                        return BT_STATUS_PARM_INVALID;
                }

                BTIF_TRACE_EVENT("set property scan mode : %x", mode);

                BTA_DmSetVisibility(disc_mode, conn_mode, BTA_DM_IGNORE, BTA_DM_IGNORE);

                storage_req_id = BTIF_CORE_STORAGE_ADAPTER_WRITE;
            }
            break;
        case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
            {
                /* Nothing to do beside store the value in NV.  Java
                   will change the SCAN_MODE property after setting timeout,
                   if required */
                storage_req_id = BTIF_CORE_STORAGE_ADAPTER_WRITE;
            }
            break;
        case BT_PROPERTY_BDADDR:
        case BT_PROPERTY_UUIDS:
        case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
        case BT_PROPERTY_REMOTE_FRIENDLY_NAME:
            /* no write support through HAL, these properties are only populated from BTA events */
            status = BT_STATUS_FAIL;
            break;
        default:
            BTIF_TRACE_ERROR("btif_get_adapter_property : invalid type %d",
            property->type);
            status = BT_STATUS_FAIL;
            break;
    }

    if (storage_req_id != BTIF_CORE_STORAGE_NO_ACTION)
    {
        int btif_status;
        /* pass on to storage for updating local database */

        memset(&(req.write_req.bd_addr), 0, sizeof(bt_bdaddr_t));
        memcpy(&(req.write_req.prop), property, sizeof(bt_property_t));

        return btif_transfer_context(execute_storage_request,
                                     storage_req_id,
                                     (char*)&req,
                                     sizeof(btif_storage_req_t)+property->len,
                                     btif_in_storage_request_copy_cb);
    }

    return status;

}

/*******************************************************************************
**
** Function         btif_get_remote_device_property
**
** Description      Fetches the remote device property from the NVRAM
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_get_remote_device_property(bt_bdaddr_t *remote_addr,
                                                 bt_property_type_t type)
{
    btif_storage_req_t req;

    if (!btif_is_enabled())
        return BT_STATUS_NOT_READY;

    memcpy(&(req.read_req.bd_addr), remote_addr, sizeof(bt_bdaddr_t));
    req.read_req.type = type;
    return btif_transfer_context(execute_storage_remote_request,
                                 BTIF_CORE_STORAGE_REMOTE_READ,
                                 (char*)&req, sizeof(btif_storage_req_t),
                                 NULL);
}

/*******************************************************************************
**
** Function         btif_get_remote_device_properties
**
** Description      Fetches all the remote device properties from NVRAM
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_get_remote_device_properties(bt_bdaddr_t *remote_addr)
{
    btif_storage_req_t req;

    if (!btif_is_enabled())
        return BT_STATUS_NOT_READY;

    memcpy(&(req.read_req.bd_addr), remote_addr, sizeof(bt_bdaddr_t));
    return btif_transfer_context(execute_storage_remote_request,
                                 BTIF_CORE_STORAGE_REMOTE_READ_ALL,
                                 (char*)&req, sizeof(btif_storage_req_t),
                                 NULL);
}

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
bt_status_t btif_set_remote_device_property(bt_bdaddr_t *remote_addr,
                                                 const bt_property_t *property)
{
    btif_storage_req_t req;

    if (!btif_is_enabled())
        return BT_STATUS_NOT_READY;

    memcpy(&(req.write_req.bd_addr), remote_addr, sizeof(bt_bdaddr_t));
    memcpy(&(req.write_req.prop), property, sizeof(bt_property_t));

    return btif_transfer_context(execute_storage_remote_request,
                                 BTIF_CORE_STORAGE_REMOTE_WRITE,
                                 (char*)&req,
                                 sizeof(btif_storage_req_t)+property->len,
                                 btif_in_storage_request_copy_cb);
}


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
bt_status_t btif_get_remote_service_record(bt_bdaddr_t *remote_addr,
                                               bt_uuid_t *uuid)
{
    if (!btif_is_enabled())
        return BT_STATUS_NOT_READY;

    return btif_dm_get_remote_service_record(remote_addr, uuid);
}


/*******************************************************************************
**
** Function         btif_get_enabled_services_mask
**
** Description      Fetches currently enabled services
**
** Returns          tBTA_SERVICE_MASK
**
*******************************************************************************/

tBTA_SERVICE_MASK btif_get_enabled_services_mask(void)
{
    return btif_enabled_services;
}

/*******************************************************************************
**
** Function         btif_enable_service
**
** Description      Enables the service 'service_ID' to the service_mask.
**                  Upon BT enable, BTIF core shall invoke the BTA APIs to
**                  enable the profiles
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_enable_service(tBTA_SERVICE_ID service_id)
{
    tBTA_SERVICE_ID *p_id = &service_id;

    /* If BT is enabled, we need to switch to BTIF context and trigger the
     * enable for that profile
     *
     * Otherwise, we just set the flag. On BT_Enable, the DM will trigger
     * enable for the profiles that have been enabled */

    btif_enabled_services |= (1 << service_id);

    BTIF_TRACE_DEBUG("%s: current services:0x%x", __FUNCTION__, btif_enabled_services);

    if (btif_is_enabled())
    {
        btif_transfer_context(btif_dm_execute_service_request,
                              BTIF_DM_ENABLE_SERVICE,
                              (char*)p_id, sizeof(tBTA_SERVICE_ID), NULL);
    }

    return BT_STATUS_SUCCESS;
}
/*******************************************************************************
**
** Function         btif_disable_service
**
** Description      Disables the service 'service_ID' to the service_mask.
**                  Upon BT disable, BTIF core shall invoke the BTA APIs to
**                  disable the profiles
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_disable_service(tBTA_SERVICE_ID service_id)
{
    tBTA_SERVICE_ID *p_id = &service_id;

    /* If BT is enabled, we need to switch to BTIF context and trigger the
     * disable for that profile so that the appropriate uuid_property_changed will
     * be triggerred. Otherwise, we just need to clear the service_id in the mask
     */

    btif_enabled_services &=  (tBTA_SERVICE_MASK)(~(1<<service_id));

    BTIF_TRACE_DEBUG("%s: Current Services:0x%x", __FUNCTION__, btif_enabled_services);

    if (btif_is_enabled())
    {
        btif_transfer_context(btif_dm_execute_service_request,
                              BTIF_DM_DISABLE_SERVICE,
                              (char*)p_id, sizeof(tBTA_SERVICE_ID), NULL);
    }

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_config_hci_snoop_log
**
** Description      enable or disable HCI snoop log
**
** Returns          bt_status_t
**
*******************************************************************************/
bt_status_t btif_config_hci_snoop_log(uint8_t enable)
{
    bte_main_config_hci_logging(enable != 0,
             btif_core_state == BTIF_CORE_STATE_DISABLED);
    return BT_STATUS_SUCCESS;
}

#if HCI_RAW_CMD_INCLUDED == TRUE
/*******************************************************************************
**
** Function         btif_hci_event_cback
**
** Description     Callback invoked on receiving HCI event
**
** Returns          None
**
*******************************************************************************/
static void btif_hci_event_cback ( tBTM_RAW_CMPL *p )
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);
	if(p != NULL)
	{
		HAL_CBACK(bt_hal_cbacks, hci_event_recv_cb, p->event_code, p->p_param_buf,
	                p->param_len);
	}
}

/*******************************************************************************
**
** Function        btif_hci_cmd_send
**
** Description     Sends a HCI raw command to the controller
**
** Returns         BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_hci_cmd_send(uint16_t opcode, uint8_t *buf, uint8_t len)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTM_Hci_Raw_Command(opcode, len, buf, btif_hci_event_cback);
    return BT_STATUS_SUCCESS;
}
#endif

void btif_hci_vsc_cback(tBTM_VSC_CMPL *p_params)
{
    UINT8  *p = p_params->p_param_buf;
    UINT8  status = 0;
    UINT8  sub_opcode = 0;

    STREAM_TO_UINT8(status, p);
    STREAM_TO_UINT8(sub_opcode, p);

    BTIF_TRACE_DEBUG("btif_hci_vsc_cback status=%d sub_opcode=0x%x", status,sub_opcode);
	switch(sub_opcode)
	{
		case HCI_VSC_HEADLESS_BREDR_DEV_GET_LIST:
            BTIF_TRACE_DEBUG("HCI_VSC_HEADLESS_BREDR_DEV_GET_LIST");
			UINT8 numdev = 0;
			STREAM_TO_UINT8(numdev, p);

			if(numdev > 0)
			{
				for(UINT8 i = 0; i < numdev ; )
				{
					UINT8 *addr = p + i;
					BTIF_TRACE_DEBUG("HCI_VSC_HEADLESS_DEV_GET_LIST:addr=%x:%x:%x:%x:%x:%x",
							*addr,*(addr + 1),*(addr + 2),*(addr + 3),*(addr + 4),*(addr + 5));
					i += 6;
				}
			}
			break;
		case HCI_VSC_HEADLESS_DEV_ADD:
            BTIF_TRACE_DEBUG("HCI_VSC_HEADLESS_DEV_ADD");
			if(status == 0x17)
				BTIF_TRACE_DEBUG("HCI_VSC_HEADLESS_DEV_ADD: device already in the white list");
            btif_read_last_memory();
			break;
		case HCI_VSC_HEADLESS_DEV_DEL:
            BTIF_TRACE_DEBUG("HCI_VSC_HEADLESS_DEV_DEL");
			if(status == 0xC)
				BTIF_TRACE_DEBUG("the white list is empty");
			if(status == 0x12)
				BTIF_TRACE_DEBUG("the specific device is not in the white list and the white list is empty");
            btif_read_last_memory();
			break;
		case HCI_VSC_HEADLESS_ENABLE:
            BTIF_TRACE_DEBUG("HCI_VSC_HEADLESS_ENABLE");
		    if (status == HCI_SUCCESS)
			{
				HAL_CBACK(bt_hal_cbacks, headless_mode_changed_cb, BT_STATUS_SUCCESS);
			}
			else
			{
				HAL_CBACK(bt_hal_cbacks, headless_mode_changed_cb, BT_STATUS_FAIL);
			}
			break;
		case HCI_VSC_HEADLESS_SET_SCAN_MODE:
            BTIF_TRACE_DEBUG("HCI_VSC_HEADLESS_SET_SCAN_MODE");
			break;
		case HCI_VSC_HEADLESS_SET_LE_ADV_DATA:
            BTIF_TRACE_DEBUG("HCI_VSC_HEADLESS_SET_LE_ADV_DATA");
			break;
		case HCI_VSC_ADD_AV_DEVICE_TO_HEADLESS:
            BTIF_TRACE_DEBUG("HCI_VSC_ADD_AV_DEVICE_TO_HEADLESS");
			if (status == HCI_SUCCESS)
			{
				HAL_CBACK(bt_hal_cbacks, add_av_headless_wakeup_cb, BT_STATUS_SUCCESS);
			}
			else
			{
				HAL_CBACK(bt_hal_cbacks, add_av_headless_wakeup_cb, BT_STATUS_FAIL);
			}
			break;
		case HCI_VSC_ENABLE_WAKE_UP_TEST:
            BTIF_TRACE_DEBUG("HCI_VSC_ENABLE_WAKE_UP_TEST");
			break;
		case HCI_VSC_ERASE_PATCH:
            BTIF_TRACE_DEBUG("HCI_VSC_ERASE_PATCH");
			break;
		case HCI_VSC_READ_FLASH_BURNING_STATUS:
            BTIF_TRACE_DEBUG("HCI_VSC_READ_FLASH_BURNING_STATUS");
			break;
		case HCI_VSC_READ_LAST_MEMORY:
            BTIF_TRACE_DEBUG("HCI_VSC_READ_LAST_MEMORY");
			break;
		case HCI_VSC_FIRMWARE_UPGRADE:
            BTIF_TRACE_DEBUG("HCI_VSC_FIRMWARE_UPGRADE");
            btif_read_version_internal();
			break;
		case HCI_VSC_WRITE_LOCAL_IRK:
             BTIF_TRACE_DEBUG("HCI_VSC_WRITE_LOCAL_IRK");
			break;
		case HCI_VSC_HOGP_ADD_DEVICE_INFO:
            BTIF_TRACE_DEBUG("HCI_VSC_HOGP_ADD_DEVICE_INFO");
			break;
		case HCI_VSC_HOGP_DELETE_DEVICE_INFO:
            BTIF_TRACE_DEBUG("HCI_VSC_HOGP_DELETE_DEVICE_INFO");
			break;
		case HCI_VSC_HOGP_READ_DEVICE_INFO:
             BTIF_TRACE_DEBUG("HCI_VSC_HOGP_READ_DEVICE_INFO");
			break;
		case HCI_VSC_HOGP_SET_SCAN_PARA:
             BTIF_TRACE_DEBUG("HCI_VSC_HOGP_SET_SCAN_PARA");
			break;
		default:
            BTIF_TRACE_DEBUG(" Error sub_opcode");
			break;
	}
}


/*******************************************************************************
**
** Function         btif_read_last_memory
**
** Description      Read the last memory contents from the flash
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_read_last_memory(void)
{
    /* Send VSC for reading the last memory cocntents from flash */
    BTIF_TRACE_ERROR("%s: READING LAST MEMORY CONTENTS FROM FLASH...",
       __FUNCTION__);
    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_READ_LAST_MEMORY,
        0, NULL, btif_hci_vsc_cback);
	return BT_STATUS_SUCCESS;

}

#define READ_VERSION_REQUEST 0x19
#define EDL_APP_VER_RES_EVT (0x02)

void save_bt_firmware_version_cback(UINT8 evt_len, UINT8 *p)
{
    UINT8 status;
    UINT8 vsc_rsp_evt;
    UINT8 i;

    BTIF_TRACE_EVENT("%s vendor event length: 0x%2x", __FUNCTION__, evt_len);

    STREAM_TO_UINT8(status, p);
    BTIF_TRACE_EVENT("%s  Status of VSC: %d", __FUNCTION__, status);

    if (status == HCI_SUCCESS) {
        STREAM_TO_UINT8(vsc_rsp_evt, p);
        if (vsc_rsp_evt == EDL_APP_VER_RES_EVT) {
            for (i = 0; i < evt_len; i++)
                BTIF_TRACE_EVENT("%s: p[%d]:0x%x", __FUNCTION__, i, p[i]);
            fw_patch_version = (p[5] << 8 | p[4]);
            BTIF_TRACE_EVENT("%s: BT FIRMWARE VERSION: 0x%2x", __FUNCTION__, fw_patch_version);
        }
        if (upgrade_initiated) {
            BTIF_TRACE_ERROR("%s: Check FW Upgrade Status", __func__);
            btif_hw_chip_firmware_update_callback();
            upgrade_initiated = 0;
        } else
            BTIF_TRACE_ERROR("%s: No upgrade was initiaed", __func__);
    }
}



int rome_get_tlv_file(char *file_path)
{
    FILE * pFile;
    long fileSize;
    int readSize;
    tlv_patch_info *ptlv_header;
    unsigned short patchVersion = 0;

    BTIF_TRACE_ERROR("%s: File Open (%s)", __FUNCTION__, file_path);
    pFile = fopen ( file_path , "r" );
    if (pFile==NULL) {
        BTIF_TRACE_ERROR("%s: File Open failed: (%s)", __FUNCTION__, file_path);
        return -1;
    }

     BTIF_TRACE_ERROR("%s: File open successful", __FUNCTION__);

    /* Get File Size */
    fseek (pFile , 0 , SEEK_END);
    fileSize = ftell (pFile);
    //PREVENT CID138376
    if(fileSize <= 0) {
        fclose(pFile);
        return -1;
	}
    rewind (pFile);

    BTIF_TRACE_ERROR("%s: File size: %d", __FUNCTION__, fileSize);

    pdata_buffer = (unsigned char*) malloc (sizeof(char)*fileSize);
    if (pdata_buffer == NULL) {
        BTIF_TRACE_ERROR("Allocated Memory failed");
        fclose (pFile);
        return -1;
    }

    /* Copy file into allocated buffer */
    readSize = fread (pdata_buffer,1,fileSize,pFile);

    /* File Close */
    fclose (pFile);

    if (readSize != fileSize) {
        BTIF_TRACE_ERROR("Read file size(%d) not matched with actual file size (%ld bytes)",readSize,fileSize);
        return -1;
    }

    ptlv_header = (tlv_patch_info *) pdata_buffer;

    /* To handle different event between rampatch and NVM */
    gTlv_type = ptlv_header->tlv_type;

    BTIF_TRACE_ERROR("%s: Type of patch: %d", __FUNCTION__, gTlv_type);

    patchVersion = ptlv_header->tlv.patch.patch_ver;
    BTIF_TRACE_ERROR("%s: Version of patch in the upgrade file: 0x%x", __FUNCTION__, patchVersion);

    if(ptlv_header->tlv_type == TLV_TYPE_PATCH){
        BTIF_TRACE_ERROR("====================================================");
        BTIF_TRACE_ERROR("TLV Type\t\t\t : 0x%x", ptlv_header->tlv_type);
        BTIF_TRACE_ERROR("Length\t\t\t : %d bytes", (ptlv_header->tlv_length1) |
                                                    (ptlv_header->tlv_length2 << 8) |
                                                    (ptlv_header->tlv_length3 << 16));
        BTIF_TRACE_ERROR("Total Length\t\t : %d bytes", ptlv_header->tlv.patch.tlv_data_len);
        BTIF_TRACE_ERROR("Patch Data Length\t\t\t : %d bytes",ptlv_header->tlv.patch.tlv_patch_data_len);
        BTIF_TRACE_ERROR("Signing Format Version\t : 0x%x", ptlv_header->tlv.patch.sign_ver);
        BTIF_TRACE_ERROR("Signature Algorithm\t : 0x%x", ptlv_header->tlv.patch.sign_algorithm);
        BTIF_TRACE_ERROR("Reserved\t\t\t : 0x%x", ptlv_header->tlv.patch.reserved1);
        BTIF_TRACE_ERROR("Product ID\t\t : 0x%04x\n", ptlv_header->tlv.patch.prod_id);
        BTIF_TRACE_ERROR("Rom Build Version\t\t : 0x%04x\n", ptlv_header->tlv.patch.build_ver);
        BTIF_TRACE_ERROR("Patch Version\t\t : 0x%04x\n", ptlv_header->tlv.patch.patch_ver);
        BTIF_TRACE_ERROR("Reserved\t\t\t : 0x%x\n", ptlv_header->tlv.patch.reserved2);
        BTIF_TRACE_ERROR("Patch Entry Address\t : 0x%x\n", (ptlv_header->tlv.patch.patch_entry_addr));
        BTIF_TRACE_ERROR("====================================================");

    }
    return patchVersion;
}
/*******************************************************************************
**
** Function         btif_hw_chip_firmware_update
**
** Description      Updates the firmware on the BT Controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_hw_chip_firmware_update(void)
{
    int err = -1;
    int upgrade_ramp_file_patch_version;
    int upgrade_nvm_file_patch_version;
    /*
     * Check if the firmware file is present for upgrade
     * Check if the firmware version in the upgrade file is
     * higher than the current version in the flash
     */
#ifdef USE_RW_FILESYSTEM
    BTIF_TRACE_ERROR("%s: Checking the patch version of the upgrade file...", __FUNCTION__);
    upgrade_ramp_file_patch_version = rome_get_tlv_file(RAMPATCH_UPGRADE_PATH);
#else
    upgrade_ramp_file_patch_version = rome_get_tlv_file(RAMPATCH_DEFAULT_PATH);
#endif

    if (upgrade_ramp_file_patch_version < 0) {
        BTIF_TRACE_ERROR("%s: Firmware rampatch Upgrade file not present", __func__);
        return BT_STATUS_FAIL;
    }

#ifdef USE_RW_FILESYSTEM
    upgrade_nvm_file_patch_version = rome_get_tlv_file(NVM_UPGRADE_PATH);
#else
    upgrade_nvm_file_patch_version = rome_get_tlv_file(NVM_DEFAULT_PATH);
#endif

    if (upgrade_nvm_file_patch_version < 0) {
        BTIF_TRACE_ERROR("%s: Firmware nvm upgrade file not present", __func__);
        return BT_STATUS_FAIL;
    }
    if ((upgrade_ramp_file_patch_version > fw_patch_version)|| (TRUE == unconditional_patch_upgrade)) {
		if(TRUE == unconditional_patch_upgrade) {
           BTIF_TRACE_ERROR("%s: Unconditional Patch upgrade is configured true", __FUNCTION__); 
        }
		BTIF_TRACE_ERROR("<FW VER IN IN FLASH: 0x%x> <FW VER IN UPGRADE FILE: 0x%x> UPGRADE IN PROGRESS...",
             fw_patch_version, upgrade_ramp_file_patch_version);

#ifdef USE_RW_FILESYSTEM
        /* Backup the existing FW file prior to upgrade */
        err = rename(RAMPATCH_DEFAULT_PATH, RAMPATCH_BACKUP_PATH);
        if (err == 0) {
            BTIF_TRACE_ERROR("%s: Backup of default RAMPATCH file success", __FUNCTION__);
        } else {
            BTIF_TRACE_ERROR("%s: Couldn't backup default RAMPATCH file!!!,err=%d,errno=%d", __FUNCTION__,err,errno);
        }

        /* Rename the upgrade FW file prior as default FW file */
        err = rename(RAMPATCH_UPGRADE_PATH, RAMPATCH_DEFAULT_PATH);
        if (err == 0) {
            BTIF_TRACE_ERROR("%s: Upgrade RAMPATCH file ready for download", __FUNCTION__);
        } else {
            BTIF_TRACE_ERROR("%s: File System error caused upgrade failure!!!,err=%d,errno=%d", __FUNCTION__,err,errno);
        }

        /* Backup the existing NVM file prior to upgrade */
        err = rename(NVM_DEFAULT_PATH, NVM_BACKUP_PATH);
        if (err == 0) {
            BTIF_TRACE_ERROR("%s: Backup of default MVM file success", __FUNCTION__);
        } else {
            BTIF_TRACE_ERROR("%s: Couldn't backup default NVM file!!!,err=%d,errno=%d", __FUNCTION__,err,errno);
        }

        /* Rename the upgrade NVM file prior as default FW file */
        err = rename(NVM_UPGRADE_PATH, NVM_DEFAULT_PATH);
        if (err == 0) {
            BTIF_TRACE_ERROR("%s: Upgrade NVM file ready for download", __FUNCTION__);
        } else {
            BTIF_TRACE_ERROR("%s: File System error caused upgrade failure!!!,err=%d,errno=%d", __FUNCTION__,err,errno);
        }
#endif
        /* Update that FW UPgrade is in progress */
        upgrade_initiated = 1;

        /* Send VSC for erasing existing FW */
        BTIF_TRACE_ERROR("%s: Sending VSC to erase existing FW and upgrade the new FW...", __FUNCTION__);
        BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_FIRMWARE_UPGRADE,
            0, NULL, btif_hci_vsc_cback);

    } else {
        BTIF_TRACE_ERROR("Firmware version: 0x%x in flash is higher than upgrade firmware file: 0x%x!! NO UPGRADE REQUIRED",
            fw_patch_version, upgrade_ramp_file_patch_version);
        return BT_STATUS_DONE;
    }

    return BT_STATUS_SUCCESS;
}

void btif_restore_backup_fw(void)
{
    int err;

    BTIF_TRACE_ERROR("%s: Restoring the previous good backup FW...", __FUNCTION__);

    /* Restore the backup RAMPATCH file as the default file */
    err = rename(RAMPATCH_BACKUP_PATH, RAMPATCH_DEFAULT_PATH);
    if (err == 0) {
        BTIF_TRACE_ERROR("%s: Restore of backup RAMPATCH file success", __FUNCTION__);
    } else {
        /* Should not reach here!! */
        BTIF_TRACE_ERROR("%s: Couldn't restore the backup RAMPATCH file as default!!!", __FUNCTION__);
    }

    /* Restore the backup NVM file as the default file */
    err = rename(NVM_BACKUP_PATH, NVM_DEFAULT_PATH);
    if (err == 0) {
        BTIF_TRACE_ERROR("%s: Restore of backup NVM file success", __FUNCTION__);
    } else {
        /* Should not reach here!! */
        BTIF_TRACE_ERROR("%s: Couldn't restore the backup NVM file as default!!!", __FUNCTION__);
    }
}


//TODO: Provide FW Update Status to OAL
/*******************************************************************************
**
** Function         Callback to OAL for providing the FW Update Status
**
** Description      Compare the version in the backup and default file to
**                  determine if the upgrade happened or not.
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_hw_chip_firmware_update_callback(void)
{
    UINT16 prev_patch_version;

    BTIF_TRACE_ERROR("%s: Checking if the upgrade succeeded...", __FUNCTION__);

#ifdef USE_RW_FILESYSTEM
    /* Retrieve the Rampatch version of the previous file */
    prev_patch_version = rome_get_tlv_file(RAMPATCH_BACKUP_PATH);
#else
    prev_patch_version = rome_get_tlv_file(RAMPATCH_DEFAULT_PATH);
#endif

    BTIF_TRACE_ERROR("FW VER IN IN FLASH: <0x%x> && Previous FW VER: <0x%x>",
        fw_patch_version, prev_patch_version);

    /*
     * Compare the Rampatch version of previous file with the current Rampatch
     * version present in the Controller. If former is greater than later, then
     * firmware upgrade failed because of upgrade Rampatch file had bad
     * CRC/Signature. Hence, Controller did not save to flash.
     */
    if (prev_patch_version > fw_patch_version) {
        BTIF_TRACE_ERROR("BT FW upgrade failed as FW VER IN IN FLASH: <0x%x> "
            "lower than previous FW VER : <0x%x>!!!", fw_patch_version,
            prev_patch_version);

        if (TRUE == unconditional_patch_upgrade)
        {
            BTIF_TRACE_ERROR("not rolling back due to unconditional_patch_upgrade");
        }
        else
        {
#ifdef USE_RW_FILESYSTEM
           /* Emergency FW D/W handling */
            BTIF_TRACE_ERROR("rolling back firmware patch");
           btif_restore_backup_fw();
#endif
           /*
            * Notify OAL on the status of the FW Upgrade via registered callback
            * function. OAL has to reload the driver and as part of driver probe()
            * call, the restored good backed FW file will be downloaded.
           */
           return BT_STATUS_FAIL;
        }
    }
    else
    {
        /* Stop the FW Upgrade timer from firing, as the upgrade is successful */
        unconditional_patch_upgrade = FALSE;
        enable_test_mode = FALSE;

        /* Invoke the FW Upgrade cback registered by OAL to notify status */
        BTIF_TRACE_ERROR("%s: BT FW Upgrade Succeeded", __FUNCTION__);
        //HAL_CBACK(bt_hal_cbacks, fw_upgrade_cb, BT_STATUS_UPGRADE_SUCCESS);
    }
    return BT_STATUS_SUCCESS;
}
 void btif_read_version_cback(tBTM_VSC_CMPL *p_params)
{
	UINT8  *p = p_params->p_param_buf;
	UINT8  status = (UINT8)(*(p));
	if (upgrade_initiated) {
		BTIF_TRACE_ERROR("%s: Check FW Upgrade Status",__func__);
		btif_hw_chip_firmware_update_callback();
		upgrade_initiated = 0;
	} else
		BTIF_TRACE_ERROR("%s: No upgrade was initiaed", __func__);
}

/*******************************************************************************
**
** Function         btif_read_version
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_read_version(btif_fw_version_t *version)
{
    if (version == NULL)
        return BT_STATUS_FAIL;

#ifdef X86_TEST_INTERFACE
    /* Return the already fetched version */
    version->patch_version = fw_patch_version;

    /* Call the registered callback function */
    HAL_CBACK(bt_hal_cbacks, read_firmware_version_cb, (UINT8 *)version);
#endif

    /* Issue the VSC to query the version, in case anything changed */
    BTIF_TRACE_ERROR("%s: Issue the VSC to query the version, in case anything changed", __FUNCTION__);
    btif_read_version_internal();

    return BT_STATUS_SUCCESS;
}

bt_status_t btif_read_version_internal()
{
    uint8_t read_patch_version = READ_VERSION_REQUEST;
    BTIF_TRACE_ERROR("%s", __FUNCTION__);

    BTA_DmVendorSpecificCommand(HCI_GRP_VENDOR_SPECIFIC,
        1, &read_patch_version, btif_read_version_cback);

    return BT_STATUS_SUCCESS;
}

bt_status_t btif_get_headless_device_list(void)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_HEADLESS_BREDR_DEV_GET_LIST,
                                     0, NULL, btif_hci_vsc_cback);
    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_enter_headless_mode
**
** Description     device_type : Bit0->Enable HOGP wakeup, Bit1->Enable BR/EDR wake up
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_enter_headless_mode(uint8_t device_type)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    enter_headless_mode = TRUE;


    /* Trigger the initial level of profile cleanup */
    BTIF_TRACE_ERROR("%s: STACK-CLEANUP: UNREG. BT SUB-SYSTEM", __FUNCTION__);
    bta_sys_disable(BTA_SYS_HW_BLUETOOTH);

    btif_config_cleanup();

    /* cleanup rfcomm & l2cap api */
    BTIF_TRACE_ERROR("%s: STACK-CLEANUP: RFCOMM-L2CAP CLEANUP", __FUNCTION__);
    btif_sock_cleanup();

    BTIF_TRACE_ERROR("%s: STACK-CLEANUP: PAN CLEANUP", __FUNCTION__);
    btif_pan_cleanup();

    BTIF_TRACE_ERROR("%s: STACK-CLEANUP: PROFILE-Q CLEANUP", __FUNCTION__);
    btif_queue_release();
    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_HEADLESS_ENABLE,
                                     1, &device_type, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_add_headless_mode_wakeup_device
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_add_headless_mode_wakeup_device(bt_bdaddr_t *remote_addr)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_HEADLESS_DEV_ADD,
                                     HCI_VSC_HEADLESS_DEV_ADD_DEL_PARAM_SIZE,
                                     (UINT8 *)remote_addr, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}


/*******************************************************************************
**
** Function         btif_add_av_dev_to_headless_mode
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_add_av_dev_to_headless_mode(bt_bdaddr_t *remote_addr)
{
    /* TODO: Check that opcode is a vendor command group */
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_ADD_AV_DEVICE_TO_HEADLESS,
                                     HCI_VSC_HEADLESS_DEV_ADD_DEL_PARAM_SIZE,
                                     (UINT8 *)remote_addr, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_delete_headless_mode_wakeup_device
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_delete_headless_mode_wakeup_device(bt_bdaddr_t *remote_addr)
{
    /* TODO: Check that opcode is a vendor command group */
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_HEADLESS_DEV_DEL,
                                     HCI_VSC_HEADLESS_DEV_ADD_DEL_PARAM_SIZE,
                                     (UINT8 *)remote_addr, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_bt_wake_up_test
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_bt_wake_up_test(void)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_ENABLE_WAKE_UP_TEST,
                                     0, NULL, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_bt_erase_patch_nvm
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_bt_erase_patch_nvm(void)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_ERASE_PATCH,
                                     0, NULL, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_bt_read_flash_burning_status
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_bt_read_flash_burning_status(void)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_READ_FLASH_BURNING_STATUS,
                                     0, NULL, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_hogp_read_link_key
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/

bt_status_t btif_hogp_read_link_key(void *str)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_HOGP_READ_DEVICE_INFO,
                                     sizeof(bt_bdaddr_t) + 1,
                                     (UINT8 *)str, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_hogp_set_scan_param
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/

bt_status_t btif_hogp_set_scan_param(hogp_le_scan_param_t *param)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_HOGP_SET_SCAN_PARA,
                                     sizeof(bt_bdaddr_t) + 1,
                                     (UINT8 *)param, btif_hci_vsc_cback);

    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_set_headless_le_adv_data
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_set_headless_le_adv_data(bt_le_headless_adv_data param)
{
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);

	uint8_t *buf =  GKI_getbuf(16 + param.adv_data_length);
	if(buf == NULL)
		return BT_STATUS_NOMEM;
    uint8_t *p = buf;

	UINT16_TO_STREAM(buf,param.adv_interval_min);
	UINT16_TO_STREAM(buf,param.adv_interval_max);
	UINT8_TO_STREAM(buf,param.adv_type);
	UINT8_TO_STREAM(buf,param.own_addr_type);
	UINT8_TO_STREAM(buf,param.peer_addr_type);
	BDADDR_TO_STREAM(buf,param.peer_addr);
	UINT8_TO_STREAM(buf,param.adv_channel_map);
	UINT8_TO_STREAM(buf,param.adv_filter_policy);
	UINT8_TO_STREAM(buf,param.adv_data_length);
	if(param.adv_data_length > 0)
		memcpy(buf,param.adv_data,param.adv_data_length);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_HEADLESS_SET_LE_ADV_DATA,
                                     16 + param.adv_data_length, p, btif_hci_vsc_cback);
	GKI_freebuf(p);
    return BT_STATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         btif_set_headless_scan_configure
**
** Description     Sends a HCI Vendor specific command to the controller
**
** Returns          BT_STATUS_SUCCESS on success
**
*******************************************************************************/
bt_status_t btif_set_headless_scan_configure(uint16_t pscan_interval, uint16_t pscan_window_size,uint8_t pscan_mode)
{
	uint8_t buf[128];
	uint8_t *p;
    BTIF_TRACE_DEBUG("%s", __FUNCTION__);
	memset(buf,0x0,sizeof(buf));
	p = buf;
	UINT16_TO_STREAM(p,pscan_interval);
	UINT16_TO_STREAM(p,pscan_window_size);
	UINT8_TO_STREAM(p,pscan_mode);

    BTA_DmNPLSpecificCommand(HCI_VSC_MAIN_NPL,HCI_VSC_HEADLESS_SET_SCAN_MODE,5,
			buf, btif_hci_vsc_cback );

    return BT_STATUS_SUCCESS;
}
