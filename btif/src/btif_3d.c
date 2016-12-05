/************************************************************************************
 *
 *  Filename:      btif_3d.c
 *
 *  Description:   3D Sync Profile Bluetooth Interface
 *
 *
 ***********************************************************************************/
#include <hardware/bluetooth.h>
#include <hardware/bt_3d.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define LOG_TAG "BTIF_3D"

#include "bta_api.h"
#include "bta_3d_api.h"
#include "bd.h"
#include "btif_storage.h"

#include "btif_common.h"
#include "btif_util.h"
#include "btif_3d.h"
#include "gki.h"
#include "l2c_api.h"


//Approximately 2 per second for a 60hz display
#define FRAMES_SYNCS_PER_CAPTURE 60

#define INVALID_PERIOD_REPEAT_THRESHOLD 10

#define MIN_PERIOD_3D 16655
#define MAX_PERIOD_3D 16690

#define PERIOD_VALID_3D(_x) ((_x >= MIN_PERIOD_3D) && (_x <= MAX_PERIOD_3D))

#define MIN_PERIOD_2D 8000
#define MAX_PERIOD_2D 9000

#define PERIOD_VALID_2D(_x) ((_x >= MIN_PERIOD_2D) && (_x <= MAX_PERIOD_2D))

#define CLK_SLOT_US 625

typedef struct
{
    uint32_t clock;
    uint16_t offset;
} tBTIF_3D_CLK_CAP_DATA;

/************************************************************************************
**  Static variables
************************************************************************************/
bt3d_callbacks_t *bt3d_callbacks = NULL;
static tBTA_3D_BCAST_DATA bcast_data;
static BOOLEAN broadcasting;
static TIMER_LIST_ENT clk_cap_to_tmr;
static BOOLEAN enabled;
static bt3d_mode_t current_mode = BT_3D_MODE_IDLE;
static unsigned int invalid_count;

static tBTIF_3D_CLK_CAP_DATA last_cap;

static void bta_3d_evt(tBTA_3D_EVT event, tBTA_3D *data);

//Called when we haven't received a Triggered Clock Capture
//for an unexpected period of time.
//
//Triggers 2D mode
static void clk_cap_to_cb(TIMER_LIST_ENT *tmr)
{
    BTIF_TRACE_DEBUG("Triggered Clock Capture stopped");
    memset(&bcast_data, 0, sizeof(bcast_data));
    memset(&last_cap, 0, sizeof(last_cap));
    HAL_CBACK(bt3d_callbacks, frame_period_cb, 65535);
}

bt_status_t btif_3d_init(void* callbacks)
{
    BTIF_TRACE_EVENT("%s", __FUNCTION__);
    BTIF_TRACE_EVENT("BTIF_3D_CALL_IN: %s", __FUNCTION__);
    bt3d_callbacks = (bt3d_callbacks_t* )callbacks;
    btif_enable_service(BTA_3D_SERVICE_ID);
    return BT_STATUS_SUCCESS;
}

bt_status_t btif_3d_set_mode(bt3d_mode_t mode, bt_bdaddr_t *master_bd_addr)
{
    bt_status_t status;

    BTIF_TRACE_EVENT("BTIF_3D_CALL_IN: %s,%d", __FUNCTION__,mode);
    if(!enabled)
        return BT_STATUS_NOT_READY;

    switch(mode)
    {
        case BT_3D_MODE_IDLE:
            BTIF_TRACE_DEBUG("Setting 3D idle mode");
            //BTA_3dDisableClockCapture();
            BTA_3dDisableBroadcasts();

            btu_stop_timer(&clk_cap_to_tmr);
            memset(&last_cap, 0, sizeof(last_cap));

            status = BT_STATUS_SUCCESS;

            break;
        case BT_3D_MODE_MASTER:
            BTIF_TRACE_DEBUG("Setting 3D master mode");
            if(current_mode == BT_3D_MODE_MASTER)
			{

                BTIF_TRACE_DEBUG("Already 3D master mode");
                return BT_STATUS_SUCCESS;
			}

            //Start in 2D mode until we have a valid period
            invalid_count = 0;
            memset(&bcast_data, 0, sizeof(tBTA_3D_BCAST_DATA));
            bcast_data.left_open_off = 0xFFFF;
            BTA_3dSetBroadcastData(&bcast_data);

            BTA_3dEnableBroadcasts(5000, 0);
            BTA_3dStartSyncTrain();
            //BTA_3dEnableClockCapture(FRAMES_SYNCS_PER_CAPTURE);

            status = BT_STATUS_SUCCESS;
            break;
        case BT_3D_MODE_SLAVE:
        case BT_3D_MODE_SHOWROOM:
        default:
            status = BT_STATUS_UNSUPPORTED;
    }

    if(status == BT_STATUS_SUCCESS)
        current_mode = mode;

    return status;
}

//XXX Reject if we aren't broadcasting?
bt_status_t btif_3d_broadcast_3d_data(bt3d_data_t data)
{
    BTIF_TRACE_EVENT("BTIF_3D_CALL_IN: %s", __FUNCTION__);
    BTIF_TRACE_EVENT("BTIF_3D %d,%d,%d,%d",data.left_open_offset,data.left_close_offset,data.right_open_offset,data.right_close_offset);
    bcast_data.left_open_off   = data.left_open_offset;
    bcast_data.left_close_off  = data.left_close_offset;
    bcast_data.right_open_off  = data.right_open_offset;
    bcast_data.right_close_off = data.right_close_offset;
    BTIF_TRACE_EVENT("DUAL_VIEW: %d", data.dual_view);
//    bcast_data.dual_view       = data.dual_view;
    bcast_data.dual_view = 0;

    BTA_3dSetBroadcastData(&bcast_data);

    return BT_STATUS_SUCCESS;
}

void btif_3d_cleanup(void)
{
    BTIF_TRACE_EVENT("BTIF_3D_CALL_IN: %s", __FUNCTION__);
    if(bt3d_callbacks)
    {
        bt3d_callbacks = NULL;
        btif_disable_service(BTA_3D_SERVICE_ID);
    }
}

#if 1
static const bt3d_interface_t bt3dInterface = 
{
    sizeof(bt3d_interface_t),
    btif_3d_init,
    btif_3d_set_mode,
    btif_3d_broadcast_3d_data,
    btif_3d_cleanup,
};
#endif

/*******************************************************************************
**
** Function         btif_3d_upstreams_evt
**
** Description      Executes 3D UPSTREAMS events in btif context
**
** Returns          void
**
*******************************************************************************/
static void btif_3d_upstreams_evt(UINT16 event, char* p_param)
{
    uint16_t  period;
    uint16_t  period_diff;
    uint32_t  shifted_clock;
    uint16_t  shifted_offset;
    uint32_t  clock_diff;
    uint8_t   fraction;
    tBTA_3D  *data          = (tBTA_3D *)p_param;
    switch(event)
    {
        case BTA_3D_ENABLE_EVT:
            if(data->status == BTA_3D_OK)
            {
                BTA_3dWriteSyncTrainParams(120000, 0);
                BTA_3dEnableClockCapture(FRAMES_SYNCS_PER_CAPTURE);
                enabled = TRUE;

                //XXX: OAL is never calling set_mode, so do this in order to function temporarily
                btif_3d_set_mode(BT_3D_MODE_MASTER, NULL);
            }
            else
                BTIF_TRACE_ERROR("Enable Error: %u", data->status);
            break;
        case BTA_3D_DISABLE_EVT:
            enabled = FALSE;
            break;
        case BTA_3D_ASSOCIATION_EVT:
            BTIF_TRACE_DEBUG("Association: %02X, %d", data->association.flags, data->association.battery);

            if((data->association.flags & BTA_3D_ASSOC_FLAGS_ASSOC) || (data->association.legacy))
            {
                HAL_CBACK(bt3d_callbacks, assos_notif_cb, (bt_bdaddr_t *)&data->association.bd);
            }

            if((!data->association.legacy) && (data->association.battery != BTA_3D_ASSOC_BATT_LVL_NOT_SUPP))
            {
                HAL_CBACK(bt3d_callbacks, batt_level_cb, (bt_bdaddr_t *)&data->association.bd, data->association.battery);
            }
            break;
        case BTA_3D_SLV_PAGE_RSP_TO_EVT:
            //Start the sync train, because a device requested it
            //(Only if we are in master mode)
            BTIF_TRACE_DEBUG("Slave pg rsp TO received");
            if(current_mode == BT_3D_MODE_MASTER)
                BTA_3dStartSyncTrain();
            break;
        case BTA_3D_SYNC_TRAIN_CMPL_EVT:
        case BTA_3D_CHANNEL_CHANGE_EVT:  //
            BTA_3dStartSyncTrain();
            break;
        case BTA_3D_CLK_CAP_EVT:
            btu_stop_timer(&clk_cap_to_tmr);
            shifted_clock = data->clk_cap.clock >> 1;
            BTIF_TRACE_DEBUG("CAPTURE: %d, %d", shifted_clock, data->clk_cap.offset);

            if(last_cap.clock != 0)
            {
                clock_diff = (shifted_clock*CLK_SLOT_US + (uint32_t)data->clk_cap.offset) - (last_cap.clock*CLK_SLOT_US + (uint32_t)last_cap.offset);
                period = (uint16_t)(clock_diff / (FRAMES_SYNCS_PER_CAPTURE + 1)); 
                fraction = (clock_diff % (FRAMES_SYNCS_PER_CAPTURE + 1)) >> 8;

                BTIF_TRACE_DEBUG("BTIF_3D_PERIOD: %d", period);

                if(PERIOD_VALID_2D(period))
                {
                    invalid_count = 0;
                    //Set 2D mode if we haven't already
                    if(bcast_data.period != 0)
                    {
                        memset(&bcast_data, 0, sizeof(tBTA_3D_BCAST_DATA));
                        bcast_data.left_open_off = 0xFFFF;
                        BTA_3dSetBroadcastData(&bcast_data);
                    }
                }
                else if(PERIOD_VALID_3D(period))
                {
                    shifted_offset = data->clk_cap.offset >> 1;
                    invalid_count  = 0;

                    // The period appears to be valid 3D
                    // Don't update to OAL if it is the same as before
                    if(period == bcast_data.period || PERIOD_VALID_3D(bcast_data.period))
                    {
                        BTIF_TRACE_DEBUG("BTIF_3D period same");
                        bcast_data.instant  = shifted_clock;
                        bcast_data.phase = shifted_offset;
                        BTA_3dSetBroadcastData(&bcast_data);
                    }
                    else
                    {
                        //The period has shifted, but is still seemingly valid 3D
                        //XXX: Need to account for slight drifts due to noise if
                        //     the problem persists an a better environment
                        BTIF_TRACE_DEBUG("BTIF_3D update period");
                        bcast_data.instant  = shifted_clock;
                        bcast_data.phase = shifted_offset;
                        bcast_data.period   = period;
                        bcast_data.fraction = fraction;
                        HAL_CBACK(bt3d_callbacks, frame_period_cb, period);
                        
                    }
                }
                else
                {
                    //This period is not a valid expected value.
                    //We could be shifting 60hz<->120hz, or there could
                    //be noise. Either way, just drop this period unless
                    //we have had a number of periods in this range in a row.
                    //If we reach the repeat threshold, drop to 2D mode
                    if(bcast_data.period)
                    {
                        if(invalid_count > INVALID_PERIOD_REPEAT_THRESHOLD)
                        {
                            BTIF_TRACE_DEBUG("Invalid threshold reached. Drop to 2D");
                            invalid_count = 0;

                            memset(&bcast_data, 0, sizeof(tBTA_3D_BCAST_DATA));
                            bcast_data.left_open_off = 0xFFFF;
                            BTA_3dSetBroadcastData(&bcast_data);
                        }
                        else
                        {
                            BTIF_TRACE_DEBUG("Invalid period (%d)", invalid_count);
                            invalid_count++;
                        }
                    }
                }

                clk_cap_to_tmr.param = (UINT32)clk_cap_to_cb;
                btu_start_timer(&clk_cap_to_tmr, BTU_TTYPE_USER_FUNC, 2);
            }

            last_cap.clock  = shifted_clock;
            last_cap.offset = data->clk_cap.offset;
            break;
        case BTA_3D_COMMAND_STATUS_EVT:
            if(data->cmd_status.status != BTA_3D_OK)
                BTIF_TRACE_ERROR("3D HCI Cmd Fail: %d, %d", data->cmd_status.cmd, data->cmd_status.status);
            break;
        default:
            BTIF_TRACE_DEBUG("Unhandled 3D event: %u", event);
    }
}

static void bta_3d_evt(tBTA_3D_EVT event, tBTA_3D *data)
{
    btif_transfer_context(btif_3d_upstreams_evt, event, (void *)data, sizeof(tBTA_3D), NULL);
}

/*******************************************************************************
**
** Function         btif_3d_execute_service
**
** Description      Initializes/Shuts down the service
**
** Returns          BT_STATUS_SUCCESS on success, BT_STATUS_FAIL otherwise
**
*******************************************************************************/
bt_status_t btif_3d_execute_service(BOOLEAN b_enable)
{
     if (b_enable)
     {
          /* Enable and register with BTA-3D */
          BTA_3dEnable(bta_3d_evt, BTIF_3D_SERVICE_NAME);
     }
     else {
         /* Disable 3D */
         BTA_3dDisable();
     }
     return BT_STATUS_SUCCESS;
}

#if 1
/*******************************************************************************
**
** Function         btif_3d_get_interface
**
** Description      Get the 3d callback interface
**
** Returns          bt3d_interface_t
**
*******************************************************************************/
const bt3d_interface_t *btif_3d_get_interface()
{
    BTIF_TRACE_EVENT("%s", __FUNCTION__);
    return &bt3dInterface;
}
#endif
