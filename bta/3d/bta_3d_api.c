//XXX copyright header?
/******************************************************************************
 *
 *  This file contains the 3D Sync API in the subsystem of BTA.
 *
 ******************************************************************************/

#include "bt_target.h"

#if defined(BTA_3D_INCLUDED) && (BTA_3D_INCLUDED == TRUE)

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "bta_3d_api.h"
#include "bta_3d_int.h"
#include "l2c_api.h"

/*****************************************************************************
 **  Constants
 *****************************************************************************/

static const tBTA_SYS_REG bta_3d_reg =
{
    bta_3d_hdl_event,
    BTA_3dDisable
};

/*******************************************************************************
 **
 ** Function         BTA_3dEnable
 **
 ** Description      This function enable 3D Display and registers the Dislpay with
 **                  lower layers.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dEnable(tBTA_3D_CBACK *p_cback, char *p_service_name)
{
    tBTA_3D_API_ENABLE *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);

    /* Register with BTA */
    //GKI_sched_lock();
    bta_sys_register(BTA_ID_3D, &bta_3d_reg);
    //GKI_sched_unlock();
    

    if((p_buf = (tBTA_3D_API_ENABLE *)GKI_getbuf(sizeof(tBTA_3D_API_ENABLE))) != NULL)
    {
        p_buf->hdr.event = BTA_3D_API_ENABLE_EVT;
        p_buf->p_cback   = p_cback;

        if(p_service_name)
            BCM_STRNCPY_S(p_buf->p_name, BTA_SERVICE_NAME_LEN+1, p_service_name, BTA_SERVICE_NAME_LEN);

        bta_sys_sendmsg(p_buf);
    }
    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

/*******************************************************************************
 **
 ** Function         BTA_3dDisable
 **
 ** Description      This function is called when the host is about power down.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dDisable(void)
{
    BT_HDR *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);
    if((p_buf = (BT_HDR *)GKI_getbuf(sizeof(BT_HDR))) != NULL)
    {
        p_buf->event = BTA_3D_API_DISABLE_EVT;

        bta_sys_sendmsg(p_buf);
    }

    //GKI_sched_lock();
    bta_sys_deregister(BTA_ID_3D);
    //GKI_sched_unlock();

    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

/*******************************************************************************
 **
 ** Function         BTA_3dWriteSyncParams
 **
 ** Description      This function writes the Synchronization Train Parameters.
 **                  Note, for spec-compliance the Interval is coded to 80ms internally.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dWriteSyncTrainParams(UINT32 timeout, UINT8 service_data)
{
    tBTA_3D_API_WRITE_SYNC_TRAIN_PARAMS *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);
    if((p_buf = (tBTA_3D_API_WRITE_SYNC_TRAIN_PARAMS *)GKI_getbuf(sizeof(tBTA_3D_API_WRITE_SYNC_TRAIN_PARAMS))) != NULL)
    {
        p_buf->hdr.event    = BTA_3D_API_WRITE_SYNC_PARAM_EVT;
        p_buf->timeout      = timeout;
        p_buf->service_data = service_data;

        bta_sys_sendmsg(p_buf);
    }
    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

/*******************************************************************************
 **
 ** Function         BTA_3dStartSyncTrain
 **
 ** Description      This function start the synchronization train.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dStartSyncTrain(void)
{
    BT_HDR *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);
    if((p_buf = (BT_HDR *)GKI_getbuf(sizeof(BT_HDR))) != NULL)
    {
        p_buf->event = BTA_3D_API_START_SYNC_TRAIN_EVT;

        bta_sys_sendmsg(p_buf);
    }
    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

/*******************************************************************************
 **
 ** Function         BTA_3dSetBroadcastData
 **
 ** Description      This function sets the data being broadcast.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dSetBroadcastData(tBTA_3D_BCAST_DATA *p_bcast_data)
{
    tBTA_3D_API_SET_BCAST_DATA *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);
    if((p_bcast_data) && ((p_buf = (tBTA_3D_API_SET_BCAST_DATA *)GKI_getbuf(sizeof(tBTA_3D_API_SET_BCAST_DATA))) != NULL))
    {
        p_buf->hdr.event  = BTA_3D_API_SET_BCAST_DATA_EVT;
        p_buf->bcast_data = *p_bcast_data;

        bta_sys_sendmsg(p_buf);
    }
    else
    {
    }
    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

/*******************************************************************************
 **
 ** Function         BTA_3dEnableBroadcasts
 **
 ** Description      This function enables 3D broadcasts.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dEnableBroadcasts(UINT16 timeout, BOOLEAN low_power)
{
    tBTA_3D_API_ENABLE_BCAST *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);
    if((p_buf = (tBTA_3D_API_ENABLE_BCAST *)GKI_getbuf(sizeof(tBTA_3D_API_ENABLE_BCAST))) != NULL)
    {
        p_buf->hdr.event = BTA_3D_API_ENABLE_BCAST_EVT;
        p_buf->timeout   = timeout;
        p_buf->low_power = low_power;

        bta_sys_sendmsg(p_buf);
    }
    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

/*******************************************************************************
 **
 ** Function         BTA_3dDisableBroadcasts
 **
 ** Description      This function disables 3D broadcasts.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dDisableBroadcasts(void)
{
    BT_HDR *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);
    if((p_buf = (BT_HDR *)GKI_getbuf(sizeof(BT_HDR))) != NULL)
    {
        p_buf->event = BTA_3D_API_DISABLE_BCAST_EVT;

        bta_sys_sendmsg(p_buf);
    }
    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

/*******************************************************************************
 **
 ** Function         BTA_3dEnableClockCapture
 **
 ** Description      This function enabled Triggered Clock Capture.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dEnableClockCapture(UINT8 filter_count)
{
    tBTA_3D_API_ENABLE_CLK_CAP *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);
    if((p_buf = (tBTA_3D_API_ENABLE_CLK_CAP *)GKI_getbuf(sizeof(tBTA_3D_API_ENABLE_CLK_CAP))) != NULL)
    {
        p_buf->hdr.event    = BTA_3D_API_ENABLE_CLK_CAP_EVT;
        p_buf->filter_count = filter_count;

        bta_sys_sendmsg(p_buf);
    }
    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

/*******************************************************************************
 **
 ** Function         BTA_3dDisableClockCapture
 **
 ** Description      This function disabled Triggered Clock Capture.
 **
 ** Returns          void
 **
 *******************************************************************************/
void BTA_3dDisableClockCapture(void)
{
    BT_HDR *p_buf;

    APPL_TRACE_API("%s: Enter", __FUNCTION__);
    if((p_buf = (BT_HDR *)GKI_getbuf(sizeof(BT_HDR))) != NULL)
    {
        p_buf->event = BTA_3D_API_DISABLE_CLK_CAP_EVT;

        bta_sys_sendmsg(p_buf);
    }
    APPL_TRACE_API("%s: Exit", __FUNCTION__);
}

#endif
