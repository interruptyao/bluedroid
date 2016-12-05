/******************************************************************************
 *
 *  This file contains the 3D Sync main functions and state machine.
 *
 ******************************************************************************/

#include "bt_target.h"

#if defined(BTA_3D_INCLUDED) && (BTA_3D_INCLUDED == TRUE)

#include <string.h>

#include "bta_3d_api.h"
#include "bta_3d_int.h"
#include "gki.h"
#include "l2c_api.h"
#include "btm_api.h"
#include "sdp_api.h"

/*****************************************************************************
** Global data
*****************************************************************************/
#if BTA_DYNAMIC_MEMORY == FALSE
tBTA_3D_CB  bta_3d_cb;
#endif


/*****************************************************************************
** Internal function definitions
*****************************************************************************/
static void bta_3d_api_enable(tBTA_3D_DATA *p_data);
static void bta_3d_api_disable(void);
static void bta_3d_api_write_params(tBTA_3D_DATA *p_data);
static void bta_3d_api_start_train(void);
static void bta_3d_api_set_bcast_data(tBTA_3D_DATA *p_data);
static void bta_3d_api_enable_bcast(tBTA_3D_DATA *p_data);
static void bta_3d_api_disable_bcast(void);
static void bta_3d_api_enable_clk_cap(tBTA_3D_DATA *p_data);
static void bta_3d_api_disable_clk_cap(void);

static void bta_3d_btm_clb_cmd_cmpl(tBTA_3D_DATA *p_data);
static void bta_3d_btm_sync_train_cmpl(tBTA_3D_DATA *p_data);
static void bta_3d_btm_trg_clk_cap(tBTA_3D_DATA *p_data);
static void bta_3d_btm_slv_page_rsp_to(void);
static void bta_3d_btm_tx_pwr(tBTA_3D_DATA *p_data);
static void bta_3d_l2ca_ucd_data(tBTA_3D_DATA *p_data);
static void bta_3d_btm_vs_evt(tBTA_3D_DATA *p_data);
static void bta_3d_btm_clb_channel_change_evt(void);

static void btm_clb_cmd_cmpl(void *result);
static void btm_sync_train_cmpl(UINT8 status);
static void btm_trg_clk_cap(tBTM_TRG_CLK_CAP *p);
static void btm_slave_page_response_to(void);
static void btm_read_inq_rsp_tx_pwr_cmpl(void *p_buf);
static void btm_vs_cmpl(tBTM_VSC_CMPL *p_buf);
static void btm_vs_evt(UINT8 len, UINT8 *p);
static void btm_clb_channel_change(void);

static void l2ca_ucd_disc_cb(BD_ADDR bd, UINT8 type, UINT32 data);
static void l2ca_ucd_data_cb(BD_ADDR bd, BT_HDR *p_buf);
static void l2ca_ucd_cong_status_cb(BD_ADDR bd, BOOLEAN cong);

static void l2ca_connect_ind(BD_ADDR bd, UINT16 lcid, UINT16 psm, UINT8 id);
static void l2ca_connect_cfm(UINT16 lcid, UINT16 result);
static void l2ca_connect_pnd_cb(UINT16 lcid);
static void l2ca_config_ind(UINT16 lcid, tL2CAP_CFG_INFO *info);
static void l2ca_config_cfm(UINT16 lcid, tL2CAP_CFG_INFO *info);
static void l2ca_disc_ind(UINT16 lcid, BOOLEAN ack);
static void l2ca_disc_cfm(UINT16 lcid, UINT16 result);
static void l2ca_qos_violation_ind(BD_ADDR bd);
static void l2ca_data_ind(UINT16 lcid, BT_HDR *p_buf);
static void l2ca_cong_status(UINT16 lcid, BOOLEAN cong);
static void l2ca_tx_cmpl(UINT16 lcid, UINT16 num);
/*****************************************************************************
** Constants and Types
*****************************************************************************/
static const tBTM_CLB_CB_INFO btm_clb_cb_info =
{
    btm_clb_cmd_cmpl,
    btm_trg_clk_cap,
    btm_sync_train_cmpl,
    btm_slave_page_response_to,
    btm_clb_channel_change
};

static const tL2CAP_UCD_CB_INFO l2ca_cb_info =
{
    l2ca_ucd_disc_cb,
    l2ca_ucd_data_cb,
    l2ca_ucd_cong_status_cb
};

static const tL2CAP_APPL_INFO l2ca_appl_info =
{
    l2ca_connect_ind,
    l2ca_connect_cfm,
    l2ca_connect_pnd_cb,
    l2ca_config_ind,
    l2ca_config_cfm,
    l2ca_disc_ind,
    l2ca_disc_cfm,
    l2ca_qos_violation_ind,
    l2ca_data_ind,
    l2ca_cong_status,
    l2ca_tx_cmpl,
};


/*****************************************************************************
** Utilities
*****************************************************************************/
static tBTA_3D_STATUS convert_btm_to_3d(tBTM_STATUS btm_status)
{
    switch(btm_status)
    {
        case BTM_SUCCESS:
            return (BTA_3D_OK);
        case BTM_BUSY:
            return (BTA_3D_ERR_BUSY);
        case BTM_NO_RESOURCES:
            return (BTA_3D_ERR_NO_RES);
        default:
            return (BTA_3D_ERR);
    }
}

static void bta_3d_cmd_status(tBTA_3D_CMD cmd, tBTA_3D_STATUS status)
{
    tBTA_3D evt;
    tBTA_3D_CBACK *p_cb = bta_3d_cb.p_cback;

    if(p_cb)
    {
        evt.cmd_status.cmd    = cmd;
        evt.cmd_status.status = status;

        (*p_cb)(BTA_3D_COMMAND_STATUS_EVT, &evt);
    }
}

static BOOLEAN bta_3d_create_record(char *service_name)
{
    APPL_TRACE_DEBUG("%s: Enter", __FUNCTION__);
    BOOLEAN result       = TRUE;
    UINT16  service_uuid = UUID_SERVCLASS_3D_DISPLAY;

    bta_3d_cb.sdp_handle = SDP_CreateRecord();

    result &= SDP_AddServiceClassIdList(bta_3d_cb.sdp_handle, 1, &service_uuid);
    result &= SDP_AddProfileDescriptorList(bta_3d_cb.sdp_handle, UUID_SERVCLASS_3D_SYNC, 0x0100);

    if(service_name && service_name[0] != '\0')
        result &= SDP_AddAttribute(bta_3d_cb.sdp_handle, ATTR_ID_SERVICE_NAME, TEXT_STR_DESC_TYPE,
                         (UINT32)(strlen(service_name)+1), (UINT8 *)service_name);

    if(!result)
    {
        SDP_DeleteRecord(bta_3d_cb.sdp_handle);
        bta_3d_cb.sdp_handle = 0;
    }

    APPL_TRACE_DEBUG("%s: Exit(%d)", __FUNCTION__,result);
    return (result);
}

static void bta_3d_cleanup()
{
    APPL_TRACE_DEBUG("%s: Enter", __FUNCTION__);
    BTA_Set3DEIREnabled(FALSE, 0);
    SDP_DeleteRecord(bta_3d_cb.sdp_handle);
    BTM_DeleteReservedLTADDR(bta_3d_cb.lt_addr);
    BTM_DeregisterCLB();
    L2CA_UcdDeregister(bta_3d_cb.psm);
    L2CA_Deregister(bta_3d_cb.psm);
    bta_3d_cb.state = BTA_3D_DISABLED;
    APPL_TRACE_DEBUG("%s: Exit", __FUNCTION__);
}

BOOLEAN bta_3d_hdl_event(BT_HDR *p_msg)
{
    APPL_TRACE_DEBUG("%s: Enter(%04X)", __FUNCTION__,p_msg->event);
    switch(p_msg->event)
    {
        case BTA_3D_API_ENABLE_EVT:
            APPL_TRACE_DEBUG(" BTA_3D_API_ENABLE_EVT is %d: %04X",  BTA_3D_API_ENABLE_EVT,  BTA_3D_API_ENABLE_EVT );
            bta_3d_api_enable((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_API_DISABLE_EVT:
            bta_3d_api_disable();
            break;
        case BTA_3D_API_WRITE_SYNC_PARAM_EVT:
            bta_3d_api_write_params((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_API_START_SYNC_TRAIN_EVT:
            bta_3d_api_start_train();
            break;
        case BTA_3D_API_SET_BCAST_DATA_EVT:
            bta_3d_api_set_bcast_data((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_API_ENABLE_BCAST_EVT:
            bta_3d_api_enable_bcast((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_API_DISABLE_BCAST_EVT:
            bta_3d_api_disable_bcast();
            break;
        case BTA_3D_API_ENABLE_CLK_CAP_EVT:
            bta_3d_api_enable_clk_cap((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_API_DISABLE_CLK_CAP_EVT:
            bta_3d_api_disable_clk_cap();
            break;
        case BTA_3D_BTM_CLB_CMD_CMPL_EVT:
            bta_3d_btm_clb_cmd_cmpl((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_BTM_SYNC_TRAIN_CMPL_EVT:
            bta_3d_btm_sync_train_cmpl((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_BTM_TRG_CLK_CAP_EVT:
            bta_3d_btm_trg_clk_cap((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_BTM_SLV_PAGE_RSP_TO_EVT:
            bta_3d_btm_slv_page_rsp_to();
            break;
        case BTA_3D_L2CA_UCD_DATA_EVT:
            bta_3d_l2ca_ucd_data((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_BTM_TX_PWR_EVT:
            bta_3d_btm_tx_pwr((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_BTM_VS_EVT:
            bta_3d_btm_vs_evt((tBTA_3D_DATA *)p_msg);
            break;
        case BTA_3D_BTM_CLB_CHANNEL_CHANGE_EVT:
            bta_3d_btm_clb_channel_change_evt();
            break;
        default:
            ;//unknown
    }

    APPL_TRACE_DEBUG("%s: Exit", __FUNCTION__);
    return (TRUE);
}

/*****************************************************************************
** API Action Handlers
*****************************************************************************/
static void bta_3d_api_enable(tBTA_3D_DATA *p_data)
{
    tBTA_3D             evt;
    tBTM_STATUS         btm_status;
    tBTA_3D_STATUS      status   = BTA_3D_OK;
    tBTA_3D_API_ENABLE *p_enable = (tBTA_3D_API_ENABLE *)p_data;

    if(bta_3d_cb.state != BTA_3D_DISABLED)
    {
        evt.status = BTA_3D_ERR_BUSY;
        if(p_data->api_enable.p_cback)
            (*p_data->api_enable.p_cback)(BTA_3D_ENABLE_EVT, &evt);
    }

    memset(&bta_3d_cb, 0, sizeof(bta_3d_cb));

    bta_3d_cb.state = BTA_3D_ENABLING;

    APPL_TRACE_DEBUG("%s: Enter", __FUNCTION__);
    if(p_enable->p_cback)
    {
        bta_3d_cb.p_cback = p_enable->p_cback;
        
        /* Add the SDP record */
        if(bta_3d_create_record(p_enable->p_name))
        {
            /* Register callbacks. */
            if(BTM_RegisterCLB((tBTM_CLB_CB_INFO *)&btm_clb_cb_info) == BTM_SUCCESS)
            {
                if(((bta_3d_cb.psm = L2CA_Register(PSM_3D_SYNC, (tL2CAP_APPL_INFO *)&l2ca_appl_info)) > 0) && (L2CA_UcdRegister(bta_3d_cb.psm, (tL2CAP_UCD_CB_INFO *)&l2ca_cb_info)) && (BTM_SetUCDSecurityLevel(FALSE, "", BTM_SEC_SERVICE_3D_SYNC, BTM_SEC_NONE, PSM_3D_SYNC, 0, 0)))
                {
                    /* Attempt to reserve the lt_addr. The cmd_cmpl callback 
                     * will be used to complete the enable. */ 
                    if((btm_status = BTM_SetReservedLTADDR(BTA_3D_LT_ADDR)) != BTM_CMD_STARTED)
                    {
                        status = convert_btm_to_3d(btm_status);
                    }
                }
                else
                    status = BTA_3D_ERR;
            }
            else
                status = BTA_3D_ERR_BUSY;
        }
        else
            status = BTA_3D_ERR_SDP;

        if(status != BTA_3D_OK)
        {
            bta_3d_cleanup();

            evt.status = status;

            (*bta_3d_cb.p_cback)(BTA_3D_ENABLE_EVT, &evt);

            bta_3d_cb.p_cback = NULL;
        }
    }
}

static void bta_3d_api_disable(void)
{
    tBTA_3D        evt;
    tBTA_3D_CBACK *p_cb = bta_3d_cb.p_cback;

    if(p_cb == NULL)
        return;

    bta_3d_cleanup();

    evt.status = BTA_3D_OK;

    (*p_cb)(BTA_3D_DISABLE_EVT, &evt);
}

static void bta_3d_api_write_params(tBTA_3D_DATA *p_data)
{
    tBTM_STATUS                          status;
    tBTA_3D_API_WRITE_SYNC_TRAIN_PARAMS *p_write_params = (tBTA_3D_API_WRITE_SYNC_TRAIN_PARAMS *)p_data;

    if((status = BTM_WriteSyncTrainParams(BTA_3D_LEGACY_INTERVAL_MIN_MAX_SLOTS, BTA_3D_LEGACY_INTERVAL_MIN_MAX_SLOTS, CONVERT_TO_BASEBAND_SLOTS(p_write_params->timeout), p_write_params->service_data)) != BTM_CMD_STARTED)
        bta_3d_cmd_status(BTA_3D_CMD_WRITE_PARAMS, convert_btm_to_3d(status));
}

static void bta_3d_api_start_train(void)
{
    tBTM_STATUS status;

    if((status = BTM_StartSyncTrain()) != BTM_CMD_STARTED)
        bta_3d_cmd_status(BTA_3D_CMD_START_TRAIN, convert_btm_to_3d(status));
}

static void bta_3d_api_set_bcast_data(tBTA_3D_DATA *p_data)
{
    UINT8                       buf[BTA_3D_BCAST_DATA_BUF_SIZE];
    UINT8                      *p_buf                           = buf;
    UINT32                      sync_mode;
    tBTM_STATUS                 status;
    tBTA_3D_API_SET_BCAST_DATA *p_set_data                      = (tBTA_3D_API_SET_BCAST_DATA *)p_data;

    sync_mode = p_set_data->bcast_data.instant & BTA_3D_BCAST_INSTANT_BITMASK;
    
    APPL_TRACE_DEBUG("Dual View: %d", p_set_data->bcast_data.dual_view);
    if(p_set_data->bcast_data.dual_view)
        sync_mode |= BTA_3D_BCAST_VMODE_DUAL_VIEW;

    UINT32_TO_STREAM(p_buf, sync_mode);
    UINT16_TO_STREAM(p_buf, p_set_data->bcast_data.phase);
    UINT16_TO_STREAM(p_buf, p_set_data->bcast_data.left_open_off);
    UINT16_TO_STREAM(p_buf, p_set_data->bcast_data.left_close_off);
    UINT16_TO_STREAM(p_buf, p_set_data->bcast_data.right_open_off);
    UINT16_TO_STREAM(p_buf, p_set_data->bcast_data.right_close_off);
    UINT16_TO_STREAM(p_buf, p_set_data->bcast_data.period);
    UINT8_TO_STREAM (p_buf, p_set_data->bcast_data.fraction);

    APPL_TRACE_DEBUG("Sync: %d", p_set_data->bcast_data.instant & BTA_3D_BCAST_INSTANT_BITMASK);
    APPL_TRACE_DEBUG("Sync_Mode: %08X", sync_mode);
    APPL_TRACE_DEBUG("LLO: %d", p_set_data->bcast_data.left_open_off);
    APPL_TRACE_DEBUG("LLC: %d", p_set_data->bcast_data.left_close_off);
    APPL_TRACE_DEBUG("RLO: %d", p_set_data->bcast_data.right_open_off);
    APPL_TRACE_DEBUG("RLC: %d", p_set_data->bcast_data.right_close_off);
    APPL_TRACE_DEBUG("Period: %d", p_set_data->bcast_data.period);

    if((status = BTM_SetCLBData(bta_3d_cb.lt_addr, HCI_CLB_FRAGMENT_SINGLE, BTA_3D_BCAST_DATA_BUF_SIZE, buf)) != BTM_CMD_STARTED)
        bta_3d_cmd_status(BTA_3D_CMD_SET_BROADCAST_DATA, convert_btm_to_3d(status));
}

static void bta_3d_api_enable_bcast(tBTA_3D_DATA *p_data)
{
    tBTM_STATUS               status;
    tBTA_3D_API_ENABLE_BCAST *p_enable = (tBTA_3D_API_ENABLE_BCAST *)p_data;

    status = BTM_SetCLB(HCI_CLB_ENABLE, 
                        bta_3d_cb.lt_addr,
                        p_enable->low_power?HCI_CLB_LPO_ALLOWED:HCI_CLB_LPO_DISALLOWED,
                        BTA_3D_CLB_BR_PACKETS,
                        BTA_3D_LEGACY_INTERVAL_MIN_MAX_SLOTS,
                        BTA_3D_LEGACY_INTERVAL_MIN_MAX_SLOTS,
                        CONVERT_TO_BASEBAND_SLOTS(p_enable->timeout));

    if(status != BTM_CMD_STARTED)
        bta_3d_cmd_status(BTA_3D_CMD_SET_BROADCAST, convert_btm_to_3d(status));
}

static void bta_3d_api_disable_bcast(void)
{
    tBTM_STATUS status;

    if((status = BTM_SetCLB(HCI_CLB_DISABLE, bta_3d_cb.lt_addr, 0, 0, 0, 0, 0)) != BTM_CMD_STARTED)
        bta_3d_cmd_status(BTA_3D_CMD_SET_BROADCAST, convert_btm_to_3d(status));
}

static void bta_3d_api_enable_clk_cap(tBTA_3D_DATA *p_data)
{
    tBTM_STATUS                 status;
    tBTA_3D_API_ENABLE_CLK_CAP *p_enable = (tBTA_3D_API_ENABLE_CLK_CAP *)p_data;

    if((status = BTM_SetTrigClkCapture(0, HCI_CLB_ENABLE, HCI_WHICH_CLOCK_LOCAL, HCI_CLB_LPO_DISALLOWED, p_enable->filter_count)) != BTM_CMD_STARTED)
        bta_3d_cmd_status(BTA_3D_CMD_SET_CLK_CAP, convert_btm_to_3d(status));
}

static void bta_3d_api_disable_clk_cap(void)
{
    tBTM_STATUS status;

    if((status = BTM_SetTrigClkCapture(0, HCI_CLB_DISABLE, HCI_WHICH_CLOCK_LOCAL, 0, 0)) != BTM_CMD_STARTED)
        bta_3d_cmd_status(BTA_3D_CMD_SET_CLK_CAP, convert_btm_to_3d(status));
}

/*****************************************************************************
** Lower Level Callback Action Handlers
*****************************************************************************/
static void bta_3d_btm_clb_cmd_cmpl(tBTA_3D_DATA *p_data)
{
    UINT8                     cmd_status = HCI_ERR_UNSPECIFIED;
    tBTA_3D                   evt;
    tBTA_3D_CBACK            *p_cb       = bta_3d_cb.p_cback;
    tBTA_3D_STATUS            status     = BTA_3D_ERR;
    tBTA_3D_BTM_CLB_CMD_CMPL *p_cmd_cmpl = (tBTA_3D_BTM_CLB_CMD_CMPL *)p_data;

    APPL_TRACE_DEBUG("%s: Enter(%d)", __FUNCTION__, p_cmd_cmpl->data.command_type);
    if((p_cmd_cmpl->data.command_type == BTM_SET_RESERVED_LT_ADDR_CMPL) && (bta_3d_cb.state == BTA_3D_ENABLING))
    {
    APPL_TRACE_DEBUG("LT ADDR cmpl: %d",p_cmd_cmpl->data.data.set_reserved.status);
        if((!p_cmd_cmpl->data.timeout) && (p_cmd_cmpl->data.data.set_reserved.status == HCI_SUCCESS)
                && (BTM_ReadInquiryRspTxPower(btm_read_inq_rsp_tx_pwr_cmpl) == BTM_CMD_STARTED))
        {
            bta_3d_cb.lt_addr = p_cmd_cmpl->data.data.set_reserved.lt_addr;
        }
        else
        {
            bta_3d_cleanup();
            evt.status = BTA_3D_ERR;

            if(p_cb)
                (*p_cb)(BTA_3D_ENABLE_EVT, &evt);
        }


    }
    else
    {
        if(!p_cmd_cmpl->data.timeout)
        {
            switch(p_cmd_cmpl->data.command_type)
            {
                case BTM_SET_CLB_CMPL:
                    cmd_status = p_cmd_cmpl->data.data.set_clb.status;
                    break;
                case BTM_START_SYNC_TRAIN_CMPL:
                    cmd_status = p_cmd_cmpl->data.data.status;
                    break;
                case BTM_SET_CLB_DATA_CMPL:
                    cmd_status = p_cmd_cmpl->data.data.set_clb_data.status;
                    break;
                case BTM_WRITE_SYNC_TRAIN_PARAM_CMPL:
                    cmd_status = p_cmd_cmpl->data.data.write_param.status;
                    break;
                case BTM_SET_TRG_CLK_CAP_CMPL:
                    cmd_status = p_cmd_cmpl->data.data.status;
                    break;
                default:
                    //Unexpected cmd result, so break out
                    return;
            }

            status = (cmd_status == HCI_SUCCESS)?BTA_3D_OK:BTA_3D_ERR;
        }
        else
            status = BTA_3D_ERR_CMD_TIMEOUT;

        bta_3d_cmd_status(p_cmd_cmpl->data.command_type, status);
    }
}

static void bta_3d_btm_sync_train_cmpl(tBTA_3D_DATA *p_data)
{
    tBTA_3D                      evt;
    tBTA_3D_CBACK               *p_cb   = bta_3d_cb.p_cback;
    tBTA_3D_BTM_SYNC_TRAIN_CMPL *p_cmpl = (tBTA_3D_BTM_SYNC_TRAIN_CMPL *)p_data;

    if(p_cb)
    {
        evt.train_status = p_cmpl->status;

        (*p_cb)(BTA_3D_SYNC_TRAIN_CMPL_EVT, &evt);
    }
}

static void bta_3d_btm_trg_clk_cap(tBTA_3D_DATA *p_data)
{
    tBTA_3D                  evt;
    tBTA_3D_CBACK           *p_cb  = bta_3d_cb.p_cback;
    tBTA_3D_BTM_TRG_CLK_CAP *p_cap = (tBTA_3D_BTM_TRG_CLK_CAP *)p_data;

    if(p_cb)
    {
        evt.clk_cap.clock  = p_cap->data.clock;
        evt.clk_cap.offset = p_cap->data.offset;

        (*p_cb)(BTA_3D_CLK_CAP_EVT, &evt);
    }
}

static void bta_3d_btm_slv_page_rsp_to(void)
{
    tBTA_3D_CBACK *p_cb = bta_3d_cb.p_cback;

    if(p_cb)
        (*p_cb)(BTA_3D_SLV_PAGE_RSP_TO_EVT, NULL);
}

static void bta_3d_btm_tx_pwr(tBTA_3D_DATA *p_data)
{
    tBTA_3D        evt;
    UINT8          enable;
    tBTA_3D_CBACK *p_cb   = bta_3d_cb.p_cback;
    
    if(p_data->tx_power.status == BTM_SUCCESS)
    {
        BTA_Set3DEIREnabled(TRUE, p_data->tx_power.tx_power);

        //Enable Legacy Association
        enable = 1;
        BTM_VendorSpecificCommand(BTA_3D_LEGACY_VS_ASSOC_CMD_OCF | HCI_GRP_VENDOR_SPECIFIC, 1, &enable, btm_vs_cmpl);
        BTM_RegisterForVSEvents(btm_vs_evt, TRUE);

        evt.status      = BTA_3D_OK;

        bta_3d_cb.state = BTA_3D_ENABLED;
    }
    else
    {
        evt.status = BTA_3D_ERR;

        bta_3d_cleanup();
    }

    if(p_cb)
        (*p_cb)(BTA_3D_ENABLE_EVT, &evt);
}

static void bta_3d_l2ca_ucd_data(tBTA_3D_DATA *p_data)
{
    UINT8         *p      = p_data->ucd_data.data;
    UINT8          opcode;
    tBTA_3D        evt;
    tBTA_3D_CBACK *p_cb   = bta_3d_cb.p_cback;

    STREAM_TO_UINT8(opcode, p);

    switch(opcode)
    {
        case BTA_3D_UCD_OPCODE_CONN_ANN:
            if(p_data->ucd_data.len >= BTA_3D_UCD_CONN_MSG_SIZE)
            {
                bdcpy(evt.association.bd, p_data->ucd_data.bd);
                STREAM_TO_UINT8(evt.association.flags, p);
                STREAM_TO_UINT8(evt.association.battery, p);
                evt.association.legacy = FALSE;

                if(p_cb)
                    (*p_cb)(BTA_3D_ASSOCIATION_EVT, &evt);
            }

            break;
        default:
            APPL_TRACE_WARNING("Unknown UCD opcode: %d", opcode);
    }
}

static void bta_3d_btm_vs_evt(tBTA_3D_DATA *p_data)
{
    tBTA_3D_CBACK *p_cb = bta_3d_cb.p_cback;
    tBTA_3D evt;
    UINT8 *p = p_data->vs_evt.data;
    UINT8 evt_code;

    STREAM_TO_UINT8(evt_code, p);

    switch(evt_code)
    {
        case BTA_3D_LEGACY_VS_ASSOC_EVT_CODE:
            if(p_data->vs_evt.len >= BTA_3D_LEGACY_VS_ASSOC_EVT_LEN)
            {
                STREAM_TO_BDADDR(evt.association.bd, p);
                evt.association.legacy = TRUE;

                if(p_cb)
                    (*p_cb)(BTA_3D_ASSOCIATION_EVT, &evt);
            }
            break;
        default:
            ;
    }
}

static void bta_3d_btm_clb_channel_change_evt(void)
{
    tBTA_3D_CBACK *p_cb = bta_3d_cb.p_cback;

    if(p_cb)
        (*p_cb) (BTA_3D_CHANNEL_CHANGE_EVT, NULL);
}

/*****************************************************************************
** BTM Callbacks
*****************************************************************************/
static void btm_clb_cmd_cmpl(void *result)
{
    tBTM_CLB_CMD_CMPL        *p_cmpl = (tBTM_CLB_CMD_CMPL *)result;
    tBTA_3D_BTM_CLB_CMD_CMPL *p_buf;

    if(p_cmpl)
    {
        if((p_buf = (tBTA_3D_BTM_CLB_CMD_CMPL *)GKI_getbuf(sizeof(tBTA_3D_BTM_CLB_CMD_CMPL))) != NULL)
        {
            p_buf->hdr.event = BTA_3D_BTM_CLB_CMD_CMPL_EVT;
            p_buf->data      = *p_cmpl;

            bta_sys_sendmsg(p_buf);
        }
    }
}

static void btm_sync_train_cmpl(UINT8 status)
{
    tBTA_3D_BTM_SYNC_TRAIN_CMPL *p_buf;

    if((p_buf = (tBTA_3D_BTM_SYNC_TRAIN_CMPL *)GKI_getbuf(sizeof(tBTA_3D_BTM_SYNC_TRAIN_CMPL))) != NULL)
    {
        p_buf->hdr.event = BTA_3D_BTM_SYNC_TRAIN_CMPL_EVT;
        p_buf->status    = status;

        bta_sys_sendmsg(p_buf);
    }
}

static void btm_trg_clk_cap(tBTM_TRG_CLK_CAP *p_cap)
{
    tBTA_3D_BTM_TRG_CLK_CAP *p_buf;

    if((p_buf = (tBTA_3D_BTM_TRG_CLK_CAP *)GKI_getbuf(sizeof(tBTA_3D_BTM_TRG_CLK_CAP))) != NULL)
    {
        p_buf->hdr.event = BTA_3D_BTM_TRG_CLK_CAP_EVT;
        p_buf->data      = *p_cap;

        bta_sys_sendmsg(p_buf);
    }
}

static void btm_slave_page_response_to(void)
{
    BT_HDR *p_buf;

    if((p_buf = (BT_HDR *)GKI_getbuf(sizeof(BT_HDR))) != NULL)
    {
        p_buf->event = BTA_3D_BTM_SLV_PAGE_RSP_TO_EVT;

        bta_sys_sendmsg(p_buf);
    }
}

static void btm_read_inq_rsp_tx_pwr_cmpl(void *p)
{
    tBTA_3D_BTM_TX_PWR     *p_buf;
    tBTM_INQ_TXPWR_RESULTS *p_results = (tBTM_INQ_TXPWR_RESULTS *)p;

    if((p_buf = (tBTA_3D_BTM_TX_PWR *)GKI_getbuf(sizeof(tBTA_3D_BTM_TX_PWR))) != NULL)
    {
        p_buf->hdr.event = BTA_3D_BTM_TX_PWR_EVT;
        p_buf->status    = p_results->status;
        p_buf->tx_power  = p_results->tx_power;

        bta_sys_sendmsg(p_buf);
    }
}

static void btm_vs_cmpl(tBTM_VSC_CMPL *p_buf)
{
    int i;

    APPL_TRACE_DEBUG("vs_cmpl: %04X", p_buf->opcode);

    for(i=0;i<p_buf->param_len;i++)
        APPL_TRACE_DEBUG("vs_cmpl[%d]=%02X", i, p_buf->p_param_buf[i]);
}

static void btm_vs_evt(UINT8 len, UINT8 *p)
{
    tBTA_3D_BTM_VS_EVT *p_buf;

    if((p_buf = (tBTA_3D_BTM_VS_EVT *)GKI_getbuf(sizeof(tBTA_3D_BTM_VS_EVT) + len)) != NULL)
    {
        p_buf->hdr.event = BTA_3D_BTM_VS_EVT;
        p_buf->len       = len;
        memcpy(p_buf->data, p, len);

        bta_sys_sendmsg(p_buf);
    }
}

static void btm_clb_channel_change(void)
{
    BT_HDR *p_buf;

    if((p_buf = (BT_HDR *)GKI_getbuf(sizeof(BT_HDR))) != NULL)
    {
        p_buf->event = BTA_3D_BTM_CLB_CHANNEL_CHANGE_EVT;

        bta_sys_sendmsg(p_buf);
    }
}
/*****************************************************************************
** UCD L2CAP Callbacks
*****************************************************************************/
static void l2ca_ucd_disc_cb(BD_ADDR bd, UINT8 type, UINT32 data)
{
    //We are only a UCD server
}

static void l2ca_ucd_data_cb(BD_ADDR bd, BT_HDR *p_buf)
{
    UINT8                 *p         = (UINT8 *)(p_buf + 1) + p_buf->offset;
    tBTA_3D_L2CA_UCD_DATA *p_bta_buf;

    if((p_bta_buf = (tBTA_3D_L2CA_UCD_DATA *)GKI_getbuf(sizeof(tBTA_3D_L2CA_UCD_DATA) + p_buf->len)) != NULL)
    {
        p_bta_buf->hdr.event = BTA_3D_L2CA_UCD_DATA_EVT;
        bdcpy(p_bta_buf->bd, bd);
        p_bta_buf->len = p_buf->len;
        memcpy(p_bta_buf->data, p, p_buf->len);

        bta_sys_sendmsg(p_bta_buf);
    }
}

static void l2ca_ucd_cong_status_cb(BD_ADDR bd, BOOLEAN cong)
{
}

/*****************************************************************************
** Dummy L2CAP Callbacks
*****************************************************************************/
//XXX Note we only use UCD data, so these are all empty;
//XXX however, we are still required to call L2CA_Register before we can
//XXX call L2CA_UcdRegister
static void l2ca_connect_ind(BD_ADDR bd, UINT16 lcid, UINT16 psm, UINT8 id)
{
}

static void l2ca_connect_cfm(UINT16 lcid, UINT16 result)
{
}

static void l2ca_connect_pnd_cb(UINT16 lcid)
{
}

static void l2ca_config_ind(UINT16 lcid, tL2CAP_CFG_INFO *info)
{
}

static void l2ca_config_cfm(UINT16 lcid, tL2CAP_CFG_INFO *info)
{
}

static void l2ca_disc_ind(UINT16 lcid, BOOLEAN ack)
{
}

static void l2ca_disc_cfm(UINT16 lcid, UINT16 result)
{
}

static void l2ca_qos_violation_ind(BD_ADDR bd)
{
}

static void l2ca_data_ind(UINT16 lcid, BT_HDR *p_buf)
{
}

static void l2ca_cong_status(UINT16 lcid, BOOLEAN cong)
{
}

static void l2ca_tx_cmpl(UINT16 lcid, UINT16 num)
{
}




#endif
