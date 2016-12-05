/******************************************************************************
 *
 *  This file contains BTA 3D Sync internal definitions
 *
 ******************************************************************************/

#ifndef BTA_3D_INT_H
#define BTA_3D_INT_H

#include "bta_sys.h"
#include "bd.h"
#include "utl.h"
#include "bta_3d_api.h"

#define PSM_3D_SYNC                0x0021
#define BTA_3D_LT_ADDR             1

#define BTA_3D_BCAST_DATA_BUF_SIZE 17

#define BTA_3D_BCAST_INSTANT_BITMASK 0x03FFFFFF
#define BTA_3D_BCAST_VMODE_BITMASK   0x40000000

#define BTA_3D_BCAST_VMODE_3D        0x00000000
#define BTA_3D_BCAST_VMODE_DUAL_VIEW 0x40000000

#define BTA_3D_LEGACY_VS_ASSOC_CMD_OCF 0x0013

#define BTA_3D_LEGACY_VS_ASSOC_EVT_CODE 0x14
#define BTA_3D_LEGACY_VS_ASSOC_EVT_LEN  18

#define BTA_3D_CLB_BR_PACKETS        (BTM_ACL_PKT_TYPES_MASK_DM1 | \
                                      BTM_ACL_PKT_TYPES_MASK_NO_2_DH1 | \
                                      BTM_ACL_PKT_TYPES_MASK_NO_3_DH1 | \
                                      BTM_ACL_PKT_TYPES_MASK_NO_2_DH3 | \
                                      BTM_ACL_PKT_TYPES_MASK_NO_3_DH3 | \
                                      BTM_ACL_PKT_TYPES_MASK_NO_2_DH5 | \
                                      BTM_ACL_PKT_TYPES_MASK_NO_3_DH5)

#define BTA_3D_LEGACY_INTERVAL_MIN_MAX 80

#define CONVERT_TO_BASEBAND_SLOTS(_x)                             ((UINT32)((((8000L * ((unsigned long)(_x))) / 500L) + 5L)/10L))
#define CONVERT_FROM_BASEBAND_SLOTS(_x)                           ((UINT32)((((5000L * (_x)) / 800L) + 5L)/10L))

#define BTA_3D_LEGACY_INTERVAL_MIN_MAX_SLOTS (CONVERT_TO_BASEBAND_SLOTS(BTA_3D_LEGACY_INTERVAL_MIN_MAX))

#define BTA_3D_UCD_CONN_MSG_SIZE 3

#define BTA_3D_UCD_OPCODE_CONN_ANN 0
/* Events for the main mailbox. */
enum
{
    /* API events */
    BTA_3D_API_ENABLE_EVT = BTA_SYS_EVT_START(BTA_ID_3D),
    BTA_3D_API_DISABLE_EVT,
    BTA_3D_API_WRITE_SYNC_PARAM_EVT,
    BTA_3D_API_START_SYNC_TRAIN_EVT,
    BTA_3D_API_SET_BCAST_DATA_EVT,
    BTA_3D_API_ENABLE_BCAST_EVT,
    BTA_3D_API_DISABLE_BCAST_EVT,
    BTA_3D_API_ENABLE_CLK_CAP_EVT,
    BTA_3D_API_DISABLE_CLK_CAP_EVT,

    /* Callback events */
    BTA_3D_BTM_CLB_CMD_CMPL_EVT,
    BTA_3D_BTM_SYNC_TRAIN_CMPL_EVT,
    BTA_3D_BTM_TRG_CLK_CAP_EVT,
    BTA_3D_BTM_SLV_PAGE_RSP_TO_EVT,
    BTA_3D_L2CA_UCD_DATA_EVT,
    BTA_3D_BTM_TX_PWR_EVT,
    BTA_3D_BTM_VS_EVT,
    BTA_3D_BTM_CLB_CHANNEL_CHANGE_EVT
};

typedef struct
{
    BT_HDR         hdr;
    tBTA_3D_CBACK *p_cback;
    char           p_name[BTA_SERVICE_NAME_LEN+1];

} tBTA_3D_API_ENABLE;

typedef struct
{
    BT_HDR hdr;
    UINT32 timeout;
    UINT8  service_data;

} tBTA_3D_API_WRITE_SYNC_TRAIN_PARAMS;

typedef struct
{
    BT_HDR             hdr;
    tBTA_3D_BCAST_DATA bcast_data;

} tBTA_3D_API_SET_BCAST_DATA;

typedef struct
{
    BT_HDR  hdr;
    UINT16  timeout;
    BOOLEAN low_power;

} tBTA_3D_API_ENABLE_BCAST;

typedef struct
{
    BT_HDR hdr;
    UINT8  filter_count;

} tBTA_3D_API_ENABLE_CLK_CAP;

typedef struct
{
    BT_HDR            hdr;
    tBTM_CLB_CMD_CMPL data;
} tBTA_3D_BTM_CLB_CMD_CMPL;

typedef struct
{
    BT_HDR hdr;
    UINT8  status;
} tBTA_3D_BTM_SYNC_TRAIN_CMPL;

typedef struct
{
    BT_HDR           hdr;
    tBTM_TRG_CLK_CAP data;
} tBTA_3D_BTM_TRG_CLK_CAP;

typedef struct
{
    BT_HDR  hdr;
    BD_ADDR bd;
    UINT16  len;
    UINT8   data[1];
} tBTA_3D_L2CA_UCD_DATA;

typedef struct
{
    BT_HDR      hdr;
    tBTM_STATUS status;
    INT8        tx_power;
} tBTA_3D_BTM_TX_PWR;

typedef struct
{
    BT_HDR hdr;
    UINT8  len;
    UINT8  data[1];
} tBTA_3D_BTM_VS_EVT;

typedef union
{
    BT_HDR                              hdr;
    tBTA_3D_API_ENABLE                  api_enable;
    tBTA_3D_API_WRITE_SYNC_TRAIN_PARAMS api_write_train_params;
    tBTA_3D_API_SET_BCAST_DATA          api_set_bcast_data;
    tBTA_3D_API_ENABLE_BCAST            api_enable_bcast;
    tBTA_3D_API_ENABLE_CLK_CAP          api_enable_clk_cap;
    tBTA_3D_BTM_CLB_CMD_CMPL            clb_cmd_cmpl;
    tBTA_3D_BTM_SYNC_TRAIN_CMPL         sync_train_cmpl;
    tBTA_3D_BTM_TRG_CLK_CAP             trg_clk_cap;
    tBTA_3D_L2CA_UCD_DATA               ucd_data;
    tBTA_3D_BTM_TX_PWR                  tx_power;
    tBTA_3D_BTM_VS_EVT                  vs_evt;
} tBTA_3D_DATA;

extern BOOLEAN bta_3d_hdl_event(BT_HDR *p_msg);

/******************************************************************************
** Main Control Block
*******************************************************************************/
enum
{
    BTA_3D_DISABLED,
    BTA_3D_ENABLING,
    BTA_3D_ENABLED,
    BTA_3D_DISABLING
};

typedef UINT8 tBTA_3D_STATE;

typedef struct
{
    tBTA_3D_STATE  state;
    tBTA_3D_CBACK *p_cback;
    UINT32         sdp_handle;
    UINT8          lt_addr;
    UINT16         psm;
}
tBTA_3D_CB;

#if BTA_DYNAMIC_MEMORY == FALSE
extern tBTA_3D_CB bta_3d_cb;
#else
extern tBTA_3D_CB *bta_3d_cb_ptr;
#define bta_3d_cb (*bta_3d_cb_ptr)
#endif

#endif
