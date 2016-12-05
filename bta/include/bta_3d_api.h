//XXX copyright header?
#ifndef BTA_3D_API_H
#define BTA_3D_API_H

#include "bta_api.h"
#include "btm_api.h"

#define BTA_3D_ENABLE_EVT          1
#define BTA_3D_DISABLE_EVT         2
#define BTA_3D_ASSOCIATION_EVT     3
#define BTA_3D_CLK_CAP_EVT         4
#define BTA_3D_SYNC_TRAIN_CMPL_EVT 5
#define BTA_3D_SLV_PAGE_RSP_TO_EVT 6
#define BTA_3D_COMMAND_STATUS_EVT  7
#define BTA_3D_CHANNEL_CHANGE_EVT  8

typedef UINT16 tBTA_3D_EVT;

enum
{
    BTA_3D_OK,
    BTA_3D_ERR,
    BTA_3D_ERR_SDP,
    BTA_3D_ERR_NO_RES,
    BTA_3D_ERR_BUSY,
    BTA_3D_ERR_CMD_TIMEOUT
};

typedef UINT8 tBTA_3D_STATUS;

typedef struct
{
    BD_ADDR bd;
    UINT8   flags;
    UINT8   battery;
    BOOLEAN legacy;
} tBTA_3D_ASSOC;

#define BTA_3D_ASSOC_FLAGS_ASSOC         0x01
#define BTA_3D_ASSOC_FLAGS_USER_BATT_REQ 0x02

#define BTA_3D_ASSOC_BATT_LVL_NOT_SUPP   0xFF

typedef struct
{
    UINT32 clock;
    UINT16 offset;
} tBTA_3D_CLK_CAP;

#define BTA_3D_CMD_WRITE_PARAMS         BTM_WRITE_SYNC_TRAIN_PARAM_CMPL
#define BTA_3D_CMD_START_TRAIN          BTM_START_SYNC_TRAIN_CMPL
#define BTA_3D_CMD_SET_BROADCAST_DATA   BTM_SET_CLB_DATA_CMPL
#define BTA_3D_CMD_SET_BROADCAST        BTM_SET_CLB_CMPL
#define BTA_3D_CMD_SET_CLK_CAP          BTM_SET_TRG_CLK_CAP_CMPL

typedef UINT16 tBTA_3D_CMD;

typedef struct
{
    tBTA_3D_CMD cmd;
    tBTA_3D_STATUS status;
} tBTA_3D_CMD_STATUS;

typedef union
{
    tBTA_3D_STATUS     status;         /* ENABLE_EVT          */
    tBTA_3D_ASSOC      association;    /* ASSOCIATION_EVT     */
    tBTA_3D_CLK_CAP    clk_cap;        /* CLK_CAP_EVT         */
    UINT8              train_status;   /* SYNC_TRAIN_CMPL_EVT */
    tBTA_3D_CMD_STATUS cmd_status;     /* COMMAND_STATUS      */
} tBTA_3D;

/* BTA 3D callback function. */
typedef void (tBTA_3D_CBACK) (tBTA_3D_EVT event, tBTA_3D *p_data);

typedef struct
{
    UINT32 instant;
    UINT16 phase;
    UINT16 left_open_off;
    UINT16 left_close_off;
    UINT16 right_open_off;
    UINT16 right_close_off;
    UINT16 period;
    UINT8 fraction;
    BOOLEAN dual_view;
} tBTA_3D_BCAST_DATA;

#ifdef __cplusplus
extern "C"
{
#endif

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
    BTA_API extern void BTA_3dEnable(tBTA_3D_CBACK *p_cback, char *p_service_name);

    /*******************************************************************************
     **
     ** Function         BTA_3dDisable
     **
     ** Description      This function is called when the host is about power down.
     **
     ** Returns          void
     **
     *******************************************************************************/
    BTA_API extern void BTA_3dDisable(void);

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
    BTA_API extern void BTA_3dWriteSyncTrainParams(UINT32 timeout, UINT8 service_data);

    /*******************************************************************************
     **
     ** Function         BTA_3dStartSyncTrain
     **
     ** Description      This function start the synchronization train.
     **
     ** Returns          void
     **
     *******************************************************************************/
    BTA_API extern void BTA_3dStartSyncTrain(void);

    /*******************************************************************************
     **
     ** Function         BTA_3dSetBroadcastData
     **
     ** Description      This function sets the data being broadcast.
     **
     ** Returns          void
     **
     *******************************************************************************/
    BTA_API extern void BTA_3dSetBroadcastData(tBTA_3D_BCAST_DATA *p_bcast_data);

    /*******************************************************************************
     **
     ** Function         BTA_3dEnableBroadcasts
     **
     ** Description      This function enables 3D broadcasts.
     **
     ** Returns          void
     **
     *******************************************************************************/
    BTA_API extern void BTA_3dEnableBroadcasts(UINT16 timeout, BOOLEAN low_power);

    /*******************************************************************************
     **
     ** Function         BTA_3dDisableBroadcasts
     **
     ** Description      This function disables 3D broadcasts.
     **
     ** Returns          void
     **
     *******************************************************************************/
    BTA_API extern void BTA_3dDisableBroadcasts(void);

    /*******************************************************************************
     **
     ** Function         BTA_3dEnableClockCapture
     **
     ** Description      This function enabled Triggered Clock Capture.
     **
     ** Returns          void
     **
     *******************************************************************************/
    BTA_API extern void BTA_3dEnableClockCapture(UINT8 filter_count);

    /*******************************************************************************
     **
     ** Function         BTA_3dDisableClockCapture
     **
     ** Description      This function disabled Triggered Clock Capture.
     **
     ** Returns          void
     **
     *******************************************************************************/
    BTA_API extern void BTA_3dDisableClockCapture(void);

#ifdef __cplusplus
}
#endif

#endif
