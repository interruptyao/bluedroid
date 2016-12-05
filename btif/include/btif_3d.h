#ifndef BTIF_3D_H
#define BTIF_3D_H

#include <hardware/bluetooth.h>
#include <hardware/bt_3d.h>
#include <stdint.h>
#include "bta_3d_api.h"
#include "btu.h"

#define BTIF_3D_SERVICE_NAME "3D Synchronization Display" 
#if 0
/* Bluetooth 3D Mode */
typedef enum {
    BTIF_3D_MODE_IDLE = 0,
    BTIF_3D_MODE_MASTER,
    BTIF_3D_MODE_SLAVE,
    BTIF_3D_MODE_SHOWROOM
} btif_3d_mode_t;

/* Bluetooth 3D Broadcast data */
typedef struct {
    uint16_t left_open_offset;
    uint16_t left_close_offset;
    uint16_t right_open_offset;
    uint16_t right_close_offset;
    uint16_t delay;
    uint8_t dual_view;
} btif_3d_data_t;

/** Callback for UCD Assoc Notification
 */
typedef void (* btif_3d_assos_notif_callback)(bt_bdaddr_t *bd_addr);

/** Callback for UCD Battery Report
 */
typedef void (* btif_3d_batt_level_callback)(bt_bdaddr_t *bd_addr,
                                          int8_t battery_level);

/** Callback for Frame period
 */
typedef void (*btif_3d_frame_period_callback)(uint16_t frame_period);

/** Callback for Slave synchronization with master (Only relevant in slave mode)
 * If lock_status is TRUE, then the slave is locked to Master, otherwise lost sync with the master*/
typedef void (*btif_3d_master_sync_callback)(uint8_t lock_status);

/** BT-3D callback structure. */
typedef struct {
    /** set to sizeof(bt3d_callbacks_t) */
    size_t      size;
    btif_3d_assos_notif_callback assos_notif_cb;
    btif_3d_batt_level_callback  batt_level_cb;
    btif_3d_frame_period_callback frame_period_cb;
    btif_3d_master_sync_callback master_sync_cb;
} btif_3d_callbacks_t;

#endif

bt_status_t btif_3d_init(void* callbacks);
bt_status_t btif_3d_set_mode(bt3d_mode_t mode, bt_bdaddr_t *master_bd_addr);
bt_status_t btif_3d_broadcast_3d_data(bt3d_data_t data);
void btif_3d_cleanup(void);

#endif
