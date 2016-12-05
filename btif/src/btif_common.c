#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hardware/bluetooth.h>

#define LOG_NDDEBUG 0
#define LOG_TAG "bluedroid"

#include "btif_common.h"
#include "btif_api.h"
#include "bt_utils.h"
//#include "btif_init.h"

/************************************************************************************
**  Static variables
************************************************************************************/

bt_callbacks_t *bt_hal_cbacks = NULL;
/** Operating System specific callouts for resource management */
bt_os_callouts_t *bt_os_callouts = NULL;


