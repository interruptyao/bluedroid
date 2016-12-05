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
 *  Filename:      bluedroidtest.c
 *
 *  Description:   Bluedroid Test application
 *
 ***********************************************************************************/

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <private/android_filesystem_config.h>
#include <android/log.h>

#include <hardware/hardware.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_3d.h>

/************************************************************************************
**  Constants & Macros
************************************************************************************/

#define PID_FILE "/data/.bdt_pid"
#define HCI_SEND_CMD
#define MAX_PARAM_LEN 6

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define CASE_RETURN_STR(const) case const: return #const;

#define UNUSED __attribute__((unused))

/************************************************************************************
**  Local type definitions
************************************************************************************/

/************************************************************************************
**  Static variables
************************************************************************************/

static unsigned char main_done = 0;
static bt_status_t status;

/* Main API */
static bluetooth_device_t* bt_device;

const bt_interface_t* sBtInterface = NULL;
static bt3d_interface_t * bt3dinf = NULL;

static gid_t groups[] = { AID_NET_BT, AID_INET, AID_NET_BT_ADMIN,
                          AID_SYSTEM, AID_MISC, AID_SDCARD_RW,
                          AID_NET_ADMIN, AID_VPN};

/* Set to 1 when the Bluedroid stack is enabled */
static unsigned char bt_enabled = 0;

/************************************************************************************
**  Static functions
************************************************************************************/

static void process_cmd(char *p, unsigned char is_job);
static void job_handler(void *param);
static void bdt_log(const char *fmt_str, ...);


/************************************************************************************
**  Externs
************************************************************************************/
int hw_reset = 0;

/************************************************************************************
**  Functions
************************************************************************************/


/************************************************************************************
**  Shutdown helper functions
************************************************************************************/

static void bdt_shutdown(void)
{
    bdt_log("shutdown bdroid test app\n");
    main_done = 1;
}


/*****************************************************************************
** Android's init.rc does not yet support applying linux capabilities
*****************************************************************************/

static void config_permissions(void)
{
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct cap;

    bdt_log("set_aid_and_cap : pid %d, uid %d gid %d", getpid(), getuid(), getgid());

    header.pid = 0;

    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

    setuid(AID_BLUETOOTH);
    setgid(AID_BLUETOOTH);

    header.version = _LINUX_CAPABILITY_VERSION;

    cap.effective = cap.permitted =  cap.inheritable =
                    1 << CAP_NET_RAW |
                    1 << CAP_NET_ADMIN |
                    1 << CAP_NET_BIND_SERVICE |
                    1 << CAP_SYS_RAWIO |
                    1 << CAP_SYS_NICE |
                    1 << CAP_SETGID;

    capset(&header, &cap);
    setgroups(sizeof(groups)/sizeof(groups[0]), groups);
}



/*****************************************************************************
**   Logger API
*****************************************************************************/

void bdt_log(const char *fmt_str, ...)
{
    static char buffer[1024];
    va_list ap;

    va_start(ap, fmt_str);
    vsnprintf(buffer, 1024, fmt_str, ap);
    va_end(ap);

    fprintf(stdout, "%s\n", buffer);
}

/*******************************************************************************
 ** Misc helper functions
 *******************************************************************************/
static const char* dump_bt_status(bt_status_t status)
{
    switch(status)
    {
        CASE_RETURN_STR(BT_STATUS_SUCCESS)
        CASE_RETURN_STR(BT_STATUS_FAIL)
        CASE_RETURN_STR(BT_STATUS_NOT_READY)
        CASE_RETURN_STR(BT_STATUS_NOMEM)
        CASE_RETURN_STR(BT_STATUS_BUSY)
        CASE_RETURN_STR(BT_STATUS_UNSUPPORTED)

        default:
            return "unknown status code";
    }
}

static void hex_dump(char *msg, void *data, int size, int trunc)
{
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};

    bdt_log("%s  \n", msg);

    /* truncate */
    if(trunc && (size>32))
        size = 32;

    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               (unsigned int)((uintptr_t)p-(uintptr_t)data) );
        }

        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) {
            /* line completed */
            bdt_log("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        bdt_log("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

/*******************************************************************************
 ** Console helper functions
 *******************************************************************************/

void skip_blanks(char **p)
{
  while (**p == ' ')
    (*p)++;
}

uint32_t get_int(char **p, int DefaultValue)
{
  uint32_t Value = 0;
  unsigned char   UseDefault;

  UseDefault = 1;
  skip_blanks(p);

  while ( ((**p)<= '9' && (**p)>= '0') )
    {
      Value = Value * 10 + (**p) - '0';
      UseDefault = 0;
      (*p)++;
    }

  if (UseDefault)
    return DefaultValue;
  else
    return Value;
}

int get_signed_int(char **p, int DefaultValue)
{
  int    Value = 0;
  unsigned char   UseDefault;
  unsigned char  NegativeNum = 0;

  UseDefault = 1;
  skip_blanks(p);

  if ( (**p) == '-')
    {
      NegativeNum = 1;
      (*p)++;
    }
  while ( ((**p)<= '9' && (**p)>= '0') )
    {
      Value = Value * 10 + (**p) - '0';
      UseDefault = 0;
      (*p)++;
    }

  if (UseDefault)
    return DefaultValue;
  else
    return ((NegativeNum == 0)? Value : -Value);
}

void get_str(char **p, char *Buffer)
{
  skip_blanks(p);

  while (**p != 0 && **p != ' ')
    {
      *Buffer = **p;
      (*p)++;
      Buffer++;
    }

  *Buffer = 0;
}

uint32_t get_hex(char **p, int DefaultValue)
{
  uint32_t Value = 0;
  unsigned char   UseDefault;

  UseDefault = 1;
  skip_blanks(p);

  while ( ((**p)<= '9' && (**p)>= '0') ||
          ((**p)<= 'f' && (**p)>= 'a') ||
          ((**p)<= 'F' && (**p)>= 'A') )
    {
      if (**p >= 'a')
        Value = Value * 16 + (**p) - 'a' + 10;
      else if (**p >= 'A')
        Value = Value * 16 + (**p) - 'A' + 10;
      else
        Value = Value * 16 + (**p) - '0';
      UseDefault = 0;
      (*p)++;
    }

  if (UseDefault)
    return DefaultValue;
  else
    return Value;
}

void get_bdaddr(const char *str, bt_bdaddr_t *bd) {
    char *d = ((char *)bd), *endp;
    int i;
    for(i = 0; i < 6; i++) {
        *d++ = strtol(str, &endp, 16);
        if (*endp != ':' && i != 5) {
            memset(bd, 0, sizeof(bt_bdaddr_t));
            return;
        }
        str = endp + 1;
    }
}

char char2num(char *p)
{
	uint8_t k1,k2,i;
	i = *p;
	if(i >= 'a' && i <= 'f')
		return i - 'a' + 10;
	else if( i >= 'A' && i <= 'F')
		return i - 'A' + 10;
	else if(i >= '0' && i <= '9')
		return i - '0';
	else
		return -1;

}

int GetBdAddr(char *p, bt_bdaddr_t *pbd_addr)
{
    char Arr[13] = {0};
    char *pszAddr = NULL;
    uint8_t k1 = 0;
    uint8_t k2 = 0;
    char i;
    char *t = NULL;

    skip_blanks(&p);

    printf("Input=%s\n", p);

    if(12 > strlen(p))
    {
        printf("\nInvalid Bd Address. Format[112233445566]\n");
        return 0;
    }

    for(i=0; i<6; i++)
    {
		k1 = char2num(p);
		p++;
		k2 = char2num(p);
		p++;
		if(k1 != -1 && k2 != -1 )
		{
			pbd_addr->address[i] = (k1<<4 | k2);
		}
		else
			return 0;
    }
    return 1;
}

void do_pairing(char *p)
{
    bt_bdaddr_t bd_addr = {{0}};
    if(GetBdAddr(p, &bd_addr) == 0) return;
}

#define is_cmd(str) ((strlen(str) == strlen(cmd)) && strncmp((const char *)&cmd, str, strlen(str)) == 0)
#define if_cmd(str)  if (is_cmd(str))

typedef void (t_console_cmd_handler) (char *p);

typedef struct {
    const char *name;
    t_console_cmd_handler *handler;
    const char *help;
    unsigned char is_job;
} t_cmd;


const t_cmd console_cmd_list[];
static int console_cmd_maxlen = 0;

static void cmdjob_handler(void *param)
{
    char *job_cmd = (char*)param;

    bdt_log("cmdjob starting (%s)", job_cmd);

    process_cmd(job_cmd, 1);

    bdt_log("cmdjob terminating");

    free(job_cmd);
}

static int create_cmdjob(char *cmd)
{
    pthread_t thread_id;
    char *job_cmd;

    job_cmd = malloc(strlen(cmd)+1); /* freed in job handler */
    strcpy(job_cmd, cmd);

    if (pthread_create(&thread_id, NULL,
                       (void*)cmdjob_handler, (void*)job_cmd)!=0)
      perror("pthread_create");

    return 0;
}

/*******************************************************************************
 ** Load stack lib
 *******************************************************************************/

int HAL_load(void)
{
    int err = 0;

    hw_module_t* module;
    hw_device_t* device;

    bdt_log("Loading HAL lib + extensions");

    err = hw_get_module(BT_HARDWARE_MODULE_ID, (hw_module_t const**)&module);
    if (err == 0)
    {
        err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
        if (err == 0) {
            bt_device = (bluetooth_device_t *)device;
            sBtInterface = bt_device->get_bluetooth_interface();
        }
    }

    bdt_log("HAL library loaded (%s)", strerror(err));

    return err;
}

int HAL_unload(void)
{
    int err = 0;

    bdt_log("Unloading HAL lib");

    sBtInterface = NULL;

    bdt_log("HAL library unloaded (%s)", strerror(err));

    return err;
}

/*******************************************************************************
 ** HAL test functions & callbacks
 *******************************************************************************/

void setup_test_env(void)
{
    int i = 0;

    while (console_cmd_list[i].name != NULL)
    {
        console_cmd_maxlen = MAX(console_cmd_maxlen, (int)strlen(console_cmd_list[i].name));
        i++;
    }
}

void check_return_status(bt_status_t status)
{
    if (status != BT_STATUS_SUCCESS)
    {
        bdt_log("HAL REQUEST FAILED status : %d (%s)", status, dump_bt_status(status));
    }
    else
    {
        bdt_log("HAL REQUEST SUCCESS");
    }
}

static void adapter_state_changed(bt_state_t state)
{
    bdt_log("ADAPTER STATE UPDATED : %s", (state == BT_STATE_OFF)?"OFF":"ON");
    if (state == BT_STATE_ON) {
        bt_enabled = 1;
    } else {
        bt_enabled = 0;
    }
}

static void dut_mode_recv(uint16_t UNUSED opcode, uint8_t UNUSED *buf, uint8_t UNUSED len)
{
    bdt_log("DUT MODE RECV : NOT IMPLEMENTED");
}

static void le_test_mode(bt_status_t status, uint16_t packet_count)
{
    bdt_log("LE TEST MODE END status:%s number_of_packets:%d", dump_bt_status(status), packet_count);
}
#ifdef HCI_SEND_CMD
static void hci_event_recv(uint8_t opcode, uint8_t *buf, uint8_t len)
{
    int i = 0;
    bdt_log("%s: RECVD. EVENT MODE : 0x%x", __func__, opcode);
    if(len){
        bdt_log("%s: RECVD. EVENT MODE : parameter=", __func__);
	for(i = 0;i<len;i++)
	    bdt_log("%02x", buf[i]);
    }
}
#endif

void headless_mode_changed_cb(bt_status_t status)
{
    bdt_log("headless_mode_changed_cb, status : %d", status);
}

void add_av_headless_wakeup_cb(bt_status_t status)
{
    bdt_log("add_av_headless_wakeup_cb, status : %d", status);
}

void lpm_read_last_memory_data_cb(lpm_last_memory_data data)
{
    bdt_log("lpm_last_memory_data:");
    bdt_log("white list addr:%x:%x:%x:%x:%x:%x",data.wlist_addr[0],data.wlist_addr[1],
			data.wlist_addr[2],data.wlist_addr[3],data.wlist_addr[4],data.wlist_addr[5]);

}

#ifdef X86_TEST_INTERFACE
void read_firmware_version_cb(uint8_t *p)
{
    int i;
    btif_fw_version_t *version = (btif_fw_version_t *)p;
    bdt_log("read_firmware_version_cb: 0x%x", version->patch_version);

}
#endif

void hw_failure_cb(bt_hw_fail_t error)
{
    bdt_log("hw_failure_cb: Recvd. HW INIT FAILURE INDICATION : %d!!!", error);
    bdt_log("hw_failure_cb: Unloading the Bluedroid Lib...");
    HAL_unload();
    bdt_log("hw_failure_cb: Loading the Bluedroid Lib...");
    HAL_load();
    bt_enabled = 0;
    hw_reset = 1;
}
static bt_callbacks_t bt_callbacks = {
    sizeof(bt_callbacks_t),
    adapter_state_changed,
    NULL, /* adapter_properties_cb */
    NULL, /* remote_device_properties_cb */
    NULL, /* device_found_cb */
    NULL, /* discovery_state_changed_cb */
    NULL, /* pin_request_cb  */
    NULL, /* ssp_request_cb  */
    NULL, /* bond_state_changed_cb */
    NULL, /* acl_state_changed_cb */
    NULL, /* thread_evt_cb */
    dut_mode_recv, /* dut_mode_recv_cb */
#if BLE_INCLUDED == TRUE
    le_test_mode, /* le_test_mode_cb */
#else
    NULL, /* le_test_mode_cb */
#endif
	#ifdef HCI_SEND_CMD
	hci_event_recv, /* hci_event_recv_cb */
	#endif
    NULL, /* energy_info_cb */
    headless_mode_changed_cb, /*headless_mode_changed_cb */
    add_av_headless_wakeup_cb, /*add_av_headless_wakeup_cb */
    hw_failure_cb, /* hw_failure_cb */
    NULL,/* add_le_headless_mode_wakeup_device_cb */
    NULL, /*delete_le_headless_mode_wakeup_device_cb*/
    NULL, /*add_le_headless_mode_wakeup_records_cb*/
    NULL, /*le_headless_mode_set_scan_param_cb*/
    NULL, /*set_le_ext_pkt_len_config_cb*/
    NULL, /*set_le_2m_config_cb*/
    NULL, /*get_le_ext_pkt_len_config_cb*/
    NULL,/*get_le_2m_config_cb*/
    NULL, /*le_hardware_setup_cb*/
    lpm_read_last_memory_data_cb, /*lpm_read_last_memory_data_cb */
    //fw_upgrade_callback fw_upgrade_cb;
};

void assos_notif_callback (bt_bdaddr_t *bd_addr)
{
	unsigned char *bd = bd_addr->address;
    bdt_log("3D Glass associate : %x:%x:%x:%x:%x:%x",bd[0],bd[1],bd[2],bd[3],bd[4],bd[5]);

}

void batt_level_callback(bt_bdaddr_t *bd_addr, int8_t battery_level)
{
	unsigned char *bd = bd_addr->address;
    bdt_log("3D Glass battery level: %d",battery_level);


}


static bt3d_callbacks_t bt3d_callbacks = {
	sizeof(bt3d_callbacks_t),
	assos_notif_callback,
	batt_level_callback,
	NULL,
	NULL,
};

static bool set_wake_alarm(uint64_t delay_millis, bool should_wake, alarm_cb cb, void *data) {
  static timer_t timer;
  static bool timer_created;

  if (!timer_created) {
    struct sigevent sigevent;
    memset(&sigevent, 0, sizeof(sigevent));
    sigevent.sigev_notify = SIGEV_THREAD;
    sigevent.sigev_notify_function = (void (*)(union sigval))cb;
    sigevent.sigev_value.sival_ptr = data;
    timer_create(CLOCK_MONOTONIC, &sigevent, &timer);
    timer_created = true;
  }

  struct itimerspec new_value;
  new_value.it_value.tv_sec = delay_millis / 1000;
  new_value.it_value.tv_nsec = (delay_millis % 1000) * 1000 * 1000;
  new_value.it_interval.tv_sec = 0;
  new_value.it_interval.tv_nsec = 0;
  timer_settime(timer, 0, &new_value, NULL);

  return true;
}

static int acquire_wake_lock(const char *lock_name) {
  return BT_STATUS_SUCCESS;
}

static int release_wake_lock(const char *lock_name) {
  return BT_STATUS_SUCCESS;
}

static bt_os_callouts_t callouts = {
    sizeof(bt_os_callouts_t),
    set_wake_alarm,
    acquire_wake_lock,
    release_wake_lock,
};

void bdt_init(void)
{
    bdt_log("INIT BT ");
    status = sBtInterface->init(&bt_callbacks);

    if (status == BT_STATUS_SUCCESS) {
        status = sBtInterface->set_os_callouts(&callouts);
    }

    check_return_status(status);
}

//#ifdef X86_TEST_INTERFACE

void bdt_hw_chip_firmware_update(char *p)
{
    bdt_log(" UPDATING BT FIRMWARE...");

    status = sBtInterface->hw_chip_firmware_update();
    check_return_status(status);
}
//#endif

void bdt_read_version(char *p)
{
    btif_fw_version_t version;
    status = sBtInterface->read_version(&version);

    check_return_status(status);
}

void bdt_enable(void)
{
    bdt_log("ENABLE BT");
    if (bt_enabled) {
        bdt_log("Bluetooth is already enabled");
        return;
    }
    status = sBtInterface->enable();

    check_return_status(status);
}

void bdt_disable(void)
{
    bdt_log("DISABLE BT");
    if (!bt_enabled) {
        bdt_log("Bluetooth is already disabled");
        return;
    }
    status = sBtInterface->disable();

    check_return_status(status);
}
void bdt_dut_mode_configure(char *p)
{
    int32_t mode = -1;

    bdt_log("BT DUT MODE CONFIGURE");
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for test_mode to work.");
        return;
    }
    mode = get_signed_int(&p, mode);
    if ((mode != 0) && (mode != 1)) {
        bdt_log("Please specify mode: 1 to enter, 0 to exit");
        return;
    }
    status = sBtInterface->dut_mode_configure(mode);

    check_return_status(status);
}

#define HCI_LE_RECEIVER_TEST_OPCODE 0x201D
#define HCI_LE_TRANSMITTER_TEST_OPCODE 0x201E
#define HCI_LE_END_TEST_OPCODE 0x201F

void bdt_le_test_mode(char *p)
{
    int cmd;
    unsigned char buf[3];
    int arg1, arg2, arg3;

    bdt_log("BT LE TEST MODE");
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for le_test to work.");
        return;
    }

    memset(buf, 0, sizeof(buf));
    cmd = get_int(&p, 0);
    switch (cmd)
    {
        case 0x1: /* RX TEST */
           arg1 = get_int(&p, -1);
           if (arg1 < 0) bdt_log("%s Invalid arguments", __FUNCTION__);
           buf[0] = arg1;
           status = sBtInterface->le_test_mode(HCI_LE_RECEIVER_TEST_OPCODE, buf, 1);
           break;
        case 0x2: /* TX TEST */
            arg1 = get_int(&p, -1);
            arg2 = get_int(&p, -1);
            arg3 = get_int(&p, -1);
            if ((arg1 < 0) || (arg2 < 0) || (arg3 < 0))
                bdt_log("%s Invalid arguments", __FUNCTION__);
            buf[0] = arg1;
            buf[1] = arg2;
            buf[2] = arg3;
            status = sBtInterface->le_test_mode(HCI_LE_TRANSMITTER_TEST_OPCODE, buf, 3);
           break;
        case 0x3: /* END TEST */
            status = sBtInterface->le_test_mode(HCI_LE_END_TEST_OPCODE, buf, 0);
           break;
        default:
            bdt_log("Unsupported command");
            return;
            break;
    }
    if (status != BT_STATUS_SUCCESS)
    {
        bdt_log("%s Test 0x%x Failed with status:0x%x", __FUNCTION__, cmd, status);
    }
    return;
}

void bdt_cleanup(void)
{
    bdt_log("CLEANUP");
    sBtInterface->cleanup();
}

void bdt_set_headless_le_adv_data(char *p)
{
    bt_le_headless_adv_data param = {
        .adv_interval_min = 0x0800,
        .adv_interval_max = 0x0800,
        .adv_type = 0x00,
        .own_addr_type = 0x00,
        .peer_addr_type = 0x00,
        .peer_addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .adv_channel_map = 0b00000111,
        .adv_filter_policy = 0x00,
        .adv_data_length = 0,
        .adv_data = ""};

    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for set headless le advertising data.");
        return;
    }
    else {
        bdt_log("set headless le advertising data");
        status = sBtInterface->set_headless_le_adv_data(param);
    }
    check_return_status(status);
    return;
}

void bdt_set_headless_scan_configure(char *p)
{
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for set headless scan configure.");
        return;
    }
    else {
        bdt_log("set headless scan configure");
        status = sBtInterface->set_headless_scan_configure(0x0800, 0x0800, 0x01);
    }
    check_return_status(status);
    return;
}

void bdt_erase_patch_nvm(void)
{
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for erase patch nvm.");
        return;
    }
    else {
        bdt_log("erase patch nvm");
        sBtInterface->bt_erase_patch_nvm();
    }
    return;
}

void bdt_read_flash_burning_status(void)
{
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for read flash burning status.");
        return;
    }
    else {
        bdt_log("read flash burning status");
        sBtInterface->bt_read_flash_burning_status();
    }
    return;
}

#ifdef HCI_SEND_CMD
void bdt_hci_send_cmd(char *p)
{
	uint16_t opcode;
	uint8_t param_len = 0;

	bdt_log("SEND BT RAW HCI CMD");

	/* Extract the command opcode */
	opcode =(uint16_t) get_hex(&p, 0);
	if (!opcode) {
		bdt_log("Invalid opcode!!!");
		return;
	}

	/* Extract the command params if any */
	param_len = (uint8_t) get_int(&p, 0);
	if (param_len)
		bdt_log("%s: No. of Cmd-params: %d", __func__, param_len);
	else
		goto send_cmd;

	/* Extract the command params if any */
	if (param_len > MAX_PARAM_LEN) {
		bdt_log("%s: Max. supported parameter length is %d", __func__, MAX_PARAM_LEN);
		return;
	}

	/* Allocate memory for the command params */
	if (param_len)
	{
		uint8_t cmd_param[param_len];
		int i;

		for (i = 0; i < param_len; i++) {
			cmd_param[i] = (uint8_t) get_hex(&p, 0);
			bdt_log("%s: cmd_params[%d]: 0x%x", __func__, i, cmd_param[i]);
	   }

		bdt_log("%s: Sending CMD: 0x%x of param_len: %d", __func__, opcode, param_len);
		status = sBtInterface->hci_cmd_send(opcode, cmd_param, param_len);
	} else {
send_cmd:
		bdt_log("%s: Sending CMD: 0x%x ", __func__, opcode);
		status = sBtInterface->hci_cmd_send(opcode, NULL, param_len);
	}
}
#endif

#ifdef HOGP_TEST_INTERFACE
void bdt_mode_switch(char *p)
{
    int32_t mode = -1;

    bdt_log("HOGP MODE SWITCH");
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for HOGP to work.");
        return;
    }
    mode = get_signed_int(&p, mode);
    if ((mode != 0) && (mode != 1)) {
        bdt_log("Please specify mode: 1 to enter HOGP mode, 0 to normal mode");
        return;
    }
    status = sBtInterface->mode_switch(mode);

    check_return_status(status);
}

void bdt_get_mode(char *p)
{

    bdt_log("HOGP GET MODE");
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for HOGP to work.");
        return;
    }
    status = sBtInterface->get_mode();

    check_return_status(status);
}

#endif

#if 1 //2015.07.13 shyi
void bdt_add_headless_mode_wakeup_device(char *p)
{
    bt_bdaddr_t bd_addr = {{0}};
    if(GetBdAddr(p, &bd_addr) == 0)
        return;

   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for add headless mode wakeup device to work.");
        return;
    }
    else {
        bdt_log("add headless mode wakeup device");
        status = sBtInterface->add_headless_mode_wakeup_device(&bd_addr);
    }
    check_return_status(status);
    return;
}

void bdt_add_av_dev_to_headless_mode(char *p)
{
    bt_bdaddr_t bd_addr = {{0}};
    if(GetBdAddr(p, &bd_addr) == 0)
        return;

   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for add headless mode wakeup device to work.");
        return;
    }
    else {
        bdt_log("add headless mode wakeup device");
        status = sBtInterface->add_av_dev_to_headless_mode(&bd_addr);
    }
    check_return_status(status);
    return;
}

void bdt_delete_headless_mode_wakeup_device(char *p)
{
    bt_bdaddr_t bd_addr = {{0}};
    if(GetBdAddr(p, &bd_addr) == 0)
        return;

   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for delete headless mode wakeup device to work.");
        return;
    }
    else {
        bdt_log("delete headless mode wakeup device");
        status = sBtInterface->delete_headless_mode_wakeup_device(&bd_addr);
    }
    check_return_status(status);
    return;
}

void bdt_get_headless_device_list(void)
{
   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for get headless device list.");
        return;
    }
    else {
        bdt_log("get headless device list");
        status = sBtInterface->get_headless_device_list();
    }
    check_return_status(status);
    return;
}

void bdt_enter_headless_mode(char *p)
{
	uint8_t device_type = 0;
    skip_blanks(&p);
	device_type = char2num(p);
   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for enter headless mode to work.");
        return;
    }
    else {
        bdt_log("enter headless mode,device type is 0x%x",device_type);
        status = sBtInterface->enter_headless_mode(device_type);
    }
    check_return_status(status);
    return;
}
void bdt_wake_up_test(void)
{
   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for wake up test.");
        return;
    }
    else {
        bdt_log("wake up test");
        sBtInterface->bt_wake_up_test();
    }
    return;
}

int bdt_set_local_did(char* p)
{
    bt_local_di_record_t local_di_record;
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for setting local did");
        return -1;
    }
    else{
        bdt_log("set_local_did");
        local_di_record.vendor = 0x0012;
        local_di_record.vendor_id_source = 0x0034;
        local_di_record.product = 0x0056;
        local_di_record.version = 0x0078;
        return sBtInterface->set_local_did(&local_di_record);
    }
}

void bdt_read_last_memory(void)
{
   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for read last memory.");
        return;
    }
    else {
        bdt_log("read last memory");
        sBtInterface->read_last_memory();
    }
    return;
}

typedef struct {
	bt_bdaddr_t bd_addr;
	unsigned char addr_type;
}link_key_info;

void bdt_hogp_read_link_key(char *p)
{
    link_key_info info;
	uint8_t k1,k2;
    if(GetBdAddr(p, &info.bd_addr) == 0)
        return;
    skip_blanks(&p);
    k1 = char2num(p + sizeof(bt_bdaddr_t)*2);
    k2 = char2num(p + sizeof(bt_bdaddr_t)*2 + 1);
	if(k1 == -1 || k2 == -1)
		return ;
	info.addr_type = (k1 << 4)|k2;
    bdt_log("addr_type = %d",info.addr_type);

   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for hogp read link key.");
        return;
    }
    else {
        bdt_log("hogp read link key");
        status = sBtInterface->hogp_read_link_key(&info);
    }
    check_return_status(status);
    return;
}

#endif

void bdt_enable_3dd_mode(char *p)
{
	bt3dinf = sBtInterface->get_profile_interface(BT_PROFILE_3D_SYNC_ID);
	if(bt3dinf)
	{
        bdt_log("INIT 3DD Profile ");
		status = bt3dinf->init(&bt3d_callbacks);
        check_return_status(status);
	}

}

void bdt_set_3dd_mode(char *p)
{
#if 0
    bt_bdaddr_t bd_addr = {{0}};
    if(GetBdAddr(p, &bd_addr) == 0)
        return;
#endif
   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for set 3dd mode");
        return;
    }
    else {
        bdt_log("set 3dd master mode");
        status = bt3dinf->set_mode(BT_3D_MODE_MASTER,NULL);
    }
    check_return_status(status);
    return;
}

void bdt_set_3dd_broadcast_data(char *p)
{
	bt3d_data_t data ;

   if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for set 3dd broadcast data");
        return;
    }
    else {
        bdt_log("set 3dd broadcast data");
		data.left_open_offset = 0xa;
		data.left_close_offset = 0xd;
		data.right_open_offset = 0x1a;
		data.right_close_offset = 0x1d;
		data.delay = 0xe;
		data.dual_view = 0;
        status = bt3dinf->broadcast_3d_data(data);
    }
    check_return_status(status);
    return;
}


/*******************************************************************************
 ** Console commands
 *******************************************************************************/

void do_help(char UNUSED *p)
{
    int i = 0;
    int max = 0;
    char line[128];
    int pos = 0;

    while (console_cmd_list[i].name != NULL)
    {
        pos = sprintf(line, "%s", (char*)console_cmd_list[i].name);
        bdt_log("%s %s\n", (char*)line, (char*)console_cmd_list[i].help);
        i++;
    }
}

void do_quit(char UNUSED *p)
{
    bdt_shutdown();
}

/*******************************************************************
 *
 *  BT TEST  CONSOLE COMMANDS
 *
 *  Parses argument lists and passes to API test function
 *
*/

void do_init(char UNUSED *p)
{
    bdt_init();
}

void do_enable(char UNUSED *p)
{
    bdt_enable();
}

void do_read_version(char *p)
{
    bdt_read_version(p);
}

void do_hw_chip_firmware_update(char *p)
{
    bdt_hw_chip_firmware_update(p);
}

void do_disable(char UNUSED *p)
{
    bdt_disable();
}
void do_dut_mode_configure(char *p)
{
    bdt_dut_mode_configure(p);
}

void do_le_test_mode(char *p)
{
    bdt_le_test_mode(p);
}

void do_cleanup(char UNUSED *p)
{
    bdt_cleanup();
}

void do_set_headless_le_adv_data(char *p)
{
	bdt_set_headless_le_adv_data(p);
}

void do_set_headless_scan_configure(char *p)
{
	bdt_set_headless_scan_configure(p);
}

void do_erase_patch_nvm(char *p)
{
	bdt_erase_patch_nvm();
}

void do_read_flash_burning_status(char *p)
{
	bdt_read_flash_burning_status();
}

#ifdef HCI_SEND_CMD
void do_hci_send_cmd(char *p)
{
    bdt_hci_send_cmd(p);
}
#endif

#ifdef HOGP_TEST_INTERFACE
void do_mode_switch(char *p)
{
    bdt_mode_switch(p);
}

void do_get_mode(char *p)
{
    bdt_get_mode(p);
}

#endif

#if 1 //2015.07.13 shyi
void do_add_headless_mode_wakeup_device(char *p)
{
	bdt_add_headless_mode_wakeup_device(p);
}

void do_add_av_dev_to_headless_mode(char *p)
{
	bdt_add_av_dev_to_headless_mode(p);
}

void do_delete_headless_mode_wakeup_device(char *p)
{
	bdt_delete_headless_mode_wakeup_device(p);
}

void do_get_headless_device_list(char *p)
{
	bdt_get_headless_device_list();
}

void do_enter_headless_mode(char *p)
{
	bdt_enter_headless_mode(p);
}

void do_wake_up_test(char *p)
{
	bdt_wake_up_test();
}

void do_read_last_memory(char *p)
{
	bdt_read_last_memory();
}

void do_hogp_read_link_key(char *p)
{
	bdt_hogp_read_link_key(p);
}

void do_set_local_did(char *p)
{
	bdt_set_local_did(p);
}

void do_enable_3dd_mode(char *p)
{
	bdt_enable_3dd_mode(p);
}

void do_set_3dd_mode(char *p)
{
	bdt_set_3dd_mode(p);
}

void do_set_3dd_broadcast_data(char *p)
{
	bdt_set_3dd_broadcast_data(p);
}

#endif
/*******************************************************************
 *
 *  CONSOLE COMMAND TABLE
 *
*/

const t_cmd console_cmd_list[] =
{
    /*
     * INTERNAL
     */

    { "help", do_help, "lists all available console commands", 0 },
    { "quit", do_quit, "", 0},

    /*
     * API CONSOLE COMMANDS
     */

     /* Init and Cleanup shall be called automatically */
    { "enable", do_enable, ":: enables bluetooth", 0 },
    { "disable", do_disable, ":: disables bluetooth", 0 },
    { "dut_mode_configure", do_dut_mode_configure, ":: DUT mode - 1 to enter,0 to exit", 0 },
    { "le_test_mode", do_le_test_mode, ":: LE Test Mode - RxTest - 1 <rx_freq>, \n\t \
                      TxTest - 2 <tx_freq> <test_data_len> <payload_pattern>, \n\t \
                      End Test - 3 <no_args>", 0 },
    /* add here */
	#ifdef HCI_SEND_CMD
	{ "hci_send_cmd", do_hci_send_cmd, "::Sends HCI RAW CMD", 0 },
	#endif
#ifdef HOGP_TEST_INTERFACE
	{ "mode_switch", do_mode_switch, ": : HOGP Mode Switch - 1 to HOGP mode, -0 to normal mode", 0 },
	{ "get_mode", do_get_mode, ": : HOGP GET Mode - 1 to HOGP mode, -0 to normal mode", 0 },
#endif

    { "add_headless_device", do_add_headless_mode_wakeup_device, ":: add headless mode wakeup device, need bd_addr", 0 },
    { "add_av_dev_to_headless_mode", do_add_av_dev_to_headless_mode, ":: add av dev to headless mode, need bd_addr", 0 },
    { "delete_headless_device", do_delete_headless_mode_wakeup_device, ":: delete headless mode wakeup device, need bd_addr", 0 },
    { "enter_headless_mode", do_enter_headless_mode, ":: enter headless	mode,need device type,1 <-> hogp;2 <-> bredr;3 <-> hogp & bredr", 0 },
    { "get_headless_device_list", do_get_headless_device_list, ":: get headless device list", 0 },
    { "wake_up_test", do_wake_up_test, ":: wake up test", 0 },
    { "set_local_did", do_set_local_did, ":: set Local VID/PID", 0 },
    { "read_last_memory", do_read_last_memory, ":: read last memory", 0 },
    { "hogp_read_link_key", do_hogp_read_link_key, ":: read hogp link key, need bd_addr and address type", 0 },


    { "read_version", do_read_version, ": : Read the BT Firmware Version", 0 },
//#ifdef X86_TEST_INTERFACE
    { "update_bt_fw", do_hw_chip_firmware_update, ": : Update new BT Firmware", 0},
//#endif

    { "set_headless_le_adv_data", do_set_headless_le_adv_data, ":: set headless le advertising data", 0 },
    { "set_headless_scan_configure", do_set_headless_scan_configure, ":: set headless scan configure", 0 },
    { "erase_patch_nvm", do_erase_patch_nvm, ":: erase patch nvm", 0 },
    { "read_flash_burning_status", do_read_flash_burning_status, ":: read flash burning status", 0 },

	{ "enable_3dd_mode", do_enable_3dd_mode, ":: enable 3dd profile", 0 },
	{ "set_3dd_mode", do_set_3dd_mode, ":: set 3dd master mode ", 0 },
	{ "set_3dd_data", do_set_3dd_broadcast_data, ":: set 3dd broadcast data", 0 },

    /* last entry */
    {NULL, NULL, "", 0},
};

/*
 * Main console command handler
*/

static void process_cmd(char *p, unsigned char is_job)
{
    char cmd[64];
    int i = 0;
    char *p_saved = p;

    get_str(&p, cmd);

    /* table commands */
    while (console_cmd_list[i].name != NULL)
    {
        if (is_cmd(console_cmd_list[i].name))
        {
            if (!is_job && console_cmd_list[i].is_job)
                create_cmdjob(p_saved);
            else
            {
                console_cmd_list[i].handler(p);
            }
            return;
        }
        i++;
    }
    bdt_log("%s : unknown command\n", p_saved);
    if (hw_reset)
        bdt_init();
    do_help(NULL);
}

int main (int UNUSED argc, char UNUSED *argv[])
{
    int opt;
    char cmd[128];
    int args_processed = 0;
    int pid = -1;

    config_permissions();
    bdt_log("\n:::::::::::::::::::::::::::::::::::::::::::::::::::");
    bdt_log(":: Bluedroid test app starting");

    if ( HAL_load() < 0 ) {
        perror("HAL failed to initialize, exit\n");
        unlink(PID_FILE);
        exit(0);
    }

    setup_test_env();

    /* Automatically perform the init */
    bdt_init();

    while(!main_done)
    {
        char line[128];

        /* command prompt */
        printf( ">" );
        fflush(stdout);

        fgets (line, 128, stdin);

        if (line[0]!= '\0')
        {
            /* remove linefeed */
            line[strlen(line)-1] = 0;

            process_cmd(line, 0);
            memset(line, '\0', 128);
        }
    }

    /* FIXME: Commenting this out as for some reason, the application does not exit otherwise*/
    //bdt_cleanup();

    HAL_unload();

    bdt_log(":: Bluedroid test app terminating");

    return 0;
}
