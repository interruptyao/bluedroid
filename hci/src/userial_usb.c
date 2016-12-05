/******************************************************************************
 *
 *  Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *  Not a Contribution.
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

/******************************************************************************
 *
 *  Filename:      userial.c
 *
 *  Description:   Contains open/read/write/close functions on serial port
 *
 ******************************************************************************/

#define LOG_TAG "bt_usb"

#include <utils/Log.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include "bt_hci_bdroid.h"
#include "userial.h"
#include "utils.h"
#include "bt_vendor_lib.h"
#include <sys/prctl.h>
#include "bt_utils.h"
#include <linux/ioctl.h>
#include "vendor.h"

#define BTUSB_IOCTL_MAGIC                             'b'

   /* Wait for an asynchronous USB Device Event (ACL/SCO/Event Data)    */
   /* received.                                                         */
#define BTUSB_IOCTL_WAIT_DATA                         _IOR(BTUSB_IOCTL_MAGIC,  0, void *)

   /* Send/Receive HCI Packets to/from USB Bluetooth Device.            */
#define BTUSB_IOCTL_SEND_PACKET                       _IOW(BTUSB_IOCTL_MAGIC,  1, void *)

#define BTUSB_IOCTL_READ_PACKET                       _IOWR(BTUSB_IOCTL_MAGIC, 2, void *)


/******************************************************************************
**  Constants & Macros
******************************************************************************/

#ifndef USERIAL_DBG
#define USERIAL_DBG FALSE
#endif

#if (USERIAL_DBG == TRUE)
#define USERIALDBG(param, ...) {ALOGD(param, ## __VA_ARGS__);}
#else
#define USERIALDBG(param, ...) {}
#endif

#ifndef ENABLE_USERIAL_TIMING_LOGS
#define ENABLE_USERIAL_TIMING_LOGS FALSE
#endif

#define MAX_SERIAL_PORT (USERIAL_PORT_3 + 1)
#define READ_LIMIT (BTHC_USERIAL_READ_MEM_SIZE - BT_HC_HDR_SIZE)

enum {
    USERIAL_RX_EXIT,
    USERIAL_RX_FLOW_OFF,
    USERIAL_RX_FLOW_ON
};

#define PACKET_TYPE_ACL    2
#define PACKET_TYPE_SCO    3
#define PACKET_TYPE_EVENT  4

#define ERESTARTSYS        512

/******************************************************************************
**  Local type definitions
******************************************************************************/

typedef struct
{
    int             fd;
    uint8_t         port;
    pthread_t       read_thread;
    BUFFER_Q        rx_q;
    HC_BT_HDR      *p_rx_hdr;
} tUSERIAL_CB;

/******************************************************************************
**  Static variables
******************************************************************************/

static tUSERIAL_CB userial_cb;
static volatile uint8_t userial_running = 0;
static volatile int cleanup_inprogress = 0;
extern int fw_upgrade_in_prog;


/******************************************************************************
**  USB initialization functions
******************************************************************************/
uint8_t userial_usb_init(void);
uint8_t userial_usb_open(uint8_t port);
uint8_t userial_open_helper(uint8_t port);
uint16_t  userial_usb_read(uint16_t msg_id, uint8_t *p_buffer, uint16_t len);
uint16_t userial_usb_write(uint16_t msg_id, uint8_t *p_data, uint16_t len);
void userial_usb_close(void);

/******************************************************************************
**  Static functions
******************************************************************************/

#if defined(ENABLE_USERIAL_TIMING_LOGS) && (ENABLE_USERIAL_TIMING_LOGS==TRUE)

static void log_userial_tx_timing(int len)
{
    #define USEC_PER_SEC 1000000L
    static struct timespec prev = {0, 0};
    struct timespec now, diff;
    unsigned int diff_us = 0;
    unsigned int now_us = 0;

    clock_gettime(CLOCK_MONOTONIC, &now);
    now_us = now.tv_sec*USEC_PER_SEC + now.tv_nsec/1000;
    diff_us = (now.tv_sec - prev.tv_sec) * USEC_PER_SEC + (now.tv_nsec - prev.tv_nsec)/1000;

    ALOGW("[userial] ts %08d diff : %08d len %d", now_us, diff_us,
                len);

    prev = now;
}

#endif


/*****************************************************************************
**   Socket signal functions to wake up userial_read_thread for termination
**
**   creating an unnamed pair of connected sockets
**      - signal_fds[0]: join fd_set in select call of userial_read_thread
**      - signal_fds[1]: trigger from userial_close
*****************************************************************************/
static int signal_fds[2]={0,1};
static inline int send_wakeup_signal(char sig_cmd)
{
    return send(signal_fds[1], &sig_cmd, sizeof(sig_cmd), 0);
}
static inline char reset_signal()
{
    char sig_recv = -1;
    recv(signal_fds[0], &sig_recv, sizeof(sig_recv), MSG_WAITALL);
    return sig_recv;
}

#define IS_PKT_TYPE(A, B)       ((B) & (1 << (A)))
#define CLEAR_PKT_TYPE(A,B)     ( *A = ((*A) & ~((1) << (B))) )
#define CLEAR_ALL_PKT_TYPE(A)   ( *A = ((*A) & ~((1 << PACKET_TYPE_EVENT) | \
                                        (1 << PACKET_TYPE_SCO) | \
                                        (1 << PACKET_TYPE_ACL))) )

/* Used for for transferring data to/from the USB Driver */
typedef struct USBPacketInfo
{
   unsigned int   pktType;
   unsigned int   buffSize;
   unsigned char *buffer;
} USBPacketRequest;

/* Read the packet data from the driver */
static int readPacket(int fd, int pkt_type, uint8_t *pbuf)
{
    int ret = 0;
    USBPacketRequest readPacketrequest;

    /* Fill in the packet request structure */
    readPacketrequest.pktType  = pkt_type;
    readPacketrequest.buffSize = READ_LIMIT;
    readPacketrequest.buffer   = pbuf;

    /* Retrieve the PACKET from driver */
    ret = ioctl(fd, BTUSB_IOCTL_READ_PACKET, &readPacketrequest);
    if (ret <= 0)
        ALOGE("%s: Failed to read packet(type: %d) with return value: %d",
            __func__, pkt_type, ret);
    else
        ALOGE("%s: Successfully read %2d bytes of packet(type: %d)",
            __func__, ret+1, pkt_type);

    return ret;
}

static int read_usb_packet(int fd, int *pkt_type, uint8_t *pbuf)
{
    int ret = 0, i = 0;

    if (*pkt_type <= 0)
    {
        ALOGE("%s: Invalid Packet type: %d", __func__, *pkt_type);
        return ret;
    }
    else if (IS_PKT_TYPE(PACKET_TYPE_EVENT, *pkt_type))
    {
        ALOGV("%s: HCI-EVENT PACKET AVAILABLE", __func__);
        /* Save the HCI PACKET TYPE that is to be fetched */
        ret = readPacket(fd, PACKET_TYPE_EVENT, pbuf);
        if (ret > 0) {
            /* Clear the EVENT packet type in the bit mask */
            CLEAR_PKT_TYPE(pkt_type, PACKET_TYPE_EVENT);
            if (pbuf[1] == 0x1) {
                ALOGE("%s: RECVD IINQUIRY COMPLETE EVENT", __func__);
                ALOGE("[ ==> 0x%2x\t0x%2x\t0x%2x\t0x%2x ]", pbuf[0], pbuf[1], pbuf[2], pbuf[3]);
            }
            else if (pbuf[1] == 0xe)
                ALOGE("%s: RECVD COMMAND COMPLETE EVENT FOR OPCODE: 0x%x",
                     __func__, ((pbuf[5] << 8) | pbuf[4]));
            else if (pbuf[1] == 0x2F) {
                ALOGE("%s: RECVD EXTENDED INQUIRY RESULT EVENT", __func__);
                ALOGE("[ ==> 0x%2x\t0x%2x\t0x%2x\t0x%2x ]", pbuf[0], pbuf[1], pbuf[2], pbuf[3]);
            }
            else if (pbuf[1] == 0x0) {
                ALOGE("%s: IGNORE UNKNOWN EVENT PACKET <0x%2x>", __func__, pbuf[1]);
                return 0;
            }
        }

        /* Check if any pending packet to be read */
        if (*pkt_type)
            ALOGI("%s: bitMask post read: %d", __func__, *pkt_type);
        else
            ALOGV("%s: Read all available data in driver's queue", __func__);
    }
    else if (IS_PKT_TYPE(PACKET_TYPE_SCO, *pkt_type))
    {
        ALOGV("%s: BT-SCO PACKET AVAILABLE", __func__);
        /* Save the HCI PACKET TYPE that is to be fetched */
        ret = readPacket(fd, PACKET_TYPE_SCO, pbuf);
        if (ret > 0) {
            /* Clear the SCO packet type in the bit mask */
            CLEAR_PKT_TYPE(pkt_type, PACKET_TYPE_SCO);
            ALOGV("%s: Retrieved %d bytes of SCO data from driver", __func__, ret);
        }

        /* Check if any pending packet to be read */
        if (*pkt_type)
            ALOGI("%s: bitMask post read: %d", __func__, *pkt_type);
        else
            ALOGV("%s: Read all available data in driver's queue", __func__);
    }
    else if (IS_PKT_TYPE(PACKET_TYPE_ACL, *pkt_type))
    {
        ALOGV("%s: BT-ACL PACKET AVAILABLE", __func__);
        /* Save the HCI PACKET TYPE that is to be fetched */
        ret = readPacket(fd, PACKET_TYPE_ACL, pbuf);
        if (ret > 0) {
            CLEAR_PKT_TYPE(pkt_type, PACKET_TYPE_ACL);
            ALOGV("%s: Retrieved %d bytes of ACL data from driver", __func__, ret);
        }

        /* Check if any pending packet to be read */
        if (*pkt_type)
            ALOGI("%s: bitMask post read: %d", __func__, *pkt_type);
        else
            ALOGV("%s: Read all available data in driver's queue", __func__);
    }
    else
        ALOGE("%s: Unkown Packet type: %d", __func__, *pkt_type);

    if (ret < 0) {
        CLEAR_ALL_PKT_TYPE(pkt_type);
    }

    return ret;
}

static int allow_device_recover(int timeout)
{
    int fd_array[CH_MAX];
    int i, status = 0;

    for (i = 1; i <= 10; i++) {
        ALOGE("%s: Device not yet up: Sleeping for another %dms...", __func__, timeout);
        utils_delay(timeout);
        if (cleanup_inprogress) {
            ALOGE("%s: Cleanup-inprogress: No need for any recovery!!", __func__);
            break;
        }
        ALOGE("%s: %d: Checking if device has come up", __func__, i);
        status = userial_open_helper(USERIAL_PORT_1);
        if (status) {
            ALOGE("%s: Device has comeup after %dms!!!", __func__, (i*timeout));
            break;
        }
    }
    return status;
}
static void simulate_command_complete_event(char *p)
{
    p[0] = 0x04; //HCI-EVENT TYPE
    p[1] = 0x0e; //HCI-CMD-COMPLETE EVENT CODE
    p[2] = 0x05; //EVENT LENGTH
    p[3] = 0x01; //CMD-CREDITS
    p[4] = 0x36; //VSC-CMD-OPCODE
    p[5] = 0xfc; //VSC-CMD-OPCODE
    p[6] = 0x00; //STATUS
    p[7] = 0x0C; //SUB-CODE
}
static void hci_disconnect_event(char *p)
{
    p[0] = 0x04; //HCI-EVENT TYPE
    p[1] = 0x10; //HARDWARE ERROR EVENT CODE
    p[2] = 0x01; //EVENT LENGTH
    p[3] = 0xFF; //HARDWARE ERROR CODE
}

/*******************************************************************************
**
** Function        select_read
**
** Description     check if fd is ready for reading and listen for termination
**                  signal. need to use select in order to avoid collision
**                  between read and close on the same fd
**
** Returns         -1: termination
**                 >=0: numbers of bytes read back from fd
**
*******************************************************************************/
static int select_read(int fd, uint8_t *pbuf, int len)
{
    static int pktBitMask = 0;
    int n = 0, ret = -1;

    while (userial_running)
    {
        /* Check if packet is already availabile */
        if (pktBitMask)
        {
            ret = read_usb_packet(fd, &pktBitMask, pbuf);
            goto exit;
        }
        else
        {
            /* Wait for packet from device */
            ALOGV("%s: Waiting for PACKET from device", __func__);
            n = ioctl(fd, BTUSB_IOCTL_WAIT_DATA, pbuf);
            if (n >= 0)
            {
                pktBitMask = *pbuf;
                ALOGV("%s: readBitMask: %d", __func__, pktBitMask);

                /* Read data from the driver */
                ret = read_usb_packet(fd, &pktBitMask, pbuf);
                goto exit;
            }
            else
            {
                /* -RESTARTSYS : sleep interrupted while waiting for data */
                ret = n;
                if (n == -ERESTARTSYS) {
                    ALOGE("%s: Interrupted while waiting for data: Continue waiting...", __func__);
                    continue;
                }
                else {
                    ALOGE("%s: ioctl() failed with ret. val: %d", __func__, n);
                    break;
                }

            }
        }
    }

exit:
    return ret;
}

static void handleSignal (int sig)
{
    if (sig == SIGUSR2) {
        ALOGE("%s: Recvd. SIGUSR2 and hence terminating", __func__);
        userial_running = 0;
        pthread_exit(0);
        ALOGE("%s: Recvd. SIGUSR2 and hence terminating end", __func__);
    }
    else
        ALOGE("%s: Recvd. signal: %d", __func__, sig);
}

/*******************************************************************************
**
** Function        userial_read_thread
**
** Description
**
** Returns         void *
**
*******************************************************************************/
static void *userial_read_thread(void *arg)
{
    int rx_length = 0;
    int sig = SIGUSR2;
    sigset_t sigSet;
    uint8_t *p;
    HC_BT_HDR *p_buf = NULL;
    struct sigaction act;

    USERIALDBG("Entering userial_read_thread()");
    prctl(PR_SET_NAME, (unsigned long)"userial_usb_read", 0, 0, 0);

    ALOGE("%s: Registering the signal handler", __func__);
	memset(&act,0x0,sizeof(struct sigaction));
    sigemptyset (&sigSet);
    sigaddset (&sigSet, sig);
    pthread_sigmask(SIG_UNBLOCK, &sigSet, NULL);
    act.sa_handler = handleSignal;
    sigaction (sig, &act, NULL );

    userial_running = 1;

    raise_priority_a2dp(TASK_HIGH_USERIAL_READ);

    while (userial_running)
    {
        if (bt_hc_cbacks)
        {
            /* Allocate one byte extra for HCI H4 Packet indicator */
            p_buf = (HC_BT_HDR *) bt_hc_cbacks->alloc( \
                                                BTHC_USERIAL_READ_MEM_SIZE + 1);
        }
        else
            p_buf = NULL;

        if (p_buf != NULL)
        {
            p_buf->offset = 0;
            p_buf->layer_specific = 0;

            /* Increment by HC_BT_HDR size(8 bytes) : Copy the received event after the header */
            p = (uint8_t *) (p_buf + 1);
            rx_length = select_read(userial_cb.fd, p, READ_LIMIT);
        }
        else
        {
            rx_length = 0;
            utils_delay(100);
            ALOGE("userial_read_thread() failed to gain buffers");
            continue;
        }

        if (rx_length > 0)
        {
            p_buf->len = (uint16_t)rx_length;
            utils_enqueue(&(userial_cb.rx_q), p_buf);

            //ALOGV("%s: Enqueued & Signalling Rx Data availability(%d bytes)", __func__, rx_length);
            bthc_rx_ready();
        }
        else if (rx_length == 0) {
            ALOGE("%s: Recvd. invalid packet from Controller: Deallocate memory and continue waiting for packet", __func__);
            if (bt_hc_cbacks)
                bt_hc_cbacks->dealloc(p_buf);
            continue;
        }
        else /* rx_length < 0 */
        {
            ALOGE("select_read return size <=0:%d, exiting userial_read_thread",\
                 rx_length);
            if(!cleanup_inprogress && fw_upgrade_in_prog  && allow_device_recover(1000)) {
				fw_upgrade_in_prog = FALSE;
				ALOGE("%s: Device recover successful.", __func__);
				ALOGE("%s: Simulating FAKE CMD-COMPLETE EVENT", __func__);
				simulate_command_complete_event(p);
				p_buf->event = 0x04; //HCIT_TYPE_EVENT;
				p_buf->len = 8;
				utils_enqueue(&(userial_cb.rx_q), p_buf);
                bthc_rx_ready();
			} else {
				if(bt_hc_cbacks)
					bt_hc_cbacks->dealloc(p_buf);
				break;
			}

        }
    } /* for */

    userial_running = 0;
    vendor_send_command(BT_VND_OP_USERIAL_CLOSE, NULL);
    ALOGE("%s: Leaving userial_read_thread()", __func__);
    pthread_exit(NULL);

    return NULL;    // Compiler friendly
}


/*****************************************************************************
**   Userial API Functions
*****************************************************************************/

/*******************************************************************************
**
** Function        userial_init
**
** Description     Initializes the userial driver
**
** Returns         TRUE/FALSE
**
*******************************************************************************/
uint8_t userial_usb_init(void)
{
    USERIALDBG("userial_usb_init");
    memset(&userial_cb, 0, sizeof(tUSERIAL_CB));
    userial_cb.fd = -1;
    utils_queue_init(&(userial_cb.rx_q));
    return TRUE;
}


/*******************************************************************************
**
** Function        userial_open
**
** Description     Open Bluetooth device with the port ID
**
** Returns         TRUE/FALSE
**
*******************************************************************************/
uint8_t userial_usb_open(uint8_t port)
{
    struct sched_param param;
    int policy, result;
    pthread_attr_t thread_attr;
    int fd_array[CH_MAX];

    ALOGE("userial_usb_open(port:%d)", port);

    if (userial_running)
    {
        /* Userial is open; close it first */
        userial_usb_close();
        utils_delay(50);
    }

    if (port >= MAX_SERIAL_PORT)
    {
        ALOGE("Port > MAX_SERIAL_PORT");
        return FALSE;
    }

    /* Calling vendor-specific part */
    {
        result = vendor_send_command(BT_VND_OP_USERIAL_OPEN, &fd_array);

        if (result != 1)
        {
            ALOGE("userial_usb_open: wrong numbers of open fd in vendor lib [%d]!",
                    result);
            ALOGE("userial_usb_open: HCI UART expects only one open fd");
            vendor_send_command(BT_VND_OP_USERIAL_CLOSE, NULL);
            return FALSE;
        }

        userial_cb.fd = fd_array[0];
    }

    if (userial_cb.fd == -1)
    {
        ALOGE("userial_usb_open: failed to open UART port");
        return FALSE;
    }

    USERIALDBG( "fd = %d", userial_cb.fd);
	cleanup_inprogress = 0;

    userial_cb.port = port;

    pthread_attr_init(&thread_attr);

    ALOGI("%s: Starting USERIAL-USB-READ thread...", __func__);
    if (pthread_create(&(userial_cb.read_thread), &thread_attr, \
                       userial_read_thread, NULL) != 0 )
    {
        ALOGE("pthread_create failed!");
        return FALSE;
    }

    if(pthread_getschedparam(userial_cb.read_thread, &policy, &param)==0)
    {
        result = pthread_setschedparam(userial_cb.read_thread, policy, &param);
        if (result != 0)
        {
            ALOGW("userial_usb_open: pthread_setschedparam failed (%s)", \
                  strerror(result));
        }
    }

    return TRUE;
}

uint8_t userial_open_helper(uint8_t port)
{
    int result;
    int fd_array[CH_MAX];

    ALOGE("userial_open_helper(port:%d)", port);

    if (port >= MAX_SERIAL_PORT)
    {
        ALOGE("Port > MAX_SERIAL_PORT");
        return FALSE;
    }

    result = vendor_send_command(BT_VND_OP_USERIAL_OPEN, &fd_array);
	if (result != 1)
	{
		ALOGE("userial_open: wrong numbers of open fd in vendor lib [%d]!",result);
		ALOGE("userial_open: HCI UART expects only one open fd");
		return FALSE;
	}

        ALOGE("userial_open: successfully to open UART port");
        userial_cb.fd = fd_array[0];
        ALOGE("1 userial_open: successfully to open UART port");

    if (userial_cb.fd == -1)
    {
        ALOGE("userial_open: failed to open UART port");
        return FALSE;
    }

    ALOGE("%s: New fd = %d", __func__, userial_cb.fd);

    userial_cb.port = port;
    return TRUE;
}

/*******************************************************************************
**
** Function        userial_read
**
** Description     Read data from the userial port
**
** Returns         Number of bytes actually read from the userial port and
**                 copied into p_data.  This may be less than len.
**
*******************************************************************************/
uint16_t  userial_usb_read(uint16_t msg_id, uint8_t *p_buffer, uint16_t len)
{
    uint16_t total_len = 0;
    uint16_t copy_len = 0;
    uint8_t *p_data = NULL;

    do
    {
        if(userial_cb.p_rx_hdr != NULL)
        {
            p_data = ((uint8_t *)(userial_cb.p_rx_hdr + 1)) + \
                     (userial_cb.p_rx_hdr->offset);

            if((userial_cb.p_rx_hdr->len) <= (len - total_len))
                copy_len = userial_cb.p_rx_hdr->len;
            else
                copy_len = (len - total_len);

            memcpy((p_buffer + total_len), p_data, copy_len);

            total_len += copy_len;

            userial_cb.p_rx_hdr->offset += copy_len;
            userial_cb.p_rx_hdr->len -= copy_len;

            if(userial_cb.p_rx_hdr->len == 0)
            {
                if (bt_hc_cbacks)
                    bt_hc_cbacks->dealloc(userial_cb.p_rx_hdr);

                userial_cb.p_rx_hdr = NULL;
            }
        }

        if(userial_cb.p_rx_hdr == NULL)
        {
            userial_cb.p_rx_hdr=(HC_BT_HDR *)utils_dequeue(&(userial_cb.rx_q));
        }
    } while ((userial_cb.p_rx_hdr != NULL) && (total_len < len));

    return total_len;
}

static int usb_write(int fd, uint8_t *p_data, uint16_t len)
{
    int ret = 0;
    USBPacketRequest sendPacketRequest;

    /* Fill in the 'write' packet request structure */
    sendPacketRequest.pktType  = *p_data;
    sendPacketRequest.buffSize = len;
    sendPacketRequest.buffer   = p_data+1;

    if (sendPacketRequest.pktType == 0x1)
        ALOGE("%s: Sending HCI-CMD: 0x%2x", __func__, ((p_data[2] << 8) | p_data[1]));

    ret = ioctl(fd, BTUSB_IOCTL_SEND_PACKET, &sendPacketRequest);
    return ret;
}

/*******************************************************************************
**
** Function        userial_write
**
** Description     Write data to the userial port
**
** Returns         Number of bytes actually written to the userial port. This
**                 may be less than len.
**
*******************************************************************************/
uint16_t userial_usb_write(uint16_t msg_id, uint8_t *p_data, uint16_t len)
{
    int ret, total = 0;

#if defined(ENABLE_USERIAL_TIMING_LOGS) && (ENABLE_USERIAL_TIMING_LOGS==TRUE)
        log_userial_tx_timing(len);
#endif
    ret = usb_write(userial_cb.fd, p_data+total, len);
    if (ret < 0) {
        ALOGE("%s: Write failed with return value: %d", __func__, ret);
        return ret;
    }
    total = len;

    return ((uint16_t)total);
}

/*******************************************************************************
**
** Function        userial_close
**
** Description     Close the userial port
**
** Returns         None
**
*******************************************************************************/
void userial_usb_close(void)
{
    int result;
    TRANSAC p_buf;
    cleanup_inprogress = 1;
    ALOGE("userial_usb_close(fd:%d)", userial_cb.fd);

    if (userial_running) {
        /* Signal userial_read_thread about port close */
        ALOGE("%s: Signalling the read thread about BT shutdown", __func__);
        pthread_kill(userial_cb.read_thread, SIGUSR2);
        if ((result=pthread_join(userial_cb.read_thread, NULL)) < 0)
            ALOGE( "pthread_join() FAILED result:%d", result);

    }


    /* Calling vendor-specific part */
    ALOGE("%s: Calling vendor specific part to close the handle to USB driver", __func__);
    vendor_send_command(BT_VND_OP_USERIAL_CLOSE, NULL);

    userial_cb.fd = -1;

    if (bt_hc_cbacks)
    {
        while ((p_buf = utils_dequeue (&(userial_cb.rx_q))) != NULL)
        {
            bt_hc_cbacks->dealloc(p_buf);
        }
    }
}

