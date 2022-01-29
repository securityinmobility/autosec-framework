/*
 * Copyright (C) 2009 - 2019 Xilinx, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>

#include "lwip/err.h"
#include "lwip/tcp.h"
#if defined (__arm__) || defined (__aarch64__)
#include "xil_printf.h"
#endif

/*****************************************************************************/
/*  User Defines										  					 */
/*****************************************************************************/
#include "attack.h"

int transfer_data() {
	return 0;
}

void print_app_header()
{
#if (LWIP_IPV6==0)
	xil_printf("\n\r\n\r-----lwIP TCP echo server ------\n\r");
#else
	xil_printf("\n\r\n\r-----lwIPv6 TCP echo server ------\n\r");
#endif
	xil_printf("TCP packets sent to port 6001 will be echoed back\n\r");
}

err_t recv_callback(void *arg, struct tcp_pcb *tpcb,
                               struct pbuf *p, err_t err)
{
	/* do not read the packet if we are not in ESTABLISHED state */
	if (!p) {
		tcp_close(tpcb);
		tcp_recv(tpcb, NULL);
		return ERR_OK;
	}

	/* indicate that the packet has been received */
	tcp_recved(tpcb, p->len);

	connection = tpcb;
	/* echo back the payload */
	/* in this case, we assume that the payload is < TCP_SND_BUF */
	if (tcp_sndbuf(tpcb) > p->len) {
		xil_printf("Requested Attack: %s \n\r", p->payload);
		xil_printf("Integer des Requests %d \n\r", atoi(p->payload));

		/*Checking out Payload data*/
		u8* frame = (u8*)(p->payload);

		// If Users wantws to stop the Busflood there is no need to inspect the other data
		u8 command = frame[0];
		if(command == Busflood_Stop) {
			busfloodActive = 0;
			xil_printf("Stopping Busflood");
			pbuf_free(p);
			return ERR_OK;
		}

		//Checking out User data
		ide = frame[1];
		id = (frame[2] << 24) + (frame[3] << 16) + (frame[4] << 8) + frame[5];
		dlc = frame[6];
		u32 bitrate = (frame[6+dlc+1] << 16) + (frame[6+dlc+2] << 8) + frame[6+dlc+3];
		xil_printf("Command: %d \n\r", command);
		xil_printf("IDE: %d \n\r", ide);
		xil_printf("Identifier: %x \n\r", id);
		xil_printf("DLC: %d \n\r", dlc);
		xil_printf("Bitrate selected: %d Hz\n\r", bitrate);

		for(int i = 0; i < dlc; i++) {
			message_data[i] = frame[7+i];
			xil_printf("Message Data %d: %d \n\r", i, message_data[i]);
		}

		if(checkBitrate(bitrate) != 0) {
			command = Bitrate_Not_Supported;
		}

		//Differntiate between different Commands and Sending Answer to the Framework
		switch(command)	{
			case(Busflood_Attack):
				attack = Busflood_Attack;
				xil_printf("Busflood Bit gesetzt.\n\r");
				char busflood_answer[] = "Busflood started";
				err = tcp_write(tpcb, busflood_answer, sizeof(busflood_answer), 1);
				attack = Busflood_Attack;
				break;
			case(Simple_Frame_Spoofing):
				attack = Simple_Frame_Spoofing;
				xil_printf("Simple Frame Spoofing Bit gesetzt.\n\r");
				char simple_spoofing_answer[] = "Simple Frame Spoofing started";
				err = tcp_write(tpcb, simple_spoofing_answer, sizeof(simple_spoofing_answer), 1);
				break;
			case(Adaptive_Spoofing):
				attack = Adaptive_Spoofing;
				xil_printf("Adaptive Spoofing Bit gesetzt.\n\r");
				char adaptive_spoofing_answer[] = "Adaptive Spoofing started";
				err = tcp_write(tpcb, adaptive_spoofing_answer, sizeof(adaptive_spoofing_answer), 1);
				break;
			case(Bitrate_Not_Supported):
				attack = No_Attack;
				xil_printf("Bitrate wird nicht unterstuetzt.\n\r");
				char bitrate_answer[] = "Bitrate not supported";
				err = tcp_write(tpcb, bitrate_answer, sizeof(bitrate_answer), 1);
				break;
			default:
				attack = No_Attack;
				char no_attack_answer[] = "Attack not implemented";
				err = tcp_write(tpcb, no_attack_answer, sizeof(no_attack_answer), 1);
				break;
		}
	} else
		xil_printf("no space in tcp_sndbuf\n\r");

	/* free the received pbuf */
	pbuf_free(p);

	return ERR_OK;
}

/*Callback beim akzeptieren einer Verbindung*/
err_t accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	static int connection = 1;

	/* set the receive callback for this connection */
	tcp_recv(newpcb, recv_callback);

	/* just use an integer number indicating the connection id as the
	   callback argument */
	tcp_arg(newpcb, (void*)(UINTPTR)connection);

	/* increment for subsequent accepted connections */
	connection++;

	return ERR_OK;
}


int start_application()
{
	struct tcp_pcb *pcb;
	err_t err;
	unsigned port = 7;

	/* create new TCP PCB structure */
	pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
	if (!pcb) {
		xil_printf("Error creating PCB. Out of Memory\n\r");
		return -1;
	}

	/* bind to specified @port */
	err = tcp_bind(pcb, IP_ANY_TYPE, port);
	if (err != ERR_OK) {
		xil_printf("Unable to bind to port %d: err = %d\n\r", port, err);
		return -2;
	}

	/* we do not need any arguments to callback functions */
	tcp_arg(pcb, NULL);

	/* listen for connections */
	pcb = tcp_listen(pcb);
	if (!pcb) {
		xil_printf("Out of memory while tcp_listen\n\r");
		return -3;
	}

	/* specify callback to use for incoming connections */
	tcp_accept(pcb, accept_callback);

	xil_printf("TCP echo server started @ port %d\n\r", port);

	return 0;
}
