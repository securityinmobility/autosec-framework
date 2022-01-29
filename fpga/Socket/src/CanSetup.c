/******************************************************************************/
/*                                                                            */
/* LoopBack.c -- PmodCAN Example Projects                                     */
/*                                                                            */
/******************************************************************************/
/* Author: Arthur Brown                                                       */
/*                                                                            */
/******************************************************************************/
/* File Description:                                                          */
/*                                                                            */
/* This demo sends data through GPIO/SPI to the PmodCAN and receives it       */
/* through the PmodCAN. Sends through UART as well.                           */
/* Loop back function                                                         */
/*                                                                            */
/******************************************************************************/
/* Revision History:                                                          */
/*                                                                            */
/*    08/30/2017(ArtVVB):   Created                                           */
/*    09/01/2017(jPeyron):  Formatted Validated                               */
/*    09/06/2017(jPeyron):  Added RX and TX demos                             */
/*    02/24/2018(atangzwj): Validated for Vivado 2017.4                       */
/*                                                                            */
/******************************************************************************/
/* Baud Rates:                                                                */
/*                                                                            */
/*    Microblaze: 9600 or what was specified in UARTlite core                 */
/*    Zynq: 115200                                                            */
/*                                                                            */
/******************************************************************************/

#include "CanSetup.h"

#include "PmodCAN.h"
#include "sleep.h"
#include "xil_cache.h"
#include "xparameters.h"

void CANInitialize();
void CAN_Initialize_Adaptive_Spoofing(u32 identifier, u8 ide);
void CANCleanup();
void EnableCaches();
void DisableCaches();

PmodCAN myDevice;

void CAN_Initialize() {
   EnableCaches();
   CAN_begin(&myDevice, XPAR_PMODCAN_0_AXI_LITE_GPIO_BASEADDR,
         XPAR_PMODCAN_0_AXI_LITE_SPI_BASEADDR);
   CAN_Configure(&myDevice, CAN_ModeNormalOperation);
   xil_printf("Can in CAN_ModeNormalOperation:\r\n");
}

void CAN_Initialize_Adaptive_Spoofing(u32 identifier, u8 ide) {
   EnableCaches();
   CAN_begin(&myDevice, XPAR_PMODCAN_0_AXI_LITE_GPIO_BASEADDR,
         XPAR_PMODCAN_0_AXI_LITE_SPI_BASEADDR);
   CAN_Configure_Adaptive_Spoofing(&myDevice, CAN_ModeNormalOperation, identifier, ide);
   xil_printf("Can in CAN_ModeNormalOperation:\r\n");
}

void CANCleanup() {
   CAN_end(&myDevice);
   DisableCaches();
}

void EnableCaches() {
#ifdef __MICROBLAZE__
#ifdef XPAR_MICROBLAZE_USE_ICACHE
   Xil_ICacheEnable();
#endif
#ifdef XPAR_MICROBLAZE_USE_DCACHE
   Xil_DCacheEnable();
#endif
#endif
}

void DisableCaches() {
#ifdef __MICROBLAZE__
#ifdef XPAR_MICROBLAZE_USE_DCACHE
   Xil_DCacheDisable();
#endif
#ifdef XPAR_MICROBLAZE_USE_ICACHE
   Xil_ICacheDisable();
#endif
#endif
}
