#include "PmodCAN.h"
#include "xil_cache.h"
#include "xparameters.h"

void CAN_Initialize();
void CAN_Initialize_Adaptive_Spoofing(u32 identifier, u8 ide);
void CANCleanup();
void EnableCaches();
void DisableCaches();
