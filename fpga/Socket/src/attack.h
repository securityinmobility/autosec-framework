#include "xgpiops.h"
#include "xparameters.h"
#include "xstatus.h"

#define NUM_INSTANCES_BITRATE 3

typedef struct  {
	u32 bitrate;
	u8 CNF3;
	u8 CNF2;
	u8 CNF1;
} bitrate_t;

typedef enum {
	Attack_OK = 0,
	Attack_ERROR = 1,
}Attack_StatusTypeDef;

typedef enum {
	Normal_Identifier = 0,
	Extended_Identifier = 1,
}Attack_IdentifierTypeDef;

extern volatile int attack;

typedef enum {
	No_Attack = 0,
	Busflood_Attack = 1,
	Simple_Frame_Spoofing = 2,
	Adaptive_Spoofing = 3,
	Error_Passive_Spoofing_Attack = 4,
	Double_Receive_Attack = 5,
	Bus_Off_Attack = 6,
	Freeze_Doom_Loop_Attack = 7,
	Busflood_Stop = 254,
	Bitrate_Not_Supported = 255,
}Attack_NumberTypeDef;


/*****************************************************************************/
/*  Variable declaration													 */
/*****************************************************************************/

struct tcp_pcb *connection;
extern u8 CNF[3];
extern u8 ide;
extern u32 id;
extern u8 dlc;
extern u8 message_data[8];
extern u8 busfloodActive;
bitrate_t Bitrate_Lookup[NUM_INSTANCES_BITRATE];

/*****************************************************************************/
/*  Function declaration													 */
/*****************************************************************************/

Attack_StatusTypeDef startBusFlood();
Attack_StatusTypeDef startSimpleFrameSpoofing(u32 identifier, u8* data, u8 length, u8 ide);
Attack_StatusTypeDef startAdaptiveSpoofing(u32 identifier, u8* data, u8 length, u8 ide);
u8 checkBitrate();
