 #ifndef __TABLES__H
 #define __TABLES__H

 uint8_t mds[4][4]=
 {
    {0x01, 0xef, 0x5b, 0x5b},
    {0x5b, 0xef, 0xef, 0x01},
    {0xef, 0x5b, 0x01, 0xef},
    {0xef, 0x01, 0xef, 0x5b}
 };

 
uint8_t q[2][256] =
{
    /* q0 */
    {
        
		0xa9,0x67,0xb3,0xe8,0x4,0xfd,0xa3,0x76,0x9a,0x92,0x80,0x78,0xe4,0xdd,0xd1,0x38,
		0xd,0xc6,0x35,0x98,0x18,0xf7,0xec,0x6c,0x43,0x75,0x37,0x26,0xfa,0x13,0x94,0x48,
		0xf2,0xd0,0x8b,0x30,0x84,0x54,0xdf,0x23,0x19,0x5b,0x3d,0x59,0xf3,0xae,0xa2,0x82,
		0x63,0x1,0x83,0x2e,0xd9,0x51,0x9b,0x7c,0xa6,0xeb,0xa5,0xbe,0x16,0xc,0xe3,0x61,
		0xc0,0x8c,0x3a,0xf5,0x73,0x2c,0x25,0xb,0xbb,0x4e,0x89,0x6b,0x53,0x6a,0xb4,0xf1,
		0xe1,0xe6,0xbd,0x45,0xe2,0xf4,0xb6,0x66,0xcc,0x95,0x3,0x56,0xd4,0x1c,0x1e,0xd7,
		0xfb,0xc3,0x8e,0xb5,0xe9,0xcf,0xbf,0xba,0xea,0x77,0x39,0xaf,0x33,0xc9,0x62,0x71,
		0x81,0x79,0x9,0xad,0x24,0xcd,0xf9,0xd8,0xe5,0xc5,0xb9,0x4d,0x44,0x8,0x86,0xe7,
		0xa1,0x1d,0xaa,0xed,0x6,0x70,0xb2,0xd2,0x41,0x7b,0xa0,0x11,0x31,0xc2,0x27,0x90,
		0x20,0xf6,0x60,0xff,0x96,0x5c,0xb1,0xab,0x9e,0x9c,0x52,0x1b,0x5f,0x93,0xa,0xef,
		0x91,0x85,0x49,0xee,0x2d,0x4f,0x8f,0x3b,0x47,0x87,0x6d,0x46,0xd6,0x3e,0x69,0x64,
		0x2a,0xce,0xcb,0x2f,0xfc,0x97,0x5,0x7a,0xac,0x7f,0xd5,0x1a,0x4b,0xe,0xa7,0x5a,
		0x28,0x14,0x3f,0x29,0x88,0x3c,0x4c,0x2,0xb8,0xda,0xb0,0x17,0x55,0x1f,0x8a,0x7d,
		0x57,0xc7,0x8d,0x74,0xb7,0xc4,0x9f,0x72,0x7e,0x15,0x22,0x12,0x58,0x7,0x99,0x34,
		0x6e,0x50,0xde,0x68,0x65,0xbc,0xdb,0xf8,0xc8,0xa8,0x2b,0x40,0xdc,0xfe,0x32,0xa4,
		0xca,0x10,0x21,0xf0,0xd3,0x5d,0xf,0x0,0x6f,0x9d,0x36,0x42,0x4a,0x5e,0xc1,0xe0
	},
    /* q1 */
    {

		0x75,0xf3,0xc6,0xf4,0xdb,0x7b,0xfb,0xc8,0x4a,0xd3,0xe6,0x6b,0x45,0x7d,0xe8,0x4b,
		0xd6,0x32,0xd8,0xfd,0x37,0x71,0xf1,0xe1,0x30,0xf,0xf8,0x1b,0x87,0xfa,0x6,0x3f,
		0x5e,0xba,0xae,0x5b,0x8a,0x0,0xbc,0x9d,0x6d,0xc1,0xb1,0xe,0x80,0x5d,0xd2,0xd5,
		0xa0,0x84,0x7,0x14,0xb5,0x90,0x2c,0xa3,0xb2,0x73,0x4c,0x54,0x92,0x74,0x36,0x51,
		0x38,0xb0,0xbd,0x5a,0xfc,0x60,0x62,0x96,0x6c,0x42,0xf7,0x10,0x7c,0x28,0x27,0x8c,
		0x13,0x95,0x9c,0xc7,0x24,0x46,0x3b,0x70,0xca,0xe3,0x85,0xcb,0x11,0xd0,0x93,0xb8,
		0xa6,0x83,0x20,0xff,0x9f,0x77,0xc3,0xcc,0x3,0x6f,0x8,0xbf,0x40,0xe7,0x2b,0xe2,
		0x79,0xc,0xaa,0x82,0x41,0x3a,0xea,0xb9,0xe4,0x9a,0xa4,0x97,0x7e,0xda,0x7a,0x17,
		0x66,0x94,0xa1,0x1d,0x3d,0xf0,0xde,0xb3,0xb,0x72,0xa7,0x1c,0xef,0xd1,0x53,0x3e,
		0x8f,0x33,0x26,0x5f,0xec,0x76,0x2a,0x49,0x81,0x88,0xee,0x21,0xc4,0x1a,0xeb,0xd9,
		0xc5,0x39,0x99,0xcd,0xad,0x31,0x8b,0x1,0x18,0x23,0xdd,0x1f,0x4e,0x2d,0xf9,0x48,
		0x4f,0xf2,0x65,0x8e,0x78,0x5c,0x58,0x19,0x8d,0xe5,0x98,0x57,0x67,0x7f,0x5,0x64,
		0xaf,0x63,0xb6,0xfe,0xf5,0xb7,0x3c,0xa5,0xce,0xe9,0x68,0x44,0xe0,0x4d,0x43,0x69,
		0x29,0x2e,0xac,0x15,0x59,0xa8,0xa,0x9e,0x6e,0x47,0xdf,0x34,0x35,0x6a,0xcf,0xdc,
		0x22,0xc9,0xc0,0x9b,0x89,0xd4,0xed,0xab,0x12,0xa2,0xd,0x52,0xbb,0x2,0x2f,0xa9,
		0xd7,0x61,0x1e,0xb4,0x50,0x4,0xf6,0xc2,0x16,0x25,0x86,0x56,0x55,0x9,0xbe,0x91
	}
};

#endif
