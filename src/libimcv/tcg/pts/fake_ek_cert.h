/*
 * Copyright (C) 2011 Sansar Choinyambuu
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup tcg_pts tcg_pts
 * @{ @ingroup tcg_pts
 */

#ifndef PTS_FAKE_EK_CERT_H_
#define PTS_FAKE_EK_CERT_H_

/* Create a fake EK cert for talking to PCA */
/* Not a valid signature, just a holder for the Endorsement Key */

char fakeEKCert[0x41a] = {
/* 00000000 */ 0x30, 0x82, 0x04, 0x16, 0x30, 0x82, 0x02, 0xfe,
		0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x40, /* |0...0..........@| */
/* 00000010 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, /* |...............0| */
/* 00000020 */ 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x3e, /* |...*.H........0>| */
/* 00000030 */ 0x31, 0x3c, 0x30, 0x3a, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x13, 0x33, 0x49, 0x6e, 0x73, 0x65, 0x63, /* |1<0:..U...3Insec| */
/* 00000040 */ 0x75, 0x72, 0x65, 0x20, 0x44, 0x65, 0x6d, 0x6f,
		0x2f, 0x54, 0x65, 0x73, 0x74, 0x20, 0x45, 0x6e, /* |ure Demo/Test En| */
/* 00000050 */ 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e,
		0x74, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x52, 0x6f, /* |dorsement Key Ro| */
/* 00000060 */ 0x6f, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
		0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x30, 0x1e, /* |ot Certificate0.| */
/* 00000070 */ 0x17, 0x0d, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, /* |..010101000000Z.| */
/* 00000080 */ 0x0d, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32,
		0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x00, /* |.491231235959Z0.| */
/* 00000090 */ 0x30, 0x82, 0x01, 0x37, 0x30, 0x22, 0x06, 0x09,
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, /* |0..70"..*.H.....| */
/* 000000a0 */ 0x07, 0x30, 0x15, 0xa2, 0x13, 0x30, 0x11, 0x06,
		0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, /* |.0...0...*.H....| */
/* 000000b0 */ 0x01, 0x09, 0x04, 0x04, 0x54, 0x43, 0x50, 0x41,
		0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, /* |....TCPA.....0..| */
/* 000000c0 */ 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x80, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000000d0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000000e0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000000f0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000100 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000110 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000120 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000130 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000140 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000150 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000160 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000170 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000180 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000190 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000001a0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000001b0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000001c0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
		0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x37, 0x30, /* |..............70| */
/* 000001d0 */ 0x82, 0x01, 0x33, 0x30, 0x37, 0x06, 0x03, 0x55,
		0x1d, 0x09, 0x04, 0x30, 0x30, 0x2e, 0x30, 0x16, /* |..307..U...00.0.| */
/* 000001e0 */ 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x10, 0x31,
		0x0d, 0x30, 0x0b, 0x0c, 0x03, 0x31, 0x2e, 0x31, /* |..g....1.0...1.1| */
/* 000001f0 */ 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x14,
		0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x12, 0x31, /* |......0...g....1| */
/* 00000200 */ 0x0b, 0x30, 0x09, 0x80, 0x01, 0x00, 0x81, 0x01,
		0x00, 0x82, 0x01, 0x02, 0x30, 0x50, 0x06, 0x03, /* |.0..........0P..| */
/* 00000210 */ 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x46,
		0x30, 0x44, 0xa4, 0x42, 0x30, 0x40, 0x31, 0x16, /* |U......F0D.B0@1.| */
/* 00000220 */ 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02,
		0x01, 0x0c, 0x0b, 0x69, 0x64, 0x3a, 0x30, 0x30, /* |0...g......id:00| */
/* 00000230 */ 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x12,
		0x30, 0x10, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, /* |0000001.0...g...| */
/* 00000240 */ 0x02, 0x0c, 0x07, 0x55, 0x6e, 0x6b, 0x6e, 0x6f,
		0x77, 0x6e, 0x31, 0x12, 0x30, 0x10, 0x06, 0x05, /* |...Unknown1.0...| */
/* 00000250 */ 0x67, 0x81, 0x05, 0x02, 0x03, 0x0c, 0x07, 0x69,
		0x64, 0x3a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0c, /* |g......id:00000.| */
/* 00000260 */ 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
		0x04, 0x02, 0x30, 0x00, 0x30, 0x75, 0x06, 0x03, /* |..U.......0.0u..| */
/* 00000270 */ 0x55, 0x1d, 0x20, 0x01, 0x01, 0xff, 0x04, 0x6b,
		0x30, 0x69, 0x30, 0x67, 0x06, 0x04, 0x55, 0x1d, /* |U. ....k0i0g..U.| */
/* 00000280 */ 0x20, 0x00, 0x30, 0x5f, 0x30, 0x25, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, /* | .0_0%..+.......| */
/* 00000290 */ 0x16, 0x19, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
		0x2f, 0x77, 0x77, 0x77, 0x2e, 0x70, 0x72, 0x69, /* |..http://www.pri| */
/* 000002a0 */ 0x76, 0x61, 0x63, 0x79, 0x63, 0x61, 0x2e, 0x63,
		0x6f, 0x6d, 0x2f, 0x30, 0x36, 0x06, 0x08, 0x2b, /* |vacyca.com/06..+| */
/* 000002b0 */ 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30,
		0x2a, 0x0c, 0x28, 0x54, 0x43, 0x50, 0x41, 0x20, /* |.......0*.(TCPA | */
/* 000002c0 */ 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20,
		0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, /* |Trusted Platform| */
/* 000002d0 */ 0x20, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x20,
		0x45, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, /* | Module Endorsem| */
/* 000002e0 */ 0x65, 0x6e, 0x74, 0x30, 0x21, 0x06, 0x03, 0x55,
		0x1d, 0x23, 0x04, 0x1a, 0x30, 0x18, 0x80, 0x16, /* |ent0!..U.#..0...| */
/* 000002f0 */ 0x04, 0x14, 0x34, 0xa8, 0x8c, 0x24, 0x7a, 0x97,
		0xf8, 0xcc, 0xc7, 0x56, 0x6d, 0xfb, 0x44, 0xa8, /* |..4..$z....Vm.D.| */
/* 00000300 */ 0xd4, 0x41, 0xaa, 0x5f, 0x4f, 0x1d, 0x30, 0x0d,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, /* |.A._O.0...*.H...| */
/* 00000310 */ 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01,
		0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000320 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000330 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000340 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000350 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000360 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000370 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000380 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000390 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003a0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003b0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003c0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003d0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003e0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003f0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000400 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000410 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01                                      /* |..........|       */
};

#endif /** PTS_FAKE_EK_CERT_H_ @}*/
