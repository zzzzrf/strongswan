/*
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#ifndef VENDOR_A_H_
#define VENDOR_A_H_

#include <qkd/qkd_factory.h>

#define VENDOR_A_SECTION "vendor_a"

qkd_service_t *vendor_a_qkd_create(settings_t *settings, char *section);

#endif /** VENDOR_A_H_ **/
