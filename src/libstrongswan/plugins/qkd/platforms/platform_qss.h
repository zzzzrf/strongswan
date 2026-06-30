/*
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

 #ifndef PLATFORM_QSS_H_
 #define PLATFORM_QSS_H_
 
 #include <qkd/qkd_factory.h>
 
 #define PLATFORM_QSS_SECTION "qss"
 
 qkd_service_t *qss_qkd_create(settings_t *settings, char *section);
 
 #endif /** PLATFORM_QSS_H_ **/
 