/*
 * Copyright (C) 2025
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

#include "qkd_factory.h"

#include <library.h>
#include <collections/enumerator.h>
#include <collections/hashtable.h>
#include <collections/linked_list.h>
#include <threading/rwlock.h>
#include <utils/debug.h>

typedef struct private_qkd_factory_t private_qkd_factory_t;

typedef struct {
	char *key;
	char *vendor;
	char *version;
	qkd_service_constructor_t create;
} entry_t;

struct private_qkd_factory_t {

	qkd_factory_t public;

	hashtable_t *services;

	linked_list_t *entries;

	rwlock_t *lock;
};

static void entry_destroy(entry_t *entry)
{
	free(entry->key);
	free(entry->vendor);
	free(entry->version);
	free(entry);
}

static char* make_key(char *vendor, char *version)
{
	char *key = NULL;

	if (!vendor)
	{
		return NULL;
	}
	if (version && strlen(version))
	{
		if (asprintf(&key, "%s:%s", vendor, version) < 0)
		{
			return NULL;
		}
		return key;
	}
	return strdup(vendor);
}

static u_int entry_hash(char *key)
{
	return chunk_hash(chunk_create(key, strlen(key)));
}

static bool entry_equals(char *a, char *b)
{
	return streq(a, b);
}

METHOD(qkd_factory_t, create, qkd_service_t*,
	private_qkd_factory_t *this, char *vendor, char *version, char *section)
{
	qkd_service_constructor_t ctor = NULL;
	qkd_service_t *service;
	entry_t *entry;
	char *key;

	if (!vendor || !section)
	{
		return NULL;
	}
	key = make_key(vendor, version);
	if (!key)
	{
		return NULL;
	}
	this->lock->read_lock(this->lock);
	entry = this->services->get(this->services, key);
	ctor = entry ? entry->create : NULL;
	this->lock->unlock(this->lock);
	free(key);
	if (!ctor)
	{
		DBG1(DBG_LIB, "no QKD service registered for vendor '%s'%s%s",
			 vendor, version && strlen(version) ? " version '" : "",
			 version && strlen(version) ? version : "");
		return NULL;
	}
	service = ctor(lib->settings, section);
	if (!service)
	{
		DBG1(DBG_LIB, "failed to create QKD service for vendor '%s'", vendor);
	}
	return service;
}

METHOD(qkd_factory_t, add_service, void,
	private_qkd_factory_t *this, char *vendor, char *version,
	qkd_service_constructor_t create)
{
	entry_t *entry;
	char *key;

	if (!vendor || !create)
	{
		return;
	}
	key = make_key(vendor, version);
	if (!key)
	{
		return;
	}
	INIT(entry,
		.key = key,
		.vendor = strdup(vendor),
		.version = version && strlen(version) ? strdup(version) : NULL,
		.create = create,
	);
	this->lock->write_lock(this->lock);
	this->services->put(this->services, entry->key, entry);
	this->entries->insert_last(this->entries, entry);
	this->lock->unlock(this->lock);
}

METHOD(qkd_factory_t, remove_service, void,
	private_qkd_factory_t *this, qkd_service_constructor_t create)
{
	enumerator_t *enumerator;
	entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->entries->create_enumerator(this->entries);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->entries->remove_at(this->entries, enumerator);
			this->services->remove(this->services, entry->key);
			entry_destroy(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

CALLBACK(service_filter, bool,
	void *null, enumerator_t *orig, va_list args)
{
	entry_t *entry;
	char **vendor, **version;

	VA_ARGS_VGET(args, vendor, version);

	if (orig->enumerate(orig, &entry))
	{
		*vendor = entry->vendor;
		*version = entry->version;
		return TRUE;
	}
	return FALSE;
}

METHOD(qkd_factory_t, create_service_enumerator, enumerator_t*,
	private_qkd_factory_t *this)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_filter(
				this->entries->create_enumerator(this->entries),
				service_filter, this->lock, (void*)this->lock->unlock);
}

METHOD(qkd_factory_t, destroy, void,
	private_qkd_factory_t *this)
{
	this->entries->destroy_function(this->entries, (void*)entry_destroy);
	this->services->destroy(this->services);
	this->lock->destroy(this->lock);
	free(this);
}

qkd_factory_t *qkd_factory_create()
{
	private_qkd_factory_t *this;

	INIT(this,
		.public = {
			.create = _create,
			.add_service = _add_service,
			.remove_service = _remove_service,
			.create_service_enumerator = _create_service_enumerator,
			.destroy = _destroy,
		},
		.services = hashtable_create((hashtable_hash_t)entry_hash,
				(hashtable_equals_t)entry_equals, 4),
		.entries = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
