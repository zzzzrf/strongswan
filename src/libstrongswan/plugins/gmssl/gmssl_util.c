#include "gmssl_util.h"
#include "crypto/hashers/hasher.h"

bool sm2_public_key_fingerprint(SM2_KEY *key, cred_encoding_type_t type, chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t enc = chunk_empty;
	uint8_t point[SM2_POINT_MAX_SIZE];
	uint8_t buffer[512];
	uint8_t *p;
	size_t len;

	if (lib->encoding->get_cache(lib->encoding, type, key, fp))
		return TRUE;

	switch (type)
	{
		case KEYID_PUBKEY_SM3:
			p = point;
			len = 0;
			if (sm2_point_to_der(&key->public_key, &p, &len) != 1)
				return FALSE;

			enc = chunk_alloc(len);
			memcpy(enc.ptr, point, len);
			break;
		case KEYID_PUBKEY_INFO_SM3:
			p = buffer;
			len = 0;
			if (sm2_public_key_info_to_der(key, &p, &len) != 1)
				return FALSE;

			enc = chunk_alloc(len);
			memcpy(enc.ptr, buffer, len);
			break;
		default:
			return FALSE;
	}
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SM3);
	if (!hasher || !hasher->allocate_hash(hasher, enc, fp))
	{
		DBG1(DBG_LIB, "SM3 not supported, fingerprinting failed");
		DESTROY_IF(hasher);
		free(enc.ptr);
		return FALSE;
	}
	free(enc.ptr);
	hasher->destroy(hasher);
	lib->encoding->cache(lib->encoding, type, key, fp);
	return TRUE;
}