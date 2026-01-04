#include "gmssl_plugin.h"

#include <library.h>
#include "crypto/crypters/crypter.h"
#include "plugins/plugin_feature.h"

#include "gmssl_hasher.h"
#include "gmssl_crypter.h"
#include "gmssl_hmac.h"
#include "gmssl_sm2_public_key.h"
#include "gmssl_sm2_private_key.h"

typedef struct private_gmssl_plugin_t private_gmssl_plugin_t;

/**
 * private data of gmssl_plugin
 */
 struct private_gmssl_plugin_t
 {
    /**
	 * public functions
	 */
    gmssl_plugin_t public;
 };

METHOD(plugin_t, get_name, char*,
	private_gmssl_plugin_t *this)
{
	return "gmssl";
}

METHOD(plugin_t, get_features, int,
	private_gmssl_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(HASHER, gmssl_hasher_create),
			PLUGIN_PROVIDE(HASHER, HASH_SM3),

		PLUGIN_REGISTER(CRYPTER, gmssl_crypter_create),
			PLUGIN_PROVIDE(CRYPTER, ENCR_SM4_CBC, 16),

		PLUGIN_REGISTER(PRF, gmssl_hmac_prf_create),
			PLUGIN_PROVIDE(PRF, PRF_HMAC_SM3),
			
		PLUGIN_REGISTER(SIGNER, gmssl_hmac_signer_create),
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SM3),

#if defined (USE_CUSTOM_EXT) && defined (USE_CUSTOM_EXT_ATTR_IKEV1_SM)
		PLUGIN_REGISTER(PRIVKEY, sm2_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_SM2),
		PLUGIN_REGISTER(PRIVKEY_GEN, sm2_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_SM2),
		PLUGIN_REGISTER(PUBKEY, sm2_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_SM2),
		PLUGIN_REGISTER(PUBKEY, sm2_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_ECDSA),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_SM2_WITH_SM3),
			PLUGIN_DEPENDS(HASHER, HASH_SM3),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_SM2_WITH_SM3),
			PLUGIN_DEPENDS(HASHER, HASH_SM3),
#endif
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_gmssl_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
PLUGIN_DEFINE(gmssl)
{
	private_gmssl_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	lib->proposal->register_token(lib->proposal, "sm4", ENCRYPTION_ALGORITHM, ENCR_SM4_CBC, 16 * 8);
	lib->proposal->register_token(lib->proposal, "sm3", INTEGRITY_ALGORITHM, AUTH_HMAC_SM3, 0);

	return &this->public.plugin;
}
