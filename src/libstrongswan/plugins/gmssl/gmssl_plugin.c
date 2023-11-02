#include "gmssl_plugin.h"

#include <library.h>
#include "crypto/crypters/crypter.h"
#include "plugins/plugin_feature.h"

#include "gmssl_hasher.h"
#include "gmssl_crypter.h"
#include "gmssl_hmac.h"

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
plugin_t *gmssl_plugin_create()
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

	lib->proposal->register_token(lib->proposal, "sm4", ENCRYPTION_ALGORITHM, ENCR_SM4_CBC, 0);
	lib->proposal->register_token(lib->proposal, "sm3", INTEGRITY_ALGORITHM, AUTH_HMAC_SM3, 0);

	return &this->public.plugin;
}
