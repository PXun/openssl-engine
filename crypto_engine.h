#ifndef _CRYPTO_ENGINE_H_
#define _CRYPTO_ENGINE_H_

ENGINE *ENGINE_load_iwall_engine();

void ENGINE_clean_iwall_engine(ENGINE *engine);

#endif

