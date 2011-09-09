/*
 * Copyright 2010 Miro Mannino <miro.mannino@gmail.com>
 * This work is licensed under the Creative Commons Attribution 2.5
 * Italy License. To view a copy of this license, visit
 * http://creativecommons.org/licenses/by/2.5/it/ or send a letter
 * to Creative Commons, 171 Second Street, Suite 300, San Francisco,
 * California, 94105, USA.
 *
 */

/**
 * @file main.c
 * @brief Start point of the fuse module
 *
 * @defgroup main Start point
 * @ingroup  main
 * @{
 */

#include <main.h>

void pubcfs_main_version(int argc, char** argv){
	fprintf(stderr,
		"pubcFS version: 0.1"
		"\n"
	);

	char* s[2] = {"", "-V"};
	fuse_main(2, s, NULL, NULL);
	exit(EXIT_FAILURE);
}

void pubcfs_main_usage(int argc, char** argv){
	fprintf(stderr,
		"\nusage: %s user privateKeyPath rootPath mountPoint [options]\n\n"
		"\n"
		"pubcFS options:\n"
		"    user             user name that have the enter priviledge\n"
		"    privateKeyPath   the private key of the user for unlock the filesystem\n"
		"    rootPath         the path of the crypted folder\n"
		"    mountPoint       the path of the encrypted folder\n"
		"\n"
		, argv[0]
	);

	char* s[2] = {argv[0], "-h"};
	fuse_main(2, s, NULL, NULL);
	exit(EXIT_FAILURE);
}

void pubcfs_main_readConfig(pubcfs_context* ctx){
	char* configFilePath;
	char* buf;
	mConfig_t* c;

	//calculate the configuration path
	configFilePath = (char*)malloc(strlen(ctx->rootPath) + strlen(PUBCFS_CONFIG_PATH) + 2);
	sprintf(configFilePath, "%s/%s", ctx->rootPath, PUBCFS_CONFIG_PATH);
	if(configFilePath == NULL){
		goto err0;
	}

	if(mConfig_readConfig(&c, configFilePath) != MCONFIG_NOERR){
		fprintf(stderr, "Error (configuration): configuration file reading fail");
		goto err1;
	}

	buf = mConfig_readValue(c, "blocksize");
	if(buf == NULL){
		fprintf(stderr, "Error (configuration): blocksize key not found");
		goto err1;
	}
	ctx->blockSize = atoi(buf);
	if(ctx->blockSize < 8){
		fprintf(stderr, "Error (configuration): blocksize value must be a number bigger than 8");
		goto err2;
	}
	free(buf);

	mConfig_dispose(c);

	return;

err2:
	free(buf);
err1:
	free(configFilePath);
err0:
	return;
}



int main(int argc, char** argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	int i, ris;
	pubcfs_context* ctx;
	RSA* privKey;

	/* in this way we check that the fs is not mounted by root because
	 * when it is mounted by root all users will have root priviledges in
	 * this fs */
	if((getuid() == 0) || (geteuid() == 0)){
		fprintf(stderr, "Running pubcFS as root is not safe\n");
		return 1;
	}

	/* create the main pubcfs context that contains all environment settings, we use the context
	 * instead of the global variables for the virtualization library that can use this module
	 * like the umfuse */
	ctx = (pubcfs_context *)malloc(sizeof(pubcfs_context));

	/*option parsing-------------*/

	if ((argc > 1 && strcmp(argv[1], "-h") == 0)){
		pubcfs_main_usage(argc, argv);
	}

	if ((argc > 1 && strcmp(argv[1], "-v") == 0)){
		pubcfs_main_version(argc, argv);
	}

	if (argc < 4){
		pubcfs_main_usage(argc, argv);
	}

	for (i = 0; i < argc; i++){
		switch (i){
		case 1:
			//User name
			//TODO: regex for check user name
			ctx->userName = strdup(argv[i]);
			break;
		case 2:
			//Private key path
			ctx->privateKeyPath = realpath(argv[i], NULL);
			if (ctx->privateKeyPath == NULL){
				fprintf(stderr, "privateKeyPath is not a valid path\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 3:
			//Root path
			ctx->rootPath = realpath(argv[i], NULL);
			if (ctx->rootPath == NULL){
				fprintf(stderr, "rootPath is not a valid path\n");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			//Add option to fuse
			fuse_opt_add_arg(&args, argv[i]);
		}
	}

	/*end option parsing-------------*/

	pubcfs_main_readConfig(ctx);
	pubcfs_initRSAModule();

	//read the private key
	privKey = pubcfs_readPrivateKey(ctx->privateKeyPath);
	if (privKey == NULL){
		fprintf(stderr, "Error: can't load private key\n");
		return false;
	}

	ctx->keyLen = PUBCFS_SIMMKEY_SIZE;
	ris = pubcfs_readSimmetricKey(privKey, ctx->rootPath, ctx->userName, &(ctx->key));
	if(ris < 0){
		switch(ris){
		//TODO: riguardare la lista degli errori
			case PUBCFS_ERR_NOUSER:
				fprintf(stderr, "Error: user not found\n");
				break;
			case PUBCFS_ERR_READERROR:
				fprintf(stderr, "Error: can't read the key of the user, read error\n");
				break;
			case PUBCFS_ERR_ENOMEM:
				fprintf(stderr, "rror: no enough memory for the operation\n");
				break;
			case PUBCFS_ERR_DECRYPTFAIL:
				fprintf(stderr, "Error: can't decrypt the simmetric key with this private key\n");
				break;
			default:
				fprintf(stderr, "Error: can't read the simmetric key\n");
		}
		exit(EXIT_FAILURE);
	}

	/* We create the key for the crypto context and when the thread need it the get function create
	 * it and assign the created context to the thread specific data pointed by ctx->cryptCtxKey */
	pthread_key_create(&(ctx->cryptCtxKey), pubcfs_destroyCryptCtx);

	/* start the fuse module with the created context */
	return fuse_main(args.argc, args.argv, getPubcFSOperations(), ctx);

}

/** @} */
