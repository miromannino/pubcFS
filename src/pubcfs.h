/*
 * Copyright 2010 Miro Mannino <miro.mannino@gmail.com>
 * This work is licensed under the Creative Commons Attribution 2.5
 * Italy License. To view a copy of this license, visit
 * http://creativecommons.org/licenses/by/2.5/it/ or send a letter
 * to Creative Commons, 171 Second Street, Suite 300, San Francisco,
 * California, 94105, USA.
 * 
 */ 

#ifndef PUBCFS_H
	
	#define PUBCFS_H

	#include <stdlib.h>
	#include <string.h>
	#include <unistd.h>
	#include <pthread.h>
	#include <sys/types.h>
	#include <dirent.h>
	#include <time.h>

	#include <openssl/evp.h>
	#include <openssl/aes.h>
	#include <openssl/rsa.h>
	#include <openssl/err.h>
	#include <openssl/pem.h>

	#include <util.h>
	#include <fuse.h>
	#include <mConfig/mConfig.h>
	#include <base64/base64.h>

	#define PUBCFS_CONFIG_FOLDER ".pubcfs"
	#define PUBCFS_CONFIG_PATH ".pubcfs/config"
	#define PUBCFS_KEY_FOLDER ".pubcfs/keys"
	#define PUBCFS_KEY_DEFAULT_MODE 0644
	#define PUBCFS_KEY_MAXSIZE
	#define PUBCFS_FILENAME_ENC_WITH_S "/enc_"
	#define PUBCFS_FILENAME_ENC "enc_"
	#define PUBCFS_FILENAME_ENC_SIZE 4

	#define PUBCFS_CONFIG_DEFAULT_BLOCKSIZE "64"

	#define PUBCFS_ERR_GENERIC 				-1	//Generic error
	#define PUBCFS_ERR_NOUSER 				-2	//When the user is not in the keys folder
	#define PUBCFS_ERR_DECRYPTFAIL 			-3	//When the key decrypt fails
	#define PUBCFS_ERR_ENCRYPTFAIL 			-4	//When the key encrypt fails
	#define PUBCFS_ERR_WRITEERROR 			-5	//When there is some problem on write
	#define PUBCFS_ERR_READERROR 			-6	//When there is some problem on write
	#define PUBCFS_ERR_NOADDUSER 			-7	//When there is impossible to add the user
	#define PUBCFS_ERR_ENOMEM	 			-8	//When there is impossible to add the user
	#define PUBCFS_ERR_BADCONFIGFOLDER		-9	//When the config folder not exists
	#define PUBCFS_ERR_ONLYONEUSR			-10 //When there is only one user and we can't remove it
	#define PUBCFS_NOERR 					 0	//All OK!!

	#define PUBCFS_SIMMKEY_SIZE 64


	typedef struct {
		EVP_CIPHER_CTX en;
		EVP_CIPHER_CTX de;
	} pubcfs_cryptoCtx;

	typedef struct {
	    char *rootPath;
	    char *privateKeyPath;
	    char *userName;
	    ubyte *key;
	    size_t keyLen;
	    size_t blockSize;
	    pthread_key_t cryptCtxKey;
	} pubcfs_context;

	char* pubcfs_encodePath(pubcfs_context* ctx, const char *path, bool addRootPath);
	char* pubcfs_decryptName(pubcfs_context* ctx, const char *name);

	int pubcfs_readBlock(pubcfs_context* ctx, pubcfs_cryptoCtx* cctx, int fp,
						 ulong block, ubyte* de_buf);
	int pubcfs_writeBlock(pubcfs_context* ctx, pubcfs_cryptoCtx* cctx, int fp,
						  ulong block, ubyte* de_buf, size_t size);

	pubcfs_context* pubcfs_getCtx();
	pubcfs_cryptoCtx* pubcfs_getCryptoCtx(pubcfs_context* st);
	pubcfs_cryptoCtx* pubcfs_createCryptoCtx(pubcfs_context* st);
	void pubcfs_destroyCryptCtx(void* cryptCtx);

	void pubcfs_encrypt(EVP_CIPHER_CTX *e, uchar* plainText, uchar* cipherText, size_t size);
	void pubcfs_decrypt(EVP_CIPHER_CTX *de, uchar* cipherText, uchar* plainText, size_t size);

	void pubcfs_initRSAModule();
	RSA* pubcfs_readPublicKey(const char *filename);
	RSA* pubcfs_readPrivateKey(const char *filename);
	void pubcfs_RSA_encrypt(RSA* key, unsigned char *plainText, unsigned char **cyperText);
	void pubcfs_RSA_decrypt(RSA* key, unsigned char *cyperText, unsigned char **plainText);

	int pubcfs_readSimmetricKey(RSA* privKey, char* rootPath, char* userName, ubyte** key);
	int pubcfs_writeSimmetricKey(RSA* pubKey, char* rootPath, char* userName, ubyte* key);
	void pubcfs_generateSimmetricKey(ubyte** key);
	int pubcfs_initPubcfsFolder(RSA* pubKey, char* rootPath, char* userName);
	int pubcfs_addUser(char* rootPath, char* userName1, char* userName2,
									   RSA* privKeyUsr1, RSA* pubKeyUsr2);
	int pubcfs_listAllUser(FILE* fdOut, char* rootPath);
	int pubcfs_countUsers(char* rootPath, uint* userCount);
	int pubcfs_deleteUser(char* rootPath, char* userName);

#endif
