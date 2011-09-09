#include <pubcfs.h>

/** Returns the absolute path of the relative path and encoded it
 *
 * @param path relative path, it will be encoded and then used for build the absolute path
 *
 * @return a string that you must deallocate with the free function
 */
char* pubcfs_encodePath(pubcfs_context* ctx, const char *path, bool addRootPath)
{
	char *ris, *token, *strtok_ctx, *path_cpy, *check;
	size_t token_len, buf_e64_len;
	char *buff, *buf_e64;
	bool firstCicle;
	pubcfs_cryptoCtx* cctx;

	cctx = pubcfs_getCryptoCtx(ctx);
	path_cpy = strdup(path); //because the strtok_r modify it

	ris = (char*)malloc(addRootPath ? (strlen(ctx->rootPath) + 1) : 1);
	if (ris == NULL) return NULL;

	//rootPath is in this format "/path/to/folder"
	if(addRootPath){
		strcpy(ris, ctx->rootPath);
		firstCicle = false;
	}else{
		ris[0] = '\0';
		firstCicle = true;
	}

	token = strtok_r(path_cpy, "/", &strtok_ctx);
	while(token != NULL){
		check = strstr(token, PUBCFS_FILENAME_ENC);
		if(check == token){
			token = token + PUBCFS_FILENAME_ENC_SIZE; //remove the PUBCFS_FILENAME_ENC prefix
			token_len = strlen(token);
			buff = (char*)malloc(token_len + 1);
			if(buff == NULL){
				free(ris);
				if(path_cpy != NULL) free(path_cpy);
				return NULL;
			}
			buff[token_len] = '\0';

			if(firstCicle){
				ris = strappend(ris, PUBCFS_FILENAME_ENC);
				firstCicle = false;
			}else{
				ris = strappend(ris, PUBCFS_FILENAME_ENC_WITH_S);
			}
			pubcfs_encrypt(&(cctx->en), (uchar*)token, (uchar*)buff, token_len);
			base64_encode((ubyte*)buff, (uchar**)(&buf_e64), token_len, &buf_e64_len, base64_OPT_FILENAMESAFE);
			free(buff);
			ris = strappend(ris, buf_e64);
		}else{
			if(!firstCicle){
				ris = strappend(ris, "/");
			}else{
				firstCicle = false;
			}
			ris = strappend(ris, token);
		}

		token = strtok_r(NULL, "/", &strtok_ctx);
	}

	if(path_cpy != NULL) free(path_cpy);

	return ris;
}

/** Returns decrypted name of an encoded name, for example the name of a file in the root directory
 * that is encrypted.
 *
 * @param name the string that contain the name to decrypt
 *
 * @return a string that you must deallocate with the free function
 */
char* pubcfs_decryptName(pubcfs_context* ctx, const char *name)
{
	char *buff, *buff2, *check;
	size_t buff_len;
	pubcfs_cryptoCtx* cctx;

	cctx = pubcfs_getCryptoCtx(ctx);

	//this is the case that the name isn't encrypted
	check = strstr(name, PUBCFS_FILENAME_ENC);
	if(check == name){

		name = name + PUBCFS_FILENAME_ENC_SIZE;

		base64_decode((uchar*)name, (uchar**)(&buff), strlen(name), &buff_len, base64_OPT_FILENAMESAFE);
		buff2 = malloc(buff_len + 1 + PUBCFS_FILENAME_ENC_SIZE);
		if(buff2 != NULL){
			strcpy(buff2, PUBCFS_FILENAME_ENC);
			pubcfs_decrypt(&(cctx->de), (uchar*)buff, (uchar*)(buff2 + PUBCFS_FILENAME_ENC_SIZE), buff_len);
			buff2[buff_len + PUBCFS_FILENAME_ENC_SIZE] = '\0';
		}else{
			buff2 = NULL;
		}

		free(buff);
	}else{
		buff2 = malloc(strlen(name) + 1);
		if (buff2 != NULL){
			strcpy(buff2, name);
		}else{
			buff2 = NULL;
		}
	}

	return buff2;
}

/** Read a block from the file and decode it
 *
 * @param ctx pubcfs_context that have all the current context
 * @param cctx pubcfs_cryptoCtx that have the crypto context
 * @param fp the file pointer of the file to read
 * @param block the block to read
 * @param de_buf pointer to a ubyte array that will contain the readed block, this buffer must be
 * allocated before with a size of ctx->blockSize
 *
 * @return the readed bytes or -1 if error
 */
int pubcfs_readBlock(pubcfs_context* ctx, pubcfs_cryptoCtx* cctx, int fp,
					 ulong block, ubyte* de_buf)
{
    int ris;
    ubyte* e_buf;

    e_buf = (ubyte*)malloc(ctx->blockSize);
    if(e_buf == NULL) return -1;

    ris = pread(fp, e_buf, ctx->blockSize, block * ctx->blockSize);
	if(ris < 0){
		return -1;
	}

	pubcfs_decrypt(&(cctx->de), e_buf, de_buf, ris);

	free(e_buf);
    return ris;
}

/** Encode and Write a block to the file
 *
 * @param ctx pubcfs_context that have all the current context
 * @param cctx pubcfs_cryptoCtx that have the crypto context
 * @param fp the file pointer of the file to read
 * @param block the block to read
 * @param de_buf pointer to a ubyte array that contain the block to write
 * @param size is usually equals to 'blocksize' but it can be less in the end of file
 *
 * @return the writed bytes or -1 if error
 */
int pubcfs_writeBlock(pubcfs_context* ctx, pubcfs_cryptoCtx* cctx, int fp,
					  ulong block, ubyte* de_buf, size_t size)
{
    int ris;
    ubyte* e_buf;

    e_buf = (ubyte*)malloc(size);
    if(e_buf == NULL) return -1;

	pubcfs_encrypt(&(cctx->en), de_buf, e_buf, size);
    ris = pwrite(fp, e_buf, size, block * ctx->blockSize);

    free(e_buf);
    return ris;
}

/** Get the pubcfs_context context, it is taken using the fuse_get_context function
 * @return the context, you cannot deallocate it
 *  */
pubcfs_context* pubcfs_getCtx(){
	return (pubcfs_context*)fuse_get_context()->private_data;
}

/** Get the pubcfs_cryptoCtx that contain all the crypto context
 * This context is separated from the normal context because in multithread situations the crypto
 * algorithm have some problems. For this problem the context is a Thread Specific Data and it
 * is created for each thread that need it
 *
 * @param ctx pubcfs_context that have all the current context
 *
 * @return the crypto context, you cannot deallocate it
 */
pubcfs_cryptoCtx* pubcfs_getCryptoCtx(pubcfs_context* ctx){
    pubcfs_cryptoCtx* cctx;

    cctx = (pubcfs_cryptoCtx*)pthread_getspecific(ctx->cryptCtxKey);
    if(cctx == NULL){
    	cctx = pubcfs_createCryptoCtx(ctx);
    	pthread_setspecific(ctx->cryptCtxKey, cctx);
    }

    return cctx;
}

/** Create a new crypto context, this function should be call only by the pubcfs_getCryptoCtx
 * function because this context have some problem with multithread
 *
 * @param ctx pubcfs_context that have all the current context
 *
 * @return the crypto context, you cannot deallocate it
 */
pubcfs_cryptoCtx* pubcfs_createCryptoCtx(pubcfs_context* ctx){
	uchar* key;
	size_t keyLength;
	EVP_CIPHER_CTX en, de;
	pubcfs_cryptoCtx* cctx = (pubcfs_cryptoCtx*)malloc(sizeof(pubcfs_cryptoCtx));
	int i, count = 5;
	uchar keyv[32];
	uchar iv[32]; //inizialization vector http://en.wikipedia.org/wiki/Initialization_vector

	key = ctx->key;
	keyLength = ctx->keyLen;

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * count is the number of times the we hash the material. More rounds are more secure but
	 * slower. EVP_BytesToKey() derives a key and IV from various parameters. type is the cipher
	 * to derive the key and IV for. md is the message digest to use. The salt paramter is used as
	 * a salt in the derivation: it should point to an 8 byte buffer or NULL if no salt is used.
	 * data is a buffer containing datal bytes which is used to derive the keying data. count is
	 * the iteration count to use. The derived key and IV will be written to key and iv respectively
	 *
	 * -----
	 *
	 * In this case we use cfb8 because we need to encrypt and decrypt stream that must have the
	 * plaintext size the same of the ciphertext
	 */
	i = EVP_BytesToKey(EVP_aes_256_cfb8(), EVP_sha1(), NULL, key, keyLength, count, keyv, iv);
	if (i != 32) {
		free(cctx);
		return NULL;
	}

	EVP_CIPHER_CTX_init(&en);
	EVP_EncryptInit_ex(&en, EVP_aes_256_cfb8(), NULL, key, iv);
	EVP_CIPHER_CTX_init(&de);
	EVP_DecryptInit_ex(&de, EVP_aes_256_cfb8(), NULL, key, iv);

	cctx->en = en;
	cctx->de = de;

	return cctx;
}

/** Destroy the crypto context, see 'pthread_key_create'
 */
void pubcfs_destroyCryptCtx(void* cctx){
	free(cctx);
	//TODO: altro?
}

/** A generic function to encrypt data, for the cfb mode the size of the encrypted text is the same
 * of the decrypted text. This semplify a lot of things!
 *
 * @param e the EVP_CIPHER_CTX that can be found in the crypto context
 * @param plainText the data to encrypt
 * @param cipherText the buffer that contain the encrypted data (it must be allocated before)
 * @param size the size of the plain/cipher text
 */
void pubcfs_encrypt(EVP_CIPHER_CTX *e, uchar* plainText, uchar* cipherText, size_t size)
{
	//TODO: errori delle funzioni EVP da controllare? potrebbe fallire qualche volta?

	int c_len, f_len;

	c_len = size;
	f_len = 0;

	/* EVP_EncryptInit_ex() sets up cipher context ctx for encryption with cipher type from ENGINE
	 * impl. ctx must be initialized before calling this function. type is normally supplied by a
	 * function such as EVP_des_cbc(). If impl is NULL then the default implementation is used.
	 * key is the symmetric key to use and iv is the IV to use (if necessary), the actual number
	 * of bytes used for the key and IV depends on the cipher. It is possible to set all
	 * parameters to NULL except type in an initial call and supply the remaining parameters in
	 * subsequent calls, all of which have type set to NULL. This is done when the default cipher
	 * parameters are not appropriate.
	 */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* EVP_EncryptUpdate() encrypts inl bytes from the buffer in and writes the encrypted version
	 * to out. This function can be called multiple times to encrypt successive blocks of data.
	 * The amount of data written depends on the block alignment of the encrypted data: as a result
	 * the amount of data written may be anything from zero bytes to (inl + cipher_block_size - 1)
	 * so outl should contain sufficient room. The actual number of bytes written is placed in
	 * outl.*/
	EVP_EncryptUpdate(e, cipherText, &c_len, plainText, size);

	/* update ciphertext with the final remaining bytes
	 * If padding is enabled (the default) then EVP_EncryptFinal_ex() encrypts the “final” data,
	 * that is any data that remains in a partial block. It uses standard block padding (aka PKCS
	 * padding). The encrypted final data is written to out which should have sufficient space
	 * for one cipher block. The number of bytes written is placed in outl. After this function
	 * is called the encryption operation is finished and no further calls to EVP_EncryptUpdate()
	 * should be made. If padding is disabled then EVP_EncryptFinal_ex() will not encrypt any more
	 * data and it will return an error if any data remains in a partial block: that is if the
	 * total data length is not a multiple of the block size.*/
	EVP_EncryptFinal_ex(e, cipherText + c_len, &f_len);

}

/** A generic function to decrypt data, for the cfb mode the size of the decrypted text is the same
 * of the encrypted text. This semplify a lot of things!
 *
 * @param de the EVP_CIPHER_CTX that can be found in the crypto context
 * @param cipherText the data to decrypt
 * @param plainText the buffer that contain the decrypted data (it must be allocated before)
 * @param size the size of the plain/cipher text
 */
void pubcfs_decrypt(EVP_CIPHER_CTX *de, uchar* cipherText, uchar* plainText, size_t size)
{
	//TODO: errori delle funzioni EVP da controllare? potrebbe fallire qualche volta?

	int p_len, f_len;

	p_len = size;
	f_len = 0;

	/* EVP_DecryptInit_ex(), EVP_DecryptUpdate() and EVP_DecryptFinal_ex() are the corresponding
	 * decryption operations. EVP_DecryptFinal() will return an error code if padding is enabled
	 * and the final block is not correctly formatted. The parameters and restrictions are identical
	 * to the encryption operations except that if padding is enabled the decrypted data buffer out
	 * passed to EVP_DecryptUpdate() should have sufficient room for (inl + cipher_block_size) bytes
	 * unless the cipher block size is 1 in which case inl bytes is sufficient.
	 */
	EVP_DecryptInit_ex(de, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(de, plainText, &p_len, cipherText, size);
	EVP_DecryptFinal_ex(de, plainText + p_len, &f_len);
}

/** Initialize the RSA functions */
void pubcfs_initRSAModule(){
	OpenSSL_add_all_algorithms();
}

RSA* pubcfs_readPublicKey(const char *filename){
	FILE* fp;
	RSA* pkey;

	fp = fopen(filename, "r");
	if (!fp) return NULL;

	pkey = PEM_read_RSA_PUBKEY(fp, NULL, 0, NULL);

	fclose (fp);
	return pkey;
}

RSA* pubcfs_readPrivateKey(const char *filename){
	FILE* fp;
	RSA* pkey;

	fp = fopen(filename, "r");
	if (!fp) return NULL;

	pkey = PEM_read_RSAPrivateKey(fp, NULL, 0, NULL /*in this parameter we can give it the passw*/);
	//we can cange the default function that request the password, see "man pem" for it

	fclose (fp);
	return pkey;
}

/** Check that the configuration folder exist and if not try to create it
 *
 * return PUBCFS_NOERR if the folder exists or it create the folders
 * 		  PUBCFS_ERR_ENOMEM if there isn't enough memory to allocate the paths
 * 		  PUBCFS_ERR_WWRITEERROR if the function can't write to the folder
 * */
int pubcfs_checkCreateConfigFolders(char* rootPath){
	char *configFolderPath, *keysFolderPath;
	struct stat st;
	int err, ris;

	if(rootPath == NULL){
		err = PUBCFS_ERR_GENERIC;
		goto ret;
	}

	configFolderPath = (char*)malloc(strlen(rootPath) + strlen(PUBCFS_CONFIG_FOLDER) + 2);
	sprintf(configFolderPath, "%s/%s", rootPath, PUBCFS_CONFIG_FOLDER);
	keysFolderPath = (char*)malloc(strlen(rootPath) + strlen(PUBCFS_KEY_FOLDER) + 2);
	sprintf(keysFolderPath, "%s/%s", rootPath, PUBCFS_KEY_FOLDER);
	if(configFolderPath == NULL || keysFolderPath == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret1;
	}

	if(stat(configFolderPath, &st) != 0){
		ris = mkdir(configFolderPath, 0755);
		if(ris == -1){
			err = PUBCFS_ERR_WRITEERROR;
			goto ret1;
		}
	}

	if(stat(keysFolderPath, &st) != 0){
		ris = mkdir(keysFolderPath, 0755);
		if(ris == -1){
			err = PUBCFS_ERR_WRITEERROR;
			goto ret1;
		}
	}

	return PUBCFS_NOERR;

	//Errors
	ret1:
		if(keysFolderPath != NULL) free(keysFolderPath);
		if(configFolderPath != NULL) free(configFolderPath);
	ret:
		return err;
}

/** Read the simmetric key decrypting the encrypted key of an user
 *
 * return PUBCFS_ERR_GENERIC on a generic error (for example a parameter is null)
 * 		  PUBCFS_NOERR all ok
 * 		  PUBCFS_ERR_ENOMEM if there isn't enough memory to allocate the paths
 *        PUBCFS_ERR_NOUSER if the user not exists
 * 		  PUBCFS_ERR_READERROR if the function can't read the key
 *        PUBCFS_ERR_DECRYPTFAIL if the decrypt fail
 * */
int pubcfs_readSimmetricKey(RSA* privKey, char* rootPath, char* userName, ubyte** key){
	char* keyFilePath;
	ubyte *e_key;
	int fp, err, ris;
	size_t readed;
	size_t e_keySize;

	if((privKey == NULL) || (rootPath == NULL) || (userName == NULL) || (key == NULL)){
	  err = PUBCFS_ERR_GENERIC;
	  goto ret;
	}

	e_keySize = RSA_size(privKey);

	//calculate the path
	keyFilePath = (char*)malloc(strlen(rootPath) + strlen(PUBCFS_KEY_FOLDER) + strlen(userName) + 3);
	if(keyFilePath == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret;
	};
	sprintf(keyFilePath, "%s/%s/%s", rootPath, PUBCFS_KEY_FOLDER, userName);

	//check that the user exist
	fp = open(keyFilePath, O_RDONLY);
	if (fp == -1){
		err = PUBCFS_ERR_NOUSER;
		goto ret1;
	}

	//read the crypted key
	e_key = (ubyte*)malloc(e_keySize);
	if(e_key == NULL){
		close(fp);
		err = PUBCFS_ERR_ENOMEM;
		goto ret1;
	}
	readed = readn(fp, e_key, e_keySize);
	if(readed != e_keySize){
		close(fp);
		err = PUBCFS_ERR_READERROR;
		goto ret1;
	}
	close(fp);

	//decrypt the key
	*key = (ubyte*)malloc(PUBCFS_SIMMKEY_SIZE);
	if(*key == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret2;
	}
	RSA_blinding_on(privKey, NULL); //it protect from the attacks that misure the decrypt time
	ris = RSA_private_decrypt(e_keySize, e_key, *key, privKey, RSA_PKCS1_PADDING);
	if (ris == -1 || ris != PUBCFS_SIMMKEY_SIZE){
		err = PUBCFS_ERR_DECRYPTFAIL;
		goto ret3;
	}

	free(e_key);
	free(keyFilePath);

	return PUBCFS_NOERR;

	//Errors
	ret3:
		free(*key);
	ret2:
		free(e_key);
	ret1:
		free(keyFilePath);
	ret:
	return err;

}

/** Write the simmetric key crypting the decrypted key of an user
 *
 * return PUBCFS_ERR_GENERIC on a generic error (for example a parameter is null)
 * 		  PUBCFS_NOERR all ok
 * 		  PUBCFS_ERR_ENOMEM if there isn't enough memory to allocate the paths
 *        PUBCFS_ERR_NOADDUSER if the function can add this user
 * 		  PUBCFS_ERR_WRITEERROR if the function can't read the key
 *        PUBCFS_ERR_ENCRYPTFAIL if the encrypt fail
 * */
int pubcfs_writeSimmetricKey(RSA* pubKey, char* rootPath, char* userName, ubyte* key){
	char* keyFilePath;
	ubyte *e_key;
	int fp, err, ris;
	size_t writed;
	size_t e_keySize;
	struct stat st;

	if((pubKey == NULL) || (rootPath == NULL) || (userName == NULL) || (key == NULL)){
	  err = PUBCFS_ERR_GENERIC;
	  goto ret;
	}

	e_keySize = RSA_size(pubKey);

	//calculate the path
	keyFilePath = (char*)malloc(strlen(rootPath) + strlen(PUBCFS_KEY_FOLDER) + strlen(userName) + 3);
	if(keyFilePath == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret;
	};
	sprintf(keyFilePath, "%s/%s/%s", rootPath, PUBCFS_KEY_FOLDER, userName);

	//encrypt the key
	e_key = (ubyte*)malloc(e_keySize);
	if(e_key == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret1;
	}
	RSA_blinding_on(pubKey, NULL); //it protect from the attacks that misure the encrypt time
	ris = RSA_public_encrypt(PUBCFS_SIMMKEY_SIZE, key, e_key, pubKey, RSA_PKCS1_PADDING);
	if (ris == -1 || ris != e_keySize){
		err = PUBCFS_ERR_ENCRYPTFAIL;
		goto ret2;
	}

	//check that the configuration folder exist and if not create it
	ris = pubcfs_checkCreateConfigFolders(rootPath);
	if(ris != PUBCFS_NOERR){
		err = ris;
		goto ret2;
	}

	//check that the user not exists
	if(stat(keyFilePath, &st) != 0){
		//create the user opening the file
		fp = open(keyFilePath, O_WRONLY | O_CREAT, PUBCFS_KEY_DEFAULT_MODE);
		if (fp == -1){
			err = PUBCFS_ERR_NOADDUSER;
			goto ret2;
		}
	}else{
		err = PUBCFS_ERR_NOADDUSER;
		goto ret2;
	}

	//write the crypted key
	writed = write(fp, e_key, e_keySize);
	if(writed != e_keySize){
		close(fp);
		err = PUBCFS_ERR_WRITEERROR;
		goto ret2;
	}
	close(fp);

	free(e_key);
	free(keyFilePath);

	return PUBCFS_NOERR;

	//Errors
	ret2:
		free(e_key);
	ret1:
		free(keyFilePath);
	ret:
	return err;

}

/** Generate a random key to use as a simmetric key
 *
 * param key point to a ubyte array that will contain the result key, it must be deallocate
 *           if *key is null the function can't allocate the memory for generate this key
 * */
void pubcfs_generateSimmetricKey(ubyte** key){
	int i;
	ubyte* risKey;

	srandom(time(NULL));

	risKey = (ubyte*)malloc(PUBCFS_SIMMKEY_SIZE);
	if(risKey == NULL){
		*key = NULL;
		return;
	}
	for(i = 0; i < PUBCFS_SIMMKEY_SIZE; i++){
		risKey[i] = (ubyte)rand();
	}

	*key = risKey;
}

/** Initialize the crypted folder, it create the configuration folder, the first user and a standard
 *  configuration file with the standard settings
 *
 * return PUBCFS_ERR_GENERIC on a generic error (for example a parameter is null)
 * 		  PUBCFS_NOERR all ok
 * 		  can return an error of the pubcfs_writeSimmetricKey function
 *
 * */
int pubcfs_initPubcfsFolder(RSA* pubKey, char* rootPath, char* userName){
	char *configFilePath;
	ubyte *de_key;
	int ris, err;
	mConfig_t* c;

	if((rootPath == NULL) || (userName == NULL) || (pubKey == NULL)){
		err = PUBCFS_ERR_GENERIC;
		goto ret;
	}

	//calculate the configuration file path
	configFilePath = (char*)malloc(strlen(rootPath) + strlen(PUBCFS_CONFIG_PATH) + 2);
	sprintf(configFilePath, "%s/%s", rootPath, PUBCFS_CONFIG_PATH);
	if(configFilePath == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret1;
	}

	//generate a random simmetric key
	pubcfs_generateSimmetricKey(&de_key);
	if(de_key == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret1;
	};

	//write the simmetric key
	ris = pubcfs_writeSimmetricKey(pubKey, rootPath, userName, de_key);
	if(ris != PUBCFS_NOERR){
		err = ris;
		goto ret2;
	};

	//create a standard configuration file
	c = mConfig_new();
	if(c == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret2;
	}
	ris = mConfig_add(c, "blocksize", PUBCFS_CONFIG_DEFAULT_BLOCKSIZE);
	if(ris == MCONFIG_EADD){
		err = PUBCFS_ERR_ENOMEM;
		goto ret3;
	}
	ris = mConfig_saveConfig(c, configFilePath);
	if(ris == MCONFIG_EFILE){
		err = PUBCFS_ERR_WRITEERROR;
		goto ret3;
	}

	//free
	mConfig_dispose(c);
	free(de_key);
	free(configFilePath);

	return PUBCFS_NOERR;

	//Errors
	ret3:
		mConfig_dispose(c);
	ret2:
		free(de_key);
	ret1:
		if(configFilePath != NULL) free(configFilePath);
	ret:
		return err;

}

/** Add an user decrypting the simmetric key of the first user and crypting to the second user
 *
 * return PUBCFS_ERR_GENERIC on a generic error (for example a parameter is null)
 * 		  PUBCFS_NOERR all ok
 * 		  can return an error of the pubcfs_writeSimmetricKey function
 * 		  can return an error of the pubcfs_readSimmetricKey function
 * */
int pubcfs_addUser(char* rootPath, char* userName1, char* userName2,
								   RSA* privKeyUsr1, RSA* pubKeyUsr2){

	ubyte *de_key;
	int ris, err;

	if((rootPath == NULL) || (userName1 == NULL) || (userName2 == NULL) ||
	   (privKeyUsr1 == NULL) || (pubKeyUsr2 == NULL)){
		err = PUBCFS_ERR_GENERIC;
		goto ret;
	}

	//write the simmetric key from the first user
	ris = pubcfs_readSimmetricKey(privKeyUsr1, rootPath, userName1, &de_key);
	if(ris != PUBCFS_NOERR){
		err = ris;
		goto ret;
	}

	//write the simmetric key to the second user
	ris = pubcfs_writeSimmetricKey(pubKeyUsr2, rootPath, userName2, de_key);
	if(ris != PUBCFS_NOERR){
		err = ris;
		goto ret1;
	};

	free(de_key);

	return PUBCFS_NOERR;

	//Errors
	ret1:
		free(de_key);
	ret:
		return err;
}

/** Print all the user int a file (for example stdout)
 *
 * return PUBCFS_ERR_GENERIC on a generic error (for example a parameter is null)
 * 		  PUBCFS_ERR_ENOMEM if there isn't enough memory to allocate the paths
 * 		  PUBCFS_NOERR all ok
 * 		  PUBCFS_ERR_READERROR when the opendir or the readdir make some error
 * */
int pubcfs_listAllUser(FILE* fdOut, char* rootPath){
	char* keysFolderPath;
	DIR *dp;
	struct dirent *de;
	int err;

	if(rootPath == NULL){
		err = PUBCFS_ERR_GENERIC;
		goto ret;
	}

	keysFolderPath = (char*)malloc(strlen(rootPath) + strlen(PUBCFS_KEY_FOLDER) + 2);
	sprintf(keysFolderPath, "%s/%s", rootPath, PUBCFS_KEY_FOLDER);
	if(keysFolderPath == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret;
	}

	dp = opendir(keysFolderPath);
	if(dp == NULL){
		err = PUBCFS_ERR_READERROR;
		goto ret1;
	}

	/* The first call of readdir can't return NULL because all directory have the . and .. entry */
	de = readdir(dp);
	if(de == NULL){
		err = PUBCFS_ERR_READERROR;
		goto ret1;
	}

	do{
		if(strcmp(de->d_name, "..") == 0) continue;
		if(strcmp(de->d_name, ".") == 0) continue;
		fprintf(fdOut, "%s\n", de->d_name);
	}while((de = readdir(dp)) != NULL);

	return PUBCFS_NOERR;

	//Errors
	ret1:
		free(keysFolderPath);
	ret:
		return err;
}

/** Count all the user in the keys folder
 *
 * return PUBCFS_ERR_GENERIC on a generic error (for example a parameter is null)
 * 		  PUBCFS_ERR_ENOMEM if there isn't enough memory to allocate the paths
 * 		  PUBCFS_NOERR all ok
 * 		  PUBCFS_ERR_READERROR when the opendir or the readdir make some error
 * */
int pubcfs_countUsers(char* rootPath, uint* userCount){
	char* keysFolderPath;
	DIR *dp;
	struct dirent *de;
	int err;

	if((rootPath == NULL) || (userCount == NULL)){
		err = PUBCFS_ERR_GENERIC;
		goto ret;
	}

	keysFolderPath = (char*)malloc(strlen(rootPath) + strlen(PUBCFS_KEY_FOLDER) + 2);
	sprintf(keysFolderPath, "%s/%s", rootPath, PUBCFS_KEY_FOLDER);
	if(keysFolderPath == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret;
	}

	dp = opendir(keysFolderPath);
	if(dp == NULL){
		err = PUBCFS_ERR_READERROR;
		goto ret1;
	}

	/* The first call of readdir can't return NULL because all directory have the . and .. entry */
	de = readdir(dp);
	if(de == NULL){
		err = PUBCFS_ERR_READERROR;
		goto ret1;
	}

	*userCount = 0;

	do{
		if(strcmp(de->d_name, "..") == 0) continue;
		if(strcmp(de->d_name, ".") == 0) continue;
		(*userCount)++;
	}while((de = readdir(dp)) != NULL);

	return PUBCFS_NOERR;

	//Errors
	ret1:
		free(keysFolderPath);
	ret:
		return err;
}

/** Delete an user if there is more than two users
 *
 * return PUBCFS_ERR_GENERIC on a generic error (for example a parameter is null)
 * 		  PUBCFS_NOERR if the simmetric key was readed
 * 		  PUBCFS_ERR_NOUSER if the user not exists
 * */
int pubcfs_deleteUser(char* rootPath, char* userName){
	int ris, err;
	uint userCount;
	char* keyFilePath;

	if((rootPath == NULL) || (userName == NULL)){
		err = PUBCFS_ERR_GENERIC;
		goto ret;
	}

	//count the user, because if there is only one user we can't remove it
	ris = pubcfs_countUsers(rootPath, &userCount);
	if(ris != PUBCFS_NOERR){
		err = ris;
		goto ret;
	};
	if(userCount <= 1){
		err = PUBCFS_ERR_ONLYONEUSR;
		goto ret;
	}

	//calculate the path
	keyFilePath = (char*)malloc(strlen(rootPath) + strlen(PUBCFS_KEY_FOLDER) + strlen(userName) + 3);
	if(keyFilePath == NULL){
		err = PUBCFS_ERR_ENOMEM;
		goto ret;
	};
	sprintf(keyFilePath, "%s/%s/%s", rootPath, PUBCFS_KEY_FOLDER, userName);

	//remove the user
	ris = unlink(keyFilePath);
	if(ris < 0){
		switch(errno){
			case ENOENT:
				err = PUBCFS_ERR_NOUSER;
				goto ret;
			default:
				err = PUBCFS_ERR_WRITEERROR;
				goto ret;
		}
	}

	return PUBCFS_NOERR;

	//Errors
	ret:
		return err;
}
