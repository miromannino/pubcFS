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
 * @file pubcfs-config
 * @brief Configure pubcfs fs
 */

#include <main.h>

int pubcfsConfig_main_usage(int argc, char** argv){
	fprintf(stderr,
		"\nusage: %s command [command options]\n\n"
		"Commands: \n"
		"\n"
		"help:\n"
		"  description: show this help\n"
		"\n"
		"init:\n"
		"  description: inizialize a new folder\n"
		"  use: %s init rootPath user publicKeyPath\n"
		"  options: \n"
		"    rootPath         the path of the crypted folder\n"
		"    user             user name to add into filesystem's users list\n"
		"    publicKeyPath    the user related public key\n"
		"\n"
		"add:\n"
		"  description: add a new user to the folder\n"
		"  use: %s add rootPath user1 privateKeyPath1 user2 publicKeyPath2\n"
		"  options: \n"
		"    rootPath         the path of the crypted folder\n"
		"    user1            user name that exists in the filesystem's users list\n"
		"    privateKeyPath1  the user1 related private key\n"
		"    user2            user name of the user that we want to add\n"
		"    publicKeyPath2   the user2 related public key\n"
		"\n"
		"delete:\n"
		"  description: delete an user if there is more than one user\n"
		"  use: %s add rootPath user\n"
		"  options: \n"
		"    rootPath         the path of the crypted folder\n"
		"    user             user name that we want to delete\n"
		"\n"
		"list:\n"
		"  description: list all the user\n"
		"  use: %s add rootPath\n"
		"  options: \n"
		"    rootPath         the path of the crypted folder\n"
		"\n"
		, argv[0], argv[0], argv[0], argv[0], argv[0]
	);

	return true;
}

int pubcfsConfig_main_init(char** argv){
	int ris;
	char *rootPath;
	char *pubKeyPath;
	char *userName;
	RSA *pubKey;

	//Get the root path (the encrypted folder)
	rootPath = realpath(argv[2], NULL);
	if (rootPath == NULL){
		fprintf(stderr, "Error: rootPath is not a valid path\n");
		return false;
	}

	//Get the user name that we want to make the first user
	userName = strdup(argv[3]);

	//Get public key path of the user and read it
	pubKeyPath = realpath(argv[4], NULL);
	if (pubKeyPath == NULL){
		fprintf(stderr, "Error: pubKeyPath is not a valid path\n");
		return false;
	}
	pubKey = pubcfs_readPublicKey(pubKeyPath);
	if (pubKey == NULL){
		fprintf(stderr, "Error: can't load public key\n");
		return false;
	}

	printf("initializing the folder\n");
	ris = pubcfs_initPubcfsFolder(pubKey, rootPath, userName);
	switch(ris){
		case PUBCFS_ERR_ENOMEM:
			fprintf(stderr, "Error: no enough memory for the operation\n");
			return false;
		case PUBCFS_ERR_NOADDUSER:
			fprintf(stderr, "Error: can't add the user, write denied or user exist\n");
			return false;
		case PUBCFS_ERR_WRITEERROR:
			fprintf(stderr, "Error: can't write the key to the user, write error\n");
			return false;
		case PUBCFS_ERR_ENCRYPTFAIL:
			fprintf(stderr, "Error: can't encrypt the simmetric key with this public key\n");
			return false;
		case PUBCFS_NOERR:
			break;
		default:
			printf("Error: generic error, cannot initialize the folder\n");
			return false;
	}

	printf("the folder has been initialized\n");
	return true;
}

int pubcfsConfig_main_add(char** argv){
	int ris;
	char *rootPath;
	char *privKeyUsr1Path, *pubKeyUsr2Path;
	char *userName1, *userName2;
	RSA *privKeyUsr1, *pubKeyUsr2;

	//Get the root path (the encrypted folder)
	rootPath = realpath(argv[2], NULL);
	if (rootPath == NULL){
		fprintf(stderr, "Error: rootPath is not a valid path\n");
		return false;
	}

	//Get the name of the two users
	userName1 = strdup(argv[3]);
	userName2 = strdup(argv[5]);

	//Get private key path of the first user and read it
	privKeyUsr1Path = realpath(argv[4], NULL);
	if (privKeyUsr1Path == NULL){
		fprintf(stderr, "Error: privKeyUsr1Path is not a valid path\n");
		return false;
	}
	privKeyUsr1 = pubcfs_readPrivateKey(privKeyUsr1Path);
	if (privKeyUsr1 == NULL){
		fprintf(stderr, "Error: can't load private key of the first user\n");
		return false;
	}

	//Get public key path of the second user
	pubKeyUsr2Path = realpath(argv[6], NULL);
	if (pubKeyUsr2Path == NULL){
		fprintf(stderr, "Error: pubKeyUsr2Path is not a valid path\n");
		return false;
	}
	pubKeyUsr2 = pubcfs_readPublicKey(pubKeyUsr2Path);
	if (pubKeyUsr2 == NULL){
		fprintf(stderr, "Error: can't load public key of the second user\n");
		return false;
	}

	ris = pubcfs_addUser(rootPath, userName1, userName2, privKeyUsr1, pubKeyUsr2);
	switch(ris){
		case PUBCFS_ERR_ENOMEM:
			fprintf(stderr, "Error: no enough memory for the operation\n");
			return false;
		case PUBCFS_ERR_NOADDUSER:
			fprintf(stderr, "Error: can't add the user, write denied or user exist\n");
			return false;
		case PUBCFS_ERR_NOUSER:
			fprintf(stderr, "Error: can't find the user\n");
			return false;
		case PUBCFS_ERR_WRITEERROR:
			fprintf(stderr, "Error: can't write the key to the second user, write error\n");
			return false;
		case PUBCFS_ERR_READERROR:
			fprintf(stderr, "Error: can't read the key from the first user, read error\n");
			return false;
		case PUBCFS_ERR_ENCRYPTFAIL:
			fprintf(stderr, "Error: can't encrypt the simmetric key with this public key\n");
			return false;
		case PUBCFS_ERR_DECRYPTFAIL:
			fprintf(stderr, "Error: can't decrypt the simmetric key with this private key\n");
			return false;
		case PUBCFS_NOERR:
			break;
		default:
			printf("Error: generic error, cannot add the user\n");
			return false;
	}

	printf("the user has been added\n");
	return true;
}

int pubcfsConfig_main_delete(char** argv){
	int ris;
	char *rootPath;
	char *userName;

	//Get the root path (the encrypted folder)
	rootPath = realpath(argv[2], NULL);
	if (rootPath == NULL){
		fprintf(stderr, "Error: rootPath is not a valid path\n");
		return false;
	}

	//Get the name of the two users
	userName = strdup(argv[3]);

	printf("deleting the user\n");
	ris = pubcfs_deleteUser(rootPath, userName);
	switch(ris){
		case PUBCFS_ERR_ENOMEM:
			fprintf(stderr, "Error: no enough memory for the operation\n");
			return false;
		case PUBCFS_ERR_NOUSER:
			fprintf(stderr, "Error: can't find the user\n");
			return false;
		case PUBCFS_ERR_WRITEERROR:
			fprintf(stderr, "Error: can't remove the user\n");
			return false;
		case PUBCFS_ERR_ONLYONEUSR:
			fprintf(stderr, "Error: only one user, you cannot remove it because in this way you will lost all data\n");
			return false;
		case PUBCFS_NOERR:
			break;
		default:
			printf("Error: generic error, cannot delete the user\n");
			return false;
	}

	return true;
}

int pubcfsConfig_main_list(char** argv){
	int ris;
	char *rootPath;

	//Get the root path (the encrypted folder)
	rootPath = realpath(argv[2], NULL);
	if (rootPath == NULL){
		fprintf(stderr, "Error: rootPath is not a valid path\n");
		return false;
	}

	ris = pubcfs_listAllUser(stdout, rootPath);
	switch(ris){
		case PUBCFS_ERR_ENOMEM:
			fprintf(stderr, "Error: no enough memory for the operation\n");
			return false;
		case PUBCFS_ERR_READERROR:
			fprintf(stderr, "Error: can't read the directory entries\n");
			return false;
		case PUBCFS_NOERR:
			break;
		default:
			printf("Error: generic error, cannot list the users\n");
			return false;
	}

	return true;
}

int main(int argc, char** argv)
{

	int ret;

	if(argc <= 1){
		pubcfsConfig_main_usage(argc, argv);
		exit(EXIT_SUCCESS);
	}

	pubcfs_initRSAModule();

	/*option parsing-------------*/

	//init command
	if ((strcmp(argv[1], "init") == 0) && argc == 5){
		ret = pubcfsConfig_main_init(argv);

	//add commmand
	}else if ((strcmp(argv[1], "add") == 0) && argc == 7){
		//accetta utente1 utente2 keyPriv1 keyPub2
		ret = pubcfsConfig_main_add(argv);

	//delete command
	}else if ((strcmp(argv[1], "delete") == 0) && argc == 4){
		//accetta utente1
		ret = pubcfsConfig_main_delete(argv);

	//list command
	}else if ((strcmp(argv[1], "list") == 0) && argc == 3){
		ret = pubcfsConfig_main_list(argv);

	//help command
	}else if ((strcmp(argv[1], "help") == 0) && argc == 2){
		ret = pubcfsConfig_main_usage(argc, argv);

	//default, show the help
	}else{
		ret = pubcfsConfig_main_usage(argc, argv);
	}

	exit(ret ? EXIT_SUCCESS : EXIT_FAILURE);

}
