/**
 * @file mConfig.h
 * @brief simple configuration reader
*/
/*
 * Copyright 2010 Miro Mannino <miro.mannino@gmail.com>
 * This work is licensed under the Creative Commons Attribution 2.5
 * Italy License. To view a copy of this license, visit
 * http://creativecommons.org/licenses/by/2.5/it/ or send a letter
 * to Creative Commons, 171 Second Street, Suite 300, San Francisco,
 * California, 94105, USA.
 * 
 */ 

#ifndef MCONFIG_H
	
	#define MCONFIG_H
	
	#include <stdlib.h>
	#include <stdio.h>
	#include <string.h>
	#include <ctype.h>
 
	#define MAXLINE_BUF 256

	#define MCONFIG_NOERR 0
	#define MCONFIG_ENOMEM -1
	#define MCONFIG_EFILE -2
	#define MCONFIG_EPARAM -3
	#define MCONFIG_EADD -3

	typedef struct str_mConfigEntry{
		char* name;
		char* value;
		struct str_mConfigEntry* next;
		struct str_mConfigEntry* prec;
	} mConfigEntry_t;
	
	typedef mConfigEntry_t mConfig_t;
	
	mConfig_t* mConfig_new();
	void mConfig_dispose(mConfig_t* l);
	
	int mConfig_add(mConfig_t* l, char* name, char* value);
	int mConfig_remove(mConfig_t* l, char* name);
	
	char* mConfig_readValue(mConfig_t* l, char* name);
	
	int mConfig_readConfig(mConfig_t** nl, char* filename);
	int mConfig_saveConfig(mConfig_t* l, char* filename);

#endif
