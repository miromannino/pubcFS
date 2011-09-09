/**
 * @file mConfig.c
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

#include <mConfig.h>

/** Trim a string
 *
 * @param in the string to trim
 *
 * @return the timmed string, it must be deallocate using free function
 */
char* mConfig_str_trim(char* in){
	char* start;
	char* end;
	size_t newSize;
	char* out;

	if(in == NULL) return NULL;

	start = in;

	// remove the starting spaces
	while(isspace(*start)) start++;

	//check if there is only spaces
	if(*start == '\0') return NULL;

	// remove the ending spaces
	end = start + strlen(start) - 1;
	while(isspace(*end)) end--;

	newSize = end - start + 1;
	out = malloc(newSize + 1);
	if(out == NULL) return NULL;

  	memcpy(out, start, newSize);
	out[newSize + 1] = '\0';

	return out;
}

/** Create a new empty configuration
 *
 *  @return a pointer to a mConfig_t struct or NULL if there is not enough memory
 */
mConfig_t* mConfig_new(){
    mConfig_t* l;

	l = (mConfig_t*)malloc(sizeof(mConfig_t));
    if (l == NULL) return NULL;

    l->name = NULL;
	l->value = NULL;
    l->next = l;
    l->prec = l;

    return l;
}

/** Dispose a configuration
 *
 * @param l the configuration that was created by the new function or the readConfig function
 */
void mConfig_dispose(mConfig_t* l){
    mConfigEntry_t* curr;
    mConfigEntry_t* lNext;

	if(l == NULL) return;

	curr = l->next;
    while(curr != l){
        lNext = curr->next;
		if (curr->name != NULL) free(curr->name);
		if (curr->value != NULL) free(curr->value);
        free(curr);
        curr = lNext;
    }
    free(l);
}

/** Add a new entry in the configuration
 *
 * @param name the entry name
 * @param value the value associated to the name
 *
 * @return CONFIG_NOERR if ok, MCONFIG_ENOMEM if there is not enough memory
 */
int mConfig_add(mConfig_t* l, char* name, char* value){
	mConfigEntry_t* c;

	if (name == NULL || value == NULL) return -1;

    c = (mConfigEntry_t*)malloc(sizeof(mConfigEntry_t));
    if (c == NULL) return MCONFIG_ENOMEM;

    c->name = strdup(name);
	c->value = strdup(value);
    c->next = l;
    c->prec = l->prec;
    l->prec->next = c;
    l->prec = c;

    return MCONFIG_NOERR;
}

/** remove an entry from the configuration
 * 
 * @param l the pointer to the configuration
 * @param name the name of te entry
 *
 * @return the number of removed entry
 */
int mConfig_remove(mConfig_t* l, char* name){
	mConfigEntry_t* curr;
	int removed;

	if(l == NULL || name == NULL) return 0;

	removed = 0;
	curr = l->next;
	while(curr != l){
		if(strcmp(curr->name, name) == 0){
			curr->next->prec = curr->prec;
			curr->prec->next = curr->next;
			free(curr->name);
			free(curr->value);
			free(curr);
			removed++;
		}
		curr = curr->next;
	}

	return removed;
}

/** Read a value from the configuration
 *
 * @param l the pointer to a configuration
 * @param name the name of the entry to read
 *
 * @return the value of the entry, if there is more than one entry with the same name only the first
 * is returned.
 */
char* mConfig_readValue(mConfig_t* l, char* name){
	mConfigEntry_t* curr;

	if(name == NULL) return NULL;

	curr = l->next;
    while(curr != l){
		if(strcmp(curr->name, name) == 0)
			return strdup(curr->value);
		curr = curr->next;
    }

	return NULL;
}

/** Read the configuration from a file
 * 
 * the configuration file is like this:
 * 
 *	name1 = value1
 *	name2 = value2
 *	name3 = value3
 *	...
 *
 * there is no checks in case of multiple values with the same entry name
 * the line with a bad format will be skip
 * 
 * @param nl is a pointer to a mConfig_t pointer that will point to the configuration
 * @param filename is the path to the configuration file
 * 
 * @return CONFIG_NOERR if there is no errors or another error if there is some problems
 *
 */
int mConfig_readConfig(mConfig_t** nl, char* filename){
	FILE* fp;
	char* strtok_ctx;
	char* buff;
	char *token, *value, *name;
	mConfig_t* l;
	int err;

	if(filename == NULL){
		err = MCONFIG_EPARAM;
		goto err0;
	}

	buff = malloc(MAXLINE_BUF);
	if(buff == NULL){
		err = MCONFIG_ENOMEM;
		goto err0;
	}

	fp = fopen(filename, "r");
	if(fp == NULL){
		err = MCONFIG_EFILE;
		goto err1;
	}
	
	l = mConfig_new();
	if(l == NULL) goto err2;
	
	while(fgets(buff, MAXLINE_BUF, fp) != NULL){
		token = strtok_r(buff, "=", &strtok_ctx);
		name = mConfig_str_trim(token);
		if(name != NULL){
			token = strtok_r(NULL, "\n", &strtok_ctx);
			value = mConfig_str_trim(token);
			if(value != NULL){
				if(mConfig_add(l, name, value) == -1){
					free(name);
					free(value);
					err = MCONFIG_EADD;
					goto err3;
				}
			}else{
				free(name);
			}
		}
	}
	
	fclose(fp);
	free(buff);

	*nl = l;
	return MCONFIG_NOERR;

err3:
	mConfig_dispose(l);
err2:
	fclose(fp);
err1:
	free(buff);
err0:
	*nl = NULL;
	return err;
}

/** Save the configuration to a file
 *
 * @param l the pointer to a configuration
 * @param filename the path to the configuration
 *
 * @return CONFIG_NOERR if there is no errors or another error if there is some problems
 */
int mConfig_saveConfig(mConfig_t* l, char* filename){
	FILE* fp;
	mConfigEntry_t* curr;

	if(filename == NULL || l == NULL){
		return MCONFIG_EPARAM;
	}

	fp = fopen(filename, "w");
	if(fp == NULL){
		return MCONFIG_EFILE;
	}

	curr = l->next;
    while(curr != l){
		fprintf(fp, "%s = %s\n", curr->name, curr->value);
		curr = curr->next;
    }

	fclose(fp);
	return MCONFIG_NOERR;
}
