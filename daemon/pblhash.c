/*
 pblhash.c - hash table implementation

 Copyright (C) 2002    Peter Graf

   This file is part of PBL - The Program Base Library.
   PBL is free software.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   For more information on the Program Base Library or Peter Graf,
   please see: http://mission.base.com/.

    $Log: pblhash.c,v $
    Revision 1.2  2002/09/12 20:46:30  peter
    added the isam file handling to the library

    Revision 1.1  2002/09/05 13:45:01  peter
    Initial revision


*/

/*
 * make sure "strings <exe> | grep Id | sort -u" shows the source file versions
 */
static char* rcsid = "$Id: pblhash.c,v 1.2 2002/09/12 20:46:30 peter Exp $";
static int   rcsid_fct() { return( rcsid ? 0 : rcsid_fct() ); }

#include <stdio.h>
#include <memory.h>
#include <malloc.h>

#include "pbl.h"

/*****************************************************************************/
/* #defines                                                                  */
/*****************************************************************************/
#define PBL_HASHTABLE_SIZE      1019

/*****************************************************************************/
/* typedefs                                                                  */
/*****************************************************************************/

typedef struct pbl_hashitem_s
{
    void                  * key;
    size_t                  keylen;

    void                  * data;

    struct pbl_hashitem_s * next;
    struct pbl_hashitem_s * prev;

    struct pbl_hashitem_s * bucketnext;
    struct pbl_hashitem_s * bucketprev;

} pbl_hashitem_t;

typedef struct pbl_hashbucket_s
{
    pbl_hashitem_t * head;
    pbl_hashitem_t * tail;

} pbl_hashbucket_t;

struct pbl_hashtable_s
{
    char             * magic;
    int                currentdeleted;
    pbl_hashitem_t   * head;
    pbl_hashitem_t   * tail;
    pbl_hashitem_t   * current;
    pbl_hashbucket_t * buckets;

};
typedef struct pbl_hashtable_s pbl_hashtable_t;
    
/*****************************************************************************/
/* globals                                                                   */
/*****************************************************************************/

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

static int hash( const unsigned char * key, size_t keylen )
{
    int ret = 104729;

    for( ; keylen-- > 0; key++ )
    {
        if( *key )
        {
            ret *= *key + keylen;
            ret %= PBL_HASHTABLE_SIZE;
        }
    }

    return( ret % PBL_HASHTABLE_SIZE );
}

/**
 * create a new hash table
 *
 * @return pblHashTable_t * retptr != NULL: pointer to new hash table
 * @return pblHashTable_t * retptr == NULL: OUT OF MEMORY
 */
pblHashTable_t * pblHtCreate( void )
{
    pbl_hashtable_t * ht;

    ht = pbl_malloc0( "pblHtCreate hashtable", sizeof( pbl_hashtable_t ) );
    if( !ht )
    {
        return( 0 );
    }

    ht->buckets = pbl_malloc0( "pblHtCreate buckets",
                               sizeof( pbl_hashbucket_t ) * PBL_HASHTABLE_SIZE);
    if( !ht->buckets )
    {
        PBL_FREE( ht );
        return( 0 );
    }

    /*
     * set the magic marker of the hashtable
     */
    ht->magic = rcsid;

    return( ( pblHashTable_t * )ht );
}

/**
 * insert a key / data pair into a hash table
 *
 * only the pointer to the data is stored in the hash table
 * no space is malloced for the data!
 *
 * @return  int ret == 0: ok
 * @return  int ret == -1: an error, see pbl_errno:
 * @return    PBL_ERROR_EXISTS:        an item with the same key already exists
 * @return    PBL_ERROR_OUT_OF_MEMORY: out of memory
 */

int pblHtInsert(
pblHashTable_t          * h,      /** hash table to insert to             */
void                    * key,    /** key to insert                       */
size_t                    keylen, /** length of that key                  */
void                    * dataptr /** dataptr to insert                   */
)
{
    pbl_hashtable_t  * ht = ( pbl_hashtable_t * )h;
    pbl_hashbucket_t * bucket = 0;
    pbl_hashitem_t   * item = 0;

    int                hashval = hash( key, keylen );
    
    bucket = ht->buckets + hashval;

    if( keylen < (size_t)1 )
    {
        /*
         * the length of the key can not be smaller than 1
         */
        pbl_errno = PBL_ERROR_EXISTS;
        return( -1 );
    }

    for( item = bucket->head; item; item = item->bucketnext )
    {
        if(( item->keylen == keylen ) && !memcmp( item->key, key, keylen ))
        {
            snprintf( pbl_errstr, PBL_ERRSTR_LEN,
                      "insert of duplicate item in hashtable\n" );
            pbl_errno = PBL_ERROR_EXISTS;
            return( -1 );
        }
    }

    item = pbl_malloc0( "pblHtInsert hashitem", sizeof( pbl_hashitem_t ) );
    if( !item )
    {
        return( -1 );
    }

    item->key = pbl_memdup( "pblHtInsert item->key", key, keylen );
    if( !item->key )
    {
        PBL_FREE( item );
        return( -1 );
    }
    item->keylen = keylen;
    item->data = dataptr;

    /*
     * link the item
     */
    PBL_LIST_APPEND( bucket->head, bucket->tail, item, bucketnext, bucketprev );
    PBL_LIST_APPEND( ht->head, ht->tail, item, next, prev );

    ht->current = item;
    return( 0 );
}












/**
 * search for a key in a hash table
 *
 * @return void * retptr != NULL: pointer to data of item found
 * @return void * retptr == NULL: no item found with the given key
 * @return     PBL_ERROR_NOT_FOUND:
 */

void * pblHtLookup(
pblHashTable_t              * h,      /** hash table to search in          */
void                        * key,    /** key to search                    */
size_t                        keylen  /** length of that key               */
)
{
    pbl_hashtable_t  * ht = ( pbl_hashtable_t * )h;
    pbl_hashbucket_t * bucket = 0;
    pbl_hashitem_t   * item = 0;

    int                hashval = hash( key, keylen );
    
    bucket = ht->buckets + hashval;

    for( item = bucket->head; item; item = item->bucketnext )
    {
        if(( item->keylen == keylen ) && !memcmp( item->key, key, keylen ))
        {
            ht->current = item;
            ht->currentdeleted = 0;
            return( item->data );
        }
    }
            
    pbl_errno = PBL_ERROR_NOT_FOUND;

    return( 0 );
}




/* returns the current record's key */
/* bruno 10-07-2004 */
char *pblHtCurrentKey(pblHashTable_t * h)
{
  
  pbl_hashtable_t  * ht = ( pbl_hashtable_t * )h;
  char *tmpkey;

  /*   strncpy(d, s+a, b-a);  */

  if( ht->current ) {
    tmpkey = (char *)malloc(ht->current->keylen+2);
    strncpy(tmpkey, ht->current->key, ht->current->keylen);
    // create a valid null terminated string
    tmpkey[ht->current->keylen]='\0';
    return tmpkey;
  }
  
  pbl_errno = PBL_ERROR_NOT_FOUND;
  return NULL;
}






/**
 * get data of first key in hash table
 *
 * This call and \Ref{pblHtNext} can be used in order to loop through all items
 * stored in a hash table.
 *
 * <PRE>
   Example:

   for( data = pblHtFirst( h ); data; data = pblHtNext( h ))
   {
       do something with the data pointer
   }
   </PRE>

 * @return void * retptr != NULL: pointer to data of first item
 * @return void * retptr == NULL: the hash table is empty
 * @return     PBL_ERROR_NOT_FOUND:
 */

void * pblHtFirst(
pblHashTable_t              * h       /** hash table to look in            */
)
{
    pbl_hashtable_t  * ht = ( pbl_hashtable_t * )h;
    pbl_hashitem_t   * item = 0;

    item = ht->head;
    if( item )
    {
        ht->current = item;
        ht->currentdeleted = 0;
        return( item->data );
    }

    pbl_errno = PBL_ERROR_NOT_FOUND;
    return( 0 );
}

/**
 * get data of next key in hash table
 *
 * This call and \Ref{pblHtFirst} can be used in order to loop through all items
 * stored in a hash table.
 *
 * <PRE>
   Example:

   for( data = pblHtFirst( h ); data; data = pblHtNext( h ))
   {
       do something with the data pointer
   }
   </PRE>

 * @return void * retptr != NULL: pointer to data of next item
 * @return void * retptr == NULL: there is no next item in the hash table
 * @return     PBL_ERROR_NOT_FOUND: 
 */

void * pblHtNext(
pblHashTable_t              * h       /** hash table to look in            */
)
{
    pbl_hashtable_t  * ht = ( pbl_hashtable_t * )h;
    pbl_hashitem_t   * item = 0;

    if( ht->current )
    {
        if( ht->currentdeleted )
        {
            item = ht->current;
        }
        else
        {
            item = ht->current->next;
        }
        ht->currentdeleted = 0;
    }
    if( item )
    {
        ht->current = item;
        return( item->data );
    }

    pbl_errno = PBL_ERROR_NOT_FOUND;
    return( 0 );
}

/**
 * get data of current key in hash table
 *
 * @return void * retptr != NULL: pointer to data of current item
 * @return void * retptr == NULL: there is no current item in the hash table
 * @return     PBL_ERROR_NOT_FOUND:
 */

void * pblHtCurrent(
pblHashTable_t              * h       /** hash table to look in            */
)
{
    pbl_hashtable_t  * ht = ( pbl_hashtable_t * )h;

    if( ht->current )
    {
        return( ht->current->data );
    }

    pbl_errno = PBL_ERROR_NOT_FOUND;
    return( 0 );
}

/**
 * remove an item from the hash table
 *
 * parameters key and keylen are optional, if they are not given
 * the current record is deleted
 *
 * if the current record is removed the pointer to the current record
 * is moved to the next record.
 *
 * <PRE>
   Example:

   for( data = pblHtFirst( h ); data; data = pblHtRemove( h, 0, 0 ))
   {
       this loop removes all items from a hash table
   }
   </PRE>
 *
 * if the current record is moved by this function the next call to
 * \Ref{pblHtNext} will return the data of the then current record.
 * Therefore the following code does what is expected:
 * It visits all items of the hash table and removes the expired ones.
 *
 * <PRE>
   for( data = pblHtFirst( h ); data; data = pblHtNext( h ))
   {
       if( needs to be deleted( data ))
       {
           pblHtRemove( h, 0, 0 );
       }
   }
   </PRE>
 
 * @return int ret == 0: ok
 * @return int ret == -1: an error, see pbl_errno:
 * @return     PBL_ERROR_NOT_FOUND: the current item is not positioned
 * @return                          or there is no item with the given key
 */

int pblHtRemove(
pblHashTable_t            * h,     /** hash table to remove from           */
void                      * key,   /** OPT: key to remove                  */
size_t                      keylen /** OPT: length of that key             */
)
{
    pbl_hashtable_t  * ht = ( pbl_hashtable_t * )h;
    pbl_hashbucket_t * bucket = 0;
    pbl_hashitem_t   * item = 0;

    int                hashval = 0;

    if( keylen && key )
    {
        hashval = hash( key, keylen );
        bucket = ht->buckets + hashval;

        for( item = bucket->head; item; item = item->bucketnext )
        {
            if(( item->keylen == keylen ) && !memcmp( item->key, key, keylen ))
            {
                break;
            }
        }
    }
    else
    {
        item = ht->current;

        if( item )
        {
            hashval = hash( item->key, item->keylen );
            bucket = ht->buckets + hashval;
        }
    }

    if( item )
    {
        if( item == ht->current )
        {
            ht->currentdeleted = 1;
            ht->current = item->next;
        }

        /*
         * unlink the item
         */
        PBL_LIST_UNLINK( bucket->head, bucket->tail, item,
                         bucketnext, bucketprev );
        PBL_LIST_UNLINK( ht->head, ht->tail, item, next, prev );

        PBL_FREE( item->key );
        PBL_FREE( item );
        return( 0 );
    }

    pbl_errno = PBL_ERROR_NOT_FOUND;
    return( -1 );
}

/**
 * delete a hash table
 *
 * the hash table has to be empty!
 *
 * @return int ret == 0: ok
 * @return int ret == -1: an error, see pbl_errno:
 * @return     PBL_ERROR_EXISTS: the hash table is not empty
 */

int pblHtDelete(
pblHashTable_t * h        /** hash table to delete */
)
{
    pbl_hashtable_t  * ht = ( pbl_hashtable_t * )h;

    if( ht->head )
    {
        pbl_errno = PBL_ERROR_EXISTS;
        return( -1 );
    }

    PBL_FREE( ht->buckets );
    PBL_FREE( ht );

    return( 0 );
}

