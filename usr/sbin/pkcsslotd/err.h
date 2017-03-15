 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

#ifndef _SLOTD_ERR_H
#define _SLOTD_ERR_H

#ifdef DEV

    #ifndef ASSERT
        #define ASSERT(_expr) _ASSERT((_expr),(__FILE__),(__LINE__))
        #define _ASSERT(_expr, _fname, _line) \
          if (!(_expr)) { \
              ErrLog("****** ****** ***** ***** ***** ***** ***** ***** ***** ****** ******"); \
              ErrLog("****** ASSERTION FAILED '%s'; %s, line %d", (#_expr), (_fname), (_line)); \
              ErrLog("****** ****** ***** ***** ***** ***** ***** ***** ***** ****** ******"); \
              ErrLog("Exiting."); \
              abort(); \
          }
    #endif /* ASSERT */

    #ifndef ASSERT_FUNC
        #define ASSERT_FUNC(_expr, _func) _ASSERT_FUNC((_expr), (_func), (__FILE__), (__LINE__))
        #define _ASSERT_FUNC(_expr, _func, _fname, _line) \
          if (!(_expr)) { \
              ErrLog("****** ****** ***** ***** ***** ***** ***** ***** ***** ****** ******"); \
              ErrLog("****** ASSERTION FAILED '%s'; %s, line %d", (#_expr), (_fname), (_line)); \
              ErrLog("Additional information from '%s':\n", (#_func)); \
	      { _func; } \
              ErrLog("End of additional information from '%s'\n", (#_func) ); \
              ErrLog("****** ****** ***** ***** ***** ***** ***** ***** ***** ****** ******"); \
              ErrLog("Exiting."); \
              abort(); \
           }
    #endif /* ASSERT_FUNC */

#else

    #ifndef ASSERT
      #define ASSERT(_expr)
    #endif /* ASSERT */

    #ifndef ASSERT_FUNC
      #define ASSERT_FUNC(_expr, _func_to_call)
    #endif /* ASSERT_FUNC */

#endif /* DEV */


#define SEV_EXPECTED          0x01
#define SEV_ALLOWED           0x02
#define SEV_ERROR             0x03
#define SEV_FATAL             0x04



typedef struct _ConstInfo {
  unsigned const int       Code;
  unsigned const char      Name[128];
  /* UCHAR      Descrip[256]; */
} ConstInfo, *pConstInfo;

#define CONSTINFO(_X) { (_X), (#_X) }



const unsigned char *ConstName         ( pConstInfo pInfoArray, unsigned int InfoArraySize, unsigned int ConstValue );

#ifdef _DAE_H
  const unsigned char *DAEConst        ( unsigned int Val );
#endif /* _DAE_H */

#ifndef _H_ERRNO
#define _H_ERRNO
#endif

#ifdef _H_ERRNO
  extern const unsigned char *SysConst        ( unsigned int Val );
  #define SysError( _x ) SysConst((_x))
#endif /* _H_ERRNO */

  extern const unsigned char *SignalConst     ( unsigned int Val );

#ifdef _H_ODMI
  const unsigned char *ODMConst        ( unsigned int Val );
#endif /* _H_ODMI */

#ifdef _PKCS11TYPES_H_
  const unsigned char *PkcsReturn      ( unsigned int Val );
  const unsigned char *PkcsFlags       ( unsigned int Val );
  const unsigned char *PkcsMechanism   ( unsigned int Val );
  const unsigned char *PkcsObject      ( unsigned int Val );
  const unsigned char *PkcsKey         ( unsigned int Val );
  const unsigned char *PkcsAttribute   ( unsigned int Val );
#endif /* _PKCS11TYPES_H_ */

const unsigned char *ResponseSeverity( unsigned int Val );


#endif /* _SLOTD_ERR_H */
