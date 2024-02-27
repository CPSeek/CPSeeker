#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-08-11 08:45:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-08-11 09:45:48

MALLOC_NAME             = "malloc"                      # void *malloc(size_t size)
REALLOC_NAME            = "realloc"                     # void *realloc (void *ptr, size_t newsize)
CALLOC_NAME             = "calloc"                      # void *calloc (size_t count, size_t eltsize)
VALLOC_NAME             = "valloc"                      # void *valloc(size_t size);
PVALLOC_NAME            = "pvalloc"                     # void *pvalloc(size_t size);
FREE_NAME               = "free"                        # void free(void* ptr);
ALIGNED_ALLOC_NAME      = "aligned_alloc"               # void *aligned_alloc (size_t alignment, size_t size);
MEMALIGN_NAME           = "memalign"                    # void *memalign(size_t alignment, size_t size);



PRINTF_NAME             = "printf"                      # int printf(const char *format, ...);
FPRINTF_NAME            = "fprintf"                     # int fprintf(FILE * stream, const char * format, ...);
VPRINTF_NAME            = "vprintf"                     # int vprintf( char *format, va_list arg_ptr );
VFPRINTF_NAME           = "vfprintf"                    # int vfprintf( FILE *stream, const char *format, va_list arg_ptr );
VSPRINTF_NAME           = "vsprintf"                    # int vsprintf( char *buffer, char *format, va_list arg_ptr );


SPRINTF_NAME            = "sprintf"                     # int sprintf(char *str, const  char *format, ...);
SNPRINTF_NAME           = "snprintf"                    # int snprintf(char *str, size_t size, const char *format, ...);

SCANF_NAME              = "scanf"                       # int scanf(const char *format, ...);
FSCANF_NAME             = "fscanf"                      # int fscanf(FILE *stream, const char *format, ...);
SSCANF_NAME             = "sscanf"                      # int sscanf(const char *str, const char* format, ...);
PUTS_NAME               = "puts"                        # int puts(const char *s);
PUTC_NAME               = "putc"                        # int putc( int ch, FILE *stream );
PUTCHAR_NAME            = "putchar"                     # int putchar(int char);

FOPEN_NAME              = "fopen"                       # FIFE *fopen(const char *path, const char *mode);
FREOPEN_NAME            = "freopen"                     # FILE *freopen( const char *fname, const char *mode, FILE *stream );
FCLOSE_NAME             = "fclose"                      # int fclose(FIFE *stream);
FGETC_NAME              = "fgetc"                       # int fgetc(FIFE *stream);
FPUTC_NAME              = "fputc"                       # int fputc(int c, FIFE *stream);
FGETS_NAME              = "fgets"                       # char *fgets(char *s, int size, FIFE *stream);
FPUTS_NAME              = "fputs"                       # int fputs(const char *s, FIFE *stream);
FREAD_NAME              = "fread"                       # size_t fread(void *ptr, size_t size, size_t nmemb, FIFE *stream);
FWRITE_NAME             = "fwrite"                      # size_t fwrite(const void *ptr, size_t size, size_t nmemb, FIFE *stream);
FSEEK_NAME              = "fseek"                       # int fseek(FIFE *stream, long offset, int whence);
FTELL_NAME              = "ftell"                       # long ftell(FIFE *stream);
REWIND_NAME             = "rewind"                      # void rewind(FIFE *stream);
FFLUSH_NAME             = "fflush"                      # int fflush(FIFE *stream);
FGETPOS_NAME            = "fgetpos"                     # int fgetpos( FILE *stream, fpos_t *position );
FSETPOS_NAME            = "fsetpos"                     # int fsetpos( FILE *stream, const fpos_t *pos );
REMOVE_NAME             = "remove"                      # int remove( const char *fname );
RENAME_NAME             = "rename"                      # int rename( const char *oldfname, const char *newfname );

SETBUF_NAME             = "setbuf"                      # void setbuf( FILE *stream, char *buffer );
SETVBUF_NAME            = "setvbuf"                     # int setvbuf( FILE *stream, char *buffer, int mode, size_t size );
TEMPFILE_NAME           = "tmpfile"                     # FILE *tmpfile( void );
TMPNAM_NAME             = "tmpnam"                      # char *tmpnam( char *name );
UNGETC_NAME             = "ungetc"                      #  int ungetc( int ch, FILE *stream );


GETC_NAME               = "getc"                        # int getc( FILE *stream );
GETCHAR_NAME            = "getchar"                     # int getchar( void );
GETS_NAME               = "gets"                        # char *gets(char *str);


CLEARERR_NAME           = "clearerr"                    # void clearerr( FILE *stream );
FERROR_NAME             = "ferror"                      # int ferror( FILE *stream );
PERROR_NAME             = "perror"                      # void perror( const char *str );
FEOF_NAME               = "feof"                        # int feof( FILE *stream );


STRCPY_NAME             = "strcpy"                      # char* strcpy()
STRNCPY_NAME            = "strncpy"                     # char* strncpy()
MEMCPY_NAME             = "memcpy"                      # char* memcpy()

STRLEN_NAME             = "strlen"                      # int strlen()
TOUPPER_NAME            = "toupper"                     # toupper()
MEMSET_NAME             = "memset"                      # memset()
STRSTR_NAME             = "strstr"                      # strstr()
STRSEP_NAME             = "strsep"                      # strsep()
STRCMP_NAME             = "strcmp"                      # strcmp()
STRNCMP_NAME            = "strncmp"                     # strncmp()
STRSPN_NAME             = "strspn"                      # strspn()
STRPBRK_NAME            = "strpbrk"                     # strpbrk()
