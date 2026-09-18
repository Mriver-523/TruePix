// simple interface to MIRACL for ecc
// (C) 2017 Riad S. Wahby <rsw@cs.nyu.edu>
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miracl.h"

// macros
#define IOERR 0
#define RTERR 1
#define VALERR 2
#define TYPERR 3
#define SYSERR 4
#define ENVERR 5

#define pymr_ERROR(eint, mstr) do { \
        error_string = mstr;        \
    } while (0);

#define pymr_CHECK_INIT do {        \
        if (mip == NULL) {          \
            pymr_ERROR(ENVERR, "Please call set_curve() first!"); \
        return NULL;                \
        }                           \
    } while (0);
// generally MULTN_MAX should be 7-10ish. Bigger and precomp/memory costs blow up.
#define MULTN_MAX 8
#define STRAUS_MAX 100

// interface functions
void pymr_clear(void);
char **pymr_set_curve(char *filename, int nelms, bool check_points);
char **pymr_pow_gh(char *varg, char *varh);
char **pymr_pow_g(char *varg);
char **pymr_pow_h(char *varh);
char **pymr_maul(char **bval, char *xval);
char **pymr_exp_mul(char **bmvals, char *xval);
char **pymr_exp_powh(char **bval, char *xval, char *yval);
char **pymr_exp(char **bval, char *xval);
char **pymr_div(char **bcvals);
char **pymr_mul(char **bcvals);
char **pymr_sqr(char **bval);
char **pymr_multiexp(char **blst, char **xlst, unsigned num);
char **pymr_multimul(char **blst, unsigned lb);
char **pymr_pow_gih(char **lst, unsigned lx, char *varh, unsigned nstart);
char **pymr_pow_gi(char **lst, unsigned lx, unsigned nstart, int nskip);
char **pymr_decompress(char *xval);
char *pymr_compress(char **bval);
char *pymr_get_error(void);
int *pymr_get_sizes(void);

// conversion functions
static bool MRBigList_FromList(big *s, char **lst, unsigned len);
static char **Tuple_FromEPoint(epoint *p);
static char **Tuple_FromTuple(char **t);
static bool EPoint_FromTuple(epoint *p, char **t);
static void MRBig_FromString(big b, char *c);

// misc
static bool multiexp_help(epoint **points, big *scalars, int num);
static bool multiexp_straus(epoint **points, big *scalars, int num);
static bool multiexp_BDLO12(epoint **points, big *scalars, int num);

// points and other data
static epoint *g=NULL, *h=NULL, *p_tmp1=NULL, *p_tmp2=NULL;
static big q_ord=NULL;
static big p_fld=NULL;
static big b_tmp1=NULL;
static big b_tmp2=NULL;
static big b_hbit=NULL;
static int msbit=0;
static miracl *mip=NULL;
static int nbases=0;
static epoint **gi=NULL;
static char *gi_mem=NULL;
static char iofst[MR_DEFAULT_BUFFER_SIZE], iosnd[MR_DEFAULT_BUFFER_SIZE];
static char *iotup[2] = {iofst, iosnd};
static char *error_string;
static int data_sizes[3] = {0,};
