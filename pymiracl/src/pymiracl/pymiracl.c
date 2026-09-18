// simple interface to MIRACL for ecc
// (C) 2017 Riad S. Wahby <rsw@cs.nyu.edu>

#include "pymiracl.h"

// get the current error string
char *pymr_get_error(void) {
    return error_string;
}

// give Python info about the sizes we need for big and epoint
int *pymr_get_sizes(void) {
    return data_sizes;
}

// clean up everything
void pymr_clear(void) {
    if (mip != NULL) {
        if (q_ord != NULL) {
            mirkill(q_ord);
            q_ord = NULL;
        }
        if (p_fld != NULL) {
            mirkill(p_fld);
            p_fld = NULL;
        }
        if (b_tmp1 != NULL) {
            mirkill(b_tmp1);
            b_tmp1 = NULL;
        }
        if (b_tmp2 != NULL) {
            mirkill(b_tmp2);
            b_tmp2 = NULL;
        }
        if (b_hbit != NULL) {
            mirkill(b_hbit);
            b_hbit = NULL;
        }
        if ((gi_mem != NULL) && (nbases > 0)) {
            ecp_memkill(gi_mem, nbases);
            nbases = 0;
            gi_mem = NULL;
        }
        if (gi != NULL) {
            free(gi);
            gi = NULL;
        }
        if (p_tmp1 != NULL) {
            epoint_free(p_tmp1);
            p_tmp1 = NULL;
        }
        if (p_tmp2 != NULL) {
            epoint_free(p_tmp2);
            p_tmp2 = NULL;
        }
        mirexit();
        mip = NULL;
    }
}

// set up curve params
char **pymr_set_curve(char *filename, int nelms, bool check_points) {
    FILE *fp;
    big a=NULL, b=NULL, x1=NULL, y1=NULL;
    iofst[MR_DEFAULT_BUFFER_SIZE-1] = '\0';
    iosnd[MR_DEFAULT_BUFFER_SIZE-1] = '\0';

    if ((fp = fopen(filename, "r")) == NULL) {
        pymr_ERROR(IOERR, "Could not open specified curve params file");
        return NULL;
    }

    int bits, nybs, words;
    if (fscanf(fp,"%d\n",&bits) == EOF) {
        pymr_ERROR(IOERR, strerror(errno));
        return NULL;
    }
    pymr_clear();

    nybs = bits / 4 + ((bits % 4) ? 1 : 0);
    bits = 4 * nybs; // actual value of bits
    words = (bits / 64) + ((bits % 64) ? 1 : 0);
    if ((mip = mirsys(words, 0)) == NULL) {
        pymr_ERROR(RTERR, "Could not initialize MIRACL");
        return NULL;
    }
    mip->IOBASE=16;

    // prep vars (previously de-initialized above)
    q_ord = mirvar(0);
    p_fld = mirvar(0);
    b_tmp1 = mirvar(0);
    b_tmp2 = mirvar(0);
    b_hbit = mirvar(0);
    msbit = bits - 1;
    expb2(msbit, b_hbit);
    a = mirvar(0);
    b = mirvar(0);

    // read in values from file
    cinnum(p_fld, fp);
    cinnum(a, fp);
    cinnum(b, fp);
    cinnum(q_ord, fp);

    // set up elliptic curve
    ecurve_init(a, b, p_fld, MR_PROJECTIVE);
    mirkill(a);
    mirkill(b);

    // set base points
    if (fscanf(fp, "%d\n", &nbases) == EOF) {
        pymr_ERROR(IOERR, strerror(errno));
        goto pymr_set_curve_failed;
    }
    if (nelms > 0) {
        nbases = nbases > nelms ? nelms : nbases;
    }
    gi = malloc(nbases * sizeof(epoint *));
    gi_mem = ecp_memalloc(nbases);
    if (gi_mem == NULL || gi == NULL) {
        goto pymr_set_curve_failed;
    }
    x1 = mirvar(0);
    y1 = mirvar(0);
    bool quit = false;
    for (int base = 0; base < nbases; base++) {
        if ((cinnum(x1, fp) == 0) || (cinnum(y1, fp) == 0)) {
            pymr_ERROR(VALERR, "Tried to read past EOF getting base");
            quit = true;
            break;
        }
        gi[base] = epoint_init_mem(gi_mem, base);
        if (!epoint_set(x1, y1, 0, gi[base])) {
            pymr_ERROR(VALERR, "Could not set up base points (not on curve?)");
            quit = true;
            break;
        }
    }
    fclose(fp);
    mirkill(x1);
    mirkill(y1);
    if (quit) {
        goto pymr_set_curve_failed;
    }
    // we use the last two bases as 'g' and 'h'
    // keep 'g' separate from any of the vector bases to catch errors
    g = gi[nbases-2];
    h = gi[nbases-1];

    // set up the rest
    p_tmp1 = epoint_init();
    p_tmp2 = epoint_init();

    if (check_points) {
        // test base points to make sure they're of order q
        epoint *w1;
        w1 = epoint_init();
        for (int base = 0; base < nbases; base++) {
            ecurve_mult(q_ord, gi[base], w1);
            if (!point_at_infinity(w1)) {
                snprintf(iotup[0], MR_DEFAULT_BUFFER_SIZE-1, "Base point %d is not of order q!", base);
                pymr_ERROR(VALERR, iotup[0]);
                quit = true;
                break;
            }
        }
        epoint_free(w1);
        if (quit) {
            return NULL;
        }
    }

    int pbits = logb2(p_fld);
    if ((bits - pbits) < 1) {
        pymr_ERROR(VALERR, "Bad curve params. #bits specified must be at least 1 more than p.");
        goto pymr_set_curve_failed;
    }

    // set the sizes we need
    data_sizes[0] = bits;
    data_sizes[1] = mr_size(mip->nib-1);    // from mrcore.c line 889
    data_sizes[2] = mr_esize(mip->nib-1);   // from mrcore.c line 2180

    cotstr(q_ord, iotup[0]);
    snprintf(iotup[1], MR_DEFAULT_BUFFER_SIZE-1, "%x", nbases - 2);
    return iotup;

pymr_set_curve_failed:
    pymr_clear();
    return NULL;
}

// gi^xi h^y
char **pymr_pow_gih(char **xlst, unsigned lx, char *varh, unsigned nstart) {
    pymr_CHECK_INIT;
    // make sure we have enough bases
    if ((int)(lx + nstart) > nbases - 2) {
        pymr_ERROR(VALERR, "Tried to use gi beyond end of list");
        return NULL;
    }
    // process arguments
    MRBig_FromString(b_tmp2, varh);

    // set up computation
    bool OK = true;
    epoint **bases = malloc((lx+1) * sizeof(epoint *));
    big *scalars = malloc((lx+1) * sizeof(big));
    if (bases == NULL || scalars == NULL) {
        pymr_ERROR(SYSERR, "ERROR allocating memory for pow_gih");
        OK = false;
        goto pow_gih_cleanup;
    }

    // get scalars
    if (!MRBigList_FromList(scalars, xlst, lx)) {
        OK = false;
        goto pow_gih_cleanup;
    }
    scalars[lx] = b_tmp2;

    // set up pointers to bases
    for (unsigned i = 0; i < lx; i++) {
        bases[i] = gi[nstart + i];
    }
    bases[lx] = h;

    // do the multiexp
    OK = multiexp_help(bases, scalars, lx+1);

pow_gih_cleanup:
    if (scalars != NULL) {
        free(scalars);
    }
    if (bases != NULL) {
        free(bases);
    }

    if (OK) {
        return Tuple_FromEPoint(p_tmp1);
    } else {
        return NULL;
    }
}

// gi^xi
char **pymr_pow_gi(char **xlst, unsigned lx, unsigned nstart, int nskip) {
    pymr_CHECK_INIT;

    if ((((int)lx - 1) * nskip + (int)nstart < 0) || (((int)lx - 1) * nskip + (int)nstart > nbases - 3)) {
        pymr_ERROR(VALERR, "Tried to use gi outside of list");
        return NULL;
    }

    // set up computation
    bool OK = true;
    epoint **bases = malloc(lx * sizeof(epoint *));
    big *scalars = malloc(lx * sizeof(big));
    if (bases == NULL || scalars == NULL) {
        pymr_ERROR(SYSERR, "ERROR allocating memory for pow_gi");
        OK = false;
        goto pow_gi_cleanup;
    }

    // get scalars
    if (!MRBigList_FromList(scalars, xlst, lx)) {
        OK = false;
        goto pow_gi_cleanup;
    }

    // set up pointers to bases
    for (unsigned i = 0; i < lx; i++) {
        bases[i] = gi[nstart + nskip * i];
    }

    // do the multiexp
    OK = multiexp_help(bases, scalars, lx);

pow_gi_cleanup:
    if (scalars != NULL) {
        free(scalars);
    }
    if (bases != NULL) {
        free(bases);
    }

    if (OK) {
        return Tuple_FromEPoint(p_tmp1);
    } else {
        return NULL;
    }
}

// g^x h^y
char **pymr_pow_gh(char *varg, char *varh) {
    pymr_CHECK_INIT;

    MRBig_FromString(b_tmp1, varg);
    MRBig_FromString(b_tmp2, varh);
    ecurve_mult2(b_tmp1, g, b_tmp2, h, p_tmp1);

    return Tuple_FromEPoint(p_tmp1);
}

// g^x
char **pymr_pow_g(char *varg) {
    pymr_CHECK_INIT;

    MRBig_FromString(b_tmp1, varg);
    ecurve_mult(b_tmp1, g, p_tmp1);

    return Tuple_FromEPoint(p_tmp1);
}

// h^y
char **pymr_pow_h(char *varh) {
    pymr_CHECK_INIT;

    MRBig_FromString(b_tmp1, varh);
    ecurve_mult(b_tmp1, h, p_tmp1);

    return Tuple_FromEPoint(p_tmp1);
}

// b * g^-x
char **pymr_maul(char **bval, char *xval) {
    pymr_CHECK_INIT;

    // compute g^-x
    MRBig_FromString(b_tmp1, xval);
    mr_psub(q_ord, b_tmp1, b_tmp2);
    ecurve_mult(b_tmp2, g, p_tmp2);

    // check b for validity
    if (!EPoint_FromTuple(p_tmp1, bval)) {
        if (point_at_infinity(p_tmp1)) {
            // b is infinity, so just return g^-x
            return Tuple_FromEPoint(p_tmp2);
        } else {
            pymr_ERROR(VALERR, "Point supplied to maul must be on curve!");
            return NULL;
        }
    }

    // all's well
    ecurve_add(p_tmp2, p_tmp1);

    return Tuple_FromEPoint(p_tmp1);
}

// b^x * m
char **pymr_exp_mul(char **bmvals, char *xval) {
    pymr_CHECK_INIT;

    // check points for validity
    bool b_valid = EPoint_FromTuple(p_tmp1, bmvals);
    bool m_valid = EPoint_FromTuple(p_tmp2, bmvals + 2);

    // get x
    MRBig_FromString(b_tmp1, xval);

    // handle cases
    if (!b_valid || !m_valid) {
        bool b_is_inf = point_at_infinity(p_tmp1);
        bool m_is_inf = point_at_infinity(p_tmp2);

        switch ((b_is_inf ? 1 : 0) | (m_is_inf ? 2 : 0)) {
            case 0: 
                // neither is infinity, one point or the other is just invalid
                break;

            case 2:
                // m is infinity
                if (b_valid) {  // result is b^x
                    ecurve_mult(b_tmp1, p_tmp1, p_tmp1);
                    return Tuple_FromEPoint(p_tmp1);
                }
                // else error
                break;

            case 1:
                // b is infinity
                if (!m_valid) {  // error
                    break;
                }
                // else fall through and return m
                // FALLTHRU

            default:
                // both are infinity, so the result is also infinity; return m
                return Tuple_FromTuple(bmvals + 2);
        }

        pymr_ERROR(VALERR, "Points supplied to exp_mul must be on curve!");
        return NULL;
    }

    // everything is normal
    ecurve_mult(b_tmp1, p_tmp1, p_tmp1);
    ecurve_add(p_tmp2, p_tmp1);

    return Tuple_FromEPoint(p_tmp1);
}

// b^x * h^y
char **pymr_exp_powh(char **bval, char *xval, char *yval) {
    pymr_CHECK_INIT;

    // check validity of b
    bool b_valid = EPoint_FromTuple(p_tmp1, bval);

    // convert y
    MRBig_FromString(b_tmp2, yval);

    // check whether b is a valid point
    if (!b_valid) {
        if (point_at_infinity(p_tmp1)) {
            // b is infinity, return h^y
            ecurve_mult(b_tmp2, h, p_tmp1);
            return Tuple_FromEPoint(p_tmp1);
        } else {
            pymr_ERROR(VALERR, "Point supplied to exp must be on curve!");
            return NULL;
        }
    }

    // all's well, convert x and compute
    MRBig_FromString(b_tmp1, xval);
    ecurve_mult2(b_tmp1, p_tmp1, b_tmp2, h, p_tmp2);

    return Tuple_FromEPoint(p_tmp2);
}

// b^x
char **pymr_exp(char **bval, char *xval) {
    pymr_CHECK_INIT;

    // check whether b is a valid point
    if (!EPoint_FromTuple(p_tmp1, bval)) {
        // if it's infinity, fall through and return, otherwise error
        if (!point_at_infinity(p_tmp1)) {
            pymr_ERROR(VALERR, "Point supplied to exp must be on curve!");
            return NULL;
        }
    } else {
        // b is valid, so multiply it out
        MRBig_FromString(b_tmp1, xval);
        ecurve_mult(b_tmp1, p_tmp1, p_tmp1);
    }

    return Tuple_FromEPoint(p_tmp1);
}

// b / c
char **pymr_div(char **bcvals) {
    pymr_CHECK_INIT;

    // check points for validity
    bool b_valid = EPoint_FromTuple(p_tmp1, bcvals);
    bool c_valid = EPoint_FromTuple(p_tmp2, bcvals + 2);
    if (!b_valid || !c_valid) {
        bool b_is_inf = point_at_infinity(p_tmp1);
        bool c_is_inf = point_at_infinity(p_tmp2);

        switch ((b_is_inf ? 1 : 0) | (c_is_inf ? 2 : 0)) {
            case 0:
                // neither is infinity, just invalid points
                break;

            case 1:
                // b is infinity
                if (c_valid) {  // return inverse of c
                    // Weierstrass, so to compute inverse just negate y
                    epoint_get(p_tmp2, b_tmp1, b_tmp2);
                    mr_psub(p_fld, b_tmp2, b_tmp2);
                    if (!epoint_set(b_tmp1, b_tmp2, 0, p_tmp2)) {
                        break;
                    }
                    return Tuple_FromEPoint(p_tmp2);
                }
                // else error
                break;

            case 2:
                // c is infinity
                if (!b_valid) { // error
                    break;
                }
                // else fall through and return b
                // FALLTHRU

            default:
                // both are infinity, so the result is also infinity; return b
                return Tuple_FromTuple(bcvals);
        }

        pymr_ERROR(VALERR, "Point supplied to div must be on curve!");
        return NULL;
    }

    // all's well
    ecurve_sub(p_tmp2, p_tmp1);

    return Tuple_FromEPoint(p_tmp1);
}

// b * c
char **pymr_mul(char **bcvals) {
    pymr_CHECK_INIT;

    // check points for validity
    bool b_valid = EPoint_FromTuple(p_tmp1, bcvals);
    bool c_valid = EPoint_FromTuple(p_tmp2, bcvals + 2);
    if (!b_valid || !c_valid) {
        bool b_is_inf = point_at_infinity(p_tmp1);
        bool c_is_inf = point_at_infinity(p_tmp2);

        switch ((b_is_inf ? 1 : 0) | (c_is_inf ? 2 : 0)) {
            case 0:
                // neither is infinity, just invalid
                break;

            case 1:
                // b is infinity
                if (c_valid) {  // return c
                    return Tuple_FromTuple(bcvals + 2);
                }
                // else error
                break;

            case 2:
                // c is infinity
                if (!b_valid) { // error
                    break;
                }
                // else fall through and return b
                // FALLTHRU

            default:
                // both are infinity, so the result is also infinity; return b
                return Tuple_FromTuple(bcvals);
        }

        pymr_ERROR(VALERR, "Point supplied to mul must be on curve!");
        return NULL;
    }

    // all's well
    ecurve_add(p_tmp2, p_tmp1);

    return Tuple_FromEPoint(p_tmp1);
}

// b * b
char **pymr_sqr(char **bval) {
    pymr_CHECK_INIT;

    // check whether b is a valid point
    if (!EPoint_FromTuple(p_tmp1, bval)) {
        if (point_at_infinity(p_tmp1)) {
            // b is infinity
            return Tuple_FromTuple(bval);
        } else {
            pymr_ERROR(VALERR, "Point supplied to exp must be on curve!");
            return NULL;
        }
    }

    // all's well
    ecurve_double(p_tmp1);

    return Tuple_FromEPoint(p_tmp1);
}

// multiexp: \prod_i b_i ^ x_i
char **pymr_multiexp(char **blst, char **xlst, unsigned num) {
    pymr_CHECK_INIT;

    if (num == 0) {
        pymr_ERROR(VALERR, "Both arguments to multiexp must have nonzero length");
        return NULL;
    }

    // allocate points
    bool OK = true;
    unsigned out_diff = 0;
    epoint **points = malloc(num * sizeof(epoint *));
    big *scalars = malloc(num * sizeof(big));
    if (points == NULL || scalars == NULL) {
        pymr_ERROR(SYSERR, "ERROR allocating memory for multiexp");
        OK = false;
        goto multiexp_cleanup;
    }

    for (unsigned i = 0; i < num; i++) {
        unsigned j = i - out_diff;
        // this is the memory we're going to use to store points and scalar
        char *pm = blst[2*i];
        MRBig_FromString(b_tmp1, blst[2*i]);
        MRBig_FromString(b_tmp2, blst[2*i+1]);
        if ((mr_lent(b_tmp1) == 0) && (mr_lent(b_tmp2) == 0)) {
            // point at infinity, just skip it
            out_diff++;
            continue;
        }

        // otherwise, repurpose this spot in blst for our epoint
        memset(pm, 0, mr_esize(mip->nib-1));
        points[j] = epoint_init_mem(pm, 0);
        if (!epoint_set(b_tmp1, b_tmp2, 0, points[j])) {
            // this is an invalid point
            pymr_ERROR(VALERR, "Point supplied to multiexp must be on curve!");
            OK = false;
            goto multiexp_cleanup;
        }
        
        // convert the scalar now
        char *sm = xlst[i];
        MRBig_FromString(b_tmp1, sm);
        memset(sm, 0, mr_size(mip->nib-1));
        scalars[j] = mirvar_mem(sm, 0);
        copy(b_tmp1, scalars[j]);
    }

    // do the multiexp, finally
    OK = multiexp_help(points, scalars, num - out_diff);

multiexp_cleanup:
    if (points != NULL) {
        free(points);
    }
    if (scalars != NULL) {
        free(scalars);
    }

    if (OK) {
        return Tuple_FromEPoint(p_tmp1);
    } else {
        return NULL;
    }
}

char **pymr_multimul(char **blst, unsigned lb) {
    pymr_CHECK_INIT;

    epoint_set(NULL, NULL, 0, p_tmp1);
    if (lb > 0) {
        for (unsigned i = 0; i < lb; i++) {
            if (!EPoint_FromTuple(p_tmp2, blst + 2*i)) {
                if (point_at_infinity(p_tmp2)) {
                    continue;
                }

                pymr_ERROR(VALERR, "Point supplied to multimul must be on curve!");
                return NULL;
            }
            ecurve_add(p_tmp2, p_tmp1);
        }
    }

    return Tuple_FromEPoint(p_tmp1);
}

// compress a point
char *pymr_compress(char **bval) {
    pymr_CHECK_INIT;

    if (!EPoint_FromTuple(p_tmp1, bval)) {
        pymr_ERROR(VALERR, "Point supplied to compress must be on curve!");
        return NULL;
    }
    int y = epoint_get(p_tmp1, b_tmp1, b_tmp1);
    if (y != 0) {
        mr_padd(b_tmp1, b_hbit, b_tmp1);
    }

    cotstr(b_tmp1, iotup[0]);
    return iotup[0];
}

// decompress a point
char **pymr_decompress(char *xval) {
    pymr_CHECK_INIT;

    MRBig_FromString(b_tmp1, xval);
    int y = 0;
    if (mr_testbit(b_tmp1, msbit)) {
        y = 1;
        mr_psub(b_tmp1, b_hbit, b_tmp1);
    }
    if (!epoint_set(b_tmp1, b_tmp1, y, p_tmp1)) {
        pymr_ERROR(VALERR, "Point supplied to decompress must be on curve!");
        return NULL;
    }

    return Tuple_FromEPoint(p_tmp1);
}

// get vec of scalars from char**
static bool MRBigList_FromList(big *s, char **lst, unsigned len) {
    for (unsigned i = 0; i < len; i++) {
        char *sm = lst[i];
        MRBig_FromString(b_tmp1, sm);
        memset(sm, 0, mr_size(mip->nib-1));
        s[i] = mirvar_mem(sm, 0);
        copy(b_tmp1, s[i]);
    }
    return true;
}

// create a Tuple from an epoint
static char **Tuple_FromEPoint(epoint *p) {
    epoint_get(p, b_tmp1, b_tmp2);
    cotstr(b_tmp1, iotup[0]);
    cotstr(b_tmp2, iotup[1]);
    return iotup;
}

static char **Tuple_FromTuple(char **t) {
    strncpy(iotup[0], t[0], MR_DEFAULT_BUFFER_SIZE-1);
    strncpy(iotup[1], t[1], MR_DEFAULT_BUFFER_SIZE-1);
    return iotup;
}

// set value of an epoint from a Tuple
static bool EPoint_FromTuple(epoint *p, char **t) {
    MRBig_FromString(b_tmp1, t[0]);
    MRBig_FromString(b_tmp2, t[1]);

    if ((mr_lent(b_tmp1) == 0) && (mr_lent(b_tmp2) == 0)) {
        epoint_set(NULL, NULL, 0, p);
        return false;
    }
    return epoint_set(b_tmp1, b_tmp2, 0, p);
}

// big from string---just a cinstr wrapper
static void MRBig_FromString(big b, char *c) {
    cinstr(b, c);
}

#include "multiexp.c"
