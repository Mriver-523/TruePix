static bool multiexp_help(epoint **points, big *scalars, int num) {
    // special cases for small multiexps
    if (num == 0) {
        epoint_set(NULL, NULL, 0, p_tmp1);  // set output to infinity
        return true;
    } else if (num == 1) {
        ecurve_mult(scalars[0], points[0], p_tmp1);
        return true;
    } else if (num == 2) {
        ecurve_mult2(scalars[0], points[0], scalars[1], points[1], p_tmp1);
        return true;
    } else if (num < MULTN_MAX) {
        ecurve_multn(num, scalars, points, p_tmp1);
        return true;
    } else if (num < STRAUS_MAX) {
        return multiexp_straus(points, scalars, num);
    }
    // otherwise, we have enough points that we should use Pippenger's
    return multiexp_BDLO12(points, scalars, num);
}

static bool multiexp_straus(epoint **points, big *scalars, int num) {
    epoint_set(NULL, NULL, 0, p_tmp1);  // set output to infinity
    bool OK = true;

    // allocate --- how many points?
    int nextra = num / 3;
    int nlast = num % 3;
    int nalloc = 4 * nextra;
    epoint **xpoints = malloc(nalloc * sizeof(epoint *));
    if (nlast == 2) {
        nalloc++;
    }
    char *xpoints_mem = ecp_memalloc(nalloc);
    epoint *final2 = NULL;
    if (nlast == 2) {
        final2 = epoint_init_mem(xpoints_mem, 4 * nextra);
        epoint_copy(points[num-2], final2);
        ecurve_add(points[num-1], final2);
    }
    // make sure alloc worked
    if (xpoints == NULL || xpoints_mem == NULL) {
#ifdef Py_PYTHON_H
        PyErr_SetString(PyExc_SystemError, "ERROR allocating memory for multiexp");
#else
        pymr_ERROR(SYSERR, "ERROR allocating memory for multiexp");
#endif
        OK = false;
        goto multiexp_straus_cleanup;
    }

#define ipoint1 points[3*j]
#define ipoint2 points[3*j+1]
#define ipoint3 points[3*j+2]
#define opoint12 xpoints[4*j]
#define opoint13 xpoints[4*j+1]
#define opoint23 xpoints[4*j+2]
#define opoint123 xpoints[4*j+3]
    // precompute windows
    for (int j = 0; j < nextra; j++) {
        for (int i = 0; i < 4; i++) {
            xpoints[4*j + i] = epoint_init_mem(xpoints_mem, 4*j + i);
        }

        // point1 * point2              (case 3)
        epoint_copy(ipoint1, opoint12);
        ecurve_add(ipoint2, opoint12);

        // point1 * point3              (case 5)
        epoint_copy(ipoint1, opoint13);
        ecurve_add(ipoint3, opoint13);

        // point2 * point3              (case 6)
        epoint_copy(ipoint2, opoint23);
        ecurve_add(ipoint3, opoint23);

        // point1 * point2 * point3     (case 7)
        epoint_copy(opoint23, opoint123);
        ecurve_add(ipoint1, opoint123);
    }

    // compute multiexp with winsize=3
    int bitval;
    for (int i = logb2(q_ord)-1; i >= 0; i--) {
        ecurve_double(p_tmp1);
        for (int j = 0; j < nextra; j++) {
            bitval = (mr_testbit(scalars[3*j], i) ? 1 : 0) | (mr_testbit(scalars[3*j+1], i) ? 2 : 0) | (mr_testbit(scalars[3*j+2], i) ? 4 : 0);
            switch (bitval) {
                case 1:
                    ecurve_add(ipoint1, p_tmp1);
                    break;
                case 2:
                    ecurve_add(ipoint2, p_tmp1);
                    break;
                case 4:
                    ecurve_add(ipoint3, p_tmp1);
                    break;
                case 3:
                    ecurve_add(opoint12, p_tmp1);
                    break;
                case 5:
                    ecurve_add(opoint13, p_tmp1);
                    break;
                case 6:
                    ecurve_add(opoint23, p_tmp1);
                    break;
                case 7:
                    ecurve_add(opoint123, p_tmp1);
                // case 0: do nothing
            }
        }

        if ((nlast == 1) && mr_testbit(scalars[num-1], i)) {
            ecurve_add(points[num-1], p_tmp1);
        } else if (nlast == 2) {
            bitval = (mr_testbit(scalars[num-2], i) ? 1 : 0) | (mr_testbit(scalars[num-1], i) ? 2 : 0);
            switch (bitval) {
                case 1:
                    ecurve_add(points[num-2], p_tmp1);
                    break;
                case 2:
                    ecurve_add(points[num-1], p_tmp1);
                    break;
                case 3:
                    ecurve_add(final2, p_tmp1);
                    // default: do nothing
            }
        }
    }
#undef ipoint1
#undef ipoint2
#undef ipoint3
#undef opoint12
#undef opoint13
#undef opoint23
#undef opoint123

multiexp_straus_cleanup:
    if (xpoints != NULL) {
        free(xpoints);
    }
    if (xpoints_mem != NULL) {
        ecp_memkill(xpoints_mem, nalloc);
    }

    return OK;
}

// This is an implementation of a simplified Pippenger's algorithm described by
// Bernstein, Doumen, Lange, and Oosterwijk. "Faster batch forgery identification."
// Proc. INDOCRYPT 2012, Dec. 2012
//
// This implementation is adapted from the C++ implementation in libff,
// https://github.com/scipr-lab/libff
static bool multiexp_BDLO12(epoint **points, big *scalars, int num) {
    epoint_set(NULL, NULL, 0, p_tmp1);  // set output to infinity
    bool result_nonzero = false;
    bool OK = true;

    // window size and #groups
    unsigned c;
    {
        unsigned lg2len = 0;
        int num_copy = num;
        while (num_copy >>= 1) lg2len++;
        c = lg2len + 2 - lg2len / 3;
    }
    unsigned num_groups = (msbit + c - 1) / c;

    // allocate memory for buckets
    unsigned nbuckets = 1 << c;
    epoint **buckets = malloc(nbuckets * sizeof(epoint *));
    bool *bucket_nonzero = malloc(nbuckets * sizeof(bool));
    char *buckets_mem = ecp_memalloc(nbuckets);
    if (buckets == NULL || bucket_nonzero == NULL || buckets_mem == NULL) {
#ifdef Py_PYTHON_H
        PyErr_SetString(PyExc_SystemError, "ERROR allocating memory for multiexp");
#else
        pymr_ERROR(SYSERR, "ERROR allocating memory for multiexp");
#endif
        OK = false;
        goto multiexp_BDLO12_cleanup;
    }
    for (unsigned i = 0; i < nbuckets; i++) {
        buckets[i] = epoint_init_mem(buckets_mem, i);
    }

    // main loop - go group-by-group through the exponent, starting from the msbits
    for (int k = num_groups - 1; k >= 0; k--) {
        // shift accumulated value left by c bits
        if (result_nonzero) {
            for (unsigned i = 0; i < c; i++) {
                ecurve_double(p_tmp1);
            }
        }

        // reset buckets
        for (unsigned i = 0; i < nbuckets; i++) {
            // set buckets to 0
            epoint_set(NULL, NULL, 0, buckets[i]);
            bucket_nonzero[nbuckets] = false;
        }

        // for each point, partition its exponent into one of the buckets
        for (unsigned i = 0; i < (unsigned) num; i++) {
            // grab the c bits of the exponent starting at k*c
            unsigned bucket_num = 0;
            for (unsigned j = 0; j < c; j++) {
                if (mr_testbit(scalars[i], k*c + j)) {
                    bucket_num |= 1 << j;
                }
            }

            // bucket[0] never gets used because g^0 is the identity
            if (bucket_num == 0) {
                continue;
            }

            // update the appropriate bucket
            if (bucket_nonzero[bucket_num]) {
                ecurve_add(points[i], buckets[bucket_num]);
            } else {
                epoint_copy(points[i], buckets[bucket_num]);
                bucket_nonzero[bucket_num] = true;
            }
        }

        // sum up the buckets in a clever way
        // buckets[0] is our running product because it's unity by construction
        for (unsigned i = nbuckets - 1; i > 0; i--) {
            // if this is a nonzero bucket, add it to the running sum
            if (bucket_nonzero[i]) {
                if (bucket_nonzero[0]) {    // bucket_nonzero[0] represents the running sum
                    ecurve_add(buckets[i], buckets[0]);
                } else {
                    epoint_copy(buckets[i], buckets[0]);
                    bucket_nonzero[0] = true;
                }
            }

            // if the running sum is nonzero, add it to the result
            if (bucket_nonzero[0]) {
                if (result_nonzero) {
                    ecurve_add(buckets[0], p_tmp1);
                } else {
                    epoint_copy(buckets[0], p_tmp1);
                    result_nonzero = true;
                }
            }
        }
    }

multiexp_BDLO12_cleanup:
    if (buckets != NULL) {
        free(buckets);
    }
    if (bucket_nonzero != NULL) {
        free(bucket_nonzero);
    }
    if (buckets_mem != NULL) {
        ecp_memkill(buckets_mem, nbuckets);
    }

    return OK;
}
