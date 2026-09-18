#include <iostream>
#include <string>
#include <sstream>
#include <NTL/ZZ_pX.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>

using namespace NTL;
std::stringstream outstream;
std::string tStr;
 
static const char *ret_stream(void);
static char *prep_string(char *s);
extern "C" {
    const char *convert_matrix(char *in);
    const char *compute_laurent(char *t_yP, char *t_r, char *t_s);
    void clear_stringstream(void);
    void init(char *p);
}

void init(char *p) {
    ZZ_p::init(conv<ZZ>(p));
}

void clear_stringstream(void) {
    outstream.clear();
    outstream.str(std::string());
}

static const char *ret_stream(void) {
    tStr = std::move(outstream.str());
    for (auto it = tStr.begin(); it != tStr.end(); it++) {
        if ((*it == '\n') || (*it == ' ')) {
            *it = ',';
        }
    }
    return tStr.c_str();
}

static char *prep_string(char *s) {
    for (unsigned i = 0; s[i] != '\0'; i++) {
        if ((s[i] == ',') || (s[i] == 'L')) {
            s[i] = ' ';
        }
    }
    return s;
}

const char *convert_matrix(char *in) {
    clear_stringstream();

    Mat<ZZ_p> mat{conv<Mat<ZZ_p>>(prep_string(in))};
    outstream << mat;
    return ret_stream();
}

const char *compute_laurent(char *t_yP, char *t_r, char *t_s) {
    clear_stringstream();

    // convert
    Mat<ZZ_p> rT, rPT;
    unsigned n;
#ifdef EXTRATESTS
    Vec<ZZ_p> uv;
#endif
    {
        Vec<ZZ_p> yP{conv<Vec<ZZ_p>>(prep_string(t_yP))};
        Mat<ZZ_p> r{conv<Mat<ZZ_p>>(prep_string(t_r))};
        Mat<ZZ_p> s{conv<Mat<ZZ_p>>(prep_string(t_s)) * 2};

        // compute r' = r o yP + 2s
        Mat<ZZ_p> rP{r};
        for (unsigned i = 0; i < rP.NumRows(); i++) {
            for (unsigned j = 0; j < rP.NumCols(); j++) {
                rP[i][j] *= yP[j];
            }
            rP[i] += s[i];
        }
        rT = transpose(r);
        rPT = transpose(rP);
        n = yP.length();
#ifdef EXTRATESTS
        ZZ_p tmp;
        uv.SetLength(2*r.NumRows() - 1);
        for (unsigned ui = 0; ui < r.NumRows(); ui++) {
            for (unsigned vi = 0; vi < r.NumRows(); vi++) {
                InnerProduct(tmp, r[ui], rP[vi]);
                uv[ui + vi] += tmp;
            }
        }
#endif
    }

    // now compute r * r' using polymul
    ZZ_pX fg;
    {
        ZZ_pX f, g, tmp;
        for (unsigned j = 0; j < n; j++) {
            f.rep = std::move(rT[j]);
            g.rep = std::move(rPT[j]);
            tmp = f * g;
            fg += tmp;
        }
    }

#ifdef EXTRATESTS
    {
        bool correct = true;
        for (unsigned j = 0; j < uv.length(); j++) {
            correct &= uv[j] == fg[j];
        }
        if (!correct) {
            std::cerr << "ERROR: mismatched results\n" << uv << std::endl << fg << std::endl;
        }
    }
#endif

    outstream << fg;
    return ret_stream();
}
