#include <stdio.h>
#include </opt/homebrew/Cellar/gmp/6.2.1_1/include/gmp.h>
#include <stdlib.h>
#include <string.h>

/* 1 + 2^121 + 2^178 + 2^241 + 2^256 */
const char *prime_polynomial_str = "115795622931445752192230534727574610162518887676182672686415539519216821469185";

struct point {
    mpz_t x; // x-coordinate
    mpz_t y; // y-coordinate (share)
};

void mul_gf2(mpz_t result, mpz_t p, mpz_t q) {
    mpz_t a, b;
    mpz_init_set(a, p);
    mpz_init_set(b, q);
    if (mpz_cmp(b ,a) > 0) {
        mpz_swap(a, b);
    }
    mpz_set_ui(result, 0);
    while (mpz_cmp_ui(b, 0) != 0) {
        mpz_t o, r;
        mpz_init_set_ui(o, 1);
        mpz_init(r);
        mpz_and(r, b, o);
        if (mpz_cmp_ui(r, 0) != 0) {
            mpz_xor(result, result, a);

        }
        mpz_mul_2exp(a,a,1);
        mpz_tdiv_q_2exp(b,b,1);
    }
    return;
}

void div_gf2(mpz_t q, mpz_t a, mpz_t b) {
    mpz_set_ui(q, 0);
    if (mpz_cmp(b ,a) > 0) {
        return;
    }
    // printf("heloo ins1\n");

    mpz_t r, s, o, tmp;
    mpz_inits(r, s, tmp, NULL);
    mpz_init_set_ui(o, 1);
    mpz_set(r, a);
    size_t deg_b = mpz_sizeinbase(b, 2);
    // printf("heloo ins2\n");
    // int i = 0;
    while(mpz_sizeinbase(r, 2) >= deg_b && mpz_cmp_ui(r, 0)) {
        mpz_mul_2exp(s, o, (int)mpz_sizeinbase(r, 2) - (int)deg_b);
        mpz_xor(q, q, s);
        mul_gf2(tmp, b, s);
        mpz_xor(r, r, tmp);
    }
}

/* Inverse of a number in 2^256 GF using Extended GCD */
void inv_gf2256(mpz_t res, mpz_t a) {

    if (mpz_cmp_ui(a, 0) == 0) {
        return;
    }

    mpz_t r0, r1, s0, s1, q, temp1, temp2, tmp;
    mpz_inits(r0, s0, s1, q, temp1, temp2, tmp, NULL);
    mpz_t primitive_poly;
    mpz_init_set_str(primitive_poly, prime_polynomial_str, 10);
    mpz_set(r0, a);
    mpz_init_set(r1, primitive_poly);
    mpz_set_ui(s0, 1);
    mpz_set_ui(s1, 0);

    while(mpz_cmp_ui(r1, 0) > 0) {
        div_gf2(q, r0, r1);
        mpz_set(temp1, r1);
        mul_gf2(tmp, q, r1);
        mpz_xor(r1, r0, tmp);
        mpz_set(r0, temp1);
        mpz_set(temp2, s1);
        mul_gf2(tmp, q, s1);
        mpz_xor(s1, s0, tmp);
        mpz_set(s0, temp2);        
    }
    mpz_set(res, s0);
}

/* Multiplication in the 2^256 Finite Field using BitMasking */
void mul_gf2256(mpz_t result, mpz_t p, mpz_t q) {
    mpz_t f1, f2, mask1, mask2, mask3, v, z, mod;
    mpz_init_set_str(mod, prime_polynomial_str, 10);

    mpz_inits(mask1, mask2, mask3, v, z, NULL);
    mpz_init_set(f1, p);
    mpz_init_set(f2, q);

    if (mpz_cmp(f2, f1) > 0) {
        mpz_swap(f1, f2);
    }

    if (mpz_cmp(mod, f1) == 0 || mpz_cmp(mod, f2) == 0) {
        mpz_set_ui(result, 0);
        return;
    }

    mpz_set_ui(mask1, 1);
    mpz_mul_2exp(mask1, mask1, 256);
    mpz_set(v, f1);
    mpz_set_ui(z, 0);
    while (mpz_cmp_ui(f2, 0) != 0) {
        mpz_set_ui(mask2, mpz_tstbit(f2, 0));
        if (mpz_cmp_ui(mask2, 0) > 0) {
            char *msk = (char *)malloc(256 + 1);
            memset(msk, '1', 256);
            msk[256] = '\0';
            mpz_set_str(mask2, msk, 2);
            free(msk);
        }

        mpz_t tmp, tmp2;
        mpz_inits(tmp, tmp2, NULL);
        mpz_xor(tmp, z, v);
        mpz_and(tmp, tmp, mask2);

        mpz_sub(tmp2, mask1, mask2);
        mpz_sub_ui(tmp2, tmp2, 1);
        mpz_and(tmp2, z, tmp2);
        mpz_ior(z, tmp, tmp2);

        mpz_mul_2exp(v, v, 1);

        mpz_div_2exp(tmp2, v, 256);
        mpz_set_ui(mask3, mpz_tstbit(tmp2, 0));
        if (mpz_cmp_ui(mask3, 0) > 0) {
            char *msk = (char *)malloc(256 + 1);
            memset(msk, '1', 256);
            msk[256] = '\0';
            mpz_set_str(mask3, msk, 2);
            free(msk);
        }

        mpz_xor(tmp, v, mod);
        mpz_and(tmp, tmp, mask3);

        mpz_sub(tmp2, mask1, mask3);
        mpz_sub_ui(tmp2, tmp2, 1);
        mpz_and(tmp2, tmp2, v);
        mpz_ior(tmp2, tmp, tmp2);
        mpz_set(v, tmp2);

        mpz_clear(tmp);
        mpz_clear(tmp2);
        mpz_div_2exp(f2, f2, 1);
    }
    mpz_set(result, z);
    
    mpz_clear(f1);
    mpz_clear(f2);
    mpz_clear(mask1);
    mpz_clear(mask2);
    mpz_clear(mask3);
    mpz_clear(v);
    mpz_clear(z);
}


struct point *split(int n, int t, char *secret) {
    struct point *points = malloc(n * sizeof(struct point));
    mpz_t sec;
    mpz_t coefficients[t];
    gmp_randstate_t state;
    mpz_t mod;
    mpz_init_set_str(mod, prime_polynomial_str, 10);

    mpz_init(sec);
    if (mpz_set_str(sec, secret, 16) != 0) {
        fprintf(stderr, "Invalid hex string\n");
        mpz_clear(sec);
        return NULL;
    }

    gmp_randinit_default(state);
    for (int i = 0; i < t - 1; i++) {
        mpz_init(coefficients[i]);
        mpz_urandomb(coefficients[i], state, 256);
    }
    mpz_init_set(coefficients[t - 1], sec);

    gmp_randclear(state);
    
    for (int i = 1; i < n + 1; i++) {
        mpz_t share, tmp;
        mpz_init(tmp);
        mpz_init_set_ui(share, 0);
        mpz_t idx;
        mpz_init_set_ui(idx, i);

        for (int j = 0; j < t; j++) {
            mul_gf2256(tmp, share, idx);
            mpz_set(share, tmp);
            mpz_xor(share, share, coefficients[j]);
        }

        mpz_init_set_ui(points[i-1].x, i);
        mpz_init_set(points[i-1].y, share);

        mpz_clear(share);
        mpz_clear(idx);
        mpz_clear(tmp);
    }
    return points;
}

void combine (struct point *points, int n) {
    mpz_t result;
    mpz_init_set_ui(result, 0);
    mpz_t mod;
    mpz_init_set_str(mod, prime_polynomial_str, 10);

    for (int i = 0; i < n; i++) {
        mpz_t x_j, y_j, num, den, tmp;
        mpz_init_set(x_j, points[i].x);
        mpz_init_set(y_j, points[i].y);
        mpz_init_set_ui(num, 1);
        mpz_init_set_ui(den, 1);
        mpz_init(tmp);
        for (int j = 0; j < n; j++) {
            mpz_t x_m;
            mpz_init_set(x_m, points[j].x);
            if (i != j) {
                mul_gf2256(tmp, num, x_m);
                mpz_set(num, tmp);

                mpz_t addn;
                mpz_init(addn);
                mpz_xor(addn, x_j, x_m);
                mul_gf2256(tmp, den, addn);
                mpz_set(den, tmp);
            }
        }
        mpz_t deninv;
        mpz_init(deninv);
        inv_gf2256(deninv, den);

        mpz_t r;
        mpz_init(r);
        mul_gf2256(r, num, deninv);
        mul_gf2256(r, r, y_j);

        mpz_xor(result, r, result);

    }
    gmp_printf("secret: %Zx\n", result);
}

int main(){
    struct point *res;
    res = split(3,2, "5ee5362498f37cc2388edceaa83822d99ae13f9e923c6ffd93224c19bf235f08");
    gmp_printf("x coefficient: %Zx\n", res[0].y);
    gmp_printf("x coefficient: %Zx\n", res[1].y);
    gmp_printf("x coefficient: %Zx\n", res[2].y);

    combine(res, 2);
    return 0;
}

