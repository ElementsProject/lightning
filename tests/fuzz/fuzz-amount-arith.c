#include "config.h"
#include <assert.h>
#include <math.h>
#include <common/amount.h>
#include <common/overflows.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv) {}

enum op {
    OP_MSAT_ADD,
    OP_MSAT_SUB,
    OP_MSAT_MUL,
    OP_MSAT_DIV,
    OP_MSAT_RATIO,
    OP_MSAT_RATIO_FLOOR,
    OP_MSAT_RATIO_CEIL,
    OP_MSAT_SCALE,
    OP_MSAT_ADD_SAT,
    OP_MSAT_SUB_SAT,
    OP_SAT_ADD,
    OP_SAT_SUB,
    OP_SAT_MUL,
    OP_SAT_DIV,
    OP_SAT_SCALE,
    OP_FEE,
    OP_ADD_FEE,
    OP_SUB_FEE,
    OP_TX_FEE,
    OP_FEERATE,
    OP_COUNT
};

void run(const uint8_t *data, size_t size) {
    if (size < sizeof(uint8_t) + 2 * sizeof(struct amount_msat) + sizeof(double))
        return;

    uint8_t op = *data++ % OP_COUNT;

    struct amount_msat a = fromwire_amount_msat(&data, &size);
    struct amount_msat b = fromwire_amount_msat(&data, &size);

    double f;
    memcpy(&f, data, sizeof(f));
    data += sizeof(f);

    struct amount_sat sa = amount_msat_to_sat_round_down(a);
    struct amount_sat sb = amount_msat_to_sat_round_down(b);

    u64 u64_param;
    memcpy(&u64_param, &f, sizeof(u64_param));

    struct amount_msat out_ms;
    struct amount_sat out_s;

    switch (op) {
    case OP_MSAT_ADD:
    {
        if (amount_msat_add(&out_ms, a, b)) {
            assert(out_ms.millisatoshis == a.millisatoshis + b.millisatoshis);
        }
        break;
    }

    case OP_MSAT_SUB:
    {
        if (amount_msat_sub(&out_ms, a, b)) {
            assert(out_ms.millisatoshis + b.millisatoshis == a.millisatoshis);
        }
        break;
    }

    case OP_MSAT_MUL:
    {
        if (amount_msat_mul(&out_ms, a, u64_param)) {
            assert(out_ms.millisatoshis == a.millisatoshis * u64_param);
        }
        break;
    }

    case OP_MSAT_DIV:
    {
        if (u64_param == 0)
            break;
        out_ms = amount_msat_div(a, u64_param);
        assert(out_ms.millisatoshis == a.millisatoshis / u64_param);
        break;
    }

    case OP_MSAT_RATIO:
    {
        if (b.millisatoshis == 0)
            break;
        double ratio = amount_msat_ratio(a, b);
        double expected = (double)a.millisatoshis / b.millisatoshis;
        assert(ratio == expected);
        break;
    }

    case OP_MSAT_RATIO_FLOOR:
    {
        if (b.millisatoshis == 0)
            break;
        u64 floor = amount_msat_ratio_floor(a, b);
        assert(floor == a.millisatoshis / b.millisatoshis);
        break;
    }

    case OP_MSAT_RATIO_CEIL:
    {
        if (b.millisatoshis == 0)
            break;

        // The assertion remains valid ONLY if there's no overflow
        if (a.millisatoshis > UINT64_MAX - b.millisatoshis + 1) {
            break;
        }

        u64 ceil = amount_msat_ratio_ceil(a, b);
        u64 quotient = a.millisatoshis / b.millisatoshis;
        u64 remainder = a.millisatoshis % b.millisatoshis;

        assert(ceil == quotient + (remainder != 0));
        break;
    }

    case OP_MSAT_SCALE:
    {
        // if (amount_msat_scale(&out_ms, a, f)) {
        //     double expect = (double)a.millisatoshis * f;
        //     assert(fabs((double)out_ms.millisatoshis - expect) < 1.0);
        // }
        break;
    }

    case OP_MSAT_ADD_SAT:
    {
        if (amount_msat_add_sat(&out_ms, a, sa)) {
            assert(out_ms.millisatoshis == sa.satoshis * MSAT_PER_SAT + a.millisatoshis);
        }
        break;
    }

    case OP_MSAT_SUB_SAT:
    {
        if (amount_msat_sub_sat(&out_ms, a, sa)) {
            assert(out_ms.millisatoshis + sa.satoshis * MSAT_PER_SAT == a.millisatoshis);
        }
        break;
    }

    case OP_SAT_ADD:
    {
        if (amount_sat_add(&out_s, sa, sb)) {
            assert(out_s.satoshis == sa.satoshis + sb.satoshis);
        }
        break;
    }

    case OP_SAT_SUB:
    {
        if (amount_sat_sub(&out_s, sa, sb)) {
            assert(out_s.satoshis == sa.satoshis - sb.satoshis);
        }
        break;
    }

    case OP_SAT_MUL:
    {
        if (amount_sat_mul(&out_s, sa, u64_param)) {
            assert(out_s.satoshis == sa.satoshis * u64_param);
        }
        break;
    }

    case OP_SAT_DIV:
    {
        if (u64_param == 0)
            break;
        out_s = amount_sat_div(sa, u64_param);
        assert(out_s.satoshis == sa.satoshis / u64_param);
        break;
    }

    case OP_SAT_SCALE:
    {
        // if (amount_sat_scale(&out_s, sa, f)) {
        //     double expect = sa.satoshis * f;
        //     assert(fabs((double)out_s.satoshis - expect) < 1.0);
        // }
        break;
    }

    case OP_FEE:
    {
        if (amount_msat_fee(&out_ms, a, (u32)(a.millisatoshis & UINT32_MAX), (u32)(b.millisatoshis & UINT32_MAX))) {
            assert(out_ms.millisatoshis >= (a.millisatoshis & UINT32_MAX));
        }
        break;
    }

    case OP_ADD_FEE:
    {
        u32 fee_base = (u32)(a.millisatoshis & UINT32_MAX);
        u32 fee_prop = (u32)(b.millisatoshis & UINT32_MAX);

        struct amount_msat original = a;
        struct amount_msat fee;

        if (amount_msat_fee(&fee, original, fee_base, fee_prop)) {
            struct amount_msat total;
            if (amount_msat_add(&total, original, fee)) {
                assert(amount_msat_greater_eq(total, fee));

                struct amount_msat expected_total;
                assert(amount_msat_add(&expected_total, original, fee));
                assert(amount_msat_eq(total, expected_total));

                a = total;
            }
        }
    }

    case OP_SUB_FEE:
    {        
        u32 fee_base = (u32)(a.millisatoshis & UINT32_MAX);
        u32 fee_prop = (u32)(b.millisatoshis & UINT32_MAX);
        struct amount_msat input = a;
        struct amount_msat output = amount_msat_sub_fee(input, fee_base, fee_prop);
        struct amount_msat fee;
        if (amount_msat_fee(&fee, output, fee_base, fee_prop)) {
            struct amount_msat sum;
            if (amount_msat_add(&sum, output, fee))
                assert(amount_msat_less_eq(sum, input));
        }
        break;
    }

    case OP_TX_FEE:
    {
        if (b.millisatoshis > SIZE_MAX)
            break;
        u32 fee_per_kw = (u32)(a.millisatoshis & UINT32_MAX);
        size_t weight = (size_t)(b.millisatoshis);

        /* weights > 2^32 are not real tx and hence, discarded */
        if (mul_overflows_u64(fee_per_kw, weight))
            break;
        struct amount_sat fee = amount_tx_fee(fee_per_kw, weight);
        u64 expected = (fee_per_kw * weight) / MSAT_PER_SAT;
        assert(fee.satoshis == expected);
        break;
    }

    case OP_FEERATE:
    {
        struct amount_sat fee = amount_msat_to_sat_round_down(a);
        size_t weight = (size_t)(b.millisatoshis);
        u32 feerate;
        if (weight && amount_feerate(&feerate, fee, weight)) {
            u64 expected = (fee.satoshis * MSAT_PER_SAT) / weight;
            assert(feerate == expected);
        }
        break;
    }

    default:
        assert(false && "unknown operation");
    }
}
