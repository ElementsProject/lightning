TEMPLATE='''#include <string>
#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type"
#endif
#if defined(__GNUC__) && __GNUC__ >= 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#include <nan.h>
#include <ccan/ccan/endian/endian.h>

#include "config.h"
#include "../include/wally_address.h"
#include "../include/wally_core.h"
#include "../include/wally_bip32.h"
#include "bip32_int.h"
#include "../include/wally_bip38.h"
#include "../include/wally_bip39.h"
#include "../include/wally_crypto.h"
#include "../include/wally_elements.h"
#include "../include/wally_script.h"
#include "../include/wally_transaction.h"
#include <vector>

namespace {

static struct wally_operations w_ops;

typedef v8::Local<v8::Object> LocalObject;

template<typename T>
static bool IsValid(const typename v8::Local<T>& local)
{
    return !local.IsEmpty() && !local->IsNull() && !local->IsUndefined();
}

template<typename T>
static bool IsValid(const typename Nan::Maybe<T>& maybe)
{
    return maybe.IsJust();
}

// Binary data is expected as objects supporting the JS Buffer interface
struct LocalBuffer {
    LocalBuffer(Nan::NAN_METHOD_ARGS_TYPE info, int n, int& ret)
        : mData(0), mLength(0)
    {
        Init(info[n], ret);
    }

    LocalBuffer(const v8::Local<v8::Value>& obj, int& ret)
        : mData(0), mLength(0)
    {
        Init(obj, ret);
    }

    void Init(const v8::Local<v8::Value>& obj, int& ret) {
        if (ret == WALLY_OK && IsValid(obj)) {
            if (!node::Buffer::HasInstance(obj))
                ret = WALLY_EINVAL;
            else {
                mBuffer = obj->ToObject(Nan::GetCurrentContext()).ToLocalChecked();
                if (IsValid(mBuffer)) {
                    mData = (unsigned char*) node::Buffer::Data(mBuffer);
                    mLength = node::Buffer::Length(mBuffer);
                }
            }
        }
    }

    LocalBuffer(size_t len, int& ret)
        : mData(0), mLength(0)
    {
        if (ret != WALLY_OK)
            return; // Do nothing, caller will already throw
        const Nan::MaybeLocal<v8::Object> local = Nan::NewBuffer(len);
        if (local.ToLocal(&mBuffer)) {
            mData = (unsigned char*) node::Buffer::Data(mBuffer);
            mLength = len;
        }
    }

    LocalObject mBuffer;
    unsigned char *mData;
    size_t mLength;
};

struct LocalArray {
    LocalArray(Nan::NAN_METHOD_ARGS_TYPE info, int n, int& ret)
    {
        Init(info[n], ret);
    }

    void Init(const v8::Local<v8::Value>& obj, int& ret) {
        if (ret != WALLY_OK)
            return;
        if (!IsValid(obj) || !obj->IsArray())
            ret = WALLY_EINVAL;
        else {
            mArray = obj->ToObject(Nan::GetCurrentContext()).ToLocalChecked();
            if (!IsValid(mArray))
                ret = WALLY_EINVAL;
        }
    }

    v8::Array& get() { return *reinterpret_cast<v8::Array *>(*mArray); }
    LocalObject mArray;
};


// uint32_t values are expected as normal JS numbers from 0 to 2^32-1
static uint32_t GetUInt32(Nan::NAN_METHOD_ARGS_TYPE info, int n, int& ret)
{
    uint32_t value = 0;
    if (ret == WALLY_OK) {
        if (!IsValid(info[n]) || !info[n]->IsUint32())
            ret = WALLY_EINVAL;
        else {
            Nan::Maybe<uint32_t> m = Nan::To<uint32_t>(info[n]);
            if (IsValid(m))
                value = m.FromJust();
            else
                ret = WALLY_EINVAL;
        }
    }
    return value;
}

#ifdef BUILD_ELEMENTS
static int32_t GetInt32(Nan::NAN_METHOD_ARGS_TYPE info, int n, int& ret)
{
    int value = 0;
    if (ret == WALLY_OK) {
        if (!IsValid(info[n]) || !info[n]->IsInt32())
            ret = WALLY_EINVAL;
        else {
            Nan::Maybe<int32_t> m = Nan::To<int32_t>(info[n]);
            if (IsValid(m))
                value = m.FromJust();
            else
                ret = WALLY_EINVAL;
        }
    }
    return value;
}
#endif

// uint64_t values are expected as an 8 byte buffer of big endian bytes
struct LocalUInt64 : public LocalBuffer {
    LocalUInt64(Nan::NAN_METHOD_ARGS_TYPE info, int n, int& ret)
        : LocalBuffer(info, n, ret)
    {
        DerivedInit(ret);
    }

    LocalUInt64(const v8::Local<v8::Value>& obj, int& ret)
        : LocalBuffer(obj, ret)
    {
        DerivedInit(ret);
    }

    void DerivedInit(int& ret) {
        mValue = 0; /* Prevent invalid warnings about uninitialised use */
        if (mData || mLength) {
            if (mLength != sizeof(mValue))
                ret = WALLY_EINVAL;
            else {
                memcpy(&mValue, mData, sizeof(mValue));
                mValue = be64_to_cpu(mValue);
            }
        } else if (ret == WALLY_OK)
            ret = WALLY_EINVAL; // Null not allowed for uint64_t values
    }
    uint64_t mValue;
};

static bool CheckException(Nan::NAN_METHOD_ARGS_TYPE info,
                           int ret, const char* errorText)
{
    switch (ret) {
    case WALLY_ERROR:
        Nan::ThrowError(errorText);
        return true;
    case WALLY_EINVAL:
        Nan::ThrowTypeError(errorText);
        return true;
    case WALLY_ENOMEM:
        Nan::ThrowError(errorText); // FIXME: Better Error?
        return true;
    }
    return false;
}

static void FreeMemoryCB(char *data, void *hint)
{
    if (data && hint)
        wally_bzero(data, reinterpret_cast<uint64_t>(hint));
    w_ops.free_fn(data);
}

static void FreeMemory(char *data, size_t size)
{
    if (data && size)
        wally_bzero(data, size);
    w_ops.free_fn(data);
}

static unsigned char* Allocate(uint32_t size, int& ret)
{
    unsigned char *res = 0;
    if (ret == WALLY_OK) {
        res = reinterpret_cast<unsigned char*>(w_ops.malloc_fn(size));
        if (!res)
            ret = WALLY_ENOMEM;
    }
    return res;
}

static LocalObject CopyBuffer(unsigned char* ptr, uint32_t size, int& ret)
{
    LocalObject res;
    if (ret == WALLY_OK) {
        Nan::MaybeLocal<v8::Object> buff;
        buff = Nan::CopyBuffer(reinterpret_cast<char*>(ptr), size);
        if (buff.IsEmpty()) {
            ret = WALLY_ENOMEM;
        } else
            res = buff.ToLocalChecked();
    }
    return res;
}

static LocalObject AllocateBuffer(unsigned char* ptr, uint32_t size, uint32_t allocated_size, int& ret)
{
    LocalObject res;
    if (ret == WALLY_OK) {
        void *hint = reinterpret_cast<void*>(allocated_size);
        Nan::MaybeLocal<v8::Object> buff;
        buff = Nan::NewBuffer(reinterpret_cast<char*>(ptr),
                              size, FreeMemoryCB, hint);
        if (buff.IsEmpty()) {
            ret = WALLY_ENOMEM;
            FreeMemoryCB(reinterpret_cast<char*>(ptr), hint);
        } else
            res = buff.ToLocalChecked();
    }
    return res;
}

static v8::Local<v8::Object> CreateWallyTxWitnessStack(wally_tx_witness_stack *witness_stack, int ret)
{
    v8::Local<v8::Object> res = Nan::New<v8::Object>();
    v8::Local<v8::Array> items = Nan::New<v8::Array>(witness_stack->num_items);

    Nan::Set(res, Nan::New("items").ToLocalChecked(), items);
    for(size_t i = 0; i < witness_stack->num_items; i++) {
        LocalObject item = CopyBuffer(witness_stack->items[i].witness,  witness_stack->items[i].witness_len, ret);
        Nan::Set(items, i, item);
    }

    Nan::Set(res, Nan::New("items_allocation_len").ToLocalChecked(), Nan::New<v8::Number>(witness_stack->items_allocation_len));

    return res;
}

static v8::Local<v8::Object> TransactionToObject(const struct wally_tx *tx, int ret)
{
    v8::Local<v8::Object> obj = Nan::New<v8::Object>();
    size_t i = 0;

    Nan::Set(obj, Nan::New("version").ToLocalChecked(), Nan::New<v8::Uint32>(tx->version));
    Nan::Set(obj, Nan::New("num_inputs").ToLocalChecked(), Nan::New<v8::Number>(tx->num_inputs));
    Nan::Set(obj, Nan::New("inputs_allocation_len").ToLocalChecked(), Nan::New<v8::Number>(tx->inputs_allocation_len));

    v8::Local<v8::Array> inputs = Nan::New<v8::Array>(tx->num_inputs);
    Nan::Set(obj, Nan::New("inputs").ToLocalChecked(), inputs);

    v8::Local<v8::Object> input;

    for(i = 0; i < tx->num_inputs; i++) {
        input = Nan::New<v8::Object>();
        Nan::Set(inputs, i, input);

        if(sizeof(tx->inputs[i].txhash) > 0) {
            LocalObject tx_hash = CopyBuffer(tx->inputs[i].txhash, WALLY_TXHASH_LEN, ret);
            Nan::Set(input, Nan::New("tx_hash").ToLocalChecked(), tx_hash);
        }

        Nan::Set(input, Nan::New("index").ToLocalChecked(), Nan::New<v8::Uint32>(tx->inputs[i].index));
        Nan::Set(input, Nan::New("sequence").ToLocalChecked(), Nan::New<v8::Uint32>(tx->inputs[i].sequence));

        if(tx->inputs[i].script_len > 0) {
            LocalObject script_pub = CopyBuffer(tx->inputs[i].script, tx->inputs[i].script_len, ret);
            Nan::Set(input, Nan::New("script_pub").ToLocalChecked(), script_pub);
        }

        if(tx->inputs[i].witness) {
            Nan::Set(input, Nan::New("witness").ToLocalChecked(), CreateWallyTxWitnessStack(tx->inputs[i].witness, ret));
        }

        Nan::Set(input, Nan::New("feature").ToLocalChecked(), Nan::New<v8::Number>(tx->inputs[i].features));
#ifdef BUILD_ELEMENTS
        if(sizeof(tx->inputs[i].blinding_nonce) > 0) {
            LocalObject blinding_nonce = CopyBuffer(tx->inputs[i].blinding_nonce, SHA256_LEN, ret);
            Nan::Set(input, Nan::New("blinding_nonce").ToLocalChecked(), blinding_nonce);
        }
        if(sizeof(tx->inputs[i].entropy) > 0) {
            LocalObject entropy = CopyBuffer(tx->inputs[i].entropy, SHA256_LEN, ret);
            Nan::Set(input, Nan::New("entropy").ToLocalChecked(), entropy);
        }
        if(tx->inputs[i].issuance_amount_len > 0) {
            LocalObject issuance_amount = CopyBuffer(tx->inputs[i].issuance_amount, tx->inputs[i].issuance_amount_len, ret);
            Nan::Set(input, Nan::New("issuance_amount").ToLocalChecked(), issuance_amount);
        }
        if(tx->inputs[i].inflation_keys_len > 0) {
            LocalObject inflation_keys = CopyBuffer(tx->inputs[i].inflation_keys, tx->inputs[i].inflation_keys_len, ret);
            Nan::Set(input, Nan::New("inflation_keys").ToLocalChecked(), inflation_keys);
        }
        if(tx->inputs[i].issuance_amount_rangeproof_len > 0) {
            LocalObject issuance_amount_rangeproof = CopyBuffer(tx->inputs[i].issuance_amount_rangeproof, tx->inputs[i].issuance_amount_rangeproof_len, ret);
            Nan::Set(input, Nan::New("issuance_amount_rangeproof").ToLocalChecked(), issuance_amount_rangeproof);
        }
        if(tx->inputs[i].inflation_keys_rangeproof_len > 0) {
            LocalObject inflation_keys_rangeproof = CopyBuffer(tx->inputs[i].inflation_keys_rangeproof, tx->inputs[i].inflation_keys_rangeproof_len, ret);
            Nan::Set(input, Nan::New("inflation_keys_rangeproof").ToLocalChecked(), inflation_keys_rangeproof);
        }

        if(tx->inputs[i].pegin_witness) {
            Nan::Set(input, Nan::New("pegin_witness").ToLocalChecked(), CreateWallyTxWitnessStack(tx->inputs[i].pegin_witness, ret));
        }
#endif /* BUILD_ELEMENTS */
    }

    Nan::Set(obj, Nan::New("num_outputs").ToLocalChecked(), Nan::New<v8::Number>(tx->num_outputs));
    Nan::Set(obj, Nan::New("outputs_allocation_len").ToLocalChecked(), Nan::New<v8::Number>(tx->outputs_allocation_len));
    v8::Local<v8::Array> outputs = Nan::New<v8::Array>(tx->num_outputs);
    Nan::Set(obj, Nan::New("outputs").ToLocalChecked(), outputs);

    v8::Local<v8::Object> output;

    for(i = 0; i < tx->num_outputs; i++) {
        output = Nan::New<v8::Object>();
        Nan::Set(outputs, i, output);

        if(tx->outputs[i].satoshi > 0) {
            Nan::Set(output, Nan::New("satoshi").ToLocalChecked(), Nan::New<v8::String>(std::to_string(tx->outputs[i].satoshi)).ToLocalChecked());
        } else {
            Nan::Set(output, Nan::New("satoshi").ToLocalChecked(), Nan::New<v8::String>(std::to_string(0)).ToLocalChecked());
        }

        if(tx->outputs[i].script_len > 0) {
            LocalObject scriptPubKey = CopyBuffer(tx->outputs[i].script, (uint32_t)tx->outputs[i].script_len, ret);
            Nan::Set(output, Nan::New("scriptPubKey").ToLocalChecked(), scriptPubKey);
        }

        Nan::Set(output, Nan::New("feature").ToLocalChecked(), Nan::New<v8::Number>(tx->outputs[i].features));
#ifdef BUILD_ELEMENTS
        if(tx->outputs[i].asset_len > 0) {
            LocalObject asset = CopyBuffer(tx->outputs[i].asset, (uint32_t)tx->outputs[i].asset_len, ret);
            Nan::Set(output, Nan::New("asset").ToLocalChecked(), asset);
        }
        if(tx->outputs[i].value_len > 0) {
            LocalObject value = CopyBuffer(tx->outputs[i].value, (uint32_t)tx->outputs[i].value_len, ret);
            Nan::Set(output, Nan::New("value").ToLocalChecked(), value);
        }
        if(tx->outputs[i].nonce_len > 0) {
            LocalObject nonce = CopyBuffer(tx->outputs[i].nonce, (uint32_t)tx->outputs[i].nonce_len, ret);
            Nan::Set(output, Nan::New("nonce").ToLocalChecked(), nonce);
        }
        if(tx->outputs[i].surjectionproof_len > 0) {
            LocalObject surjectionproof = CopyBuffer(tx->outputs[i].surjectionproof, (uint32_t)tx->outputs[i].surjectionproof_len, ret);
            Nan::Set(output, Nan::New("surjectionproof").ToLocalChecked(), surjectionproof);
        }
        if(tx->outputs[i].rangeproof_len > 0) {
            LocalObject rangeproof = CopyBuffer(tx->outputs[i].rangeproof, (uint32_t)tx->outputs[i].rangeproof_len, ret);
            Nan::Set(output, Nan::New("rangeproof").ToLocalChecked(), rangeproof);
        }
#endif /* BUILD_ELEMENTS */
    }

    Nan::Set(obj, Nan::New("lock_time").ToLocalChecked(), Nan::New<v8::Uint32>(tx->locktime));

    int wally_ret;
    size_t weight = 0;
    wally_ret = wally_tx_get_weight(tx, &weight);
    if (wally_ret == WALLY_OK)
        Nan::Set(obj, Nan::New("weight").ToLocalChecked(), Nan::New<v8::Uint32>(static_cast<uint32_t>(weight)));

    size_t vsize = 0;
    wally_ret = wally_tx_get_vsize(tx, &vsize);
    if (wally_ret == WALLY_OK)
        Nan::Set(obj, Nan::New("vsize").ToLocalChecked(), Nan::New<v8::Uint32>(static_cast<uint32_t>(vsize)));

    return obj;
}

} // namespace

!!nan_impl!!

NAN_MODULE_INIT(Init) {
    w_ops.struct_size = sizeof(w_ops);
    wally_get_operations(&w_ops);
    !!nan_decl!!
}

NODE_MODULE(wallycore, Init)

#if __clang__
#pragma clang diagnostic pop
#endif
#if defined(__GNUC__) && __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif'''

def _generate_nan(funcname, f):
    input_args = []
    output_args = []
    args = []
    result_wrap = 'res'
    postprocessing = []
    num_outs = len([arg for arg in f.arguments if 'out' in arg])
    if num_outs > 1:
        cur_out = 0
        input_args.extend([
            'v8::Local<v8::Array> res;',
            'if (ret == WALLY_OK) {',
            '    res = Nan::New<v8::Array>(%s);' % num_outs,
            '    if (!IsValid(res))',
            '       ret = WALLY_ENOMEM;',
            '}',
        ])
    for i, arg in enumerate(f.arguments):
        if isinstance(arg, tuple):
            # Fixed output array size
            output_args.append('LocalBuffer res(%s, ret);' % arg[1])
            output_args.append('if (ret == WALLY_OK && !res.mLength) ret = WALLY_ENOMEM;')
            args.append('res.mData')
            args.append('res.mLength')
            result_wrap = 'res.mBuffer'
        elif arg.startswith('const_bytes'):
            input_args.append('LocalBuffer arg%s(info, %s, ret);' % (i, i))
            args.append('arg%s.mData' % i)
            args.append('arg%s.mLength' % i)
        elif arg.startswith('out_is_success'):
            postprocessing.extend([
                'bool is_success = (ret == WALLY_OK) ? true : false;',
                'v8::Local<v8::Boolean> res = Nan::New(is_success);',
                'ret = WALLY_OK;  // reset '
            ])
        elif arg.startswith('out_bool_by_size_t'):
            input_args.extend([
                'size_t out_size%s = 0;' % (i),
            ])
            args.append('&out_size%s' % i)
            postprocessing.extend([
                'bool is_checked%s = (out_size%s == 0) ? false : true;' % (i, i),
                'v8::Local<v8::Boolean> res = Nan::New(is_checked%s);' % (i),
            ])
        elif arg.startswith('uint32_t'):
            input_args.append('uint32_t arg%s = GetUInt32(info, %s, ret);' % (i, i))
            args.append('arg%s' % i)
        elif arg.startswith('int'):
            input_args.append('int32_t arg%s = GetInt32(info, %s, ret);' % (i, i))
            args.append('arg%s' % i)
        elif arg.startswith('const_char'):
            input_args.extend([
                'std::string info%s = *Nan::Utf8String(info[%s]);' % (i, i),
                'char* char%s = new char[info%s.size() + 1];' % (i, i),
                'std::char_traits<char>::copy(char%s, info%s.c_str(), info%s.size() + 1);' % (i, i, i),
            ])
            args.append('char%s' % i)
            postprocessing.extend([
                'if (char%s)' % i,
                '    delete[] char%s;' % i,
            ])
        elif arg.startswith('string'):
            args.append('*Nan::Utf8String(info[%s])' % i)
        elif arg.startswith('const_uint64s'):
            input_args.extend([
                'std::vector<uint64_t> be64array%s;' % i,
                'LocalArray arr%s(info, %s, ret);' % (i, i),
                'if (ret == WALLY_OK) {',
                '    const size_t len = arr%s.get().Length();' % i,
                '    be64array%s.reserve(len);' % i,
                '    for (size_t i = 0; i < len && ret == WALLY_OK; ++i)',
                '        be64array%s.push_back(LocalUInt64(arr%s.get().Get(Nan::GetCurrentContext(), i).ToLocalChecked(), ret).mValue);' % (i, i),
                '}',
            ])
            postprocessing.extend([
                'if (!be64array%s.empty())' % i,
                '    wally_bzero(&be64array%s[0], be64array%s.size());' % (i, i)
            ])
            args.append('be64array%s.empty() ? 0 : &be64array%s[0]' % (i, i))
            args.append('be64array%s.size()' % i)
        elif arg.startswith('uint64_t'):
            input_args.append('LocalUInt64 arg%s(info, %s, ret);' % (i, i))
            args.append('arg%s.mValue' % i)
        elif arg == 'out_str_p':
            output_args.append('char *result_ptr = 0;')
            args.append('&result_ptr')
            postprocessing.extend([
                'v8::Local<v8::String> str_res;',
                'if (ret == WALLY_OK) {',
                '    str_res = Nan::New<v8::String>(result_ptr, -1).ToLocalChecked();',
                '    wally_free_string(result_ptr);',
                '    if (!IsValid(str_res))',
                '        ret = WALLY_ENOMEM;',
                '}',
            ])
            result_wrap = 'str_res'
        elif arg.startswith('out_bytes_sized'):
            output_args.extend([
                'const uint32_t res_size = GetUInt32(info, %s, ret);' % i,
                'unsigned char *res_ptr = Allocate(res_size, ret);',
                'size_t out_size = 0;'
            ])
            args.append('res_ptr')
            args.append('res_size')
            args.append('&out_size')
            postprocessing.extend([
                'if (ret != WALLY_OK || out_size > res_size) {',
                '    FreeMemory(reinterpret_cast<char *>(res_ptr), res_size);',
                '    ret = ret == WALLY_OK ? WALLY_ERROR : ret;',
                '}',
                'LocalObject res = AllocateBuffer(res_ptr, out_size, res_size, ret);',
            ])
        elif arg == 'out_bytes_fixedsized':
            output_args.extend([
                'const uint32_t res_size%s = GetUInt32(info, %s, ret);' % (i, i),
                'unsigned char *res_ptr%s = Allocate(res_size%s, ret);' % (i, i),
                'LocalObject res%s = AllocateBuffer(res_ptr%s, res_size%s, res_size%s, ret);' % (i, i, i, i),
            ])
            args.append('res_ptr%s' % i)
            args.append('res_size%s' % i)
            if num_outs > 1:
                postprocessing.extend([
                    'if (ret == WALLY_OK)',
                    '    if (!Nan::Set(res, %s, res%s).FromMaybe(false))' % (cur_out, i),
                    '        ret = WALLY_ERROR;',
                ])
                cur_out += 1
            else:
                result_wrap = 'res%s' % i
        elif arg == 'out_uint64_t':
            assert num_outs > 1  # wally_asset_unblind is the only func using this type
            output_args.extend([
                'unsigned char *res_ptr%s = Allocate(sizeof(uint64_t), ret);' % i,
                'uint64_t *be64%s = reinterpret_cast<uint64_t *>(res_ptr%s);' % (i, i),
            ])
            args.append('be64%s' % i)
            postprocessing.extend([
                'if (ret == WALLY_OK) {',
                '    *be64%s = cpu_to_be64(*be64%s);' % (i, i),
                '}',
                'LocalObject res%s = CopyBuffer(res_ptr%s, sizeof(uint64_t), ret);' % (i, i),
                'FreeMemory(reinterpret_cast<char *>(res_ptr%s), sizeof(uint64_t));'% (i),
                'if (ret == WALLY_OK) {',
                '    if (!Nan::Set(res, %s, res%s).FromMaybe(false)) ' % (cur_out, i),
                '        ret = WALLY_ERROR;',
                '}',
            ])
            cur_out += 1
        elif arg == 'bip32_in':
            input_args.append((
                'ext_key* inkey;'
                'const LocalObject buf = info[%s]->ToObject(Nan::GetCurrentContext()).ToLocalChecked();'
                'unsigned char* inbuf = (unsigned char*) node::Buffer::Data(buf);'
                'bip32_key_unserialize_alloc(inbuf, node::Buffer::Length(buf), &inkey);'
            ) % (i))
            args.append('inkey')
            postprocessing.append('bip32_key_free(inkey);')
        elif arg in ['bip32_pub_out', 'bip32_priv_out']:
            output_args.append(
                'ext_key *outkey;'
                'LocalObject res = Nan::NewBuffer(BIP32_SERIALIZED_LEN).ToLocalChecked();'
                'unsigned char *out = (unsigned char*) node::Buffer::Data(res);'
            )
            args.append('&outkey')
            flag = {'bip32_pub_out': 'BIP32_FLAG_KEY_PUBLIC',
                    'bip32_priv_out': 'BIP32_FLAG_KEY_PRIVATE'}[arg]
            postprocessing.append('bip32_key_serialize(outkey, %s, out, BIP32_SERIALIZED_LEN);' % flag)
            postprocessing.append('bip32_key_free(outkey);')
        elif arg in ['bip39_words_lang_in']:
            input_args.append((
                'struct words *wordlist;'
                'if (ret == WALLY_OK)'
                '    ret = bip39_get_wordlist(*Nan::Utf8String(info[%s]), &wordlist);'
            ) % (i))
            args.append('wordlist')
        elif arg == 'tx_out':
            input_args.append('struct wally_tx *tx_out%s = NULL;' % i)
            args.append('&tx_out%s' % i)
            postprocessing.extend([
                'v8::Local<v8::Object> res;',
                'if (ret == WALLY_OK) {',
                '    res = TransactionToObject(tx_out%s, ret);' % i,
                '    wally_tx_free(tx_out%s);'% i,
                '}',
            ])
        else:
            assert False, 'unknown argument type'

    call_name = (f.wally_name or funcname) + ('_alloc' if f.nodejs_append_alloc else '')
    return ('''
NAN_METHOD(%s) {
    int ret = WALLY_OK;
    !!input_args!!
    !!output_args!!
    if (ret == WALLY_OK)
        ret = %s(!!args!!);
    !!postprocessing!!
    if (!CheckException(info, ret, "%s"))
        info.GetReturnValue().Set(%s);
}
''' % (funcname, call_name, funcname, result_wrap)).replace(
        '!!input_args!!', '\n    '.join(input_args)
    ).replace(
        '!!output_args!!', '\n    '.join(output_args)
    ).replace(
        '!!args!!', ', '.join(args)
    ).replace(
        '!!postprocessing!!', '\n    '.join(postprocessing)
    )

def generate(functions, build_type):
    nan_implementations = []
    nan_declarations = []
    nan_declarations.append('using Nan::Export;')
    for i, (funcname, f) in enumerate(functions):
        nan_implementations.append(_generate_nan(funcname, f))
        nan_declarations.append('NAN_EXPORT(target, %s);' % funcname)
    return TEMPLATE.replace(
        '!!nan_impl!!',
        ''.join(nan_implementations)
    ).replace(
        '!!nan_decl!!',
        '\n    '.join(nan_declarations)
    )
