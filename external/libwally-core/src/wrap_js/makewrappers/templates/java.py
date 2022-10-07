TEMPLATE = '''package com.blockstream.libwally;

import java.nio.charset.Charset;
import java.util.Arrays;

import android.util.Base64;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

public class WallyCordova extends CordovaPlugin {
    @Override
    public boolean execute(
            final String action, final JSONArray args,
            final CallbackContext callbackContext) throws JSONException {

        !!java_cases!!

        return true;
    }
}
'''


def _generate_java(funcname, f):
    input_args = []
    output_args = []
    args = []
    output_assignment = ''
    postprocessing = ''
    for i, arg in enumerate(f.arguments):
        if isinstance(arg, tuple):
            output_args.append('byte[] res = new byte[%s];' % arg[1])
            args.append('res');
        elif arg == 'out_str_p':
            output_assignment = 'String res = '
        elif arg == 'out_bytes_sized':
            output_args.append('byte[] resIn = new byte[args.getInt(%s)];' % i)
            args.append('resIn');
            output_assignment = 'int len = '
            postprocessing = 'byte[] res = Arrays.copyOf(resIn, len);'
        elif arg == 'out_bytes_fixedsized':
            output_args.append('byte[] resIn = new byte[args.getInt(%s)];' % i)
            args.append('resIn');
            postprocessing = 'byte[] res = Arrays.copyOf(resIn, args.getInt(%s));' % i
        elif arg.startswith('const_bytes'):
            input_args.append(
                'byte[] input%s = '
                'Base64.decode(args.getString(%s), Base64.NO_WRAP);' % (
                    i, i
                )
            )
            args.append('input%s' % i)
        elif arg.startswith('uint32_t'):
            args.append('args.getLong(%s)' % i)
        elif arg.startswith('string'):
            args.append('args.getString(%s)' % i)
        elif arg == 'bip32_in':
            input_args.append((
                'Object inkey = Wally.bip32_key_unserialize(Base64.decode(args.getString(%s), Base64.NO_WRAP));'
            ) % i)
            args.append('inkey');
            postprocessing = 'Wally.bip32_key_free(inkey);'
        elif arg in ['bip32_pub_out', 'bip32_priv_out']:
            output_assignment = 'Object outkey = '
            flag = {'bip32_pub_out': 'BIP32_FLAG_KEY_PUBLIC',
                    'bip32_priv_out': 'BIP32_FLAG_KEY_PRIVATE'}[arg]
            postprocessing = (
                'byte[] res = Wally.bip32_key_serialize(outkey, Wally.%s);'
                'Wally.bip32_key_free(outkey);'
            ) % flag
    return ('''
        if (action.equals("%s")) {
            !!input_args!!
            !!output_args!!
            !!output_assignment!! Wally.%s(!!args!!);
            !!postprocessing!!
            PluginResult result = new PluginResult(PluginResult.Status.OK, res);
            callbackContext.sendPluginResult(result);
        }
    ''' % (funcname, f.wally_name or (funcname[len('wally_'):]
            if funcname.startswith('wally_') else funcname))).replace(
        '!!input_args!!', '\n'.join(input_args)
    ).replace(
        '!!output_args!!', '\n'.join(output_args)
    ).replace(
        '!!args!!', ', '.join(args)
    ).replace(
        '!!output_assignment!!', output_assignment
    ).replace(
        '!!postprocessing!!', postprocessing
    )


def generate(functions, build_type):
    java_cases = []
    for i, (funcname, f) in enumerate(functions):
        java_cases.append(_generate_java(funcname, f))
    return TEMPLATE.replace(
        '!!java_cases!!',
        ' else '.join(java_cases)
    )
