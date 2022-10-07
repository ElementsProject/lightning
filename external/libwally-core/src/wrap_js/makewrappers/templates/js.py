TEMPLATE = '''
try {
    var window = global.window || {};
} catch (e) { var window = {}; }

module.exports = {};

if (window.cordova) {
    var base64 = require('base64-js');

    module.exports.wally_hex_from_bytes = function (uintArray) {
        return uintArray.reduce(function (hex, i) {
            return hex + (i < 16 ? '0' : '') + i.toString(16);
        }, '');
    };

    !!list_of_cordova_funcs!!
} else {
    var wallycore = require('./build/!!build_type!!/wallycore');
    // nodejs
    !!list_of_nodejs_funcs!!
}
var _export = function(name, value) {
    Object.defineProperty(module.exports, name, {'value': value, 'writable': false});
}
var _zero = new Uint8Array([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]);
var _one = new Uint8Array([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01]);
_export('ZERO_64', _zero);
_export('ONE_64', _one);

'''

def _generate_cordovajs(funcname, func):
    args = []
    resolve_wrap = 'res'
    cur_out = 0
    for i, arg in enumerate(func.arguments):
        if (isinstance(arg, tuple)
            or 'out_bytes' in arg
            or arg in ['bip32_priv_out', 'bip32_pub_out']
        ):
            resolve_wrap = 'new Uint8Array(res)'
        if not isinstance(arg, tuple):
            if arg.startswith('const_bytes') or arg == 'bip32_in':
                args.append('base64.fromByteArray(_arguments[%s])' % i)
            elif arg.startswith('string') or arg.startswith('uint32_t'):
                args.append('_arguments[%s]' % i)
            elif arg in ['out_bytes_sized', 'out_bytes_fixedsized']:
                if getattr(func, 'out_size', None):
                    args.append(func.out_size)
                elif getattr(func, 'out_sizes', None):
                    args.append(func.out_sizes[cur_out])
                    cur_out += 1
                else:
                    args.append('_arguments[%s]' % i)
    return '''
        module.exports.%s = function () {
            var _arguments = arguments;
            return new Promise(function (resolve, reject) {
                window.cordova.exec(
                    function (res) { resolve(%s); },
                    reject, 'Wally', '%s', [%s]
                );
            });
        };
    ''' % (funcname, resolve_wrap, funcname, ', '.join(args))


def _generate_nodejs(funcname, func):
    add_args = ''
    wrapper = '%s'
    cur_out = 0
    postprocessing = []
    for i, arg in enumerate(func.arguments):
        if isinstance(arg, tuple) or arg in [
            'out_uint64_t', 'out_bytes_sized', 'out_bytes_fixedsized'
        ]:
            if getattr(func, 'out_sizes', None):
                postprocessing.append(
                    'res[%s] = new Uint8Array(res[%s].buffer);' % (cur_out, cur_out)
                )
                cur_out += 1
            else:
                # TODO: maybe worth simplifying to avoid having to pass this null argument:
                # (only required for arg being tuple, which never happens with out_size, hence
                #  no add_args in the `if` above)
                add_args = '_arguments.push(null);'
                wrapper = 'new Uint8Array(%s.buffer)'
        if arg in ['out_bytes_sized', 'out_bytes_fixedsized']:
            if getattr(func, 'out_size', None):
                add_args = '_arguments.push(%s);' % func.out_size
            elif getattr(func, 'out_sizes', None):
                add_args += '_arguments.push(%s);' % func.out_sizes[cur_out-1]
    wrapper = wrapper % ('wallycore.%s.apply(wallycore, _arguments)' % funcname)
    return ('''
        module.exports.%s = function () {
            var _arguments = [];
            _arguments.push.apply(_arguments, arguments);
            !!add_args!!
            var res = %s;
            !!posprocessing!!
            return Promise.resolve(res);
        }
    ''' % (funcname, wrapper)).replace(
        '!!add_args!!', add_args
    ).replace(
        '!!posprocessing!!', '\n'.join(postprocessing)
    )


def generate(functions, build_type):
    list_of_cordova_funcs = []
    list_of_nodejs_funcs = []
    for funcname, f in functions:
        list_of_cordova_funcs.append(_generate_cordovajs(funcname, f))
        list_of_nodejs_funcs.append(_generate_nodejs(funcname, f))
    return TEMPLATE.replace(
        '!!build_type!!', build_type
    ).replace(
         '!!list_of_cordova_funcs!!',
        '\n\n'.join(list_of_cordova_funcs)
    ).replace(
        '!!list_of_nodejs_funcs!!',
        '\n\n'.join(list_of_nodejs_funcs)
    )
    return TEMPLATE
