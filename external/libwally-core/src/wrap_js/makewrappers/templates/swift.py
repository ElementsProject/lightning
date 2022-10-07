
TEMPLATE = '''import Wally

@objc(WallyCordova) class WallyCordova : CDVPlugin {
    !!swift_cases!!
}'''


def _generate_swift(funcname, f):
    input_args = []
    output_args = []
    args = []
    postprocessing = []
    result_wrap = 'result'
    for i, arg in enumerate(f.arguments):
        if isinstance(arg, tuple):
            output_args.append(
                'let resultSwift = [UInt8](repeating: 0, count: %s);'
                'let resultPtr = UnsafeMutablePointer<UInt8>(mutating: resultSwift);' % arg[1])
            args.append('resultPtr')
            args.append(str(arg[1]))
            postprocessing.append('let result = resultSwift.map({ (i) -> NSValue in return NSNumber(value: i) })');
        elif arg.startswith('const_bytes'):
            input_args.append(
                '''let array_%s_B64 = command.argument(at: %s) as! NSString as String;
                let array_%s_Data = NSData(
                    base64Encoded: array_%s_B64, options: NSData.Base64DecodingOptions.init(rawValue: 0));
                let array_%s = [UInt8](repeating: 0, count: array_%s_Data!.length);
                array_%s_Data?.getBytes(
                    UnsafeMutableRawPointer(mutating: array_%s),
                    range: NSRange(location: 0, length: array_%s_Data!.length));
                let array_%s_Ptr = UnsafeMutablePointer<UInt8>(mutating: array_%s);'''  % tuple(
                    [i]*11
                )
            )
            args.append('array_%s_Ptr' % i)
            args.append('array_%s_Data!.length' % i)
        elif arg.startswith('uint32_t'):
            args.append('(command.argument(at: %s) as! NSNumber).uint32Value' % i)
        elif arg.startswith('string'):
            args.append('command.argument(at: %s) as! NSString as String' % i)
        elif arg == 'out_str_p':
            output_args.append('var result_Ptr : UnsafeMutablePointer<CChar>? = nil;')
            args.append('&result_Ptr')
            result_wrap = 'String.init(validatingUTF8: result_Ptr!)'
        elif arg == 'out_bytes_sized':
            output_args.extend([
                'let inSize = (command.argument(at: %s) as! NSNumber).intValue;' % i,
                'let resultSwift = [UInt8](repeating: 0, count: inSize);',
                'let resultPtr = UnsafeMutablePointer<UInt8>(mutating: resultSwift);',
                'var outSize : size_t = 0;'
            ])
            args.append('resultPtr')
            args.append('inSize')
            args.append('&outSize')
            postprocessing.append('let result = resultSwift.prefix(upTo: outSize).map({ (i) -> NSValue in return NSNumber(value: i) })');
        elif arg == 'out_bytes_fixedsized':
            output_args.extend([
                'let inSize = (command.argument(at: %s) as! NSNumber).intValue;' % i,
                'let resultSwift = [UInt8](repeating: 0, count: inSize);',
                'let resultPtr = UnsafeMutablePointer<UInt8>(mutating: resultSwift);',
            ])
            args.append('resultPtr')
            args.append('inSize')
            postprocessing.append('let result = resultSwift.map({ (i) -> NSValue in return NSNumber(value: i) })');
        elif arg == 'bip32_in':
            input_args.append((
                '''let array_%s_B64 = command.argument(at: %s) as! NSString as String;
                let array_%s_Data = NSData(
                    base64Encoded: array_%s_B64, options: NSData.Base64DecodingOptions.init(rawValue: 0));
                let array_%s = [UInt8](repeating: 0, count: array_%s_Data!.length);
                array_%s_Data?.getBytes(
                    UnsafeMutableRawPointer(mutating: array_%s),
                    range: NSRange(location: 0, length: array_%s_Data!.length));
                let array_%s_Ptr = UnsafeMutablePointer<UInt8>(mutating: array_%s);

                var inkey: UnsafePointer<Wally.ext_key>?;
                Wally.bip32_key_unserialize_alloc(array_%s_Ptr, array_%s_Data!.length, &inkey);
            ''') % tuple(
                [i]*13
            ))
            args.append('inkey');
            postprocessing.append('Wally.bip32_key_free(inkey);')
        elif arg in ['bip32_pub_out', 'bip32_priv_out']:
            output_args.extend([
                'var outkey: UnsafePointer<Wally.ext_key>?;',
                'let resultSwift = [UInt8](repeating: 0, count: Int(Wally.BIP32_SERIALIZED_LEN));',
                'let resultPtr = UnsafeMutablePointer<UInt8>(mutating: resultSwift);',
            ])
            args.append('&outkey')
            flag = {'bip32_pub_out': 'BIP32_FLAG_KEY_PUBLIC',
                    'bip32_priv_out': 'BIP32_FLAG_KEY_PRIVATE'}[arg]
            postprocessing.append('Wally.bip32_key_serialize(outkey, UInt32(Wally.%s), resultPtr, Int(Wally.BIP32_SERIALIZED_LEN));' % flag)
            postprocessing.append('Wally.bip32_key_free(outkey);')
            postprocessing.append('let result = resultSwift.map({ (i) -> NSValue in return NSNumber(value: i) })');
    return ('''
        func %s(_ command: CDVInvokedUrlCommand) {
            !!input_args!!
            !!output_args!!
            Wally.%s(!!args!!);
            !!postprocessing!!
            let pluginResult = CDVPluginResult(
                status: CDVCommandStatus_OK,
                messageAs: %s
            )
            commandDelegate!.send(
                pluginResult, callbackId:command.callbackId
            )
        }
    ''' % (funcname,
           (f.wally_name or funcname) + ('_alloc' if f.nodejs_append_alloc else ''),
           result_wrap)).replace(
        '!!input_args!!', '\n'.join(input_args)
    ).replace(
        '!!output_args!!', '\n'.join(output_args)
    ).replace(
        '!!args!!', ', '.join(args)
    ).replace(
        '!!postprocessing!!', '\n'.join(postprocessing)
    )


def generate(functions, build_type):
    swift_cases = []
    for i, (funcname, f) in enumerate(functions):
        swift_cases.append(_generate_swift(funcname, f))
    return TEMPLATE.replace(
        '!!swift_cases!!',
        ''.join(swift_cases)
    )
