#include "config.h"

#include <wally_crypto.h>
#include <wally_transaction.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static const char *asset_issuance_hex =
    "010000000001a530c0e71eac524e367c12af33da41f70ac7d2521f53ccea1ed6d0c910c4cd500000008000ffffffff000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f01000775f05a074000010000000000000000640125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a500000015100000000";
static const char *asset_issuance_sighash_hex = "6b80cb95c4e55a103f2defb33a03e7bce8ee94c8d8cfbac5c3165b278eca2c17";

static const char *wit_hex = "0100000001014e045b7e6765d2496759573fdf8b1a0654b2e37854e103b3e06d5483fa3342520100000000ffffffff03014ef03cd34de2960dae84cbc9cd331dfcfc43bd25211277ddcdfc3dc5ec2b281a01000000000000271000000b27ad9fecdd364999ebe74f4b4a957df17d674a70c1a70c148a1a5095a0cf63e209e7bc1795e9fc4f621ddd0da5cb4929d4fecf203a306c3c05b8b7efb635bcd2900017a914014207bc736cc9dc6987cfa8bd35eb42cc7c8f17870a10eb8af2226c6b86828129278d49b886fc7644ef9191be99d76687735bfd8e6609840bfd776976b4096371a5e6bee6b579e6fb713133f501f14782034dcd5034c10017a9146bb73a0d85b06239dff9ceeaca6217f2c357688a870000000000000000000043010001f1ba4c6db37e3700a72791c8c29d4ea5ba1e5c9bf97697a81856d010027bfd46bbdf7c6b20118d5ae45490c89278fe41e4be2e66b2bf3bd90832e30d45bceb54fd0c0a601f00000000000000015e750af13502a03c3619e927c91fa2d24d5467d5e1f77b7f195ad430406b90f1d378acae0611654efa9e089f40d56868ae7590ed07b3d5621c74a12b0b8250f131788b69c04870b7ce293604c9f0cbf3afa63e2d7207b0c831ae6256e32d6dde356c8208a7546b8d11b40af53fe9b33715e4fae19e1e97c64fa890e9c99dfe9b8054560584d22315a9156f7bdde2fc51e7cb1a3b8996a510c1d94a5f2b3aa47a878bcc684bf5936c2e8376fee350bfff127fac64542174dfdd2495f592584ea5b8ca5d72aeb5a7c9d07d57f1c2a5e290fbd151d5810cfbd653c1619d40e93cc3403665e1ec4ee9a84435450f558618e9f0a4d99febd412eeb3e87df568a4b26a9fd22c2f6227aa8282095336dbaf2250142b9eaa02d33bdbddb75b7f97bf9a18ecae602b53e28ce70086d6d696a923d90c11c07e9f0d0b0d7acf8f6afe44251b40dcd874b57de6197cad19c00fb5e92013ffc2c94d18f410815cd12be9f9471f9d8f5d9ab68189cf9b7b101f196fb1aec1c4c481d6ea98ed6093d2eccc17b7aff3912d20f29b2522d1a7342243252e09295da59c49e0bab12b4c30956c4de4e8a00c133d64a524c72f1189b7ec0f3f98a8e6ffc9e290aa05d7bad41942c3c6e2ec9937a3114cfd0940fd1902ad4a170122036f8ce22e30cb1691f4bc33ebd2ce7b1aa46d69aa86519966b06a618cbd1f563c762e64c9e63516149aee85366bfa5e3aa568b9a57ecc209ae72a2501f76183679652f2d7fd1df36d63581de75ef4ffb082ef4e7361453f93be4cc46920e5555b20ebc8aa9720972d0c28a3ec7d6f733ef8c96761b9311d7f3b3e084e5aae5aa22f274c3682554a8aaacb8d2057403c3e30bdf6689dda3cfe5367898158f72af666ca4e44c56a77e63e78e22833935471d08ceaab009510bf2f1f12e824f67bd13e80dcfccf34ce7bb84e266875d62b83b78fcac0c99879891f183c54b6b9c0445c174f0617622e06541672c7e7291de01cfb8732cc8a0c38f37442b505e2d1d3e7a50931cb96aee38daaf952356202e72f9f522d455677a358972832c2eb7e59ad70c3db8dade3c2c3f93c16dccacbdf5ec66b1c0f83e73ff484e7ae6a855f1825fbc21763a516ef5672a02ded2315994137acac567d60cff30e1a106d9b2c255d16c2c0e9a38d5e3ae249862023acad6c2c5f9091899841beb178b57ec19136920aa29cff89e05f6f4f51faf5b6624b54daf3b02949fd705c11e75397abbf68be2a9cdf96479ca1edd86ae7eec3285ebc3335c53ba007a4e4f9d0c650b79e3b09d2ef05d75a60d8b4fd4b7f52f662affd96ce2a93bc60061ec4d868c28d34f7fc7b733cf19aaa660c2adb93aa97fae2ad21e960032c50ea5cfab14d4ef68e363cdff730e0ad62b10fec6c0aad87b002cdab6a960b04ce31a20fcce9c4747b8b1260fd498166b3b3f9cc7f3bd182b417fd5d2157e0ad2a85d5eacc8c6eb454760b925751a35c73c52172df0c36f63a92c4f49593154eff4dd526086c732d4178ad2a554e89390cbd833ca698dfba063a7c009bbe34941146727d46e1fc2d911d71e28808eb41e2c7d865f369dc2ff08421491decb6fc14fa538738e1784fec18cc8a024794282457aff53df4242fda599a1f02002502f96783ea55c61eafd7f8d898081f79e6431a2d14908ef6ce8b3c9865a26e30556b9030e077cb145a2e0874e03b09847265cfcb0dc9e87456e0bae75413ac878785a06aa8d7b77855fd734cc85da07abd1e396d8ec46f6a9d45c5097dd1733cdb0530986ea5057305007df18ad5487da229a501fda1160130ef7cb50e02e8c3a2062dd2f5776c3c9ff30e10d227963b0989bdaf920edbac75be9fba45d628d094704afd18df53f5d4ffd47c031f1cec6146772e771aece3639cb4654d83193efd492c84c1302a1f163a4e67ec915927029503f1889d18bc646f0f1458614ace319f32677aa4c6e57dc780b9fec68e5bdb7796a8730ce6deef2ea160e4b7b22ee6643b83801e1fed3d513fc74ecf6de2a0ddf2224f8ccdcdec4f0856e85ed1876d9719442c94075cacebdc1960cddd61ca13d2eb703fcc2f596f6cb85ffab49aaeb23d073ce946f63687ad5c81ef597f867c899c4dc1b1be7d3e257d1a7becfd282491f9aa6fc8a0eba09c282cd7d2ee90b9f7d87b8a396b181d539b033a98f47b328d0f16d5e5c643719ef0c0c3c9654122c26fbc9027c4483430687b89fcf56e22f725ed5dfff1a10202e19fd701a8d865cd310b817f4299488c5ce40fd5b32241596a895ff244f00feca737f236967436605c011ef445de837d5e30c52be104f9f539986215a6788de4d3b4f58a7766d67b48ea42b3c034bcc3fb57254469b7b39465e19fcce00a89e0eaa63d694fa7954ae2142e32ed5ee031309169e2a0dfc92220ce8847cc8ca3153db24865d2589a9f0ec53add24c8646667014169f1f55363aaa16996458051447155af15f936b1b5844c1f008923c6b0c816c696c80dfc1564d1e0a01f15b820d2d76e65b0f0ad571e7a8765968e06ee51a9378b069ad6082d8f366fc2fba90b010dc48650f782d51a0e483fd00dc364a509bc1c265a3bda08402d482a7704b2c13937544e2dba2ce246836fee17ab18529434fa04e2a3040857d9754962e625a41dbc2daa5ee08590857168ae87d58c33299c11f33a23a525d3e57c4e06fbb3e69a156b54097a59dc5aac192a4fe4027e9d07cd8bd285f348abbd4df85ed0a76861fad3301bc8418e9f9fa482cc828c9c6208735f70e5c4b5a422f1c71e6c9b4b06a40cecb6cabe551d2499409d7add781f812bcffaaaf8ecdfe18822102b1771128a8a2fd53f6360ad4c5999054d444ed093bd7154111c73ece89b212f18ec3e4a5bc0b3d2237df5604696a434c5b0b4287991db79e764a51d5601c1a7cf54ee350cb7162e91ae316c636bab2aa5e24aaeae862614696eb1e23bb5a689c5b8dc1e00ebd12a0c7e1a78d98fdf3fb1c1ca298037ddfe9989742eab08ff7ef1abbca022a1cce7cf21acdca73531658c0789185a48f3080540a8f41345db1b6f02d6dd378c10b1c69dba68d5d2854ed134f51aab60ea516137750ee4188808c4ba173257820a2176aa2c0131c17f6e798c9a64010cf7cf7eacc29e5275bfd9c64899d263905e79c0c7679066afd106586562fe60d2468fb723db8448827d03a019f5e615d3a76348494053f1a9fddb94615f73a18c922c91e18a9c740c8b77257953717dd079b97d5b6cd4b90eaea65b4f94ab71045539d649990bfe2802d9373daac441f1b33cafd0abbb8d73e43aff3cc2cf5b49d0cf99faa7b102332b9d9a11ebc15c160a507863a24ffa70006e69e0d8385f7e219a771e29a1900c48b20590362e84f1c266968795bc6b96f1b6e963398a12bb9b96f5139b379b4cb8a2a14171d181626ecdb3252a2c77e4dc11caa7c36bb450d49c94590b61059da625cf613fb367a9cf4ca5f82f2772f9b57eef79fd501da26c3a12d11dbcf294729ca637bf48d6e9103d19b2f90f6f05f8f23011017a9646f275e925688e805a107834de24f99fec23e8b4830ae2cdcab98629b81ca3b9c6a1d7bb1d42d4e60c96db41b08c816a1c46441250861d9dd13987bf3f430100014c55a623f706d8e2295c9cdf59f041c9e8a317c4a97c02569238d230d477179b42ea7dcd3e66f5017dc32821ec2135492330ca2cab17fe24507e9b7f0693a372fd0c0a601f00000000000000010a7b0b3a6bb8cdff5dc6814a2844f80881226614f416680c6dd295f47d5a93d917f292d3c2c596ce8a8d342a65a100e59024dee29b90dfcdf563528e25c728895753f76f95a03c56f2d2aa0dc04bcd42e0f8f8ca6e77c384339c547f41652f0d2370d8de35ba96fec6ee45256886383659673f9fb6c32457190f745809826f33af34552fa65b1f631d4d3a23c09edc02933643d2fab5b427ebee6632b81463944a39d61b5549750792232b0b0bd3074bdd6c4efa15d9287d5ccad46fc10b0adf2a22caea19c1f3271030a749a4fd3a69d64972e9a9c91f30e9b3f2d48a47858eb25478ea14ea9bb686d34ef7598fba8379184b9b69909728149308171003111a68f918174cbfbc814f8150473297bf5b90da08efa789d1ffd45aa89c87477eee1a531670b6316e0b6201293e0109cffb394d2647d26009124273559fafea5126b9abf3038b33949678f593e03399baa4fcb81d3a508f3ca32a510ba7740c3639e3295da9b8fd9d532bd8c42b415c8e997a4851a323f65e3177e09e032264e69313663793e802ddeef5fee4d8b070b059f9bd16a6b8ba15a80ed020355d6d8ae5199654f61a54850d321a950ae719db87dca6607ea88cafd7efc3946b54726acc226e6ed4de287bfb697854176c09411b21d65d95006c4d6fc0a54e6d0bc93896c658880fb252a12de84a6f359e9a00912fe8847afc2b8fc1476c649ec910d6d6fc4df5ea40547cc4c6ca4dc58f19845820839e9ea8d740f81160f7ff55c194773e4445614055c569dd525f3b8f9d81fc8c756addd54d948c47d819e6e02cc2dbd184636cb1beafccd4987320ad7a885397edef25df86dc88c8222ffc0cd994e675deb87b5021e04026e1c5a7b94cd3041185d3478144c7b2d333644daa5283d733e887fd3073ccad7ea8acf20d2cb5b8f56dccb3739599339fb6d06ed200e10a0fb1b60d90c0288f2eb8d0fd194eef8dd843e3cb6896372ab3bea4850107a5630132e8666d33013229a0d914b4e02aaab6791541803af59732c79bd6c6a75d9bcc85d874f719cfe8bb0484c2589e4bbf4f99bc0ed0223118201c4ece98fbdbd1ec6432f871a6b3a478fbd35c37d35cc5456fa6221bacdb013c318f77e169d73f2c336cfb24c64f855266c1d788107536a88b19e779bccffb0a334f86b7e0db6ab54376ac64cf6a927ac22c4643e4a12a1149c32f3bd92efce124dbc66300b4a34a6e3ea0610cd5f12146dd5d318a3764366689ba0adf940abbc44231f7d9d4e9809469f16b16d8674c987e668fed79da3c8cd3a3ce1c75122213264cf7b6cdcb19c9c943cb2ccceca9b13bbd147117113da764be055bf5f05ea751b4ce27ce24806832c8febcc3f7865c7978419791cf29141d81c621f45f9d03aab1bd24806b7cc3f5c8c635573bd8173ac8344ef0e4931c77c285b4356ad1a56173da15a3e1d17d19882df4c769a2da46a7c015488aa236c49443108663ace7181758dac98a97692cd196eda684b14dc72d933a44ff813f2f4c783a3d2d91acd707a818ed8f54fde68f0cdac9f037a88a9468dba387fd98952575321b992aac7a2f7443cb4f751936b4809862166d69d70ac5b94db37775b95fa430648150b5a843e64df023f97dcf7712775ef69aa74e666c74877c233f58898ab3b215e41c28db0fc67db293f98714a834d4b72231934d830bb6cd743a93b13e14a7b551d32d2c6b8f5163630ac4b66d2b26caf4cd0ba78a4e5b6e765bc305be95ab7ece7d10077fac67324c76bdddbaabb02234415cb7415b2166c30d32ab0fff69fd8bfd5a90ae998318ba0b91f7b358a715272951e0781638e032aa6b13f070112ab9759efa2ed9580d0f0dd0f88687ebe0fcf6db9e7174f80bb241083d1c03242420bfd6e13037a4c6366f181a4264e453c6485d1e5c9f6c5765dee081085e31557201af9a0a3e1e3e76e4a1f0cd8e0f6206e35f6b1080d6922866d025222db82980a736eec91f744bca2fa50061f8277b59f93396535eb0664208df0b9ff721bb9ebf0b7991973949ee46ca9e2e297097e8c67bc8283ee81e3c709590fe871b5ab7c3470a8abe5ccac42b580e6fd48544d9d728769c5fef390904a17f92a544816f9c7d1eff5fa753f0868e04cafac8d148ad4020f957db6b144a85143f2428307c6cb9e9d318b33e24834bd68a459092369c8be915ce32ef5756b402abceea754e0d48f9710ee6cc3d414603677675259419635f4c1ed60e2afd41523bb87a58fa0531efd8bc3013a0c3c1dd413739820b722b788347f18cf4a02ceafef5dfd9fd31396cffd62396dbe284ad81e29477bc137bc4eda694a56e38c1f6be585d262dccf43f473e3ad414eef8f293b3ef38bda8a4ea49f42a86c344902ca33a025fd6ef24f4abc68adb913d77c15dab79f37ec3c06e9f7b121ba8ef790a12fa5d8854881c23ed85d248b4d1af97629872b1b19c0dda948bcd3a1d335db25465fe4e67335532338b5146afe8a5f34f13852d9a50cc98bf1cedef8b345af708819d74038147a7cf13572a5c2bcca5ce557f1b21dabc4cddb6476f749f218bc843dd4b1a63c56dbb35eab0047f879a37ce8467990d3f44787e35242ff4dca0617ce13eb73c061280b66e6bfbe4c00f04b06fbd0528a3f9296db5a4ab9fa061a468a166e9f264b83f9762c5e9556ec421e5cb255ae14251fb27041ce6bd7d92abed2deb6d4242c52782609380031c300d87d4c99b5c1408c7c2882c511ff579bee4804590c639d8df0ce786a0b2b97e2e869cc34c84239ed0af580fb2f3f358c47ff589b3397637936adce383b8104f945559d3b495f2f3c9ffa28486c4c42b9eb883ffecb1582a7bc8178491ba6e3ac635264e277fe86cb348d7e43625ec2c9efe95b315fe682c96eb8b262010b1f83a2e6e533c2d03dcaff4c78f9d29800f707ae8590233ece6e10936db5f19470b7004002004ad1090feed95ec265182f213abe32b8cb60047f5f526ffa001b7b55cbd584ea6a667028862ccd87543b0d8d3a3078b7fdfabc326e39b31bf11e0e193a81d0c92bff3065c4bb5bce60d8533d38c82bd8cfe6d86855933afb836420e7b8e38b859efbcec926a56f856fd723360106c26e46767f69938def8562bcbf36a2161e537bd2b0e145a7dad835b3d9cc37f8842a8abc0718c20e3a02014f1cb21a81d02f6708b39c9a6122e19049280383f6e0208c065e9758dff09d878c2fd124716c440ca736289d5607aa33cff74eb45ab6973bc5754aeb143f51d1e4f6de63377c34ec9df5c46e808aa8b7407931f17a3681eb115b588c32542eb005bbbdfd63fffaacbd08db1f1d9fd044b0093a136c9952bb046ea1d17ea8e13462d4c827e8c06839a1d5e8633e1a44765d5194245ac8ec7dd7bf6ab48d3497420e43afd050ed0fdc39c98adb20f44102dc8cd961be7d0feef271859b2b52e9f5dbc0601c4b54e9efb0598e91a244d303d3195e95a93e74f6aed737e2c5f4c652c398b1c65a8bfa584a9cc06f418b6cc9f9c72923faae36c9f12bd81c670655d8341ef98a38a72229ec9455e94fb9adaaaba7509d85d4ed93d1a2174eca8718ea49a72a7fef0b34e5d2e729ae53421d1453ee481b275463fa4e3ff67226cc765b7";
static const char *wit_sighash_hex = "450f330746507f7a53b805895b6026dd5947cbf65a7b49eeb850c32e9de17cd9";

static const char *coinbase_hex = "0200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502b2010101ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000b1b2001976a914370b9f298b2e2a9d8751bcf1a78787148fd5372d88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000266a24aa21a9edd591f3570cdb19344a1cca79de32d6e0e8b15dac7764dd47d3b30824c7d753ef000000ff0000012010000000000000000000000000000000000000000000000000000000000000000000000000";

static const char *pegin_hex = "02000000010146d1860f7d3ce3711c69a1ed3a78613321aeaf4e5b3560ab0bbc62edb1f649dd0100004000ffffffff0201e13da48cd2489551ba5c4749f0e87a6566df8c0a71f5cb5865991de1c71c6d6801000000003b9ab2f4001976a914e960f3b3149abbeed93419a8ad7c61d6dff7ea8188ac01e13da48cd2489551ba5c4749f0e87a6566df8c0a71f5cb5865991de1c71c6d6801000000000000170c00000000000000000247304402206a29b6ce97619a0ff623af2b6e1c598cb17949806288dacbc4353000b80a6a4102203728658c5bf603bf0422e2bda65bd5b0d088d149dd471c33b6442a6314aed2190121031eeece02cd7cf0991767576bccc59fc8c61fd04bd22e6c400f18a4d2b14e4175060800ca9a3b0000000020e13da48cd2489551ba5c4749f0e87a6566df8c0a71f5cb5865991de1c71c6d682006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1600143fd9e2dd6fddb292c1756ea8a4232bdc4778fdfabc02000000019f15926099f03eb83aa9a7033ead61251134e48ea485952bdd71dc58154223ac0000000049483045022100a082acded3b4b07656b992835cb2914d23a910f8fae4fa6dfdffab72f50627b802202ae910309c257ee64cee2f72677577a6e406a110528c162f929b55dcce9b83e401fdffffff0250196bee0000000017a914032219e59890b855333f795430d6be7c2317f60d8700ca9a3b0000000017a914f0b371c2caad4dc2ab9b9d18cf8dcd5ed6399a8d8765000000970000002019012458b559e25cb28b4a7a1bbf7ed9f21aa534eaffafb95180b60915e78f297f90e5961b1e31891c20358ba59fa5f3e746cb81dc889a248f4be6fb0741d156623f625affff7f20000000000200000002e9356f452ac067d744d9bebae569c9fcfebd24a87ff391638c82037a244d3fde46d1860f7d3ce3711c69a1ed3a78613321aeaf4e5b3560ab0bbc62edb1f649dd010500000000";
static const char *pegin_wit_hex[] =
{
    "00ca9a3b00000000",
    "e13da48cd2489551ba5c4749f0e87a6566df8c0a71f5cb5865991de1c71c6d68",
    "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
    "00143fd9e2dd6fddb292c1756ea8a4232bdc4778fdfa",
    "02000000019f15926099f03eb83aa9a7033ead61251134e48ea485952bdd71dc58154223ac0000000049483045022100a082acded3b4b07656b992835cb2914d23a910f8fae4fa6dfdffab72f50627b802202ae910309c257ee64cee2f72677577a6e406a110528c162f929b55dcce9b83e401fdffffff0250196bee0000000017a914032219e59890b855333f795430d6be7c2317f60d8700ca9a3b0000000017a914f0b371c2caad4dc2ab9b9d18cf8dcd5ed6399a8d8765000000",
    "0000002019012458b559e25cb28b4a7a1bbf7ed9f21aa534eaffafb95180b60915e78f297f90e5961b1e31891c20358ba59fa5f3e746cb81dc889a248f4be6fb0741d156623f625affff7f20000000000200000002e9356f452ac067d744d9bebae569c9fcfebd24a87ff391638c82037a244d3fde46d1860f7d3ce3711c69a1ed3a78613321aeaf4e5b3560ab0bbc62edb1f649dd0105"
};
static const size_t pegin_tx_siz = 718; // from liquidd
static const size_t pegin_tx_vsiz = 304; // from liquidd

#define check_ret(r) if (r != WALLY_OK) return false

static bool tx_roundtrip(const char *tx_hex, const char *sighash_hex)
{
    struct wally_tx *tx;
    struct wally_tx_input *in, *new_in;
    struct wally_tx_output *out, *new_out;
    char *new_hex;
    unsigned char signature_hash[SHA256_LEN];
    unsigned char ct_value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    size_t i;
    size_t is_elements;
    int ret;
    const uint32_t flags = WALLY_TX_FLAG_USE_WITNESS;

    /* Unserialize and serialize the tx and verify they match */
    ret = wally_tx_from_hex(tx_hex, flags | WALLY_TX_FLAG_USE_ELEMENTS, &tx);
    check_ret(ret);

    ret = wally_tx_to_hex(tx, flags, &new_hex);
    if (ret != WALLY_OK || strcmp(tx_hex, new_hex))
        return false;

    ret = wally_free_string(new_hex);
    check_ret(ret);

    ret = wally_tx_is_elements(tx, &is_elements);
    if (ret != WALLY_OK || !is_elements)
        return false;

    ret = wally_tx_confidential_value_from_satoshi(1000, ct_value, sizeof(ct_value));
    check_ret(ret);

    in = &tx->inputs[0];
    ret = wally_tx_get_elements_signature_hash(tx, 0, NULL, 0,
                                               ct_value, sizeof(ct_value),
                                               WALLY_SIGHASH_ALL, WALLY_TX_FLAG_USE_WITNESS,
                                               signature_hash, sizeof(signature_hash));
    check_ret(ret);

    ret = wally_hex_from_bytes(signature_hash, sizeof(signature_hash), &new_hex);
    if (ret != WALLY_OK || strcmp(sighash_hex, new_hex))
        return false;

    ret = wally_free_string(new_hex);
    check_ret(ret);

    /* Test adding and removing inputs */
    ret = wally_tx_elements_input_init_alloc(in->txhash, sizeof(in->txhash),
                                             in->index, in->sequence,
                                             in->script, in->script_len, in->witness,
                                             in->blinding_nonce, WALLY_TX_ASSET_TAG_LEN,
                                             in->entropy, WALLY_TX_ASSET_TAG_LEN,
                                             in->issuance_amount, in->issuance_amount_len,
                                             in->inflation_keys, in->inflation_keys_len,
                                             in->issuance_amount_rangeproof,
                                             in->issuance_amount_rangeproof_len,
                                             in->inflation_keys_rangeproof,
                                             in->inflation_keys_rangeproof_len,
                                             in->pegin_witness,
                                             &new_in);
    check_ret(ret);
    for (i = 0; i < 5; ++i) {
        ret = wally_tx_add_input(tx, new_in);
        check_ret(ret);
    }
    ret = wally_tx_remove_input(tx, 5); /* Remove last */
    check_ret(ret);
    ret = wally_tx_add_elements_raw_input(tx, new_in->txhash, WALLY_TXHASH_LEN,
                                          new_in->index, new_in->sequence,
                                          new_in->script, new_in->script_len,
                                          new_in->witness,
                                          new_in->blinding_nonce, WALLY_TX_ASSET_TAG_LEN,
                                          new_in->entropy, WALLY_TX_ASSET_TAG_LEN,
                                          new_in->issuance_amount, new_in->issuance_amount_len,
                                          new_in->inflation_keys, new_in->inflation_keys_len,
                                          new_in->issuance_amount_rangeproof,
                                          new_in->issuance_amount_rangeproof_len,
                                          new_in->inflation_keys_rangeproof,
                                          new_in->inflation_keys_rangeproof_len,
                                          new_in->pegin_witness, 0);
    check_ret(ret);
    ret = wally_tx_remove_input(tx, 3); /* Remove middle */
    check_ret(ret);
    ret = wally_tx_remove_input(tx, 2); /* Remove middle */
    check_ret(ret);
    ret = wally_tx_remove_input(tx, 0); /* Remove first */
    check_ret(ret);

    /* Test adding and removing outputs */
    out = &tx->outputs[0];
    ret = wally_tx_elements_output_init_alloc(out->script, out->script_len,
                                              out->asset, out->asset_len,
                                              out->value, out->value_len,
                                              out->nonce, out->nonce_len,
                                              out->surjectionproof, out->surjectionproof_len,
                                              out->rangeproof, out->rangeproof_len, &new_out);
    check_ret(ret);

    for (i = 0; i < 5; ++i) {
        ret = wally_tx_add_output(tx, new_out);
        check_ret(ret);
    }

    ret = wally_tx_remove_output(tx, 5); /* Remove last */
    check_ret(ret);
    ret = wally_tx_add_elements_raw_output(tx, new_out->script, new_out->script_len,
                                           new_out->asset, new_out->asset_len,
                                           new_out->value, new_out->value_len,
                                           new_out->nonce, new_out->nonce_len,
                                           new_out->surjectionproof, new_out->surjectionproof_len,
                                           new_out->rangeproof, new_out->rangeproof_len, 0);
    check_ret(ret);
    ret = wally_tx_remove_output(tx, 3); /* Remove middle */
    check_ret(ret);
    ret = wally_tx_remove_output(tx, 2); /* Remove middle */
    check_ret(ret);
    ret = wally_tx_remove_output(tx, 0); /* Remove first */
    check_ret(ret);

    in = &tx->inputs[0];
    ret = wally_tx_get_elements_signature_hash(tx, 0, in->script, in->script_len,
                                               NULL, 0, WALLY_SIGHASH_ALL,
                                               0, signature_hash, sizeof(signature_hash));
    check_ret(ret);

    /* Clean up (for valgrind heap checking) */
    ret = wally_tx_free(tx);
    check_ret(ret);
    ret = wally_tx_input_free(new_in);
    check_ret(ret);
    ret = wally_tx_output_free(new_out);
    check_ret(ret);
    return true;
}

static bool tx_coinbase(const char *tx_hex)
{
    struct wally_tx *tx;
    char *new_hex;
    const uint32_t flags = WALLY_TX_FLAG_USE_WITNESS;
    size_t is_elements, is_coinbase;
    int ret;

    /* Unserialize and serialize the tx and verify they match */
    ret = wally_tx_from_hex(tx_hex, flags | WALLY_TX_FLAG_USE_ELEMENTS, &tx);
    check_ret(ret);

    ret = wally_tx_to_hex(tx, flags, &new_hex);
    if (ret != WALLY_OK || strcmp(tx_hex, new_hex))
        return false;

    ret = wally_free_string(new_hex);
    check_ret(ret);

    ret = wally_tx_is_elements(tx, &is_elements);
    if (ret != WALLY_OK || !is_elements)
        return false;

    ret = wally_tx_is_coinbase(tx, &is_coinbase);
    if (ret != WALLY_OK || !is_coinbase)
        return false;

    /* Clean up (for valgrind heap checking) */
    ret = wally_tx_free(tx);
    check_ret(ret);

    return true;
}

static bool tx_pegin(const char *tx_hex, const char **tx_pegin_wit_hex, size_t num_pegin_wit)
{
    struct wally_tx *tx;
    struct wally_tx_input *in;
    struct wally_tx_witness_stack *pegin_wit;
    struct wally_tx_witness_item *item;
    char *new_hex;
    const uint32_t flags = WALLY_TX_FLAG_USE_WITNESS;
    size_t is_elements, is_pegin, siz, i;
    int ret;

    /* Unserialize and serialize the tx and verify they match */
    ret = wally_tx_from_hex(tx_hex, flags | WALLY_TX_FLAG_USE_ELEMENTS, &tx);
    check_ret(ret);

    ret = wally_tx_to_hex(tx, flags, &new_hex);
    if (ret != WALLY_OK || strcmp(tx_hex, new_hex))
        return false;

    ret = wally_free_string(new_hex);
    check_ret(ret);

    ret = wally_tx_is_elements(tx, &is_elements);
    if (ret != WALLY_OK || !is_elements)
        return false;

    ret = wally_tx_get_length(tx, WALLY_TX_FLAG_USE_WITNESS, &siz);
    if (ret != WALLY_OK || siz != pegin_tx_siz)
        return false;

    ret = wally_tx_get_vsize(tx, &siz);
    if (ret != WALLY_OK || siz != pegin_tx_vsiz)
        return false;

    in = &tx->inputs[0];

    ret = wally_tx_elements_input_is_pegin(in, &is_pegin);
    if (ret != WALLY_OK || !is_pegin)
        return false;

    pegin_wit = in->pegin_witness;
    if (!pegin_wit || pegin_wit->num_items != num_pegin_wit)
        return false;

    for (i = 0; i < pegin_wit->num_items; ++i) {
        bool failed;

        item = &pegin_wit->items[i];

        ret = wally_hex_from_bytes(item->witness, item->witness_len, &new_hex);
        failed = ret != WALLY_OK || strcmp(tx_pegin_wit_hex[i], new_hex);

        ret = wally_free_string(new_hex);
        check_ret(ret);

        if (failed)
            return false;
    }

    ret = wally_tx_add_elements_raw_input(tx, in->txhash, WALLY_TXHASH_LEN,
                                          in->index | WALLY_TX_PEGIN_FLAG, in->sequence,
                                          in->script, in->script_len,
                                          in->witness,
                                          in->blinding_nonce, WALLY_TX_ASSET_TAG_LEN,
                                          in->entropy, WALLY_TX_ASSET_TAG_LEN,
                                          in->issuance_amount, in->issuance_amount_len,
                                          in->inflation_keys, in->inflation_keys_len,
                                          in->issuance_amount_rangeproof,
                                          in->issuance_amount_rangeproof_len,
                                          in->inflation_keys_rangeproof,
                                          in->inflation_keys_rangeproof_len,
                                          in->pegin_witness, 0);
    check_ret(ret);

    ret = wally_tx_remove_input(tx, 0);
    check_ret(ret);

    ret = wally_tx_to_hex(tx, flags, &new_hex);
    if (ret != WALLY_OK || strcmp(tx_hex, new_hex))
        return false;

    ret = wally_free_string(new_hex);
    check_ret(ret);

    /* Clean up (for valgrind heap checking) */
    ret = wally_tx_free(tx);
    check_ret(ret);

    return true;
}

static bool test_tx_parse(void)
{
    return tx_roundtrip(asset_issuance_hex, asset_issuance_sighash_hex) &&
           tx_roundtrip(wit_hex, wit_sighash_hex) && tx_coinbase(coinbase_hex) &&
           tx_pegin(pegin_hex, pegin_wit_hex, sizeof(pegin_wit_hex) / sizeof(pegin_wit_hex[0]));
}

int main(void)
{
    bool tests_ok = true;

#define RUN(t) if (!t()) { printf(#t " test_tx() test failed!\n"); tests_ok = false; }

    RUN(test_tx_parse);

    return tests_ok ? 0 : 1;
}
