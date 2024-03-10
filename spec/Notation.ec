require import List.

from Jasmin require import JModel.

require import Array8 Array25 Array_SPX_N Array_SPX_PK_BYTES Array_SPX_SK_BYTES 
               Array_SPX_SEED_BYTES Array_SPX_BYTES.

(********************************* PARAMETERS *********************************)

op SPX_N = 16.
op SPX_FULL_HEIGHT = 66.
op SPX_D = 22.
op SPX_FORS_HEIGHT = 6.
op SPX_FORS_TREES = 33.
op SPX_WOTS_W = 16.
op SPX_ADDR_BYTES = 32.
op SPX_WOTS_LOGW = 4.
op SPX_WOTS_LEN1 = 32.
op SPX_WOTS_LEN2 = 3.
op SPX_WOTS_LEN = 35.
op SPX_WOTS_BYTES = 560.
op SPX_WOTS_PK_BYTES = 560.
op SPX_TREE_HEIGHT = 3.
op SPX_FORS_MSG_BYTES = 25.
op SPX_FORS_BYTES = 3696.
op SPX_FORS_PK_BYTES = 16.
op SPX_BYTES = 17088.
op SPX_PK_BYTES = 32.
op SPX_SK_BYTES = 64.
op SPX_OFFSET_LAYER = 3.
op SPX_OFFSET_TREE = 8.
op SPX_OFFSET_TYPE = 19.
op SPX_OFFSET_KP_ADDR2 = 22.
op SPX_OFFSET_KP_ADDR1 = 23.
op SPX_OFFSET_CHAIN_ADDR = 27.
op SPX_OFFSET_HASH_ADDR = 31.
op SPX_OFFSET_TREE_HGT = 27.
op SPX_OFFSET_TREE_INDEX = 28.
op SPX_ADDR_TYPE_WOTS = 0.
op SPX_ADDR_TYPE_WOTSPK = 1.
op SPX_ADDR_TYPE_HASHTREE = 2.
op SPX_ADDR_TYPE_FORSTREE = 3.
op SPX_ADDR_TYPE_FORSPK = 4.
op SPX_ADDR_TYPE_WOTSPRF = 5.
op SPX_ADDR_TYPE_FORSPRF = 6.
op SPX_SEED_BYTES = 48.
op SPX_TREE_BITS = 63.
op SPX_TREE_BYTES = 8.
op SPX_LEAF_BITS = 3.
op SPX_LEAF_BYTES = 1.
op SPX_DGST_BYTES = 34.

(******************************************************************************)

type byte = W8.t.

type pub_seed = byte Array_SPX_N.t.
type sk_seed = byte Array_SPX_N.t.
type ctx = pub_seed * sk_seed.

type adrs = W32.t Array8.t.

type public_key = byte Array_SPX_PK_BYTES.t.
type secret_key = byte Array_SPX_SK_BYTES.t.
type key_pair = public_key * secret_key.

type message = byte list. (* TODO: FIXME: *)
type signature = byte Array_SPX_BYTES.t.

type seed = byte Array_SPX_SEED_BYTES.t.
