from enum import IntEnum
import struct

# ======================
# ADRS data structure
# ======================
class ADRSType(IntEnum):
    WOTS_HASH  = 0
    WOTS_PK    = 1
    TREE       = 2
    FORS_TREE  = 3
    FORS_ROOTS = 4
    WOTS_PRF   = 5
    FORS_PRF   = 6

class ADRS:
    """"
    32-byte SPHINCS+ hash function address.
    1 word = 32 bits. (reminder 1 byte = 8 bits)
    Layout:
    word 0 - layer address - describes the height of a tree within the hypertree
    starting from height zero for tress on the bottom layer.

    words 1,2,3 - tree address - describes position of a tree within a layer
    of a multi-tree starting with index zero for the leftmost tree.
    word 4 - type of the address
    words 5,6,7 - depends on the type of the address.
    """
    size = 32
    # For context, type dictates which both some of the properties 
    # that specific ADRS should hold
    # as well as dictate the purpose of this specific ADRS instance.
    def __init__(self):
        # index words to make life easier
        self.words = [0] * 8 # 8 words, 1 word is 4 bytes, stored in big-endian.
        pass
    
    # getter functions
    def get_word(self, index:int) -> int:
        return self.words[index]
    

    # setter functions for the in-common words
    # we want each word to be in unsigned 32 bit int. in which case, we
    # directly handle those instances by raising errors to ensure that the
    # format remains an unsigned-32 bit int.
    # this is just an added check to ensure that all values are proper (as they should be)
    # before this func gets called anyway.
    def set_word(self, index: int, value: int) -> None:
        if (value < 0):
            raise ValueError(f"{value} must be a positive integer value to be put into a word")
        if (value > 0xFFFFFFFF):
            raise ValueError(f"Value {value} exceeds 32 bit limit")
        self.words[index] = value
    
    def set_layer_add(self, layer: int) -> None:
        self.set_word(0, layer)

    def set_tree_add(self, tree: int) -> None:
        # Tree address spans words 1-3 (96 bits, big-endian).
        tree = tree & 0xFFFFFFFFFFFFFFFFFFFFFFFF  # clamp to 96 bits
        # self-explanatory, we get to the specific word and then clamp it to be 32 bits
        self.set_word(1, (tree >> 64) & 0xFFFFFFFF) 
        self.set_word(2, (tree >> 32) & 0xFFFFFFFF)
        self.set_word(3,  tree        & 0xFFFFFFFF)
    
    # 
    def set_type(self, adrs_type:ADRSType) -> None:
        self.set_word(4, int(adrs_type))
        self.set_word(5, 0)
        self.set_word(6, 0)
        self.set_word(7, 0)

    # ===============
    # Type Specific
    # ===============

    def set_key_pair_add(self, kpa:int) -> None:
        self.set_word(5, kpa)

    def set_chain_add(self, ch_add:int) -> None:
        self.set_word(6, ch_add)
    
    # As a convention, this is 0 for all WOTS_
    def set_hash_add(self, ha_add:int) -> None:
        self.set_word(7, ha_add)
    
    # As a convention, this is 0 for all FORS_PRF
    def set_tree_height(self, tree_h:int) -> None:
        self.set_word(6, tree_h)

    def set_tree_index(self, tree_i:int) -> None:
        self.set_word(7, tree_i)

    # ==========
    # Type-specific Getters - should not be called wrongly in the correct impl anw.
    # ==========

    def get_hash_add(self) -> int:
        return self.get_word(7)

    def get_chain_add(self) -> int:
        return self.get_word(6)

    def get_key_pair_add(self) -> int:
        return self.get_word(5)

    def get_tree_height(self) -> int:
        return self.get_word(6)

    def get_tree_index(self) -> int:
        return self.get_word(7)

    # ==========
    # Serialisation - following the spec, we want everything encoded into 32 bytes.
    # ==========
    def to_bytes(self) -> bytes:
        # big-endian 8 unsigned integers following the schema.    
        return struct.pack(">8I", *self.words)

    def from_bytes(cls, data:bytes) -> "ADRS":
        if (len(data)!= cls.size):
            raise ValueError(f"ADRS must be {cls.size} bytes, received {len(data)} instead.")
        adrs = cls()
        adrs.words = list(struct.unpack(">8I", data))
        return adrs
    
    # Debugging print statement
    def __repr__(self) -> str:
        return (
            f"ADRS(layer={self.words[0]}, "
            f"tree={self.words[1:4]}, "
            f"type={self.words[4]}, "
            f"words5-7={self.words[5:8]})"
        )
    
    # helper function to allow for copying of ADRS instance
    # prevents unwanted mutability.
    def copy(self) -> "ADRS":
        new = ADRS()
        new.words = self.words[:]
        return new

    


"""
    All fields within these addresses encode unsigned integers. When describing the generation
of addresses we use set methods that take positive integers and set the bits of a field to the
binary representation of that integer, in big-endian notation. Throughout this document, we
adhere to the convention of assuming that changing the type word of an address (indicated
by the use of the set_type() method) initializes the subsequent three words to zero.
"""

