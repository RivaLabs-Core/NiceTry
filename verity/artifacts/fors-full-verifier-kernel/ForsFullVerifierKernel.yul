object "ForsFullVerifierKernel" {
    code {
        if callvalue() {
            revert(0, 0)
        }
        function __verity_array_element_calldata_checked(data_offset, length, index) -> word {
            if iszero(lt(index, length)) {
                revert(0, 0)
            }
            word := calldataload(add(data_offset, mul(index, 32)))
        }
        function __verity_array_element_memory_checked(data_offset, length, index) -> word {
            if iszero(lt(index, length)) {
                revert(0, 0)
            }
            word := mload(add(data_offset, mul(index, 32)))
        }
        function internal_internal_nMask() -> __ret0 {
            __ret0 := 115792089237316195423570985008687907852929702298719625575994209400481361428480
            leave
        }
        function internal_internal_lower160Mask() -> __ret0 {
            __ret0 := 1461501637330902918203684832716283019655932542975
            leave
        }
        function internal_internal_openingWords() -> __ret0 {
            __ret0 := 150
            leave
        }
        function internal_internal_rootsHashLen() -> __ret0 {
            __ret0 := 864
            leave
        }
        function internal_internal_sigLen() -> __ret0 {
            __ret0 := 2448
            leave
        }
        function internal_internal_sectionOffset() -> __ret0 {
            __ret0 := 32
            leave
        }
        function internal_internal_counterOffset() -> __ret0 {
            __ret0 := 2432
            leave
        }
        function internal_internal_treeLen() -> __ret0 {
            __ret0 := 96
            leave
        }
        function internal_internal_forcedZero(dVal) -> __ret0 {
            let idx := and(shr(125, dVal), 31)
            __ret0 := eq(idx, 0)
            leave
        }
        function internal_internal_hMsg(pkSeed, r, digest, counter) -> __ret0 {
            mstore(0, pkSeed)
            mstore(32, r)
            mstore(64, digest)
            mstore(96, 115792089237316195423570985008687907853269984665640564039457584007913129639933)
            mstore(128, counter)
            __ret0 := keccak256(0, 160)
            leave
        }
        function internal_internal_leafAdrs(tree, leafIdx) -> __ret0 {
            let base := shl(128, 3)
            __ret0 := or(base, or(shl(5, tree), leafIdx))
            leave
        }
        function internal_internal_nodeAdrs(tree, height, treeScale, parentIdx) -> __ret0 {
            let base := shl(128, 3)
            let heightWord := shl(32, height)
            let globalIdx := add(mul(tree, treeScale), parentIdx)
            __ret0 := or(base, or(heightWord, globalIdx))
            leave
        }
        function internal_internal_indexAt(dVal, tree) -> __ret0 {
            let bitOffset := mul(5, tree)
            __ret0 := and(shr(bitOffset, dVal), 31)
            leave
        }
        function internal_internal_leafHash(pkSeed, tree, leafIdx, sk) -> __ret0 {
            let adrs := internal_internal_leafAdrs(tree, leafIdx)
            mstore(896, pkSeed)
            mstore(928, adrs)
            mstore(960, sk)
            let digest := keccak256(896, 96)
            __ret0 := and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
            leave
        }
        function internal_internal_nodeHash(pkSeed, tree, height, treeScale, parentIdx, left, right) -> __ret0 {
            let adrs := internal_internal_nodeAdrs(tree, height, treeScale, parentIdx)
            mstore(896, pkSeed)
            mstore(928, adrs)
            mstore(960, left)
            mstore(992, right)
            let digest := keccak256(896, 128)
            __ret0 := and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
            leave
        }
        function internal_internal_climbLevel(pkSeed, tree, height, treeScale, pathIdx, node, sibling) -> __ret0, __ret1 {
            let parentIdx := div(pathIdx, 2)
            {
                let __ite_cond := eq(mod(pathIdx, 2), 0)
                if __ite_cond {
                    let next := internal_internal_nodeHash(pkSeed, tree, height, treeScale, parentIdx, node, sibling)
                    __ret0 := next
                    __ret1 := parentIdx
                    leave
                }
                if iszero(__ite_cond) {
                    let next := internal_internal_nodeHash(pkSeed, tree, height, treeScale, parentIdx, sibling, node)
                    __ret0 := next
                    __ret1 := parentIdx
                    leave
                }
            }
        }
        function internal_internal_reconstructTree(pkSeed, tree, leafIdx, sk, auth0, auth1, auth2, auth3, auth4) -> __ret0 {
            let leaf := internal_internal_leafHash(pkSeed, tree, leafIdx, sk)
            let node1, idx1 := internal_internal_climbLevel(pkSeed, tree, 1, 16, leafIdx, leaf, auth0)
            let node2, idx2 := internal_internal_climbLevel(pkSeed, tree, 2, 8, idx1, node1, auth1)
            let node3, idx3 := internal_internal_climbLevel(pkSeed, tree, 3, 4, idx2, node2, auth2)
            let node4, idx4 := internal_internal_climbLevel(pkSeed, tree, 4, 2, idx3, node3, auth3)
            let node5, idx5 := internal_internal_climbLevel(pkSeed, tree, 5, 1, idx4, node4, auth4)
            let _terminalIdx := idx5
            __ret0 := node5
            leave
        }
        function internal_internal_openingAt(openings_data_offset, openings_length, tree, field) -> __ret0 {
            let idx := add(mul(tree, 6), field)
            let value := __verity_array_element_calldata_checked(openings_data_offset, openings_length, idx)
            __ret0 := and(value, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
            leave
        }
        function internal_internal_rawWord(sigData, byteOffset) -> __ret0 {
            let word := calldataload(add(sigData, byteOffset))
            __ret0 := and(word, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
            leave
        }
        function internal_internal_compressRoots(_pkSeed) -> __ret0 {
            mstore(32, shl(128, 4))
            let digest := keccak256(0, 864)
            __ret0 := and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
            leave
        }
        function internal_internal_addressFromRoot(pkSeed, pkRoot) -> __ret0 {
            mstore(0, pkSeed)
            mstore(32, pkRoot)
            let digest := keccak256(0, 64)
            __ret0 := and(digest, 1461501637330902918203684832716283019655932542975)
            leave
        }
        function internal_internal_recoverTyped(r, pkSeed, digest, counter, openings_data_offset, openings_length) -> __ret0 {
            {
                let __ite_cond := eq(openings_length, 150)
                if __ite_cond {
                    let maskedR := and(r, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                    let maskedPkSeed := and(pkSeed, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                    let maskedCounter := and(counter, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                    let dVal := internal_internal_hMsg(maskedPkSeed, maskedR, digest, maskedCounter)
                    let ok := internal_internal_forcedZero(dVal)
                    {
                        let __ite_cond := ok
                        if __ite_cond {
                            mstore(0, maskedPkSeed)
                            for {
                                let t := 0
                            } lt(t, 25) {
                                t := add(t, 1)
                            } {
                                let leafIdx := internal_internal_indexAt(dVal, t)
                                let sk := internal_internal_openingAt(openings_data_offset, openings_length, t, 0)
                                let auth0 := internal_internal_openingAt(openings_data_offset, openings_length, t, 1)
                                let auth1 := internal_internal_openingAt(openings_data_offset, openings_length, t, 2)
                                let auth2 := internal_internal_openingAt(openings_data_offset, openings_length, t, 3)
                                let auth3 := internal_internal_openingAt(openings_data_offset, openings_length, t, 4)
                                let auth4 := internal_internal_openingAt(openings_data_offset, openings_length, t, 5)
                                let root := internal_internal_reconstructTree(maskedPkSeed, t, leafIdx, sk, auth0, auth1, auth2, auth3, auth4)
                                let rootPtr := add(64, mul(t, 32))
                                mstore(rootPtr, root)
                            }
                            let pkRoot := internal_internal_compressRoots(maskedPkSeed)
                            let signer := internal_internal_addressFromRoot(maskedPkSeed, pkRoot)
                            __ret0 := signer
                            leave
                        }
                        if iszero(__ite_cond) {
                            __ret0 := 0
                            leave
                        }
                    }
                }
                if iszero(__ite_cond) {
                    __ret0 := 0
                    leave
                }
            }
        }
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            function __verity_array_element_calldata_checked(data_offset, length, index) -> word {
                if iszero(lt(index, length)) {
                    revert(0, 0)
                }
                word := calldataload(add(data_offset, mul(index, 32)))
            }
            function __verity_array_element_memory_checked(data_offset, length, index) -> word {
                if iszero(lt(index, length)) {
                    revert(0, 0)
                }
                word := mload(add(data_offset, mul(index, 32)))
            }
            function internal_internal_nMask() -> __ret0 {
                __ret0 := 115792089237316195423570985008687907852929702298719625575994209400481361428480
                leave
            }
            function internal_internal_lower160Mask() -> __ret0 {
                __ret0 := 1461501637330902918203684832716283019655932542975
                leave
            }
            function internal_internal_openingWords() -> __ret0 {
                __ret0 := 150
                leave
            }
            function internal_internal_rootsHashLen() -> __ret0 {
                __ret0 := 864
                leave
            }
            function internal_internal_sigLen() -> __ret0 {
                __ret0 := 2448
                leave
            }
            function internal_internal_sectionOffset() -> __ret0 {
                __ret0 := 32
                leave
            }
            function internal_internal_counterOffset() -> __ret0 {
                __ret0 := 2432
                leave
            }
            function internal_internal_treeLen() -> __ret0 {
                __ret0 := 96
                leave
            }
            function internal_internal_forcedZero(dVal) -> __ret0 {
                let idx := and(shr(125, dVal), 31)
                __ret0 := eq(idx, 0)
                leave
            }
            function internal_internal_hMsg(pkSeed, r, digest, counter) -> __ret0 {
                mstore(0, pkSeed)
                mstore(32, r)
                mstore(64, digest)
                mstore(96, 115792089237316195423570985008687907853269984665640564039457584007913129639933)
                mstore(128, counter)
                __ret0 := keccak256(0, 160)
                leave
            }
            function internal_internal_leafAdrs(tree, leafIdx) -> __ret0 {
                let base := shl(128, 3)
                __ret0 := or(base, or(shl(5, tree), leafIdx))
                leave
            }
            function internal_internal_nodeAdrs(tree, height, treeScale, parentIdx) -> __ret0 {
                let base := shl(128, 3)
                let heightWord := shl(32, height)
                let globalIdx := add(mul(tree, treeScale), parentIdx)
                __ret0 := or(base, or(heightWord, globalIdx))
                leave
            }
            function internal_internal_indexAt(dVal, tree) -> __ret0 {
                let bitOffset := mul(5, tree)
                __ret0 := and(shr(bitOffset, dVal), 31)
                leave
            }
            function internal_internal_leafHash(pkSeed, tree, leafIdx, sk) -> __ret0 {
                let adrs := internal_internal_leafAdrs(tree, leafIdx)
                mstore(896, pkSeed)
                mstore(928, adrs)
                mstore(960, sk)
                let digest := keccak256(896, 96)
                __ret0 := and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                leave
            }
            function internal_internal_nodeHash(pkSeed, tree, height, treeScale, parentIdx, left, right) -> __ret0 {
                let adrs := internal_internal_nodeAdrs(tree, height, treeScale, parentIdx)
                mstore(896, pkSeed)
                mstore(928, adrs)
                mstore(960, left)
                mstore(992, right)
                let digest := keccak256(896, 128)
                __ret0 := and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                leave
            }
            function internal_internal_climbLevel(pkSeed, tree, height, treeScale, pathIdx, node, sibling) -> __ret0, __ret1 {
                let parentIdx := div(pathIdx, 2)
                {
                    let __ite_cond := eq(mod(pathIdx, 2), 0)
                    if __ite_cond {
                        let next := internal_internal_nodeHash(pkSeed, tree, height, treeScale, parentIdx, node, sibling)
                        __ret0 := next
                        __ret1 := parentIdx
                        leave
                    }
                    if iszero(__ite_cond) {
                        let next := internal_internal_nodeHash(pkSeed, tree, height, treeScale, parentIdx, sibling, node)
                        __ret0 := next
                        __ret1 := parentIdx
                        leave
                    }
                }
            }
            function internal_internal_reconstructTree(pkSeed, tree, leafIdx, sk, auth0, auth1, auth2, auth3, auth4) -> __ret0 {
                let leaf := internal_internal_leafHash(pkSeed, tree, leafIdx, sk)
                let node1, idx1 := internal_internal_climbLevel(pkSeed, tree, 1, 16, leafIdx, leaf, auth0)
                let node2, idx2 := internal_internal_climbLevel(pkSeed, tree, 2, 8, idx1, node1, auth1)
                let node3, idx3 := internal_internal_climbLevel(pkSeed, tree, 3, 4, idx2, node2, auth2)
                let node4, idx4 := internal_internal_climbLevel(pkSeed, tree, 4, 2, idx3, node3, auth3)
                let node5, idx5 := internal_internal_climbLevel(pkSeed, tree, 5, 1, idx4, node4, auth4)
                let _terminalIdx := idx5
                __ret0 := node5
                leave
            }
            function internal_internal_openingAt(openings_data_offset, openings_length, tree, field) -> __ret0 {
                let idx := add(mul(tree, 6), field)
                let value := __verity_array_element_calldata_checked(openings_data_offset, openings_length, idx)
                __ret0 := and(value, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                leave
            }
            function internal_internal_rawWord(sigData, byteOffset) -> __ret0 {
                let word := calldataload(add(sigData, byteOffset))
                __ret0 := and(word, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                leave
            }
            function internal_internal_compressRoots(_pkSeed) -> __ret0 {
                mstore(32, shl(128, 4))
                let digest := keccak256(0, 864)
                __ret0 := and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                leave
            }
            function internal_internal_addressFromRoot(pkSeed, pkRoot) -> __ret0 {
                mstore(0, pkSeed)
                mstore(32, pkRoot)
                let digest := keccak256(0, 64)
                __ret0 := and(digest, 1461501637330902918203684832716283019655932542975)
                leave
            }
            function internal_internal_recoverTyped(r, pkSeed, digest, counter, openings_data_offset, openings_length) -> __ret0 {
                {
                    let __ite_cond := eq(openings_length, 150)
                    if __ite_cond {
                        let maskedR := and(r, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        let maskedPkSeed := and(pkSeed, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        let maskedCounter := and(counter, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        let dVal := internal_internal_hMsg(maskedPkSeed, maskedR, digest, maskedCounter)
                        let ok := internal_internal_forcedZero(dVal)
                        {
                            let __ite_cond := ok
                            if __ite_cond {
                                mstore(0, maskedPkSeed)
                                for {
                                    let t := 0
                                } lt(t, 25) {
                                    t := add(t, 1)
                                } {
                                    let leafIdx := internal_internal_indexAt(dVal, t)
                                    let sk := internal_internal_openingAt(openings_data_offset, openings_length, t, 0)
                                    let auth0 := internal_internal_openingAt(openings_data_offset, openings_length, t, 1)
                                    let auth1 := internal_internal_openingAt(openings_data_offset, openings_length, t, 2)
                                    let auth2 := internal_internal_openingAt(openings_data_offset, openings_length, t, 3)
                                    let auth3 := internal_internal_openingAt(openings_data_offset, openings_length, t, 4)
                                    let auth4 := internal_internal_openingAt(openings_data_offset, openings_length, t, 5)
                                    let root := internal_internal_reconstructTree(maskedPkSeed, t, leafIdx, sk, auth0, auth1, auth2, auth3, auth4)
                                    let rootPtr := add(64, mul(t, 32))
                                    mstore(rootPtr, root)
                                }
                                let pkRoot := internal_internal_compressRoots(maskedPkSeed)
                                let signer := internal_internal_addressFromRoot(maskedPkSeed, pkRoot)
                                __ret0 := signer
                                leave
                            }
                            if iszero(__ite_cond) {
                                __ret0 := 0
                                leave
                            }
                        }
                    }
                    if iszero(__ite_cond) {
                        __ret0 := 0
                        leave
                    }
                }
            }
            {
                let __has_selector := iszero(lt(calldatasize(), 4))
                if iszero(__has_selector) {
                    revert(0, 0)
                }
                if __has_selector {
                    switch shr(224, calldataload(0))
                    case 0xe93dc552 {
                        /* nMask() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        return(0, 32)
                    }
                    case 0x68529acd {
                        /* lower160Mask() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, 1461501637330902918203684832716283019655932542975)
                        return(0, 32)
                    }
                    case 0xaf661c5a {
                        /* openingWords() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, 150)
                        return(0, 32)
                    }
                    case 0xfb82947c {
                        /* rootsHashLen() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, 864)
                        return(0, 32)
                    }
                    case 0x620d6b1d {
                        /* sigLen() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, 2448)
                        return(0, 32)
                    }
                    case 0x2226e715 {
                        /* sectionOffset() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, 32)
                        return(0, 32)
                    }
                    case 0xcfb408a0 {
                        /* counterOffset() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, 2432)
                        return(0, 32)
                    }
                    case 0xfdb1770c {
                        /* treeLen() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, 96)
                        return(0, 32)
                    }
                    case 0xdee6eff1 {
                        /* forcedZero() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 36) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 36) {
                            revert(0, 0)
                        }
                        let dVal := calldataload(4)
                        let idx := and(shr(125, dVal), 31)
                        mstore(0, eq(idx, 0))
                        return(0, 32)
                    }
                    case 0xe2c7e38c {
                        /* hMsg() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 132) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 132) {
                            revert(0, 0)
                        }
                        let pkSeed := calldataload(4)
                        let r := calldataload(36)
                        let digest := calldataload(68)
                        let counter := calldataload(100)
                        mstore(0, pkSeed)
                        mstore(32, r)
                        mstore(64, digest)
                        mstore(96, 115792089237316195423570985008687907853269984665640564039457584007913129639933)
                        mstore(128, counter)
                        mstore(0, keccak256(0, 160))
                        return(0, 32)
                    }
                    case 0xdfa40381 {
                        /* leafAdrs() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        let tree := calldataload(4)
                        let leafIdx := calldataload(36)
                        let base := shl(128, 3)
                        mstore(0, or(base, or(shl(5, tree), leafIdx)))
                        return(0, 32)
                    }
                    case 0x78f655be {
                        /* nodeAdrs() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 132) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 132) {
                            revert(0, 0)
                        }
                        let tree := calldataload(4)
                        let height := calldataload(36)
                        let treeScale := calldataload(68)
                        let parentIdx := calldataload(100)
                        let base := shl(128, 3)
                        let heightWord := shl(32, height)
                        let globalIdx := add(mul(tree, treeScale), parentIdx)
                        mstore(0, or(base, or(heightWord, globalIdx)))
                        return(0, 32)
                    }
                    case 0x66532a6f {
                        /* indexAt() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        let dVal := calldataload(4)
                        let tree := calldataload(36)
                        let bitOffset := mul(5, tree)
                        mstore(0, and(shr(bitOffset, dVal), 31))
                        return(0, 32)
                    }
                    case 0xc43fc109 {
                        /* leafHash() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 132) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 132) {
                            revert(0, 0)
                        }
                        let pkSeed := calldataload(4)
                        let tree := calldataload(36)
                        let leafIdx := calldataload(68)
                        let sk := calldataload(100)
                        let adrs := internal_internal_leafAdrs(tree, leafIdx)
                        mstore(896, pkSeed)
                        mstore(928, adrs)
                        mstore(960, sk)
                        let digest := keccak256(896, 96)
                        mstore(0, and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480))
                        return(0, 32)
                    }
                    case 0x7b0fcb8b {
                        /* nodeHash() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 228) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 228) {
                            revert(0, 0)
                        }
                        let pkSeed := calldataload(4)
                        let tree := calldataload(36)
                        let height := calldataload(68)
                        let treeScale := calldataload(100)
                        let parentIdx := calldataload(132)
                        let left := calldataload(164)
                        let right := calldataload(196)
                        let adrs := internal_internal_nodeAdrs(tree, height, treeScale, parentIdx)
                        mstore(896, pkSeed)
                        mstore(928, adrs)
                        mstore(960, left)
                        mstore(992, right)
                        let digest := keccak256(896, 128)
                        mstore(0, and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480))
                        return(0, 32)
                    }
                    case 0x6fb382a7 {
                        /* climbLevel() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 228) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 228) {
                            revert(0, 0)
                        }
                        let pkSeed := calldataload(4)
                        let tree := calldataload(36)
                        let height := calldataload(68)
                        let treeScale := calldataload(100)
                        let pathIdx := calldataload(132)
                        let node := calldataload(164)
                        let sibling := calldataload(196)
                        let parentIdx := div(pathIdx, 2)
                        {
                            let __ite_cond := eq(mod(pathIdx, 2), 0)
                            if __ite_cond {
                                let next := internal_internal_nodeHash(pkSeed, tree, height, treeScale, parentIdx, node, sibling)
                                mstore(0, next)
                                mstore(32, parentIdx)
                                return(0, 64)
                            }
                            if iszero(__ite_cond) {
                                let next := internal_internal_nodeHash(pkSeed, tree, height, treeScale, parentIdx, sibling, node)
                                mstore(0, next)
                                mstore(32, parentIdx)
                                return(0, 64)
                            }
                        }
                    }
                    case 0xfbdc5c36 {
                        /* reconstructTree() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 292) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 292) {
                            revert(0, 0)
                        }
                        let pkSeed := calldataload(4)
                        let tree := calldataload(36)
                        let leafIdx := calldataload(68)
                        let sk := calldataload(100)
                        let auth0 := calldataload(132)
                        let auth1 := calldataload(164)
                        let auth2 := calldataload(196)
                        let auth3 := calldataload(228)
                        let auth4 := calldataload(260)
                        let leaf := internal_internal_leafHash(pkSeed, tree, leafIdx, sk)
                        let node1, idx1 := internal_internal_climbLevel(pkSeed, tree, 1, 16, leafIdx, leaf, auth0)
                        let node2, idx2 := internal_internal_climbLevel(pkSeed, tree, 2, 8, idx1, node1, auth1)
                        let node3, idx3 := internal_internal_climbLevel(pkSeed, tree, 3, 4, idx2, node2, auth2)
                        let node4, idx4 := internal_internal_climbLevel(pkSeed, tree, 4, 2, idx3, node3, auth3)
                        let node5, idx5 := internal_internal_climbLevel(pkSeed, tree, 5, 1, idx4, node4, auth4)
                        let _terminalIdx := idx5
                        mstore(0, node5)
                        return(0, 32)
                    }
                    case 0xf8e1c8c1 {
                        /* openingAt() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 100) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 100) {
                            revert(0, 0)
                        }
                        let openings_offset := calldataload(4)
                        if lt(openings_offset, 96) {
                            revert(0, 0)
                        }
                        let openings_abs_offset := add(4, openings_offset)
                        if gt(openings_abs_offset, sub(calldatasize(), 32)) {
                            revert(0, 0)
                        }
                        let openings_length := calldataload(openings_abs_offset)
                        let openings_tail_head_end := add(openings_abs_offset, 32)
                        let openings_tail_remaining := sub(calldatasize(), openings_tail_head_end)
                        if gt(openings_length, div(openings_tail_remaining, 32)) {
                            revert(0, 0)
                        }
                        let openings_data_offset := openings_tail_head_end
                        let tree := calldataload(36)
                        let field := calldataload(68)
                        let idx := add(mul(tree, 6), field)
                        let value := __verity_array_element_calldata_checked(openings_data_offset, openings_length, idx)
                        mstore(0, and(value, 115792089237316195423570985008687907852929702298719625575994209400481361428480))
                        return(0, 32)
                    }
                    case 0x6c4839f9 {
                        /* rawWord() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        let sigData := calldataload(4)
                        let byteOffset := calldataload(36)
                        let word := calldataload(add(sigData, byteOffset))
                        mstore(0, and(word, 115792089237316195423570985008687907852929702298719625575994209400481361428480))
                        return(0, 32)
                    }
                    case 0xc2c5977e {
                        /* compressRoots() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 36) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 36) {
                            revert(0, 0)
                        }
                        let _pkSeed := calldataload(4)
                        mstore(32, shl(128, 4))
                        let digest := keccak256(0, 864)
                        mstore(0, and(digest, 115792089237316195423570985008687907852929702298719625575994209400481361428480))
                        return(0, 32)
                    }
                    case 0xa22276d9 {
                        /* addressFromRoot() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        let pkSeed := calldataload(4)
                        let pkRoot := calldataload(36)
                        mstore(0, pkSeed)
                        mstore(32, pkRoot)
                        let digest := keccak256(0, 64)
                        mstore(0, and(digest, 1461501637330902918203684832716283019655932542975))
                        return(0, 32)
                    }
                    case 0xbc70497f {
                        /* recoverTyped() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 164) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 164) {
                            revert(0, 0)
                        }
                        let r := calldataload(4)
                        let pkSeed := calldataload(36)
                        let digest := calldataload(68)
                        let counter := calldataload(100)
                        let openings_offset := calldataload(132)
                        if lt(openings_offset, 160) {
                            revert(0, 0)
                        }
                        let openings_abs_offset := add(4, openings_offset)
                        if gt(openings_abs_offset, sub(calldatasize(), 32)) {
                            revert(0, 0)
                        }
                        let openings_length := calldataload(openings_abs_offset)
                        let openings_tail_head_end := add(openings_abs_offset, 32)
                        let openings_tail_remaining := sub(calldatasize(), openings_tail_head_end)
                        if gt(openings_length, div(openings_tail_remaining, 32)) {
                            revert(0, 0)
                        }
                        let openings_data_offset := openings_tail_head_end
                        {
                            let __ite_cond := eq(openings_length, 150)
                            if __ite_cond {
                                let maskedR := and(r, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                                let maskedPkSeed := and(pkSeed, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                                let maskedCounter := and(counter, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                                let dVal := internal_internal_hMsg(maskedPkSeed, maskedR, digest, maskedCounter)
                                let ok := internal_internal_forcedZero(dVal)
                                {
                                    let __ite_cond := ok
                                    if __ite_cond {
                                        mstore(0, maskedPkSeed)
                                        for {
                                            let t := 0
                                        } lt(t, 25) {
                                            t := add(t, 1)
                                        } {
                                            let leafIdx := internal_internal_indexAt(dVal, t)
                                            let sk := internal_internal_openingAt(openings_data_offset, openings_length, t, 0)
                                            let auth0 := internal_internal_openingAt(openings_data_offset, openings_length, t, 1)
                                            let auth1 := internal_internal_openingAt(openings_data_offset, openings_length, t, 2)
                                            let auth2 := internal_internal_openingAt(openings_data_offset, openings_length, t, 3)
                                            let auth3 := internal_internal_openingAt(openings_data_offset, openings_length, t, 4)
                                            let auth4 := internal_internal_openingAt(openings_data_offset, openings_length, t, 5)
                                            let root := internal_internal_reconstructTree(maskedPkSeed, t, leafIdx, sk, auth0, auth1, auth2, auth3, auth4)
                                            let rootPtr := add(64, mul(t, 32))
                                            mstore(rootPtr, root)
                                        }
                                        let pkRoot := internal_internal_compressRoots(maskedPkSeed)
                                        let signer := internal_internal_addressFromRoot(maskedPkSeed, pkRoot)
                                        mstore(0, signer)
                                        return(0, 32)
                                    }
                                    if iszero(__ite_cond) {
                                        mstore(0, 0)
                                        return(0, 32)
                                    }
                                }
                            }
                            if iszero(__ite_cond) {
                                mstore(0, 0)
                                return(0, 32)
                            }
                        }
                    }
                    case 0x1aad75c5 {
                        /* recover() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        let _sig_offset := calldataload(4)
                        if lt(_sig_offset, 64) {
                            revert(0, 0)
                        }
                        let _sig_abs_offset := add(4, _sig_offset)
                        if gt(_sig_abs_offset, sub(calldatasize(), 32)) {
                            revert(0, 0)
                        }
                        let _sig_length := calldataload(_sig_abs_offset)
                        let _sig_tail_head_end := add(_sig_abs_offset, 32)
                        let _sig_tail_remaining := sub(calldatasize(), _sig_tail_head_end)
                        if gt(_sig_length, _sig_tail_remaining) {
                            revert(0, 0)
                        }
                        let _sig_data_offset := _sig_tail_head_end
                        let digest := calldataload(36)
                        let sigOffset := calldataload(4)
                        let sigLenOffset := add(4, sigOffset)
                        let sigLen := calldataload(sigLenOffset)
                        {
                            let __ite_cond := eq(sigLen, 2448)
                            if __ite_cond {
                                let sigData := add(sigLenOffset, 32)
                                let r := internal_internal_rawWord(sigData, 0)
                                let pkSeed := internal_internal_rawWord(sigData, 16)
                                let counter := internal_internal_rawWord(sigData, 2432)
                                let digestWord := digest
                                let dVal := internal_internal_hMsg(pkSeed, r, digestWord, counter)
                                let ok := internal_internal_forcedZero(dVal)
                                {
                                    let __ite_cond := ok
                                    if __ite_cond {
                                        mstore(0, pkSeed)
                                        for {
                                            let t := 0
                                        } lt(t, 25) {
                                            t := add(t, 1)
                                        } {
                                            let leafIdx := internal_internal_indexAt(dVal, t)
                                            let treeBase := add(32, mul(t, 96))
                                            let sk := internal_internal_rawWord(sigData, treeBase)
                                            let auth0 := internal_internal_rawWord(sigData, add(treeBase, 16))
                                            let auth1 := internal_internal_rawWord(sigData, add(treeBase, 32))
                                            let auth2 := internal_internal_rawWord(sigData, add(treeBase, 48))
                                            let auth3 := internal_internal_rawWord(sigData, add(treeBase, 64))
                                            let auth4 := internal_internal_rawWord(sigData, add(treeBase, 80))
                                            let root := internal_internal_reconstructTree(pkSeed, t, leafIdx, sk, auth0, auth1, auth2, auth3, auth4)
                                            let rootPtr := add(64, mul(t, 32))
                                            mstore(rootPtr, root)
                                        }
                                        let pkRoot := internal_internal_compressRoots(pkSeed)
                                        let signer := internal_internal_addressFromRoot(pkSeed, pkRoot)
                                        mstore(0, signer)
                                        return(0, 32)
                                    }
                                    if iszero(__ite_cond) {
                                        mstore(0, 0)
                                        return(0, 32)
                                    }
                                }
                            }
                            if iszero(__ite_cond) {
                                mstore(0, 0)
                                return(0, 32)
                            }
                        }
                    }
                    default {
                        revert(0, 0)
                    }
                }
            }
        }
    }
}