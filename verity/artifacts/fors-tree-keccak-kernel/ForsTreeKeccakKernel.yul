object "ForsTreeKeccakKernel" {
    code {
        if callvalue() {
            revert(0, 0)
        }
        function internal_internal_nMask() -> __ret0 {
            __ret0 := 115792089237316195423570985008687907852929702298719625575994209400481361428480
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
        function internal_internal_treeRootFromDVal(pkSeed, dVal, tree, sk, auth0, auth1, auth2, auth3, auth4) -> __ret0 {
            let leafIdx := internal_internal_indexAt(dVal, tree)
            let root := internal_internal_reconstructTree(pkSeed, tree, leafIdx, sk, auth0, auth1, auth2, auth3, auth4)
            __ret0 := root
            leave
        }
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            function internal_internal_nMask() -> __ret0 {
                __ret0 := 115792089237316195423570985008687907852929702298719625575994209400481361428480
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
            function internal_internal_treeRootFromDVal(pkSeed, dVal, tree, sk, auth0, auth1, auth2, auth3, auth4) -> __ret0 {
                let leafIdx := internal_internal_indexAt(dVal, tree)
                let root := internal_internal_reconstructTree(pkSeed, tree, leafIdx, sk, auth0, auth1, auth2, auth3, auth4)
                __ret0 := root
                leave
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
                    case 0x54343dba {
                        /* treeRootFromDVal() */
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
                        let dVal := calldataload(36)
                        let tree := calldataload(68)
                        let sk := calldataload(100)
                        let auth0 := calldataload(132)
                        let auth1 := calldataload(164)
                        let auth2 := calldataload(196)
                        let auth3 := calldataload(228)
                        let auth4 := calldataload(260)
                        let leafIdx := internal_internal_indexAt(dVal, tree)
                        let root := internal_internal_reconstructTree(pkSeed, tree, leafIdx, sk, auth0, auth1, auth2, auth3, auth4)
                        mstore(0, root)
                        return(0, 32)
                    }
                    default {
                        revert(0, 0)
                    }
                }
            }
        }
    }
}