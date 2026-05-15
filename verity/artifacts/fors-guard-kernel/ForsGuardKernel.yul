object "ForsGuardKernel" {
    code {
        if callvalue() {
            revert(0, 0)
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
        function internal_internal_treeOffset(tree) -> __ret0 {
            __ret0 := add(32, mul(tree, 96))
            leave
        }
        function internal_internal_authOffset(tree, level) -> __ret0 {
            let base := add(32, mul(tree, 96))
            __ret0 := add(add(base, 16), mul(level, 16))
            leave
        }
        function internal_internal_omittedIndex(dVal) -> __ret0 {
            __ret0 := and(shr(125, dVal), 31)
            leave
        }
        function internal_internal_forcedZero(dVal) -> __ret0 {
            let idx := and(shr(125, dVal), 31)
            __ret0 := eq(idx, 0)
            leave
        }
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
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
            function internal_internal_treeOffset(tree) -> __ret0 {
                __ret0 := add(32, mul(tree, 96))
                leave
            }
            function internal_internal_authOffset(tree, level) -> __ret0 {
                let base := add(32, mul(tree, 96))
                __ret0 := add(add(base, 16), mul(level, 16))
                leave
            }
            function internal_internal_omittedIndex(dVal) -> __ret0 {
                __ret0 := and(shr(125, dVal), 31)
                leave
            }
            function internal_internal_forcedZero(dVal) -> __ret0 {
                let idx := and(shr(125, dVal), 31)
                __ret0 := eq(idx, 0)
                leave
            }
            {
                let __has_selector := iszero(lt(calldatasize(), 4))
                if iszero(__has_selector) {
                    revert(0, 0)
                }
                if __has_selector {
                    switch shr(224, calldataload(0))
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
                    case 0x06ac7adf {
                        /* treeOffset() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 36) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 36) {
                            revert(0, 0)
                        }
                        let tree := calldataload(4)
                        mstore(0, add(32, mul(tree, 96)))
                        return(0, 32)
                    }
                    case 0x9d86b274 {
                        /* authOffset() */
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
                        let level := calldataload(36)
                        let base := add(32, mul(tree, 96))
                        mstore(0, add(add(base, 16), mul(level, 16)))
                        return(0, 32)
                    }
                    case 0xcb1e1a85 {
                        /* omittedIndex() */
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
                        mstore(0, and(shr(125, dVal), 31))
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
                    default {
                        revert(0, 0)
                    }
                }
            }
        }
    }
}