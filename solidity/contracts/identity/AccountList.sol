// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AccountList - the account nodes a wallet holds.
///
/// @notice A set per wallet that a reader walks by page. Adding and removing
///         cost the same however many nodes a list holds: a node's position is
///         kept beside the list, and a removal moves the last node into the
///         gap rather than shifting what follows.
///
/// @dev A node sits in at most one list at a time, so its position is keyed by
///      the node alone. Positions are one-based, so that zero means the node
///      is in no list. A page is addressed by index, counted from zero, like
///      the array it is cut from.
///
///      Order is arbitrary. A removal changes it, and nothing here or above
///      reads it: a page is a slice of the current arrangement, not a history.
library AccountList {
    struct Data {
        /// wallet -> the nodes it holds.
        mapping(address => bytes32[]) nodes;
        /// node -> one-based position in the list that holds it.
        mapping(bytes32 => uint256) position;
    }

    /// @dev Appends a node that no list holds.
    function add(Data storage self, address wallet, bytes32 node) internal {
        bytes32[] storage list = self.nodes[wallet];
        list.push(node);
        self.position[node] = list.length;
    }

    /// @dev Removes a node by moving the last node into its place. The wallet
    ///      named must be the one holding the node: the position says where
    ///      in a list the node sits, not which list, and a caller naming the
    ///      wrong one would overwrite a stranger's entry.
    function remove(Data storage self, address wallet, bytes32 node) internal {
        bytes32[] storage list = self.nodes[wallet];
        uint256 index = self.position[node] - 1;
        uint256 lastIndex = list.length - 1;
        if (index != lastIndex) {
            bytes32 last = list[lastIndex];
            list[index] = last;
            self.position[last] = index + 1;
        }
        list.pop();
        delete self.position[node];
    }

    function count(Data storage self, address wallet) internal view returns (uint256) {
        return self.nodes[wallet].length;
    }

    /// @dev The nodes at indices `[from, from + limit)`, clipped to the list.
    ///      A `from` past the end answers an empty page rather than reverting,
    ///      so a reader paging by a count it read a moment ago is not thrown by
    ///      a removal in between.
    function page(Data storage self, address wallet, uint256 from, uint256 limit)
        internal
        view
        returns (bytes32[] memory out)
    {
        bytes32[] storage list = self.nodes[wallet];
        uint256 length = list.length;
        if (from >= length) return out;
        uint256 end = limit < length - from ? from + limit : length;
        out = new bytes32[](end - from);
        for (uint256 i = from; i < end; i++) {
            out[i - from] = list[i];
        }
    }
}
