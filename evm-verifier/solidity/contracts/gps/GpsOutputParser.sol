// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.6.12;

import "../components/FactRegistry.sol";
import "../cpu/CpuPublicInputOffsetsBase.sol";

contract GpsOutputParser is CpuPublicInputOffsetsBase, FactRegistry {
    uint256 internal constant METADATA_TASKS_OFFSET = 1;
    uint256 internal constant METADATA_TASK_HEADER_SIZE = 3;
    uint256 internal constant NODE_STACK_ITEM_SIZE = 2;
    uint256 internal constant FIRST_CONTINUOUS_PAGE_INDEX = 1;

    event LogMemoryPagesHashes(bytes32 programOutputFact, bytes32[] pagesHashes);

    function registerGpsFacts(
        uint256[] calldata taskMetadata,
        uint256[] memory publicMemoryPages,
        uint256 outputStartAddress
    ) internal {
        uint256 totalNumPages = publicMemoryPages[0];
        uint256[] memory pageHashesLogData = new uint256[](totalNumPages + 3);
        pageHashesLogData[1] = 0x40;

        uint256 curAddr = outputStartAddress + 5;
        uint256 curPage = FIRST_CONTINUOUS_PAGE_INDEX;
        uint256[] memory nodeStack = new uint256[](NODE_STACK_ITEM_SIZE * totalNumPages);

        uint256 taskMetadataOffset = METADATA_TASKS_OFFSET;
        uint256 nTasks = taskMetadata[0];

        for (uint256 task = 0; task < nTasks; task++) {
            uint256 curOffset = 0;
            uint256 firstPageOfTask = curPage;
            uint256 nTreePairs = taskMetadata[taskMetadataOffset + METADATA_TASK_HEADER_SIZE];

            uint256 nodeStackLen = 0;

            for (uint256 treePair = 0; treePair < nTreePairs; treePair++) {
                uint256 nPages = taskMetadata[
                    taskMetadataOffset + METADATA_TASK_HEADER_SIZE + 2 * treePair
                ];

                require(nPages < 2**20, "Invalid value of n_pages in tree structure.");

                for (uint256 i = 0; i < nPages; i++) {
                    (uint256 pageSize, uint256 pageHash) = pushPageToStack(
                        publicMemoryPages,
                        curAddr,
                        curOffset,
                        nodeStack,
                        nodeStackLen
                    );
                    pageHashesLogData[curPage - firstPageOfTask + 3] = pageHash;
                    curPage++;
                    nodeStackLen++;
                    curAddr += pageSize;
                    curOffset += pageSize;
                }

                uint256 nNodes = taskMetadata[
                    taskMetadataOffset + METADATA_TASK_HEADER_SIZE + 2 * treePair + 1
                ];

                if (nNodes != 0) {
                    nodeStackLen = constructNode(nodeStack, nodeStackLen, nNodes);
                }
            }

            require(nodeStackLen == 1, "Node stack must contain exactly one item.");

            uint256 programHash = taskMetadata[taskMetadataOffset + 1];

            {
                uint256 outputSize = taskMetadata[taskMetadataOffset + METADATA_OFFSET_TASK_OUTPUT_SIZE];

                require(
                    nodeStack[NODE_STACK_OFFSET_END] + 2 == outputSize,
                    "Sum of page sizes does not match output size."
                );
            }

            uint256 programOutputFact = nodeStack[NODE_STACK_OFFSET_HASH];
            bytes32 fact = keccak256(abi.encode(programHash, programOutputFact));

            taskMetadataOffset += METADATA_TASK_HEADER_SIZE + 2 * nTreePairs;

            {
                bytes32 logHash = keccak256("LogMemoryPagesHashes(bytes32,bytes32[])");
                assembly {
                    let buf := add(pageHashesLogData, 0x20)
                    let length := sub(curPage, firstPageOfTask)
                    mstore(buf, programOutputFact)
                    mstore(add(buf, 0x40), length)
                    log1(buf, mul(add(length, 3), 0x20), logHash)
                }
            }
            
            registerFact(fact);
            curAddr += 2;
        }

        require(totalNumPages == curPage, "Not all memory pages were processed.");
    }

    function pushPageToStack(
        uint256[] memory pageInfoPtr,
        uint256 curAddr,
        uint256 curOffset,
        uint256[] memory nodeStack,
        uint256 nodeStackLen
    ) private pure returns (uint256 pageSize, uint256 pageHash) {
        uint256 pageAddr = pageInfoPtr[PAGE_INFO_ADDRESS_OFFSET];
        pageSize = pageInfoPtr[PAGE_INFO_SIZE_OFFSET];
        pageHash = pageInfoPtr[PAGE_INFO_HASH_OFFSET];

        require(pageSize < 2**30, "Invalid page size.");
        require(pageAddr == curAddr, "Invalid page address.");

        nodeStack[NODE_STACK_ITEM_SIZE * nodeStackLen + NODE_STACK_OFFSET_END] = curOffset + pageSize;
        nodeStack[NODE_STACK_ITEM_SIZE * nodeStackLen + NODE_STACK_OFFSET_HASH] = pageHash;
    }

    function constructNode(
        uint256[] memory nodeStack,
        uint256 nodeStackLen,
        uint256 nNodes
    ) private pure returns (uint256) {
        require(nNodes <= nodeStackLen, "Invalid value of n_nodes in tree structure.");
        uint256 newNodeEnd = nodeStack[NODE_STACK_ITEM_SIZE * (nodeStackLen - 1) + NODE_STACK_OFFSET_END];
        uint256 newStackLen = nodeStackLen - nNodes;

        uint256 nodeStart = 0x20 + newStackLen * NODE_STACK_ITEM_SIZE * 0x20;
        uint256 newNodeHash = uint256(keccak256(abi.encodePacked(add(nodeStack, nodeStart), nNodes * 0x40)));

        nodeStack[NODE_STACK_ITEM_SIZE * newStackLen + NODE_STACK_OFFSET_END] = newNodeEnd;
        nodeStack[NODE_STACK_ITEM_SIZE * newStackLen + NODE_STACK_OFFSET_HASH] = newNodeHash + 1;

        return newStackLen + 1;
    }
}
