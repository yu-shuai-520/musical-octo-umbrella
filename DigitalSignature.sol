// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract DigitalSignature {
    uint256 public constant MAX_SIGNERS = 20;
    uint256 public constant MIN_SIGNERS = 1;

    struct User {
        string name;
        bool isRegistered;
    }

    struct ContractMeta {
        uint256 id;
        address creator;
        string title;
        string content;
        bytes32 contentHash;
        bool isCompleted;
        uint256 createdAt;
        uint256 expiresAt;
    }

    mapping(address => User) public users;
    mapping(bytes32 => bool) public usedHashes;

    mapping(uint256 => ContractMeta) private metas;
    uint256 public contractCount;

    mapping(uint256 => address[]) private signersMap;
    mapping(uint256 => mapping(address => bool)) private signedMap;

    mapping(address => uint256[]) private createdContracts;
    mapping(address => uint256[]) private pendingContracts;

    event ContractCreated(uint256 indexed contractId, address indexed creator, string title, uint256 expiresAt);
    event ContractSigned(uint256 indexed contractId, address indexed signer, uint256 signedAt);
    event ContractCompleted(uint256 indexed contractId);
    event UserRegistered(address indexed userAddress, string name);

    function registerUser(string memory _name) public {
        require(bytes(_name).length > 0, "Name required");
        users[msg.sender] = User({name: _name, isRegistered: true});
        emit UserRegistered(msg.sender, _name);
    }

    function createContract(
        address[] memory _signers,
        string memory _title,
        string memory _content,
        uint256 _expiresInDays
    ) public {
        require(_signers.length >= MIN_SIGNERS && _signers.length <= MAX_SIGNERS, "invalid signers count");
        require(bytes(_title).length > 0, "title required");
        require(bytes(_content).length > 0, "content required");

        bytes32 h = keccak256(abi.encodePacked(_content));
        require(!usedHashes[h], "content already used");
        usedHashes[h] = true;

        contractCount++;
        uint256 id = contractCount;

        metas[id] = ContractMeta({
            id: id,
            creator: msg.sender,
            title: _title,
            content: _content,
            contentHash: h,
            isCompleted: false,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + (_expiresInDays * 1 days)
        });

        createdContracts[msg.sender].push(id);

        for (uint i = 0; i < _signers.length; i++) {
            signersMap[id].push(_signers[i]);
            signedMap[id][_signers[i]] = false;
            pendingContracts[_signers[i]].push(id);
        }

        emit ContractCreated(id, msg.sender, _title, metas[id].expiresAt);
    }

    function signContract(uint256 _contractId) public {
        ContractMeta storage m = metas[_contractId];
        require(m.id != 0, "contract not found");
        require(!m.isCompleted, "contract already completed");

        int signerIndex = -1;
        for (uint i = 0; i < signersMap[_contractId].length; i++) {
            if (signersMap[_contractId][i] == msg.sender) {
                signerIndex = int(i);
                break;
            }
        }
        require(signerIndex >= 0, "not a signer");

        if (signedMap[_contractId][msg.sender]) {
            revert("already signed");
        }

        signedMap[_contractId][msg.sender] = true;
        emit ContractSigned(_contractId, msg.sender, block.timestamp);

        _removePending(msg.sender, _contractId);

        bool all = true;
        for (uint j = 0; j < signersMap[_contractId].length; j++) {
            if (!signedMap[_contractId][signersMap[_contractId][j]]) { all = false; break; }
        }
        if (all) {
            m.isCompleted = true;
            emit ContractCompleted(_contractId);
        }
    }

    function _removePending(address user, uint256 id) internal {
        uint256[] storage arr = pendingContracts[user];
        for (uint i = 0; i < arr.length; i++) {
            if (arr[i] == id) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                break;
            }
        }
    }

    function getContract(uint256 _contractId) public view returns (
        uint256 id,
        address creator,
        address[] memory signers,
        string memory title,
        string memory content,
        bytes32 contentHash,
        bool[] memory isSigned,
        bool isCompleted,
        uint256 createdAt,
        uint256 expiresAt
    ) {
        ContractMeta storage m = metas[_contractId];
        require(m.id != 0, "contract not found");

        address[] storage s = signersMap[_contractId];
        signers = new address[](s.length);
        isSigned = new bool[](s.length);
        for (uint i = 0; i < s.length; i++) {
            signers[i] = s[i];
            isSigned[i] = signedMap[_contractId][s[i]];
        }

        return (
            m.id,
            m.creator,
            signers,
            m.title,
            m.content,
            m.contentHash,
            isSigned,
            m.isCompleted,
            m.createdAt,
            m.expiresAt
        );
    }

    function getUserCreatedContracts(address _user) public view returns (uint256[] memory) {
        return createdContracts[_user];
    }

    function getUserPendingContracts(address _user) public view returns (uint256[] memory) {
        return pendingContracts[_user];
    }

    function verifyContract(uint256 _contractId, string memory _content) public view returns (bool) {
        ContractMeta storage m = metas[_contractId];
        if (m.id == 0) return false;
        return m.contentHash == keccak256(abi.encodePacked(_content));
    }

}
