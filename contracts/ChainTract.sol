pragma solidity ^0.8.0;

contract ChainTract {
    mapping(bytes32 => mapping(address => bool)) public documentSignatures;
    mapping(bytes32 => address) public documentOwner;

    event DocumentSigned(bytes32 indexed documentHash, address indexed signer);
    event DocumentRegistered(bytes32 indexed documentHash, address indexed owner);

    modifier onlyOwner(bytes32 documentHash) {
        require(msg.sender == documentOwner[documentHash], "Caller is not the document owner");
        _;
    }

    function registerDocument(bytes32 documentHash) public {
        require(documentOwner[documentHash] == address(0), "Document already registered");
        documentOwner[documentHash] = msg.sender;
        emit DocumentRegistered(documentHash, msg.sender);
    }

    function signDocument(bytes32 documentHash, address signer) public {
        require(documentOwner[documentHash] != address(0), "Document not registered");
        require(!documentSignatures[documentHash][signer], "Document already signed by this address");

        documentSignatures[documentHash][signer] = true;
        emit DocumentSigned(documentHash, signer);
    }

    function hasSigned(bytes32 documentHash, address signer) public view returns (bool) {
        return documentSignatures[documentHash][signer];
    }

    function getDocumentOwner(bytes32 documentHash) public view returns (address) {
        return documentOwner[documentHash];
    }
}
