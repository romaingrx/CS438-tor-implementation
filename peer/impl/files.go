package impl

import (
	"encoding/hex"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
	"go.dedis.ch/cs438/utils"
	"golang.org/x/xerrors"
	"io"
	"math"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

func (n *node) Upload(data io.Reader) (metaHash string, err error) {
	blobStore := n.conf.Storage.GetDataBlobStore()

	metaFileChunks := make([][]byte, 0)

	for {
		chunk := make([]byte, n.conf.ChunkSize)
		n, err := data.Read(chunk)
		if err == io.EOF {
			break
		}
		chunk = chunk[:n]
		sha256String, sha256Bytes := utils.Sha256Encode(chunk)
		metaFileChunks = append(metaFileChunks, sha256Bytes)

		blobStore.Set(sha256String, chunk)
	}

	metaFileKeyBytes := make([]byte, 0)
	metaFileValueBytes := make([]byte, 0)

	for _, c := range metaFileChunks {
		if len(metaFileValueBytes) > 0 {
			metaFileValueBytes = append(metaFileValueBytes, []byte(peer.MetafileSep)...)
		}
		metaFileKeyBytes = append(metaFileKeyBytes, c...)
		metaFileValueBytes = append(metaFileValueBytes, []byte(hex.EncodeToString(c))...) // WTF?
	}

	metaHash, _ = utils.Sha256Encode(metaFileKeyBytes)
	blobStore.Set(metaHash, metaFileValueBytes)
	return metaHash, nil
}

func (n *node) localDownload(metahash string) ([]byte, error) {
	blob := n.conf.Storage.GetDataBlobStore()
	metaBytes := blob.Get(metahash)
	if len(metaBytes) == 0 {
		return nil, xerrors.Errorf("Metahash %s not found in the local blob", metahash)
	}
	return metaBytes, nil
}

func (n *node) localChunksDownload(metahash string) ([][]byte, error) {
	metafile, err := n.localDownload(metahash)
	if err != nil {
		return nil, err
	}

	// Split the bytes with the MetafileSep
	chunkHexKeys := strings.Split(string(metafile), peer.MetafileSep)

	chunks := make([][]byte, 0)
	blob := n.conf.Storage.GetDataBlobStore()
	for _, chunkHash := range chunkHexKeys {
		if len(chunkHash) == 0 {
			continue
		}
		if blob.Get(chunkHash) != nil {
			chunks = append(chunks, []byte(chunkHash))
		} else {
			chunks = append(chunks, nil)
		}
	}

	return chunks, nil
}

func (n *node) peerChunckDownload(hash string, p string) ([]byte, error) {
	var try uint
	for try = 0; try < n.conf.BackoffDataRequest.Retry; try++ {
		requestId, err := n.SendDataRequest(hash, p)
		if err != nil {
			return nil, err
		}

		channel, ok := n.dataReply.Load(requestId)
		if ok {
			select {
			case <-n.stop:
				return nil, xerrors.Errorf("Received stop")
			case dataReplyMsg := <-channel.(chan types.DataReplyMessage):
				if dataReplyMsg.Value == nil {
					return nil, xerrors.Errorf("The peer does not have the corresponding value for hash %s", hash)
				}
				return dataReplyMsg.Value, nil
			case <-time.After(n.conf.BackoffDataRequest.Initial):
				continue
			}
		} else {
			return nil, xerrors.Errorf("Channel to receive the reply data (%s) was not opened", requestId)
		}

	}

	return nil, xerrors.Errorf("It was not possible to get the bytes after %d retries\n", n.conf.BackoffDataRequest.Retry)

}

func (n *node) peerDownload(metahash string) ([]byte, error) {
	// If the metahash is in our catalog, get the data from this peer
	p := n.catalog.GetOne(metahash)
	if p == "" {
		// Get random peer in the catalog otherwise
		p := n.catalog.GetRandomPeer()
		if p == "" {
			return nil, xerrors.Errorf("It is not possible to find a peer in order to download metahash (%s)", metahash)
		}
	}

	// Get the bytes if the peer has the data
	bytes, err := n.peerChunckDownload(metahash, p)
	if err != nil {
		return nil, err
	}
	// Update both catalog and storage
	n.UpdateCatalog(metahash, p)
	n.conf.Storage.GetDataBlobStore().Set(metahash, bytes)
	return bytes, nil
}

func (n *node) Download(metahash string) (chunks []byte, err error) {
	return n.DownloadInner(metahash, true)
}

func (n *node) DownloadInner(metahash string, top bool) (chunks []byte, err error) {
	// Several cases :
	// 1. Has the metahash in its own catalog
	// 2. Find the peers having the metahash
	// 3. Nobody has the metahash

	if chunks, err = n.localDownload(metahash); err == nil {
		// 1.
		n.log.Printf("Found the hash %s in the local blob with chunks %b\n", metahash, chunks)
	} else if chunks, err = n.peerDownload(metahash); err != nil {
		// 3.
		return nil, xerrors.Errorf("Data has not been found neither in local nor in a peer blob")
	}
	// 2.

	if !top {
		// It's a chunk so returns directly
		return chunks, nil
	} else {
		// Split the bytes with the MetafileSep
		chunkHexKeys := strings.Split(string(chunks), peer.MetafileSep)

		// It's a metafile so collect each chunk
		allBytes := make([]byte, 0)
		for _, chunkHash := range chunkHexKeys {
			// Download each chunk either locally or via a peer
			chunkBytes, err := n.DownloadInner(chunkHash, false)
			if err != nil {
				return nil, err
			}
			// Append each bytes values
			allBytes = append(allBytes, chunkBytes...)
		}

		// Returns the bytes concatenated
		return allBytes, nil
	}
}

func (n *node) Tag(name string, mh string) error {

	// hw2
	if n.conf.TotalPeers == 1 {
		n.conf.Storage.GetNamingStore().Set(name, []byte(mh))
	} else {
		// Launch the Paxos consensus scheme in a blocking call
		// hw3
		if n.conf.Storage.GetNamingStore().Get(name) != nil {
			return xerrors.Errorf("Name %s already exists in the naming store", name)
		}
		n.BeginPaxosConsensus(name, mh)
	}

	return nil
}

func (n *node) Resolve(name string) (metahash string) {
	return string(n.conf.Storage.GetNamingStore().Get(name))
}

func (n *node) GetCatalog() peer.Catalog {
	return n.catalog.Copy()
}

func (n *node) UpdateCatalog(key string, peer string) {
	n.catalog.Add(key, peer)
}

func (n *node) searchAllLocal(reg regexp.Regexp, inBlobStore bool) (names []string, err error) {
	matchedNames := make([]string, 0)

	for _, name := range n.conf.Storage.GetNamingStore().GetKeys() {
		cdt := reg.MatchString(name) && (!inBlobStore || n.conf.Storage.GetDataBlobStore().Get(n.Resolve(name)) != nil)
		n.log.Printf("Name %s is appened (%d) to the selection for reg %s\n", name, cdt, reg.String())
		if cdt {
			matchedNames = append(matchedNames, name)
		}
	}

	return matchedNames, nil
}

func (n *node) splitBudgetPeers(budget uint, excepted []string) (map[string]uint, error) {
	peerBudgets := make(map[string]uint)

	peers := n.GetNeighborsExcepted(excepted)
	if len(peers) == 0 {
		// return nil, xerrors.Errorf("No peers to split the budget with")
		return make(map[string]uint), nil
	}

	budgetPerPeer := utils.Uint(math.Floor(utils.Float(budget) / float64(len(peers))))
	leftBudgetPerPeer := utils.Uint(math.Mod(utils.Float(budget), float64(len(peers))))
	n.log.Printf("Base budget : %d, mod budget %d\n", budgetPerPeer, leftBudgetPerPeer)
	for _, randIndex := range rand.Perm(len(peers)) {
		if budgetPerPeer == 0 {
			peerBudgets[peers[randIndex]] = 1
			if len(peerBudgets) == int(budget) {
				break
			}
		} else {
			peerBudgets[peers[randIndex]] = budgetPerPeer
			if leftBudgetPerPeer > 0 {
				peerBudgets[peers[randIndex]]++
				leftBudgetPerPeer--
			}
		}
	}
	return peerBudgets, nil
}

func (n *node) searchAllPeer(timeout time.Duration, searchRequestMsg types.SearchRequestMessage, excepted []string) (names map[string]bool, err error) {
	peerBudgets, err := n.splitBudgetPeers(searchRequestMsg.Budget, excepted)
	if err != nil {
		return nil, err
	}
	n.log.Println("Splitted budget by peer: ", peerBudgets)

	// In case of search request from another peer
	if timeout == 0 {
		timeout = math.MaxInt64 * time.Nanosecond
	}

	// Search for each peer in parallel
	for p, pBudget := range peerBudgets {
		pSearchRequestMsg := types.SearchRequestMessage{
			RequestID: searchRequestMsg.RequestID,
			Origin:    searchRequestMsg.Origin,
			Pattern:   searchRequestMsg.Pattern,
			Budget:    pBudget,
		}

		// Send the request data message
		_, err := n.SendSearchRequestMessage(pSearchRequestMsg, p)
		if err != nil {
			n.log.Println(err)
		}
	}

	// Wait for the answer on the channel
	channel, ok := n.searchReply.Load(searchRequestMsg.RequestID)
	if !ok {
		n.log.Printf("Channel was not created for the search request %s\n", searchRequestMsg.RequestID)
		return
	}

	allNames := make(map[string]bool, 0)
MAIN:
	for {
		select {
		case <-n.stop:
			break MAIN
		case <-time.After(timeout):
			break MAIN
		case searchReplyMsg := <-channel.(chan types.SearchReplyMessage):
			for _, fileInfo := range searchReplyMsg.Responses {
				n.log.Printf("Received search reply %s for requestID %s\n", fileInfo.Name, searchRequestMsg.RequestID)
				allNames[fileInfo.Name] = allNames[fileInfo.Name] || n.fullyKnowsName(fileInfo.Chunks)
			}
		}
	}

	return allNames, nil

}

func (n *node) SearchAll(reg regexp.Regexp, budget uint, timeout time.Duration) (names []string, err error) {
	names, err = n.searchAllLocal(reg, false)
	if err != nil {
		return nil, err
	}
	n.log.Println("Search found locally", names)

	searchRequestMsg := types.SearchRequestMessage{}.New(n.conf.Socket.GetAddress(), reg, budget)
	peerNames, err := n.searchAllPeer(timeout, *searchRequestMsg, []string{n.conf.Socket.GetAddress()})
	if err != nil {
		// TODO : return nil or names? What is more safe?
		return names, err
	}
	n.log.Println("Search found on peer", peerNames)
	for name := range peerNames {
		names = append(names, name)
	}

	return utils.Unique(names), nil
}

func (n *node) fullyKnowsName(chunks [][]byte) bool {
	for _, chunk := range chunks {
		if len(chunk) == 0 {
			return false
		}
	}
	return true
}

func (n *node) searchFirstLocal(reg regexp.Regexp, inBlobStore bool) (names string, err error) {
	for _, name := range n.conf.Storage.GetNamingStore().GetKeys() {
		cdt := reg.MatchString(name) && (!inBlobStore || n.conf.Storage.GetDataBlobStore().Get(n.Resolve(name)) != nil)
		if cdt {
			metahash := n.Resolve(name)
			chunks, err := n.localChunksDownload(metahash)
			if err != nil {
				n.log.Println(err)
				continue
			}
			if n.fullyKnowsName(chunks) {
				return name, nil
			}
			n.log.Printf("Name %s is not fully known : %v\n", name, err)
		}
	}
	return "", xerrors.Errorf("No name is fully known")
}

func (n *node) searchFirstPeers(reg regexp.Regexp, conf peer.ExpandingRing) (names string, err error) {

	var k uint
	var budget uint = conf.Initial
	for k = 0; k < conf.Retry; k++ {
		searchRequestMsg := types.SearchRequestMessage{}.New(n.conf.Socket.GetAddress(), reg, budget)
		// TODO URGENT: Remove multiple but otherwise it's impossible
		peerNames, err := n.searchAllPeer(conf.Timeout*10, *searchRequestMsg, []string{n.conf.Socket.GetAddress()})
		if err != nil {
			return "", err
		}
		for name, isFullyKnown := range peerNames {
			if isFullyKnown {
				return name, nil
			}
		}

		budget *= conf.Factor
	}

	return "", nil
	// return "", xerrors.Errorf("No peers fully known a name")
}

func (n *node) SearchFirst(pattern regexp.Regexp, conf peer.ExpandingRing) (name string, err error) {
	name, err = n.searchFirstLocal(pattern, true)
	if err == nil {
		return name, nil
	}

	name, err = n.searchFirstPeers(pattern, conf)
	return name, err
}
