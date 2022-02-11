package proto

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/runtime/protoimpl"
)

type hash = [32]byte

func hashDesc(b []byte) hash {
	return sha256.Sum256(b)
}

func newRegistry() *registry {
	return &registry{
		mu:             new(sync.RWMutex),
		reg:            new(protoregistry.Files),
		filepathToHash: map[string]hash{},
		hashToFilepath: map[hash][]string{},
		fdByHash:       map[hash]protoreflect.FileDescriptor{},
	}
}

type registry struct {
	mu *sync.RWMutex

	reg *protoregistry.Files

	filepathToHash map[string]hash                      // maps file paths to content hashes
	hashToFilepath map[hash][]string                    // maps a file descriptor hash to its import paths
	fdByHash       map[hash]protoreflect.FileDescriptor // maps hash->protoreflect.FileDescriptor
}

func (r *registry) registerRaw(filepath string, fdZippedBytes []byte) error {
	fdHash := hashDesc(fdZippedBytes)
	// check if file is known through its path.
	knownPath, err := r.knownFilepath(filepath, fdHash)
	if err != nil {
		return err
	}
	if knownPath {
		return nil
	}
	// this path is unknown, but we might be in the case in which
	// the same file descriptor bytes are being registered but
	// with a different path.
	knownHash := r.knownHash(fdHash)
	if knownHash {
		r.registerImportAliasByHash(fdHash, filepath)
		return nil
	}

	// if the file is totally unknown then we need to register it
	zr, err := gzip.NewReader(bytes.NewReader(fdZippedBytes))
	if err != nil {
		return fmt.Errorf("bad gzipped file descriptor: %w", err)
	}
	fdBytes, err := ioutil.ReadAll(zr)
	if err != nil {
		return fmt.Errorf("bad gzipped file descriptor: %w", err)
	}

	fd := protoimpl.DescBuilder{
		RawDescriptor: fdBytes,
		FileRegistry:  r,
	}.Build()

	// save fd info
	r.saveFileDescriptor(filepath, fdHash, fd.File)
	return nil
}

func (r *registry) FindFileByPath(path string) (protoreflect.FileDescriptor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fd, err := r.reg.FindFileByPath(path)
	if err == nil {
		return fd, nil
	}
	if !errors.Is(err, protoregistry.NotFound) {
		return nil, err
	}

	h, exist := r.filepathToHash[path]
	if !exist {
		return nil, fmt.Errorf("%w: %s", protoregistry.NotFound, path)
	}

	return r.fdByHash[h], nil
}

func (r *registry) FindDescriptorByName(name protoreflect.FullName) (protoreflect.Descriptor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reg.FindDescriptorByName(name)
}

func (r *registry) RegisterFile(file protoreflect.FileDescriptor) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.reg.RegisterFile(file)
	return err
}

func (r *registry) RegisterImportAlias(original string, alias string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	hash, exists := r.filepathToHash[original]
	if !exists {
		return fmt.Errorf("unable to register alias %s for filename %s as it does not exist", alias, original)
	}

	r.hashToFilepath[hash] = append(r.hashToFilepath[hash], alias)
	r.filepathToHash[alias] = hash

	return nil
}

func (r *registry) knownFilepath(filename string, fdHash hash) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fileHash, known := r.filepathToHash[filename]
	if known {
		// if it's known we compare hashes to assert that contents match
		if fileHash != fdHash {
			return false, fmt.Errorf("double registration of the same file %s with different content hashes %x <-> %x", filename, fileHash, fdHash)
		}
	}
	// file is unknown
	return false, nil
}

func (r *registry) knownHash(fdHash hash) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, known := r.fdByHash[fdHash]
	return known
}

func (r *registry) registerImportAliasByHash(fdHash hash, filename string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.hashToFilepath[fdHash] = append(r.hashToFilepath[fdHash], filename)
	r.filepathToHash[filename] = fdHash

	_, _ = fmt.Fprintf(os.Stderr, "detected import aliases for files %s", r.hashToFilepath[fdHash])
}

func (r *registry) saveFileDescriptor(filename string, fdHash hash, fd protoreflect.FileDescriptor) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.fdByHash[fdHash] = fd
	r.filepathToHash[filename] = fdHash
	r.hashToFilepath[fdHash] = []string{filename} // this is init always.

	k := make([]string, 0, len(r.filepathToHash))
	for x := range r.filepathToHash {
		k = append(k, x)
	}
}
