package orchd

import "context"

// RegistryFoldForTest exposes the daemon's own registry read, so a test can
// check that it reads the directory it is writing rather than refusing it.
//
// Exported from a _test.go file, so it exists only under test and widens no
// API. The read itself is the daemon's, unmodified — a test that reimplemented
// it would be checking its own copy.
func (s *Server) RegistryFoldForTest() (any, error) {
	return s.registryNow(context.Background())
}
