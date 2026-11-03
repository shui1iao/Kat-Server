package kernel

import "os"

func openProviderFile(path string) (*os.File, error) { return os.Open(path) }
